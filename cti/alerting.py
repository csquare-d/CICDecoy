"""
CI/CDecoy — Alert Notification Forwarder

Sends alert notifications to external services (Slack, Teams, PagerDuty)
when high-severity events are detected.

Configuration via environment variables:
    ALERT_WEBHOOK_URL      — Slack/Teams incoming webhook URL
    ALERT_WEBHOOK_TYPE     — "slack", "teams", or "pagerduty" (default: auto-detect)
    ALERT_MIN_SEVERITY     — Minimum severity to forward: info, low, medium, high, critical (default: high)
    ALERT_PAGERDUTY_KEY    — PagerDuty Events API v2 routing key (if using PagerDuty)
    ALERT_RATE_LIMIT       — Max alerts per minute (default: 10)
"""

import logging
import os
import time
from collections import deque
from typing import Any

import httpx

logger = logging.getLogger("cicdecoy.alerting")

SEVERITY_LEVELS = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Severity → Slack sidebar color
_SEVERITY_COLORS = {
    "info": "#36a64f",
    "low": "#2196F3",
    "medium": "#FF9800",
    "high": "#FF5722",
    "critical": "#FF0000",
}

# Severity → PagerDuty Events API v2 severity string
_PD_SEVERITY = {
    "info": "info",
    "low": "warning",
    "medium": "warning",
    "high": "error",
    "critical": "critical",
}

PAGERDUTY_EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"


class AlertForwarder:
    """Forwards high-severity CI/CDecoy events to Slack, Teams, or PagerDuty."""

    def __init__(
        self,
        webhook_url: str | None = None,
        webhook_type: str | None = None,
        min_severity: str = "high",
        pagerduty_key: str | None = None,
        rate_limit: int = 10,
    ):
        self.webhook_url = webhook_url or os.environ.get("ALERT_WEBHOOK_URL", "")
        self.pagerduty_key = pagerduty_key or os.environ.get("ALERT_PAGERDUTY_KEY", "")
        self.rate_limit = rate_limit or int(os.environ.get("ALERT_RATE_LIMIT", "10"))

        # Resolve webhook type
        raw_type = webhook_type or os.environ.get("ALERT_WEBHOOK_TYPE", "")
        self.webhook_type = raw_type.lower() if raw_type else self._detect_type()

        # Severity threshold
        sev = (min_severity or os.environ.get("ALERT_MIN_SEVERITY", "high")).lower()
        if sev not in SEVERITY_LEVELS:
            logger.warning(f"Unknown severity '{sev}', defaulting to 'high'")
            sev = "high"
        self.threshold = SEVERITY_LEVELS[sev]

        # Sliding-window rate limiter (timestamps of recent sends)
        self._send_times: deque[float] = deque()

        # Lazy httpx client
        self._client: httpx.AsyncClient | None = None

        self.enabled = bool(self.webhook_url or self.pagerduty_key)
        if self.enabled:
            logger.info(
                f"AlertForwarder enabled: type={self.webhook_type} "
                f"threshold={sev} rate_limit={self.rate_limit}/min"
            )
        else:
            logger.info("AlertForwarder disabled (no webhook URL or PagerDuty key configured)")

    # ── Type detection ───────────────────────────────────────────────

    def _detect_type(self) -> str:
        url = self.webhook_url.lower()
        if "hooks.slack.com" in url:
            return "slack"
        if "outlook.office.com/webhook" in url or ".webhook.office.com" in url:
            return "teams"
        if self.pagerduty_key:
            return "pagerduty"
        return "slack"  # sensible default

    # ── Rate limiting ────────────────────────────────────────────────

    def _rate_limited(self) -> bool:
        now = time.monotonic()
        # Purge entries older than 60 seconds
        while self._send_times and self._send_times[0] < now - 60:
            self._send_times.popleft()
        return len(self._send_times) >= self.rate_limit

    def _record_send(self) -> None:
        self._send_times.append(time.monotonic())

    # ── Public API ───────────────────────────────────────────────────

    async def maybe_send(self, event: dict[str, Any]) -> bool:
        """Send an alert if the event meets the severity threshold.

        Returns True if an alert was dispatched, False otherwise.
        """
        if not self.enabled:
            return False

        severity = event.get("severity", "info").lower()
        level = SEVERITY_LEVELS.get(severity, 0)
        if level < self.threshold:
            return False

        if self._rate_limited():
            logger.warning("Alert rate limit reached, dropping notification")
            return False

        return await self._dispatch(event)

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    # ── Dispatch ─────────────────────────────────────────────────────

    async def _dispatch(self, event: dict[str, Any]) -> bool:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=10.0)

        if self.webhook_type == "pagerduty":
            payload = self._format_pagerduty(event)
            url = PAGERDUTY_EVENTS_URL
        elif self.webhook_type == "teams":
            payload = self._format_teams(event)
            url = self.webhook_url
        else:
            payload = self._format_slack(event)
            url = self.webhook_url

        return await self._post(url, payload)

    async def _post(self, url: str, payload: dict) -> bool:
        """POST with retry on 429 / 5xx (max 2 retries, exponential backoff)."""
        for attempt in range(3):
            try:
                resp = await self._client.post(url, json=payload)  # type: ignore[union-attr]
                if resp.status_code < 300:
                    self._record_send()
                    logger.debug(f"Alert sent ({self.webhook_type}): {resp.status_code}")
                    return True
                if resp.status_code == 429 or resp.status_code >= 500:
                    wait = 2 ** attempt
                    logger.warning(
                        f"Alert webhook returned {resp.status_code}, "
                        f"retrying in {wait}s (attempt {attempt + 1}/3)"
                    )
                    import asyncio
                    await asyncio.sleep(wait)
                    continue
                # 4xx (not 429) — don't retry
                logger.error(f"Alert webhook failed: {resp.status_code} {resp.text[:200]}")
                return False
            except httpx.HTTPError as exc:
                logger.error(f"Alert webhook request error: {exc}")
                if attempt < 2:
                    import asyncio
                    await asyncio.sleep(2 ** attempt)
                    continue
                return False
        return False

    # ── Formatters ───────────────────────────────────────────────────

    @staticmethod
    def _extract(event: dict) -> dict:
        """Pull common fields from an enriched event dict."""
        severity = event.get("severity", "unknown")
        source_ip = event.get("source_ip", "n/a")
        decoy = event.get("decoy_name", "unknown")
        session_id = event.get("session_id", "")
        timestamp = event.get("timestamp", "")

        # MITRE technique — take first if present
        techniques = event.get("mitre_techniques", [])
        if techniques and isinstance(techniques[0], dict):
            tech = f"{techniques[0].get('technique_id', '')} {techniques[0].get('name', '')}".strip()
        elif techniques:
            tech = str(techniques[0])
        else:
            tech = "n/a"

        # Best-effort command extraction
        data = event.get("data", {})
        command = data.get("command", data.get("input", ""))

        return {
            "severity": severity,
            "source_ip": source_ip,
            "decoy": decoy,
            "session_id": session_id,
            "timestamp": timestamp,
            "technique": tech,
            "command": command,
        }

    def _format_slack(self, event: dict) -> dict:
        f = self._extract(event)
        blocks: list[dict] = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "\U0001f6a8 CI/CDecoy Alert"},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Severity:* {f['severity']}"},
                    {"type": "mrkdwn", "text": f"*Source IP:* {f['source_ip']}"},
                    {"type": "mrkdwn", "text": f"*Decoy:* {f['decoy']}"},
                    {"type": "mrkdwn", "text": f"*Technique:* {f['technique']}"},
                ],
            },
        ]
        if f["command"]:
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Command:* `{f['command']}`"},
            })
        blocks.append({
            "type": "context",
            "elements": [
                {"type": "mrkdwn", "text": f"Session {f['session_id'][:8] if f['session_id'] else 'n/a'} | {f['timestamp']}"},
            ],
        })
        return {"blocks": blocks}

    def _format_teams(self, event: dict) -> dict:
        f = self._extract(event)
        color = _SEVERITY_COLORS.get(f["severity"].lower(), "FF0000").lstrip("#")
        facts = [
            {"name": "Source IP", "value": f["source_ip"]},
            {"name": "Decoy", "value": f["decoy"]},
            {"name": "Technique", "value": f["technique"]},
        ]
        if f["command"]:
            facts.append({"name": "Command", "value": f["command"]})
        return {
            "@type": "MessageCard",
            "themeColor": color,
            "title": f"CI/CDecoy Alert \u2014 {f['severity']}",
            "sections": [{"facts": facts}],
        }

    def _format_pagerduty(self, event: dict) -> dict:
        f = self._extract(event)
        pd_sev = _PD_SEVERITY.get(f["severity"].lower(), "error")
        return {
            "routing_key": self.pagerduty_key,
            "event_action": "trigger",
            "payload": {
                "summary": f"CI/CDecoy: {f['severity']} alert from {f['decoy']} ({f['technique']})",
                "severity": pd_sev,
                "source": f["decoy"],
                "component": "cicdecoy",
                "custom_details": {
                    "source_ip": f["source_ip"],
                    "session_id": f["session_id"],
                    "technique": f["technique"],
                    "command": f["command"],
                    "timestamp": f["timestamp"],
                },
            },
        }
