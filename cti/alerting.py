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

import asyncio
import ipaddress
import logging
import os
import socket
import time
from collections import deque
from typing import Any
from urllib.parse import urlparse

import httpx

logger = logging.getLogger("cicdecoy.alerting")


def _validate_webhook_url(url: str) -> str:
    """Validate a webhook URL to prevent SSRF attacks.

    Only HTTPS (and HTTP for localhost dev) are allowed.  Hostnames that
    resolve to private/loopback/link-local IPs are rejected to prevent
    the forwarder from being used to probe internal services.

    Returns the validated URL or raises ValueError.
    """
    if not url:
        return url

    parsed = urlparse(url)

    # Only allow http(s) schemes
    if parsed.scheme not in ("http", "https"):
        raise ValueError(
            f"Webhook URL scheme must be http or https, got: {parsed.scheme!r}"
        )

    hostname = parsed.hostname or ""

    # Block URLs without a hostname
    if not hostname:
        raise ValueError("Webhook URL must include a hostname")

    # Check if hostname is a raw IP address in a private/reserved range
    try:
        addr = ipaddress.ip_address(hostname)
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
            raise ValueError(
                f"Webhook URL must not target private/loopback/link-local "
                f"addresses: {hostname}"
            )
    except ValueError as exc:
        # Re-raise our own ValueErrors, skip if it's just "not an IP"
        if "must not target" in str(exc) or "scheme must be" in str(exc):
            raise
        # Check for obfuscated IP addresses (hex, octal, decimal encoding)
        # e.g., 0x7f000001 = 127.0.0.1, 2130706433 = 127.0.0.1
        _obfuscated = hostname.lower().strip()
        try:
            # Try parsing as integer (decimal IP like 2130706433)
            if _obfuscated.isdigit():
                int_ip = int(_obfuscated)
                if 0 <= int_ip <= 0xFFFFFFFF:
                    addr = ipaddress.ip_address(int_ip)
                    if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
                        raise ValueError(f"Webhook URL uses obfuscated private IP: {hostname} ({addr})")
            # Try parsing hex (0x7f000001)
            elif _obfuscated.startswith('0x'):
                int_ip = int(_obfuscated, 16)
                if 0 <= int_ip <= 0xFFFFFFFF:
                    addr = ipaddress.ip_address(int_ip)
                    if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
                        raise ValueError(f"Webhook URL uses obfuscated private IP: {hostname} ({addr})")
        except (ValueError, OverflowError) as exc2:
            if "obfuscated" in str(exc2):
                raise exc2 from None
        # hostname is a DNS name — allow known webhook services,
        # block obviously internal hostnames
        lower = hostname.lower()
        _INTERNAL_SUFFIXES = (
            ".internal", ".local", ".localhost", ".svc",
            ".svc.cluster.local", ".corp", ".lan",
        )
        if any(lower.endswith(s) for s in _INTERNAL_SUFFIXES):
            raise ValueError(
                f"Webhook URL hostname looks internal: {hostname}"
            ) from None

    # Block obfuscated IP formats (hex, decimal, abbreviated)
    # These bypass ipaddress.ip_address() but resolve to private IPs
    try:
        resolved = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        if resolved:
            for family, _, _, _, addr in resolved:
                ip_str = addr[0]
                try:
                    addr_obj = ipaddress.ip_address(ip_str)
                    if addr_obj.is_private or addr_obj.is_loopback or addr_obj.is_link_local or addr_obj.is_reserved:
                        raise ValueError(
                            f"Webhook URL resolves to private/loopback address: "
                            f"{hostname} -> {ip_str}"
                        )
                except ValueError as ve:
                    if "resolves to" in str(ve):
                        raise
    except socket.gaierror:
        pass  # DNS resolution failed — allow (will fail at request time)
    except ValueError as ve:
        if "resolves to" in str(ve):
            raise

    return url

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
        raw_url = webhook_url or os.environ.get("ALERT_WEBHOOK_URL", "")
        try:
            self.webhook_url = _validate_webhook_url(raw_url)
        except ValueError as e:
            logger.error("Invalid webhook URL: %s", e)
            self.webhook_url = ""
        self.pagerduty_key = pagerduty_key or os.environ.get("ALERT_PAGERDUTY_KEY", "")
        if rate_limit:
            self.rate_limit = rate_limit
        else:
            try:
                self.rate_limit = int(os.environ.get("ALERT_RATE_LIMIT", "10"))
            except (ValueError, TypeError):
                logger.warning("Invalid ALERT_RATE_LIMIT env var, using default 10")
                self.rate_limit = 10

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
        # Minimum 2 seconds between alerts to prevent bursts
        if self._send_times and (now - self._send_times[-1]) < 2.0:
            return True
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

        severity = str(event.get("severity") or "info").lower()
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
            # Block redirect-based SSRF (e.g., 302 → http://169.254.169.254/)
            self._client = httpx.AsyncClient(
                timeout=10.0,
                follow_redirects=False,
            )

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
                    await asyncio.sleep(wait)
                    continue
                # 4xx (not 429) — don't retry
                logger.error("Alert webhook failed: %d %s", resp.status_code, resp.reason_phrase)
                return False
            except httpx.HTTPError as exc:
                logger.error("Alert webhook request error: %s", type(exc).__name__)
                logger.debug("Webhook error detail", exc_info=True)
                if attempt < 2:
                    await asyncio.sleep(2 ** attempt)
                    continue
                return False
        return False

    # ── Formatters ───────────────────────────────────────────────────

    @staticmethod
    def _extract(event: dict) -> dict:
        """Pull common fields from an enriched event dict."""
        severity = str(event.get("severity") or "unknown")
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
        if not isinstance(data, dict):
            data = {}
        command = (data.get("command", data.get("input", "")) or "")[:256]

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
                {"type": "mrkdwn", "text": f"Session {f['session_id'][:12] if f['session_id'] else 'n/a'} | {f['timestamp']}"},
            ],
        })
        return {"blocks": blocks}

    def _format_teams(self, event: dict) -> dict:
        f = self._extract(event)
        color = _SEVERITY_COLORS.get(str(f["severity"]).lower(), "FF0000").lstrip("#")
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
        pd_sev = _PD_SEVERITY.get(str(f["severity"]).lower(), "error")
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
