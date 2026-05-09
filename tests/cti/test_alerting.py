"""
CI/CDecoy — Alert Forwarder Tests

Tests for cti/alerting.py: AlertForwarder class covering initialization,
webhook type detection, severity filtering, rate limiting, payload formatting,
HTTP dispatch with retries, close behavior, and full maybe_send integration.
"""

import asyncio
import socket
import time
from collections import deque
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from alerting import (
    PAGERDUTY_EVENTS_URL,
    SEVERITY_LEVELS,
    AlertForwarder,
    _PD_SEVERITY,
    _SEVERITY_COLORS,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_event(
    severity="high",
    source_ip="198.51.100.42",
    decoy_name="ssh-decoy-01",
    session_id="sess-abc123def456",
    timestamp="2026-04-22T12:00:00Z",
    technique_id="T1082",
    technique_name="System Information Discovery",
    command="whoami",
    mitre_as_dict=True,
):
    """Build a minimal event dict matching what AlertForwarder._extract expects."""
    if mitre_as_dict:
        techniques = [{"technique_id": technique_id, "name": technique_name}]
    else:
        techniques = [f"{technique_id} {technique_name}"]

    evt = {
        "severity": severity,
        "source_ip": source_ip,
        "decoy_name": decoy_name,
        "session_id": session_id,
        "timestamp": timestamp,
        "mitre_techniques": techniques,
        "data": {"command": command} if command else {},
    }
    return evt


# =========================================================================
# 1. Initialization & Configuration
# =========================================================================


class TestInitialization:

    def test_disabled_by_default(self):
        fwd = AlertForwarder()
        assert fwd.enabled is False

    def test_enabled_via_webhook_url(self):
        fwd = AlertForwarder(webhook_url="https://hooks.slack.com/services/T/B/x")
        assert fwd.enabled is True

    def test_enabled_via_pagerduty_key(self):
        fwd = AlertForwarder(pagerduty_key="pd-routing-key-123")
        assert fwd.enabled is True

    def test_env_var_fallback_webhook_url(self, monkeypatch):
        monkeypatch.setenv("ALERT_WEBHOOK_URL", "https://hooks.slack.com/services/T/B/x")
        fwd = AlertForwarder()
        assert fwd.enabled is True
        assert fwd.webhook_url == "https://hooks.slack.com/services/T/B/x"

    def test_env_var_fallback_pagerduty_key(self, monkeypatch):
        monkeypatch.setenv("ALERT_PAGERDUTY_KEY", "pd-key-from-env")
        fwd = AlertForwarder()
        assert fwd.enabled is True
        assert fwd.pagerduty_key == "pd-key-from-env"

    def test_env_var_fallback_min_severity(self, monkeypatch):
        monkeypatch.setenv("ALERT_WEBHOOK_URL", "https://hooks.slack.com/x")
        monkeypatch.setenv("ALERT_MIN_SEVERITY", "low")
        # The init signature defaults min_severity="high", so env var only
        # kicks in when caller passes None explicitly.
        fwd = AlertForwarder(min_severity=None)
        assert fwd.threshold == SEVERITY_LEVELS["low"]

    def test_env_var_fallback_rate_limit(self, monkeypatch):
        monkeypatch.setenv("ALERT_RATE_LIMIT", "25")
        fwd = AlertForwarder(rate_limit=0)
        assert fwd.rate_limit == 25

    def test_env_var_fallback_webhook_type(self, monkeypatch):
        monkeypatch.setenv("ALERT_WEBHOOK_URL", "https://example.com/hook")
        monkeypatch.setenv("ALERT_WEBHOOK_TYPE", "teams")
        fwd = AlertForwarder()
        assert fwd.webhook_type == "teams"

    def test_invalid_min_severity_defaults_to_high(self):
        fwd = AlertForwarder(
            webhook_url="https://hooks.slack.com/x",
            min_severity="banana",
        )
        assert fwd.threshold == SEVERITY_LEVELS["high"]

    def test_custom_rate_limit(self):
        fwd = AlertForwarder(rate_limit=42)
        assert fwd.rate_limit == 42


# =========================================================================
# 2. Webhook Type Detection
# =========================================================================


class TestTypeDetection:

    def test_slack_url_detected(self):
        fwd = AlertForwarder(webhook_url="https://hooks.slack.com/services/T/B/x")
        assert fwd.webhook_type == "slack"

    def test_teams_url_outlook(self):
        fwd = AlertForwarder(
            webhook_url="https://outlook.office.com/webhook/abc123"
        )
        assert fwd.webhook_type == "teams"

    def test_teams_url_webhook_office(self):
        fwd = AlertForwarder(
            webhook_url="https://myorg.webhook.office.com/webhook/abc"
        )
        assert fwd.webhook_type == "teams"

    def test_pagerduty_detection_via_key(self):
        fwd = AlertForwarder(
            webhook_url="https://example.com/unknown",
            pagerduty_key="pd-key",
        )
        # Auto-detect sees unrecognized URL but pagerduty_key is set
        # However, the code checks URL patterns first. Since the URL is unknown
        # and pagerduty_key is set, it should return "pagerduty".
        assert fwd.webhook_type == "pagerduty"

    def test_pagerduty_detection_no_url(self):
        fwd = AlertForwarder(pagerduty_key="pd-key")
        assert fwd.webhook_type == "pagerduty"

    def test_default_slack_for_unknown_url(self):
        fwd = AlertForwarder(webhook_url="https://example.com/custom-hook")
        assert fwd.webhook_type == "slack"

    def test_explicit_type_override(self):
        fwd = AlertForwarder(
            webhook_url="https://hooks.slack.com/services/T/B/x",
            webhook_type="teams",
        )
        assert fwd.webhook_type == "teams"


# =========================================================================
# 3. Severity Filtering
# =========================================================================


class TestSeverityFiltering:

    @pytest.mark.asyncio
    async def test_event_below_threshold_filtered(self):
        fwd = AlertForwarder(
            webhook_url="https://hooks.slack.com/x", min_severity="high"
        )
        event = _make_event(severity="medium")
        result = await fwd.maybe_send(event)
        assert result is False

    @pytest.mark.asyncio
    async def test_event_at_threshold_passes(self):
        fwd = AlertForwarder(
            webhook_url="https://hooks.slack.com/x", min_severity="high"
        )
        event = _make_event(severity="high")
        with patch.object(fwd, "_dispatch", new_callable=AsyncMock, return_value=True):
            result = await fwd.maybe_send(event)
        assert result is True

    @pytest.mark.asyncio
    async def test_event_above_threshold_passes(self):
        fwd = AlertForwarder(
            webhook_url="https://hooks.slack.com/x", min_severity="medium"
        )
        event = _make_event(severity="critical")
        with patch.object(fwd, "_dispatch", new_callable=AsyncMock, return_value=True):
            result = await fwd.maybe_send(event)
        assert result is True

    @pytest.mark.asyncio
    async def test_missing_severity_treated_as_info(self):
        fwd = AlertForwarder(
            webhook_url="https://hooks.slack.com/x", min_severity="low"
        )
        event = _make_event(severity="high")
        del event["severity"]  # missing severity -> "info" (level 0)
        result = await fwd.maybe_send(event)
        assert result is False


# =========================================================================
# 4. Rate Limiting
# =========================================================================


class TestRateLimiting:

    def test_under_limit_not_rate_limited(self):
        fwd = AlertForwarder(rate_limit=5)
        now = time.monotonic()
        # Space entries >2s apart to avoid burst protection
        fwd._send_times = deque([now - 10, now - 8, now - 6, now - 4])
        assert fwd._rate_limited() is False

    def test_at_limit_is_rate_limited(self):
        fwd = AlertForwarder(rate_limit=5)
        fwd._send_times = deque([time.monotonic()] * 5)
        assert fwd._rate_limited() is True

    def test_window_expiry_purges_old_entries(self):
        fwd = AlertForwarder(rate_limit=3)
        now = 1000.0
        # 3 old entries (>60s ago) + 1 recent
        old_times = [now - 90, now - 80, now - 70]
        fwd._send_times = deque(old_times + [now - 5])
        with patch("time.monotonic", return_value=now):
            assert fwd._rate_limited() is False
        # Old entries should have been purged
        assert len(fwd._send_times) == 1

    def test_record_send_appends_timestamp(self):
        fwd = AlertForwarder(rate_limit=10)
        with patch("time.monotonic", return_value=42.0):
            fwd._record_send()
        assert 42.0 in fwd._send_times

    @pytest.mark.asyncio
    async def test_rate_limited_maybe_send_returns_false(self):
        fwd = AlertForwarder(
            webhook_url="https://hooks.slack.com/x",
            min_severity="info",
            rate_limit=2,
        )
        fwd._send_times = deque([time.monotonic()] * 2)
        event = _make_event(severity="critical")
        result = await fwd.maybe_send(event)
        assert result is False


# =========================================================================
# 5. Payload Formatting
# =========================================================================


class TestPayloadFormatting:

    # -- Extract --

    def test_extract_with_dict_technique(self):
        event = _make_event(mitre_as_dict=True)
        f = AlertForwarder._extract(event)
        assert "T1082" in f["technique"]
        assert "System Information Discovery" in f["technique"]

    def test_extract_with_string_technique(self):
        event = _make_event(mitre_as_dict=False)
        f = AlertForwarder._extract(event)
        assert "T1082" in f["technique"]

    def test_extract_no_techniques(self):
        event = _make_event()
        event["mitre_techniques"] = []
        f = AlertForwarder._extract(event)
        assert f["technique"] == "n/a"

    def test_extract_missing_fields(self):
        event = {}
        f = AlertForwarder._extract(event)
        assert f["severity"] == "unknown"
        assert f["source_ip"] == "n/a"
        assert f["decoy"] == "unknown"
        assert f["session_id"] == ""
        assert f["timestamp"] == ""
        assert f["technique"] == "n/a"
        assert f["command"] == ""

    def test_extract_command_from_input_key(self):
        event = {"data": {"input": "ls -la"}}
        f = AlertForwarder._extract(event)
        assert f["command"] == "ls -la"

    # -- Slack --

    def test_format_slack_structure(self):
        fwd = AlertForwarder(webhook_url="https://hooks.slack.com/x")
        event = _make_event(command="cat /etc/passwd")
        payload = fwd._format_slack(event)
        assert "blocks" in payload
        blocks = payload["blocks"]
        # header, fields section, command section, context
        assert len(blocks) == 4
        assert blocks[0]["type"] == "header"
        assert blocks[1]["type"] == "section"
        assert "fields" in blocks[1]
        assert blocks[2]["type"] == "section"  # command block
        assert "`cat /etc/passwd`" in blocks[2]["text"]["text"]
        assert blocks[3]["type"] == "context"

    def test_format_slack_without_command(self):
        fwd = AlertForwarder(webhook_url="https://hooks.slack.com/x")
        event = _make_event(command=None)
        payload = fwd._format_slack(event)
        blocks = payload["blocks"]
        # header, fields section, context (no command block)
        assert len(blocks) == 3
        assert blocks[0]["type"] == "header"
        assert blocks[1]["type"] == "section"
        assert blocks[2]["type"] == "context"

    def test_format_slack_context_session_id(self):
        fwd = AlertForwarder(webhook_url="https://hooks.slack.com/x")
        event = _make_event(session_id="sess-abcdef123456")
        payload = fwd._format_slack(event)
        context_block = payload["blocks"][-1]
        text = context_block["elements"][0]["text"]
        assert "sess-abc" in text  # first 8 chars

    def test_format_slack_no_session_id(self):
        fwd = AlertForwarder(webhook_url="https://hooks.slack.com/x")
        event = _make_event(session_id="")
        payload = fwd._format_slack(event)
        context_block = payload["blocks"][-1]
        text = context_block["elements"][0]["text"]
        assert "n/a" in text

    # -- Teams --

    def test_format_teams_structure(self):
        fwd = AlertForwarder(
            webhook_url="https://outlook.office.com/webhook/abc",
        )
        event = _make_event(severity="critical", command="rm -rf /")
        payload = fwd._format_teams(event)
        assert payload["@type"] == "MessageCard"
        assert "critical" in payload["title"]
        assert "sections" in payload
        facts = payload["sections"][0]["facts"]
        fact_names = [f["name"] for f in facts]
        assert "Source IP" in fact_names
        assert "Decoy" in fact_names
        assert "Technique" in fact_names
        assert "Command" in fact_names

    def test_format_teams_no_command(self):
        fwd = AlertForwarder(
            webhook_url="https://outlook.office.com/webhook/abc",
        )
        event = _make_event(command=None)
        payload = fwd._format_teams(event)
        facts = payload["sections"][0]["facts"]
        fact_names = [f["name"] for f in facts]
        assert "Command" not in fact_names

    def test_format_teams_theme_color_mapping(self):
        fwd = AlertForwarder(
            webhook_url="https://outlook.office.com/webhook/abc",
        )
        for severity, hex_color in _SEVERITY_COLORS.items():
            event = _make_event(severity=severity)
            payload = fwd._format_teams(event)
            expected = hex_color.lstrip("#")
            assert payload["themeColor"] == expected, (
                f"themeColor mismatch for {severity}"
            )

    # -- PagerDuty --

    def test_format_pagerduty_structure(self):
        fwd = AlertForwarder(pagerduty_key="pd-routing-key-xyz")
        event = _make_event(severity="high")
        payload = fwd._format_pagerduty(event)
        assert payload["routing_key"] == "pd-routing-key-xyz"
        assert payload["event_action"] == "trigger"
        assert "payload" in payload
        p = payload["payload"]
        assert p["severity"] == _PD_SEVERITY["high"]
        assert p["component"] == "cicdecoy"
        assert "source_ip" in p["custom_details"]
        assert "command" in p["custom_details"]

    def test_format_pagerduty_severity_mapping(self):
        fwd = AlertForwarder(pagerduty_key="pd-key")
        for severity, expected_pd in _PD_SEVERITY.items():
            event = _make_event(severity=severity)
            payload = fwd._format_pagerduty(event)
            assert payload["payload"]["severity"] == expected_pd, (
                f"PD severity mismatch for {severity}"
            )

    def test_format_pagerduty_summary_contains_decoy(self):
        fwd = AlertForwarder(pagerduty_key="pd-key")
        event = _make_event(decoy_name="web-decoy-03")
        payload = fwd._format_pagerduty(event)
        assert "web-decoy-03" in payload["payload"]["summary"]


# =========================================================================
# 6. HTTP Dispatch & Retry
# =========================================================================


class TestHTTPDispatchRetry:

    @pytest.mark.asyncio
    async def test_successful_post(self):
        fwd = AlertForwarder(webhook_url="https://hooks.slack.com/x")
        fwd._client = AsyncMock()
        fwd._client.post.return_value = httpx.Response(200)
        result = await fwd._post("https://hooks.slack.com/x", {"text": "hi"})
        assert result is True
        fwd._client.post.assert_called_once()

    @pytest.mark.asyncio
    async def test_non_retryable_error_400(self):
        fwd = AlertForwarder(webhook_url="https://hooks.slack.com/x")
        fwd._client = AsyncMock()
        fwd._client.post.return_value = httpx.Response(400, text="Bad Request")
        result = await fwd._post("https://hooks.slack.com/x", {"text": "hi"})
        assert result is False
        assert fwd._client.post.call_count == 1

    @pytest.mark.asyncio
    async def test_retryable_429_then_success(self):
        fwd = AlertForwarder(webhook_url="https://hooks.slack.com/x")
        fwd._client = AsyncMock()
        fwd._client.post.side_effect = [
            httpx.Response(429),
            httpx.Response(200),
        ]
        with patch("asyncio.sleep", new_callable=AsyncMock):
            result = await fwd._post("https://hooks.slack.com/x", {})
        assert result is True
        assert fwd._client.post.call_count == 2

    @pytest.mark.asyncio
    async def test_retryable_500_then_success(self):
        fwd = AlertForwarder(webhook_url="https://hooks.slack.com/x")
        fwd._client = AsyncMock()
        fwd._client.post.side_effect = [
            httpx.Response(500),
            httpx.Response(200),
        ]
        with patch("asyncio.sleep", new_callable=AsyncMock):
            result = await fwd._post("https://hooks.slack.com/x", {})
        assert result is True
        assert fwd._client.post.call_count == 2

    @pytest.mark.asyncio
    async def test_http_error_with_retry(self):
        fwd = AlertForwarder(webhook_url="https://hooks.slack.com/x")
        fwd._client = AsyncMock()
        fwd._client.post.side_effect = [
            httpx.ConnectError("connection refused"),
            httpx.Response(200),
        ]
        with patch("asyncio.sleep", new_callable=AsyncMock):
            result = await fwd._post("https://hooks.slack.com/x", {})
        assert result is True
        assert fwd._client.post.call_count == 2

    @pytest.mark.asyncio
    async def test_max_retries_exhausted(self):
        fwd = AlertForwarder(webhook_url="https://hooks.slack.com/x")
        fwd._client = AsyncMock()
        fwd._client.post.side_effect = httpx.ConnectError("down")
        with patch("asyncio.sleep", new_callable=AsyncMock):
            result = await fwd._post("https://hooks.slack.com/x", {})
        assert result is False
        assert fwd._client.post.call_count == 3

    @pytest.mark.asyncio
    async def test_successful_post_records_send(self):
        fwd = AlertForwarder(webhook_url="https://hooks.slack.com/x")
        fwd._client = AsyncMock()
        fwd._client.post.return_value = httpx.Response(200)
        assert len(fwd._send_times) == 0
        await fwd._post("https://hooks.slack.com/x", {})
        assert len(fwd._send_times) == 1

    @pytest.mark.asyncio
    async def test_failed_post_does_not_record_send(self):
        fwd = AlertForwarder(webhook_url="https://hooks.slack.com/x")
        fwd._client = AsyncMock()
        fwd._client.post.return_value = httpx.Response(400, text="bad")
        await fwd._post("https://hooks.slack.com/x", {})
        assert len(fwd._send_times) == 0


# =========================================================================
# 7. Close
# =========================================================================


class TestClose:

    @pytest.mark.asyncio
    async def test_client_closed_properly(self):
        fwd = AlertForwarder(webhook_url="https://hooks.slack.com/x")
        mock_client = AsyncMock()
        fwd._client = mock_client
        await fwd.close()
        mock_client.aclose.assert_awaited_once()
        assert fwd._client is None

    @pytest.mark.asyncio
    async def test_close_when_no_client(self):
        fwd = AlertForwarder(webhook_url="https://hooks.slack.com/x")
        assert fwd._client is None
        await fwd.close()  # should not raise
        assert fwd._client is None

    @pytest.mark.asyncio
    async def test_double_close_is_safe(self):
        fwd = AlertForwarder(webhook_url="https://hooks.slack.com/x")
        fwd._client = AsyncMock()
        await fwd.close()
        await fwd.close()  # second close should be safe
        assert fwd._client is None


# =========================================================================
# 8. Integration: maybe_send full flow
# =========================================================================


class TestMaybeSendIntegration:

    @pytest.mark.asyncio
    async def test_disabled_forwarder_returns_false(self):
        fwd = AlertForwarder()  # no URL or key
        event = _make_event(severity="critical")
        assert await fwd.maybe_send(event) is False

    @pytest.mark.asyncio
    async def test_below_severity_returns_false(self):
        fwd = AlertForwarder(
            webhook_url="https://hooks.slack.com/x", min_severity="critical"
        )
        event = _make_event(severity="high")
        assert await fwd.maybe_send(event) is False

    @pytest.mark.asyncio
    async def test_rate_limited_returns_false(self):
        fwd = AlertForwarder(
            webhook_url="https://hooks.slack.com/x",
            min_severity="info",
            rate_limit=1,
        )
        fwd._send_times = deque([time.monotonic()])
        event = _make_event(severity="critical")
        assert await fwd.maybe_send(event) is False

    @pytest.mark.asyncio
    async def test_successful_dispatch_returns_true(self):
        fwd = AlertForwarder(
            webhook_url="https://hooks.slack.com/x", min_severity="info"
        )
        event = _make_event(severity="high")
        with patch.object(fwd, "_dispatch", new_callable=AsyncMock, return_value=True):
            result = await fwd.maybe_send(event)
        assert result is True

    @pytest.mark.asyncio
    async def test_dispatch_routes_to_slack(self):
        fwd = AlertForwarder(
            webhook_url="https://hooks.slack.com/x", min_severity="info"
        )
        event = _make_event(severity="high")
        with patch.object(fwd, "_post", new_callable=AsyncMock, return_value=True) as mock_post:
            result = await fwd.maybe_send(event)
        assert result is True
        url_arg = mock_post.call_args[0][0]
        assert url_arg == "https://hooks.slack.com/x"
        payload_arg = mock_post.call_args[0][1]
        assert "blocks" in payload_arg

    @pytest.mark.asyncio
    async def test_dispatch_routes_to_teams(self):
        fwd = AlertForwarder(
            webhook_url="https://outlook.office.com/webhook/abc",
            min_severity="info",
        )
        event = _make_event(severity="high")
        with patch.object(fwd, "_post", new_callable=AsyncMock, return_value=True) as mock_post:
            result = await fwd.maybe_send(event)
        assert result is True
        payload_arg = mock_post.call_args[0][1]
        assert payload_arg["@type"] == "MessageCard"

    @pytest.mark.asyncio
    async def test_dispatch_routes_to_pagerduty(self):
        fwd = AlertForwarder(
            pagerduty_key="pd-key-abc", min_severity="info"
        )
        event = _make_event(severity="high")
        with patch.object(fwd, "_post", new_callable=AsyncMock, return_value=True) as mock_post:
            result = await fwd.maybe_send(event)
        assert result is True
        url_arg = mock_post.call_args[0][0]
        assert url_arg == PAGERDUTY_EVENTS_URL
        payload_arg = mock_post.call_args[0][1]
        assert payload_arg["routing_key"] == "pd-key-abc"

    @pytest.mark.asyncio
    async def test_dispatch_lazy_inits_client(self):
        fwd = AlertForwarder(
            webhook_url="https://hooks.slack.com/x", min_severity="info"
        )
        assert fwd._client is None
        with patch.object(fwd, "_post", new_callable=AsyncMock, return_value=True):
            await fwd.maybe_send(_make_event(severity="high"))
        assert fwd._client is not None
        await fwd.close()


# =========================================================================
# 9. Webhook URL Validation (SSRF prevention)
# =========================================================================


from alerting import _validate_webhook_url


class TestWebhookURLValidation:

    def test_valid_https_url(self):
        url = "https://hooks.slack.com/services/xxx"
        assert _validate_webhook_url(url) == url

    def test_valid_http_url(self):
        """HTTP URLs to non-private hosts should be accepted."""
        url = "http://webhook.example.com/hook"
        # Mock DNS resolution to return a public IP so it passes the resolver check
        with patch("socket.getaddrinfo", return_value=[
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 0)),
        ]):
            assert _validate_webhook_url(url) == url

    def test_rejects_loopback_127(self):
        with pytest.raises(ValueError, match="private|loopback"):
            _validate_webhook_url("http://127.0.0.1/hook")

    def test_rejects_loopback_localhost(self):
        """localhost resolves to 127.0.0.1 / ::1, which is loopback."""
        with pytest.raises(ValueError, match="private|loopback"):
            _validate_webhook_url("http://localhost/hook")

    def test_rejects_private_10(self):
        with pytest.raises(ValueError, match="private|loopback"):
            _validate_webhook_url("http://10.0.0.1/hook")

    def test_rejects_private_172(self):
        with pytest.raises(ValueError, match="private|loopback"):
            _validate_webhook_url("http://172.16.0.1/hook")

    def test_rejects_private_192(self):
        with pytest.raises(ValueError, match="private|loopback"):
            _validate_webhook_url("http://192.168.1.1/hook")

    def test_rejects_link_local(self):
        with pytest.raises(ValueError, match="private|loopback|link.local"):
            _validate_webhook_url("http://169.254.1.1/hook")

    def test_rejects_ftp_scheme(self):
        with pytest.raises(ValueError, match="scheme must be http or https"):
            _validate_webhook_url("ftp://example.com/hook")

    def test_rejects_file_scheme(self):
        with pytest.raises(ValueError, match="scheme must be http or https"):
            _validate_webhook_url("file:///etc/passwd")

    def test_rejects_internal_svc(self):
        with pytest.raises(ValueError, match="internal"):
            _validate_webhook_url("http://service.svc.cluster.local/hook")

    def test_rejects_internal_local(self):
        with pytest.raises(ValueError, match="internal"):
            _validate_webhook_url("http://myhost.local/hook")

    def test_rejects_empty_url(self):
        """Empty string should return empty (falsy), not raise."""
        result = _validate_webhook_url("")
        assert result == ""

    def test_rejects_none_url(self):
        """None should return None (falsy), not raise."""
        # The function checks `if not url:` which covers None
        result = _validate_webhook_url(None)
        assert result is None
