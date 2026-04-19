"""
CI/CDecoy — Integration Tests: Event Pipeline

Verifies the NATS -> CTI enrichment pipeline works end-to-end for both
SSH and HTTP events.  Uses real enrichment logic (no mocks on the
classification layer) while mocking external services (NATS, DB, GeoIP).
"""

import uuid
from datetime import datetime, timezone

import pytest

from enrichment import enrich_event
from session_analyzer import SessionAnalyzer

# ── Helpers ───────────────────────────────────────────


def _make_raw_ssh_event(
    command: str = "",
    source_ip: str = "198.51.100.42",
    session_id: str | None = None,
    event_type: str = "command.exec",
) -> dict:
    """Build a raw SSH decoy event as the pipeline would receive it."""
    return {
        "event_id": f"evt-{uuid.uuid4().hex[:12]}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "decoy_name": "ssh-decoy-01",
        "decoy_tier": 2,
        "session_id": session_id or f"sess-{uuid.uuid4().hex[:12]}",
        "event_type": event_type,
        "source_ip": source_ip,
        "source_port": 44120,
        "data": {
            "command": command,
            "client_ip": source_ip,
        },
    }


def _make_raw_http_event(
    enrichment: dict,
    path: str = "/admin/login",
    method: str = "GET",
    source_ip: str = "203.0.113.10",
    session_id: str | None = None,
) -> dict:
    """Build a raw HTTP decoy event with pre-classified enrichment."""
    return {
        "event_id": f"evt-{uuid.uuid4().hex[:12]}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "decoy_name": "http-decoy-01",
        "decoy_tier": 1,
        "session_id": session_id or f"sess-{uuid.uuid4().hex[:12]}",
        "event_type": "http.request",
        "source_ip": source_ip,
        "source_port": 52301,
        "data": {
            "client_ip": source_ip,
            "path": path,
            "method": method,
            "enrichment": enrichment,
        },
    }


# ═══════════════════════════════════════════════════════
#  1. SSH command event enrichment
# ═══════════════════════════════════════════════════════


class TestSSHCommandEventEnriched:
    """An SSH event with 'cat /etc/passwd' should map to credential-access."""

    def test_enrichment_detects_mitre_technique(self):
        raw = _make_raw_ssh_event(command="cat /etc/passwd")
        result = enrich_event(raw)

        assert result["mitre_techniques"], "Expected at least one MITRE technique"
        technique_ids = [t["technique_id"] for t in result["mitre_techniques"]]
        # T1003.008 = /etc/passwd and /etc/shadow
        assert any(
            tid.startswith("T1003") for tid in technique_ids
        ), f"Expected T1003.x in {technique_ids}"

    def test_severity_is_not_info(self):
        raw = _make_raw_ssh_event(command="cat /etc/passwd")
        result = enrich_event(raw)
        assert result["severity"] != "info", "Credential access should not be info"

    def test_tags_include_tactic(self):
        raw = _make_raw_ssh_event(command="cat /etc/passwd")
        result = enrich_event(raw)
        assert "credential-access" in result["tags"]


# ═══════════════════════════════════════════════════════
#  2. HTTP event enrichment (passthrough)
# ═══════════════════════════════════════════════════════


class TestHTTPEventEnriched:
    """HTTP events carry pre-classified enrichment from the HTTP decoy."""

    def test_technique_passthrough(self):
        enrichment = {
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "tactic": "initial-access",
            "severity": "high",
            "tool_signature": "sqlmap/1.7",
            "tags": ["scanner"],
        }
        raw = _make_raw_http_event(enrichment=enrichment, path="/api/users?id=1")
        result = enrich_event(raw)

        assert len(result["mitre_techniques"]) == 1
        tech = result["mitre_techniques"][0]
        assert tech["technique_id"] == "T1190"
        assert tech["tactic"] == "initial-access"

    def test_tool_signature_preserved(self):
        enrichment = {
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "tactic": "initial-access",
            "severity": "high",
            "tool_signature": "sqlmap/1.7",
        }
        raw = _make_raw_http_event(enrichment=enrichment)
        result = enrich_event(raw)

        assert "sqlmap/1.7" in result["tool_signatures"]

    def test_severity_passthrough(self):
        enrichment = {
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "tactic": "initial-access",
            "severity": "high",
        }
        raw = _make_raw_http_event(enrichment=enrichment)
        result = enrich_event(raw)

        assert result["severity"] == "high"

    def test_tags_include_tactic_and_custom(self):
        enrichment = {
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "tactic": "initial-access",
            "severity": "medium",
            "tags": ["scanner", "automated"],
        }
        raw = _make_raw_http_event(enrichment=enrichment)
        result = enrich_event(raw)

        assert "initial-access" in result["tags"]
        assert "scanner" in result["tags"]
        assert "automated" in result["tags"]


# ═══════════════════════════════════════════════════════
#  3. HTTP injection event enrichment
# ═══════════════════════════════════════════════════════


class TestHTTPInjectionEventEnriched:
    """HTTP events with injection payloads should preserve severity and tags."""

    def test_injection_severity_preserved(self):
        enrichment = {
            "technique_id": "T1059.007",
            "technique_name": "JavaScript",
            "tactic": "execution",
            "severity": "critical",
            "tags": ["xss", "injection"],
        }
        raw = _make_raw_http_event(
            enrichment=enrichment,
            path="/search?q=<script>alert(1)</script>",
        )
        result = enrich_event(raw)

        assert result["severity"] == "critical"

    def test_injection_technique_preserved(self):
        enrichment = {
            "technique_id": "T1059.007",
            "technique_name": "JavaScript",
            "tactic": "execution",
            "severity": "high",
            "tags": ["xss", "injection"],
        }
        raw = _make_raw_http_event(
            enrichment=enrichment,
            path="/search?q=<script>alert(1)</script>",
        )
        result = enrich_event(raw)

        assert result["mitre_techniques"][0]["technique_id"] == "T1059.007"
        assert "xss" in result["tags"]
        assert "injection" in result["tags"]


# ═══════════════════════════════════════════════════════
#  4. SSH event without command => severity "info"
# ═══════════════════════════════════════════════════════


class TestSSHEventNoCommand:
    """An SSH event with no command should return info severity."""

    def test_no_command_returns_info(self):
        raw = _make_raw_ssh_event(command="", event_type="session.start")
        result = enrich_event(raw)

        assert result["severity"] == "info"
        assert result["mitre_techniques"] == []

    def test_no_command_empty_techniques(self):
        raw = _make_raw_ssh_event(command="")
        result = enrich_event(raw)

        assert result["mitre_techniques"] == []
        assert result["tool_signatures"] == []


# ═══════════════════════════════════════════════════════
#  5. GeoIP enrichment key presence
# ═══════════════════════════════════════════════════════


class TestGeoIPEnrichment:
    """The geo dict should always be present in the enrichment result."""

    def test_geo_key_exists_public_ip(self):
        raw = _make_raw_ssh_event(
            command="whoami",
            source_ip="8.8.8.8",
        )
        result = enrich_event(raw)

        assert "geo" in result, "geo key must be present in enrichment"
        assert isinstance(result["geo"], dict)

    def test_geo_key_exists_private_ip(self):
        raw = _make_raw_ssh_event(
            command="id",
            source_ip="192.168.1.1",
        )
        result = enrich_event(raw)

        assert "geo" in result
        assert isinstance(result["geo"], dict)
        # Private IPs should be flagged
        assert result["geo"].get("private") is True

    def test_geo_key_exists_empty_ip(self):
        raw = _make_raw_ssh_event(command="ls", source_ip="")
        result = enrich_event(raw)

        assert "geo" in result
        assert isinstance(result["geo"], dict)


# ═══════════════════════════════════════════════════════
#  6. SessionAnalyzer ingestion
# ═══════════════════════════════════════════════════════


class TestSessionAnalyzerIngestion:
    """Feed multiple enriched events into SessionAnalyzer and verify tracking."""

    async def _enrich_and_ingest(self, analyzer, session_id, command):
        """Helper: enrich a raw SSH event, then ingest into analyzer."""
        raw = _make_raw_ssh_event(command=command, session_id=session_id)
        enrichment = enrich_event(raw)
        payload = {
            "event_type": "command.exec",
            "mitre_techniques": enrichment["mitre_techniques"],
            "tool_signatures": enrichment["tool_signatures"],
            "severity": enrichment["severity"],
            "tags": enrichment["tags"],
            "data": raw.get("data", {}),
        }
        return await analyzer.ingest(session_id, payload)

    @pytest.mark.asyncio
    async def test_techniques_tracked_across_events(self):
        analyzer = SessionAnalyzer()
        sid = f"sess-{uuid.uuid4().hex[:12]}"

        await self._enrich_and_ingest(analyzer, sid, "whoami")
        await self._enrich_and_ingest(analyzer, sid, "cat /etc/passwd")
        verdict = await self._enrich_and_ingest(analyzer, sid, "uname -a")

        # Should have accumulated multiple phases
        assert verdict["kill_chain_phases"] >= 1
        assert verdict["behavioral_score"] > 0.0

    @pytest.mark.asyncio
    async def test_session_close_returns_summary(self):
        analyzer = SessionAnalyzer()
        sid = f"sess-{uuid.uuid4().hex[:12]}"

        await self._enrich_and_ingest(analyzer, sid, "whoami")
        await self._enrich_and_ingest(analyzer, sid, "cat /etc/shadow")

        summary = await analyzer.close_session(sid)
        assert summary is not None
        assert summary["session_id"] == sid
        assert summary["command_count"] >= 2
        assert len(summary["techniques_observed"]) >= 1
        assert summary["classification"] != "unknown"

    @pytest.mark.asyncio
    async def test_multiple_sessions_independent(self):
        analyzer = SessionAnalyzer()
        sid_a = f"sess-{uuid.uuid4().hex[:12]}"
        sid_b = f"sess-{uuid.uuid4().hex[:12]}"

        await self._enrich_and_ingest(analyzer, sid_a, "whoami")
        await self._enrich_and_ingest(analyzer, sid_b, "cat /etc/shadow")

        assert analyzer.active_session_count == 2

        summary_a = await analyzer.close_session(sid_a)
        summary_b = await analyzer.close_session(sid_b)

        assert summary_a["session_id"] == sid_a
        assert summary_b["session_id"] == sid_b
        # Session B accessed shadow, should be higher severity
        assert summary_b["max_severity"] != "info"

    @pytest.mark.asyncio
    async def test_verdict_keys_present(self):
        analyzer = SessionAnalyzer()
        sid = f"sess-{uuid.uuid4().hex[:12]}"

        verdict = await self._enrich_and_ingest(analyzer, sid, "id")

        expected_keys = {
            "kill_chain_detected",
            "kill_chain_phases",
            "phase_progression",
            "session_severity",
            "behavioral_score",
            "session_classification",
            "alert_triggers",
        }
        assert expected_keys.issubset(verdict.keys()), (
            f"Missing keys: {expected_keys - verdict.keys()}"
        )
