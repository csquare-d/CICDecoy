"""
CI/CDecoy — Falco Correlator Tests

Tests for Falco alert parsing, session correlation, container escape
detection, alert severity classification, and edge cases.
Uses mock asyncpg pool from conftest.py — no real DB or NATS required.
"""

import json
import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timezone

from falco_correlator import FalcoCorrelator

# Re-use the mock pool infrastructure from conftest
from conftest import MockAsyncpgPool, MockAsyncpgConn


# ── Helpers ───────────────────────────────────────────

def make_falco_alert(
    rule="CICDecoy — Write to kernel interface",
    priority="CRITICAL",
    pod_name="decoy-bastion-dmz-01-7f8b9c-x4k2",
    namespace="decoys-production",
    container="ssh-decoy",
    proc_name="bash",
    cmdline="echo 1 > /proc/sys/kernel/core_pattern",
    output="ESCAPE ATTEMPT: Write to kernel interface in decoy container",
    timestamp=None,
    extra_fields=None,
):
    """Build a realistic falcosidekick NATS payload."""
    fields = {
        "k8s.pod.name": pod_name,
        "k8s.ns.name": namespace,
        "container.name": container,
        "proc.name": proc_name,
        "proc.cmdline": cmdline,
    }
    if extra_fields:
        fields.update(extra_fields)

    return {
        "rule": rule,
        "priority": priority,
        "output": output,
        "time": timestamp or datetime.now(timezone.utc).isoformat(),
        "output_fields": fields,
    }


class SessionAwareConn(MockAsyncpgConn):
    """Mock connection that can return a session_id for active session lookup."""

    def __init__(self, session_id=None):
        self._session_id = session_id

    async def fetchrow(self, query, *args):
        if "session_id" in query and self._session_id:
            return {"session_id": self._session_id}
        return None

    async def execute(self, query, *args):
        pass


class SessionAwarePool(MockAsyncpgPool):
    """Mock pool that uses SessionAwareConn."""

    def __init__(self, session_id=None):
        self.conn = SessionAwareConn(session_id=session_id)

    def acquire(self):
        from conftest import _AcquireContext
        return _AcquireContext(self.conn)


# ══════════════════════════════════════════════════════
#  Pod Name Parsing
# ══════════════════════════════════════════════════════


class TestPodToDecoyName:

    def test_standard_pod_name(self):
        name = FalcoCorrelator._pod_to_decoy_name(
            "decoy-bastion-dmz-01-7f8b9c-x4k2")
        assert name == "bastion-dmz-01"

    def test_simple_pod_name(self):
        name = FalcoCorrelator._pod_to_decoy_name(
            "decoy-webserver-abc123-def456")
        assert name == "webserver"

    def test_non_decoy_pod_returned_as_is(self):
        name = FalcoCorrelator._pod_to_decoy_name("nginx-proxy-abc123-def456")
        assert name == "nginx-proxy-abc123-def456"

    def test_decoy_prefix_only(self):
        name = FalcoCorrelator._pod_to_decoy_name("decoy-short")
        assert name == "short"

    def test_empty_pod_name(self):
        name = FalcoCorrelator._pod_to_decoy_name("")
        assert name == ""

    def test_decoy_prefix_two_segments(self):
        name = FalcoCorrelator._pod_to_decoy_name("decoy-name-hash")
        assert name == "name-hash"


# ══════════════════════════════════════════════════════
#  ATT&CK Mapping
# ══════════════════════════════════════════════════════


class TestFalcoAttackMap:

    def test_kernel_write_maps_to_t1611(self):
        tid, tname = FalcoCorrelator.FALCO_ATTACK_MAP[
            "CICDecoy — Write to kernel interface"]
        assert tid == "T1611"
        assert tname == "Escape to Host"

    def test_mount_syscall_maps_to_t1611(self):
        tid, _ = FalcoCorrelator.FALCO_ATTACK_MAP[
            "CICDecoy — Mount syscall in decoy"]
        assert tid == "T1611"

    def test_ptrace_maps_to_t1055(self):
        tid, tname = FalcoCorrelator.FALCO_ATTACK_MAP[
            "CICDecoy — Ptrace from decoy container"]
        assert tid == "T1055"
        assert tname == "Process Injection"

    def test_unexpected_shell_maps_to_t1059(self):
        tid, _ = FalcoCorrelator.FALCO_ATTACK_MAP[
            "CICDecoy — Unexpected shell in decoy"]
        assert tid == "T1059.004"

    def test_internet_connection_maps_to_t1048(self):
        tid, _ = FalcoCorrelator.FALCO_ATTACK_MAP[
            "CICDecoy — Internet connection from decoy"]
        assert tid == "T1048"

    def test_container_escape_recon_maps_to_t1082(self):
        tid, _ = FalcoCorrelator.FALCO_ATTACK_MAP[
            "CICDecoy — Container escape recon in decoy"]
        assert tid == "T1082"

    def test_privilege_escalation_maps_to_t1548(self):
        tid, _ = FalcoCorrelator.FALCO_ATTACK_MAP[
            "CICDecoy — Privilege escalation in decoy"]
        assert tid == "T1548"

    def test_binary_execution_maps_to_t1204(self):
        tid, _ = FalcoCorrelator.FALCO_ATTACK_MAP[
            "CICDecoy — Binary execution in decoy"]
        assert tid == "T1204.002"

    def test_all_rules_have_mappings(self):
        """Every known Falco rule name should have an ATT&CK mapping."""
        expected_rules = [
            "CICDecoy — Write to kernel interface",
            "CICDecoy — Mount syscall in decoy",
            "CICDecoy — Ptrace from decoy container",
            "CICDecoy — Kernel module load from decoy",
            "CICDecoy — Unexpected shell in decoy",
            "CICDecoy — Unexpected outbound connection",
            "CICDecoy — Internet connection from decoy",
            "CICDecoy — Container escape recon in decoy",
            "CICDecoy — Privilege escalation in decoy",
            "CICDecoy — Binary execution in decoy",
        ]
        for rule in expected_rules:
            assert rule in FalcoCorrelator.FALCO_ATTACK_MAP, \
                f"Missing ATT&CK mapping for rule: {rule}"


# ══════════════════════════════════════════════════════
#  Alert Processing (process_alert)
# ══════════════════════════════════════════════════════


class TestProcessAlert:

    @pytest.mark.asyncio
    async def test_process_alert_increments_count(self):
        pool = MockAsyncpgPool()
        correlator = FalcoCorrelator(pool)
        await correlator.process_alert(make_falco_alert())
        assert correlator.alert_count == 1

    @pytest.mark.asyncio
    async def test_process_multiple_alerts(self):
        pool = MockAsyncpgPool()
        correlator = FalcoCorrelator(pool)
        await correlator.process_alert(make_falco_alert())
        await correlator.process_alert(make_falco_alert(
            rule="CICDecoy — Mount syscall in decoy"))
        await correlator.process_alert(make_falco_alert(
            rule="CICDecoy — Ptrace from decoy container"))
        assert correlator.alert_count == 3

    @pytest.mark.asyncio
    async def test_alert_without_pod_name_skipped(self):
        pool = MockAsyncpgPool()
        correlator = FalcoCorrelator(pool)
        alert = make_falco_alert(pod_name="")
        await correlator.process_alert(alert)
        # Alert count should not increment because we return early
        assert correlator.alert_count == 1
        assert correlator.correlated_count == 0

    @pytest.mark.asyncio
    async def test_correlated_count_when_session_found(self):
        pool = SessionAwarePool(session_id="sess-test-123")
        correlator = FalcoCorrelator(pool)
        await correlator.process_alert(make_falco_alert())
        assert correlator.correlated_count == 1

    @pytest.mark.asyncio
    async def test_no_correlation_when_no_active_session(self):
        pool = SessionAwarePool(session_id=None)
        correlator = FalcoCorrelator(pool)
        await correlator.process_alert(make_falco_alert())
        assert correlator.correlated_count == 0

    @pytest.mark.asyncio
    async def test_execute_called_for_insert(self):
        pool = MockAsyncpgPool()
        pool.conn.execute = AsyncMock()
        correlator = FalcoCorrelator(pool)
        await correlator.process_alert(make_falco_alert())
        # Should have called execute for the INSERT INTO falco_alerts
        pool.conn.execute.assert_called()
        call_args = pool.conn.execute.call_args_list[0]
        assert "INSERT INTO falco_alerts" in call_args[0][0]


# ══════════════════════════════════════════════════════
#  Session Correlation
# ══════════════════════════════════════════════════════


class TestSessionCorrelation:

    @pytest.mark.asyncio
    async def test_find_active_session_returns_session_id(self):
        pool = SessionAwarePool(session_id="sess-abc-123")
        correlator = FalcoCorrelator(pool)
        result = await correlator._find_active_session(
            "bastion-dmz-01", datetime.now(timezone.utc).isoformat())
        assert result == "sess-abc-123"

    @pytest.mark.asyncio
    async def test_find_active_session_returns_empty_for_no_match(self):
        pool = SessionAwarePool(session_id=None)
        correlator = FalcoCorrelator(pool)
        result = await correlator._find_active_session(
            "nonexistent-decoy", datetime.now(timezone.utc).isoformat())
        assert result == ""

    @pytest.mark.asyncio
    async def test_find_active_session_empty_decoy_name(self):
        pool = SessionAwarePool(session_id="sess-abc-123")
        correlator = FalcoCorrelator(pool)
        result = await correlator._find_active_session(
            "", datetime.now(timezone.utc).isoformat())
        assert result == ""


# ══════════════════════════════════════════════════════
#  Escape Attempt Marking
# ══════════════════════════════════════════════════════


class TestMarkEscapeAttempt:

    @pytest.mark.asyncio
    async def test_mark_escape_calls_execute(self):
        pool = MockAsyncpgPool()
        pool.conn.execute = AsyncMock()
        correlator = FalcoCorrelator(pool)
        await correlator._mark_escape_attempt(
            "sess-123", "bastion-dmz-01",
            "CICDecoy — Write to kernel interface")
        pool.conn.execute.assert_called_once()
        call_sql = pool.conn.execute.call_args[0][0]
        assert "engage_outcomes" in call_sql
        assert "escape_attempted" in call_sql
        assert "deception_maintained" in call_sql

    @pytest.mark.asyncio
    async def test_mark_escape_passes_correct_args(self):
        pool = MockAsyncpgPool()
        pool.conn.execute = AsyncMock()
        correlator = FalcoCorrelator(pool)
        await correlator._mark_escape_attempt(
            "sess-xyz", "my-decoy", "SomeRule")
        args = pool.conn.execute.call_args[0]
        assert args[1] == "sess-xyz"
        assert args[2] == "my-decoy"


# ══════════════════════════════════════════════════════
#  Escape Event Injection
# ══════════════════════════════════════════════════════


class TestInjectEscapeEvent:

    @pytest.mark.asyncio
    async def test_inject_escape_event_calls_execute(self):
        pool = MockAsyncpgPool()
        pool.conn.execute = AsyncMock()
        correlator = FalcoCorrelator(pool)
        await correlator._inject_escape_event(
            session_id="sess-001",
            decoy_name="bastion-01",
            timestamp=datetime.now(timezone.utc).isoformat(),
            rule="CICDecoy — Write to kernel interface",
            priority="CRITICAL",
            proc_name="bash",
            cmdline="echo payload > /proc/sys/kernel/core_pattern",
            pod_name="decoy-bastion-01-abc-def",
        )
        pool.conn.execute.assert_called_once()
        call_sql = pool.conn.execute.call_args[0][0]
        assert "INSERT INTO decoy_events" in call_sql
        assert "falco.escape" in call_sql

    @pytest.mark.asyncio
    async def test_inject_escape_event_uses_attack_map(self):
        pool = MockAsyncpgPool()
        pool.conn.execute = AsyncMock()
        correlator = FalcoCorrelator(pool)
        await correlator._inject_escape_event(
            session_id="sess-002",
            decoy_name="web-01",
            timestamp="2026-01-15T12:00:00Z",
            rule="CICDecoy — Ptrace from decoy container",
            priority="CRITICAL",
            proc_name="gdb",
            cmdline="gdb -p 1",
            pod_name="decoy-web-01-abc-def",
        )
        # Check the mitre_techniques JSON arg contains T1055
        call_args = pool.conn.execute.call_args[0]
        mitre_json = call_args[5]  # 6th positional arg
        mitre_data = json.loads(mitre_json)
        assert mitre_data[0]["technique_id"] == "T1055"

    @pytest.mark.asyncio
    async def test_inject_escape_event_unknown_rule_defaults_to_t1611(self):
        pool = MockAsyncpgPool()
        pool.conn.execute = AsyncMock()
        correlator = FalcoCorrelator(pool)
        await correlator._inject_escape_event(
            session_id="sess-003",
            decoy_name="test-01",
            timestamp="2026-01-15T12:00:00Z",
            rule="Some Unknown Rule",
            priority="WARNING",
            proc_name="unknown",
            cmdline="unknown",
            pod_name="decoy-test-01-abc-def",
        )
        call_args = pool.conn.execute.call_args[0]
        mitre_json = call_args[5]
        mitre_data = json.loads(mitre_json)
        assert mitre_data[0]["technique_id"] == "T1611"
        assert mitre_data[0]["technique_name"] == "Escape to Host"

    @pytest.mark.asyncio
    async def test_inject_escape_event_raw_data_structure(self):
        pool = MockAsyncpgPool()
        pool.conn.execute = AsyncMock()
        correlator = FalcoCorrelator(pool)
        await correlator._inject_escape_event(
            session_id="sess-004",
            decoy_name="db-01",
            timestamp="2026-01-15T12:00:00Z",
            rule="CICDecoy — Mount syscall in decoy",
            priority="CRITICAL",
            proc_name="mount",
            cmdline="mount -t proc proc /mnt",
            pod_name="decoy-db-01-abc-def",
        )
        call_args = pool.conn.execute.call_args[0]
        raw_json = call_args[6]  # 7th positional arg
        raw_data = json.loads(raw_json)
        assert raw_data["source"] == "falco"
        assert raw_data["rule"] == "CICDecoy — Mount syscall in decoy"
        assert raw_data["severity"] == "critical"
        assert raw_data["behavior"] == "container_escape"
        assert raw_data["process"] == "mount"
        assert raw_data["command_line"] == "mount -t proc proc /mnt"


# ══════════════════════════════════════════════════════
#  Full Pipeline: process_alert with correlated session
# ══════════════════════════════════════════════════════


class TestFullCorrelationPipeline:

    @pytest.mark.asyncio
    async def test_correlated_alert_marks_escape_and_injects_event(self):
        pool = SessionAwarePool(session_id="sess-full-test")
        pool.conn.execute = AsyncMock()
        correlator = FalcoCorrelator(pool)
        await correlator.process_alert(make_falco_alert())

        assert correlator.correlated_count == 1
        # Should have 3 execute calls:
        # 1. INSERT INTO falco_alerts
        # 2. INSERT INTO engage_outcomes (mark_escape_attempt)
        # 3. INSERT INTO decoy_events (inject_escape_event)
        assert pool.conn.execute.call_count == 3

        calls_sql = [c[0][0] for c in pool.conn.execute.call_args_list]
        assert any("falco_alerts" in sql for sql in calls_sql)
        assert any("engage_outcomes" in sql for sql in calls_sql)
        assert any("decoy_events" in sql for sql in calls_sql)

    @pytest.mark.asyncio
    async def test_uncorrelated_alert_only_stores(self):
        pool = SessionAwarePool(session_id=None)
        pool.conn.execute = AsyncMock()
        correlator = FalcoCorrelator(pool)
        await correlator.process_alert(make_falco_alert())

        assert correlator.correlated_count == 0
        # Only 1 execute call: INSERT INTO falco_alerts
        assert pool.conn.execute.call_count == 1
        assert "falco_alerts" in pool.conn.execute.call_args[0][0]


# ══════════════════════════════════════════════════════
#  Stats Property
# ══════════════════════════════════════════════════════


class TestStats:

    def test_initial_stats(self):
        pool = MockAsyncpgPool()
        correlator = FalcoCorrelator(pool)
        stats = correlator.stats
        assert stats["total_alerts"] == 0
        assert stats["correlated"] == 0
        assert stats["correlation_rate"] == 0

    @pytest.mark.asyncio
    async def test_stats_after_alerts(self):
        pool = SessionAwarePool(session_id="sess-1")
        correlator = FalcoCorrelator(pool)
        pool.conn.execute = AsyncMock()
        await correlator.process_alert(make_falco_alert())
        await correlator.process_alert(make_falco_alert())

        # Change pool to return no session for next alert
        pool.conn = SessionAwareConn(session_id=None)
        await correlator.process_alert(make_falco_alert())

        stats = correlator.stats
        assert stats["total_alerts"] == 3
        assert stats["correlated"] == 2
        assert stats["correlation_rate"] == pytest.approx(66.7, abs=0.1)


# ══════════════════════════════════════════════════════
#  Edge Cases
# ══════════════════════════════════════════════════════


class TestEdgeCases:

    @pytest.mark.asyncio
    async def test_missing_output_fields(self):
        """Alert with empty output_fields should not crash."""
        pool = MockAsyncpgPool()
        correlator = FalcoCorrelator(pool)
        alert = {
            "rule": "CICDecoy — Unknown rule",
            "priority": "WARNING",
            "output": "some output",
            "time": datetime.now(timezone.utc).isoformat(),
            "output_fields": {},
        }
        await correlator.process_alert(alert)
        # No pod name means early return after incrementing alert_count
        assert correlator.alert_count == 1
        assert correlator.correlated_count == 0

    @pytest.mark.asyncio
    async def test_missing_rule_field(self):
        """Alert with no rule field should still be processable."""
        pool = MockAsyncpgPool()
        correlator = FalcoCorrelator(pool)
        alert = make_falco_alert(rule="")
        await correlator.process_alert(alert)
        assert correlator.alert_count == 1

    @pytest.mark.asyncio
    async def test_missing_time_field_uses_now(self):
        """Alert without a time field should default to now."""
        pool = MockAsyncpgPool()
        pool.conn.execute = AsyncMock()
        correlator = FalcoCorrelator(pool)
        alert = make_falco_alert()
        del alert["time"]
        await correlator.process_alert(alert)
        # Should not crash; timestamp is extracted with a default
        assert correlator.alert_count == 1

    @pytest.mark.asyncio
    async def test_completely_empty_alert(self):
        """A fully empty dict should not crash (no pod -> early return)."""
        pool = MockAsyncpgPool()
        correlator = FalcoCorrelator(pool)
        await correlator.process_alert({})
        assert correlator.alert_count == 1
        assert correlator.correlated_count == 0

    @pytest.mark.asyncio
    async def test_alert_with_no_output_fields_key(self):
        """Alert missing the output_fields key entirely."""
        pool = MockAsyncpgPool()
        correlator = FalcoCorrelator(pool)
        alert = {
            "rule": "CICDecoy — Write to kernel interface",
            "priority": "CRITICAL",
            "output": "some output",
        }
        await correlator.process_alert(alert)
        assert correlator.alert_count == 1
        assert correlator.correlated_count == 0

    @pytest.mark.asyncio
    async def test_non_decoy_pod_name(self):
        """Alert from a non-decoy pod should still be stored."""
        pool = MockAsyncpgPool()
        pool.conn.execute = AsyncMock()
        correlator = FalcoCorrelator(pool)
        alert = make_falco_alert(pod_name="nginx-proxy-abc123-def456")
        await correlator.process_alert(alert)
        assert correlator.alert_count == 1
        pool.conn.execute.assert_called()


# ══════════════════════════════════════════════════════
#  Alert Severity Classification
# ══════════════════════════════════════════════════════


class TestAlertSeverity:

    def test_escape_rules_are_critical(self):
        """All container escape Falco rules should map to T1611."""
        escape_rules = [
            "CICDecoy — Write to kernel interface",
            "CICDecoy — Mount syscall in decoy",
            "CICDecoy — Kernel module load from decoy",
        ]
        for rule in escape_rules:
            tid, _ = FalcoCorrelator.FALCO_ATTACK_MAP[rule]
            assert tid == "T1611", f"Rule '{rule}' should map to T1611"

    def test_recon_rule_maps_to_discovery(self):
        tid, tname = FalcoCorrelator.FALCO_ATTACK_MAP[
            "CICDecoy — Container escape recon in decoy"]
        assert tid == "T1082"
        assert tname == "System Information Discovery"

    def test_outbound_connection_maps_to_remote_services(self):
        tid, tname = FalcoCorrelator.FALCO_ATTACK_MAP[
            "CICDecoy — Unexpected outbound connection"]
        assert tid == "T1021"
        assert tname == "Remote Services"
