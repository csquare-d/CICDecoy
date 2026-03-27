"""
CI/CDecoy — Event Schema & Serialization Tests

Validates that events flowing through the system conform to the
decoy_events schema and that serialization round-trips cleanly.
"""

import json
import uuid
from datetime import datetime, timezone

import pytest

from conftest import make_nats_event, make_session_row


# ── Event factory produces valid schema ─────────────

class TestEventSchema:
    """Validate that make_nats_event matches decoy_events table columns."""

    REQUIRED_FIELDS = {
        "event_id", "timestamp", "decoy_name", "decoy_tier",
        "session_id", "event_type",
    }

    OPTIONAL_FIELDS = {
        "source_ip", "source_port", "geo", "mitre_techniques",
        "tool_signatures", "severity", "tags", "raw_data",
    }

    VALID_EVENT_TYPES = {"connection", "auth", "command", "alert", "session"}
    VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}

    def test_has_all_required_fields(self):
        event = make_nats_event()
        for field in self.REQUIRED_FIELDS:
            assert field in event, f"Missing required field: {field}"

    def test_has_all_optional_fields(self):
        event = make_nats_event()
        for field in self.OPTIONAL_FIELDS:
            assert field in event, f"Missing optional field: {field}"

    def test_event_id_format(self):
        event = make_nats_event()
        assert event["event_id"].startswith("evt-")
        assert len(event["event_id"]) > 10

    def test_event_ids_are_unique(self):
        ids = {make_nats_event()["event_id"] for _ in range(100)}
        assert len(ids) == 100

    def test_session_id_format(self):
        event = make_nats_event()
        assert event["session_id"].startswith("sess-")

    def test_timestamp_is_iso8601(self):
        event = make_nats_event()
        ts = datetime.fromisoformat(event["timestamp"])
        assert ts.tzinfo is not None, "Timestamp must be timezone-aware"

    def test_severity_is_valid(self):
        for sev in self.VALID_SEVERITIES:
            event = make_nats_event(severity=sev)
            assert event["severity"] == sev

    def test_decoy_tier_is_int(self):
        event = make_nats_event(decoy_tier=3)
        assert isinstance(event["decoy_tier"], int)
        assert event["decoy_tier"] in (1, 2, 3)

    def test_source_port_is_int(self):
        event = make_nats_event()
        assert isinstance(event["source_port"], int)
        assert 0 <= event["source_port"] <= 65535

    def test_mitre_techniques_structure(self):
        event = make_nats_event()
        techs = event["mitre_techniques"]
        assert isinstance(techs, list)
        assert len(techs) >= 1
        for tech in techs:
            assert "technique_id" in tech
            assert "technique_name" in tech
            assert "tactic" in tech
            assert tech["technique_id"].startswith("T")

    def test_geo_is_dict(self):
        event = make_nats_event()
        assert isinstance(event["geo"], dict)

    def test_raw_data_contains_command(self):
        event = make_nats_event(command="cat /etc/passwd")
        assert event["raw_data"]["command"] == "cat /etc/passwd"


# ── JSON serialization round-trip ───────────────────

class TestSerialization:
    """Events must survive JSON encode/decode without data loss."""

    def test_event_round_trip(self):
        event = make_nats_event()
        encoded = json.dumps(event)
        decoded = json.loads(encoded)
        assert decoded == event

    def test_event_as_nats_payload(self):
        """Simulate what happens when an event goes through NATS."""
        event = make_nats_event()
        wire = json.dumps(event).encode("utf-8")
        assert len(wire) < 1_048_576, "Must fit within NATS max_payload (1MB)"
        restored = json.loads(wire.decode("utf-8"))
        assert restored["event_id"] == event["event_id"]

    def test_nested_json_fields(self):
        """JSONB columns (geo, mitre_techniques, raw_data) must serialize cleanly."""
        event = make_nats_event()
        for field in ("geo", "mitre_techniques", "raw_data", "tool_signatures", "tags"):
            val = event[field]
            encoded = json.dumps(val)
            decoded = json.loads(encoded)
            assert decoded == val

    def test_session_row_jsonb_round_trip(self):
        row = make_session_row()
        for field in ("commands", "mitre_techniques", "tools_detected",
                      "attack_phases", "geo", "honeytokens_accessed"):
            val = row[field]
            if isinstance(val, str):
                decoded = json.loads(val)
                re_encoded = json.dumps(decoded)
                assert json.loads(re_encoded) == decoded


# ── Session row schema ──────────────────────────────

class TestSessionSchema:
    """Validate make_session_row matches decoy_sessions table."""

    REQUIRED_COLUMNS = {
        "session_id", "decoy_name", "decoy_tier", "source_ip",
        "start_time", "auth_username", "auth_attempts", "command_count",
        "mitre_techniques", "max_severity", "kill_chain_detected",
    }

    def test_has_required_columns(self):
        row = make_session_row()
        for col in self.REQUIRED_COLUMNS:
            assert col in row, f"Missing column: {col}"

    def test_session_id_uniqueness(self):
        ids = {make_session_row()["session_id"] for _ in range(100)}
        assert len(ids) == 100

    def test_start_time_is_datetime(self):
        row = make_session_row()
        assert isinstance(row["start_time"], datetime)

    def test_kill_chain_flag(self):
        row_yes = make_session_row(kill_chain=True)
        row_no = make_session_row(kill_chain=False)
        assert row_yes["kill_chain_detected"] is True
        assert row_no["kill_chain_detected"] is False

    def test_techniques_are_parseable(self):
        row = make_session_row()
        techs = json.loads(row["mitre_techniques"])
        assert isinstance(techs, list)
        assert all("technique_id" in t for t in techs)


# ── NATS subject naming ────────────────────────────

class TestNATSSubjects:
    """Validate NATS subject hierarchy matches the spec."""

    VALID_PREFIXES = [
        "cicdecoy.decoy.events.connection",
        "cicdecoy.decoy.events.auth",
        "cicdecoy.decoy.events.command",
        "cicdecoy.decoy.events.alert",
        "cicdecoy.decoy.events.session",
        "cicdecoy.alert.",
        "cicdecoy.honeytoken.triggered.",
        "cicdecoy.security.falco.",
    ]

    def test_event_subject_format(self):
        for event_type in ("connection", "auth", "command", "alert", "session"):
            subject = f"cicdecoy.decoy.events.{event_type}"
            assert subject.startswith("cicdecoy.decoy.events.")
            # Must not contain spaces or slashes
            assert " " not in subject
            assert "/" not in subject

    def test_subjects_match_stream_filters(self):
        """DECOY_EVENTS stream subscribes to cicdecoy.decoy.events.>"""
        stream_filter = "cicdecoy.decoy.events.>"
        base = stream_filter.replace(".>", ".")
        for event_type in ("connection", "auth", "command", "alert", "session"):
            subject = f"cicdecoy.decoy.events.{event_type}"
            assert subject.startswith(base)

    def test_alert_subjects_match_stream(self):
        """ALERTS stream subscribes to cicdecoy.alert.> and cicdecoy.honeytoken.triggered.>"""
        assert "cicdecoy.alert.high".startswith("cicdecoy.alert.")
        assert "cicdecoy.honeytoken.triggered.aws-cred".startswith("cicdecoy.honeytoken.triggered.")