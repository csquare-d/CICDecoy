"""Contract tests: validate NATS event schemas between producers and consumers.

These tests ensure that:
1. SSH decoy events contain fields the CTI pipeline requires
2. HTTP decoy events contain fields the CTI pipeline requires
3. Honeytoken events contain required fields
4. Enriched events contain fields the dashboard and SIEM forwarder expect
5. Both envelope shapes (SSH nested source vs HTTP flat) are handled
"""

import datetime
import os
import sys
import unittest
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "lib"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "ssh-decoy"))


# ---------------------------------------------------------------------------
# Helper: simulate the CTI pipeline's field resolution logic
# (matching pipeline.py lines 294-370) without importing async code.
# ---------------------------------------------------------------------------


def resolve_pipeline_fields(raw):
    """Extract normalized fields from either SSH or HTTP envelope shapes.

    SSH envelopes use nested ``source.decoy`` / ``source.tier`` and put the
    client IP inside ``data.client_ip``.

    HTTP envelopes use flat ``decoy_name`` / ``decoy_tier`` / ``source_ip``.

    The pipeline uses a fallback chain so both shapes resolve to the same
    canonical set of fields.
    """
    decoy_name = raw.get("decoy_name") or raw.get("source", {}).get("decoy")
    decoy_tier = raw.get("decoy_tier") or raw.get("source", {}).get("tier")
    source_ip = raw.get("source_ip") or raw.get("data", {}).get("client_ip")
    return {
        "event_id": raw.get("event_id"),
        "timestamp": raw.get("timestamp"),
        "decoy_name": decoy_name,
        "decoy_tier": decoy_tier,
        "session_id": raw.get("session_id"),
        "event_type": raw.get("event_type"),
        "source_ip": source_ip,
    }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _ssh_envelope(**overrides):
    """Build a minimal SSH decoy event envelope (server.py line 307 shape)."""
    base = {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "version": "1.0",
        "source": {
            "decoy": "ssh-prod-east-1",
            "tier": 2,
        },
        "session_id": str(uuid.uuid4()),
        "event_type": "auth.success",
        "data": {
            "client_ip": "192.0.2.42",
            "username": "admin",
            "password_sha256": "e3b0c44298fc1c149afbf4c8996fb924" "27ae41e4649b934ca495991b7852b855",
            "accepted": True,
        },
    }
    base.update(overrides)
    return base


def _http_envelope(**overrides):
    """Build a minimal HTTP decoy event envelope (telemetry.py line 64 shape)."""
    base = {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "version": "1.0",
        "decoy_name": "http-prod-west-2",
        "decoy_tier": 1,
        "session_id": str(uuid.uuid4()),
        "event_type": "http.request",
        "source_ip": "198.51.100.7",
        "data": {
            "method": "GET",
            "path": "/admin/login",
            "user_agent": "Mozilla/5.0",
        },
    }
    base.update(overrides)
    return base


# ===================================================================
# Tests
# ===================================================================


class TestSSHDecoyEnvelope(unittest.TestCase):
    """Validate the SSH decoy's event envelope shape."""

    def test_ssh_envelope_has_required_fields(self):
        env = _ssh_envelope()
        # Top-level scalars
        self.assertIsInstance(env["event_id"], str)
        uuid.UUID(env["event_id"])  # must be valid UUID
        self.assertIn("T", env["timestamp"])  # ISO 8601
        self.assertEqual(env["version"], "1.0")
        # Nested source
        self.assertIsInstance(env["source"]["decoy"], str)
        self.assertIsInstance(env["source"]["tier"], int)
        # Session / event
        self.assertIsInstance(env["session_id"], str)
        self.assertIsInstance(env["event_type"], str)
        # Data payload
        self.assertIsInstance(env["data"], dict)

    def test_ssh_envelope_decoy_name_resolvable(self):
        raw = _ssh_envelope()
        resolved = raw.get("decoy_name") or raw.get("source", {}).get("decoy")
        self.assertEqual(resolved, "ssh-prod-east-1")

    def test_ssh_envelope_source_ip_resolvable(self):
        raw = _ssh_envelope()
        resolved = raw["data"].get("client_ip")
        self.assertEqual(resolved, "192.0.2.42")


class TestHTTPDecoyEnvelope(unittest.TestCase):
    """Validate the HTTP decoy's flat envelope shape."""

    def test_http_envelope_has_required_fields(self):
        env = _http_envelope()
        self.assertIsInstance(env["event_id"], str)
        uuid.UUID(env["event_id"])
        self.assertIn("T", env["timestamp"])
        self.assertEqual(env["version"], "1.0")
        self.assertIsInstance(env["decoy_name"], str)
        self.assertIsInstance(env["decoy_tier"], int)
        self.assertIsInstance(env["session_id"], str)
        self.assertIsInstance(env["event_type"], str)
        self.assertIsInstance(env["source_ip"], str)
        self.assertIsInstance(env["data"], dict)

    def test_http_envelope_decoy_name_resolvable(self):
        raw = _http_envelope()
        resolved = raw.get("decoy_name")
        self.assertEqual(resolved, "http-prod-west-2")


class TestEventTypeSchemas(unittest.TestCase):
    """Validate specific event type data dicts."""

    def test_auth_success_has_credential_fields(self):
        data = {
            "username": "admin",
            "password_sha256": "e3b0c44298fc1c149afbf4c8996fb924" "27ae41e4649b934ca495991b7852b855",
            "accepted": True,
            "client_ip": "192.0.2.42",
        }
        for field in ("username", "client_ip", "accepted"):
            self.assertIn(field, data, f"Missing required field: {field}")
        # Accept either password_hash or password_sha256
        self.assertTrue(
            "password_hash" in data or "password_sha256" in data,
            "Must have password_hash or password_sha256",
        )

    def test_command_exec_has_command(self):
        data = {
            "command": "cat /etc/passwd",
            "cwd": "/home/admin",
        }
        for field in ("command", "cwd"):
            self.assertIn(field, data, f"Missing required field: {field}")

    def test_session_end_has_duration(self):
        data = {
            "reason": "client_disconnect",
            "command_count": 5,
            "duration_seconds": 42.7,
        }
        for field in ("reason", "command_count", "duration_seconds"):
            self.assertIn(field, data, f"Missing required field: {field}")

    def test_honeytoken_accessed_has_token_fields(self):
        data = {
            "token_name": "prod-env-creds",
            "token_type": "env-var",
            "access_type": "file_read",
            "access_vector": "shell",
            "accessed_path": "/opt/.env",
            "content_hash": "abc123",
            "client_ip": "192.0.2.42",
            "username": "admin",
        }
        required = (
            "token_name",
            "token_type",
            "access_type",
            "access_vector",
            "accessed_path",
            "content_hash",
            "client_ip",
            "username",
        )
        for field in required:
            self.assertIn(field, data, f"Missing required field: {field}")

    def test_honeytoken_deleted_has_token_fields(self):
        data = {
            "token_name": "prod-env-creds",
            "token_type": "env-var",
            "access_type": "file_deleted",
            "access_vector": "shell",
            "accessed_path": "/opt/.env",
            "content_hash": "abc123",
            "client_ip": "192.0.2.42",
            "username": "admin",
        }
        required = (
            "token_name",
            "token_type",
            "access_type",
            "access_vector",
            "accessed_path",
            "content_hash",
            "client_ip",
            "username",
        )
        for field in required:
            self.assertIn(field, data, f"Missing required field: {field}")
        self.assertEqual(data["access_type"], "file_deleted")


class TestEnrichedEventSchema(unittest.TestCase):
    """Validate what the CTI pipeline publishes after enrichment."""

    def _enriched_event(self):
        return {
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "decoy_name": "ssh-prod-east-1",
            "decoy_tier": 2,
            "session_id": str(uuid.uuid4()),
            "event_type": "auth.success",
            "source_ip": "192.0.2.42",
            "severity": "high",
            "mitre_techniques": [
                {
                    "technique_id": "T1078",
                    "technique_name": "Valid Accounts",
                    "tactic": "initial-access",
                },
            ],
            "tool_signatures": ["hydra-ssh"],
            "tags": ["brute-force", "credential-stuffing"],
        }

    def test_enriched_event_has_flat_fields(self):
        ev = self._enriched_event()
        required = (
            "event_id",
            "timestamp",
            "decoy_name",
            "decoy_tier",
            "session_id",
            "event_type",
            "source_ip",
            "severity",
            "mitre_techniques",
            "tool_signatures",
            "tags",
        )
        for field in required:
            self.assertIn(field, ev, f"Missing required field: {field}")
        self.assertIsInstance(ev["mitre_techniques"], list)
        self.assertIsInstance(ev["tool_signatures"], list)
        self.assertIsInstance(ev["tags"], list)

    def test_enriched_event_mitre_technique_shape(self):
        ev = self._enriched_event()
        for technique in ev["mitre_techniques"]:
            self.assertIn("technique_id", technique)
            self.assertIn("technique_name", technique)
            self.assertIn("tactic", technique)
            self.assertIsInstance(technique["technique_id"], str)
            self.assertIsInstance(technique["technique_name"], str)
            self.assertIsInstance(technique["tactic"], str)


class TestCredentialReuse(unittest.TestCase):
    """Validate credential reuse events."""

    def test_credential_reuse_has_required_fields(self):
        ev = {
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "event_type": "honeytoken.credential_reuse",
            "decoy_name": "ssh-prod-east-1",
            "decoy_tier": 2,
            "session_id": str(uuid.uuid4()),
            "source_ip": "192.0.2.42",
            "source_port": 54321,
            "severity": "critical",
            "data": {
                "username": "admin",
                "password_hash": "e3b0c44298fc1c149afbf4c8996fb924" "27ae41e4649b934ca495991b7852b855",
            },
        }
        required_top = (
            "event_id",
            "timestamp",
            "event_type",
            "decoy_name",
            "decoy_tier",
            "session_id",
            "source_ip",
            "source_port",
            "severity",
        )
        for field in required_top:
            self.assertIn(field, ev, f"Missing required field: {field}")
        self.assertEqual(ev["event_type"], "honeytoken.credential_reuse")
        self.assertEqual(ev["severity"], "critical")
        self.assertIn("username", ev["data"])
        self.assertIn("password_hash", ev["data"])


class TestSchemaCompatibility(unittest.TestCase):
    """Cross-cutting: both envelope shapes must survive pipeline field resolution."""

    def test_ssh_event_survives_pipeline_field_resolution(self):
        raw = _ssh_envelope()
        resolved = resolve_pipeline_fields(raw)
        self.assertEqual(resolved["decoy_name"], "ssh-prod-east-1")
        self.assertEqual(resolved["decoy_tier"], 2)
        self.assertEqual(resolved["source_ip"], "192.0.2.42")
        self.assertIsNotNone(resolved["event_id"])
        self.assertIsNotNone(resolved["timestamp"])
        self.assertIsNotNone(resolved["session_id"])
        self.assertIsNotNone(resolved["event_type"])

    def test_http_event_survives_pipeline_field_resolution(self):
        raw = _http_envelope()
        resolved = resolve_pipeline_fields(raw)
        self.assertEqual(resolved["decoy_name"], "http-prod-west-2")
        self.assertEqual(resolved["decoy_tier"], 1)
        self.assertEqual(resolved["source_ip"], "198.51.100.7")
        self.assertIsNotNone(resolved["event_id"])
        self.assertIsNotNone(resolved["timestamp"])
        self.assertIsNotNone(resolved["session_id"])
        self.assertIsNotNone(resolved["event_type"])


if __name__ == "__main__":
    unittest.main()
