"""
CI/CDecoy — Credential Correlation Tests

Tests for canary credential loading and cross-decoy credential reuse
detection in cti/pipeline.py (Collector class).

All external dependencies (NATS, asyncpg) are mocked.
"""

# Python 3.10 lacks datetime.UTC (added in 3.11).  Patch it in before
# importing pipeline so `from datetime import UTC` succeeds.
import datetime as _dt_mod
import hashlib
import json
import os
import uuid
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio

if not hasattr(_dt_mod, "UTC"):
    _dt_mod.UTC = _dt_mod.UTC

from conftest import MockAsyncpgPool
from pipeline import Collector

# ── Helpers ────────────────────────────────────────────


def _make_msg(payload: dict, subject: str = None) -> MagicMock:
    """Build a mock NATS message with .data, .subject, and .ack()."""
    if subject is None:
        decoy_name = payload.get("decoy_name")
        if not decoy_name:
            source = payload.get("source", {})
            if isinstance(source, dict):
                decoy_name = source.get("decoy", "unknown")
            else:
                decoy_name = "unknown"
        event_type = payload.get("event_type", "unknown")
        subject = f"cicdecoy.decoy.events.{decoy_name}.{event_type}"
    msg = MagicMock()
    msg.data = json.dumps(payload).encode()
    msg.subject = subject
    msg.ack = AsyncMock()
    return msg


def _auth_event(
    username="deploy-bot",
    password_hash="",
    event_type="auth.success",
    source_ip="198.51.100.42",
    decoy_name="ssh-decoy-01",
    session_id=None,
):
    """Build an auth event payload for credential correlation tests."""
    return {
        "event_id": f"evt-{uuid.uuid4().hex[:12]}",
        "timestamp": datetime.now(_dt_mod.UTC).isoformat(),
        "decoy_name": decoy_name,
        "decoy_tier": 2,
        "session_id": session_id or f"sess-{uuid.uuid4().hex[:12]}",
        "event_type": event_type,
        "source_ip": source_ip,
        "source_port": 44120,
        "data": {
            "username": username,
            "password_hash": password_hash,
            "client_ip": source_ip,
            "client_port": 44120,
        },
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
#  1. _load_canary_credentials
# ══════════════════════════════════════════════════════


class TestLoadCanaryCredentials:
    def test_load_canary_credentials_from_env(self):
        """Valid JSON in CANARY_CREDENTIALS populates the credential set."""
        creds = [
            {"username": "admin", "password": "hunter2"},
            {"username": "deploy-bot", "password": "s3cret"},
        ]
        c = Collector(nats_url="nats://mock:4222", db_dsn="postgresql://mock/mock")
        with patch.dict(os.environ, {"CANARY_CREDENTIALS": json.dumps(creds)}):
            c._load_canary_credentials()

        assert len(c._canary_credentials) == 2
        # Verify the stored tuples use SHA-256 hashes, not plaintext
        admin_hash = hashlib.sha256(b"hunter2").hexdigest()
        assert ("admin", admin_hash) in c._canary_credentials
        deploy_hash = hashlib.sha256(b"s3cret").hexdigest()
        assert ("deploy-bot", deploy_hash) in c._canary_credentials

    def test_load_canary_credentials_empty(self):
        """Missing/empty CANARY_CREDENTIALS results in an empty set."""
        c = Collector(nats_url="nats://mock:4222", db_dsn="postgresql://mock/mock")
        with patch.dict(os.environ, {}, clear=True):
            # Ensure the var is truly absent
            os.environ.pop("CANARY_CREDENTIALS", None)
            c._load_canary_credentials()
        assert len(c._canary_credentials) == 0

    def test_load_canary_credentials_invalid_json(self):
        """Invalid JSON in CANARY_CREDENTIALS must not crash; set stays empty."""
        c = Collector(nats_url="nats://mock:4222", db_dsn="postgresql://mock/mock")
        with patch.dict(os.environ, {"CANARY_CREDENTIALS": "not-valid-json{{{"}):
            c._load_canary_credentials()  # should not raise
        assert len(c._canary_credentials) == 0


# ══════════════════════════════════════════════════════
#  2. Credential correlation in _process_message
# ══════════════════════════════════════════════════════


class TestCredentialCorrelation:
    @pytest.mark.asyncio
    async def test_credential_match_detected(self, collector):
        """Auth event with matching canary credentials publishes a reuse event."""
        password = "s3cret"
        pw_hash = hashlib.sha256(password.encode()).hexdigest()

        # Seed the collector with a canary credential
        collector._canary_credentials = {("deploy-bot", pw_hash)}

        event = _auth_event(username="deploy-bot", password_hash=pw_hash)
        msg = _make_msg(event)
        await collector._process_message(msg)

        # The collector should have published a honeytoken.credential_reuse event
        publish_calls = collector.nc.publish.call_args_list
        reuse_calls = [call for call in publish_calls if "credential_reuse" in str(call)]
        assert len(reuse_calls) >= 1, f"Expected a credential_reuse publish; got calls: {publish_calls}"

        # Verify the published payload
        reuse_subject = reuse_calls[0][0][0]
        reuse_payload = json.loads(reuse_calls[0][0][1])
        assert reuse_payload["event_type"] == "honeytoken.credential_reuse"
        assert reuse_payload["severity"] == "critical"
        assert reuse_payload["data"]["username"] == "deploy-bot"
        assert reuse_payload["data"]["password_hash"] == pw_hash
        assert "credential_reuse" in reuse_subject

    @pytest.mark.asyncio
    async def test_credential_no_match_ignored(self, collector):
        """Auth event with non-matching credentials does not publish a reuse event."""
        canary_hash = hashlib.sha256(b"s3cret").hexdigest()
        collector._canary_credentials = {("deploy-bot", canary_hash)}

        # Use a different password hash that does NOT match the canary
        different_hash = hashlib.sha256(b"wrong-password").hexdigest()
        event = _auth_event(username="deploy-bot", password_hash=different_hash)
        msg = _make_msg(event)
        await collector._process_message(msg)

        # No credential_reuse event should have been published
        publish_calls = collector.nc.publish.call_args_list
        reuse_calls = [call for call in publish_calls if "credential_reuse" in str(call)]
        assert len(reuse_calls) == 0, f"No credential_reuse expected; got: {reuse_calls}"

    @pytest.mark.asyncio
    async def test_credential_hash_comparison(self, collector):
        """Canary credentials store SHA-256 hashes; events carry password_hash.

        Verify that the comparison works when the event's password_hash matches
        the SHA-256 of the canary's plaintext password.
        """
        plaintext = "canary-password-123"
        expected_hash = hashlib.sha256(plaintext.encode()).hexdigest()

        # Load via env var to exercise the full hashing path
        creds = [{"username": "honeypot-user", "password": plaintext}]
        with patch.dict(os.environ, {"CANARY_CREDENTIALS": json.dumps(creds)}):
            collector._load_canary_credentials()

        # The stored credential should use the hash, not plaintext
        assert ("honeypot-user", expected_hash) in collector._canary_credentials

        # An auth event with the matching hash should trigger correlation
        event = _auth_event(username="honeypot-user", password_hash=expected_hash)
        msg = _make_msg(event)
        await collector._process_message(msg)

        publish_calls = collector.nc.publish.call_args_list
        reuse_calls = [call for call in publish_calls if "credential_reuse" in str(call)]
        assert len(reuse_calls) >= 1, "SHA-256 hash comparison should match canary credential"
