"""
CI/CDecoy -- HTTP Session Tracking Tests

Tests for session creation, reuse, credential recording,
request counting, cookie signing, session isolation,
CSRF token invalidation, and global credential caps.
"""

import asyncio
import secrets
from unittest.mock import MagicMock

import pytest
from http_session import COOKIE_NAME, SessionTracker


def _make_request(host="1.2.3.4", user_agent="test-agent", cookies=None, headers=None):
    """Build a mock FastAPI Request object."""
    request = MagicMock()
    request.cookies = cookies or {}
    request.client = MagicMock()
    request.client.host = host
    _headers = {"user-agent": user_agent}
    if headers:
        _headers.update(headers)
    request.headers = _headers
    return request


class TestSessionCreation:
    @pytest.mark.asyncio
    async def test_create_new_session(self):
        tracker = SessionTracker("test-secret")
        request = _make_request()

        session_id, data = await tracker.get_or_create_session(request)

        assert session_id is not None
        assert len(session_id) == 12
        assert data["source_ip"] == "1.2.3.4"
        assert data["user_agent"] == "test-agent"
        assert data["requests"] == 0
        assert data["credentials_submitted"] == []

    @pytest.mark.asyncio
    async def test_session_extracts_forwarded_ip(self):
        tracker = SessionTracker("test-secret")
        request = _make_request(
            headers={"x-forwarded-for": "10.0.0.1, 192.168.1.1"},
        )

        _, data = await tracker.get_or_create_session(request)
        assert data["source_ip"] == "10.0.0.1"

    @pytest.mark.asyncio
    async def test_session_falls_back_to_client_host(self):
        tracker = SessionTracker("test-secret")
        request = _make_request(host="203.0.113.5")

        _, data = await tracker.get_or_create_session(request)
        assert data["source_ip"] == "203.0.113.5"


class TestSessionReuse:
    @pytest.mark.asyncio
    async def test_existing_session_reused(self):
        tracker = SessionTracker("test-secret")
        request = _make_request()

        session_id_1, _ = await tracker.get_or_create_session(request)

        # Simulate the signed cookie being sent back
        signed_cookie = tracker._signer.dumps(session_id_1)
        request2 = _make_request(cookies={COOKIE_NAME: signed_cookie})

        session_id_2, _ = await tracker.get_or_create_session(request2)
        assert session_id_1 == session_id_2

    @pytest.mark.asyncio
    async def test_invalid_cookie_creates_new_session(self):
        tracker = SessionTracker("test-secret")
        request = _make_request(cookies={COOKIE_NAME: "garbage-value"})

        session_id, data = await tracker.get_or_create_session(request)
        assert session_id is not None
        assert data["source_ip"] == "1.2.3.4"

    @pytest.mark.asyncio
    async def test_cookie_for_unknown_session_creates_new(self):
        tracker = SessionTracker("test-secret")
        # Valid signature but session_id not tracked
        signed = tracker._signer.dumps("nonexistent123")
        request = _make_request(cookies={COOKIE_NAME: signed})

        session_id, _ = await tracker.get_or_create_session(request)
        assert session_id != "nonexistent123"


class TestCredentialRecording:
    @pytest.mark.asyncio
    async def test_record_credential(self):
        tracker = SessionTracker("test-secret")
        request = _make_request()
        session_id, _ = await tracker.get_or_create_session(request)

        await tracker.record_credential(session_id, "admin", "password123", "aws")

        session = tracker._sessions[session_id]
        assert len(session["credentials_submitted"]) == 1
        cred = session["credentials_submitted"][0]
        assert cred["username"] == "admin"
        assert cred["password_sha256"] == __import__("hashlib").sha256(b"password123").hexdigest()
        assert cred["portal"] == "aws"
        assert "timestamp" in cred

    @pytest.mark.asyncio
    async def test_record_multiple_credentials(self):
        tracker = SessionTracker("test-secret")
        request = _make_request()
        session_id, _ = await tracker.get_or_create_session(request)

        await tracker.record_credential(session_id, "admin", "pass1", "aws")
        await tracker.record_credential(session_id, "root", "pass2", "jenkins")

        session = tracker._sessions[session_id]
        assert len(session["credentials_submitted"]) == 2

    @pytest.mark.asyncio
    async def test_record_credential_unknown_session(self):
        tracker = SessionTracker("test-secret")
        # Should not raise
        await tracker.record_credential("nonexistent", "admin", "pass", "aws")


class TestRequestTracking:
    @pytest.mark.asyncio
    async def test_record_request_increments_counter(self):
        tracker = SessionTracker("test-secret")
        request = _make_request()
        session_id, _ = await tracker.get_or_create_session(request)

        assert tracker._sessions[session_id]["requests"] == 0
        await tracker.record_request(session_id)
        assert tracker._sessions[session_id]["requests"] == 1
        await tracker.record_request(session_id)
        assert tracker._sessions[session_id]["requests"] == 2

    @pytest.mark.asyncio
    async def test_record_request_unknown_session(self):
        tracker = SessionTracker("test-secret")
        # Should not raise
        await tracker.record_request("nonexistent")


class TestActiveSessionCount:
    def test_active_sessions_starts_at_zero(self):
        tracker = SessionTracker("test-secret")
        assert tracker.active_sessions == 0

    @pytest.mark.asyncio
    async def test_active_sessions_increments(self):
        tracker = SessionTracker("test-secret")
        req1 = _make_request(host="1.1.1.1")
        req2 = _make_request(host="2.2.2.2")

        await tracker.get_or_create_session(req1)
        assert tracker.active_sessions == 1

        await tracker.get_or_create_session(req2)
        assert tracker.active_sessions == 2


class TestCookieSetting:
    def test_set_cookie_on_response(self):
        tracker = SessionTracker("test-secret")
        response = MagicMock()

        tracker.set_cookie(response, "abc123")

        response.set_cookie.assert_called_once()
        call_kwargs = response.set_cookie.call_args
        assert call_kwargs.kwargs["key"] == COOKIE_NAME
        assert call_kwargs.kwargs["httponly"] is True
        assert call_kwargs.kwargs["samesite"] == "lax"


class TestSessionIsolation:
    @pytest.mark.asyncio
    async def test_separate_sessions_independent_counters(self):
        """Two sessions from different IPs should have independent request counts."""
        tracker = SessionTracker("test-secret")
        req1 = _make_request(host="1.1.1.1")
        req2 = _make_request(host="2.2.2.2")

        sid1, _ = await tracker.get_or_create_session(req1)
        sid2, _ = await tracker.get_or_create_session(req2)
        assert sid1 != sid2

        # Increment only session 1's counter
        await tracker.record_request(sid1)
        await tracker.record_request(sid1)
        await tracker.record_request(sid1)

        assert tracker._sessions[sid1]["requests"] == 3
        assert tracker._sessions[sid2]["requests"] == 0

    @pytest.mark.asyncio
    async def test_separate_sessions_independent(self):
        """Two sessions for different IPs have fully separate state."""
        tracker = SessionTracker("test-secret")
        req1 = _make_request(host="10.0.0.1", user_agent="attacker-A")
        req2 = _make_request(host="10.0.0.2", user_agent="attacker-B")

        sid1, data1 = await tracker.get_or_create_session(req1)
        sid2, data2 = await tracker.get_or_create_session(req2)

        # Unique IDs
        assert sid1 != sid2
        # Each session records its own IP and user-agent
        assert data1["source_ip"] == "10.0.0.1"
        assert data2["source_ip"] == "10.0.0.2"
        assert data1["user_agent"] == "attacker-A"
        assert data2["user_agent"] == "attacker-B"

        # Mutating one session does not affect the other
        await tracker.record_request(sid1)
        await tracker.mark_seen(sid1)
        assert tracker._sessions[sid1]["requests"] == 1
        assert tracker._sessions[sid1]["seen"] is True
        assert tracker._sessions[sid2]["requests"] == 0
        assert tracker._sessions[sid2]["seen"] is False

    @pytest.mark.asyncio
    async def test_credential_isolation(self):
        """Credentials from one session must not appear in another."""
        tracker = SessionTracker("test-secret")
        req1 = _make_request(host="1.1.1.1")
        req2 = _make_request(host="2.2.2.2")

        sid1, _ = await tracker.get_or_create_session(req1)
        sid2, _ = await tracker.get_or_create_session(req2)

        await tracker.record_credential(sid1, "admin", "secret123", "aws")

        assert len(tracker._sessions[sid1]["credentials_submitted"]) == 1
        assert len(tracker._sessions[sid2]["credentials_submitted"]) == 0

    @pytest.mark.asyncio
    async def test_invalid_cookie_creates_new_session(self):
        """A forged/invalid session cookie should result in a brand-new session."""
        tracker = SessionTracker("test-secret")
        req1 = _make_request(host="5.5.5.5")
        sid1, _ = await tracker.get_or_create_session(req1)

        # Forge a cookie using a different secret
        from itsdangerous import URLSafeSerializer
        forged_signer = URLSafeSerializer("wrong-secret")
        forged_cookie = forged_signer.dumps(sid1)

        req2 = _make_request(host="6.6.6.6", cookies={COOKIE_NAME: forged_cookie})
        sid2, data2 = await tracker.get_or_create_session(req2)

        # A new, distinct session must be created
        assert sid2 != sid1
        assert data2["source_ip"] == "6.6.6.6"
        assert data2["requests"] == 0
        assert data2["credentials_submitted"] == []

    @pytest.mark.asyncio
    async def test_invalid_cookie_rejected(self):
        """A forged cookie signed with a different secret should create a new session."""
        tracker = SessionTracker("test-secret")
        req1 = _make_request()
        sid1, _ = await tracker.get_or_create_session(req1)

        # Forge a cookie using a different secret
        from itsdangerous import URLSafeSerializer
        forged_signer = URLSafeSerializer("wrong-secret")
        forged_cookie = forged_signer.dumps(sid1)

        req2 = _make_request(cookies={COOKIE_NAME: forged_cookie})
        sid2, _ = await tracker.get_or_create_session(req2)

        assert sid2 != sid1

    @pytest.mark.asyncio
    async def test_concurrent_session_creation(self):
        """Multiple sessions should be creatable concurrently without errors."""
        tracker = SessionTracker("test-secret")

        async def create_session(ip):
            req = _make_request(host=ip)
            return await tracker.get_or_create_session(req)

        results = await asyncio.gather(
            *[create_session(f"10.{i}.0.1") for i in range(20)]
        )

        session_ids = [r[0] for r in results]
        # All session IDs should be unique
        assert len(set(session_ids)) == 20
        assert tracker.active_sessions == 20


class TestCSRFTokenInvalidation:

    @pytest.mark.asyncio
    async def test_csrf_token_invalidated_after_use(self):
        """CSRF token should be consumed after successful validation."""
        tracker = SessionTracker("test-secret")
        request = _make_request()
        session_id, _ = await tracker.get_or_create_session(request)

        token = secrets.token_hex(32)
        tracker.store_csrf_token(session_id, token)

        # First validation should succeed
        assert tracker.validate_csrf_token(session_id, token) is True
        # Second validation with same token should fail (consumed)
        assert tracker.validate_csrf_token(session_id, token) is False

    @pytest.mark.asyncio
    async def test_csrf_token_wrong_value_rejected(self):
        """Wrong CSRF token should be rejected."""
        tracker = SessionTracker("test-secret")
        request = _make_request()
        session_id, _ = await tracker.get_or_create_session(request)

        token = secrets.token_hex(32)
        tracker.store_csrf_token(session_id, token)

        assert tracker.validate_csrf_token(session_id, "wrong-token") is False

    @pytest.mark.asyncio
    async def test_csrf_token_missing_session_rejected(self):
        """CSRF validation for a non-existent session should return False."""
        tracker = SessionTracker("test-secret")
        assert tracker.validate_csrf_token("nonexistent", "some-token") is False

    @pytest.mark.asyncio
    async def test_csrf_token_not_set_rejected(self):
        """CSRF validation when no token was stored should return False."""
        tracker = SessionTracker("test-secret")
        request = _make_request()
        session_id, _ = await tracker.get_or_create_session(request)

        assert tracker.validate_csrf_token(session_id, "any-token") is False

    @pytest.mark.asyncio
    async def test_csrf_wrong_token_does_not_consume(self):
        """A failed validation should not consume the stored token."""
        tracker = SessionTracker("test-secret")
        request = _make_request()
        session_id, _ = await tracker.get_or_create_session(request)

        token = secrets.token_hex(32)
        tracker.store_csrf_token(session_id, token)

        # Wrong token should fail but not consume
        assert tracker.validate_csrf_token(session_id, "wrong") is False
        # Correct token should still work
        assert tracker.validate_csrf_token(session_id, token) is True


class TestGlobalCredentialCap:

    @pytest.mark.asyncio
    async def test_global_credential_cap(self):
        """Global credential cap should prevent unbounded growth."""
        import http_session
        tracker = SessionTracker("test-secret")
        original_cap = http_session._GLOBAL_CREDENTIAL_CAP
        http_session._GLOBAL_CREDENTIAL_CAP = 5
        try:
            request = _make_request()
            session_id, _ = await tracker.get_or_create_session(request)
            for i in range(10):
                await tracker.record_credential(session_id, f"user{i}", f"pass{i}", "test")
            assert tracker._total_credentials <= 5
            assert len(tracker._sessions[session_id]["credentials_submitted"]) <= 5
        finally:
            http_session._GLOBAL_CREDENTIAL_CAP = original_cap

    @pytest.mark.asyncio
    async def test_global_credential_cap_across_sessions(self):
        """Global credential cap should apply across all sessions."""
        import http_session
        tracker = SessionTracker("test-secret")
        original_cap = http_session._GLOBAL_CREDENTIAL_CAP
        http_session._GLOBAL_CREDENTIAL_CAP = 4
        try:
            req1 = _make_request(host="1.1.1.1")
            req2 = _make_request(host="2.2.2.2")
            sid1, _ = await tracker.get_or_create_session(req1)
            sid2, _ = await tracker.get_or_create_session(req2)

            for i in range(3):
                await tracker.record_credential(sid1, f"u{i}", f"p{i}", "aws")
            for i in range(3):
                await tracker.record_credential(sid2, f"u{i}", f"p{i}", "aws")

            total = (len(tracker._sessions[sid1]["credentials_submitted"])
                     + len(tracker._sessions[sid2]["credentials_submitted"]))
            assert total <= 4
            assert tracker._total_credentials <= 4
        finally:
            http_session._GLOBAL_CREDENTIAL_CAP = original_cap
