"""
CI/CDecoy -- HTTP Session Tracking Tests

Tests for session creation, reuse, credential recording,
request counting, and cookie signing.
"""

from unittest.mock import MagicMock

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
    def test_create_new_session(self):
        tracker = SessionTracker("test-secret")
        request = _make_request()

        session_id, data = tracker.get_or_create_session(request)

        assert session_id is not None
        assert len(session_id) == 12
        assert data["source_ip"] == "1.2.3.4"
        assert data["user_agent"] == "test-agent"
        assert data["requests"] == 0
        assert data["credentials_submitted"] == []

    def test_session_extracts_forwarded_ip(self):
        tracker = SessionTracker("test-secret")
        request = _make_request(
            headers={"x-forwarded-for": "10.0.0.1, 192.168.1.1"},
        )

        _, data = tracker.get_or_create_session(request)
        assert data["source_ip"] == "10.0.0.1"

    def test_session_falls_back_to_client_host(self):
        tracker = SessionTracker("test-secret")
        request = _make_request(host="203.0.113.5")

        _, data = tracker.get_or_create_session(request)
        assert data["source_ip"] == "203.0.113.5"


class TestSessionReuse:
    def test_existing_session_reused(self):
        tracker = SessionTracker("test-secret")
        request = _make_request()

        session_id_1, _ = tracker.get_or_create_session(request)

        # Simulate the signed cookie being sent back
        signed_cookie = tracker._signer.dumps(session_id_1)
        request2 = _make_request(cookies={COOKIE_NAME: signed_cookie})

        session_id_2, _ = tracker.get_or_create_session(request2)
        assert session_id_1 == session_id_2

    def test_invalid_cookie_creates_new_session(self):
        tracker = SessionTracker("test-secret")
        request = _make_request(cookies={COOKIE_NAME: "garbage-value"})

        session_id, data = tracker.get_or_create_session(request)
        assert session_id is not None
        assert data["source_ip"] == "1.2.3.4"

    def test_cookie_for_unknown_session_creates_new(self):
        tracker = SessionTracker("test-secret")
        # Valid signature but session_id not tracked
        signed = tracker._signer.dumps("nonexistent123")
        request = _make_request(cookies={COOKIE_NAME: signed})

        session_id, _ = tracker.get_or_create_session(request)
        assert session_id != "nonexistent123"


class TestCredentialRecording:
    def test_record_credential(self):
        tracker = SessionTracker("test-secret")
        request = _make_request()
        session_id, _ = tracker.get_or_create_session(request)

        tracker.record_credential(session_id, "admin", "password123", "aws")

        session = tracker._sessions[session_id]
        assert len(session["credentials_submitted"]) == 1
        cred = session["credentials_submitted"][0]
        assert cred["username"] == "admin"
        assert cred["password"] == "password123"
        assert cred["portal"] == "aws"
        assert "timestamp" in cred

    def test_record_multiple_credentials(self):
        tracker = SessionTracker("test-secret")
        request = _make_request()
        session_id, _ = tracker.get_or_create_session(request)

        tracker.record_credential(session_id, "admin", "pass1", "aws")
        tracker.record_credential(session_id, "root", "pass2", "jenkins")

        session = tracker._sessions[session_id]
        assert len(session["credentials_submitted"]) == 2

    def test_record_credential_unknown_session(self):
        tracker = SessionTracker("test-secret")
        # Should not raise
        tracker.record_credential("nonexistent", "admin", "pass", "aws")


class TestRequestTracking:
    def test_record_request_increments_counter(self):
        tracker = SessionTracker("test-secret")
        request = _make_request()
        session_id, _ = tracker.get_or_create_session(request)

        assert tracker._sessions[session_id]["requests"] == 0
        tracker.record_request(session_id)
        assert tracker._sessions[session_id]["requests"] == 1
        tracker.record_request(session_id)
        assert tracker._sessions[session_id]["requests"] == 2

    def test_record_request_unknown_session(self):
        tracker = SessionTracker("test-secret")
        # Should not raise
        tracker.record_request("nonexistent")


class TestActiveSessionCount:
    def test_active_sessions_starts_at_zero(self):
        tracker = SessionTracker("test-secret")
        assert tracker.active_sessions == 0

    def test_active_sessions_increments(self):
        tracker = SessionTracker("test-secret")
        req1 = _make_request(host="1.1.1.1")
        req2 = _make_request(host="2.2.2.2")

        tracker.get_or_create_session(req1)
        assert tracker.active_sessions == 1

        tracker.get_or_create_session(req2)
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
