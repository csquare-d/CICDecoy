"""Unit tests for the SSH decoy authentication handler."""

import time
from unittest.mock import patch

import pytest

from auth_handler import AuthAttempt, AuthHandler, AuthResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _FakeConfig:
    """Minimal config object that satisfies AuthHandler.__init__."""

    def __init__(
        self,
        *,
        auth_mode="selective",
        credentials=None,
        lockout_after=5,
        lockout_duration=60,
        fail_before_success=2,
    ):
        self.auth_mode = auth_mode
        self.credentials = credentials or [
            {"username": "admin", "password": "admin123"},
            {"username": "deploy", "password": "d3pl0y!"},
        ]
        self.lockout_after = lockout_after
        self.lockout_duration = lockout_duration
        self.fail_before_success = fail_before_success


# ---------------------------------------------------------------------------
# Selective mode (default)
# ---------------------------------------------------------------------------

class TestSelectiveMode:
    def _handler(self, **kw):
        return AuthHandler(_FakeConfig(auth_mode="selective", **kw))

    def test_valid_credentials_accepted(self):
        h = self._handler()
        result = h.check_password("admin", "admin123", "10.0.0.1")
        assert result.accepted is True
        assert result.username == "admin"

    def test_wrong_password_rejected(self):
        h = self._handler()
        result = h.check_password("admin", "wrong", "10.0.0.1")
        assert result.accepted is False

    def test_unknown_user_rejected(self):
        h = self._handler()
        result = h.check_password("nobody", "admin123", "10.0.0.1")
        assert result.accepted is False

    def test_multiple_valid_users(self):
        h = self._handler()
        r1 = h.check_password("admin", "admin123", "10.0.0.1")
        r2 = h.check_password("deploy", "d3pl0y!", "10.0.0.2")
        assert r1.accepted is True
        assert r2.accepted is True

    def test_case_sensitive_username(self):
        h = self._handler()
        result = h.check_password("Admin", "admin123", "10.0.0.1")
        assert result.accepted is False

    def test_case_sensitive_password(self):
        h = self._handler()
        result = h.check_password("admin", "Admin123", "10.0.0.1")
        assert result.accepted is False

    def test_empty_password_rejected(self):
        h = self._handler()
        result = h.check_password("admin", "", "10.0.0.1")
        assert result.accepted is False


# ---------------------------------------------------------------------------
# Open mode
# ---------------------------------------------------------------------------

class TestOpenMode:
    def test_any_credentials_accepted(self):
        h = AuthHandler(_FakeConfig(auth_mode="open"))
        result = h.check_password("random", "whatever", "10.0.0.1")
        assert result.accepted is True

    def test_empty_credentials_accepted(self):
        h = AuthHandler(_FakeConfig(auth_mode="open"))
        result = h.check_password("", "", "10.0.0.1")
        assert result.accepted is True


# ---------------------------------------------------------------------------
# Closed mode
# ---------------------------------------------------------------------------

class TestClosedMode:
    def test_valid_credentials_rejected(self):
        h = AuthHandler(_FakeConfig(auth_mode="closed"))
        result = h.check_password("admin", "admin123", "10.0.0.1")
        assert result.accepted is False

    def test_any_credentials_rejected(self):
        h = AuthHandler(_FakeConfig(auth_mode="closed"))
        result = h.check_password("root", "toor", "10.0.0.1")
        assert result.accepted is False


# ---------------------------------------------------------------------------
# Realistic mode
# ---------------------------------------------------------------------------

class TestRealisticMode:
    def _handler(self, fail_before_success=2, **kw):
        return AuthHandler(
            _FakeConfig(auth_mode="realistic", fail_before_success=fail_before_success, **kw)
        )

    def test_first_attempt_rejected_even_with_valid_creds(self):
        h = self._handler(fail_before_success=2)
        result = h.check_password("admin", "admin123", "10.0.0.1")
        assert result.accepted is False

    def test_accepted_after_threshold(self):
        h = self._handler(fail_before_success=2)
        ip = "10.0.0.1"
        # First two attempts should fail
        r1 = h.check_password("admin", "admin123", ip)
        r2 = h.check_password("admin", "admin123", ip)
        assert r1.accepted is False
        assert r2.accepted is False
        # Third attempt should succeed
        r3 = h.check_password("admin", "admin123", ip)
        assert r3.accepted is True

    def test_invalid_creds_never_accepted(self):
        h = self._handler(fail_before_success=1)
        ip = "10.0.0.1"
        for _ in range(10):
            result = h.check_password("admin", "wrong", ip)
            assert result.accepted is False

    def test_different_ips_tracked_independently(self):
        h = self._handler(fail_before_success=1)
        # IP 1: first attempt fails
        r1 = h.check_password("admin", "admin123", "10.0.0.1")
        assert r1.accepted is False
        # IP 2: first attempt also fails (independent counter)
        r2 = h.check_password("admin", "admin123", "10.0.0.2")
        assert r2.accepted is False
        # IP 1: second attempt succeeds
        r3 = h.check_password("admin", "admin123", "10.0.0.1")
        assert r3.accepted is True

    def test_fail_before_success_zero_means_immediate(self):
        h = self._handler(fail_before_success=0)
        result = h.check_password("admin", "admin123", "10.0.0.1")
        assert result.accepted is True


# ---------------------------------------------------------------------------
# Lockout
# ---------------------------------------------------------------------------

class TestLockout:
    def test_lockout_after_threshold(self):
        h = AuthHandler(_FakeConfig(auth_mode="selective", lockout_after=3, lockout_duration=300))
        ip = "10.0.0.99"
        for _ in range(3):
            h.check_password("admin", "wrong", ip)
        # Next attempt should be locked out
        result = h.check_password("admin", "admin123", ip)
        assert result.accepted is False
        assert "lock" in result.reason.lower()

    def test_lockout_per_ip(self):
        h = AuthHandler(_FakeConfig(auth_mode="selective", lockout_after=3))
        # Lock out IP 1
        for _ in range(3):
            h.check_password("admin", "wrong", "10.0.0.1")
        # IP 2 should still work
        result = h.check_password("admin", "admin123", "10.0.0.2")
        assert result.accepted is True

    def test_lockout_expires(self):
        h = AuthHandler(_FakeConfig(auth_mode="selective", lockout_after=2, lockout_duration=5))
        ip = "10.0.0.1"
        # Trigger lockout
        h.check_password("x", "x", ip)
        h.check_password("x", "x", ip)
        result = h.check_password("admin", "admin123", ip)
        assert result.accepted is False
        # Fast-forward time past lockout
        with patch("time.time", return_value=time.time() + 10):
            result = h.check_password("admin", "admin123", ip)
            assert result.accepted is True


# ---------------------------------------------------------------------------
# Public key logging
# ---------------------------------------------------------------------------

class TestPubkeyAttempt:
    def test_pubkey_always_rejected(self):
        h = AuthHandler(_FakeConfig())
        h.log_pubkey_attempt("admin", "AAAAB3NzaC1yc2EAAA...", "10.0.0.1")
        attempts = h.get_all_attempts()
        assert len(attempts) == 1
        assert attempts[0]["accepted"] is False
        assert "pubkey" in attempts[0]["reason"]


# ---------------------------------------------------------------------------
# Attempt tracking
# ---------------------------------------------------------------------------

class TestAttemptTracking:
    def test_attempts_recorded(self):
        h = AuthHandler(_FakeConfig())
        h.check_password("admin", "admin123", "10.0.0.1")
        h.check_password("root", "wrong", "10.0.0.2")
        attempts = h.get_all_attempts()
        assert len(attempts) == 2

    def test_attempt_contains_required_fields(self):
        h = AuthHandler(_FakeConfig())
        h.check_password("admin", "admin123", "10.0.0.1")
        attempt = h.get_all_attempts()[0]
        assert "timestamp" in attempt
        assert "client_ip" in attempt
        assert "username" in attempt
        assert "accepted" in attempt
        assert "reason" in attempt

    def test_attempt_records_ip(self):
        h = AuthHandler(_FakeConfig())
        h.check_password("admin", "admin123", "192.168.1.1")
        assert h.get_all_attempts()[0]["client_ip"] == "192.168.1.1"
