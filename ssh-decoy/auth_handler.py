# CI/CDecoy — Authentication Handler
# images/ssh-decoy/src/auth_handler.py
#
# Handles authentication with configurable modes:
# - open: accept any credentials
# - selective: accept only specific username/password combos
# - realistic: reject first N attempts, then accept (simulates brute-force success)
# - closed: reject all (pure credential harvesting)
#
# All attempts are logged for CTI regardless of mode.

import logging
import threading
import time
from collections import deque
from dataclasses import dataclass

logger = logging.getLogger("cicdecoy.auth")


@dataclass
class AuthAttempt:
    """A single authentication attempt record."""
    timestamp: float
    client_ip: str
    username: str
    password: str | None = None
    pubkey_fingerprint: str | None = None
    accepted: bool = False
    rejection_reason: str | None = None


@dataclass
class AuthResult:
    accepted: bool
    username: str
    reason: str


class AuthHandler:
    """
    Multi-mode authentication handler with credential harvesting.

    Tracks per-IP attempt counts for realistic mode and lockout
    enforcement. Every attempt is recorded for CTI.
    """

    def __init__(self, config):
        self.config = config
        self.attempts: deque[AuthAttempt] = deque(maxlen=100_000)

        # Per-IP tracking
        self.ip_attempt_counts: dict[str, int] = {}
        self.ip_lockout_until: dict[str, float] = {}

        # Per-IP successful auth tracking (for realistic mode)
        self.ip_fail_counts: dict[str, int] = {}

        # Lock for all per-IP dict access (callbacks come from asyncssh threads)
        self._lockout_lock = threading.Lock()

        # Build credential lookup table
        self.valid_creds: dict[str, str] = {}
        for cred in config.credentials:
            self.valid_creds[cred["username"]] = cred.get("password", "")

    # Maximum credential string length to prevent memory abuse
    MAX_CREDENTIAL_LEN = 1024

    def check_password(
        self, username: str, password: str, client_ip: str
    ) -> AuthResult:
        """
        Evaluate a password authentication attempt.

        Returns AuthResult indicating accept/reject.
        All attempts are logged regardless.
        """
        # Reject empty passwords — real SSH servers never allow them.
        # Exception: "open" mode accepts everything for max credential capture.
        if self.config.auth_mode != "open" and (not password or not password.strip()):
            return AuthResult(False, username, "Empty password rejected")

        # Truncate oversized credentials to prevent memory exhaustion
        username = username[:self.MAX_CREDENTIAL_LEN]
        password = password[:self.MAX_CREDENTIAL_LEN]

        attempt = AuthAttempt(
            timestamp=time.time(),
            client_ip=client_ip,
            username=username,
            password=password,
        )

        with self._lockout_lock:
            # Check lockout
            if self._is_locked_out(client_ip):
                attempt.accepted = False
                attempt.rejection_reason = "lockout"
                self.attempts.append(attempt)
                safe_user = username.replace("\n", "\\n").replace("\r", "\\r")
                logger.info(f"Locked out: {safe_user}@{client_ip}")
                return AuthResult(False, username, "Account locked")

            # Increment attempt counter
            self.ip_attempt_counts[client_ip] = \
                self.ip_attempt_counts.get(client_ip, 0) + 1

            # Check lockout threshold
            if self.ip_attempt_counts[client_ip] >= self.config.lockout_after:
                self.ip_lockout_until[client_ip] = \
                    time.time() + self.config.lockout_duration
                attempt.accepted = False
                attempt.rejection_reason = "lockout_triggered"
                self.attempts.append(attempt)
                return AuthResult(False, username, "Too many attempts")

        # Mode-specific evaluation (outside lock — no shared-dict mutation)
        result = self._evaluate(username, password, client_ip)

        attempt.accepted = result.accepted
        attempt.rejection_reason = result.reason if not result.accepted else None
        self.attempts.append(attempt)

        logger.log(
            logging.INFO if result.accepted else logging.DEBUG,
            "Auth %s: user=%s from %s (mode=%s, reason=%s)",
            "SUCCESS" if result.accepted else "FAIL",
            username.replace("\n", "\\n"),
            client_ip,
            self.config.auth_mode,
            result.reason,
        )

        return result

    def _evaluate(
        self, username: str, password: str, client_ip: str
    ) -> AuthResult:
        """Mode-specific credential evaluation."""
        mode = self.config.auth_mode

        if mode == "open":
            return AuthResult(True, username, "open_mode")

        elif mode == "closed":
            return AuthResult(False, username, "closed_mode")

        elif mode == "selective":
            if (username in self.valid_creds
                    and self.valid_creds[username] == password):
                return AuthResult(True, username, "valid_credentials")
            return AuthResult(False, username, "invalid_credentials")

        elif mode == "realistic":
            # Track failures per IP — accept after N failures
            # with valid creds (simulates brute-force "success")
            ip_key = f"{client_ip}:{username}"

            creds_valid = (
                username in self.valid_creds
                and self.valid_creds[username] == password
            )

            with self._lockout_lock:
                if ip_key not in self.ip_fail_counts:
                    self.ip_fail_counts[ip_key] = 0

                if creds_valid:
                    if self.ip_fail_counts[ip_key] >= self.config.fail_before_success:
                        return AuthResult(True, username, "realistic_accept")
                    else:
                        # Reject even valid creds until threshold met
                        self.ip_fail_counts[ip_key] += 1
                        return AuthResult(False, username, "realistic_delay")
                else:
                    self.ip_fail_counts[ip_key] += 1
                    return AuthResult(False, username, "invalid_credentials")

        return AuthResult(False, username, "unknown_mode")

    def log_pubkey_attempt(
        self, username: str, key_b64: str, client_ip: str
    ):
        """Record a public key authentication attempt."""
        attempt = AuthAttempt(
            timestamp=time.time(),
            client_ip=client_ip,
            username=username,
            pubkey_fingerprint=key_b64[:44] + "...",  # Truncate for logging
            accepted=False,
            rejection_reason="pubkey_not_accepted",
        )
        self.attempts.append(attempt)
        safe_user = username.replace("\n", "\\n").replace("\r", "\\r")
        logger.info(
            f"Pubkey attempt: {safe_user} from {client_ip} "
            f"key={key_b64[:20]}..."
        )

    def _is_locked_out(self, client_ip: str) -> bool:
        if client_ip in self.ip_lockout_until:
            if time.time() < self.ip_lockout_until[client_ip]:
                return True
            else:
                del self.ip_lockout_until[client_ip]
                self.ip_attempt_counts[client_ip] = 0
        return False

    def get_all_attempts(self) -> list[dict]:
        """Export all attempts as dicts (for CTI pipeline)."""
        return [
            {
                "timestamp": a.timestamp,
                "client_ip": a.client_ip,
                "username": a.username,
                "password_present": bool(a.password),
                "pubkey": a.pubkey_fingerprint,
                "accepted": a.accepted,
                "reason": a.rejection_reason,
            }
            for a in self.attempts
        ]
