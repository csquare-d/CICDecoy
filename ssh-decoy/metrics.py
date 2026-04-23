"""Prometheus metrics for the SSH decoy."""

from prometheus_client import Counter, Gauge, Histogram, Info

SESSIONS_TOTAL = Counter(
    "ssh_sessions_total",
    "Total SSH sessions",
    ["auth_result"],  # success, failed
)

ACTIVE_SESSIONS = Gauge(
    "ssh_active_sessions",
    "Currently active SSH sessions",
)

COMMANDS_PROCESSED = Counter(
    "ssh_commands_total",
    "Total commands processed",
    ["tier"],
)

SESSION_DURATION = Histogram(
    "ssh_session_duration_seconds",
    "SSH session duration",
    buckets=[1, 5, 10, 30, 60, 120, 300, 600, 1800, 3600],
)

AUTH_ATTEMPTS = Counter(
    "ssh_auth_attempts_total",
    "SSH authentication attempts",
    ["method", "result"],  # method: password, publickey; result: success, failed
)

CREDENTIALS_CAPTURED = Counter(
    "ssh_credentials_captured_total",
    "Unique credentials captured",
)

BUILD_INFO = Info(
    "ssh_server",
    "SSH server build info",
)
BUILD_INFO.info({"version": "0.1.0", "component": "ssh-server"})
