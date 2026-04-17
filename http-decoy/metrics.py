"""Prometheus metrics for the HTTP decoy."""

import re

from prometheus_client import Counter, Gauge, Histogram, Info

BUILD_INFO = Info("cicdecoy_http_decoy", "HTTP Decoy build information")
BUILD_INFO.info({"version": "0.1.0", "tier": "2"})

# Request metrics
HTTP_REQUESTS = Counter(
    "cicdecoy_http_requests_total",
    "Total HTTP requests received",
    ["method", "path_group", "status_code"],
)

CREDENTIALS_CAPTURED = Counter(
    "cicdecoy_http_credentials_captured_total",
    "Total credential submissions captured",
    ["portal"],  # aws, gitlab, jenkins, wordpress, corporate, outlook, phpmyadmin, grafana, admin, api
)

ACTIVE_SESSIONS = Gauge(
    "cicdecoy_http_active_sessions",
    "Number of active attacker sessions",
)

SESSION_DURATION = Histogram(
    "cicdecoy_http_session_duration_seconds",
    "Duration of attacker sessions",
    buckets=[10, 30, 60, 120, 300, 600, 1800, 3600],
)

REQUEST_LATENCY = Histogram(
    "cicdecoy_http_request_latency_seconds",
    "Request processing latency",
    ["method"],
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0],
)

INJECTION_ATTEMPTS = Counter(
    "cicdecoy_http_injection_attempts_total",
    "Detected injection attempts (SQLi, XSS, path traversal)",
    ["type"],  # sqli, xss, path_traversal, ssti, log4shell
)

SCANNER_DETECTIONS = Counter(
    "cicdecoy_http_scanner_detections_total",
    "Detected automated scanner activity",
    ["tool"],  # sqlmap, nikto, wpscan, nuclei, gobuster, burp, etc.
)

SENSITIVE_PATH_PROBES = Counter(
    "cicdecoy_http_sensitive_path_probes_total",
    "Probes for sensitive paths (.env, .git, config files)",
    ["path_category"],  # git, env, config, backup, debug, admin
)

ATTACK_TECHNIQUES = Counter(
    "cicdecoy_http_attack_techniques_total",
    "MITRE ATT&CK techniques observed",
    ["technique_id", "tactic"],
)


def normalize_path_group(path: str) -> str:
    """Normalize request path for Prometheus label (avoid cardinality explosion)."""
    # Replace UUIDs, numeric IDs, etc. with placeholders
    path = re.sub(r'/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', '/:uuid', path)
    path = re.sub(r'/\d+', '/:id', path)
    # Truncate to first 2 segments for API paths
    if path.startswith('/api/'):
        parts = path.split('/')
        return '/'.join(parts[:4]) if len(parts) > 4 else path
    return path
