"""Prometheus metrics for the dashboard backend."""

from prometheus_client import Counter, Gauge, Histogram, Info

API_REQUESTS = Counter(
    "cicdecoy_dashboard_requests_total",
    "Dashboard API requests",
    ["endpoint", "method"],
)

SSE_CONNECTIONS = Gauge(
    "cicdecoy_dashboard_sse_connections",
    "Active SSE connections",
)

EVENT_BUFFER_SIZE = Gauge(
    "cicdecoy_dashboard_event_buffer_size",
    "Current event buffer size",
)

DB_QUERY_LATENCY = Histogram(
    "cicdecoy_dashboard_db_query_seconds",
    "Database query latency",
    ["query"],
    buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5],
)

BUILD_INFO = Info(
    "cicdecoy_dashboard",
    "Dashboard build info",
)
BUILD_INFO.info({"version": "0.1.0", "component": "dashboard"})
