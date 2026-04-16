"""Prometheus metrics for the CTI pipeline."""

from prometheus_client import Counter, Gauge, Histogram, Info

EVENTS_PROCESSED = Counter(
    "cicdecoy_cti_events_processed_total",
    "Total events processed by CTI pipeline",
    ["event_type"],
)

EVENTS_ERRORS = Counter(
    "cicdecoy_cti_errors_total",
    "CTI pipeline processing errors",
    ["error_type"],
)

ENRICHMENT_LATENCY = Histogram(
    "cicdecoy_cti_enrichment_seconds",
    "Event enrichment latency",
    buckets=[0.001, 0.005, 0.01, 0.05, 0.1, 0.5],
)

ACTIVE_SESSIONS = Gauge(
    "cicdecoy_cti_active_sessions",
    "Currently tracked active sessions",
)

FALCO_ALERTS = Counter(
    "cicdecoy_falco_alerts_total",
    "Total Falco runtime security alerts",
    ["rule", "priority"],
)

FALCO_CORRELATED = Counter(
    "cicdecoy_falco_correlated_total",
    "Falco alerts correlated with sessions",
)

NATS_CONSUMER_LAG = Gauge(
    "cicdecoy_cti_nats_consumer_pending",
    "NATS consumer pending message count",
    ["consumer"],
)

BUILD_INFO = Info(
    "cicdecoy_cti",
    "CTI pipeline build info",
)
BUILD_INFO.info({"version": "0.1.0", "component": "cti-pipeline"})
