"""Prometheus metrics for the inference gateway."""

from prometheus_client import Counter, Gauge, Histogram, Info

INFERENCE_REQUESTS = Counter(
    "cicdecoy_inference_requests_total",
    "Total inference requests",
    ["profile", "source"],  # source: llm, cache, fallback
)

INFERENCE_LATENCY = Histogram(
    "cicdecoy_inference_latency_seconds",
    "Inference request latency",
    ["profile"],
    buckets=[0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0],
)

INFERENCE_TOKENS = Counter(
    "cicdecoy_inference_tokens_total",
    "Total tokens consumed by LLM",
    ["profile"],
)

CACHE_SIZE = Gauge(
    "cicdecoy_inference_cache_entries",
    "Current response cache size",
)

FILTER_VIOLATIONS = Counter(
    "cicdecoy_response_filter_violations_total",
    "Response filter violations caught",
    ["violation_type"],
)

BUILD_INFO = Info(
    "cicdecoy_inference",
    "Inference gateway build info",
)
BUILD_INFO.info({"version": "0.1.0", "component": "inference-gateway"})
