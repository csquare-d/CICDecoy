# Observability

CI/CDecoy exposes Prometheus metrics from all core services. The project intentionally does **not** bundle Prometheus, Grafana, or any monitoring stack — operators are expected to use their existing observability infrastructure.

## Metrics Endpoints

| Service | Port | Path | Notes |
|---------|------|------|-------|
| Operator | 8080 | `/metrics` | kopf built-in metrics |
| Inference Gateway | 8000 | `/metrics` | Mounted as ASGI sub-app |
| Dashboard | 8080 | `/metrics` | Mounted as ASGI sub-app |
| CTI Pipeline | 9090 | `/metrics` | Standalone HTTP server |
| SSH Decoy | 9091 | `/metrics` | Standalone HTTP server |

## Key Metrics

### SSH Decoy (`cicdecoy_ssh_*`)

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `cicdecoy_ssh_sessions_total` | Counter | `auth_result` | Total SSH sessions |
| `cicdecoy_ssh_active_sessions` | Gauge | — | Currently active sessions |
| `cicdecoy_ssh_commands_total` | Counter | `tier` | Commands processed |
| `cicdecoy_ssh_session_duration_seconds` | Histogram | — | Session duration distribution |
| `cicdecoy_ssh_auth_attempts_total` | Counter | `method`, `result` | Auth attempts by method |
| `cicdecoy_ssh_credentials_captured_total` | Counter | — | Unique credentials captured |

### Inference Gateway (`cicdecoy_inference_*`)

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `cicdecoy_inference_requests_total` | Counter | `profile`, `source` | Requests by source (llm/cache/fallback) |
| `cicdecoy_inference_latency_seconds` | Histogram | `profile` | Inference latency with buckets up to 30s |
| `cicdecoy_inference_tokens_total` | Counter | `profile` | LLM tokens consumed |
| `cicdecoy_inference_cache_entries` | Gauge | — | Response cache size |
| `cicdecoy_response_filter_violations_total` | Counter | `violation_type` | Security filter catches |

### CTI Pipeline (`cicdecoy_cti_*`)

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `cicdecoy_cti_events_processed_total` | Counter | `event_type` | Events processed |
| `cicdecoy_cti_errors_total` | Counter | `error_type` | Processing errors |
| `cicdecoy_cti_enrichment_seconds` | Histogram | — | Enrichment latency |
| `cicdecoy_cti_active_sessions` | Gauge | — | Tracked sessions |
| `cicdecoy_falco_alerts_total` | Counter | `rule`, `priority` | Falco alerts received |
| `cicdecoy_falco_correlated_total` | Counter | — | Alerts correlated with sessions |
| `cicdecoy_cti_nats_consumer_pending` | Gauge | `consumer` | NATS consumer lag |

### Dashboard (`cicdecoy_dashboard_*`)

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `cicdecoy_dashboard_requests_total` | Counter | `endpoint`, `method` | API requests |
| `cicdecoy_dashboard_sse_connections` | Gauge | — | Active SSE connections |
| `cicdecoy_dashboard_event_buffer_size` | Gauge | — | Event buffer size |
| `cicdecoy_dashboard_db_query_seconds` | Histogram | `query` | DB query latency |

## Kubernetes — ServiceMonitor

If you use the [Prometheus Operator](https://github.com/prometheus-operator/prometheus-operator), enable ServiceMonitors in your Helm values:

```yaml
monitoring:
  serviceMonitor:
    enabled: true
    namespace: monitoring        # namespace where Prometheus runs
    interval: 30s
    additionalLabels:            # match your Prometheus serviceMonitorSelector
      release: kube-prometheus
```

This creates ServiceMonitor resources for operator, inference, dashboard, and CTI pipeline.

## NATS Monitoring

NATS exposes its own monitoring HTTP endpoint on port 8222:

```bash
# Stream stats (includes consumer lag)
curl -s http://localhost:8222/jsz?streams=true | jq .

# Connection stats
curl -s http://localhost:8222/connz | jq .

# General server stats
curl -s http://localhost:8222/varz | jq .
```

For Prometheus scraping of NATS, deploy the [nats-exporter](https://github.com/nats-io/prometheus-nats-exporter) alongside NATS.

## TimescaleDB Monitoring

TimescaleDB (PostgreSQL) metrics can be scraped via [postgres_exporter](https://github.com/prometheus-community/postgres_exporter). Key queries:

```sql
-- Hypertable sizes
SELECT hypertable_name, pg_size_pretty(hypertable_size(format('%I.%I', hypertable_schema, hypertable_name)::regclass))
FROM timescaledb_information.hypertables;

-- Chunk compression stats
SELECT * FROM timescaledb_information.compressed_chunk_stats;

-- Retention policy status
SELECT * FROM timescaledb_information.jobs WHERE proc_name = 'policy_retention';
```

## Health Checks

All services expose health endpoints used by Kubernetes probes:

| Service | Liveness | Readiness |
|---------|----------|-----------|
| Operator | `/healthz` (port 8081) | `/readyz` (port 8081) |
| Dashboard | `/api/stats` (port 8080) | `/api/stats` (port 8080) |
| Inference | `/v1/health` (port 8000) | `/v1/health` (port 8000) |
| NATS | `/healthz` (port 8222) | `/healthz` (port 8222) |
| TimescaleDB | `pg_isready` | `pg_isready` |

## What We Don't Bundle (and Why)

| Tool | Why Not |
|------|---------|
| **Prometheus** | Operators already have it. Bundling creates conflicts with existing scrape configs. |
| **Grafana** | Same reason. We expose standard metrics — any dashboard tool works. |
| **Loki/ELK** | Container stdout goes to the operator's existing log pipeline. |
| **OpenTelemetry** | Distributed tracing is planned for post-1.0. Current service count doesn't justify the complexity. |
| **Alerting rules** | Too deployment-specific. Document what to alert on (see below), don't prescribe thresholds. |

## Recommended Alerts

These are suggestions — tune thresholds for your deployment:

| Alert | Query | Severity |
|-------|-------|----------|
| Inference latency spike | `histogram_quantile(0.95, cicdecoy_inference_latency_seconds) > 5` | warning |
| CTI consumer lag | `cicdecoy_cti_nats_consumer_pending > 1000` | warning |
| Falco escape detected | `increase(cicdecoy_falco_alerts_total{priority="Critical"}[5m]) > 0` | critical |
| No events processed | `increase(cicdecoy_cti_events_processed_total[10m]) == 0` | warning |
| SSH decoy down | `cicdecoy_ssh_active_sessions == 0 AND up{job="ssh-decoy"} == 0` | critical |
| High error rate | `rate(cicdecoy_cti_errors_total[5m]) / rate(cicdecoy_cti_events_processed_total[5m]) > 0.05` | warning |
| Cache hit rate low | `cicdecoy_inference_cache_entries / cicdecoy_inference_requests_total < 0.1` | info |

## Local Development

In docker-compose, metrics endpoints are available on the mapped ports:

```bash
# Inference metrics (if using tier3 profile)
curl -s http://localhost:8000/metrics

# Dashboard metrics
curl -s http://localhost:8080/metrics

# NATS monitoring
curl -s http://localhost:8222/varz
```
