# Operational Runbooks

Common operational tasks for CI/CDecoy. These runbooks assume a Helm-based Kubernetes deployment. For local development, see [CONTRIBUTING.md](../CONTRIBUTING.md).

---

## Deploy a Decoy

### Via CLI

```bash
# Deploy from a manifest file
cicdecoy deploy -f decoy.yaml

# Deploy and wait for Active status
cicdecoy deploy -f decoy.yaml --wait

# Deploy to a specific namespace
cicdecoy deploy -f decoy.yaml -n decoy-dmz
```

### Via kubectl

```bash
kubectl apply -f decoy.yaml
kubectl get decoys -w  # Watch status progression: Pending → Deploying → Active
```

### Verify

```bash
# Check decoy status
kubectl get decoys
# NAME             TIER   SERVICE   ZONE   STATUS   INTERACTIONS   AGE
# ssh-bastion-01   2      ssh       dmz    Active   0              2m

# Check operator logs for reconciliation
kubectl logs -l app.kubernetes.io/component=operator -n cicdecoy --tail=50

# Check the decoy pod is running
kubectl get pods -l cicdecoy.io/decoy=ssh-bastion-01
```

---

## Destroy a Decoy

```bash
# Via CLI
cicdecoy destroy ssh-bastion-01

# Via kubectl
kubectl delete decoy ssh-bastion-01

# Destroy all decoys in a namespace
cicdecoy destroy --all -n decoy-dmz
```

The operator handles cleanup: Deployment, Service, and credential Secret are garbage-collected via ownerReferences.

---

## Monitor Active Sessions

### Real-time via CLI

```bash
# Watch live sessions across all decoys
cicdecoy sessions watch

# Watch a specific decoy
cicdecoy sessions watch --decoy ssh-bastion-01

# Watch with severity filter
cicdecoy sessions watch --severity high
```

### Real-time via Dashboard

Open `http://<dashboard>:8080` and navigate to the Sessions page. Events stream in real-time via SSE.

### Query historical sessions

```bash
# List recent sessions
cicdecoy sessions list --since 24h

# List sessions from a specific decoy
cicdecoy sessions list --decoy ssh-bastion-01

# List high-severity sessions
cicdecoy sessions list --severity high

# Replay a session in the terminal
cicdecoy sessions replay <session-id>
```

---

## Check Platform Health

### Quick status

```bash
cicdecoy status
```

Shows: decoy fleet summary, NATS connectivity, database health, inference service availability.

### Component-level checks

```bash
# NATS
kubectl exec -it deploy/cicdecoy-nats -n cicdecoy -- nats server check connection

# TimescaleDB
kubectl exec -it sts/cicdecoy-timescaledb -n cicdecoy -- pg_isready

# CTI Pipeline
kubectl logs -l app.kubernetes.io/component=cti-pipeline -n cicdecoy --tail=20

# Operator
kubectl logs -l app.kubernetes.io/component=operator -n cicdecoy --tail=20

# Dashboard
curl -H "X-API-Key: <key>" http://<dashboard>:8080/api/stats
```

### NATS stream health

```bash
# Check stream sizes and consumer lag
kubectl exec -it deploy/cicdecoy-nats -n cicdecoy -- nats stream ls
kubectl exec -it deploy/cicdecoy-nats -n cicdecoy -- nats consumer info DECOY_EVENTS cti-collector
```

Key metrics to watch:
- `num_pending`: messages waiting to be processed (consumer lag)
- `num_redelivered`: messages that failed processing and were redelivered
- `last_ack`: timestamp of last successful acknowledgment

---

## Investigate a Kill Chain Alert

When a kill chain alert fires (3+ MITRE tactics in one session):

1. **Identify the session**
   ```bash
   cicdecoy sessions list --severity critical --since 1h
   ```

2. **Replay the session**
   ```bash
   cicdecoy sessions replay <session-id>
   ```
   Or via dashboard: Sessions > click session > Replay tab

3. **Check the attacker's technique progression**
   - Dashboard: Sessions > click session > Kill Chain Timeline
   - CLI: the replay output shows MITRE technique annotations per command

4. **Export intelligence**
   ```bash
   # STIX bundle
   cicdecoy intel export --format stix --session <session-id>

   # CSV for spreadsheet analysis
   cicdecoy intel export --format csv --since 24h
   ```

5. **Check for repeat visitors**
   ```bash
   cicdecoy intel actors --since 7d
   ```

6. **Correlate with Falco alerts**
   ```bash
   kubectl logs -l app.kubernetes.io/component=cti-pipeline -n cicdecoy | grep "falco"
   ```

---

## Rotate Decoy Identities

Identity rotation changes the decoy's hostname, credentials, SSH keys, and banners to prevent attacker targeting.

```bash
# Rotate a single decoy
cicdecoy fleet rotate ssh-bastion-01

# Rotate all decoys in a fleet
cicdecoy fleet rotate --fleet dmz-ssh-fleet
```

The operator creates a new Deployment revision. Active sessions are drained gracefully during the rollout.

---

## Scale a Fleet

```bash
# Scale a fleet to 10 decoys
cicdecoy fleet scale dmz-ssh-fleet --replicas 10

# Check fleet status
cicdecoy fleet status dmz-ssh-fleet
```

---

## Export Threat Intelligence

```bash
# MITRE ATT&CK technique summary
cicdecoy intel mitre --since 30d

# IOC list (IPs, tools, techniques)
cicdecoy intel iocs --since 7d

# Threat actor clustering
cicdecoy intel actors --since 30d

# Full export
cicdecoy intel export --format json --since 30d > intel-export.json
cicdecoy intel export --format stix --since 30d > stix-bundle.json
cicdecoy intel export --format csv --since 30d > events.csv

# Generate a markdown intelligence report
cicdecoy intel report --since 7d --format md > weekly-report.md
```

---

## SIEM Forwarder Configuration

### Syslog

```yaml
# In Helm values.yaml
siemForwarder:
  enabled: true
  config:
    siemType: syslog
    outputFormat: cef
    syslogEndpoint: "syslog.corp.internal:514"
    syslogProtocol: tcp
    syslogFacility: local0
```

### Splunk HEC

```yaml
siemForwarder:
  enabled: true
  config:
    siemType: splunk_hec
    outputFormat: json
    splunkEndpoint: "https://splunk.corp.internal:8088"
    splunkIndex: cicdecoy
    splunkSource: cicdecoy-forwarder
  secrets:
    splunkHecToken: "<token>"  # Or use existingSecret
```

### Elasticsearch

```yaml
siemForwarder:
  enabled: true
  config:
    siemType: elastic
    outputFormat: ecs
    elasticEndpoint: "https://elastic.corp.internal:9200"
    elasticIndex: cicdecoy-raw
  secrets:
    elasticApiKey: "<api-key>"  # Or elasticPassword with elasticUsername
```

### Webhook (generic)

```yaml
siemForwarder:
  enabled: true
  config:
    siemType: webhook
    outputFormat: json
    webhookUrl: "https://soar.corp.internal/api/ingest"
    webhookHeaders: "Authorization:Bearer token123,X-Source:cicdecoy"
```

### Verify forwarding

```bash
# Check forwarder logs
kubectl logs -l app.kubernetes.io/component=siem-forwarder -n cicdecoy --tail=50

# Check NATS consumer lag (events waiting to be forwarded)
kubectl exec -it deploy/cicdecoy-nats -n cicdecoy -- \
  nats consumer info DECOY_EVENTS siem-forwarder-normalized
```

---

## Database Maintenance

### Manual backup

```bash
kubectl exec -it sts/cicdecoy-timescaledb -n cicdecoy -- \
  pg_dump -U cicdecoy cicdecoy | gzip > backup-$(date +%Y%m%d).sql.gz
```

### Check database size

```bash
kubectl exec -it sts/cicdecoy-timescaledb -n cicdecoy -- \
  psql -U cicdecoy -c "SELECT pg_size_pretty(pg_database_size('cicdecoy'));"
```

### Check hypertable chunk sizes

```bash
kubectl exec -it sts/cicdecoy-timescaledb -n cicdecoy -- \
  psql -U cicdecoy -c "SELECT hypertable_name, range_start, range_end, pg_size_pretty(total_bytes) FROM timescaledb_information.chunks ORDER BY range_end DESC LIMIT 10;"
```

### Manual retention cleanup

TimescaleDB retention policies are configured during schema initialization. To manually drop old data:

```bash
kubectl exec -it sts/cicdecoy-timescaledb -n cicdecoy -- \
  psql -U cicdecoy -c "SELECT drop_chunks('decoy_events', older_than => INTERVAL '90 days');"
```

---

## Troubleshooting

### Decoy stuck in "Deploying" status

```bash
# Check operator logs
kubectl logs -l app.kubernetes.io/component=operator -n cicdecoy --tail=100

# Check if the decoy pod is starting
kubectl get pods -l cicdecoy.io/decoy=<name> -o wide

# Check pod events
kubectl describe pod -l cicdecoy.io/decoy=<name>
```

Common causes:
- Image pull failure (check `imagePullSecrets` in values.yaml)
- Insufficient resources (check pod events for `Insufficient cpu/memory`)
- NATS not ready (check init container logs)

### Events not appearing in dashboard

```bash
# 1. Check if decoy is publishing to NATS
kubectl logs -l cicdecoy.io/decoy=<name> --tail=20

# 2. Check NATS stream has messages
kubectl exec -it deploy/cicdecoy-nats -n cicdecoy -- \
  nats stream info DECOY_EVENTS

# 3. Check CTI pipeline is consuming
kubectl logs -l app.kubernetes.io/component=cti-pipeline -n cicdecoy --tail=20

# 4. Check consumer lag
kubectl exec -it deploy/cicdecoy-nats -n cicdecoy -- \
  nats consumer info DECOY_EVENTS cti-collector

# 5. Check dashboard SSE connection
curl -N -H "X-API-Key: <key>" http://<dashboard>:8080/api/events/stream
```

### Inference service returning errors (Tier 3)

```bash
# Check inference pod
kubectl logs -l app.kubernetes.io/component=inference -n cicdecoy --tail=50

# Check Ollama is responding
kubectl exec -it deploy/cicdecoy-inference -n cicdecoy -- \
  curl -s http://localhost:11434/api/tags

# Check model is loaded
kubectl exec -it deploy/cicdecoy-inference -n cicdecoy -- \
  curl -s http://localhost:11434/api/tags | jq '.models[].name'
```

Common causes:
- Ollama hasn't finished downloading the model (check logs for download progress)
- Insufficient memory (Tier 3 inference needs 4+ GB RAM)
- Model name mismatch between Decoy spec and inference config

### High NATS consumer lag

If `num_pending` is growing:

```bash
# Check pipeline processing rate
kubectl logs -l app.kubernetes.io/component=cti-pipeline -n cicdecoy --tail=20 | grep "event_count"

# Check for database connection issues
kubectl logs -l app.kubernetes.io/component=cti-pipeline -n cicdecoy --tail=50 | grep -i "error\|timeout"

# Check TimescaleDB load
kubectl exec -it sts/cicdecoy-timescaledb -n cicdecoy -- \
  psql -U cicdecoy -c "SELECT count(*) FROM pg_stat_activity WHERE state = 'active';"
```

If the pipeline is healthy but lag persists, the event rate exceeds processing capacity. Consider:
- Increasing pipeline resources (CPU/memory)
- Adding event filtering in the SIEM forwarder to reduce load
- Scaling TimescaleDB storage

### Dashboard API returning 503

```bash
# Check database connectivity
kubectl exec -it deploy/cicdecoy-dashboard -n cicdecoy -- \
  curl -s http://localhost:8080/healthz

# Check dashboard logs
kubectl logs -l app.kubernetes.io/component=dashboard -n cicdecoy --tail=50
```

The dashboard returns 503 when it cannot connect to TimescaleDB. Check database pod health and network policies.
