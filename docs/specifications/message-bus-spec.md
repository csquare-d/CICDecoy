# CI/CDecoy — Message Bus Specification
# platform/nats/message-bus-spec.md
#
# NATS JetStream is the event backbone of CI/CDecoy. Every interaction
# with every decoy flows through NATS as structured events. This spec
# defines the topic hierarchy, stream configuration, consumer patterns,
# delivery guarantees, and operational guidelines.

---

## Why NATS JetStream

The message bus is the central nervous system of the platform. It needs to:

1. Handle high-throughput bursts (a fleet of 50 decoys under scan = thousands of events/sec)
2. Guarantee delivery to the CTI pipeline (no lost attacker interactions)
3. Support real-time streaming to the dashboard and CLI watchers
4. Allow replay of historical events for forensics
5. Run efficiently on resource-constrained k3s nodes

NATS JetStream fits because it provides persistent streams with replay,
lightweight resource footprint (~30MB RAM for typical workloads), native
Kubernetes deployment, and subject-based routing that maps cleanly to
our decoy hierarchy. It also supports exactly-once delivery semantics
for the CTI pipeline while allowing ephemeral consumers for real-time
dashboards.

---

## Topic Hierarchy

All CI/CDecoy events use a dot-delimited subject namespace under the
`cicdecoy.` prefix. Wildcards are supported (`*` for single token,
`>` for multi-token suffix).

```
cicdecoy.
├── decoy.                              # All decoy-originated events
│   ├── events.                         # Interaction events
│   │   ├── {decoy-name}.              # Per-decoy namespace
│   │   │   ├── connection.new          # New TCP connection
│   │   │   ├── connection.error        # Connection-level error
│   │   │   ├── auth.attempt            # Authentication attempt (success or fail)
│   │   │   ├── auth.success            # Successful authentication
│   │   │   ├── auth.failure            # Failed authentication
│   │   │   ├── session.start           # Interactive session began
│   │   │   ├── session.end             # Session terminated
│   │   │   ├── session.error           # Session-level error
│   │   │   ├── command.exec            # Command executed by attacker
│   │   │   ├── command.response        # Response sent to attacker
│   │   │   ├── keystroke               # Raw keystroke timing data
│   │   │   ├── file.read               # Attacker read a file
│   │   │   ├── file.write              # Attacker wrote/created a file
│   │   │   ├── file.upload             # Attacker uploaded a file
│   │   │   └── file.exfil              # File exfiltration detected
│   │   └── _aggregate.                 # Pre-aggregated events
│   │       ├── auth_summary            # Auth attempt summaries (1min windows)
│   │       └── session_summary         # Session completion summaries
│   │
│   ├── health.                         # Decoy health & status
│   │   ├── {decoy-name}.
│   │   │   ├── heartbeat               # Periodic liveness signal
│   │   │   ├── status_change           # Status transition (active→degraded, etc.)
│   │   │   └── fingerprint_check       # Fingerprint validation result
│   │   └── _fleet.                     # Fleet-level health
│   │       ├── summary                 # Aggregated fleet health
│   │       └── rotation                # Rotation events
│   │
│   └── lifecycle.                      # Decoy lifecycle events
│       ├── {decoy-name}.
│       │   ├── deployed                # Decoy came online
│       │   ├── destroyed               # Decoy removed
│       │   ├── rotated                 # Identity rotation completed
│       │   └── config_updated          # Configuration change applied
│       └── _fleet.
│           ├── scale                   # Fleet scaled up/down
│           └── rotation_batch          # Fleet rotation batch event
│
├── honeytoken.                         # Honeytoken events
│   ├── triggered.                      # Token was accessed/used
│   │   ├── {token-name}.
│   │   │   ├── file_read               # Token file was read
│   │   │   ├── api_call                # Token credential used for API call
│   │   │   ├── network_egress          # Token data left the network
│   │   │   └── credential_stuffing     # Token appeared in breach data
│   │   └── _all                        # All triggers (for unified alerting)
│   └── status.
│       ├── {token-name}.active         # Token is deployed and monitored
│       └── {token-name}.expired        # Token has expired
│
├── alert.                              # Alert events (high-priority subset)
│   ├── critical                        # Critical severity alerts
│   ├── high                            # High severity alerts
│   ├── medium                          # Medium severity alerts
│   └── _all                            # All alerts unified
│
├── cti.                                # CTI pipeline events
│   ├── enriched.                       # Post-enrichment events
│   │   ├── event                       # Individual enriched event
│   │   └── session                     # Enriched session summary
│   ├── ioc.                            # IOC lifecycle
│   │   ├── new                         # New IOC generated
│   │   ├── updated                     # IOC sighting count updated
│   │   └── expired                     # IOC expired/deactivated
│   ├── stix.                           # STIX output
│   │   ├── bundle                      # New STIX bundle generated
│   │   └── indicator                   # Individual STIX indicator
│   └── report.                         # Reports
│       ├── daily                       # Daily intel summary
│       └── weekly                      # Weekly intel summary
│
├── inference.                          # LLM inference service events
│   ├── request                         # Inference request received
│   ├── response                        # Inference response sent
│   ├── cache_hit                       # Response served from cache
│   ├── error                           # Inference error
│   └── metrics                         # Periodic performance metrics
│
├── security.                           # Runtime security events
│   └── falco.                          # Falco eBPF alerts
│       ├── {node}.{pod}                # Per-node, per-pod alerts
│       ├── escape                      # Container escape attempts
│       ├── lateral_movement            # Outbound connections from decoys
│       └── recon                       # Container escape reconnaissance
│
└── platform.                           # Platform-level events
    ├── operator.                       # Operator events
    │   ├── reconcile                   # Reconciliation cycle
    │   ├── error                       # Operator error
    │   └── validation_failure          # CRD validation failure
    ├── health.                         # Platform component health
    │   ├── nats                        # NATS cluster health
    │   ├── inference                   # Inference service health
    │   ├── storage                     # Database health
    │   └── pipeline                    # CTI pipeline health
    └── audit.                          # Operator/admin actions
        ├── deploy                      # Decoy deployment
        ├── destroy                     # Decoy destruction
        ├── rotate                      # Manual rotation trigger
        └── config_change               # Configuration change
```

### Subject Naming Conventions

- Decoy names: lowercase, alphanumeric + hyphens (`bastion-dmz-01`)
- Token names: lowercase, alphanumeric + hyphens (`aws-prod-admin-canary`)
- No spaces, underscores only for reserved prefixes (`_aggregate`, `_fleet`, `_all`)
- Max subject length: 255 characters

### Common Subscription Patterns

```
# All events from a specific decoy
cicdecoy.decoy.events.bastion-dmz-01.>

# All authentication events across all decoys
cicdecoy.decoy.events.*.auth.*

# All critical alerts
cicdecoy.alert.critical

# All honeytoken triggers
cicdecoy.honeytoken.triggered.>

# All command executions (for the CTI pipeline)
cicdecoy.decoy.events.*.command.exec

# Everything (firehose — careful with bandwidth)
cicdecoy.>
```

---

## Stream Configuration

JetStream streams define how messages are persisted, retained, and replayed.

### Stream: `DECOY_EVENTS`

The primary event stream. Captures all decoy interaction data.

```yaml
name: DECOY_EVENTS
subjects:
  - "cicdecoy.decoy.events.>"
retention: limits              # Keep until limits hit
max_msgs: -1                   # Unlimited message count
max_bytes: 10737418240         # 10 GB max storage
max_age: 7776000000000000      # 90 days (nanoseconds)
max_msg_size: 1048576          # 1 MB per message
storage: file                  # Persistent file storage
num_replicas: 1                # Single replica (k3s)
discard: old                   # Discard oldest when limits hit
duplicate_window: 120000000000 # 2 minute dedup window (nanos)
allow_rollup: false
deny_delete: true              # Prevent message deletion (forensics)
deny_purge: true               # Prevent stream purge (forensics)
```

**Rationale:** 90-day retention at up to 10GB covers most operational
needs. File storage ensures persistence across pod restarts. Dedup
window prevents duplicate events from multiple exporters. Delete/purge
denial ensures forensic integrity.

### Stream: `ALERTS`

High-priority alert stream with shorter retention but guaranteed delivery.

```yaml
name: ALERTS
subjects:
  - "cicdecoy.alert.>"
  - "cicdecoy.honeytoken.triggered.>"
retention: interest            # Keep until all consumers ACK
max_msgs: 100000
max_bytes: 104857600           # 100 MB
max_age: 2592000000000000      # 30 days
storage: file
num_replicas: 1
discard: old
```

**Rationale:** Interest-based retention ensures alerts aren't discarded
until every consumer (Slack webhook, SIEM exporter, dashboard) has
processed them. Critical for ensuring no alerts are silently dropped.

### Stream: `CTI_OUTPUT`

Post-enrichment CTI data and generated intelligence products.

```yaml
name: CTI_OUTPUT
subjects:
  - "cicdecoy.cti.>"
retention: limits
max_msgs: -1
max_bytes: 5368709120          # 5 GB
max_age: 7776000000000000      # 90 days
storage: file
num_replicas: 1
discard: old
```

### Stream: `INFERENCE_METRICS`

LLM inference service telemetry. Lower priority, shorter retention.

```yaml
name: INFERENCE_METRICS
subjects:
  - "cicdecoy.inference.>"
retention: limits
max_msgs: 1000000
max_bytes: 1073741824          # 1 GB
max_age: 604800000000000       # 7 days
storage: file
num_replicas: 1
discard: old
```

### Stream: `FALCO_ALERTS`

Runtime security alerts from Falco eBPF monitoring. Captures container
escape attempts, lateral movement, and privilege escalation from decoy pods.
Correlated with decoy session data by the CTI pipeline.

```yaml
name: FALCO_ALERTS
subjects:
  - "cicdecoy.security.falco.>"
retention: limits
max_msgs: 500000
max_bytes: 536870912           # 512 MB
max_age: 2592000000000000      # 30 days
storage: file
num_replicas: 1
discard: old
deny_delete: true              # Forensic integrity
deny_purge: true
```

### Stream: `PLATFORM`

Platform-level events: operator actions, health, audit trail.

```yaml
name: PLATFORM
subjects:
  - "cicdecoy.platform.>"
  - "cicdecoy.decoy.health.>"
  - "cicdecoy.decoy.lifecycle.>"
retention: limits
max_msgs: 500000
max_bytes: 1073741824          # 1 GB
max_age: 7776000000000000      # 90 days
storage: file
num_replicas: 1
discard: old
deny_delete: true
deny_purge: true
```

---

## Consumer Definitions

Consumers define how downstream services read from streams. Two types:
- **Durable:** Named, persistent cursor. Survives restarts. For services that must process every message.
- **Ephemeral:** Unnamed, temporary. For real-time watchers. Missed messages during downtime are lost.

### Consumer: `cti-collector` (Durable)

The CTI pipeline collector. Must process every single event. This is the
most critical consumer — losing events means losing intelligence.

```yaml
stream: DECOY_EVENTS
durable_name: cti-collector
filter_subject: "cicdecoy.decoy.events.>"
deliver_policy: all            # Start from first available message
ack_policy: explicit           # Require explicit ACK per message
ack_wait: 30000000000          # 30 second ACK timeout (nanos)
max_deliver: 5                 # Retry up to 5 times
max_ack_pending: 5000          # Up to 5000 unACKed messages in flight
replay_policy: instant         # Deliver as fast as possible (catch-up)
sample_freq: "100"             # Sample 100% for metrics
```

**Flow:** Collector receives message → normalizes → enriches → stores
in TimescaleDB → ACKs the message. If processing fails, NATS redelivers
after 30 seconds, up to 5 times. After 5 failures, the message goes to
a dead-letter subject for manual investigation.

### Consumer: `alert-dispatcher` (Durable)

Routes alerts to Slack, SIEM, and other notification channels.

```yaml
stream: ALERTS
durable_name: alert-dispatcher
filter_subject: "cicdecoy.alert.>"
deliver_policy: new            # Only new messages (no backfill)
ack_policy: explicit
ack_wait: 10000000000          # 10 second ACK timeout
max_deliver: 10                # More retries (alerts are critical)
max_ack_pending: 100
```

### Consumer: `honeytoken-alerter` (Durable)

Dedicated consumer for honeytoken triggers. Separate from general
alerts because honeytoken triggers have different routing logic
(custom webhook callbacks, canary provider notifications).

```yaml
stream: ALERTS
durable_name: honeytoken-alerter
filter_subject: "cicdecoy.honeytoken.triggered.>"
deliver_policy: all
ack_policy: explicit
ack_wait: 15000000000          # 15 seconds
max_deliver: 10
max_ack_pending: 50
```

### Consumer: `siem-exporter` (Durable)

Pushes enriched events to external SIEMs (Splunk, Elastic, Sentinel).

```yaml
stream: CTI_OUTPUT
durable_name: siem-exporter
filter_subject: "cicdecoy.cti.enriched.>"
deliver_policy: all
ack_policy: explicit
ack_wait: 60000000000          # 60 seconds (SIEM ingest can be slow)
max_deliver: 3
max_ack_pending: 1000
```

### Consumer: `stix-publisher` (Durable)

Publishes STIX bundles to the TAXII server.

```yaml
stream: CTI_OUTPUT
durable_name: stix-publisher
filter_subject: "cicdecoy.cti.stix.>"
deliver_policy: all
ack_policy: explicit
ack_wait: 30000000000
max_deliver: 5
max_ack_pending: 100
```

### Consumer: `ioc-tracker` (Durable)

Maintains the IOC database — updates sighting counts, deactivates
expired indicators, generates new IOCs from enriched events.

```yaml
stream: CTI_OUTPUT
durable_name: ioc-tracker
filter_subject: "cicdecoy.cti.ioc.>"
deliver_policy: all
ack_policy: explicit
ack_wait: 15000000000
max_deliver: 5
max_ack_pending: 500
```

### Consumer: `dashboard-live` (Ephemeral)

Real-time event feed for the web dashboard. Ephemeral because the
dashboard can tolerate missing events during reconnection — it will
query the database for historical data.

```yaml
stream: DECOY_EVENTS
# No durable_name — ephemeral
filter_subject: "cicdecoy.decoy.events.>"
deliver_policy: new            # Only new events from now
ack_policy: none               # Fire-and-forget (fast)
replay_policy: instant
flow_control: true             # Backpressure if dashboard is slow
idle_heartbeat: 5000000000     # 5 second heartbeat
```

### Consumer: `cli-watcher` (Ephemeral)

Used by `cicdecoy sessions watch` and `cicdecoy logs` commands.
One ephemeral consumer per CLI session.

```yaml
stream: DECOY_EVENTS
filter_subject: "cicdecoy.decoy.events.{decoy-name}.>"  # Dynamic per CLI session
deliver_policy: new
ack_policy: none
idle_heartbeat: 10000000000    # 10 seconds
inactive_threshold: 60000000000 # Auto-cleanup after 60s idle
```

### Consumer: `health-monitor` (Durable)

Watches decoy health events and triggers operator actions (restart
degraded decoys, alert on offline decoys).

```yaml
stream: PLATFORM
durable_name: health-monitor
filter_subject: "cicdecoy.decoy.health.>"
deliver_policy: new
ack_policy: explicit
ack_wait: 10000000000
max_deliver: 3
max_ack_pending: 200
```

### Consumer: `falco-correlator` (Durable)

Correlates Falco runtime security alerts with active decoy sessions.
When a Falco alert fires for a decoy pod, this consumer matches it
to the concurrent session and enriches the session data with escape
attempt details. Updates the Engage outcome to reflect deception failure.

```yaml
stream: FALCO_ALERTS
durable_name: falco-correlator
filter_subject: "cicdecoy.security.falco.>"
deliver_policy: all
ack_policy: explicit
ack_wait: 15000000000          # 15 seconds
max_deliver: 5
max_ack_pending: 500
replay_policy: instant
```

---

## Event Schemas

All events are JSON-encoded. Every event includes a common header.

### Common Header

```json
{
  "event_id": "uuid-v4",
  "timestamp": "2024-01-18T14:03:22.847Z",
  "version": "1.0",
  "source": {
    "decoy": "bastion-dmz-01",
    "tier": 3,
    "pod": "decoy-bastion-dmz-01-7f8b9c-x4k2",
    "node": "k3s-worker-02"
  }
}
```

### Event: `command.exec`

```json
{
  "...common_header",
  "session_id": "uuid-v4",
  "event_type": "command.exec",
  "data": {
    "command": "cat /home/jmorales/.aws/credentials",
    "cwd": "/home/jmorales",
    "username": "jmorales",
    "uid": 1000,
    "command_index": 5,
    "env_snapshot": {
      "AWS_PROFILE": "prod-admin"
    }
  }
}
```

### Event: `auth.attempt`

```json
{
  "...common_header",
  "session_id": "pre-auth",
  "event_type": "auth.attempt",
  "data": {
    "client_ip": "45.33.32.156",
    "client_port": 48932,
    "username": "admin",
    "password": "admin123",
    "method": "password",
    "accepted": true,
    "reason": "realistic_accept",
    "attempt_number": 3
  }
}
```

### Event: `alert`

```json
{
  "...common_header",
  "session_id": "uuid-v4",
  "event_type": "alert",
  "data": {
    "severity": "critical",
    "behavior": "lateral_movement",
    "command": "ssh db-prod-01.corp.internal",
    "mitre_technique": "T1021.004",
    "mitre_name": "SSH",
    "client_ip": "45.33.32.156",
    "username": "jmorales"
  }
}
```

### Event: `honeytoken.triggered`

```json
{
  "...common_header",
  "session_id": "uuid-v4",
  "event_type": "honeytoken.triggered",
  "data": {
    "token_name": "aws-prod-admin-canary",
    "token_type": "aws-credential",
    "access_type": "file_read",
    "accessed_path": "/home/jmorales/.aws/credentials",
    "client_ip": "45.33.32.156",
    "username": "jmorales",
    "decoy_name": "bastion-dmz-01",
    "full_content_read": true
  }
}
```

---

## Deployment Configuration

### NATS Server (k3s Helm values)

```yaml
# platform/helm/cicdecoy/values-nats.yaml

nats:
  image:
    repository: nats
    tag: "2.10-alpine"

  resources:
    requests:
      cpu: 100m
      memory: 256Mi
    limits:
      cpu: 500m
      memory: 512Mi

  jetstream:
    enabled: true
    memStorage:
      enabled: true
      size: 256Mi           # In-memory buffer for hot data
    fileStorage:
      enabled: true
      size: 20Gi            # Persistent storage for all streams
      storageClassName: local-path  # k3s default storage class

  config:
    max_payload: 1048576    # 1 MB max message size
    max_connections: 1024
    write_deadline: "10s"

    jetstream:
      max_mem: 268435456    # 256 MB
      max_file: 21474836480 # 20 GB
      store_dir: /data/jetstream

  # Monitoring
  prometheus:
    enabled: true
    port: 7777

  # k3s-specific
  nodeSelector:
    cicdecoy.io/role: "platform"

  persistence:
    enabled: true
    size: 20Gi
    storageClass: local-path
```

### NATS Box (admin/debug sidecar)

```yaml
natsbox:
  enabled: true
  image:
    repository: natsio/nats-box
    tag: "0.14"
```

---

## Operational Procedures

### Stream Initialization

On first deployment, the operator creates all streams and durable
consumers. This is idempotent — running it again updates existing
streams without data loss.

```bash
# Initialize script (run by Helm post-install hook)
nats stream add DECOY_EVENTS \
  --subjects "cicdecoy.decoy.events.>" \
  --retention limits \
  --max-bytes 10GB \
  --max-age 90d \
  --storage file \
  --discard old \
  --dupe-window 2m \
  --deny-delete \
  --deny-purge

nats consumer add DECOY_EVENTS cti-collector \
  --filter "cicdecoy.decoy.events.>" \
  --deliver all \
  --ack explicit \
  --wait 30s \
  --max-deliver 5 \
  --max-pending 5000 \
  --replay instant

# ... repeat for all streams and consumers
```

### Monitoring

Key metrics to watch (exported to Prometheus):

```
# Stream health
jetstream_stream_messages{stream="DECOY_EVENTS"}         # Total messages in stream
jetstream_stream_bytes{stream="DECOY_EVENTS"}             # Storage used
jetstream_stream_consumer_count{stream="DECOY_EVENTS"}    # Active consumers

# Consumer health
jetstream_consumer_ack_pending{consumer="cti-collector"}  # Unprocessed messages
jetstream_consumer_num_redelivered{consumer="cti-collector"} # Failed deliveries
jetstream_consumer_delivered_stream_seq{consumer="cti-collector"} # Processing position

# Alert thresholds
# WARN: ack_pending > 1000 (consumer falling behind)
# CRIT: ack_pending > 5000 (consumer is stuck)
# WARN: num_redelivered increasing (processing failures)
# CRIT: stream_bytes > 8GB (approaching 10GB limit)
```

### Disaster Recovery

1. **Consumer falls behind:** Increase `max_ack_pending`. If persistent,
   scale up consumer replicas (CTI pipeline supports horizontal scaling).

2. **Stream approaching storage limit:** Increase `max_bytes` or decrease
   `max_age`. Consider archiving old data to object storage first.

3. **NATS pod restart:** JetStream recovers from file storage. Durable
   consumers resume from last ACKed position. Ephemeral consumers
   (dashboard, CLI) reconnect and receive only new events.

4. **Total data loss:** Redeploy NATS with stream definitions. Historical
   data is gone from the bus, but the CTI pipeline has already persisted
   everything to TimescaleDB. Only in-flight unprocessed events are lost.

### Backpressure Handling

If producers (decoys) emit faster than consumers can process:

1. JetStream buffers messages in the stream (up to `max_bytes`).
2. If a consumer's `max_ack_pending` is reached, NATS pauses delivery
   to that consumer until it ACKs some messages.
3. Producers are never blocked — they publish fire-and-forget to NATS.
   The stream absorbs bursts.
4. If the stream itself fills up, `discard: old` drops the oldest
   messages. This is acceptable because older events have likely
   already been processed by the CTI pipeline.

---

## Security

### Authentication

NATS uses decentralized JWT-based auth with NKeys.

```yaml
# Accounts
accounts:
  - name: DECOY_PRODUCERS
    # Decoy containers publish events
    permissions:
      publish:
        allow:
          - "cicdecoy.decoy.events.>"
          - "cicdecoy.honeytoken.triggered.>"
        deny:
          - "cicdecoy.platform.>"
          - "cicdecoy.cti.>"
      subscribe:
        deny:
          - ">"      # Decoys cannot subscribe to anything

  - name: CTI_PIPELINE
    # CTI services consume and produce
    permissions:
      publish:
        allow:
          - "cicdecoy.cti.>"
          - "cicdecoy.alert.>"
      subscribe:
        allow:
          - "cicdecoy.decoy.events.>"
          - "cicdecoy.honeytoken.triggered.>"

  - name: DASHBOARD
    # Read-only for UI
    permissions:
      publish:
        deny:
          - ">"
      subscribe:
        allow:
          - "cicdecoy.>"

  - name: OPERATOR
    # Full access for platform operator
    permissions:
      publish:
        allow:
          - "cicdecoy.platform.>"
          - "cicdecoy.decoy.lifecycle.>"
          - "cicdecoy.decoy.health.>"
      subscribe:
        allow:
          - "cicdecoy.>"

  - name: INFERENCE
    # Inference service metrics only
    permissions:
      publish:
        allow:
          - "cicdecoy.inference.>"
      subscribe:
        deny:
          - ">"
```

### Encryption

- **In-transit:** TLS 1.3 between all NATS clients and server.
  Certificates managed by cert-manager on k3s.
- **At-rest:** JetStream file storage encrypted via k3s encrypted
  storage class or LUKS on the underlying volume.

### Network Isolation

- NATS runs in the `cicdecoy-system` namespace.
- NetworkPolicies restrict access to NATS ports (4222, 6222, 7777)
  to only labeled pods within CI/CDecoy namespaces.
- Decoy pods can reach NATS but cannot reach each other.
- The inference service and CTI pipeline have separate network
  policy rules.
