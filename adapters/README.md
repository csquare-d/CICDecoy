# CI/CDecoy Adapters

Third-party honeypot adapters for the CI/CDecoy intelligence pipeline.

## What This Does

Existing honeypots produce logs. CI/CDecoy produces intelligence. These adapters
bridge the gap: they read from honeypot-native output, translate events into the
CI/CDecoy common schema, and publish to NATS. Everything downstream — ATT&CK
mapping, session correlation, STIX output, Engage scoring — works identically
whether the event came from a native CI/CDecoy decoy or a third-party honeypot.

```
┌─────────────┐     ┌─────────────┐     ┌──────────────────────────────────┐
│   Cowrie     │     │   Adapter   │     │           NATS                  │
│  (SSH/Tel)   │────▶│  (sidecar)  │────▶│  cicdecoy.decoy.events.{d}.{t} │
│  JSON logs   │     │  translate  │     │                                  │
└─────────────┘     └─────────────┘     └──────────┬───────────────────────┘
                                                    │
┌─────────────┐     ┌─────────────┐                │
│   Dionaea   │     │   Adapter   │                │  (same NATS subjects as
│ (SMB/HTTP)  │────▶│  (sidecar)  │────────────────┤   native CI/CDecoy decoys)
│  JSON logs  │     │  translate  │                │
└─────────────┘     └─────────────┘                │
                                                    │
┌─────────────┐     ┌─────────────┐                │
│    T-Pot    │     │   Adapter   │                │
│   (multi)   │────▶│   (polls    │────────────────┘
│ Elasticsrch │     │    ES)      │
└─────────────┘     └─────────────┘
                                          ┌──────────────────────────────┐
                                          │  CI/CDecoy CTI Pipeline      │
                                          │                              │
                                          │  ┌────────────────────────┐  │
                                          │  │ Enrichment Service     │  │
                                          │  │ • GeoIP lookup         │  │
                                          │  │ • ATT&CK mapping       │  │
                                          │  │ • Tool identification  │  │
                                          │  │ • Threat feed lookup   │  │
                                          │  └──────────┬─────────────┘  │
                                          │             │                │
                                          │  ┌──────────▼─────────────┐  │
                                          │  │ Session Correlator     │  │
                                          │  │ • Cross-decoy linking  │  │
                                          │  │ • Kill chain detection │  │
                                          │  │ • Engage scoring       │  │
                                          │  └──────────┬─────────────┘  │
                                          │             │                │
                                          │  ┌──────────▼─────────────┐  │
                                          │  │ Storage + Output       │  │
                                          │  │ • TimescaleDB          │  │
                                          │  │ • STIX/TAXII           │  │
                                          │  │ • SIEM forwarding      │  │
                                          │  └────────────────────────┘  │
                                          └──────────────────────────────┘
```

## Available Adapters

| Adapter  | Source           | Protocols                | Status  |
|----------|-----------------|--------------------------|---------|
| Cowrie   | JSON log (tail)  | SSH, Telnet              | Draft   |
| Dionaea  | JSON log (tail)  | SMB, HTTP, FTP, MySQL    | Draft   |
| T-Pot    | Elasticsearch    | All T-Pot honeypots      | Draft   |

## Event Flow

Every adapter does exactly three things:

1. **Read** from the honeypot's native output
2. **Translate** to the CI/CDecoy common event schema
3. **Publish** to NATS on `cicdecoy.decoy.events.{decoy_name}.{event_type}`

No enrichment. No ATT&CK mapping. No correlation. Those happen downstream
and are shared across all event sources.

## Common Event Schema

Every event published to NATS has this structure, matching the `decoy_events`
table in TimescaleDB:

```json
{
  "event_id": "uuid-v4",
  "timestamp": "2024-01-18T14:03:22.847Z",
  "version": "1.0",
  "source": {
    "decoy": "bastion-dmz-01",
    "tier": 3
  },
  "session_id": "cowrie-a1b2c3d4",
  "event_type": "command.exec",
  "source_ip": "45.33.32.156",
  "source_port": 48932,
  "severity": "medium",
  "data": {
    "command": "cat /etc/passwd",
    "username": "admin"
  },
  "_adapter": {
    "name": "cowrie",
    "version": "0.1.0",
    "original_event_id": "cowrie.command.input",
    "ingest_latency_ms": 12
  }
}
```

### Event Types

| event_type            | Description                        | Cowrie | Dionaea | T-Pot |
|-----------------------|------------------------------------|--------|---------|-------|
| `connection`          | New connection to decoy            | ✓      | ✓       | ✓     |
| `auth.attempt`        | Login attempt (success or failure) | ✓      | ✓       | ✓     |
| `command.exec`        | Command executed in session        | ✓      |         | ✓     |
| `file.access`         | File download/upload               | ✓      | ✓       | ✓     |
| `alert`               | High-confidence indicator          |        |         |       |
| `honeytoken.triggered`| Honeytoken accessed                |        |         |       |
| `session.closed`      | Session ended                      | ✓      |         |       |

## Deployment

### Cowrie with adapter sidecar (Helm)

```bash
helm install cowrie-bastion ./deploy/helm/cowrie-adapter \
  --set decoy.name=bastion-dmz-01 \
  --set decoy.tier=3 \
  --set nats.url=nats://nats.cicdecoy.svc.cluster.local:4222 \
  --namespace cicdecoy
```

This deploys a pod with two containers:
- **cowrie**: runs the Cowrie SSH honeypot, writes JSON logs to a shared volume
- **adapter**: tails the JSON logs, translates, publishes to NATS

### T-Pot adapter (standalone)

```bash
docker run -e ADAPTER_TYPE=tpot \
  -e ADAPTER_DECOY_NAME=tpot-external-01 \
  -e TPOT_ES_URL=http://tpot-host:64298 \
  -e NATS_URL=nats://your-nats:4222 \
  ghcr.io/cicdecoy/adapter
```

## Writing a New Adapter

Implement the `adapter.Adapter` interface:

```go
type Adapter interface {
    Name() string
    Start(ctx context.Context, events chan<- schema.Event) error
    HealthCheck(ctx context.Context) error
}
```

Your adapter's `Start` method reads from whatever the honeypot produces and
sends `schema.Event` values to the channel. The publisher handles NATS.

The adapter contract is deliberately narrow:
- **Do** translate field names to the common schema
- **Do** set a baseline severity
- **Do** prefix session IDs to avoid collisions
- **Don't** do ATT&CK mapping (enrichment service handles this)
- **Don't** do session correlation (correlator handles this)
- **Don't** do GeoIP lookups (enrichment service handles this)

### Example: minimal adapter skeleton

```go
func (a *MyAdapter) Start(ctx context.Context, events chan<- schema.Event) error {
    for rawEvent := range a.readFromHoneypot(ctx) {
        event := schema.NewEvent("myhoneypot", a.cfg.DecoyName, a.cfg.DecoyTier)
        event.SessionID = "myhoneypot-" + rawEvent.SessionID
        event.EventType = mapEventType(rawEvent)
        event.SourceIP = rawEvent.RemoteAddr
        event.Severity = "info"
        event.Data = map[string]any{
            "protocol": rawEvent.Protocol,
            // ... honeypot-specific fields
        }
        events <- event
    }
    return nil
}
```