# Architecture Overview

CI/CDecoy is a Kubernetes-native deception platform. This page explains how the components fit together.

For the visual architecture diagram, see the [Platform Architecture](../README.md#platform-architecture) section in the README (rendered as interactive Mermaid diagrams on GitHub).

---

## Component Map

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Kubernetes Cluster                           │
│                                                                     │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────┐   │
│  │SSH Decoy │  │SSH Decoy │  │HTTP Decoy│  │  Decoy Operator  │   │
│  │ (Tier 2) │  │ (Tier 3) │  │ 7 portals│  │  (kopf/Python)   │   │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────────┬─────────┘   │
│       │              │             │                  │             │
│       │   ┌──────────▼─────────────▼──┐     watches Decoy CRDs    │
│       └──►│     NATS JetStream        │◄──────────────┘            │
│           │  cicdecoy.decoy.events.>  │                            │
│           └──────────┬────────────────┘                            │
│                      │                                              │
│           ┌──────────▼────────────┐     ┌────────────────────┐     │
│           │    CTI Pipeline       │     │  Inference Service  │     │
│           │ enrich → classify →   │     │  Ollama / vLLM      │     │
│           │ score  → alert        │     │  prompt → filter     │     │
│           └──────────┬────────────┘     └────────────────────┘     │
│                      │                                              │
│           ┌──────────▼────────────┐     ┌────────────────────┐     │
│           │    TimescaleDB        │     │   SIEM Forwarder    │     │
│           │  events, sessions,    │     │  JSON/CEF/LEEF/ECS  │     │
│           │  IOCs, engage         │     │  → Splunk/Elastic/  │     │
│           └──────────┬────────────┘     │    Syslog/Webhook   │     │
│                      │                  └────────────────────┘     │
│           ┌──────────▼────────────┐                                │
│           │     Dashboard         │                                │
│           │  REST API + SSE       │                                │
│           │  React SPA            │                                │
│           └───────────────────────┘                                │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Data Flow

Every attacker interaction follows this path:

1. **Attacker connects** to a decoy (SSH or HTTP)
2. **Decoy publishes** events to NATS JetStream (`cicdecoy.decoy.events.{decoy_name}.{event_type}`)
3. **CTI Pipeline** consumes events via durable pull subscriber (`cti-collector`)
   - **Enriches** with MITRE ATT&CK technique mappings (70+ patterns) and tool signatures (48 tools)
   - **Classifies** the session: scanner → basic_operator → manual_operator → advanced_threat
   - **Scores** behavior: 0.0-1.0 weighted across 6 factors
   - **Detects** kill chains (3+ MITRE tactics in one session)
   - **Publishes** alerts to `cicdecoy.alert.session.{type}` and enriched events to `cicdecoy.enriched.events.>`
4. **TimescaleDB** stores all events as time-series data with JSONB columns for flexible querying
5. **Dashboard** subscribes to enriched events via SSE for real-time display
6. **SIEM Forwarder** (optional) subscribes to events and forwards to external SIEMs
7. **Alerting** dispatches to Slack, Teams, PagerDuty on high-severity events

### Tier 3 (Adaptive) Flow

When a Tier 3 decoy receives a command it can't handle locally:

1. Decoy's command router exhausts local handlers (builtins → fast-path → common → hifi engine)
2. Falls through to **inference service** via HTTP POST
3. **Prompt engine** builds system prompt from DecoyProfile + session context
4. **LLM** (Ollama/vLLM) generates response
5. **Response filter** strips AI identity leaks, infrastructure references, capability denials
6. **Response cache** stores deterministic command outputs (uname, cat /etc/hostname, etc.)
7. Filtered response returned to decoy → sent to attacker

---

## Component Details

| Component | Language | Location | Port | Description |
|-----------|----------|----------|------|-------------|
| **Decoy Operator** | Python (kopf) | `platform/operator/` | 8080 (metrics), 8081 (health) | Watches Decoy CRDs, creates Deployments + Services + Secrets |
| **SSH Decoy** | Python (asyncssh) | `ssh-decoy/` | 22 (configurable) | Full shell emulation: 83+ commands, COW filesystem, SFTP, SCP |
| **HTTP Decoy** | Python (FastAPI) | `http-decoy/` | 8080 (configurable) | 7 login portals, attack detection, credential capture |
| **CTI Pipeline** | Python (asyncio) | `cti/` | 9090 (metrics) | Event enrichment, session analysis, alerting, Engage mapping |
| **Inference Service** | Python (FastAPI) | `inference/` | 8000 | LLM gateway with prompt engineering and response filtering |
| **Dashboard** | Python + React | `dashboard/` | 8080 | REST API, SSE streaming, session replay, MITRE heatmap |
| **SIEM Forwarder** | Go | `siem-forwarder/` | — | Multi-format export to Splunk, Elastic, syslog, webhook |
| **CLI** | Go | `platform/cli/` | — | Deploy, destroy, monitor, export intelligence |
| **NATS** | — (upstream image) | — | 4222 | JetStream message bus for all event transport |
| **TimescaleDB** | — (upstream image) | — | 5432 | Time-series event storage with hypertables |

---

## NATS Streams

All inter-component communication flows through NATS JetStream:

| Stream | Subjects | Retention | Purpose |
|--------|----------|-----------|---------|
| `DECOY_EVENTS` | `cicdecoy.decoy.events.>` | 72h / 5GB | Raw decoy interactions |
| `ENRICHED_EVENTS` | `cicdecoy.enriched.events.>` | 72h / 5GB | CTI-enriched events (dashboard, SIEM) |
| `ALERTS` | `cicdecoy.alert.>` | 168h / 1GB | High-severity session alerts |
| `HONEYTOKEN_EVENTS` | `cicdecoy.honeytoken.>` | 720h / 1GB | Honeytoken access events |
| `FALCO_ALERTS` | `cicdecoy.security.falco.>` | 720h / 1GB | Falco runtime security alerts |
| `PLATFORM` | `cicdecoy.platform.>` | 168h / 1GB | Operator/health events |
| `SIEM_FORWARDER_DLQ` | `cicdecoy.siem.dlq` | 720h / 1GB | SIEM forwarder dead-letter queue |

See [Message Bus Specification](specifications/message-bus-spec.md) for the full topic hierarchy.

---

## Fidelity Tiers

| Tier | Name | Behavior | Resource Cost | Use Case |
|------|------|----------|--------------|----------|
| **1** | Beacon | Listen on port, log connections, no interaction | Minimal (50m CPU / 64Mi) | Perimeter detection, network scanning |
| **2** | Scripted | Deterministic response trees from pre-built sets | Low (200m CPU / 128Mi) | Credential harvesting, tool detection |
| **3** | Adaptive | LLM-generated responses with session coherence | Medium-High (needs inference service) | Advanced threat engagement, TTP elicitation |

The command router resolution chain for SSH is: shell builtins → fast-path config → 83 common handlers → hifi engine (38 templates) → tier dispatch (Tier 1: "not found", Tier 2: scripted, Tier 3: LLM inference).

---

## Security Model

All components follow defense-in-depth:

- **Non-root containers** (UID 65534 for control plane, UID 70 for TimescaleDB)
- **Read-only root filesystems** with tmpfs for runtime state
- **All capabilities dropped** (`drop: [ALL]`)
- **No privilege escalation** (`allowPrivilegeEscalation: false`)
- **PodDisruptionBudgets** enabled by default for all control plane components
- **Network egress** restricted via NetworkPolicy (decoys can only reach NATS)
- **NATS authentication** via shared secret
- **Dashboard API key** authentication with rate limiting (100 req/min)
- **Inference response filtering** prevents LLM from leaking infrastructure details
- **CSRF protection** on all HTTP decoy login forms (hmac.compare_digest)
- **Input validation** via Pydantic field validators on inference requests

---

## Related Documentation

- [CRD Reference](crd-reference.md) — Schema for all 5 custom resources
- [API Reference](api-reference.md) — Dashboard REST API endpoints
- [Database Schema](database-schema.md) — TimescaleDB tables, indexes, queries
- [Message Bus Spec](specifications/message-bus-spec.md) — NATS topic hierarchy
- [Deception as Code Spec](specifications/deception-as-code-spec.md) — Design philosophy
- [Decoy Manifest Schema](specifications/decoy-manifest-schema.md) — Manifest authoring guide
- [Operational Runbooks](runbooks.md) — Deploy, monitor, troubleshoot
- [ROADMAP](ROADMAP.md) — Planned features by version
