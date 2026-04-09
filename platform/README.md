# CI/CDecoy — Kubernetes Platform Layer

Helm chart, CLI, and operator that deploy the existing MVP stack to k3s.

## What This Adds to Your MVP

```
MVP/                              ← your existing code
├── ssh-decoy/                    ← builds cicdecoy-ssh image
├── cti/                          ← builds cicdecoy-cti-pipeline image
├── dashboard/                    ← builds cicdecoy-dashboard image
├── inference/                    ← builds cicdecoy-inference image
├── config/                       ← schema, nats.conf, engage, falco, profiles
├── profiles/
├── tests/
├── docker-compose.dev.yaml       ← existing dev workflow
│
├── operator/                     ← NEW: Kubernetes operator (kopf)
│   ├── reconciler.py             ← watches Decoy CRs → creates Deployments
│   ├── Dockerfile
│   └── requirements.txt
│
├── cli/                          ← NEW: cicdecoy CLI
│   ├── cicdecoy/main.py          ← validate, apply, render, list, status, fidelity-check
│   └── pyproject.toml
│
├── helm/                         ← NEW: Helm chart
│   ├── cicdecoy/
│   │   ├── Chart.yaml
│   │   ├── values.yaml
│   │   ├── crds/                 ← Decoy, DecoyTemplate, HoneyToken, DecoyProfile, DecoyFleet
│   │   ├── files/                ← populated by setup-helm-files.sh from config/
│   │   └── templates/
│   │       ├── _helpers.tpl      ← shared helpers + data env + wait containers
│   │       ├── rbac.yaml         ← SA + ClusterRole + Binding
│   │       ├── operator.yaml     ← operator Deployment + config ConfigMap
│   │       ├── timescaledb.yaml  ← StatefulSet + PVC + schema init + Secret
│   │       ├── nats-init.yaml    ← post-install Job: 6 streams, 7 consumers
│   │       ├── cti-pipeline.yaml ← pipeline Deployment + GeoIP updater
│   │       ├── dashboard.yaml    ← Deployment + Service + Ingress
│   │       ├── inference.yaml    ← Deployment + Service + model config
│   │       ├── configmaps.yaml   ← engage, profiles, responses, falco rules
│   │       ├── namespaces.yaml   ← decoy namespaces + NetworkPolicy
│   │       └── extras.yaml       ← SIEM forwarder + fidelity CronJob
│   └── values-dev.yaml           ← k3s local dev overrides
│
├── Makefile                      ← NEW: build → k3s-import → helm install
└── setup-helm-files.sh           ← NEW: copies config/ into helm/cicdecoy/files/
```

## Quickstart (k3s)

```bash
# 1. Install k3s
curl -sfL https://get.k3s.io | sh -
mkdir -p ~/.kube && sudo cp /etc/rancher/k3s/k3s.yaml ~/.kube/config

# 2. Prepare helm chart files from your existing configs
chmod +x setup-helm-files.sh
./setup-helm-files.sh

# 3. Build + deploy everything
make deploy

# 4. Install CLI
make cli-install

# 5. Deploy decoys via CRDs
cicdecoy validate config/dev-decoy.yaml
cicdecoy apply config/dev-decoy.yaml

# 6. Check everything
make status
```

## Architecture

```
                    ┌────────────────────────────┐
                    │      cicdecoy CLI           │
                    │  validate → apply → status  │
                    └─────────────┬──────────────┘
                                  │ Decoy CRs
                                  ▼
┌──────────────────────────────────────────────────────────────┐
│  Operator (kopf)                                              │
│  Decoy CR → Deployment(ssh-decoy + telemetry sidecar)         │
│           → Service(NodePort/ClusterIP)                       │
│           → NetworkPolicy(egress isolation)                   │
└──────┬───────────────────────────────────────────────────────┘
       │ raw events
       ▼
┌──────────────────────────────────────────────────────────────┐
│  NATS JetStream                                               │
│                                                               │
│  DECOY_EVENTS ─────┬─→ cti-pipeline consumer                 │
│                     └─→ siem-forwarder-normalized consumer    │
│                                                               │
│  ENRICHED_EVENTS ──┬─→ dashboard-live consumer                │
│                    └─→ siem-forwarder consumer                │
│                                                               │
│  ALERTS ───────────→ dashboard-alerts consumer                │
│  FALCO_ALERTS ─────→ falco-correlator consumer                │
│  HONEYTOKEN_EVENTS   (token trigger tracking)                 │
│  PLATFORM            (operator/health/audit)                  │
└──────┬───────────────────────────────────────────────────────┘
       │
       ▼
┌──────────────────┐     ┌──────────────────────────────┐
│  CTI Pipeline    │     │  Dashboard                    │
│  (cti/)          │     │  (dashboard/)                 │
│                  │     │                               │
│  enrichment.py ──┼──→  │  SSE live feed ← enriched     │
│  session_analyzer│     │  REST ← TimescaleDB           │
│  falco_correlator│     │  Session replay                │
│  engage_mapper   │     │  MITRE heatmap                 │
│                  │     │  Kill chain timeline            │
│  ┌───────────┐   │     │  Engage effectiveness           │
│  │TimescaleDB│◄──┘     │  Fleet status                  │
│  │           │◄────────┘                               │
│  │decoy_events│                                         │
│  │falco_alerts│         ┌──────────────────────────────┐
│  │engage_out  │         │  SIEM Forwarder (optional)   │
│  └───────────┘         │  Splunk HEC / Elastic / CEF   │
│                         └──────────────────────────────┘
│
│  ┌──────────────┐
│  │  Inference    │
│  │  (inference/) │
│  │  Tier 3 LLM   │
│  └──────────────┘
```

## NATS Streams & Consumers

Created automatically by a post-install Helm hook:

| Stream | Subjects | Retention | Purpose |
|--------|----------|-----------|---------|
| `DECOY_EVENTS` | `cicdecoy.decoy.events.>` | 72h / 5GB | Raw adapter events |
| `ENRICHED_EVENTS` | `cicdecoy.enriched.events.>` | 72h / 5GB | Post-enrichment |
| `ALERTS` | `cicdecoy.alert.>` | 7d / 1GB | High-severity |
| `HONEYTOKEN_EVENTS` | `cicdecoy.honeytoken.>` | 30d / 1GB | Token triggers |
| `FALCO_ALERTS` | `cicdecoy.security.falco.>` | 30d / 1GB | Container escapes (immutable) |
| `PLATFORM` | `cicdecoy.platform.>` | 7d / 1GB | Health, audit |

| Consumer | Stream | Deliver | Purpose |
|----------|--------|---------|---------|
| `cti-pipeline` | DECOY_EVENTS | all | Enrichment pipeline |
| `dashboard-live` | ENRICHED_EVENTS | new | SSE live feed |
| `dashboard-alerts` | ALERTS | new | Alert ticker |
| `falco-correlator` | FALCO_ALERTS | all | Escape correlation |
| `siem-forwarder` | ENRICHED_EVENTS | all | SIEM export (enriched) |
| `siem-forwarder-normalized` | DECOY_EVENTS | all | SIEM export (raw) |
| `health-monitor` | PLATFORM | new | Platform health |

## Data Flow

```
SSH Decoy → telemetry sidecar → NATS cicdecoy.decoy.events.{decoy}.{type}
  → CTI Pipeline:
      1. Parse raw event
      2. enrich_event() → MITRE techniques, tool sigs, severity, tags
      3. session_analyzer → behavioral profiling, intent classification
      4. GeoIP resolve (if enabled)
      5. Falco correlate (if container escape)
      6. engage_mapper → ENGAGE activity/outcome tracking
      7. INSERT into TimescaleDB decoy_events
      8. Republish → cicdecoy.enriched.events.{type}
      9. If severity >= high → cicdecoy.alert.{severity}
  → Dashboard reads enriched events via SSE + queries TimescaleDB via REST
  → SIEM Forwarder ships to Splunk/Elastic/syslog
```

## CLI Commands

```
cicdecoy validate <paths...>       Schema + fidelity pre-check
cicdecoy apply <paths...>          Validate and kubectl apply (dependency-ordered)
cicdecoy apply --dry-run <paths>   Server-side dry run
cicdecoy render <paths...>         Dump parsed manifests to stdout
cicdecoy list [-n ns] [-k kind]    List decoys, honeytokens, fleets
cicdecoy status <name> -n <ns>     Detailed status + ENGAGE mapping
cicdecoy fidelity-check <paths>    Banner, profile, telemetry checks
```

## Make Targets

```
make build              Build all Docker images
make k3s-import         Import images into k3s (no registry)
make helm-install       Install chart to k3s
make deploy             build + k3s-import + helm-install + wait
make status             Show pods, decoys, honeytokens, NATS streams
make logs-pipeline      Tail CTI pipeline logs
make logs-dashboard     Tail dashboard logs
make test               Run pytest suite
make clean              Uninstall + delete namespaces
```

## Migrating from docker-compose

Your existing `docker-compose.dev.yaml` still works for local development. The Helm chart deploys the same topology to k3s:

| docker-compose service | Helm component |
|------------------------|----------------|
| `ssh-decoy` | Operator creates per Decoy CR |
| `cti-pipeline` | `cti-pipeline` Deployment |
| `dashboard` | `dashboard` Deployment + NodePort 30080 |
| `inference` | `inference` Deployment |
| `nats` | NATS subchart + init Job |
| `timescaledb` | `timescaledb` StatefulSet + PVC |

The key difference: in docker-compose, the SSH decoy is a static container. In k3s, each `Decoy` CR triggers the operator to create a Deployment with the appropriate image, config mounts, and telemetry sidecar.
