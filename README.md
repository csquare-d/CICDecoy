# CI/CDecoy

**Cyber deception infrastructure deployed through CI/CD pipelines.**

CI/CDecoy is a platform that lets security teams define, version, and continuously deploy cyber deception assets — honeypots, honeytokens, and decoy services — using familiar GitOps workflows on Kubernetes (k3s). Every interaction with a decoy is captured, enriched with threat intelligence context, and output as structured CTI.

```
┌─────────────┐     ┌──────────┐     ┌───────────┐     ┌───────────┐
│  Git Repo   │────▶│  CI/CD   │────▶│  k3s      │────▶│  CTI      │
│  (Decoy     │     │  Pipeline│     │  Cluster  │     │  Pipeline │
│   Manifests)│     │          │     │  (Decoys) │     │  (STIX)   │
└─────────────┘     └──────────┘     └───────────┘     └───────────┘
```

## Key Features

**Decoy-as-Code.** Decoys are defined in YAML manifests, version-controlled in Git, and deployed through CI/CD pipelines. Your deception posture is auditable, reproducible, and rollback-capable.

**Three Fidelity Tiers.** Tier 1 beacons log connections with minimal resources. Tier 2 scripted decoys handle common interactions. Tier 3 adaptive decoys use an LLM to generate contextually coherent responses that maintain state across a full interactive session.

**LLM-Backed Interaction.** Tier 3 decoys connect to a shared inference gateway that gives each decoy a "personality" — complete with a realistic filesystem, user accounts, bash history, and installed software. Attackers get convincing responses to arbitrary commands.

**Automated CTI Generation.** Every interaction flows through an enrichment pipeline that performs GeoIP resolution, MITRE ATT&CK mapping, threat feed correlation, tool identification, and behavioral analysis. Output as STIX 2.1 bundles, IOC feeds, or direct SIEM integration.

**Kubernetes-Native.** Decoys are managed through Custom Resource Definitions. `kubectl get decoys` works. The operator handles scheduling, health checks, rotation, and auto-recovery.

**Fleet Management.** Deploy dozens of decoys with randomized identities from a single `DecoyFleet` manifest. Automatic rotation refreshes decoy identities on a configurable schedule.

---

## Quick Start

### Prerequisites

- k3s cluster (v1.26+)
- Helm 3
- `kubectl` configured for your cluster

### Install the Platform

```bash
# Add the CI/CDecoy Helm repo
helm repo add cicdecoy https://ghcr.io/cicdecoy/charts

# Install
helm install cicdecoy cicdecoy/cicdecoy \
  --namespace cicdecoy-system --create-namespace \
  --wait
```

### Deploy Your First Decoy

```yaml
# my-first-decoy.yaml
apiVersion: cicdecoy.io/v1alpha1
kind: Decoy
metadata:
  name: ssh-honeypot-01
  namespace: decoys-production
spec:
  service:
    type: ssh
    port: 22
  fidelity:
    tier: 2
    scripted:
      responseSet: "openssh-8.9"
  identity:
    hostname: "web-server-03"
    os:
      family: linux
      distribution: "Ubuntu"
      version: "22.04 LTS"
  authentication:
    mode: selective
    credentials:
      - username: admin
        password: admin123
  telemetry:
    sessionCapture:
      fullTranscript: true
```

```bash
kubectl apply -f my-first-decoy.yaml

# Check status
kubectl get decoys -n decoys-production
cicdecoy status decoys
```

### Watch Live Sessions

```bash
# Real-time activity stream
cicdecoy sessions watch

# List active sessions
cicdecoy sessions list --live

# Replay a session
cicdecoy sessions replay <session-id> --annotated
```

### Query Intelligence

```bash
# Active IOCs
cicdecoy intel iocs --severity high --since 24h

# MITRE ATT&CK summary
cicdecoy intel mitre --since 7d

# Generate report
cicdecoy intel report --period daily --format md
```

---

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                        k3s Cluster                             │
│                                                                │
│  ┌──────────────────────┐  ┌────────────────────────────────┐  │
│  │   Decoy Operator     │  │   Decoy Fleet                  │  │
│  │   (CRD Controller)   │  │   ┌─────┐ ┌─────┐ ┌─────┐     │  │
│  │                      │──│   │ SSH │ │ HTTP│ │ SMB │ ... │  │
│  └──────────────────────┘  │   │ T3  │ │ T2  │ │ T1  │     │  │
│                            │   └──┬──┘ └──┬──┘ └──┬──┘     │  │
│  ┌──────────────────────┐  └─────│────────│───────│─────────┘  │
│  │  Inference Gateway   │◄───────┘        │       │            │
│  │  (LLM Service)       │        ┌───────┘───────┘            │
│  └──────────────────────┘        ▼                             │
│                            ┌──────────┐                        │
│                            │   NATS   │ (Message Bus)          │
│                            └────┬─────┘                        │
│                                 │                              │
│  ┌──────────────────────────────┼────────────────────────────┐ │
│  │         CTI Pipeline         │                            │ │
│  │  ┌──────────┐  ┌────────────┴──┐  ┌───────────────────┐  │ │
│  │  │Collector │─▶│  Enrichment   │─▶│  Output           │  │ │
│  │  │          │  │  GeoIP,MITRE  │  │  STIX,IOCs,SIEM   │  │ │
│  │  └──────────┘  │  Feeds,Tools  │  └───────────────────┘  │ │
│  │                └───────────────┘                          │ │
│  └───────────────────────┬───────────────────────────────────┘ │
│                          │                                     │
│                    ┌─────▼─────┐    ┌─────────────┐            │
│                    │TimescaleDB│    │  Dashboard   │            │
│                    │           │◄───│  (Web UI)    │            │
│                    └───────────┘    └─────────────┘            │
└────────────────────────────────────────────────────────────────┘
```

### Components

| Component | Purpose | Language |
|-----------|---------|----------|
| Decoy Operator | Reconciles Decoy CRDs into running pods | Go |
| SSH/HTTP/SMB Decoys | Protocol emulation containers | Python |
| Inference Gateway | Shared LLM service for Tier 3 decoys | Python (FastAPI) |
| CTI Pipeline | Event collection, enrichment, output | Python |
| Message Bus | Event routing between all components | NATS JetStream |
| Storage | Time-series event database | TimescaleDB |
| Dashboard | Web UI for operators | React/TypeScript |
| CLI | Command-line management tool | Go |

---

## Documentation

| Document | Description |
|----------|-------------|
| [Getting Started](docs/getting-started.md) | Installation and first decoy deployment |
| [Architecture](docs/architecture.md) | System design and data flow |
| [Decoy Authoring](docs/decoy-authoring.md) | Writing decoy manifests |
| [Profile Authoring](docs/profile-authoring.md) | Creating system personalities for Tier 3 |
| [CTI Integration](docs/cti-integration.md) | Connecting to SIEMs and TIPs |
| [CLI Reference](docs/cli-reference.md) | Complete CLI command documentation |
| [Threat Model](docs/threat-model.md) | Security considerations |
| [Contributing](CONTRIBUTING.md) | Development setup and guidelines |

---

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.
