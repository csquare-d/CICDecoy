# CI/CDecoy v0.1.0 — Initial Release

**Deception as Code for Kubernetes**
CI/CDecoy is an open-source platform that lets security teams define, version, and deploy cyber deception assets — honeypots, honeytokens, and decoy services — through GitOps workflows on Kubernetes. Every attacker interaction is captured, enriched with MITRE ATT&CK context, and output as structured threat intelligence.

This is the first official release.

## Highlights

- **Decoy-as-Code** — Define deception assets as YAML manifests in Git. Deploy through CI/CD pipelines. Version, review, and roll back like any other infrastructure.

- **Three Fidelity Tiers** — Tier 1 (beacon/port listener), Tier 2 (scripted high-fidelity responses), and Tier 3 (LLM-adaptive via locally-hosted Ollama — zero API keys, zero cloud dependencies).

- **Built-in Threat Intelligence** — Automatic MITRE ATT&CK mapping across 70+ techniques, tool signature detection for 48 attacker tools, behavioral scoring, GeoIP enrichment, kill chain reconstruction, and STIX 2.1 output.

- **Kubernetes-Native** — Decoys are Custom Resources. A kopf-based operator handles scheduling, lifecycle, and credential rotation. Helm chart included.

- **Zero API Keys Required** — The default stack runs entirely offline. Tier 3 LLM support uses Ollama locally. No cloud vendor lock-in.

## What's Included

### Decoy Services

| Service | Description |
|---------|-------------|
| **SSH Decoy** | Full SSH honeypot with real authentication, interactive shell, command routing, SFTP/SCP capture, copy-on-write filesystem, and session recording. Supports all three fidelity tiers. |
| **HTTP Decoy** | Login portal honeypot with 8 built-in themes (corporate, AWS, GitLab, WordPress, Jenkins, Outlook, phpMyAdmin, Grafana). Captures credentials, tracks sessions, spoofs server headers. |

### Platform

| Component | Description |
|-----------|-------------|
| **Kubernetes Operator** | Reconciles `Decoy` CRDs into pods, services, and secrets. Handles credential generation, NATS wiring, and status reporting. |
| **CTI Pipeline** | Event collector and correlator. Subscribes to NATS JetStream, enriches events with ATT&CK mappings, tool signatures, and behavioral analysis, then stores in TimescaleDB. |
| **Dashboard** | React frontend + FastAPI backend. Live event feed via SSE, session replay, MITRE ATT&CK heatmap, MITRE Engage mapping, and REST API with key-based authentication. |
| **SIEM Forwarder** | Go service that exports events to Splunk HEC, Elasticsearch, syslog, and webhooks in JSON, CEF, LEEF, and ECS formats. Includes dead-letter queue and retry logic. |
| **CLI** | `cicdecoy` command-line tool for deploying decoys, validating configs, replaying sessions, and querying threat intel. Binaries for Linux, macOS, and Windows. |
| **Inference Gateway** | Shared LLM gateway for Tier 3 adaptive responses. Supports Ollama, OpenAI-compatible APIs, and local model hosting. |
| **Adapters** | Integration layer for third-party honeypots (Cowrie, Dionaea) to normalize events into the CI/CDecoy pipeline. |

### Infrastructure

- **NATS JetStream** for durable event routing between all services
- **TimescaleDB** for time-series event storage with automatic retention policies
- **Helm chart** with NATS subchart dependency, RBAC, PodDisruptionBudgets, and security-hardened pod specs
- **Chainguard base images** (zero CVE OS layer) for all Python and Go services
- **Docker Compose** for local development — `docker compose up --build` and you're running

### CI/CD

- Unit tests for all Python and Go services
- E2E smoke test on k3d (Helm install, operator reconciliation, SSH probe, event pipeline verification)
- Docker Compose integration test
- Trivy container scanning
- CodeQL static analysis
- Automated release pipeline: multi-arch container images to GHCR, CLI binaries, Helm chart packaging

## Quick Start

**Local development (no Kubernetes required):**

```bash
git clone https://github.com/csquare-d/CICDecoy.git
cd CICDecoy
docker compose up --build

# In another terminal:
ssh admin@localhost -p 2222  # password: admin123
# Open http://localhost:8080 for the dashboard
```

**With Tier 3 LLM support (100% local, no API key):**

```bash
docker compose --profile tier3 up --build
ssh admin@localhost -p 2223  # password: admin123
# First run pulls ~2GB model — subsequent starts are instant
```

**Kubernetes (Helm):**

```bash
helm repo add nats https://nats-io.github.io/k8s/helm/charts/
helm dependency build platform/helm/cicdecoy
helm install cicdecoy platform/helm/cicdecoy -n cicdecoy-system --create-namespace
```

## Known Limitations

This is a v0.1.0 release — functional and tested, but not yet production-hardened.

- Operator does not yet support webhook validation for Decoy CRDs
- HTTP Decoy does not yet support Tier 3 (LLM-adaptive) responses
- Alerting integrations (Slack, Teams, PagerDuty) are planned for v0.2.0
- Threat feed enrichment (GreyNoise, AbuseIPDB) is planned for v0.2.0
- Honeytoken support is planned for v0.2.0
- Additional decoy types (MySQL, PostgreSQL, Kubernetes API, SMB) are on the roadmap

See the [ROADMAP](https://github.com/csquare-d/CICDecoy/blob/main/docs/ROADMAP.md) for the full plan.

## Release Assets

| Asset | Description |
|-------|-------------|
| `cicdecoy-linux-amd64` | CLI binary (Linux x86_64) |
| `cicdecoy-linux-arm64` | CLI binary (Linux ARM64) |
| `cicdecoy-darwin-amd64` | CLI binary (macOS Intel) |
| `cicdecoy-darwin-arm64` | CLI binary (macOS Apple Silicon) |
| `cicdecoy-windows-amd64.exe` | CLI binary (Windows x86_64) |
| `cicdecoy-*.tgz` | Helm chart package |
| `checksums.txt` | SHA-256 checksums for all assets |

**Container images** (GHCR):

```
ghcr.io/csquare-d/cicdecoy-ssh:0.1.0
ghcr.io/csquare-d/cicdecoy-cti-pipeline:0.1.0
ghcr.io/csquare-d/cicdecoy-dashboard:0.1.0
ghcr.io/csquare-d/cicdecoy-operator:0.1.0
ghcr.io/csquare-d/cicdecoy-inference:0.1.0
ghcr.io/csquare-d/cicdecoy-siem-forwarder:0.1.0
ghcr.io/csquare-d/cicdecoy-http-decoy:0.1.0
ghcr.io/csquare-d/cicdecoy-telemetry:0.1.0
```

## Links

- **Website:** https://cicdecoy.systems/
- **Documentation:** [README](https://github.com/csquare-d/CICDecoy/blob/main/README.md)
- **Roadmap:** [ROADMAP.md](https://github.com/csquare-d/CICDecoy/blob/main/docs/ROADMAP.md)
- **License:** Apache 2.0

*Built with rigor and purpose.*
