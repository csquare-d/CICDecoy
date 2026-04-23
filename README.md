# CI/CDecoy

**The open-source framework for Deception as Code.**

CI/CDecoy lets security teams define, version, and continuously deploy cyber deception assets. Honeypots, honeytokens, and decoy services, all using familiar GitOps workflows on Kubernetes. Every interaction with a decoy is captured, enriched with threat intelligence context, and output as structured CTI.

```yaml
apiVersion: cicdecoy.io/v1alpha1
kind: Decoy
metadata:
  name: ssh-jumpbox-03
spec:
  service: { type: ssh, port: 22 }
  fidelity: { tier: 3, adaptive: { model: llama3 } }
  identity: { hostname: "jump-03", profileRef: "sre-workstation" }
  authentication:
    mode: selective
    credentials:
      - { username: admin, password: "W3lcome2024!" }
  telemetry:
    sessionCapture: { fullTranscript: true, keystrokeTimings: true }
  engage:
    activity: EAC0001
    goal: EG0001
    hypothesis: "Adversaries targeting the DMZ will attempt SSH credential access."
```

```bash
cicdecoy validate decoys/
cicdecoy deploy decoys/ --wait
cicdecoy sessions watch --annotated
```

## Key Features

**Decoy-as-Code.** Decoys are YAML manifests, version-controlled in Git, deployed through CI/CD. Your deception deployments are auditable, reproducible, and rollback-capable.

**Three Fidelity Tiers.** Tier 1 beacons log connections with minimal resources. Tier 2 scripted decoys handle common interactions with realistic entropy. Tier 3 adaptive decoys use an LLM — for SSH, this means contextually coherent responses across a full interactive shell session; for HTTP, Tier 3 provides dynamic content generation and enrichment (realistic page content, search results, API data, fake database exports) while the protocol layer remains scripted.

**LLM-Backed Interaction.** Tier 3 SSH decoys connect to a shared inference gateway that gives each decoy a personality, a realistic filesystem, user accounts, bash history, and installed software. Tier 3 HTTP decoys use the same inference gateway for dynamic content generation — producing realistic blog posts, user directories, file listings, API responses, and error pages rather than static templates.

**Automated CTI Generation.** Every interaction flows through an enrichment pipeline: MITRE ATT&CK mapping, tool identification, behavioral analysis, GeoIP resolution, and kill chain reconstruction. Output as structured JSON, CSV, or direct SIEM integration. STIX 2.1 indicator export is available for IOCs; full STIX bundle export and TAXII server integration are planned.

**Kubernetes-Native.** Decoys are Custom Resource Definitions. `kubectl get decoys` works. The operator handles scheduling, health checks, rotation, and auto-recovery.

**Fleet Management.** Deploy dozens of decoys from a single `DecoyFleet` manifest with randomized identities and configurable rotation schedules.

**MITRE Engage Integration.** Every decoy maps to ENGAGE activities, approaches, and goals with per-session intelligence value tracking and null criteria.

**Third-Party Adapters.** Thin sidecar adapters that will translate Cowrie, Dionaea, T-Pot, and others into the CI/CDecoy common event schema. The pipeline doesn't care where the event came from.

**SIEM Forwarder.** Ship events to Splunk, Elastic, or syslog in enriched or normalized mode. Run both simultaneously.

## How CI/CDecoy Compares

The deception technology landscape ranges from single-protocol open-source honeypots to enterprise platforms with hefty price tags. CI/CDecoy occupies a distinct position: it brings Deception-as-Code, LLM-adaptive fidelity, and a Kubernetes-native operating model to an open-source framework with an integrated CTI pipeline. The table below is an honest look at where each option excels.

| Capability | CI/CDecoy | Single-Protocol Honeypots | T-Pot | Commercial Platforms |
|---|---|---|---|---|
| **Protocol Coverage** | SSH + HTTP (more planned) | One protocol (SSH, HTTP, SMB, etc.) | ~20 protocols via bundled honeypots | Broad coverage |
| **Interaction Fidelity** | Tier 1-3 (beacon → scripted → LLM-adaptive) | Medium to high within their protocol | Varies by bundled honeypot | Medium to high |
| **LLM-Adaptive Responses** | Local LLM via inference gateway | Not supported | Not supported | Not supported |
| **MITRE ATT&CK Mapping** | Automatic per-session | Not supported | Manual / community rules | Automatic |
| **Kill Chain Detection** | Real-time reconstruction | Not supported | Not supported | Included |
| **Kubernetes Native** | CRDs + Operator | Not supported | Docker only | Varies by vendor |
| **Deception as Code** | GitOps-ready YAML manifests | Not supported | Not supported | Not supported |
| **Integrated CTI Pipeline** | NATS + TimescaleDB | Log files only | ELK stack | Proprietary |
| **Real-time Dashboard** | SSE + React | Rarely included | Kibana | Included |
| **SIEM Forwarding** | Splunk, Elastic, syslog | Manual export | Supported | Supported |
| **Fleet Management** | DecoyFleet CRD | Not supported | Not supported | Supported |
| **Behavioral Scoring** | Session analysis + intent classification | Not supported | Not supported | Supported |
| **Open Source** | Apache 2.0 | Varies (BSD, GPL, MIT) | GPL | Proprietary |
| **Cost** | Free | Free | Free | $$$$ |

> **Worth noting:** Single-protocol honeypots like Cowrie (SSH), Dionaea (SMB/HTTP), and Conpot (ICS) are battle-tested and often offer the deepest emulation within their specialty. T-Pot provides unmatched protocol breadth by composing dozens of these honeypots into a single deployment. Commercial platforms deliver enterprise support, SLAs, and mature integrations. CI/CDecoy's differentiators are its Deception-as-Code model, LLM-driven interaction fidelity, Kubernetes-native architecture, and built-in CTI enrichment pipeline.

## Platform Architecture

```mermaid

graph TB
    subgraph SRC["<b>SOURCE CONTROL</b><br/>Decoy-as-Code"]
        REPO[("Git Repository<br/>Decoy Manifests<br/>Profiles &amp; Templates")]
        PR["Pull Request<br/>Review &amp; Approve<br/>Deception Changes"]
    end

    subgraph CICD["<b>CI/CD PIPELINE</b>"]
        BUILD["Build<br/>Container Images"]
        VALIDATE["Validate<br/>Fidelity Tests<br/>nmap · banners · timing"]
        STAGE["Staging<br/>Deploy to test namespace<br/>Interaction smoke tests"]
        PROMOTE["Promote<br/>GitOps sync to production"]
    end

    subgraph K3S["<b>K3S CLUSTER</b>"]

        subgraph CTRL["Control Plane"]
            OP["Decoy Operator<br/>CRD Controller"]
            GITOPS["ArgoCD / Flux<br/>GitOps Reconciler"]
        end

        subgraph DECOYS["Decoy Fleet"]
            subgraph T1["Tier 1 — Beacon"]
                T1A["Port Listener<br/>TCP/UDP"]
                T1B["Banner Service<br/>SSH · HTTP · FTP"]
            end
            subgraph T2["Tier 2 — Scripted"]
                T2A["SSH Honeypot<br/>Scripted Responses"]
                T2B["HTTP Webapp<br/>Fake Login · API<br/>(Planned)"]
                T2C["SMB Share<br/>Honeytoken Files<br/>(Planned)"]
            end
            subgraph T3["Tier 3 — Adaptive (LLM)"]
                T3A["SSH Server<br/>Full Shell Emulation"]
                T3B["MySQL Server<br/>Query Processing<br/>(Planned)"]
                T3C["Web App<br/>Dynamic Content<br/>Generation (Planned)"]
            end
        end

        subgraph INFERENCE["LLM Inference Service"]
            GW["Inference Gateway<br/>FastAPI"]
            PROMPT["Prompt Engine<br/>Profile + State → Prompt"]
            CACHE["Response Cache<br/>Common Commands"]
            FILTER["Output Filter<br/>Leak Prevention"]
            MODEL["LLM Runtime<br/>Local Model · vLLM / Ollama"]
        end

        subgraph BUS["Message Bus"]
            NATS["NATS / Kafka<br/>Interaction Events"]
        end

        subgraph TOKENS["Honeytokens (Planned)"]
            HT1["AWS Creds<br/>Canary Keys"]
            HT2["Kubeconfig<br/>Fake Cluster"]
            HT3["DB Dump<br/>Seeded Data"]
        end
    end

    subgraph CTI["<b>CTI PIPELINE</b>"]
        COLLECT["Collector<br/>Ingest · Normalize<br/>Deduplicate"]
        ENRICH["Enrichment<br/>GeoIP · Threat Feeds<br/>MITRE ATT&amp;CK Mapping<br/>Tool Identification"]
        ANALYZE["Session Analyzer<br/>Behavioral Profiling<br/>Intent Classification"]
        STORE[("TimescaleDB<br/>Interaction Store")]
    end

    subgraph OUTPUT["<b>CTI OUTPUT</b>"]
        STIX["STIX 2.1<br/>Bundles<br/>(Planned)"]
        TAXII["TAXII Server<br/>Intel Sharing<br/>(Planned)"]
        SIEM["SIEM Export<br/>Splunk · Elastic<br/>Sentinel"]
        IOC["IOC Feed<br/>IPs · Hashes<br/>Domains · TTPs"]
        REPORT["Intel Reports<br/>Human-Readable"]
    end

    subgraph DASH["<b>DASHBOARD</b>"]
        UI["Web UI"]
        MAP["Deployment<br/>Topology"]
        REPLAY["Session<br/>Replay"]
        INTEL["Threat<br/>Intelligence"]
    end

    %% ── Source → Pipeline ──
    REPO --> PR
    PR --> BUILD
    BUILD --> VALIDATE
    VALIDATE --> STAGE
    STAGE --> PROMOTE

    %% ── Pipeline → Cluster ──
    PROMOTE --> GITOPS
    GITOPS --> OP

    %% ── Operator → Decoys ──
    OP --> T1
    OP --> T2
    OP --> T3
    OP --> TOKENS

    %% ── Tier 3 → Inference ──
    T3A -. "command + state" .-> GW
    T3B -. "query + schema (planned)" .-> GW
    T3C -. "content generation (planned)" .-> GW
    GW --> PROMPT
    GW --> CACHE
    PROMPT --> MODEL
    MODEL --> FILTER
    FILTER -. "response" .-> GW

    %% ── All Decoys → Message Bus ──
    T1 -- "connection logs" --> NATS
    T2 -- "interaction logs" --> NATS
    T3 -- "full session data" --> NATS
    TOKENS -- "access alerts" --> NATS

    %% ── Bus → CTI Pipeline ──
    NATS --> COLLECT
    COLLECT --> ENRICH
    ENRICH --> ANALYZE
    ANALYZE --> STORE

    %% ── Store → Outputs ──
    STORE --> STIX
    STORE --> TAXII
    STORE --> SIEM
    STORE --> IOC
    STORE --> REPORT

    %% ── Dashboard ──
    STORE --> UI
    UI --> MAP
    UI --> REPLAY
    UI --> INTEL

    %% ── Styling ──
    classDef source fill:#2d3748,stroke:#4a5568,color:#e2e8f0,stroke-width:2px
    classDef pipeline fill:#1a365d,stroke:#2b6cb0,color:#bee3f8,stroke-width:2px
    classDef cluster fill:#1c4532,stroke:#276749,color:#c6f6d5,stroke-width:2px
    classDef tier1 fill:#744210,stroke:#975a16,color:#fefcbf,stroke-width:1px
    classDef tier2 fill:#7b341e,stroke:#9c4221,color:#feebc8,stroke-width:1px
    classDef tier3 fill:#553c9a,stroke:#6b46c1,color:#e9d8fd,stroke-width:2px
    classDef inference fill:#553c9a,stroke:#805ad5,color:#e9d8fd,stroke-width:2px
    classDef cti fill:#234e52,stroke:#2c7a7b,color:#b2f5ea,stroke-width:2px
    classDef output fill:#1a365d,stroke:#3182ce,color:#bee3f8,stroke-width:2px
    classDef dash fill:#322659,stroke:#553c9a,color:#e9d8fd,stroke-width:2px
    classDef bus fill:#975a16,stroke:#d69e2e,color:#fefcbf,stroke-width:2px

    class REPO,PR source
    class BUILD,VALIDATE,STAGE,PROMOTE pipeline
    class OP,GITOPS cluster
    class T1A,T1B tier1
    class T2A,T2B,T2C tier2
    class T3A,T3B,T3C tier3
    class GW,PROMPT,CACHE,FILTER,MODEL inference
    class NATS bus
    class HT1,HT2,HT3 tier1
    class COLLECT,ENRICH,ANALYZE,STORE cti
    class STIX,TAXII,SIEM,IOC,REPORT output
    class UI,MAP,REPLAY,INTEL dash
```

```mermaid
graph LR
    A[Decoy] -->|sidecar| B(NATS · raw)
    B --> C{CTI Pipeline}
    C -->|ATT&CK · GeoIP · tools| D[(TimescaleDB)]
    C --> E(NATS · enriched)
    C -->|severity ≥ high| F(NATS · alerts)
    E --> G[Dashboard]
    E --> H[SIEM Forwarder]
    F --> G
```

### Components

| Component | Purpose | Language |
|-----------|---------|----------|
| **Operator** | Reconciles Decoy CRDs into running pods | Python (kopf) |
| **CLI** | Deploy, validate, replay, query intelligence | Go (cobra) |
| **SSH Decoy** | Tier 1-3 SSH honeypot with LLM integration | Python |
| **Inference Gateway** | Shared LLM service for Tier 3 decoys | Python (FastAPI) |
| **CTI Pipeline** | Event enrichment, ATT&CK mapping, storage | Python |
| **Dashboard** | Web UI: live feed, session replay, MITRE heatmap | React + FastAPI |
| **NATS JetStream** | Event routing between all components | — |
| **TimescaleDB** | Time-series event storage | — |
| **Adapters** | Sidecar translators for third-party honeypots | Go |
| **SIEM Forwarder** | Export to Splunk, Elastic, syslog, CEF | Python |

## Quick Start

### Prerequisites

- k3s cluster (v1.26+)
- Helm 3
- `kubectl` configured for your cluster

### Install

```bash
# Install the platform
helm repo add cicdecoy https://ghcr.io/cicdecoy/charts
helm install cicdecoy cicdecoy/cicdecoy \
  --namespace cicdecoy-system --create-namespace --wait

# Install the CLI
# (download from releases, or build from source)
make -C platform cli-build
sudo cp platform/bin/cicdecoy /usr/local/bin/
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
    scriptedResponses: "openssh-8.9"
  identity:
    hostname: "web-server-03"
    os: { family: linux, distro: "Ubuntu 22.04.3 LTS" }
  authentication:
    mode: selective
    credentials:
      - { username: admin, password: admin123 }
  telemetry:
    sessionCapture: { fullTranscript: true }
    exporter:
      type: nats
      endpoint: "nats://nats:4222"
      subject: "cicdecoy.events.ssh"
```

```bash
cicdecoy validate my-first-decoy.yaml
cicdecoy deploy my-first-decoy.yaml --wait
cicdecoy status decoys
```

### Watch Live Sessions

```bash
cicdecoy sessions watch --annotated
cicdecoy sessions list --live --severity high
cicdecoy sessions replay <session-id> --speed 2
```

### Query Intelligence

```bash
cicdecoy intel iocs --severity high --since 24h
cicdecoy intel mitre --since 7d
cicdecoy intel report --period weekly --format md -o report.md
cicdecoy intel export --format stix --since 30d -o monthly.stix.json
```

## Repository Structure

```bash
cicdecoy/
│
├── ssh-decoy/                      Tier 1–3 SSH honeypot (Python, asyncssh)
├── http-decoy/                     Tier 1–2 HTTP honeypot (Python, FastAPI)
├── cti/                            CTI enrichment pipeline
│   ├── pipeline.py                   NATS → enrich → TimescaleDB → republish
│   ├── enrichment.py                 MITRE ATT&CK + tool detection
│   ├── session_analyzer.py           Behavioral profiling + intent classification
│   ├── falco_correlator.py           Container escape correlation
│   └── engage_mapper.py              MITRE Engage outcome tracking
├── dashboard/                      React + FastAPI web UI
│   ├── main.py                       Backend — SSE, REST, NATS subscriber
│   └── src/                          React SPA — sessions, replay, MITRE heatmap
├── inference/                      LLM inference gateway for Tier 3
│
├── config/                         Shared infrastructure config
│   ├── schema.sql                    TimescaleDB schema
│   ├── nats.conf                     NATS JetStream config
│   ├── falco-rules.yaml              Container escape detection
│   └── engage-annotations.yaml       MITRE Engage mappings
├── decoys/                         Decoy definitions and data
│   ├── examples/                     Example decoy manifests
│   ├── profiles/                     Device personality profiles (JSON)
│   └── responses/                    Scripted response databases
│
├── platform/                       Kubernetes deployment layer
│   ├── helm/cicdecoy/                Helm chart (CRDs, templates, values)
│   ├── cli/                          Go CLI (cobra)
│   ├── operator/                     Kubernetes operator (kopf)
│   ├── setup-helm-files.sh           Populates Helm chart from config/ and decoys/
│   └── Makefile                      build → k3s-import → helm install → deploy
│
├── adapters/                       Third-party honeypot integration (Go)
│   ├── pkg/                          Common event schema, adapter interface, NATS publisher
│   ├── adapters/                     Cowrie, Dionaea, T-Pot implementations
│   └── deploy/helm/                  Per-adapter Helm charts
│
├── siem-forwarder/                 SIEM export (Go) — Splunk, Elastic, syslog, webhook
│
├── tests/                          Test suites (pytest)
│   ├── ssh-decoy/                    SSH decoy unit tests
│   ├── cti/                          CTI enrichment tests
│   ├── dashboard/                    Dashboard API tests
│   └── schema/                       Event schema validation
│
├── scripts/                        Helper scripts (quickstart, deployment)
├── tools/                          Response capture utilities
├── docs/                           Documentation and specifications
├── docker-compose.yaml             Local development stack (no API keys needed)
└── Makefile                        Dev workflow: up, test, ssh, logs, dashboard
```

### CRD Kinds

| Kind | Purpose |
|------|---------|
| `Decoy` | Single deception asset — currently SSH; HTTP, MySQL, SMB planned |
| `DecoyTemplate` | Reusable parameterized decoy definition |
| `DecoyProfile` | OS/network fingerprint for realistic identity |
| `HoneyToken` | Canary credential or file placed inside decoys (CRD defined; placement and trigger detection planned) |
| `DecoyFleet` | Deploy N decoys from a template across zones |

### NATS Streams

| Stream | Subjects | Retention | Purpose |
|--------|----------|-----------|---------|
| `DECOY_EVENTS` | `cicdecoy.decoy.events.>` | 72h | Raw events from decoys and adapters |
| `ENRICHED_EVENTS` | `cicdecoy.enriched.events.>` | 72h | Post-enrichment pipeline output |
| `ALERTS` | `cicdecoy.alert.>` | 7d | High-severity alerts |
| `HONEYTOKEN_EVENTS` | `cicdecoy.honeytoken.>` | 30d | Token trigger events |
| `FALCO_ALERTS` | `cicdecoy.security.falco.>` | 30d | Container escape detection (immutable) |
| `PLATFORM` | `cicdecoy.platform.>` | 7d | Operator health and audit |

## CLI Reference

```bash
cicdecoy deploy <manifest|dir>       Deploy decoys from YAML
cicdecoy destroy <name|--all>        Remove decoys
cicdecoy rotate <name|--all>         Trigger identity rotation
cicdecoy status [decoys|health]      Platform and fleet overview
cicdecoy fleet list|scale|rotate     Fleet management
cicdecoy sessions list               List sessions (--live, --severity, --since)
cicdecoy sessions watch              Real-time activity stream
cicdecoy sessions replay <id>        Terminal replay with ATT&CK annotations
cicdecoy sessions export <id>        Export as JSON, CSV, or STIX 2.1
cicdecoy intel iocs                  Active indicators of compromise
cicdecoy intel actors                Observed threat actors
cicdecoy intel mitre                 ATT&CK technique frequency
cicdecoy intel honeytokens           Honeytoken trigger history
cicdecoy intel export                Bulk export (STIX, CSV, JSON)
cicdecoy intel report                Generate intelligence report
cicdecoy validate <manifest>         Lint, schema check, fidelity pre-check
cicdecoy logs <decoy> [-f]           Stream interaction logs
cicdecoy profile list|show           Manage decoy profiles
cicdecoy config view|set             CLI configuration
```

## Development

### Local Development (docker-compose)

```bash
docker compose up -d
# Dashboard at http://localhost:8080
# NATS at localhost:4222
# TimescaleDB at localhost:5432
```

Or use the Makefile shortcuts:

```bash
make up          # Tier 2 stack
make up-tier3    # Tier 2 + Tier 3 (local LLM via Ollama)
make ssh         # SSH into the Tier 2 decoy
make dashboard   # Open dashboard in browser
```

### Kubernetes Development (k3s)

```bash
cd platform
./setup-helm-files.sh          # Copy configs into Helm chart
make deploy                    # Build images → import to k3s → helm install
make status                    # Check pods, decoys, NATS streams
make logs-pipeline             # Tail CTI pipeline
```

### Tests

```bash
cd tests
pip install -r requirements.txt
pytest -v
```

## Documentation

| Document | Description |
|----------|-------------|
| [Deception as Code](docs/specifications/deception-as-code-spec.md) | The DaC concept and manifesto |
| [Adapter Contract](docs/specifications/adapter-contract.md) | How to write a third-party adapter |

## Roadmap

See [docs/ROADMAP.md](docs/ROADMAP.md) for the full versioned roadmap. Here's the summary:

| Version | Theme | Target | Highlights |
|---------|-------|--------|------------|
| **v0.2.0** | Operational Readiness | Q2 2026 | Slack/Teams/PagerDuty alerting, threat feed integration (GreyNoise, abuse.ch), honeytoken placement & trigger detection, SIEM export maturity, SSH/HTTP fidelity improvements |
| **v0.3.0** | Protocol Expansion | Q3 2026 | HTTP Tier 3 (dynamic content generation), MySQL/PostgreSQL decoy, Kubernetes API decoy, SMB file share decoy, CTI enrichment expansion |
| **v0.4.0** | Intelligence Maturity | Q4 2026 | STIX 2.1 bundles + TAXII server, attacker fingerprinting & attribution, attack graph + geo map visualization, export/reporting, behavioral anomaly detection |
| **v0.5.0** | Enterprise Operations | Q1–Q2 2027 | Fleet auto-rotation, operator webhooks, Terraform/Ansible modules, cloud VPC integration, decoy management dashboard UI, multi-tenancy, TUI CLI mode |
| **v1.0.0** | Production GA | Q3–Q4 2027 | CRD v1 stability, SOAR connectors, automated response, CTF/training mode, RDP/FTP/DNS/SMTP decoys, performance benchmarks, adapter completions |

Contributions toward any of these are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for how to get involved.

## We'd Like to Hear from You

CI/CDecoy is built for defenders, and the best deception tooling comes from real-world operator feedback. Whether you're running honeypots in production, evaluating deception platforms, or just curious? We want to hear from you!

**Ways to get involved:**

- **Try it out** — `docker compose up` gets you running in under two minutes. Deploy a decoy, poke around, and tell us what surprised you.
- **Open an issue** — Bug reports, feature requests, and deployment questions all welcome on [GitHub Issues](https://github.com/csquare-d/CICDecoy/issues).
- **Start a discussion** — Have a use case, deployment pattern, or integration idea? Open a [GitHub Discussion](https://github.com/csquare-d/CICDecoy/discussions).
- **Contribute** — From documentation fixes to new protocol decoys, all contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for how to get started.
- **Share your experience** — If you've deployed CI/CDecoy in a lab or production environment, we'd love to hear what worked, what didn't, and what you'd want next.

We're especially interested in feedback on:

- Which protocol decoys would be most valuable for your environment?
- How the CTI pipeline output integrates with your existing SIEM/SOAR workflow
- Whether the Deception-as-Code model (YAML manifests, GitOps, Helm) fits your operational workflow
- Ideas for LLM-driven decoy personalities and profiles

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.
