# CI/CDecoy

[![CI](https://github.com/csquare-d/CICDecoy/actions/workflows/ci.yaml/badge.svg)](https://github.com/csquare-d/CICDecoy/actions/workflows/ci.yaml)
[![CodeQL](https://github.com/csquare-d/CICDecoy/actions/workflows/codeql.yaml/badge.svg)](https://github.com/csquare-d/CICDecoy/actions/workflows/codeql.yaml)
[![codecov](https://codecov.io/gh/csquare-d/CICDecoy/branch/main/graph/badge.svg)](https://codecov.io/gh/csquare-d/CICDecoy)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

**The open-source framework for Deception as Code.**

[https://cicdecoy.systems](https://cicdecoy.systems/) · [Documentation](docs/getting-started.md) · [Roadmap](docs/ROADMAP.md)

CI/CDecoy lets security teams define, version, and continuously deploy cyber deception assets: honeypots, honeytokens, and decoy services. All using familiar GitOps workflows on Kubernetes. Every interaction is captured, enriched with MITRE ATT&CK context, and output as structured threat intelligence.

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
cicdecoy deploy decoys/ --wait
cicdecoy sessions watch --annotated
```

## Why CI/CDecoy

**Decoy-as-Code.** Decoys are YAML manifests in Git, deployed through CI/CD. Auditable, reproducible, rollback-capable.

**Three Fidelity Tiers.** Tier 1 beacons log connections. Tier 2 scripted decoys handle realistic interactions. Tier 3 adaptive decoys build on Tier 2 using a local LLM for coherent, open-ended shell sessions to fill in gaps that a Tier 2 scripted decoy cannot fill alone to fool human operators.

**Built-in CTI Pipeline.** Every interaction is enriched with MITRE ATT&CK mappings (70+ techniques), tool signatures (48 tools), behavioral scoring, GeoIP, and kill chain detection, not just logged, but also classified and scored.

**Kubernetes-Native.** Decoys are CRDs. `kubectl get decoys` works. The operator handles scheduling, health, and lifecycle.

**SIEM Integration.** Ship enriched events to Splunk, Elasticsearch, syslog, or webhooks in JSON, CEF, LEEF, or ECS format with retry, circuit breaker, and dead-letter queue.

**MITRE Engage.** Map every decoy to Engage activities, approaches, and goals. Track intelligence value per session.

## How It Compares

| Capability | CI/CDecoy | Single-Protocol Honeypots | T-Pot | Commercial |
|---|---|---|---|---|
| **LLM-Adaptive Responses** | Local LLM via inference gateway | No | No | No |
| **MITRE ATT&CK Mapping** | Automatic per-session | No | Manual | Automatic |
| **Deception as Code** | GitOps-ready YAML manifests | No | No | No |
| **Kubernetes Native** | CRDs + Operator | No | Docker only | Varies |
| **Protocol Coverage** | SSH + HTTP (more planned) | One protocol | ~20 via bundles | Broad |
| **Kill Chain Detection** | Real-time | No | No | Yes |
| **Integrated CTI Pipeline** | NATS + TimescaleDB | Log files | ELK stack | Proprietary |
| **Cost** | Free (Apache 2.0) | Free | Free | $$$$ |

> Single-protocol honeypots like Cowrie and Dionaea are battle-tested within their specialty. T-Pot provides unmatched protocol breadth. Commercial platforms deliver enterprise support and SLAs. CI/CDecoy's differentiators are its Deception-as-Code model, LLM fidelity, Kubernetes-native architecture, and built-in CTI enrichment.

## Architecture

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

| Component | Purpose | Language |
|-----------|---------|----------|
| **Operator** | Reconciles Decoy CRDs into running pods | Python (kopf) |
| **SSH Decoy** | Tier 1-3 SSH honeypot with LLM integration | Python (asyncssh) |
| **HTTP Decoy** | Tier 1-2 HTTP honeypot with 7 login portals | Python (FastAPI) |
| **Inference Gateway** | Shared LLM service for Tier 3 decoys | Python (FastAPI) |
| **CTI Pipeline** | Event enrichment, ATT&CK mapping, behavioral analysis | Python |
| **Dashboard** | Live feed, session replay, MITRE heatmap | React + FastAPI |
| **CLI** | Deploy, validate, replay, query intelligence | Go (cobra) |
| **SIEM Forwarder** | Export to Splunk, Elastic, syslog, webhook | Go |
| **NATS JetStream** | Event routing between all components | — |
| **TimescaleDB** | Time-series event storage | — |

## Quick Start

```bash
# Local dev — no API keys needed
docker compose up -d
# Dashboard at http://localhost:8080 | SSH decoy on port 2222

# Or on Kubernetes
VERSION=$(curl -s https://api.github.com/repos/csquare-d/CICDecoy/releases/latest | grep tag_name | cut -d '"' -f 4)
curl -LO "https://github.com/csquare-d/CICDecoy/releases/download/${VERSION}/cicdecoy-${VERSION}.tgz"
helm install cicdecoy ./cicdecoy-${VERSION}.tgz \
  --namespace cicdecoy-system --create-namespace --wait
```

Deploy a decoy, watch it work:

```bash
cicdecoy deploy decoys/examples/ssh-honeypot.yaml --wait
cicdecoy sessions watch --annotated
cicdecoy intel mitre --since 7d
```

See [Getting Started](docs/getting-started.md) for the full walkthrough.

## CLI Highlights

```bash
cicdecoy deploy <manifest>           # Deploy decoys from YAML
cicdecoy sessions watch              # Real-time activity stream
cicdecoy sessions replay <id>        # Terminal replay with ATT&CK annotations
cicdecoy intel mitre                 # Technique frequency heatmap
cicdecoy intel export --format stix  # Bulk STIX/CSV/JSON export
cicdecoy fleet scale <name> --n 10   # Scale a decoy fleet
```

Full command reference in [docs/runbooks.md](docs/runbooks.md).

## Roadmap

| Version | Theme | Highlights |
|---------|-------|------------|
| **v0.2.0** | Operational Readiness | Threat feeds (GreyNoise, abuse.ch), honeytoken triggers, SIEM maturity |
| **v0.3.0** | Protocol Expansion | MySQL/PostgreSQL decoy, K8s API decoy, HTTP Tier 3, Hydra adaptive orchestration |
| **v0.4.0** | Intelligence Maturity | STIX/TAXII, attacker fingerprinting, attack graph visualization |
| **v0.5.0** | Enterprise Ops | Fleet auto-rotation, Terraform modules, multi-tenancy, TUI CLI |
| **v1.0.0** | Production GA | CRD v1, SOAR connectors, CTF mode, RDP/FTP/DNS decoys |

Full roadmap: [docs/ROADMAP.md](docs/ROADMAP.md)

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture Overview](docs/architecture.md) | Component map, data flow, security model |
| [CRD Reference](docs/crd-reference.md) | Schema for all 5 custom resources (Decoy, DecoyTemplate, DecoyProfile, HoneyToken, DecoyFleet) |
| [API Reference](docs/api-reference.md) | Dashboard REST API — 15 endpoints, SSE streaming, authentication |
| [Database Schema](docs/database-schema.md) | TimescaleDB tables, indexes, retention policies, query patterns |
| [Operational Runbooks](docs/runbooks.md) | Deploy, monitor, troubleshoot, export intelligence, SIEM setup |
| [Deception as Code Spec](docs/specifications/deception-as-code-spec.md) | The DaC philosophy and five principles |
| [Message Bus Spec](docs/specifications/message-bus-spec.md) | NATS topic hierarchy, stream config, delivery guarantees |
| [Decoy Manifest Schema](docs/specifications/decoy-manifest-schema.md) | Authoring guide for decoy manifests and profiles |
| [Adapter Contract](docs/specifications/adapter-contract.md) | How to integrate third-party honeypots |
| [SIEM Forwarding Spec](docs/specifications/siem-forwarding-spec.md) | Format specs for CEF, LEEF, ECS output |
| [Getting Started](docs/getting-started.md) | First deployment walkthrough |
| [Production Deployment](docs/production-deployment.md) | Hardening, scaling, backup, monitoring |
| [Falco Setup](docs/falco-setup.md) | Container escape detection integration |
| [Profile Authoring](docs/guides/profile-authoring.md) | Creating OS personality profiles for Tier 3 |
| [ROADMAP](docs/ROADMAP.md) | Versioned feature roadmap with completion status |
| [CONTRIBUTING](CONTRIBUTING.md) | Dev setup, testing, contribution guidelines |

## Get Involved

CI/CDecoy is built for defenders. This is an early release — if you try it, we want to know what worked and what didn't.

- **Website** — [cicdecoy.systems](https://cicdecoy.systems/) for project overview and updates.
- **Try it** — `docker compose up` gets you running in under two minutes.
- **Report issues** — [GitHub Issues](https://github.com/csquare-d/CICDecoy/issues) for bugs, feature requests, questions.
- **Discuss** — [GitHub Discussions](https://github.com/csquare-d/CICDecoy/discussions) for use cases, deployment patterns, integration ideas.
- **Contribute** — From doc fixes to new protocol decoys. See [CONTRIBUTING.md](CONTRIBUTING.md).

We're especially interested in: which protocol decoys matter most for your environment, how the CTI output fits your SIEM/SOAR workflow, and whether the Deception-as-Code model fits how you operate.

## License

Apache License 2.0. See [LICENSE](LICENSE).
