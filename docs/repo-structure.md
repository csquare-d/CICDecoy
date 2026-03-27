# CI/CDecoy — Repository Structure

## Overview

Monorepo layout organized around GitOps principles. Decoy definitions are declarative,
pipelines are automated, and the entire deception posture is version-controlled.

---

```
cicdecoy/
│
├── .github/
│   └── workflows/
│       ├── build-decoys.yml          # Build & push decoy container images
│       ├── validate-manifests.yml    # Lint + fidelity-test decoy configs
│       └── deploy-staging.yml        # Deploy to staging namespace for testing
│
├── decoys/                           # ─── DECOY DEFINITIONS (the "source code") ───
│   ├── templates/                    # Base templates per service type
│   │   ├── ssh-server.yaml
│   │   ├── http-webapp.yaml
│   │   ├── smb-fileshare.yaml
│   │   ├── mysql-db.yaml
│   │   ├── rdp-workstation.yaml
│   │   ├── dns-resolver.yaml
│   │   └── ftp-server.yaml
│   │
│   ├── profiles/                     # System "personalities" for LLM-backed decoys
│   │   ├── dev-workstation.json      # Ubuntu 22.04, node/python installed, git repos
│   │   ├── db-server.json            # CentOS, MySQL 8.0, cron jobs, log rotation
│   │   ├── ci-runner.json            # Debian, Docker, Jenkins agent, build artifacts
│   │   ├── legacy-webserver.json     # Old Apache, PHP 5.6, WordPress — irresistible
│   │   └── jump-box.json            # Hardened-looking bastion with SSH keys
│   │
│   ├── honeytokens/                  # Data-layer deception assets
│   │   ├── aws-credentials.yaml     # Fake AWS keys (canary tokens)
│   │   ├── kubeconfig.yaml          # Fake cluster credentials
│   │   ├── database-dump.yaml       # Seeded "leaked" database
│   │   └── internal-docs.yaml       # Fake sensitive documents
│   │
│   └── deployments/                  # Concrete deployment manifests (what actually runs)
│       ├── production/
│       │   ├── dmz-decoys.yaml
│       │   ├── internal-net-decoys.yaml
│       │   └── cloud-decoys.yaml
│       └── staging/
│           └── test-decoys.yaml
│
├── images/                           # ─── CONTAINER IMAGES ───
│   ├── base/                         # Shared base image with instrumentation layer
│   │   ├── Dockerfile
│   │   └── instrumentation/
│   │       ├── logger.py             # Structured interaction logging
│   │       ├── session.py            # Session state management
│   │       └── exporter.py           # Metrics + log export (OTEL)
│   │
│   ├── ssh-decoy/
│   │   ├── Dockerfile
│   │   ├── entrypoint.sh
│   │   └── src/
│   │       ├── server.py             # Paramiko-based SSH server
│   │       ├── auth_handler.py       # Credential capture + configurable auth
│   │       ├── command_router.py     # Fast-path / slow-path command dispatch
│   │       └── filesystem.py         # Virtual filesystem state
│   │
│   ├── http-decoy/
│   │   ├── Dockerfile
│   │   └── src/
│   │       ├── server.py             # HTTP/HTTPS server with configurable routes
│   │       ├── webapp_emulator.py    # Fake app logic (login pages, APIs)
│   │       └── exploit_detector.py   # Pattern match known exploit attempts
│   │
│   ├── smb-decoy/
│   │   ├── Dockerfile
│   │   └── src/
│   │       ├── server.py             # SMB protocol emulation
│   │       ├── shares.py             # Fake file shares with honeytoken files
│   │       └── auth_handler.py       # NTLM/credential capture
│   │
│   ├── mysql-decoy/
│   │   ├── Dockerfile
│   │   └── src/
│   │       ├── server.py             # MySQL wire protocol emulation
│   │       ├── query_handler.py      # SQL parsing + fake result generation
│   │       └── schema.py             # Virtual database schema
│   │
│   └── generic-decoy/                # Extensible base for custom protocols
│       ├── Dockerfile
│       └── src/
│           └── plugin_loader.py      # Load protocol plugins at runtime
│
├── inference/                        # ─── LLM INFERENCE SERVICE ───
│   ├── Dockerfile
│   ├── src/
│   │   ├── server.py                 # FastAPI inference gateway
│   │   ├── prompt_engine.py          # System prompt construction per decoy profile
│   │   ├── session_context.py        # Inject session state into LLM context
│   │   ├── response_filter.py        # Sanitize LLM output (prevent data leaks)
│   │   ├── timing.py                 # Realistic response delay injection
│   │   └── cache.py                  # Response cache for common commands
│   ├── models/
│   │   └── model-config.yaml         # Model selection, quantization, resource limits
│   └── prompts/
│       ├── base-system.txt           # Core "you are a Linux server" system prompt
│       ├── ssh-session.txt           # SSH-specific prompt template
│       ├── sql-session.txt           # SQL interaction prompt template
│       └── web-session.txt           # Web app interaction prompt template
│
├── cti/                              # ─── CTI PIPELINE ───
│   ├── collector/
│   │   ├── Dockerfile
│   │   └── src/
│   │       ├── ingest.py             # Consume logs from decoys (NATS/Kafka)
│   │       ├── normalize.py          # Normalize to common event schema
│   │       └── deduplicate.py        # Deduplicate across decoys/sessions
│   │
│   ├── enrichment/
│   │   ├── Dockerfile
│   │   └── src/
│   │       ├── geoip.py              # GeoIP enrichment
│   │       ├── threatfeed.py         # Correlate with known threat feeds
│   │       ├── mitre_mapper.py       # Map commands/behavior → ATT&CK techniques
│   │       ├── tool_identifier.py    # Identify attacker tooling (C2 frameworks, etc.)
│   │       └── session_analyzer.py   # Behavioral analysis across full sessions
│   │
│   ├── output/
│   │   ├── Dockerfile
│   │   └── src/
│   │       ├── stix_formatter.py     # Generate STIX 2.1 bundles
│   │       ├── taxii_server.py       # TAXII 2.1 server for intel sharing
│   │       ├── siem_exporter.py      # Push to Splunk/Elastic/Sentinel
│   │       ├── ioc_generator.py      # Extract and publish IOCs
│   │       └── report_generator.py   # Human-readable intel reports
│   │
│   └── storage/
│       └── schema.sql                # TimescaleDB schema for interaction data
│
├── platform/                         # ─── CLUSTER INFRASTRUCTURE ───
│   ├── k3s/
│   │   ├── cluster-config.yaml       # k3s server/agent configuration
│   │   └── registries.yaml           # Private registry config
│   │
│   ├── helm/
│   │   └── cicdecoy/                # Helm chart for full platform deployment
│   │       ├── Chart.yaml
│   │       ├── values.yaml
│   │       ├── values-production.yaml
│   │       └── templates/
│   │           ├── decoy-operator.yaml
│   │           ├── inference-service.yaml
│   │           ├── cti-pipeline.yaml
│   │           ├── message-bus.yaml
│   │           ├── monitoring.yaml
│   │           └── networkpolicies.yaml
│   │
│   ├── gitops/                       # ArgoCD / Flux configuration
│   │   ├── applications.yaml
│   │   └── kustomization.yaml
│   │
│   └── networking/
│       ├── ingress.yaml              # Traefik config for decoy exposure
│       ├── network-policies.yaml     # Isolation between decoys and platform
│       └── service-mesh.yaml         # Optional: Linkerd for mTLS between components
│
├── operator/                         # ─── KUBERNETES OPERATOR ───
│   ├── Dockerfile
│   └── src/
│       ├── main.go                   # Operator entrypoint
│       ├── controllers/
│       │   ├── decoy_controller.go   # Reconcile Decoy CRDs → running pods
│       │   └── honeytoken_controller.go
│       ├── api/
│       │   └── v1alpha1/
│       │       ├── decoy_types.go    # CRD type definitions
│       │       └── honeytoken_types.go
│       └── pkg/
│           ├── fidelity.go           # Tier validation and resource allocation
│           └── health.go             # Decoy health checking
│
├── dashboard/                        # ─── WEB UI ───
│   ├── Dockerfile
│   ├── package.json
│   └── src/
│       ├── App.tsx
│       ├── pages/
│       │   ├── Overview.tsx          # Deployment map + health status
│       │   ├── Sessions.tsx          # Live + historical session viewer
│       │   ├── Intelligence.tsx      # CTI feed dashboard
│       │   ├── DecoyBuilder.tsx      # Visual decoy configuration
│       │   └── Settings.tsx
│       └── components/
│           ├── SessionReplay.tsx     # Terminal replay of attacker sessions
│           ├── AttackTimeline.tsx    # ATT&CK-mapped interaction timeline
│           ├── ThreatMap.tsx         # Geographic visualization
│           └── DecoyTopology.tsx     # Network topology of deployed decoys
│
├── cli/                              # ─── CLI TOOL ───
│   ├── main.go
│   └── cmd/
│       ├── deploy.go                 # cicdecoy deploy <manifest>
│       ├── status.go                 # cicdecoy status
│       ├── sessions.go              # cicdecoy sessions list/watch/replay
│       ├── intel.go                  # cicdecoy intel export/query
│       └── validate.go              # cicdecoy validate <manifest>
│
├── tests/
│   ├── fidelity/                     # Decoy convincingness tests
│   │   ├── nmap_fingerprint_test.py  # Does it fool OS detection?
│   │   ├── banner_grab_test.py       # Are banners realistic?
│   │   ├── interaction_test.py       # Multi-command session tests
│   │   └── timing_test.py           # Response latency realism
│   ├── integration/
│   │   ├── pipeline_test.py          # End-to-end: interaction → CTI output
│   │   └── deploy_test.py           # Manifest → running decoy validation
│   └── security/
│       ├── breakout_test.py          # Ensure decoys can't be used as pivot
│       └── isolation_test.py         # Network policy enforcement tests
│
├── docs/
│   ├── architecture.md
│   ├── getting-started.md
│   ├── decoy-authoring.md           # How to write decoy manifests
│   ├── profile-authoring.md         # How to create system personalities
│   ├── cti-integration.md           # Connecting to SIEMs and TIPs
│   └── threat-model.md             # Security considerations for the platform itself
│
├── Makefile
├── docker-compose.dev.yaml          # Local dev environment
├── LICENSE
└── README.md
```

---

## Key Design Decisions

### Why a Kubernetes Operator?
Custom Resource Definitions (CRDs) let operators manage decoys like native k8s objects.
`kubectl get decoys`, `kubectl describe decoy ssh-dmz-01` — familiar workflows for
any platform team. The operator handles scheduling, health checks, and auto-recovery.

### Why a Shared Inference Service?
Running one LLM instance per decoy is wasteful. A centralized inference gateway with
request routing lets Tier 3 decoys share GPU/CPU resources efficiently. The gateway
also enforces response filtering so the LLM never leaks real infrastructure details.

### Why GitOps?
Your deception posture becomes auditable, reproducible, and rollback-capable. "What
decoys were deployed on March 3rd?" becomes a `git log` query. PR reviews on decoy
changes mean peer validation of deception strategy.

### Why Fidelity Tests?
Decoys that get fingerprinted are worse than no decoys — they tell attackers you're
running deception. Automated fidelity testing (nmap scans, banner checks, interaction
scripts) runs in CI to catch regressions before deployment.
