# Changelog

All notable changes to the CI/CDecoy project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Dashboard API-key authentication** -- all `/api/*` routes and the SSE
  live event stream now require a shared API key (`X-API-Key` header or
  `?api_key=` query param for SSE). `/healthz`, `/metrics`, and static
  assets remain public. In dev mode without `DASHBOARD_API_KEY` set, an
  ephemeral key is generated and logged; in production the backend refuses
  to start without one.
- React login modal prompting for the API key on first load, with
  localStorage persistence, automatic re-prompt on 401, and a "Sign out"
  button in the header
- `/healthz` endpoint for Kubernetes liveness/readiness probes (public)
- Helm `dashboard.auth` values block with `existingSecret`, `apiKey`, and
  auto-generated Secret support
- `DASHBOARD_API_KEY` env var in docker-compose.yaml
- 17 new auth tests in `tests/dashboard/test_auth.py`
- Kubernetes end-to-end smoke test workflow (`.github/workflows/e2e-k3d.yaml`)
  spinning up a k3d cluster on every PR, installing the Helm chart, applying a
  test Decoy CR, driving an SSH probe, and asserting the event reaches the
  dashboard `/api/events` endpoint
- `make e2e-k3d` target for running the same smoke test locally via
  `tests/e2e/local_run.sh`
- E2E helper scripts under `tests/e2e/` (`run_smoke.sh`, `dump_logs.sh`,
  `local_run.sh`) and a minimal Tier 2 SSH Decoy fixture
  (`tests/e2e/fixtures/test-decoy.yaml`)

### Changed

- Restructured repository layout away from MVP directory structure into a
  production-ready top-level service layout (ssh-decoy, inference, cti,
  dashboard, siem-forwarder, tests)
- Added development workflow resources and contributor documentation
- **Helm chart defaults now install out-of-the-box.** Component images default
  to `ghcr.io/csquare-d/cicdecoy-*:{{ .Chart.AppVersion }}` (the location the
  release workflow publishes to) instead of `localhost:5000/*:dev`. Added a
  `global.imageRegistry` knob so operators can redirect every cicdecoy image
  to a private mirror in one place, plus `global.imagePullSecrets` for
  authenticated registries.
- Helm chart `files/` directory is now populated and committed, so
  `helm template` and `helm install` work on a fresh clone without running
  `platform/setup-helm-files.sh` first. The script is retained as an optional
  re-sync tool for when the canonical sources under `config/` or `decoys/`
  change.

### Security

- **Removed hardcoded default passwords from the Helm chart.** The Postgres
  password is now auto-generated via `randAlphaNum 24` on first install and
  preserved across upgrades by looking up the existing
  `{release}-db-credentials` Secret. Added
  `timescaledb.auth.existingSecret`, `nats.existingSecret`, and
  `siemForwarder.existingSecret` value patterns for operators supplying
  pre-created Secrets.
- Tightened operator RBAC: split `secrets` into its own rule in
  `templates/rbac.yaml` so the verb set can be narrowed independently of
  pods/services/configmaps, and dropped any residual wildcard verbs in favor
  of an explicit list.
- Pinned Python base images to `python:3.12-slim` with SHA256 digest across all services
- Pinned Node base image to `node:20-slim` with SHA256 digest for the dashboard
- Pinned Go base image to `golang:1.22-alpine` for the SIEM forwarder and CLI
- Updated GitHub Actions dependencies (setup-go, upload-artifact,
  download-artifact, setup-buildx-action, metadata-action)
- Updated Python test dependencies: pytest 9.0.3, httpx 0.28.1,
  uvicorn 0.44.0, sse-starlette 3.3.4, nats-py 2.14.0, asyncpg 0.31.0,
  pytest-asyncio 1.3.0
- Bumped nats-go from 1.37.0 to 1.51.0 for the SIEM forwarder

### Migration notes

- `values.yaml` no longer sets `timescaledb.auth.password`. Users who relied
  on the former `cicdecoy`/`cicdecoy` default must either pre-create a Secret
  and set `timescaledb.auth.existingSecret`, or set
  `timescaledb.auth.password` explicitly. Fresh installs get a chart-generated
  24-character random password that is preserved across upgrades.
- Per-component `image.repository` / `image.tag` values default to empty
  strings and fall back to `global.imageRegistry` + the chart `appVersion`.
  Explicit `--set <component>.image.tag=dev` overrides continue to work.

## [0.1.0] - 2026-04-13

Initial pre-release of the CI/CDecoy Deception-as-Code platform.

### Added

- **SSH Decoy Service** with configurable banners, three fidelity tiers
  (beacon, scripted, and LLM-adaptive), and full session capture
- **LLM Inference Gateway** providing Tier 3 adaptive decoys with contextually
  coherent responses via a shared inference service
- **CTI Enrichment Pipeline** as a standalone service performing MITRE ATT&CK
  mapping, tool identification, behavioral analysis, GeoIP resolution, and
  STIX 2.1 bundle generation
- **Session Analyzer** for kill chain reconstruction and per-session
  intelligence value tracking
- **React Dashboard** with real-time event monitoring, MITRE Engage bar graphs,
  session drill-down views, and server-sent event streaming
- **SIEM Forwarder** (Go) shipping enriched events to Splunk, Elastic, and
  syslog endpoints
- **NATS Messaging Backbone** connecting all services via publish/subscribe
  event streaming
- **Kubernetes Platform Design** with Helm charts, Custom Resource Definitions,
  and GitOps-ready deployment manifests
- **CI/CD Pipeline** with GitHub Actions for container image builds, fidelity
  validation tests, and integration test harness
- **Platform Architecture Documentation** including Mermaid diagrams and
  scaffolding reference docs
- **MITRE Engage Integration** mapping decoys to ENGAGE activities, approaches,
  and goals

### Fixed

- Eliminated duplicate events and localhost noise in the event pipeline
- Resolved dashboard display issues with Engage bar graphs and color theming
- Corrected NATS configuration settings for inter-service communication
