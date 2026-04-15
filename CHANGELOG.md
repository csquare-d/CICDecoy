# Changelog

All notable changes to the CI/CDecoy project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Restructured repository layout away from MVP directory structure into a
  production-ready top-level service layout (ssh-decoy, inference, cti,
  dashboard, siem-forwarder, tests)
- Added development workflow resources and contributor documentation

### Security

- Bumped Python base images from 3.12-slim to 3.14-slim across all services
- Bumped Node base image from 20-slim to 25-slim for the dashboard
- Bumped Go base image from 1.22-alpine to 1.26-alpine for the SIEM forwarder
- Updated GitHub Actions dependencies (setup-go, upload-artifact,
  download-artifact, setup-buildx-action, metadata-action)
- Updated Python test dependencies: pytest 9.0.3, httpx 0.28.1,
  uvicorn 0.44.0, sse-starlette 3.3.4, nats-py 2.14.0, asyncpg 0.31.0,
  pytest-asyncio 1.3.0
- Bumped nats-go from 1.37.0 to 1.51.0 for the SIEM forwarder

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
