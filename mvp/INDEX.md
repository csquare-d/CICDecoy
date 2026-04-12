# CI/CDecoy — Project Archive

Complete design, documentation, and runnable MVP for the CI/CDecoy
Deception as Code platform. **No API keys required.**

## Quick Start

    cd mvp/
    make up          # Start Tier 2 HiFi (no LLM needed)
    make ssh         # SSH in (admin / admin123)
    make events      # Watch NATS events live
    make db-events   # Query stored events
    make db-engage   # View Engage effectiveness metrics
    make db-falco    # View Falco runtime security alerts

    # Optional: local LLM for Tier 3
    make up-tier3    # Starts Ollama (~2GB download first time)
    make ssh3        # SSH into LLM-backed decoy

## Contents

    docs/                    Documentation, specs, production deployment guide
    architecture/            System diagrams, example deployments
    design/                  Component prototypes (SSH, inference, CTI, operator, CLI, dashboard)
    cicd/                    GitHub Actions workflows (build, fidelity, deploy, release)
    helm/                    Helm chart with Falco, NATS, TimescaleDB dependencies
    tests/                   Test framework (unit, fidelity, integration, security, Falco, Engage)
    mvp/
      ssh-decoy/             SSH honeypot (asyncssh) + high-fidelity scripted engine
      inference/             LLM gateway (local Ollama, no API key)
      cti/                   Event collector + Falco correlator + MITRE Engage mapper
      config/                Decoy configs, DB schema, Falco rules, Engage annotations
      profiles/              System personality definitions
      responses/             Captured response databases
      tools/                 Response capture tool
