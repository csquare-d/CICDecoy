# Contributing to CI/CDecoy

Thanks for your interest in CI/CDecoy. This guide covers everything you need to get a local development environment running and submit your first contribution.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Repository Layout](#repository-layout)
- [Architecture Overview](#architecture-overview)
- [Development Workflow](#development-workflow)
- [Code Quality](#code-quality)
- [Testing](#testing)
- [Common Contribution Areas](#common-contribution-areas)
- [Submitting a Pull Request](#submitting-a-pull-request)
- [Design Principles](#design-principles)
- [Security Considerations](#security-considerations)
- [Debugging](#debugging)
- [Reference Tables](#reference-tables)
- [Reporting Issues](#reporting-issues)

---

## Prerequisites

- **Docker** and **Docker Compose** (v2+)
- **Python 3.12+**
- **Go 1.22+** (only if working on CLI, adapters, or SIEM forwarder)
- **Node 20+** (only if working on the dashboard frontend)
- **Git**

No API keys, cloud accounts, or Kubernetes cluster required for local development.

## Quick Start

```bash
# Clone and enter the repo
git clone https://github.com/cicdecoy/cicdecoy.git
cd cicdecoy

# Install Python dev dependencies
make install

# Install pre-commit hooks
pre-commit install

# Start the full local stack
make up

# Verify it works
make ssh              # SSH into the decoy (password: admin123)
make dashboard        # Open the web UI
make db-events        # Check events reached the database
```

## Repository Layout

```bash
ssh-decoy/          Python SSH honeypot (Tier 1-3)
cti/                CTI enrichment pipeline (MITRE ATT&CK, tool detection)
dashboard/          React frontend + FastAPI backend
inference/          LLM inference gateway (Tier 3, Ollama)
platform/           Kubernetes layer (operator, Helm chart, Go CLI)
adapters/           Third-party honeypot adapters (Go)
siem-forwarder/     SIEM export service (Go)
config/             Shared infrastructure config (SQL schema, NATS, Falco)
decoys/             Decoy manifests, profiles, and response databases
tests/              Test suite organized by component
tools/              Development utilities
docs/               Specifications and guides
```

### Service source code organization

Each Python service follows the same pattern:

```bash
ssh-decoy/
├── server.py           # Entry point and main loop
├── *.py                # Domain modules (no cross-service imports)
├── requirements.txt    # Pinned dependencies
└── Dockerfile          # Standalone container build
```

Services never import from each other. They communicate exclusively through NATS messages and HTTP APIs. This means you can work on a single service without understanding the others.

---

## Architecture Overview

### Data Flow

```bash
Attacker
  │
  ▼
SSH Decoy ──publish──▶ NATS (DECOY_EVENTS stream)
                           │
                           ▼
                      CTI Pipeline
                       ├─ MITRE ATT&CK classification
                       ├─ Tool signature detection
                       ├─ Behavioral scoring
                       ├─ Falco correlation
                       └─ MITRE Engage mapping
                           │
                    ┌──────┴──────┐
                    ▼              ▼
              TimescaleDB    NATS (enriched)
                    │              │
                    ▼              ▼
              Dashboard      SIEM Forwarder
               (REST + SSE)   (Splunk/Elastic/syslog)
```

### Three Fidelity Tiers

| Tier | Name | How It Responds | When To Use |
|------|------|-----------------|-------------|
| **1** | Beacon | Logs connections, returns banners | Network-level deception, port scanning detection |
| **2** | Scripted | Pre-recorded responses from a database, realistic entropy | Default. Handles most attacker interactions convincingly |
| **3** | Adaptive | LLM generates responses using device profiles and session context | Deep engagement. Responds coherently to arbitrary commands |

When contributing to the SSH decoy, understand which tier your change affects. Tier 2 changes go in `command_router.py` and `hifi_engine.py`. Tier 3 changes go in `inference/`.

### Inter-Service Communication

| From | To | Protocol | Channel |
|------|----|----------|---------|
| SSH Decoy | NATS | NATS pub | `cicdecoy.decoy.events.{name}.{type}` |
| SSH Decoy (Tier 3) | Inference | HTTP POST | `/v1/command` |
| CTI Pipeline | NATS | NATS sub | `cicdecoy.decoy.events.>` (pull consumer) |
| CTI Pipeline | TimescaleDB | SQL | `INSERT INTO decoy_events` |
| CTI Pipeline | NATS | NATS pub | `cicdecoy.enriched.events.{type}` |
| CTI Pipeline | NATS | NATS pub | `cicdecoy.alert.session.*` |
| Dashboard | NATS | NATS sub | `cicdecoy.enriched.events.>` |
| Dashboard | TimescaleDB | SQL | `SELECT` queries |
| SIEM Forwarder | NATS | NATS sub | Multiple streams (pull consumer) |
| Adapters | NATS | NATS pub | `cicdecoy.decoy.events.{name}.{type}` |

### Event Lifecycle

Every attacker interaction follows this path:

1. **SSH Decoy** emits a raw event (e.g., `command.exec` with the command text)
2. **NATS JetStream** durably stores it in the `DECOY_EVENTS` stream
3. **CTI Pipeline** pulls the event, runs enrichment:
   - Classifies MITRE ATT&CK techniques from command patterns
   - Detects tool signatures (metasploit, hashcat, etc.)
   - Scores behavioral severity
   - Updates session-level state (kill chain detection, classification)
4. **TimescaleDB** stores the enriched event
5. **CTI Pipeline** republishes to `cicdecoy.enriched.events.{type}`
6. **Dashboard** receives via SSE and updates the live feed
7. **SIEM Forwarder** (if enabled) exports to Splunk/Elastic/syslog

### Common Event Schema

Every event — whether from the SSH decoy, an adapter, or the CTI pipeline — conforms to this structure:

```json
{
  "event_id": "evt-a1b2c3d4e5f6",
  "timestamp": "2025-01-15T14:30:00.000Z",
  "decoy_name": "ssh-decoy-01",
  "decoy_tier": 2,
  "session_id": "sess-f6e5d4c3b2a1",
  "event_type": "command.exec",
  "source_ip": "198.51.100.42",
  "source_port": 44120,
  "severity": "medium",
  "mitre_techniques": [
    {
      "technique_id": "T1082",
      "technique_name": "System Information Discovery",
      "tactic": "discovery"
    }
  ],
  "tool_signatures": [],
  "tags": [],
  "raw_data": {
    "command": "uname -a",
    "output_lines": 1
  }
}
```

If you add new event types or fields, update the schema in `config/schema.sql` and add validation tests in `tests/schema/test_event_schema.py`.

---

## Development Workflow

### Running the Stack

```bash
make up              # Tier 2 stack (scripted responses, no LLM)
make up-tier3        # Tier 2 + Tier 3 (local LLM via Ollama, ~2GB first run)
make down            # Stop everything
make clean           # Stop + remove data volumes
make reset           # Stop + remove volumes + images (full reset)
```

### Connecting to Services

| Service | URL / Command |
|---------|---------------|
| SSH Decoy (Tier 2) | `ssh admin@localhost -p 2222` (password: `admin123`) |
| SSH Decoy (Tier 3) | `ssh admin@localhost -p 2223` (password: `admin123`) |
| Dashboard | http://localhost:8080 |
| NATS Monitor | http://localhost:8222 |
| TimescaleDB | `make db` (psql shell) |
| Inference API | http://localhost:8000/v1/health (Tier 3 only) |
| Ollama | http://localhost:11434 (Tier 3 only) |

### Observability

```bash
make logs            # All container logs
make logs-decoy      # SSH decoy logs only
make logs-collector  # CTI pipeline logs only
make logs-tier3      # Tier 3 decoy + inference + Ollama
make events          # Live NATS event stream (all subjects)
```

### Database Inspection

```bash
make db              # Interactive psql shell
make db-events       # Last 20 events
make db-sessions     # Session summaries (grouped by session_id)
make db-alerts       # High-severity alerts
make db-falco        # Falco runtime security alerts
make db-engage       # MITRE Engage effectiveness metrics
make db-escapes      # Sessions where attacker detected the honeypot
```

### Dashboard Frontend Development

If you're working on the React frontend:

```bash
make dashboard-dev   # Start Vite dev server with hot-reload
```

This runs the Vite dev server on http://localhost:5173 with hot module replacement. The backend services must be running (`make up`) for API calls to work.

---

## Code Quality

### Linting and Formatting

```bash
make lint            # Run ruff linter
make fmt             # Auto-format Python code
make check           # Lint + test (same checks as CI)
```

### Code Style

**Python:** Enforced by [ruff](https://docs.astral.sh/ruff/). Run `make fmt` before committing.

- Line length: 120 characters
- Target: Python 3.12
- Imports sorted automatically (isort rules)
- Security rules enabled (flake8-bandit) with honeypot-specific exceptions

**Go:** Standard `gofmt`. Run `go fmt ./...` in the relevant module directory.

**JavaScript/React:** 2-space indentation. No linter currently configured for frontend.

**Commits:** Write clear, concise commit messages in present tense ("Add SSH command handler", not "Added SSH command handler"). Keep commits atomic — one logical change per commit.

### Pre-commit Hooks

Install the pre-commit hooks to catch issues before they reach CI:

```bash
pip install pre-commit
pre-commit install
```

This runs automatically on every commit:
- **ruff lint** with auto-fix for trivial issues
- **ruff format** to enforce consistent style
- **trailing whitespace** removal
- **YAML/JSON** syntax validation
- **large file** detection (>500KB)
- **no direct commits to main** (use feature branches)

To run hooks manually against all files:

```bash
pre-commit run --all-files
```

### Branch Naming

```
feature/short-description
fix/issue-or-bug-description
docs/what-you-documented
refactor/what-you-refactored
```

---

## Testing

### Running Tests

```bash
make test            # Run all unit tests
make check           # Lint + test (what CI runs)
```

To run a specific test file or class:

```bash
cd tests
python3 -m pytest ssh-decoy/test_command_router.py -v
python3 -m pytest ssh-decoy/test_auth_handler.py::TestRealisticMode -v
python3 -m pytest cti/test_cti_enrichment.py -k "test_mitre" -v
```

### Test Organization

```bash
tests/
├── conftest.py          # Shared fixtures: event factories, mock DB/NATS
├── pytest.ini           # Config: asyncio_mode=auto, verbose output
├── requirements.txt     # Test dependencies
├── ssh-decoy/           # SSH decoy unit tests
│   ├── test_auth_handler.py      # All 4 auth modes, lockout, pubkey
│   ├── test_command_router.py    # Builtins, commands, pipes, redirects, sudo
│   ├── test_filesystem.py        # VirtualFilesystem CRUD, listing, permissions
│   ├── test_cow_filesystem.py    # Copy-on-Write overlay, tombstones, delta
│   ├── test_hifi_engine.py       # Response DB, templates, fuzzy matching
│   └── test_session_state.py     # Session state mutations
├── cti/                 # CTI pipeline tests
│   ├── test_cti_enrichment.py    # MITRE classification, severity, tool detection
│   └── test_session_analyzer.py  # Behavioral scoring, kill chain, alerting
├── dashboard/           # Dashboard API tests
│   └── test_dashboard_api.py     # REST endpoints, SSE streaming
└── schema/              # Event schema tests
    └── test_event_schema.py      # Validation, serialization
```

### Where to Put Tests

| You changed... | Tests go in... |
|----------------|----------------|
| `ssh-decoy/*.py` | `tests/ssh-decoy/` |
| `cti/*.py` | `tests/cti/` |
| `dashboard/main.py` | `tests/dashboard/` |
| Event schema changes | `tests/schema/` |

### Writing Tests

Tests import source code via `sys.path` manipulation in `tests/conftest.py`. No package installation needed beyond `make install`.

**Sync test example:**

```python
from auth_handler import AuthHandler

class TestMyFeature:
    def test_basic_case(self):
        handler = AuthHandler(config)
        result = handler.check_password("admin", "admin123", "10.0.0.1")
        assert result.accepted is True
```

**Async test example:**

```python
import pytest

@pytest.mark.asyncio
async def test_command_response(router, state, fs):
    result = await router.route("whoami", state, fs, tier=2)
    assert "admin" in result
```

**Using test factories** (from `conftest.py`):

```python
from conftest import make_nats_event, make_session_row

def test_event_processing():
    event = make_nats_event(
        event_type="command",
        command="cat /etc/shadow",
        severity="high",
        technique_id="T1552.001",
    )
    assert event["severity"] == "high"
```

### Test Conventions

- Group related tests in classes: `class TestAuthLockout:`
- One assertion concept per test (but multiple `assert` lines are fine)
- Use descriptive names: `test_lockout_expires_after_duration`, not `test_lockout_3`
- Mock external dependencies (NATS, DB) — never require running services for unit tests
- For the SSH decoy, use the `_FakeConfig` pattern from existing tests

---

## Common Contribution Areas

### Adding a new command to the SSH decoy

The command router handles ~85 commands across builtins, filesystem, network, and system categories.

1. Edit `ssh-decoy/command_router.py`
2. Add your handler method (e.g., `_cmd_newcommand`)
3. Register it in `_handle_common()` dispatch table
4. Add tests in `tests/ssh-decoy/test_command_router.py`

```python
# In _handle_common(), add to the dispatch dict:
"newcommand": lambda: self._cmd_newcommand(parts, state, fs),

# Then implement:
def _cmd_newcommand(self, parts, state, fs):
    """Simulate the newcommand output."""
    return "realistic output here"
```

Commands should return realistic output that matches what a real Linux system would produce. When in doubt, run the command on an actual Ubuntu system and use that output as a reference.

### Adding a MITRE ATT&CK technique mapping

The enrichment engine classifies commands against ATT&CK techniques using regex patterns.

1. Edit `cti/enrichment.py` — add pattern to `MITRE_COMMAND_MAP`
2. Add tests in `tests/cti/test_cti_enrichment.py`

```python
# In MITRE_COMMAND_MAP, add:
(r"your_regex_pattern", "TXXXX", "Technique Name", "tactic"),
```

Patterns are matched against the full command string. Use `\b` word boundaries to avoid false positives. Reference [MITRE ATT&CK](https://attack.mitre.org/) for correct technique IDs and tactic names.

### Adding a new decoy profile

Profiles define the "personality" of a decoy — what OS it pretends to be, what software is installed, what processes are running.

1. Create a JSON file in `decoys/profiles/`
2. Follow the structure of `decoys/profiles/dev-workstation.json`
3. Key fields: `system` (hostname, OS, kernel), `users`, `software.services`, `filesystem_extras`, `narrative`
4. Test: modify `decoys/examples/ssh-honeypot.yaml` to reference your profile, then `make up`

### Adding a HiFi engine template

Templates in the HiFi engine generate realistic output using the virtual filesystem and session state, without needing a response database.

1. Edit `ssh-decoy/hifi_engine.py`
2. Register your template in `_register_templates()`
3. Implement `_tpl_yourcommand(self, cmd, parts, state, fs) -> Optional[str]`
4. Add tests in `tests/ssh-decoy/test_hifi_engine.py`

Templates should return `None` if they can't handle the specific invocation — the engine will fall through to other resolution strategies.

### Working on the CTI pipeline

The pipeline is an async Python process that consumes from NATS, enriches events, and writes to TimescaleDB.

Key files:
- `cti/pipeline.py` — main consumer loop, session management, alert triggers
- `cti/enrichment.py` — MITRE ATT&CK classification, tool detection, severity scoring
- `cti/session_analyzer.py` — multi-command behavioral profiling, intent classification
- `cti/falco_correlator.py` — Falco runtime alert correlation
- `cti/engage_mapper.py` — MITRE Engage activity and outcome tracking

### Working on the dashboard

The dashboard is a React SPA with a FastAPI backend.

- **Backend** (`dashboard/main.py`): 14 REST endpoints + SSE streaming
- **Frontend** (`dashboard/src/`): React 18 + Vite + React Router

Backend changes: edit `main.py`, add tests in `tests/dashboard/`
Frontend changes: edit files in `dashboard/src/`, use `make dashboard-dev` for hot-reload

### Working on the Go CLI

```bash
cd platform/cli
go vet ./...
go build -o cicdecoy .
./cicdecoy --help
```

CLI commands live in `platform/cli/cmd/`. Each file is a cobra command. Shared clients (k8s, NATS, DB) are in `platform/cli/pkg/`.

### Working on adapters or SIEM forwarder

```bash
cd adapters    # or cd siem-forwarder
go vet ./...
go build ./...
```

Adapters translate third-party honeypot events into the common CI/CDecoy event schema and publish to NATS. See [Adapter Contract](docs/specifications/adapter-contract.md) for the interface specification.

### Working on the Kubernetes operator

```bash
cd platform/operator
# The operator uses kopf (Python) to watch Decoy CRDs
# Edit reconciler.py
# Test by deploying to a k3s cluster (see platform/Makefile)
```

---

## Submitting a Pull Request

### Before You Submit

1. Run `make check` (lint + test) and ensure it passes
2. Ensure your changes have tests
3. Keep commits atomic — one logical change per commit
4. Write clear commit messages in present tense

### PR Process

1. Fork the repo and create a feature branch from `main`
2. Make your changes
3. Push and open a PR against `main`
4. Fill in the PR description with:
   - **Summary**: 1-3 bullet points of what changed and why
   - **Test plan**: How you verified the changes work

### PR Checklist

- [ ] `make check` passes (lint + test)
- [ ] New code has tests
- [ ] Commit messages are clear and atomic
- [ ] No secrets or credentials committed
- [ ] Documentation updated if behavior changed

### What Makes a Good PR

- **Small and focused.** One feature, one bug fix, or one refactor. Not all three.
- **Tests included.** If you added a command handler, there should be a test that calls it and checks the output.
- **No drive-by cleanups.** Don't reformat code you didn't change, add docstrings to untouched functions, or "improve" surrounding code.
- **Explains the why.** The diff shows *what* changed. The PR description should explain *why*.

---

## Design Principles

These principles guide what gets accepted into CI/CDecoy.

### Realism over features

A decoy's value is measured by how long an attacker believes it's real. Every response, every timing delay, every error message should match what a real Linux system would produce. When adding a command handler, run the real command on Ubuntu and match the output format exactly.

### Intelligence over alerts

The CTI pipeline exists to produce structured intelligence (MITRE ATT&CK mappings, behavioral profiles, kill chain detection), not just fire alerts. When adding enrichment logic, think about what an analyst would want to know, not just "is this bad?"

### Offline by default

The entire local development stack runs without API keys, cloud accounts, or internet access. Tier 3 uses Ollama for local LLM inference. If you add a feature that requires an external service, it must be optional and the system must degrade gracefully without it.

### Services don't share code

Each service (ssh-decoy, cti, dashboard, inference) is an independent container with its own dependencies, Dockerfile, and requirements.txt. They communicate through NATS and HTTP, never through shared Python imports. This keeps services independently deployable and testable.

### The event schema is the contract

All services agree on the common event schema. If you need to add a field, update `config/schema.sql`, add it to the event schema tests, and ensure backward compatibility — existing events without the field should still work.

---

## Security Considerations

CI/CDecoy is a security tool. Code quality matters more than usual.

### What the response filter prevents

The inference gateway (`inference/response_filter.py`) strips LLM responses that would reveal the decoy's nature:

- "I'm an AI" / "I'm a language model" / "I can't actually execute"
- Internal paths like `/opt/cicdecoy` or `inference-gateway`
- NATS connection strings or database DSNs
- Markdown formatting, code fences, or other non-terminal output

If you modify the inference pipeline, ensure the filter still catches these patterns. An attacker who realizes they're in a honeypot will disconnect immediately, and all intelligence value is lost.

### Credentials are intentional

The codebase contains hardcoded passwords like `admin123` and `W3lcome2024!`. These are **intentional honeypot credentials**, not security vulnerabilities. Ruff's bandit rules are configured to suppress these warnings (`S105`, `S106`). Don't "fix" them.

### Virtual filesystem boundaries

The SSH decoy uses a virtual filesystem (`filesystem.py`, `cow_filesystem.py`) — it never touches the real filesystem. The Copy-on-Write layer (`SessionFilesystem`) ensures each session gets isolated mutations. If you add filesystem operations, always go through the `fs` parameter, never through Python's `os` or `pathlib` directly.

### Session isolation

Each SSH session gets its own:
- Session ID (UUID)
- CoW filesystem overlay
- Environment variables
- Command history
- Sudo authentication state

Never leak state between sessions. The `SessionState` object in `session.py` is the single source of truth for per-session state.

---

## Debugging

### Events not appearing in the database

```bash
# Check if the decoy is publishing events
make events                    # Watch NATS live — you should see events when you SSH in

# Check if the CTI pipeline is running
make logs-collector            # Look for "Processing event" or errors

# Check NATS stream health
docker compose exec nats nats stream info DECOY_EVENTS -s nats://localhost:4222

# Check the database directly
make db-events                 # Should show recent events
```

Common causes:
- NATS streams not initialized (check `nats-init` container exited successfully)
- CTI pipeline crashed (check `make logs-collector`)
- TimescaleDB not ready when pipeline started (check health)

### SSH decoy not responding

```bash
make logs-decoy                # Check for Python tracebacks
docker compose restart ssh-decoy
```

Common causes:
- Host key generation failed (check `/var/lib/cicdecoy/` volume)
- Config file not mounted (check `docker compose config | grep -A5 ssh-decoy`)
- Port conflict on 2222 (check `lsof -i :2222`)

### Tier 3 LLM not working

```bash
# Check Ollama is running and model is loaded
curl http://localhost:11434/api/tags

# Check inference gateway health
curl http://localhost:8000/v1/health

# Check inference logs
make logs-tier3

# If model isn't pulling, restart Ollama init
docker compose --profile tier3 restart ollama-init
```

### Dashboard showing no data

```bash
# Check SSE connection
curl -N http://localhost:8080/api/events/stream

# Check database connection
curl http://localhost:8080/api/stats

# Inject test events
make dashboard-inject          # Single event
make dashboard-burst           # 20 events
```

### Tests failing locally but passing in CI (or vice versa)

```bash
# Ensure you have the right Python version
python3 --version              # Should be 3.11+

# Ensure all deps are installed
make install

# Run from the tests directory
cd tests && python3 -m pytest -v --tb=long
```

Common causes:
- Wrong Python version (tests require 3.11+)
- Missing dependencies (`make install`)
- Stale `.pyc` files (delete `__pycache__/` directories)
- Running from wrong directory (must be in `tests/`)

---

## Reference Tables

### NATS Streams

| Stream | Subjects | Retention | Purpose |
|--------|----------|-----------|---------|
| `DECOY_EVENTS` | `cicdecoy.decoy.events.>` | 72h | Raw events from decoys and adapters |
| `ALERTS` | `cicdecoy.alert.>`, `cicdecoy.honeytoken.triggered.>` | 30d | High-severity alerts |
| `FALCO_ALERTS` | `cicdecoy.security.falco.>` | 30d | Container escape detection |

### Database Tables

| Table | Purpose | Key Columns |
|-------|---------|-------------|
| `decoy_events` | All interaction events (hypertable) | timestamp, session_id, event_type, severity, mitre_techniques |
| `falco_alerts` | Falco runtime alerts | rule_name, pod_name, correlated_session_id |
| `engage_outcomes` | MITRE Engage session metrics | intelligence_value, deception_maintained, escape_attempted |
| `fs_delta` | Per-session filesystem mutations | session_id, path, operation |

### Makefile Targets

| Target | Description |
|--------|-------------|
| `make up` | Start Tier 2 stack |
| `make up-tier3` | Start Tier 2 + Tier 3 (Ollama) |
| `make down` | Stop all services |
| `make ssh` | SSH into Tier 2 decoy |
| `make ssh3` | SSH into Tier 3 decoy |
| `make test` | Run unit tests |
| `make lint` | Run ruff linter |
| `make fmt` | Auto-format code |
| `make check` | Lint + test |
| `make install` | Install all Python dependencies |
| `make logs` | Tail all logs |
| `make events` | Watch NATS events live |
| `make db` | Open psql shell |
| `make db-events` | Show last 20 events |
| `make db-sessions` | Show session summaries |
| `make dashboard` | Open dashboard in browser |
| `make dashboard-dev` | Vite hot-reload server |
| `make dashboard-inject` | Inject test event |
| `make clean` | Remove data volumes |
| `make reset` | Full reset (volumes + images) |

### Environment Variables

See `.env.example` for all configurable variables. Key ones:

| Variable | Default | Used By |
|----------|---------|---------|
| `NATS_URL` / `NATS_ENDPOINT` | `nats://nats:4222` | All services |
| `DB_DSN` | `postgresql://cicdecoy:cicdecoy@timescaledb:5432/cicdecoy` | CTI, Dashboard |
| `DECOY_CONFIG` | `/etc/cicdecoy/decoy.yaml` | SSH Decoy |
| `DECOY_TIER` | `2` | SSH Decoy |
| `INFERENCE_ENDPOINT` | `http://inference:8000` | SSH Decoy (Tier 3) |
| `MODEL_CONFIG` | `/etc/cicdecoy/model-config.yaml` | Inference |
| `PROFILES_DIR` | `/etc/cicdecoy/profiles` | SSH Decoy, Inference |
| `RESPONSE_DB_DIR` | `/app/responses` | SSH Decoy |
| `LOG_LEVEL` | `DEBUG` | All services |

---

## Further Reading

- [Deception as Code Spec](docs/specifications/deception-as-code-spec.md) — core philosophy, CRD design, and lifecycle
- [Message Bus Spec](docs/specifications/message-bus-spec.md) — NATS streams, subjects, and event schema
- [Decoy Manifest Schema](docs/specifications/decoy-manifest-schema.md) — YAML manifest reference
- [Adapter Contract](docs/specifications/adapter-contract.md) — how to integrate third-party honeypots
- [SIEM Forwarding Spec](docs/specifications/siem-forwarding-spec.md) — export formats and SIEM targets

---

## Reporting Issues

Open an issue on GitHub with:

- What you expected vs what happened
- Steps to reproduce
- Relevant logs (`make logs-decoy`, `make logs-collector`, etc.)
- Your environment (OS, Docker version, Python version)

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
