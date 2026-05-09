# CI/CDecoy — Hydra: Adaptive Deception Orchestration Specification

 Hydra is the adaptive orchestration layer of CI/CDecoy. It closes the
 feedback loop between attacker intelligence (produced by the CTI pipeline)
 and deception infrastructure (managed by the operator). Where the CTI
 pipeline answers "what is the attacker doing?", Hydra answers "what should
 we do about it?"

 This specification defines the decision engine architecture, the
 HydraStrategy CRD, the NATS control plane, the breadcrumb injection
 protocol, and the safety constraints that prevent runaway automation.

---

## Why Hydra Exists

CI/CDecoy's CTI pipeline classifies attackers into four tiers of sophistication (scanner, basic_operator, manual_operator, advanced_threat), assigns behavioral scores (0.0-1.0), maps TTPs to MITRE ATT&CK, and produces high-confidence session alerts (kill chain detection, C2 framework identification, dangerous progression patterns). This intelligence currently flows to dashboards, SIEM forwarders, and webhook alerts.

What it does not do is feed back into the deception infrastructure.

A scanner probing port 22 receives the same decoy experience as an advanced threat actor running Cobalt Strike. A Tier 1 beacon decoy stays a Tier 1 beacon regardless of who connects. Breadcrumbs are planted at deployment time and never adapt to what the attacker is actually looking for.

This is a missed opportunity. The deception literature (MITRE Engage, Thinkst's canary philosophy, Cymmetria's MazeRunner research) consistently identifies adaptive engagement as the highest-value deception pattern: tailoring the environment to the attacker based on observed behavior to maximize intelligence collection, increase dwell time, and guide the attacker toward controlled infrastructure.

Hydra implements adaptive engagement as a Kubernetes-native control loop:

1. **Observe**: Consume alerts and enriched events from the CTI pipeline via NATS
2. **Orient**: Match incoming signals against operator-defined HydraStrategy CRDs
3. **Decide**: Select actions, apply safety constraints, optionally request human approval
4. **Act**: Create Decoy/HoneyToken CRDs, inject breadcrumbs into running decoys, escalate engagement tiers

The name "Hydra" reflects the core behavior: cut off one head (attacker compromises or otherwises is done with a decoy) and two more appear (new decoys deployed, new breadcrumbs planted, engagement deepened).

## Architecture

### Component Placement

```bash
                                      ┌──────────────────────────┐
                                      │       CTI Pipeline       │
                                      │  session_analyzer.py     │
                                      │  enrichment.py           │
                                      │  engage_mapper.py        │
                                      └────────────┬─────────────┘
                                                   │
                                    NATS: cicdecoy.alert.session.>
                                    NATS: cicdecoy.enriched.events.>
                                                   │
                                      ┌────────────▼─────────────┐
                                      │         HYDRA            │
                                      │  ┌───────────────────┐   │
                                      │  │  Strategy Loader  │   │  ◄── watches HydraStrategy CRDs
                                      │  └────────┬──────────┘   │
                                      │  ┌────────▼──────────┐   │
                                      │  │  Decision Engine  │   │  ◄── evaluates triggers
                                      │  └────────┬──────────┘   │
                                      │  ┌────────▼──────────┐   │
                                      │  │ Constraint Checker│   │  ◄── cooldowns, limits, circuit breaker
                                      │  └────────┬──────────┘   │
                                      │  ┌────────▼──────────┐   │
                                      │  │ Action Executor   │   │  ◄── creates CRDs, publishes NATS
                                      │  └───────────────────┘   │
                                      └───────┬──────┬───────────┘
                                              │      │
                              ┌───────────────┘      └──────────────┐
                              │                                     │
                    K8s API (CRDs)                         NATS Control Plane
                              │                                     │
               ┌──────────────▼──────────┐          ┌───────────────▼──────────┐
               │       Operator          │          │     Running Decoys       │
               │  reconciler.py          │          │  ssh-decoy/server.py     │
               │                         │          │  http-decoy/main.py      │
               │  Reconciles new Decoy   │          │                          │
               │  CRs into Deployments   │          │  ControlReceiver injects │
               │  + Services + Secrets   │          │  breadcrumbs into VFS    │
               └─────────────────────────┘          └──────────────────────────┘
```

### Service Design

Hydra is a **Python asyncio service** deployed as a Kubernetes Deployment. The language choice is deliberate:

- **Shared data models**: The CTI pipeline's alert schemas, session classification constants (`TOOL_CATEGORIES`, `SEVERITY_RANK`), and MITRE technique mappings are all Python. Hydra needs to deserialize and reason about the same structures.
- **Kubernetes client**: The `kubernetes` Python client is already used by the operator. Hydra uses it to create Decoy/HoneyToken CRDs and watch HydraStrategy resources.
- **NATS client**: `nats-py` (asyncio) is already used by the CTI pipeline. Hydra follows identical connection and JetStream patterns.
- **Performance**: Hydra processes decisions at alert-rate (tens per minute during active attacks, near-zero otherwise). There is no throughput bottleneck that would justify a compiled language.

### Deployment

Hydra deploys as a single-replica Deployment (leader-elected if scaled) following the exact patterns established by the CTI pipeline (`cti-pipeline.yaml`):

- Init container waiting for NATS readiness
- `automountServiceAccountToken: true` (requires K8s API access)
- Read-only root filesystem, non-root user (65534), all capabilities dropped
- Prometheus metrics on a dedicated port
- Liveness/readiness probes on health endpoint
- Config mounted from ConfigMap

### RBAC

Hydra operates at the **CRD level only**. It creates and patches Decoy, HoneyToken, and HydraStrategy resources. It does **not** manage Deployments, Pods, or Secrets directly — that remains the operator's responsibility. This separation is critical for safety:

```yaml
# Hydra's ClusterRole
rules:
  # CRD management — create/patch deception resources
  - apiGroups: ["cicdecoy.io"]
    resources: ["decoys", "honeytokens", "decoytemplates", "decoyprofiles", "hydrastrategies"]
    verbs: ["get", "list", "watch", "create", "update", "patch"]
  - apiGroups: ["cicdecoy.io"]
    resources: ["decoys/status", "honeytokens/status", "hydrastrategies/status"]
    verbs: ["get", "patch", "update"]
  # Namespace discovery (read-only)
  - apiGroups: [""]
    resources: ["namespaces"]
    verbs: ["get", "list", "watch"]
```

Hydra intentionally cannot delete CRDs (no `delete` verb). Dynamic decoys are retired by patching their status to `Retired`, which the operator handles during reconciliation. This prevents accidental mass deletion.

---

## HydraStrategy CRD

### Overview

A HydraStrategy is a Kubernetes custom resource that defines an adaptive response policy. It declares:

- **When** to act (trigger conditions)
- **What** to do (actions)
- **How much** to do (constraints)
- **Why** (MITRE Engage mapping for reporting)

Strategies are namespaced resources, evaluated in priority order (higher priority number = evaluated first). Multiple strategies can match the same event; all matching strategies execute (subject to constraints).

### Example

```yaml
apiVersion: cicdecoy.io/v1alpha1
kind: HydraStrategy
metadata:
  name: advanced-threat-engage
  namespace: cicdecoy
  labels:
    cicdecoy.io/strategy-class: offensive
spec:
  enabled: true
  priority: 200
  description: >-
    When an advanced threat actor or high-scoring session is detected,
    deploy a Tier 3 adaptive decoy tailored to their observed interests,
    inject SSH breadcrumbs pointing to it, and plant AWS honeytokens.
  triggers:
    - classification: advanced_threat
    - minBehavioralScore: 0.7
  actions:
    - type: deploy_decoy
      templateRef: tier3-ssh-workstation
      injectIntoSource: true
    - type: inject_breadcrumb
      breadcrumbTemplate: ssh-known-hosts
    - type: place_honeytoken
      honeytokenType: aws-key
  constraints:
    cooldownSeconds: 600
    maxDecoysPerExecution: 3
    maxTotalDynamicDecoys: 20
    ttlSeconds: 86400
    requireApproval: false
  engage:
    activity: EAC0006      # Pocket Lure
    approach: EAP0004      # Direction
    goal: EGA0004          # Elicit
```

### Trigger Semantics

Each trigger object defines a set of conditions. Within a single trigger, all specified conditions must be met (**AND** logic). Across multiple triggers in the `triggers` array, any one matching trigger activates the strategy (**OR** logic).

This allows expressive rules like "advanced_threat classification **OR** behavioral score >= 0.7" (two triggers) as well as "manual_operator classification **AND** C2 tool detected" (one trigger with both fields).

**Trigger fields:**

| Field | Type | Semantics |
|-------|------|-----------|
| `classification` | enum | Session classification must exactly match. Values: `scanner`, `basic_operator`, `manual_operator`, `advanced_threat` |
| `minBehavioralScore` | float (0.0-1.0) | Behavioral score must be >= this value |
| `alertTypes` | string[] | At least one of these alert types must be present. Values: `kill_chain`, `dangerous_progression`, `high_behavioral_score`, `c2_framework_detected` |
| `requiredTechniques` | string[] | At least one of these MITRE ATT&CK technique IDs must appear in the session |
| `requiredToolCategories` | string[] | At least one tool from these categories must be detected. Values: `c2`, `enumeration`, `reconnaissance`, `exploitation`, `credential_access`, `exfiltration` |
| `minPhaseCount` | int | Session must have traversed at least this many distinct MITRE tactic phases |
| `minCommandCount` | int | Session must have this many commands executed |
| `decoyTypes` | string[] | Triggering decoy must be one of these service types (e.g., `ssh`, `http`) |

### Action Types

| Action | Parameters | Effect |
|--------|-----------|--------|
| `deploy_decoy` | `templateRef` (required), `targetNamespace`, `injectIntoSource` | Creates a Decoy CR by instantiating a DecoyTemplate. If `injectIntoSource` is true, also injects breadcrumbs into the triggering decoy that point to the new one. |
| `inject_breadcrumb` | `breadcrumbTemplate` (required) | Publishes a NATS injection command to the triggering decoy. Template generates context-appropriate files. |
| `place_honeytoken` | `honeytokenType` (required) | Generates a canary credential value, creates a HoneyToken CR, and injects the credential file into the triggering decoy. |
| `escalate_tier` | `targetTier` (required) | Patches the triggering Decoy CR's `spec.fidelity.tier` field. The operator's `on.update` handler naturally reconciles the change. |
| `deploy_fleet` | `templateRef` (required), `fleetCount` (1-10) | Creates a DecoyFleet CR to deploy multiple decoys from a template. |

### Constraints

| Field | Default | Purpose |
|-------|---------|---------|
| `cooldownSeconds` | 300 | Minimum interval between executions for the same (strategy, session_id) pair |
| `maxDecoysPerExecution` | 3 | Maximum Decoy CRs created per single strategy execution |
| `maxTotalDynamicDecoys` | 20 | Global cap on Hydra-managed Decoys (across all strategies) |
| `requireApproval` | false | If true, actions are queued for human approval before execution |
| `activeHours` | null | Optional time window restriction (startHour, endHour, timezone) |
| `ttlSeconds` | null | Auto-retire dynamic decoys after this duration |

### Global Constraints (Engine-Level)

Beyond per-strategy constraints, the Hydra engine enforces global safety limits:

- **Max actions per hour**: 50 (configurable). Prevents runaway strategy chains.
- **Circuit breaker**: If the engine encounters 10+ errors in 5 minutes, all action execution pauses and an alert is published to `cicdecoy.hydra.status`. Requires manual reset via CLI or dashboard.
- **Resource counting**: Before creating a Decoy CR, Hydra queries the K8s API for all Decoys with label `cicdecoy.io/hydra-managed=true` and respects the `maxTotalDynamicDecoys` cap.

### Status

```yaml
status:
  executionCount: 47
  lastExecutionTime: "2026-04-27T14:30:00Z"
  lastSessionId: "sess-abc123"
  dynamicDecoysCreated: 12
  honeytokensPlaced: 8
  conditions:
    - type: Ready
      status: "True"
      lastTransitionTime: "2026-04-27T10:00:00Z"
      reason: Loaded
      message: "Strategy loaded and active"
```

---

## NATS Control Plane

### New Stream: HYDRA_CONTROL

```yaml
name: HYDRA_CONTROL
subjects:
  - "cicdecoy.hydra.>"
retention: limits
max_bytes: 1073741824     # 1 GB
max_age: 604800000000000  # 7 days (nanoseconds)
max_msg_size: 1048576     # 1 MB per message
storage: file
num_replicas: 1
discard: old
deny_delete: true
deny_purge: true
```

### Subject Hierarchy

```
cicdecoy.hydra.
├── decisions.                         # Audit trail
│   └── {strategy-name}               # Decision event per strategy execution
│
├── control.                           # Commands to running components
│   ├── inject.                        # Breadcrumb/honeytoken injection
│   │   └── {decoy-name}              # Targeted to specific decoy
│   └── escalate.                      # Tier escalation audit events
│       └── {decoy-name}              # Audit record (actual escalation via K8s patch)
│
├── approval.                          # Human approval flow
│   ├── request                        # Pending decisions requiring approval
│   └── response                       # Approval/denial from human operator
│
└── status                             # Engine health/status heartbeats
```

### Consumers

| Consumer | Stream | Filter | Deliver | Ack Wait | Max Deliver |
|----------|--------|--------|---------|----------|-------------|
| `hydra-engine` | `HYDRA_CONTROL` | `cicdecoy.hydra.>` | all | 30s | 5 |
| `hydra-triggers` | `ALERTS` | `cicdecoy.alert.session.>` | all | 30s | 5 |
| `hydra-enriched` | `ENRICHED_EVENTS` | `cicdecoy.enriched.events.>` | all | 10s | 3 |

### Consumed Subjects (Existing Streams)

Hydra subscribes to two existing streams:

1. **`cicdecoy.alert.session.>`** (ALERTS stream) — The primary trigger source. Session-level alerts with classification, behavioral score, tool signatures, and technique lists. These are the highest-confidence signals.

2. **`cicdecoy.enriched.events.>`** (ENRICHED_EVENTS stream, optional) — Individual enriched events for real-time context. Not used for triggering by default, but available for strategies that need per-event granularity.

---

## Breadcrumb Injection Protocol

### Runtime Injection

When a strategy's action is `inject_breadcrumb` or `place_honeytoken`, Hydra publishes a message to `cicdecoy.hydra.control.inject.{decoy_name}`. The target decoy's `ControlReceiver` (a new component in the decoy process) subscribes to this subject and applies the injection.

### Message Schema

```json
{
  "command": "inject_breadcrumb",
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "strategy": "advanced-threat-engage",
  "session_id": "sess-abc123",
  "timestamp": "2026-04-27T14:30:00Z",
  "breadcrumbs": [
    {
      "path": "/home/admin/.ssh/known_hosts",
      "content": "10.0.3.15 ecdsa-sha2-nistp256 AAAA...\n10.0.3.16 ecdsa-sha2-nistp256 AAAA...",
      "owner": "admin",
      "permissions": "0644",
      "mode": "append"
    },
    {
      "path": "/home/admin/.aws/credentials",
      "content": "[default]\naws_access_key_id = AKIAIOSFODNN7HYDRA01\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bHydraCanaryKey01\nregion = us-east-1",
      "owner": "admin",
      "permissions": "0600",
      "mode": "create",
      "honeytoken_ref": "hydra-aws-canary-abc123"
    }
  ],
  "inject_into": "base",
  "target_sessions": ["all"]
}
```

### Injection Scope

The `inject_into` field controls where files are written:

- `"base"` — Writes to the shared `VirtualFilesystem`. Visible to all current and future sessions on this decoy. This is the default and most useful mode.
- `"session"` — Writes only to the specified `target_sessions` COW overlays. Useful for per-attacker customization without affecting other sessions.
- `"both"` — Writes to both the base filesystem and specified session overlays.

### ControlReceiver Design

A new class added to `ssh-decoy/server.py` and `http-decoy/main.py`:

```python
class ControlReceiver:
    """Subscribes to NATS control commands for this decoy."""

    def __init__(self, nc, decoy_name, filesystem, session_manager):
        self.nc = nc
        self.decoy_name = decoy_name
        self.filesystem = filesystem        # VirtualFilesystem (base)
        self.session_manager = session_manager  # for session-scoped injection

    async def start(self):
        subject = f"cicdecoy.hydra.control.inject.{self.decoy_name}"
        await self.nc.subscribe(subject, cb=self._on_inject)

    async def _on_inject(self, msg):
        # Parse, validate, apply injection to filesystem
        # Publish acknowledgment to cicdecoy.hydra.status
```

The `VirtualFilesystem` class gains a public `inject_file(path, content, owner, permissions, mode)` method that performs thread-safe file injection. The existing `_add_file` is a private method only called during initialization; `inject_file` handles runtime mutation with appropriate locking.

---

## Breadcrumb Templates

Templates generate contextually appropriate breadcrumb content based on the attacker's observed behavior. Each template produces one or more files and optionally an associated HoneyToken CR.

### Template Catalog

| Template | Trigger Context | Files Generated | Honeytoken? |
|----------|----------------|-----------------|-------------|
| `aws-creds` | Attacker uses aws/cloud tools or accesses .aws/ | `/home/{user}/.aws/credentials`, `/home/{user}/.aws/config` | Yes (aws-key) |
| `ssh-known-hosts` | Any SSH decoy interaction | `/home/{user}/.ssh/known_hosts` with IPs of other decoys | No |
| `bash-history` | manual_operator or advanced_threat classification | `/home/{user}/.bash_history` with commands referencing internal hosts | No |
| `kubeconfig` | Attacker accesses .kube/ or runs kubectl | `/home/{user}/.kube/config` with canary cluster/token | Yes (kubeconfig) |
| `database-cred` | Attacker probes DB ports or runs DB tools | `/home/{user}/.pgpass` or `/home/{user}/.my.cnf` | Yes (database-cred) |
| `git-credentials` | Attacker accesses .git/ or runs git commands | `/home/{user}/.git-credentials` with canary GitHub token | Yes (api-token) |
| `docker-config` | Attacker accesses Docker files or runs docker | `/home/{user}/.docker/config.json` with registry canary | Yes (api-token) |
| `env-file` | Attacker reads environment or .env files | `/opt/app/.env` with canary DB/API credentials | Yes (database-cred) |

### Honeytoken Value Generation

When a template produces a honeytoken, the generator creates a credential value with an embedded tracking identifier:

- **AWS keys**: Valid AKIA-format key with last 8 characters encoding the strategy+session hash. Invalid for real AWS API calls but structurally valid enough to pass automated extraction tools.
- **SSH keys**: Real RSA keypair with the key comment field set to the tracking ID. Structurally valid and will fingerprint correctly.
- **API tokens**: UUID-based tokens with a recognizable prefix (`ht-cicdecoy-`) for correlation.
- **Kubeconfigs**: Valid YAML structure pointing to a non-routable IP (e.g., `10.255.255.1`) with a canary bearer token.

Each generated value is stored in:
1. A `HoneyToken` CRD (for Kubernetes-native tracking)
2. The `hydra_dynamic_honeytokens` database table (for historical querying)

---

## Database Schema

### hydra_decisions (hypertable)

Records every decision Hydra makes, including suppressed/rate-limited decisions for complete audit trail.

```sql
CREATE TABLE hydra_decisions (
    decision_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    strategy_name   TEXT NOT NULL,
    session_id      TEXT,
    source_ip       INET,
    decoy_name      TEXT,
    classification  TEXT,
    behavioral_score FLOAT,
    trigger_summary JSONB NOT NULL,
    actions_taken   JSONB NOT NULL,
    actions_pending JSONB,
    outcome         TEXT NOT NULL DEFAULT 'executed',
    error_message   TEXT,
    decoys_created  TEXT[],
    honeytokens_placed TEXT[],
    metadata        JSONB
);

SELECT create_hypertable('hydra_decisions', 'timestamp', if_not_exists => TRUE);
CREATE INDEX idx_hydra_decisions_strategy ON hydra_decisions (strategy_name, timestamp DESC);
CREATE INDEX idx_hydra_decisions_session ON hydra_decisions (session_id) WHERE session_id IS NOT NULL;
CREATE INDEX idx_hydra_decisions_outcome ON hydra_decisions (outcome, timestamp DESC);
```

**Outcome values**: `executed`, `pending_approval`, `suppressed_cooldown`, `suppressed_limit`, `error`

### hydra_dynamic_decoys

Tracks lifecycle of Hydra-managed decoys (decoys created by strategies, not manually deployed ones).

```sql
CREATE TABLE hydra_dynamic_decoys (
    decoy_name      TEXT PRIMARY KEY,
    namespace       TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    strategy_name   TEXT NOT NULL,
    triggering_session TEXT,
    source_ip       INET,
    decoy_type      TEXT,
    decoy_tier      INTEGER,
    ttl_expires_at  TIMESTAMPTZ,
    status          TEXT NOT NULL DEFAULT 'active',
    retired_at      TIMESTAMPTZ,
    interaction_count INTEGER DEFAULT 0,
    metadata        JSONB
);

CREATE INDEX idx_hydra_dynamic_decoys_status ON hydra_dynamic_decoys (status);
CREATE INDEX idx_hydra_dynamic_decoys_ttl ON hydra_dynamic_decoys (ttl_expires_at)
    WHERE status = 'active';
```

### hydra_dynamic_honeytokens

Tracks dynamically placed honeytokens and their trigger status.

```sql
CREATE TABLE hydra_dynamic_honeytokens (
    honeytoken_name TEXT PRIMARY KEY,
    namespace       TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    strategy_name   TEXT NOT NULL,
    honeytoken_type TEXT NOT NULL,
    placed_in_decoy TEXT,
    file_path       TEXT,
    triggering_session TEXT,
    triggered       BOOLEAN DEFAULT FALSE,
    triggered_at    TIMESTAMPTZ,
    triggered_by_ip INET,
    metadata        JSONB
);

CREATE INDEX idx_hydra_dynamic_ht_triggered ON hydra_dynamic_honeytokens (triggered, created_at);
CREATE INDEX idx_hydra_dynamic_ht_decoy ON hydra_dynamic_honeytokens (placed_in_decoy);
```

---

## Default Strategies

CI/CDecoy ships five example HydraStrategy manifests covering the attacker classification spectrum. Operators can use these as-is, modify them, or create entirely custom strategies.

### 1. scanner-breadcrumb

**Trigger**: `classification == scanner`
**Actions**: Inject cloud credential breadcrumbs into the source decoy.
**Rationale**: Scanners are low-effort, high-volume. Most won't act on breadcrumbs, but the ones that do self-select as higher-value targets. Cost is minimal (no new decoys, just file injection), upside is converting drive-by probes into tracked engagements.

### 2. operator-escalate

**Trigger**: `classification == manual_operator AND behavioral_score >= 0.5`
**Actions**: Escalate triggering decoy to Tier 2 (if currently Tier 1), deploy an adjacent SSH decoy, inject `.ssh/known_hosts` entries pointing to the new decoy.
**Rationale**: Manual operators who persist past initial reconnaissance are worth engaging. A Tier 2 response with realistic scripted commands keeps them interested longer than a Tier 1 beacon. The breadcrumb trail creates opportunities for lateral movement telemetry.

### 3. advanced-threat-engage

**Trigger**: `classification == advanced_threat OR behavioral_score >= 0.7`
**Actions**: Deploy a Tier 3 adaptive decoy matching the attacker's interests, inject breadcrumbs pointing to it, place AWS honeytokens.
**Rationale**: Advanced threats warrant maximum engagement. Tier 3's LLM-backed responses can sustain arbitrary interactive sessions. The honeytoken creates an external detection channel (if the attacker uses the AWS key outside the decoy, CloudTrail catches it).

### 4. c2-detected-expand

**Trigger**: `alert_type == c2_framework_detected`
**Actions**: Deploy a fleet of 3 decoys simulating lateral movement targets, plant kubeconfig honeytokens.
**Rationale**: C2 framework detection indicates a serious actor with infrastructure. Expanding the deception surface gives them multiple targets to explore, multiplying intelligence collection. Kubeconfigs are high-value targets for cloud-savvy operators.

### 5. kill-chain-alert

**Trigger**: `alert_type == kill_chain`
**Actions**: Same as advanced-threat-engage, but with `requireApproval: true`.
**Rationale**: Kill chain detection (multiple MITRE phases completed) is the highest-confidence alert. But it also carries the highest risk of false positive (legitimate red team, security researcher). Requiring human approval adds a checkpoint before committing resources.

---

## TTL Reaper

Dynamic decoys are temporary by design. They exist to engage a specific attacker or session and should not persist indefinitely, consuming resources and creating confusion.

The TTL Reaper is a periodic async task within the Hydra engine that:

1. Every 60 seconds, queries `hydra_dynamic_decoys` for records where `ttl_expires_at < NOW() AND status = 'active'`
2. For each expired decoy:
   a. Patches the Decoy CR's status to `Retired`
   b. Updates the database record (`status = 'retired'`, `retired_at = NOW()`)
   c. Publishes an audit event to `cicdecoy.hydra.decisions.{strategy}.retired`
3. The operator's reconciler handles the actual teardown (scaling Deployment to 0, cleaning up resources)

If no `ttlSeconds` is set on the strategy, dynamic decoys persist until manually retired.

---

## Metrics

Hydra exposes Prometheus metrics on its metrics port:

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `hydra_decisions_total` | counter | strategy, outcome | Total decisions made |
| `hydra_actions_total` | counter | strategy, action_type | Total actions executed |
| `hydra_dynamic_decoys_active` | gauge | — | Current count of active Hydra-managed decoys |
| `hydra_dynamic_honeytokens_total` | counter | strategy, type | Total honeytokens placed |
| `hydra_honeytokens_triggered_total` | counter | strategy, type | Honeytokens that were triggered by attackers |
| `hydra_cooldowns_hit_total` | counter | strategy | Decisions suppressed by cooldown |
| `hydra_limits_hit_total` | counter | strategy | Decisions suppressed by resource limits |
| `hydra_approvals_pending` | gauge | — | Decisions awaiting human approval |
| `hydra_errors_total` | counter | strategy, error_type | Errors during action execution |
| `hydra_circuit_breaker_state` | gauge | — | 0 = closed (healthy), 1 = open (paused) |
| `hydra_decision_latency_seconds` | histogram | strategy | Time from signal receipt to action execution |

---

## Phased Implementation

### Phase 1 — MVP: Core Decision Engine

**Goal**: Hydra can consume alerts, evaluate strategies, and create new Decoy CRDs.

**Scope**:
- HydraStrategy CRD definition added to existing CRD file
- `hydra/engine.py` — asyncio main loop, NATS consumer, strategy evaluation
- `hydra/strategy_loader.py` — K8s watch for HydraStrategy CRDs
- `hydra/action_executor.py` — `deploy_decoy` action only (creates Decoy CR from DecoyTemplate)
- `hydra/constraints.py` — cooldown tracking, resource counting, circuit breaker
- `hydra/db.py` — database operations for `hydra_decisions` and `hydra_dynamic_decoys`
- `hydra/metrics.py` — Prometheus counter/gauge registration
- SQL migration for new tables
- Helm template (`hydra.yaml`, `hydra-rbac.yaml`)
- `hydra:` section in `values.yaml`
- NATS stream/consumer additions to `nats-init.yaml`
- `hydra` service in `docker-compose.yaml`
- 2-3 example strategy YAMLs
- Unit tests for engine, strategy loader, constraints

**Not in scope**: Breadcrumb injection, honeytoken generation, tier escalation, approval flow, TTL reaper.

### Phase 2 — Runtime Injection + Honeytokens

**Goal**: Full closed-loop deception. Attacker interacts with decoy, Hydra observes, injects breadcrumbs, attacker follows breadcrumbs to new decoys.

**Scope**:
- `hydra/breadcrumb_templates.py` — all 8 contextual template generators
- `hydra/honeytoken_generator.py` — canary credential generators with tracking IDs
- `ssh-decoy/server.py` — `ControlReceiver` class for NATS injection commands
- `ssh-decoy/filesystem.py` — public `inject_file()` method on `VirtualFilesystem`
- `inject_breadcrumb`, `place_honeytoken`, `escalate_tier` actions in action_executor
- `hydra/approval.py` — human approval queue via NATS
- `hydra/ttl_reaper.py` — periodic dynamic decoy expiration
- SQL migration for `hydra_dynamic_honeytokens`
- All 5 default strategies
- Integration tests (NATS flow, breadcrumb visibility)
- Dashboard panel for Hydra decisions

### Phase 3 — Advanced Strategies + Observability

**Goal**: Sophisticated behavioral matching, campaign-level orchestration, ML hooks.

**Scope**:
- Compound triggers (temporal conditions, cross-session correlation)
- Strategy effectiveness feedback loop (honeytoken trigger rate tracking)
- Campaign grouping for aggregate reporting
- ML hook point (external scoring endpoint via HTTP webhook)
- Geographic/ASN-based triggers
- CLI commands (`cicdecoy hydra status`, `cicdecoy hydra strategies list`, `cicdecoy hydra approve`)
- Grafana dashboard templates
- Comprehensive E2E tests

---

## Relationship to Existing Components

### CTI Pipeline

Hydra is a **consumer** of the CTI pipeline's output. It does not modify or interfere with the pipeline's enrichment, storage, or alerting. Both systems subscribe to the same NATS subjects via separate durable consumers with independent cursors.

### Operator

Hydra creates CRDs. The operator reconciles them. Hydra never communicates with the operator directly — the Kubernetes API is the interface. For tier escalation, Hydra patches the Decoy CR's `spec.fidelity.tier` field, and the operator's existing `@kopf.on.update` handler reconciles the change naturally (rebuilding the Deployment with new tier-appropriate configuration).

### Decoys

Hydra communicates with running decoys **only** via NATS control messages for breadcrumb injection. It never connects to decoy pods directly, reads their logs, or accesses their filesystems. The ControlReceiver within each decoy is a clean interface boundary.

### Dashboard

The dashboard can query `hydra_decisions`, `hydra_dynamic_decoys`, and `hydra_dynamic_honeytokens` tables for visualization. Hydra decisions also flow through NATS (`cicdecoy.hydra.decisions.>`) for SSE real-time updates.

### SIEM Forwarder

The SIEM forwarder can optionally subscribe to the `HYDRA_CONTROL` stream to forward Hydra decision events to external SIEMs. This provides audit trail integration with existing SOC tooling.
