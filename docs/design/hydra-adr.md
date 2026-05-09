# Architecture Decision Record: Hydra — Adaptive Deception Orchestration

**Status:** Accepted  
**Date:** 2026-04-27  
**Authors:** @csquare-d  
**Related Spec:** [hydra-adaptive-orchestration-spec.md](../specifications/hydra-adaptive-orchestration-spec.md)  
**Related Roadmap Section:** v0.3.0+ (see [ROADMAP.md](../ROADMAP.md))

---

## 1. Problem Statement

CI/CDecoy produces high-quality attacker intelligence but does not act on it. The CTI pipeline classifies every session into one of four sophistication tiers (scanner, basic_operator, manual_operator, advanced_threat), computes a behavioral score, maps observed techniques to MITRE ATT&CK, and triggers session-level alerts. This intelligence flows to dashboards and SIEM forwarders — but never back into the deception infrastructure.

The result is that every attacker receives the same static decoy experience regardless of sophistication. A scanner and a Cobalt Strike operator get identical environments. Breadcrumbs and honeytokens are planted at deployment time and never adapt. There is no mechanism to:

- Deploy new decoys in response to detected threats
- Inject contextual breadcrumbs based on observed attacker interests
- Escalate engagement tiers when high-value attackers are identified
- Automatically expand the deception surface when C2 frameworks or kill chains are detected

This gap means CI/CDecoy leaves significant intelligence value on the table. The deception literature consistently identifies adaptive engagement as the highest-yield pattern, and CI/CDecoy already produces the signals needed to drive it.

---

## 2. Decision

Introduce **Hydra**, a new service that implements a closed-loop adaptive deception orchestrator. Hydra sits between the CTI pipeline (intelligence producer) and the operator/decoys (infrastructure managers), consuming behavioral signals and executing adaptive response strategies.

The design is captured in the full specification at `docs/specifications/hydra-adaptive-orchestration-spec.md`. This ADR focuses on the engineering decisions and their rationale.

---

## 3. Key Engineering Decisions

### 3.1 Separate Service vs. Extending the CTI Pipeline

**Decision:** Hydra is a new standalone service, not an extension of the CTI pipeline.

**Alternatives considered:**
- (A) Add Hydra logic directly to `cti/pipeline.py`
- (B) Add Hydra as a kopf handler in the existing operator
- (C) New standalone service

**Why (C):**

The CTI pipeline's job is intelligence production: ingest events, enrich them, classify sessions, emit alerts, store to database. Its failure mode is "we miss an event." Hydra's job is infrastructure mutation: create CRDs, inject files, manage lifecycles. Its failure mode is "we accidentally create 100 decoys" or "we inject wrong files into production decoys."

Coupling these concerns creates a blast radius problem. A bug in Hydra's strategy evaluation could crash the CTI pipeline, causing event loss. A resource exhaustion issue in the pipeline could delay Hydra's responses. They have fundamentally different reliability requirements and should fail independently.

The operator was also considered and rejected. The operator reconciles CRDs into Kubernetes workloads — it doesn't consume NATS events or run behavioral analysis. Adding event consumption would bloat its scope and create a direct dependency on NATS availability for reconciliation.

A standalone service also enables independent scaling, deployment, and feature gating (Hydra can be disabled entirely via `hydra.enabled: false` in values.yaml without affecting any other component).

### 3.2 Python (asyncio) vs. Go

**Decision:** Python with asyncio.

**Alternatives considered:**
- (A) Go (like CLI and SIEM forwarder)
- (B) Python (like CTI pipeline and operator)

**Why (B):**

1. **Shared data models.** Hydra deserializes the same alert/event schemas produced by the CTI pipeline's session_analyzer.py and enrichment.py. These are Python dataclasses and dicts with specific field semantics. Reimplementing them in Go creates a synchronization burden — every time a new tool signature or technique mapping is added to the CTI pipeline, the Go model must be updated in lockstep.

2. **Kubernetes client.** The operator already uses the `kubernetes` Python client. Hydra's CRD operations (create, patch, watch) follow identical patterns. The Go client-go library is more mature, but there's no existing Go code in the project that manages CRDs.

3. **NATS client.** `nats-py` (asyncio) is battle-tested in the CTI pipeline. Hydra's NATS patterns (JetStream pull subscribe, publish) are identical.

4. **Performance is irrelevant.** Hydra processes at alert-rate: tens of decisions per minute during active attacks, near-zero otherwise. The decision engine is I/O-bound (NATS subscribe, K8s API calls, DB writes), not CPU-bound. Python's GIL is not a factor because everything is asyncio.

5. **Team coherence.** Four of CI/CDecoy's six core services are Python (CTI pipeline, operator, SSH decoy, HTTP decoy). Adding another Go service increases the cognitive context-switching cost for contributors.

The exception where Go is used (CLI, SIEM forwarder) is justified: the CLI benefits from single-binary distribution, and the SIEM forwarder's hot path (NATS→format→output) benefits from zero-allocation buffer management. Neither applies to Hydra.

### 3.3 CRD-Level Actions vs. Direct Kubernetes Resource Management

**Decision:** Hydra operates exclusively at the CRD level. It creates/patches Decoy and HoneyToken custom resources. The existing operator handles reconciliation into Deployments, Services, and Secrets.

**Alternatives considered:**
- (A) Hydra creates Deployments/Services directly
- (B) Hydra creates CRDs, operator reconciles

**Why (B):**

Separation of concerns. The operator has established patterns for image selection, resource limits, security contexts, label conventions, health probes, and telemetry sidecar injection. Duplicating this logic in Hydra would create divergence — a security context hardening applied to the operator wouldn't automatically apply to Hydra-created workloads.

The CRD boundary also provides a natural audit point. Every dynamic decoy exists as a Kubernetes resource with creation timestamp, labels, and ownership metadata. `kubectl get decoys -l cicdecoy.io/hydra-managed=true` shows exactly what Hydra has done.

For tier escalation specifically: Hydra patches `spec.fidelity.tier` on the Decoy CR. The operator's existing `@kopf.on.update` handler fires, sees the tier change, and rebuilds the Deployment with the new tier's image and environment variables. Zero new reconciliation code needed in the operator.

### 3.4 HydraStrategy as CRD vs. ConfigMap vs. Static Config

**Decision:** HydraStrategy is a Kubernetes CRD (CustomResourceDefinition).

**Alternatives considered:**
- (A) ConfigMap with YAML strategies
- (B) Static YAML file mounted into the Hydra pod
- (C) CRD

**Why (C):**

1. **Kubernetes-native lifecycle.** CRDs get versioning, validation (OpenAPI v3 schema), RBAC, audit logging, and `kubectl` integration for free. `kubectl get hydrastrategies` works out of the box.

2. **Dynamic updates.** Hydra watches HydraStrategy resources. Creating, modifying, or deleting a strategy takes effect immediately without restarting Hydra. ConfigMaps can technically be watched too, but CRDs provide typed validation that ConfigMaps don't.

3. **GitOps compatibility.** Strategies live in Git as YAML manifests. ArgoCD/Flux can sync them like any other CRD. This aligns with the Deception as Code philosophy — strategies are code, managed with the same rigor as decoy manifests.

4. **Status subresource.** The CRD status field tracks execution counts, last execution time, and conditions. This metadata lives alongside the strategy definition and is queryable via the API.

5. **Consistency.** The project already defines 5 CRDs (Decoy, DecoyTemplate, DecoyProfile, HoneyToken, DecoyFleet). Adding HydraStrategy follows the established pattern. Introducing a different configuration mechanism would be inconsistent.

### 3.5 NATS Control Messages for Injection vs. Kubernetes API

**Decision:** Breadcrumb injection into running decoys uses NATS pub/sub, not Kubernetes API.

**Alternatives considered:**
- (A) Update a ConfigMap that the decoy mounts, then signal the pod
- (B) Exec into the pod and write files
- (C) NATS pub/sub to a ControlReceiver in the decoy process

**Why (C):**

(A) requires the decoy to poll or watch the ConfigMap for changes, adds Kubernetes API dependency to the decoy's hot path, and involves a multi-step race (update ConfigMap → wait for kubelet to project the update → signal the decoy). The latency is 30-60 seconds per the Kubernetes ConfigMap projection interval.

(B) requires Hydra to have pod/exec permissions, violating the principle that Hydra operates at CRD level only. It's also fragile (pod restarts lose injected state) and creates a direct network dependency between Hydra and decoy pods.

(C) leverages the existing NATS infrastructure. Decoys already connect to NATS for telemetry publishing. Adding a subscription to a control subject is minimal code. Delivery is near-instantaneous (~milliseconds). JetStream durability ensures injection commands survive brief decoy restarts. The VirtualFilesystem (in-memory) is the natural target for injected files since it's what commands like `cat`, `ls`, and `find` read from.

### 3.6 Tier Escalation via CR Patch vs. NATS Command

**Decision:** Tier escalation is implemented by patching the Decoy CR's `spec.fidelity.tier` field via the Kubernetes API. The NATS `cicdecoy.hydra.control.escalate.{decoy}` subject is used only for audit logging.

**Alternatives considered:**
- (A) NATS command to operator, operator patches the CR
- (B) Hydra patches the CR directly

**Why (B):**

The Kubernetes API is the source of truth for decoy configuration. Patching the CR directly triggers the operator's existing `@kopf.on.update` handler, which already knows how to reconcile tier changes (rebuild Deployment with new image, env vars, inference config). No new operator code needed.

(A) introduces an unnecessary indirection: Hydra → NATS → operator → K8s API → reconcile. The NATS hop adds latency, a failure point, and requires new message handling code in the operator. Since Hydra already has K8s API access (for creating Decoy CRs), patching an existing CR is simpler.

### 3.7 No Delete Permission — Retire Instead

**Decision:** Hydra's RBAC does not include the `delete` verb for any resource. Dynamic decoys are retired by patching their status, not by deleting the CR.

**Rationale:** Deletion is irreversible and dangerous. A bug in the TTL reaper or constraint checker that accidentally marks all decoys as expired would delete production deception infrastructure. By only allowing status patches, the worst case is that decoys get marked as Retired — the operator scales their Deployments to 0, but the CRDs remain for forensic review. An operator can recover by patching the status back to Active.

This also creates a clean audit trail: the lifecycle of every dynamic decoy (created → active → retired) is visible in the CRD's status history and the `hydra_dynamic_decoys` database table.

### 3.8 Cooldown Keyed on (Strategy, Session) Not (Strategy, IP)

**Decision:** Cooldown deduplication is keyed on `(strategy_name, session_id)`, not `(strategy_name, source_ip)`.

**Rationale:** A single IP can have multiple sessions (reconnects, parallel connections). Each session may exhibit different behavior (one session scans, another runs C2). Keying on IP would suppress responses to genuinely different attack phases from the same source.

Conversely, if an attacker maintains a single long session that generates multiple alerts (as classification escalates from basic_operator to advanced_threat), the cooldown correctly prevents repeated strategy execution within the same session.

The global `maxActionsPerHour` limit provides IP-level protection against resource exhaustion from a single highly active source.

### 3.9 Approval Queue via NATS, Not External System

**Decision:** Human approval for high-risk strategies flows through NATS (`cicdecoy.hydra.approval.{request|response}`), not an external ticketing or chat system.

**Rationale:** Phase 1/2 simplicity. NATS is already the event backbone. The dashboard can subscribe to approval requests and present them in a UI. The CLI can subscribe and present them interactively. No external system dependency.

Future phases may add Slack/Teams/PagerDuty approval flows as action types, but the core mechanism should not depend on external service availability.

---

## 4. What Hydra Is Not

Clarity on scope prevents feature creep:

- **Not a SOAR.** Hydra does not orchestrate response actions outside the deception infrastructure. It does not block IPs, create firewall rules, or trigger EDR isolations. Those are downstream actions for SOAR platforms consuming CI/CDecoy's SIEM exports.

- **Not an ML engine.** Phase 3 adds an ML hook point (external scoring via HTTP webhook), but Hydra itself uses deterministic rule matching. The Session Analyzer's classification and behavioral scoring are the "ML" — Hydra consumes their output.

- **Not a replacement for the operator.** Hydra creates CRDs. The operator reconciles them. Hydra never manages Deployments, Pods, Services, or Secrets directly.

- **Not a honeytoken monitor.** Hydra places honeytokens. Detecting their use (e.g., monitoring AWS CloudTrail for canary AKIA keys) is a separate concern covered by the HoneyToken CRD's `tracking` spec and future v0.2.0 work.

---

## 5. Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Runaway decoy creation | Resource exhaustion, cluster instability | Global `maxTotalDynamicDecoys` cap, `maxActionsPerHour` limit, circuit breaker |
| Strategy logic error (false positive) | Unnecessary decoys deployed | `requireApproval: true` for high-confidence strategies, TTL auto-retirement, audit trail in database |
| NATS unavailability | Hydra cannot receive triggers | Hydra logs warning and retries with exponential backoff. No actions taken during outage (fail-safe). Resume from durable consumer position on reconnect — no events lost. |
| Kubernetes API unavailability | Hydra cannot create CRDs | Action execution retries with backoff. Decision recorded as `outcome: error` in database. Circuit breaker trips after sustained failures. |
| Breadcrumb injection to wrong decoy | Attacker sees files intended for different context | Injection is keyed on `decoy_name` in NATS subject. Only the targeted decoy's ControlReceiver processes the message. |
| Attacker detects dynamic decoy creation | Attacker realizes they're in a honeypot | TTL means dynamic decoys appear and disappear naturally. Naming patterns from DecoyTemplates look like real infrastructure. Injection adds files — it doesn't modify existing ones. |
| Conflicting strategies | Multiple strategies fire for same event, creating redundant decoys | Cooldown dedup prevents duplicate actions. Resource cap provides hard limit. Audit trail shows which strategies fired. |

---

## 6. Dependencies

| Dependency | Version | Purpose |
|-----------|---------|---------|
| `nats-py` | >=2.6.0 | NATS JetStream client (asyncio) |
| `kubernetes` | >=28.1.0 | Kubernetes API client for CRD management |
| `asyncpg` | >=0.29.0 | PostgreSQL/TimescaleDB async client |
| `prometheus-client` | >=0.20.0 | Metrics exposition |
| `pyyaml` | >=6.0 | Strategy and template parsing |

All are already dependencies of other CI/CDecoy Python services.

---

## 7. Future Considerations

These items were explicitly deferred from the initial design:

- **Cross-session correlation triggers** (Phase 3): "Same IP seen on 3+ decoys" or "behavioral score increased from 0.3 to 0.8 within 5 minutes." Requires temporal state management in the engine.
- **Strategy effectiveness feedback loop** (Phase 3): Track which strategies produce honeytokens that actually get triggered. Auto-tune strategy priority based on yield.
- **Campaign abstraction** (Phase 3): Group related Hydra decisions under a campaign label for aggregate reporting.
- **ML scoring hook** (Phase 3): Strategy trigger can reference an external HTTP endpoint for custom ML model scoring.
- **Multi-cluster federation** (Beyond v1.0): Hydra decisions that span multiple Kubernetes clusters.

---

## 8. Decision Context (For Future Reference)

This design was developed on 2026-04-27 during the repo-restructure branch preparation for open-source release. The following context informed the decisions:

### What existed at design time:
- **CTI Pipeline**: Fully functional with session classification (4 tiers), behavioral scoring (0.0-1.0), 70+ MITRE technique mappings, 49 tool signatures, kill chain detection, and MITRE Engage mapping.
- **Operator**: kopf-based, reconciles Decoy CRDs into Deployments + Services + Secrets. Handles all 3 fidelity tiers.
- **CRDs**: 5 defined (Decoy, DecoyTemplate, DecoyProfile, HoneyToken, DecoyFleet). DecoyTemplate/DecoyProfile/DecoyFleet not yet reconciled by operator (v0.5.0 roadmap).
- **NATS**: JetStream with DECOY_EVENTS and FALCO_ALERTS streams. Alert subjects for session-level events. No control plane subjects.
- **SSH Decoy**: 60+ commands, COW filesystem, SCP/SFTP, 3 tiers, hifi_engine with 38 templates.
- **HTTP Decoy**: 10 login portals, attack detection, CSRF protection.
- **HoneyToken CRD**: Schema defined, placement spec defined, but no runtime trigger detection yet.

### What did not exist:
- Any feedback loop from CTI → infrastructure
- Any NATS control subjects for commanding running components
- Any mechanism for runtime file injection into decoys
- Any dynamic decoy lifecycle management
- Any strategy/playbook system for adaptive response

### Key codebase files for Hydra integration:
- `cti/session_analyzer.py` — Classification and scoring logic (Hydra's trigger source)
- `cti/pipeline.py` — NATS consumer patterns, DB schema setup
- `platform/operator/reconciler.py` — CRD reconciliation patterns
- `ssh-decoy/filesystem.py` — VirtualFilesystem.inject_file() target
- `ssh-decoy/server.py` — ControlReceiver integration point
- `platform/helm/cicdecoy/crds/decoys.cicdecoy.io.yaml` — CRD definitions
- `platform/helm/cicdecoy/templates/nats-init.yaml` — Stream/consumer setup
- `platform/helm/cicdecoy/values.yaml` — Component configuration
