# Architecture Decision Record: Honeytoken Detection Types — Access vs. Usage

**Status:** Accepted  
**Date:** 2026-06-25  
**Authors:** @csquare-d  
**Related Spec:** [honeytoken-architecture.md](honeytoken-architecture.md)  
**Related Roadmap Section:** v0.2.0 (Access Detection), v0.3.0 (Usage Detection)

## 1. Problem Statement

Honeytokens serve two fundamentally different detection purposes that require different architectures:

**Type 1 — Access Detection (inside the decoy):** An attacker reads a file containing fake credentials on a CI/CDecoy honeypot. The decoy itself detects the access and fires an alert. This tells us *the attacker found the bait*.

**Type 2 — Usage Detection (outside the decoy):** An attacker exfiltrates those fake credentials and attempts to use them on a real system — an AWS API, an SSH server, a database. An external system detects the usage and fires an alert. This tells us *the attacker stole and weaponized the bait*.

These are complementary signals at different points in the kill chain:

```
Attacker connects → Finds credential file → Reads it → Exfiltrates → Uses it
                                              ^                        ^
                                          Type 1 fires             Type 2 fires
                                          (T1552.001               (TA0006 Credential
                                           Credential               Access — confirmed
                                           In Files)                 exfiltration)
```

Type 1 is self-contained — CI/CDecoy controls the entire detection surface. Type 2 requires external infrastructure to monitor credential usage on real platforms. The question is: what types of external monitoring should CI/CDecoy support, and when?

## 2. Decision

CI/CDecoy will support both detection types through a phased approach:

- **v0.2.0:** Type 1 (Access Detection) fully self-contained, zero external dependencies
- **v0.3.0:** Type 2 (Usage Detection) integration with external canary token providers and cloud-native monitoring

The `HoneyToken` CRD's `spec.type` enum already defines eight token types. We categorize them by which detection types apply:

| Token Type | Type 1 (Access) | Type 2 (Usage) | Usage Detection Mechanism |
|-----------|:---:|:---:|---------------------------|
| `aws-key` | Yes | Yes | AWS CloudTrail detects API calls with the canary IAM key |
| `ssh-key` | Yes | Yes | Auth log on monitored bastion / `authorized_keys` canary |
| `api-token` | Yes | Yes | API gateway rejects but logs the bearer token |
| `database-cred` | Yes | Yes | Monitored dummy DB listener logs auth attempts |
| `certificate` | Yes | Partial | Certificate Transparency logs detect issuance, not usage |
| `kubeconfig` | Yes | Yes | K8s audit log detects API calls with the canary ServiceAccount |
| `env-var` | Yes | No | `printenv` in a shell is access-only; no external usage path |
| `file` | Yes | Depends | Generic files may contain embedded DNS/HTTP callback tokens |

## 3. Key Engineering Decisions

### 3.1 Type 1: Read-Hook Architecture

**Decision:** Instrument `SessionFilesystem.read_file()` with an access callback that checks paths against a `HoneytokenRegistry`. Fire once per (path, session) pair.

**Alternatives considered:**
- (A) Instrument the `CommandRouter` to detect file-reading commands (`cat`, `head`, `less`, `grep`)
- (B) Wrap the filesystem layer with a monitoring proxy
- (C) Add a callback hook to `read_file()` itself

**Why (C):**

(A) only catches shell commands and misses SFTP `open()`, SCP downloads, and commands we don't recognize (e.g., custom scripts). It also requires maintaining a list of "file-reading" commands that evolves with attacker techniques.

(B) adds complexity for little benefit, the filesystem is already layered (base + COW overlay), adding a third layer creates indirection that makes debugging harder.

(C) catches *every* file read regardless of access vector (shell, SFTP, SCP) with a single instrumentation point. The `read_file()` method is the chokepoint, there is no other path to file content. The callback is optional (no-op when no honeytokens are configured), so zero overhead for decoys without them.

For SFTP and SCP, we additionally instrument `DecoySFTPServer.open()` and `_handle_scp()` to capture the access vector metadata (was it a shell `cat` or an SFTP download?).

### 3.2 Type 2: Provider Integration Model

**Decision:** CI/CDecoy does not build its own external canary token infrastructure. Instead, it integrates with existing providers through a plugin model, starting with self-hosted Canarytokens and cloud-native monitoring (AWS CloudTrail, GCP Audit Logs).

**Alternatives considered:**
- (A) Build a custom DNS/HTTP callback server as a CI/CDecoy service
- (B) Integrate exclusively with Canarytokens.org (hosted)
- (C) Plugin model supporting multiple providers
- (D) Do nothing, only support Type 1

**Why (C):**

(A) would require CI/CDecoy to operate authoritative DNS infrastructure and maintain callback servers. This is significant operational overhead and duplicates mature open-source solutions (Canarytokens, Knary). CI/CDecoy's value is in the deception orchestration, not the callback infrastructure.

(B) is free and easy but creates a dependency on a third-party hosted service. More importantly, Canarytokens.org's AWS account IDs are publicly known and tools like TruffleHog can identify and skip canary credentials by decoding the account ID from the access key. Self-hosted Canarytokens with a custom domain and AWS account eliminate this fingerprinting risk.

(D) leaves significant value on the table. Type 1 tells you an attacker *found* credentials. Type 2 tells you they *used* them. The combination is a high-confidence indicator of active compromise that justifies immediate incident response.

(C) gives operators flexibility: use self-hosted Canarytokens if you have the infrastructure, use cloud-native monitoring if you're on AWS/GCP/Azure, or use no external monitoring if you want a zero-dependency deployment.

### 3.3 External Monitor Integration Point

**Decision:** The `HoneyToken` CRD gains an `externalMonitor` field. The CI/CDecoy CTI pipeline exposes a `/api/webhook/canarytoken` endpoint that external providers POST to when a token fires. The pipeline correlates the external trigger with the original honeytoken placement.

**Alternatives considered:**
- (A) Polling external APIs (CloudTrail, Canarytokens API) from a dedicated service
- (B) Webhook receiver on the CTI pipeline
- (C) Webhook receiver as a standalone microservice

**Why (B):**

(A) requires credentials for every external service and introduces polling latency. CloudTrail polling at 5-minute intervals means 5 additional minutes of detection delay on top of CloudTrail's own delivery latency.

(C) adds another service to deploy and maintain. The CTI pipeline already handles event ingestion and enrichment, adding a webhook receiver is a natural extension of its existing role.

(B) receives alerts in real-time (push, not pull), reuses the existing event processing infrastructure (enrichment, DB storage, republish to dashboard, alert forwarding), and requires no new service deployment. The webhook endpoint validates a shared secret to prevent spoofing.

### 3.4 Token Content: Static vs. Unique-Per-Session

**Decision:** Support both modes. Static tokens are seeded into the base `VirtualFilesystem` at boot (shared across all sessions). Unique tokens are generated per-session with embedded session IDs for attribution.

**Why both:**

Static tokens (same content for every attacker) are simpler to manage and sufficient for most use cases. If the credential appears in the wild, you know it came from this decoy, but not which session.

Unique tokens (session-specific content) enable precise attribution: if `AKIA_SESSION_47aac0c5` shows up in CloudTrail, you know exactly which SSH session exfiltrated it. This matters for incident response when multiple attackers target the same decoy.

The trade-off is memory: unique tokens require COW overlay storage per session. We cap at 100 honeytokens per Decoy CR (already enforced by `maxItems: 100` in the CRD schema). For unique tokens, a small template engine replaces `{{session_id}}`, `{{timestamp}}`, and `{{client_ip}}` placeholders in the token content at session start.

## 4. What This Is Not

- **Not a full Canarytokens replacement.** CI/CDecoy integrates with Canarytokens; it does not reimplement DNS callback servers, document-embedded beacons, or PDF canaries. Use Canarytokens (self-hosted or SaaS) for those.
- **Not real credential management.** The AWS keys, SSH keys, and database credentials in honeytokens are fake or zero-permission. CI/CDecoy never stores or manages real credentials.
- **Not a SOAR.** When a Type 2 trigger fires, CI/CDecoy alerts operators and enriches the event with context. It does not automatically revoke credentials, block IPs, or initiate incident response workflows. That's the SOAR's job (planned integration in v0.4.0+).

## 5. Type 2 Provider Details

### 5.1 Self-Hosted Canarytokens

**How it works:**
1. Operator deploys [canarytokens-docker](https://github.com/thinkst/canarytokens-docker) on their own infrastructure with a custom domain
2. CI/CDecoy's `HoneyToken` CR specifies `externalMonitor.type: canarytokens` with the instance URL
3. On reconciliation, the operator (or a future Hydra service) calls the Canarytokens factory API to create tokens:
   - `POST /api/v1/canarytoken/factory/create` with `kind=dns` or `kind=aws-id`
   - The webhook URL points back to CI/CDecoy's CTI pipeline: `https://cicdecoy.example.com/api/webhook/canarytoken`
4. The generated token content (DNS hostname, AWS key, etc.) is embedded in the honeytoken file content
5. When the token fires externally, Canarytokens POSTs to CI/CDecoy with source IP, timestamp, and token ID
6. The CTI pipeline correlates the trigger with the original placement and emits a `honeytoken.triggered` event with `access_type: external_usage`

**Token types available:** DNS, HTTP, AWS credential, Azure credential, MySQL dump, Word/Excel/PDF documents, QR codes, Windows directory, WireGuard config, and more.

**Advantages of self-hosted:** Custom domain eliminates fingerprinting risk. Your own AWS account for credential tokens means TruffleHog cannot identify them. Full control over data retention.

### 5.2 AWS CloudTrail (Native)

**How it works:**
1. Operator creates a zero-permission IAM user: `{"Effect": "Deny", "Action": "*", "Resource": "*"}`
2. Generates access key pair and plants it in a CI/CDecoy honeytoken file
3. `HoneyToken` CR specifies `externalMonitor.type: aws-cloudtrail` with the IAM user ARN
4. Operator configures an EventBridge rule in their AWS account:
   - Source: `aws.iam` 
   - Detail: matches the canary IAM user ARN
   - Target: CI/CDecoy webhook URL (via API Gateway or Lambda proxy)
5. When the stolen credential is used, CloudTrail logs the `AccessDenied` event, EventBridge fires the rule, and the webhook delivers to CI/CDecoy

**Latency:** 5-15 minutes (CloudTrail delivery). For faster detection, use CloudTrail Lake with EventBridge in the same region (2-5 minutes).

**Cost:** Under $1/month for low-volume canary monitoring.

**Fingerprinting risk:** An attacker can extract the AWS account ID from the access key ID (base32 decoding). Mitigation: use a dedicated AWS account for canary credentials, not your main production account.

### 5.3 GCP Audit Logs (Native)

**How it works:**
1. Create a GCP service account with no IAM bindings
2. Generate a JSON key file and plant it in a honeytoken
3. `HoneyToken` CR specifies `externalMonitor.type: gcp-audit`
4. Cloud Logging log-based alert fires on Admin Activity events from the canary SA
5. Notification channel delivers to CI/CDecoy webhook

**Latency:** Near real-time (seconds to low minutes) for Admin Activity audit logs.

### 5.4 DNS Callback (Generic)

**How it works:**
1. Embed a unique FQDN in honeytoken content: `db-prod.{unique-id}.canary.example.com`
2. The authoritative nameserver for `canary.example.com` is a monitored DNS server (Canarytokens, Knary, or custom)
3. When the attacker resolves the hostname from any network, the DNS query reaches the authoritative NS
4. The NS POSTs to CI/CDecoy's webhook with the query details

**Why DNS is special:** DNS resolution works even when HTTP is blocked. An attacker who exfiltrates a config file containing `DATABASE_HOST=db-prod.abc123.canary.example.com` will trigger a DNS query when they try to connect — even from an air-gapped network that only allows DNS. This makes DNS callbacks the most reliable external detection mechanism.

**Limitation:** Source IP is the recursive resolver (e.g., 8.8.8.8), not the attacker's IP. Attribution is limited.

## 6. Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Attackers fingerprint canary credentials (TruffleHog account ID decode) | Token bypassed silently | Use self-hosted Canarytokens with dedicated AWS account. Rotate tokens periodically. |
| External webhook endpoint exposed to internet | Spoofed trigger events | HMAC-SHA256 signature validation on all webhook payloads. IP allowlist for known providers. |
| CloudTrail/audit log latency (5-15 min) | Attacker completes attack before alert fires | Type 1 (access detection) fires immediately. Type 2 is a complementary signal, not a replacement for in-decoy detection. |
| Token content in env vars visible in `kubectl describe` | Operational leak of canary content | Acceptable: content is intentionally fake. For sensitive deployments, use a Secret instead of inline env var. |
| Alert fatigue from automated scanners triggering Type 1 | Noise obscures real threats | Per-session dedup. Behavioral scoring: scanner sessions get lower alert priority than interactive sessions that progressively explore the filesystem. |
| DNS caching suppresses repeated Type 2 DNS triggers | Missed detections | Providers set TTL=0 or very low. Document this as a known limitation. |

## 7. Dependencies

| Dependency | Component | Required For |
|-----------|-----------|-------------|
| `SessionFilesystem.read_file()` callback | SSH Decoy | Type 1 access detection |
| `HONEYTOKEN_MANIFEST` env var | Operator + Decoys | Token seeding |
| `HONEYTOKEN_EVENTS` NATS stream | CTI Pipeline | Event routing (already provisioned) |
| Self-hosted Canarytokens instance | External | Type 2 via Canarytokens (operator-managed) |
| AWS CloudTrail + EventBridge | External | Type 2 via AWS (operator-managed) |
| Webhook receiver endpoint | CTI Pipeline | Type 2 ingest |

## 8. Implementation Timeline

### v0.2.0 — Access Detection (Type 1)

| Milestone | Description |
|-----------|-------------|
| `HoneytokenRegistry` class | In-memory registry, env var loading, filesystem seeding |
| `read_file()` instrumentation | Access callback, dedup, event emission |
| SFTP/SCP instrumentation | Honeytoken checks on file open/download |
| Operator integration | Parse `spec.filesystem.honeytokens`, pass as env var |
| CTI enrichment | `honeytoken.accessed` → severity critical, T1552.001 |
| Dashboard page | Trigger history, placement map, drill-down |
| E2E test | Seed token, access it, verify event in pipeline |

### v0.3.0 — Usage Detection (Type 2)

| Milestone | Description |
|-----------|-------------|
| `externalMonitor` CRD field | Add to `HoneyToken` CRD spec |
| Webhook receiver | `/api/webhook/canarytoken` on CTI pipeline with HMAC validation |
| Canarytokens integration | Factory API client, token lifecycle management |
| AWS CloudTrail integration | EventBridge rule template, correlation logic |
| Per-session unique tokens | Template engine for `{{session_id}}` placeholders |
| Correlation engine | Match external trigger → original placement → session → attacker |

### v0.4.0+ — Advanced

| Milestone | Description |
|-----------|-------------|
| GCP/Azure native integration | Audit log monitoring for cloud credential tokens |
| Token rotation | Automatic credential rotation on schedule or post-trigger |
| Hydra integration | Adaptive honeytoken placement based on attacker behavior |
| SOAR connectors | Trigger incident response workflows on Type 2 alerts |

## 9. Decision Context (For Future Reference)

This ADR was written when CI/CDecoy had:
- A working SSH decoy with COW filesystem, SFTP, and SCP support
- A working HTTP decoy with 8 login portal themes and discovery endpoints
- A `HoneyToken` CRD stub (reserved, no operator support)
- A `spec.filesystem.honeytokens` field on the Decoy CRD (defined in schema, ignored by operator)
- `HONEYTOKEN_EVENTS` NATS stream (provisioned but unused)
- SIEM forwarder mapping for `honeytoken.trigger` -> `CICD-6001` severity 9
- Engage mapper with `HONEYTOKEN_MAPPING` for token types
- AlertForwarder supporting Slack, Teams, and PagerDuty webhooks
- No external canary token integration
- No file-read monitoring in the filesystem layer

The key insight driving the two-type split: in-decoy access detection (Type 1) and external usage detection (Type 2) are complementary but architecturally independent. Type 1 requires no external infrastructure and can ship in v0.2.0. Type 2 requires integration with external monitoring platforms and benefits from the v0.3.0 timeline to design the provider plugin model properly. Trying to ship both simultaneously would delay the high-value Type 1 detection for an integration layer that most early adopters don't need yet.
