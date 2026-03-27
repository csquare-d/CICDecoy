# CI/CDecoy — Production Deployment Architecture

## Network Zones

A mature CI/CDecoy deployment has four network zones with strict
boundary controls between them.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        ENTERPRISE NETWORK                               │
│                                                                         │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │  TARGET ZONES (where decoys appear to live)                      │   │
│  │                                                                  │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌──────────────┐            │   │
│  │  │ DMZ         │  │ Production  │  │ Dev/Staging   │            │   │
│  │  │ 10.100.0/24 │  │ 10.0.1-5/24│  │ 10.0.8-10/24 │            │   │
│  │  │             │  │             │  │               │            │   │
│  │  │ ◆ SSH decoy │  │ ◆ DB decoy │  │ ◆ SSH decoy   │            │   │
│  │  │ ◆ HTTP      │  │ ◆ SMB      │  │ ◆ HTTP        │            │   │
│  │  │ ◆ FTP       │  │ ◆ SSH      │  │               │            │   │
│  │  └──────┬──────┘  └──────┬─────┘  └───────┬──────┘            │   │
│  │         │                │                 │                    │   │
│  │         └────────────────┼─────────────────┘                    │   │
│  │                          │                                      │   │
│  │              DECOY DATA PLANE (telemetry only)                  │   │
│  │              VXLAN / WireGuard / VLAN trunk                     │   │
│  │                          │                                      │   │
│  └──────────────────────────┼──────────────────────────────────────┘   │
│                             │                                          │
│  ┌──────────────────────────┼──────────────────────────────────────┐   │
│  │  MANAGEMENT ZONE         │        (isolated network segment)    │   │
│  │  10.200.0.0/24           │                                      │   │
│  │                          ▼                                      │   │
│  │  ┌──────────────────────────────────────────────────────────┐   │   │
│  │  │                 k3s Control Plane                         │   │   │
│  │  │                                                          │   │   │
│  │  │  ┌──────────┐ ┌──────────┐ ┌────────────┐ ┌──────────┐  │   │   │
│  │  │  │ Operator │ │ NATS     │ │ TimescaleDB│ │Inference │  │   │   │
│  │  │  │          │ │ JetStream│ │            │ │ Gateway  │  │   │   │
│  │  │  └──────────┘ └──────────┘ └────────────┘ └──────────┘  │   │   │
│  │  │                                                          │   │   │
│  │  │  ┌──────────────────────┐ ┌──────────────────────────┐   │   │   │
│  │  │  │  CTI Pipeline        │ │  Dashboard               │   │   │   │
│  │  │  │  Collector           │ │  (auth required)         │   │   │   │
│  │  │  │  Enrichment          │ │                          │   │   │   │
│  │  │  │  STIX/TAXII Output   │ │                          │   │   │   │
│  │  │  └──────────────────────┘ └──────────────────────────┘   │   │   │
│  │  └──────────────────────────────────────────────────────────┘   │   │
│  │                          │                                      │   │
│  │              MANAGEMENT ACCESS                                  │   │
│  │              VPN / jump host / RBAC                              │   │
│  │                          │                                      │   │
│  └──────────────────────────┼──────────────────────────────────────┘   │
│                             │                                          │
│  ┌──────────────────────────┼──────────────────────────────────────┐   │
│  │  INTEGRATION ZONE        │                                      │   │
│  │                          ▼                                      │   │
│  │  ┌──────────────────────────────────────────────────────────┐   │   │
│  │  │  Outbound CTI Only                                       │   │   │
│  │  │                                                          │   │   │
│  │  │  → SIEM (Splunk/Elastic/Sentinel)                        │   │   │
│  │  │  → SOAR platform                                         │   │   │
│  │  │  → TAXII feed consumers                                  │   │   │
│  │  │  → Slack/Teams alerting                                  │   │   │
│  │  │  → Threat intel sharing (ISAC feeds)                     │   │   │
│  │  └──────────────────────────────────────────────────────────┘   │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

## Firewall Rules (enforced at network boundary, not just k8s NetworkPolicy)

### Decoy → Management Zone
- ALLOW: NATS (TCP 4222) — telemetry export only
- ALLOW: Inference Gateway (TCP 8000) — Tier 3 LLM requests only
- DENY: Everything else

### Decoy → Target Zone
- DENY: All outbound to real hosts
  (prevents pivot if decoy is somehow compromised)
- Exception: configured beacon traffic to fake DNS/NTP
  (simulated, doesn't actually reach real services)

### Decoy → Internet
- DENY: All
  (decoys must never make real outbound connections)

### Management Zone → Target Zone
- DENY: All (management plane never touches production)

### Management Zone → Integration Zone
- ALLOW: SIEM ingest endpoints (specific IPs/ports)
- ALLOW: TAXII publish (TCP 443 to specific hosts)
- ALLOW: Webhook destinations (Slack/Teams URLs)
- DENY: Everything else

### Operator Access → Management Zone
- ALLOW: VPN or jump host only
- REQUIRE: MFA + RBAC
- AUDIT: All kubectl and dashboard access


## Distributed Agent Architecture

For Model 2 (distributed nodes), each target network segment gets
a lightweight k3s agent node.

```
Target Subnet: 10.0.3.0/24 (Production Database Network)
├── 10.0.3.10  db-prod-01        (real PostgreSQL server)
├── 10.0.3.11  db-prod-02        (real PostgreSQL replica)
├── 10.0.3.12  db-backup-01      (real backup server)
├── 10.0.3.50  db-staging-03     ◆ DECOY (k3s agent node)
│   ├── MySQL decoy (port 3306)
│   ├── SSH decoy (port 22)
│   └── SMB share with honeytoken DB dumps
└── 10.0.3.51  db-reporting-01   ◆ DECOY (k3s agent node)
    ├── PostgreSQL decoy (port 5432)
    └── SSH decoy (port 22)

Agent Node Spec:
  Hardware: Raspberry Pi 4 (4GB) / Intel NUC / VM with 4GB RAM
  OS: Ubuntu 22.04 minimal + k3s agent
  Network: Native interface on target subnet (real IP, real ARP)
  Storage: 32GB (local response DBs, no persistent state)
  Backhaul: WireGuard tunnel to management zone for NATS + k8s API
```

### Agent Node Hardening

Each distributed agent is a potential physical capture target.
An attacker who finds the device could extract its configuration,
discover the management plane, or tamper with it.

Mitigations:
- Full disk encryption (LUKS) with TPM-sealed keys where hardware supports it
- No SSH server on the agent itself (k3s API only, via WireGuard)
- Read-only root filesystem (changes don't survive reboot)
- Tamper detection: agent reports heartbeat every 60s; missed heartbeats
  trigger alert and automatic credential rotation
- No management credentials stored on the agent — k3s join token only,
  rotated monthly
- Agent identity is ephemeral: if compromised, revoke the join token,
  re-image, rejoin. No data loss because all state is in the central DB.


## DNS Integration

Decoys need to be discoverable through normal DNS resolution to be
convincing. There are three approaches:

### Option A: Real DNS entries (highest fidelity)
Add A records for decoys in your internal DNS:
  db-staging-03.corp.internal  → 10.0.3.50
  db-reporting-01.corp.internal → 10.0.3.51

Pro: Indistinguishable from real hosts.
Con: Requires coordination with the DNS team. Records must be
     updated when decoys rotate.

### Option B: Decoy DNS server
Run a decoy DNS resolver that responds to queries for decoy
hostnames. Configure DHCP to include this resolver alongside
the real one. Attackers querying DNS see decoy entries mixed
with real entries.

Pro: Self-contained, no external team coordination.
Con: Only works if DHCP pushes the decoy resolver.

### Option C: mDNS/LLMNR/NBNS poisoning (aggressive)
Decoys respond to multicast DNS and NetBIOS name queries for
their configured hostnames. On Windows-heavy networks, this
makes decoys discoverable via standard name resolution without
any DNS infrastructure changes.

Pro: Zero infrastructure changes required.
Con: Only works on local broadcast domains. May conflict with
     existing LLMNR/NBNS if not carefully configured.

Recommendation: Start with Option A for high-value Tier 3 decoys
(they need to be specifically discoverable). Use Option C for
Tier 1 beacons on Windows segments (passive discovery). Option B
for environments where you can't modify the authoritative DNS.


## Active Directory Integration

For Windows-heavy environments, decoys need to appear as domain
members to be convincing.

### Decoy Computer Accounts
Create computer accounts in AD for each decoy:
  CN=DB-STAGING-03,OU=Servers,OU=Deception,DC=corp,DC=internal

Place them in a dedicated OU (so they don't interfere with real
GPOs) but with names that match the naming convention of real
servers in adjacent OUs.

### Decoy User Accounts
Create user accounts that appear in LDAP enumeration:
  CN=svc-db-backup,OU=ServiceAccounts,OU=Deception,DC=corp,DC=internal

These accounts have weak or guessable passwords. When an attacker
authenticates with them, the decoy captures the credential and the
CTI pipeline fires an alert.

### Kerberoasting Honeytokens
Register SPNs on decoy service accounts:
  MSSQLSvc/db-staging-03.corp.internal:1433

Attackers performing Kerberoasting will request TGS tickets for
these SPNs. The decoy doesn't need to actually run SQL Server —
it just needs the SPN registered. Monitor for TGS-REQ events in
AD logs targeting these SPNs.

### Group Policy
Decoy computer objects should be exempt from most GPOs to avoid
interfering with decoy operation. Create a "Deception Assets" OU
with GPO inheritance blocked, and a minimal GPO that only sets
the machine's timezone and display name for consistency.


## Scaling

### Small (1-50 decoys)
Single k3s node, all-in-one. Management plane and decoys co-located.
Suitable for a single office network or small cloud environment.

  Resources: 8 CPU, 16GB RAM, 100GB storage
  Decoy mix: 30× Tier 1, 15× Tier 2, 5× Tier 3
  Inference: Ollama with 8B model on CPU (slow but functional)

### Medium (50-500 decoys)
3-node k3s cluster for the management plane. 5-20 distributed
agent nodes in target segments. Dedicated GPU node for inference
(or external LLM endpoint).

  Control plane: 3× (4 CPU, 8GB RAM)
  Agent nodes: 10-20× (2 CPU, 4GB RAM each)
  Inference: 1× GPU node (NVIDIA T4/A10) or vLLM cluster
  Storage: 500GB TimescaleDB, 50GB NATS

### Large (500+ decoys)
Multi-cluster. Regional k3s clusters with federated management.
Each region has its own NATS cluster, with cross-cluster
replication feeding a central CTI pipeline.

  Regional clusters: 3-5 regions, 3 nodes each
  Agent nodes: 50-100+ across all segments
  Inference: Dedicated vLLM cluster with multiple GPUs
  Storage: TimescaleDB with read replicas, NATS supercluster
  CTI: Dedicated enrichment cluster for high-throughput processing


## Operational Procedures

### Deployment Workflow (GitOps)

1. Operator creates branch: `feature/add-dmz-decoys`
2. Writes decoy manifests in `decoys/deployments/production/dmz/`
3. Opens PR — CI runs:
   - Manifest validation (schema, cross-refs, coherence)
   - Fidelity tests against staging cluster
   - Engage annotation verification
4. Security team reviews PR (deception strategy review)
5. Merge to main → ArgoCD syncs to production cluster
6. Operator verifies: `cicdecoy status decoys --zone dmz`

### Rotation Procedure

Identity rotation prevents attackers from fingerprinting decoys
over time (same hostname, same SSH key = suspicious).

Automatic rotation (configured per decoy):
  - Interval: 7-30 days depending on exposure
  - Strategy: gradual (spin up new, drain old, swap DNS)
  - What rotates: hostname, SSH host key, user passwords,
    filesystem timestamps, bash history, process PIDs
  - What persists: IP address (unless fleet rotation),
    service type, fidelity tier, profile personality

Manual rotation (triggered by compromise detection):
  - If an attacker explicitly identifies a decoy as fake,
    rotate immediately with full identity change
  - Rotate all decoys the attacker interacted with
  - Review session transcripts to understand what gave it away
  - Update fidelity tests to catch the fingerprint they used

### Incident Response Integration

When a decoy fires a critical alert:

1. IMMEDIATE: Alert to SOC via Slack/SIEM/SOAR
2. 0-5 MIN: SOC analyst reviews live session in dashboard
3. 5-15 MIN: Determine if attacker is on a real host that
   pivoted to the decoy, or if they entered via the decoy
4. 15-30 MIN: If real compromise detected, initiate IR
   workflow using CTI from the decoy session (IOCs, TTPs,
   tool identification, lateral movement targets)
5. ONGOING: Keep the decoy session alive as long as possible
   to collect intelligence while IR proceeds on real hosts

The key insight: decoy alerts are HIGH CONFIDENCE. Unlike IDS
alerts that may be false positives, any interactive session on
a decoy is definitively malicious (no legitimate user should
ever access a decoy). This means decoy alerts can trigger
automated containment actions that would be too risky for
probabilistic detections.

### Monitoring and Health

Platform health monitoring (separate from decoy monitoring):

  - NATS: stream depth, consumer lag, publish rate
  - TimescaleDB: disk usage, query latency, replication lag
  - Inference: request latency p50/p95/p99, cache hit rate
  - Operator: reconciliation errors, CRD validation failures
  - Agent nodes: heartbeat, disk, memory, WireGuard tunnel status

Decoy health monitoring:
  - Port responsiveness (is the service actually listening?)
  - Banner correctness (does nmap see what we expect?)
  - Fingerprint validation (periodic self-scan)
  - Session capacity (are we at max concurrent sessions?)

Alert on: missed agent heartbeats, NATS consumer lag > 1000,
inference p95 > 5s, decoy fingerprint mismatch, any decoy
going offline unexpectedly.


## Compliance Considerations

### Legal
- Deception is legal in your own network in most jurisdictions
- Honeypots on the internet may have different legal status
- Captured credentials are evidence — handle chain of custody
- Session recordings may contain PII — apply data retention policies
- Consult legal counsel before deploying in regulated environments

### Audit
- All decoy deployments tracked in Git (GitOps audit trail)
- All operator actions logged via platform audit subject
- NATS streams configured with deny-delete, deny-purge
- TimescaleDB retention policies enforced automatically
- Dashboard access logged with user identity

### Data Handling
- Attacker passwords captured in cleartext (necessary for intel)
  → Encrypt at rest in TimescaleDB
  → Restrict access to CTI pipeline service account
  → Purge per retention policy (default: 90 days)
- Session transcripts may contain sensitive data the attacker accessed
  → Same encryption and retention as passwords
  → Flag sessions that accessed honeytokens for legal hold
