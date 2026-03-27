# Decoy Authoring Guide

This guide covers how to write effective decoy manifests — from simple beacons to high-fidelity adaptive decoys that can sustain prolonged interactive sessions with skilled attackers.

## Design Principles

Before writing a manifest, decide what you want to catch and who you're trying to fool.

**Breadth vs. depth.** Tier 1 beacons are cheap and fast to deploy. Scatter dozens across your network to detect scanning and reconnaissance. Tier 3 adaptive decoys are resource-intensive but can engage a human attacker for hours, generating rich behavioral intelligence. Most deployments use a pyramid: many T1, some T2, few T3.

**Placement matters.** A decoy on the same subnet as your real database servers will attract different attackers than one in the DMZ. Place decoys where attackers would logically look: near high-value targets, on common lateral movement paths, and in network segments that should have no interactive users.

**Believability comes from context.** A decoy named `honeypot-01` running on port 2222 with a default banner is worse than nothing — it tells the attacker you're running deception. A decoy named `build-server-04` on port 22 with a realistic Jenkins installation and seeded CI/CD credentials is a convincing target.

## Manifest Structure

Every decoy manifest has these sections. Only `service`, `fidelity`, `identity`, and `authentication` are required.

```yaml
apiVersion: cicdecoy.io/v1alpha1
kind: Decoy
metadata:
  name: <unique-name>
  namespace: <deployment-namespace>
  labels:
    cicdecoy.io/tier: "<1|2|3>"
    cicdecoy.io/zone: "<network-zone>"
    cicdecoy.io/campaign: "<optional-campaign>"
spec:
  service: { ... }           # What protocol and port
  fidelity: { ... }          # How convincing (tier + config)
  identity: { ... }          # What this machine looks like
  authentication: { ... }    # How logins are handled
  filesystem: { ... }        # Virtual filesystem content (optional)
  networkBehavior: { ... }   # Network presence simulation (optional)
  telemetry: { ... }         # Data capture and alerting (optional)
  resources: { ... }         # CPU/memory (optional, has defaults)
  lifecycle: { ... }         # Rotation and health (optional)
```

## Choosing a Fidelity Tier

### Tier 1 — Beacon

Listens on a port, captures connection metadata, optionally grabs banners. No interactive capability. Use for network trip wires.

Resource cost: ~32 MB RAM, ~50m CPU. You can run hundreds.

Best for: detecting network scans, identifying which subnets are being probed, early warning.

```yaml
fidelity:
  tier: 1
```

No additional configuration needed. The decoy just listens and logs.

### Tier 2 — Scripted

Handles common commands with pre-defined responses. Falls back to "command not found" for anything unexpected. Use for catching automated tools and less sophisticated attackers.

Resource cost: ~128 MB RAM, ~100m CPU.

Best for: credential harvesting, detecting automated exploitation tools, catching scripts.

```yaml
fidelity:
  tier: 2
  scripted:
    responseSet: "openssh-8.9"      # Pre-built response library
    customResponses:                 # Your overrides
      - match: "uname -a"
        response: "Linux build-04 5.15.0-91-generic ..."
```

### Tier 3 — Adaptive

LLM-backed responses with full session state. Maintains a coherent virtual environment across arbitrary commands. Use for engaging skilled human attackers and red teams.

Resource cost: ~256 MB RAM per decoy, plus shared inference service.

Best for: threat actor behavioral analysis, red team detection, generating rich CTI, engaging advanced persistent threats.

```yaml
fidelity:
  tier: 3
  adaptive:
    profileRef: "dev-workstation"    # DecoyProfile to emulate
    inferenceConfig:
      maxSessionTokens: 8192
      temperature: 0.3
    fastPath:
      enabled: true                  # Handle simple commands without LLM
      commands:
        - { match: "^ls", source: filesystem }
        - { match: "^pwd$", source: state }
    guardrails:
      preventRealCommands: true
      filterPatterns:                # REQUIRED for Tier 3
        - "(?i)honeypot"
        - "(?i)I('m| am) an AI"
```

## Honeytokens

Honeytokens are data-layer deception: fake credentials, keys, and documents seeded into the decoy's filesystem. When an attacker accesses them, you get a high-confidence alert.

```yaml
apiVersion: cicdecoy.io/v1alpha1
kind: HoneyToken
metadata:
  name: aws-canary-01
spec:
  type: aws-credential
  content:
    template: aws-credentials
    values:
      accessKeyId: "AKIAIOSFODNN7CANARY1"
      secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bCanaryKey01"
  tracking:
    callbackURL: "https://cti.internal/honeytoken/trigger"
  alertOn: [apiCall, networkEgress]
```

Place them in the decoy's filesystem overlay:

```yaml
filesystem:
  overlays:
    - type: honeytoken
      tokenRefs: ["aws-canary-01"]
      placements:
        - tokenRef: "aws-canary-01"
          path: /home/admin/.aws/credentials
```

## Fleet Deployment

For deploying many decoys at once with randomized identities:

```yaml
apiVersion: cicdecoy.io/v1alpha1
kind: DecoyFleet
metadata:
  name: internal-network
spec:
  replicas: 20
  templateRef: "ssh-server"
  variance:
    hostnames:
      pattern: "srv-{{ .zone }}-{{ .seq | printf \"%02d\" }}"
      zones: ["dev", "staging", "prod"]
    profiles:
      pool: ["dev-workstation", "db-server", "ci-runner"]
    fidelity:
      distribution:
        tier1: 0.6
        tier2: 0.3
        tier3: 0.1
  rotation:
    enabled: true
    interval: 336h
    strategy: rolling
```

---

# Profile Authoring Guide

Profiles define the "soul" of a Tier 3 decoy — the system prompt context that makes the LLM behave like a specific machine with a specific purpose and history.

## What Makes a Good Profile

The best profiles tell a story. They don't just list installed packages — they explain why those packages are there, who uses the machine, and what its role is. The LLM uses this narrative to generate contextually appropriate responses to unexpected commands.

**Specificity matters.** "A Linux server" produces generic responses. "A senior SRE's bastion host in the DMZ running Ansible playbooks against production and used as a jump box to database servers" produces responses with realistic bash history, realistic config files, and realistic error messages when the attacker tries to SSH to those database servers.

**Consistency is non-negotiable.** If the profile says Python 3.10 is installed, `python3 --version` must return 3.10, `which python3` must return `/usr/bin/python3`, and `pip list` must return packages consistent with the machine's role. The narrative section is the LLM's guide for maintaining this consistency.

## Profile Structure

```yaml
apiVersion: cicdecoy.io/v1alpha1
kind: DecoyProfile
metadata:
  name: <profile-name>
spec:
  description: "One-sentence description"

  system:
    os: "Ubuntu 22.04.3 LTS"
    kernel: "5.15.0-91-generic"
    hostname: "{{ .decoy.identity.hostname }}"    # Templated
    uptime: "67 days, 3:14"
    timezone: "America/New_York"

  users:
    - name: jchen
      fullName: "Jamie Chen"
      groups: ["sudo", "docker", "developers"]
      shell: /bin/bash
      lastLogin: "2024-01-15 09:32:01"

  software:
    packages:
      - { name: "openssh-server", version: "8.9p1" }
      # ... list everything an attacker might check
    services:
      - { name: "sshd", status: "active", port: 22 }

  environment:
    variables:
      NODE_ENV: "production"
    crontab:
      - "0 3 * * * /home/deploy/scripts/backup.sh"

  narrative: |
    This is the most important field. Write a detailed paragraph
    describing who uses this machine, what it does, what's installed
    and why, what other systems it connects to, and any quirks
    or history that would make it feel lived-in.
```

## The Narrative Field

This is injected directly into the LLM's system prompt. Write it as if you're briefing a method actor about their character. Include the machine's purpose and role in the organization, who uses it (name, title, habits), what software is installed and why, what other machines it talks to (and their fake hostnames), any recent events ("Jordan has been meaning to patch but the product launch delayed it"), and the general vibe (busy developer box vs. quiet jump host).

## Testing Profiles

Use the CLI to interactively test a profile before deploying:

```bash
cicdecoy profile test dev-workstation
```

This spawns a temporary Tier 3 decoy with the profile and drops you into an interactive session where you can verify the personality feels right.

---

# CTI Integration Guide

CI/CDecoy generates structured threat intelligence from every decoy interaction. This guide covers how to connect that intelligence to your existing security toolstack.

## Output Formats

The CTI pipeline produces output in several formats, all from the same enriched event data.

**STIX 2.1 Bundles.** Structured threat intelligence objects: Indicators, Attack Patterns, Observed Data, Relationships, Tools, and Sightings. Published via TAXII 2.1 server or as JSON files.

**IOC Feeds.** Simple indicator lists (IPs, domains, hashes) with confidence scores and MITRE technique tags. Available as JSON, CSV, or STIX patterns.

**SIEM Events.** Enriched events pushed directly to Splunk (HEC), Elastic (API), or Microsoft Sentinel (API).

**Intel Reports.** Human-readable summaries in Markdown, HTML, or PDF covering daily, weekly, or monthly activity.

## TAXII Server

The built-in TAXII 2.1 server allows any STIX/TAXII-compatible Threat Intelligence Platform to pull CI/CDecoy intelligence.

```bash
# Enable in Helm values
cti:
  output:
    taxii:
      enabled: true
      port: 9443
```

Discovery endpoint: `https://<cluster-ip>:9443/taxii2/`

Collections available: `cicdecoy-indicators` (IOCs), `cicdecoy-observations` (enriched events), `cicdecoy-attack-patterns` (MITRE technique sightings).

## Splunk Integration

```yaml
cti:
  output:
    siem:
      enabled: true
      type: splunk
      endpoint: "https://splunk-hec.corp.internal:8088"
      indexName: "cicdecoy"
      credentialSecret: "splunk-hec-token"   # k8s Secret with HEC token
```

Events arrive in Splunk with sourcetype `cicdecoy:event` and are pre-enriched with MITRE technique IDs, GeoIP data, and severity classifications. Build Splunk dashboards using the `mitre_techniques{}` JSON field for ATT&CK heatmaps.

## Elastic Integration

```yaml
cti:
  output:
    siem:
      enabled: true
      type: elastic
      endpoint: "https://elastic.corp.internal:9200"
      indexName: "cicdecoy-events"
      credentialSecret: "elastic-api-key"
```

Events are indexed using ECS (Elastic Common Schema) field mappings. The `threat.technique.id` field contains MITRE ATT&CK technique IDs for use with Elastic's built-in ATT&CK Navigator.

## Custom Webhooks

For Slack, Teams, PagerDuty, or custom integrations, configure alerting in individual decoy manifests:

```yaml
telemetry:
  alerting:
    channels:
      - type: webhook
        url: "https://hooks.slack.com/services/..."
      - type: webhook
        url: "https://your-soar-platform.com/api/ingest"
        headers:
          Authorization: "Bearer ${SOAR_TOKEN}"
```

---

# Threat Model

CI/CDecoy is a security tool that deliberately exposes services to attackers. This document covers the security considerations of running the platform itself.

## Attack Surface

**Decoy containers are intentionally exposed.** They accept connections from untrusted networks. The security boundary is the container: an attacker interacts with the decoy's virtual environment, not the real OS.

**The LLM is an indirect attack vector.** An attacker's commands become part of the LLM prompt. Prompt injection could theoretically cause the LLM to break character, leak infrastructure details, or produce unexpected output. Guardrails and output filtering mitigate this.

## Mitigations

### Container Isolation

Decoy pods run with restricted security contexts: non-root user (UID 1000), read-only root filesystem where possible, no privilege escalation (`allowPrivilegeEscalation: false`), dropped capabilities, and no access to the host network or PID namespace. Commands entered by attackers are never executed — they're parsed by the decoy application and responded to with simulated output.

### Network Isolation

NetworkPolicies enforce strict segmentation. Decoy pods can reach NATS (for event publishing) and nothing else — not the Kubernetes API, not other decoys, not the inference service directly (inference requests go through the command router). The inference service and CTI pipeline have their own isolated network policies.

### LLM Guardrails

The response filter applies multi-stage filtering to every LLM response. Regex patterns catch character breaks (the model saying "I'm an AI"), infrastructure leaks (references to cicdecoy paths), and formatting artifacts (markdown that wouldn't appear in a real terminal). If a response fails filtering, it's replaced with an empty string or a generic error rather than being passed to the attacker.

### Credential Management

Fake credentials in decoy manifests are not real credentials. However, they should be treated with care — if an attacker discovers the same fake password is used across all decoys, they'll identify the deception. Use unique credentials per decoy and rotate them with the identity rotation feature. Honeytoken tracking credentials (AWS keys, kubeconfig tokens) are intentionally fake but formatted to be realistic. They should be unique per token and registered with your canary provider for tracking.

### Operational Security

The platform itself is a target. An attacker who compromises the CI/CDecoy operator or dashboard gains visibility into your entire deception posture. Protect these components with the same rigor as any security tool: restrict dashboard access by IP or VPN, use RBAC to limit who can modify decoy manifests, audit all operator actions via the platform audit log, and encrypt NATS traffic with TLS.

## Known Limitations

**LLM hallucination.** Despite guardrails, an LLM may occasionally produce inconsistent responses — a file that existed in one command might not exist in the next. The fast-path system mitigates this for common commands, but novel interactions always carry some hallucination risk.

**Timing side channels.** Tier 3 responses have inherent latency from LLM inference. Sophisticated attackers might notice that simple commands (which hit the fast path) respond in ~20ms while unusual commands (which hit the LLM) take 200ms–2s. The timing injection system adds realistic jitter but cannot perfectly mask the bimodal distribution.

**Resource exhaustion.** An attacker who opens many concurrent sessions to a Tier 3 decoy can consume significant inference resources. Rate limiting on the inference gateway and per-decoy session limits mitigate this, but a determined attacker could still degrade inference performance for other decoys.

## Reporting Vulnerabilities

If you discover a security vulnerability in CI/CDecoy, please report it responsibly. Do not open a public GitHub issue. Email security@cicdecoy.io with a description and we'll work with you on a fix.
