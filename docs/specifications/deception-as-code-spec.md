# Deception as Code: Specification v1.0

**Reference Implementation:** CI/CDecoy  
**Status:** Draft  
**Date:** April 2026

---

## Abstract

Deception as Code (DaC) is the practice of defining, deploying, and operating cyber deception infrastructure through declarative configurations managed in version control, deployed through CI/CD pipelines, and measured by the threat intelligence they produce, not by the alerts they generate.

The name is intentional. It follows the same pattern as Infrastructure as Code, Detection as Code, and Policy as Code, not because it is derivative, but because it makes a specific claim: deception infrastructure should be managed with the same engineering rigor, automation, and auditability that modern organizations apply to every other category of infrastructure. The fact that the deception community has not broadly adopted these practices says more about the insularity of the deception tooling ecosystem than it does about any fundamental incompatibility between deception operations and modern deployment methodology.

DaC makes a harder claim than Infrastructure as Code does. IaC is primarily about deployment methodology. DaC is about what the deployment is *for*. The claim is this: the telemetry and analysis pipeline is the product, not the decoy itself. A decoy with no telemetry is furniture. A decoy that generates an alert is a tripwire. A decoy that produces structured intelligence about what adversaries are trying to do, what tools they are using, and what it means for your real environment. That is an adversary engagement platform. DaC is about building the third thing.

---

## 1. Motivation

Sun Tzu wrote about deception. The Allies built entire phantom armies out of inflatable tanks and fake radio traffic to deceive the Wehrmacht before D-Day. The fundamental idea, that you can gain advantage by controlling what your adversary believes about your environment, is not new and it is not controversial. What is surprising is how poorly the cybersecurity industry has operationalized it despite decades of availability.

Honeypots have existed since the early 1990s. Lance Spitzner was writing about honeynets in the late 1990s. The concept has been around for over thirty years, and yet deception remains a niche capability that most organizations either ignore entirely or deploy in the most minimal possible way.

Deception is one of the few defensive techniques with a near-zero false positive rate. Any interaction with a decoy is definitionally suspicious. That is too valuable a property to lock behind enterprise sales cycles and six-figure appliance licenses.

### 1.1 The Deployment Gap

Every other discipline in modern security operations has adopted declarative, pipeline-driven practices. Detection engineering teams manage their SIEM rules in Git, validate them in CI, and deploy them through automated pipelines. Infrastructure security teams define their cloud security posture in Terraform and enforce it through policy-as-code. Vulnerability management programs automate scanning and remediation tracking through the same CI/CD platforms that ship application code.

But deception, a discipline that involves deploying and managing distributed infrastructure across network segments, still largely operates through manual deployment, point-and-click commercial platforms, or ad hoc scripts that live on a single engineer's laptop.

There is no technical reason that a decoy manifest cannot live in a Git repository alongside your Terraform modules and Helm charts. There is no reason that a commit to that repository cannot trigger a pipeline that validates the decoy configuration, builds the container image, runs a fidelity check against a fingerprinting suite, and deploys it to a cluster through ArgoCD or Flux. There is no reason that decoy rotation cannot be a scheduled pipeline job rather than a calendar reminder that someone eventually ignores. The entire deployment lifecycle of a deception program maps cleanly onto patterns that platform engineering teams have been refining for over a decade.

### 1.2 The Intelligence Gap

Most deception products focus on deployment: stand up a honeypot, get an alert when someone touches it. That is table stakes. The real value is in the intelligence:

- **What** did the adversary interact with?
- **How** did they interact with it? What TTPs are they using?
- **Why?** What does their behavior tell us about their objectives, tooling, and sophistication?
- **So what?** What should we do differently in our real environment based on what we learned?

The gap between "an alert fired" and "here is a structured adversary profile with ATT&CK mappings, tool signatures, and a strategic assessment" is where most deception programs fail. DaC treats that gap as the primary design problem.

### 1.3 Enabling Technologies

Two developments make DaC practical now in ways it was not five years ago:

**Large language models.** An LLM-backed decoy can maintain coherent interactive sessions, respond to arbitrary commands, and sustain engagement with human operators who would immediately fingerprint a scripted response database. This changes the fidelity ceiling from "fool an automated scanner" to "fool a red teamer."

**GitOps maturity.** The tooling for declarative infrastructure management is battle-tested. ArgoCD, Flux, Terraform, Helm, Pulumi. The practices of Infrastructure as Code and CI/CD have been standard in software engineering and platform operations for years. Security engineering teams already manage detection-as-code repositories, deploy infrastructure through Terraform pipelines, and operate Kubernetes clusters through GitOps workflows. The tooling exists, the patterns are well understood, and the operational muscle memory is already there.

The missing piece was treating the intelligence pipeline as the primary concern rather than an afterthought. That is the DaC contribution: the decoy is the sensor, the pipeline is the instrument, and the intelligence is the product.

---

## 2. Five Principles

DaC is not a product. It is a reference architecture built around five operational commitments. Each one can be adopted incrementally, but they are most valuable together.

### 2.1 Decoys Are Declarative

A decoy is defined in a manifest. YAML, HCL, whatever your team already uses for infrastructure. The manifest describes what the decoy emulates, where it is placed, what telemetry it captures, and what collection requirement it is designed to satisfy.

If you cannot articulate the intelligence question, you should not deploy the decoy. Every deception artifact, whether it is a honeypot service, a honeytoken, a breadcrumb, or a lure, needs a hypothesis tied to a specific MITRE Engage activity and an expected adversary behavior it is designed to elicit or observe.

This means your deception posture is version-controlled, peer-reviewed, and auditable. You can diff your deception environment the same way you diff your production infrastructure. You can roll back a change that degraded fidelity, or promote a decoy from staging to production after validating that it does not fingerprint easily. Declarative also means reproducible. Tear down a decoy cluster, redeploy it in a different network segment, and get the same configuration with the same telemetry contracts. No manual setup. No snowflake honeypots that nobody remembers how to rebuild.

```yaml
# Example decoy manifest
apiVersion: cicdecoy.io/v1
kind: Decoy
metadata:
  name: prod-ssh-lure-01
  namespace: deception
  labels:
    tier: "2"
    protocol: ssh
    segment: dmz
spec:
  emulates: ubuntu-22.04-openssh
  fidelity: scripted
  engage:
    activity: EAC0001           # Lure
    hypothesis: >
      Adversaries targeting the DMZ will attempt SSH credential
      access. Capture credential patterns and post-auth behavior.
    collection_requirements:
      - credential_patterns
      - post_auth_commands
      - tool_signatures
  telemetry:
    capture_session: true
    capture_commands: true
    timing_entropy: true
  rotation:
    schedule: "0 0 * * 0"      # Weekly
    strategy: identity_refresh
```

The `hypothesis` field is not optional. It is the discipline that prevents deception posture from becoming a collection of honeypots that nobody remembers the purpose of. Every decoy should be answering a specific intelligence question or testing a specific adversary hypothesis. When you review your deception posture quarterly, decoys that are not producing answers to the questions they were deployed to answer should be retired or redeployed.

### 2.2 Deployment Is Continuous

Deception infrastructure follows the same CI/CD patterns as application code. A commit to the decoy repository triggers a pipeline that validates the configuration, builds the container images, runs fidelity checks, and deploys them to the cluster. GitOps tooling like Flux or ArgoCD manages the desired state.

This matters for two reasons. First, deception assets should rotate. A honeypot that has been sitting at the same IP with the same SSH banner for six months is burned. Adversaries fingerprint static deception environments and share that knowledge through their own operational networks. Continuous deployment makes rotation a pipeline stage, not a manual task that gets deprioritized until someone realizes their decoys have been fingerprinted.

Second, deception posture should evolve in response to the intelligence it produces. When your analysis reveals that adversaries are targeting SMB shares and ignoring SSH, your next commit should shift coverage accordingly. The feedback loop from intelligence back to deployment is the operational advantage of treating deception as code.

**Deployment lifecycle:**

```
Git commit
  → CI pipeline validates manifest schema
  → Builds container image
  → Runs fidelity tests against fingerprinting suite
  → Pushes to registry
  → GitOps controller (ArgoCD/Flux) reconciles desired state
  → Operator deploys decoy pods to k3s cluster
  → Telemetry pipeline confirms event flow
  → Scheduled rotation triggers identity refresh
```

### 2.3 Telemetry Is the Primary Output

The telemetry pipeline is the core of DaC, not the decoys themselves. Decoys are sensors. The pipeline is the instrument. The intelligence is the product.

Events are not connection logs with timestamps. They are structured records that capture who interacted with the decoy, what they did, what tools they used, what phase of the kill chain they are in, and what it tells us about their sophistication and objectives. Every event includes the context an analyst would need to make it actionable without going back to raw logs.

Telemetry produces sessions, not alerts. Events are grouped into `InteractionSession` objects with behavioral fingerprints. The analyzer consumes these in batch to produce profiles and assessments, not real-time pings. The reasoning: intelligence production needs context. A single SSH auth attempt is noise. A session that starts with SSH brute force, pivots to command execution, clears bash history, and drops a tool. That is a story about an adversary.

### 2.4 Analysis Over Alerting

An alert says "something happened." Analysis says "here is who did it, what they were trying to accomplish, how sophisticated they are, what tools they used, and what you should do about it."

DaC analyzers consume telemetry sessions and produce structured CTI outputs:

- **TTP mapping:** Every observed action maps to MITRE ATT&CK technique IDs. This is a static, maintainable mapping, not an ML model. You should know exactly why each mapping exists.
- **Adversary profiling:** Sophistication scoring, tool identification, operational security indicators, and inferred objectives derived from behavioral patterns across sessions.
- **Campaign correlation:** Linking sessions across decoys and time. The same credential set tried across three honeypots in the same subnet is not three alerts. It is one campaign.
- **Strategic assessment:** The top-level intelligence product. It answers four questions: what hypotheses were confirmed or refuted, what detection gaps were discovered, what should we hunt for in production, and how should we adjust the deception posture.

The `StrategicAssessment` is the deliverable your team acts on. Everything else exists to produce it.

### 2.5 Deception Posture Is Measured

Deception operations map to MITRE Engage activities, approaches, and goals. Every decoy deployment is an Engage operation with measurable outcomes. Campaign-level reporting should answer: "Our deception posture tested N hypotheses this quarter, confirmed M adversary behaviors, identified K detection gaps, and informed J changes to production defenses."

Measurement includes:

- **Coverage:** What percentage of your network segments, identity stores, and cloud environments have deception assets deployed?
- **Fidelity:** Are decoys passing fingerprint validation? What percentage of interactions exceed the discovery phase (meaning the decoy was convincing enough for the adversary to continue)?
- **Intelligence yield:** How many strategic assessments were produced? How many detection rules or hunt hypotheses were generated from deception telemetry?
- **Freshness:** What is the average age of deployed decoys? How many are past their rotation schedule?

If you cannot measure your deception program, you cannot improve it. If you cannot improve it, adversaries will outpace it.

---

## 3. Deception Asset Taxonomy

DaC defines six categories of deception assets. Each has different resource costs, telemetry depth, and operational complexity. A mature deception program uses all of them in combination.

### 3.1 Honeytokens

A honeytoken is a credential, API key, URL, or document embedded somewhere it might be found by an attacker but would never be accessed by a legitimate user. Any use of a honeytoken is a guaranteed breach indicator. There is no baseline to tune, no threshold to set, and no false positive rate to manage. If it fires, something is wrong.

The reach of honeytokens extends further than most organizations initially appreciate: Word documents that call back when opened, PDFs that beacon when printed, DNS records that alert when resolved, fake entries in password managers, fabricated SSH host configurations. Each of these is a tripwire that requires no maintenance and produces an alert only when something suspicious actually happens.

**Types supported:**

| Type | Example | Detection Signal |
|------|---------|-----------------|
| `aws-credential` | Access key in `~/.aws/credentials` | Any AWS API call using the key |
| `kubeconfig` | Cluster config on developer workstation | Any k8s API call using the context |
| `api-key` | GitHub PAT in `.env` file | Any GitHub API call using the token |
| `database-cred` | Connection string in config file | Any database connection attempt |
| `ssh-key` | Private key in `~/.ssh/` | Any SSH authentication attempt |
| `document` | Word doc with embedded beacon | Document opened or printed |

### 3.2 Honeypots

Honeypots offer an entire fake system for the attacker to interact with. The intelligence gap between fidelity levels is significant. A low-interaction SSH honeypot tells you that someone tried `root` with the password `admin123` at 03:14 UTC. A high-interaction SSH honeypot tells you that the same actor then ran `whoami`, `id`, `uname -a`, read `/etc/passwd`, attempted to write to `/root/.ssh/authorized_keys`, and tried to download a tool from an external host. The first is a detection signal. The second is an adversary profile.

DaC defines three fidelity tiers for honeypots (see Section 4).

**Supported protocols:**

| Protocol | Use Case |
|----------|----------|
| SSH | Credential harvesting, post-auth behavior capture, lateral movement |
| HTTP/HTTPS | Web application lures (WordPress, Jenkins, Grafana, custom APIs) |
| SMB | File share access, honeytoken document interaction |
| MySQL/PostgreSQL | Database credential testing, query analysis |
| RDP | Workstation simulation, GUI-based interaction capture |
| FTP | Legacy system simulation, file access patterns |
| DNS | Reconnaissance detection, C2 beaconing |

### 3.3 Breadcrumbs

Breadcrumbs are artifacts planted in real systems to guide attackers toward deception environments. They do not detect anything on their own. Their value is improving the probability that an attacker navigating your real environment will stumble into a monitored decoy before they reach anything that matters.

A fake SSH config entry in a developer's home directory pointing to a decoy host, a DNS record for a server that only exists in your deception cluster, a cloud credential file with entries that belong to honey accounts. All of these are breadcrumbs. The tradecraft of breadcrumb design is making them look real enough to be tempting without being so obvious that a sophisticated attacker recognizes them as traps.

### 3.4 Lures

Lures are data artifacts designed to attract interaction. A database record with a recognizable pattern (an executive's name, a high-value project codename) that stands out during enumeration. A file share named `finance-backup` in a subnet where an attacker has just gained access. Lures overlap with breadcrumbs but differ in intent: breadcrumbs guide movement, lures attract engagement.

### 3.5 Honey Records

Fake database rows, Active Directory objects, DNS entries, or cloud resources that exist solely for detection. A Kerberoastable AD service account with an SPN that no legitimate service uses. A DNS record for a hostname that resolves to a decoy. A cloud IAM role with permissions that no real workload needs. Each is a canary embedded in a real data store.

### 3.6 Decoy Data and Deception Networks

At the upper end of the deception spectrum are fabricated datasets and fake network segments that mirror production topology. A decoy database seeded with fake customer records that contain embedded tracking mechanisms fires an alert if the data is ever exfiltrated and opened. A honey network segment that mirrors your production VLAN layout but contains only instrumented decoys gives you a picture of how an attacker would traverse your real environment if they gained access. These represent mature deception programs and are the end state, not the starting point.

---

## 4. Fidelity Tiers

Fidelity determines how convincing a decoy is under adversary scrutiny, how much telemetry it produces, and how many resources it consumes. DaC defines three tiers. Operators choose the tier per-decoy based on where it sits in the network and what intelligence question it answers.

### 4.1 Tier 1: Beacon

Listens and logs. Connection metadata only. The decoy emulates the surface of a service (a banner, an open port, perhaps a login prompt) without running real or deeply emulated software.

- **Resource cost:** ~32MB RAM per instance. Deploy hundreds as network tripwires.
- **Telemetry depth:** Connection timestamps, source IPs, ports, protocol banners.
- **Use case:** Network-wide coverage. Trip wires across subnets. Early warning of scanning and lateral movement.
- **Limitation:** No post-authentication behavior capture. Tells you someone knocked on the door, not what they did inside.

### 4.2 Tier 2: Scripted (High-Fidelity)

Full virtual filesystem, session state, captured response databases, pipe handling. Convincing under prolonged interaction without requiring an LLM. Response databases are captured from real systems and validated against fingerprinting suites.

- **Resource cost:** ~128MB RAM per instance.
- **Telemetry depth:** Full session transcripts, command sequences, file access patterns, credential submissions, tool downloads, timing analysis.
- **Use case:** Targeted placement in high-value network segments. Generating adversary profiles from post-authentication behavior.
- **Limitation:** Breaks on novel or unexpected commands outside the response database. Sophisticated attackers who test edge cases may fingerprint scripted responses.

### 4.3 Tier 3: Adaptive (LLM-Backed)

Everything Tier 2 does, plus a local LLM (e.g., Ollama, no external API keys) handles novel commands. The LLM inference layer handles arbitrary command sequences while maintaining session coherence. A response cache for common commands keeps latency realistic.

- **Resource cost:** ~512MB+ RAM per instance, plus shared inference service.
- **Telemetry depth:** Everything Tier 2 captures, plus adversary behavior in response to unexpected or dynamic system states.
- **Use case:** Engaging skilled human attackers during hands-on-keyboard operations. Maximum intelligence yield per session.
- **Limitation:** Higher operational complexity. Latency management is critical. LLM response times must fall within the distribution of real system response times to avoid detection.

**Tier selection guidance:**

| Scenario | Recommended Tier |
|----------|-----------------|
| Broad network coverage, many decoys | Tier 1 |
| DMZ or perimeter-facing services | Tier 2 |
| Internal servers adjacent to crown jewels | Tier 2 or Tier 3 |
| Active threat hunt, known adversary in environment | Tier 3 |
| Honeytokens and breadcrumbs | Tier 1 (no interaction required) |

The `fidelity.distribution` field in a `DecoyFleet` manifest allows operators to specify the ratio of tiers across a fleet deployment (for example, 60% Tier 1, 30% Tier 2, 10% Tier 3), letting the operator balance coverage breadth against intelligence depth.

---

## 5. Manifest Schema

Decoy manifests are Kubernetes Custom Resource Definitions (CRDs) that follow the standard resource pattern. Operators write YAML, commit it to Git, and the CI/CDecoy operator reconciles the desired state into running decoy pods on the cluster.

### 5.1 CRD Group and Kinds

```yaml
apiVersion: cicdecoy.io/v1alpha1
kind: Decoy | DecoyTemplate | HoneyToken | DecoyProfile | DecoyFleet
```

### 5.2 Decoy

The core resource. Defines a single deception asset.

```yaml
apiVersion: cicdecoy.io/v1alpha1
kind: Decoy
metadata:
  name: ssh-dmz-01
  namespace: decoys-production
  labels:
    cicdecoy.io/tier: "3"
    cicdecoy.io/zone: "dmz"
    cicdecoy.io/campaign: "q1-threat-hunt"
  annotations:
    cicdecoy.io/description: "Simulated dev jump box in DMZ"
    cicdecoy.io/owner: "blue-team"
spec:
  service:
    type: ssh                           # Protocol to emulate
    port: 22
    banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
  fidelity:
    tier: 3
    adaptive:
      model: "llama3"
      maxLatencyMs: 200
      cacheCommonCommands: true
  identity:
    hostname: "dev-jump-dmz-01"
    os:
      family: linux
      distro: "Ubuntu 22.04.3 LTS"
      kernel: "5.15.0-91-generic"
    profileRef: "dev-workstation"        # Reference to DecoyProfile
  authentication:
    mode: selective                      # open | selective | realistic | closed
    allowCredentials:
      - username: admin
        password: "Passw0rd!"
      - username: dev
        password: "dev2024"
    captureAll: true
  filesystem:
    base: "ubuntu-22.04-dev"
    honeytokens:
      - path: "/home/dev/.aws/credentials"
        tokenRef: "aws-key-breadcrumb"
      - path: "/home/dev/.ssh/config"
        content: |
          Host prod-db
            HostName 10.0.3.42
            User deploy
  telemetry:
    sessionCapture:
      fullTranscript: true
      keystrokeTimings: true
      fileUploads: true
    exporter:
      type: nats
      endpoint: "nats://nats:4222"
      subject: "cicdecoy.events.ssh"
  engage:
    activity: EAC0001                    # Lure
    approach: EAP0001                    # Strategic Planning
    goal: EG0001                         # Collect
    hypothesis: >
      Adversaries targeting the DMZ will attempt SSH credential access.
      Post-auth behavior will reveal tool preferences and lateral
      movement patterns.
    collection_requirements:
      - credential_patterns
      - post_auth_commands
      - tool_signatures
      - lateral_movement_targets
    null_criteria: >
      No interaction after 30 days suggests this network segment is not
      a target, or adversaries are using a different initial access vector.
  resources:
    requests:
      memory: "512Mi"
      cpu: "250m"
    limits:
      memory: "1Gi"
      cpu: "500m"
  lifecycle:
    rotation:
      enabled: true
      interval: "168h"                   # Weekly
      strategy: identity_refresh         # Change hostname, IP, credentials
    healthCheck:
      enabled: true
      interval: "1h"
      fingerprintValidation: true        # Run fingerprint tests on schedule
  network:
    discoverability:
      arpRespond: true
      pingRespond: true
    beaconTraffic:
      enabled: true
      targets:
        - host: "10.0.1.1"
          port: 53
          protocol: dns
          interval: "30s"
```

### 5.3 DecoyProfile

Defines the identity and personality of a decoy: the operating system details, user accounts, installed software, and narrative context that make it believable.

```yaml
apiVersion: cicdecoy.io/v1alpha1
kind: DecoyProfile
metadata:
  name: dev-workstation
spec:
  system:
    hostname_pattern: "dev-ws-{{ .seq }}"
    os: "Ubuntu 22.04.3 LTS"
    kernel: "5.15.0-91-generic"
    uptime_range: "7d-90d"
    timezone: "America/Los_Angeles"
  users:
    - username: dev
      uid: 1001
      groups: ["dev", "docker", "sudo"]
      shell: "/bin/bash"
      home: "/home/dev"
    - username: deploy
      uid: 1002
      groups: ["deploy"]
      shell: "/bin/bash"
      home: "/home/deploy"
  software:
    packages:
      - "openssh-server 8.9p1"
      - "docker-ce 24.0.7"
      - "python3 3.10.12"
      - "node 18.19.0"
      - "git 2.34.1"
    services:
      - "ssh"
      - "docker"
      - "cron"
  narrative: >
    A developer workstation used for building and deploying containerized
    applications. The dev user has Docker and sudo access. The deploy user
    has limited access for CI/CD pipeline operations. Recent bash history
    should include git operations, docker builds, and kubectl commands.
```

### 5.4 HoneyToken

Defines a credential or artifact with tracking capabilities.

```yaml
apiVersion: cicdecoy.io/v1alpha1
kind: HoneyToken
metadata:
  name: aws-key-breadcrumb
  labels:
    cicdecoy.io/type: "aws-credential"
spec:
  type: aws-credential
  content:
    access_key_id: "AKIA3EXAMPLE7DECOY01"
    secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    profile_name: "prod-deploy"
    region: "us-west-2"
  placement:
    locations:
      - "~/.aws/credentials on dev-ws-042"
      - ".env file in /opt/app/deploy/"
    discovery_paths:
      - "File enumeration on compromised endpoint"
      - "Process environment variable listing"
  tracking:
    provider: cloudtrail
    alertOn:
      - "sts:GetCallerIdentity"
      - "s3:ListBuckets"
      - "iam:GetUser"
      - "*"                              # Any API call
  engage:
    activity: EAC0004                    # Pocket Litter
    hypothesis: >
      Are adversaries harvesting and using AWS credentials from
      compromised endpoints? The specific API calls reveal what cloud
      resources the adversary is targeting.
    mitre_techniques:
      - "T1552.001"                      # Credentials In Files
      - "T1528"                          # Steal Application Access Token
```

### 5.5 DecoyFleet

Deploy N decoys with randomized hostnames, ports, profiles, and fidelity tiers. Rolling rotation replaces a percentage of decoys on a schedule to prevent fingerprinting.

```yaml
apiVersion: cicdecoy.io/v1alpha1
kind: DecoyFleet
metadata:
  name: internal-network-sweep
  namespace: decoys-production
spec:
  replicas: 15
  templateRef: "ssh-server"

  variance:
    hostnames:
      pattern: "srv-{{ .zone }}-{{ .seq | printf \"%02d\" }}"
      zones: ["dev", "staging", "prod"]
    ports:
      ssh: [22, 2222, 22222]
    profiles:
      pool:
        - "dev-workstation"
        - "db-server"
        - "ci-runner"
        - "legacy-webserver"
    fidelity:
      distribution:
        tier1: 0.6
        tier2: 0.3
        tier3: 0.1

  placement:
    spreadAcross: "zones"
    avoidSubnets:
      - "10.0.1.0/24"                   # Real production servers
      - "10.0.2.0/24"                   # Management network

  rotation:
    enabled: true
    interval: "336h"                     # Rotate fleet every 2 weeks
    strategy: rolling
    rollPercentage: 20
```

---

## 6. Telemetry Model

### 6.1 Event Schema

The atomic unit of telemetry is a `TelemetryEvent`. Every field exists because it answers a question an analyst would ask.

```yaml
TelemetryEvent:
  event_id: string                       # UUID
  timestamp: datetime                    # UTC
  decoy_id: string                       # Which decoy was touched
  decoy_name: string
  decoy_type: string                     # honeypot | honeytoken | breadcrumb | ...

  source:
    source_ip: string
    source_port: integer
    source_hostname: string
    user_agent: string
    credentials_used:
      username: string
      password: string
    tls_fingerprint: string              # JA3/JA4 hash
    ssh_fingerprint: string              # Client key fingerprint
    geo:
      country: string
      city: string
      lat: float
      lon: float
    asn: string
    threat_intel_hits: array             # Matches from threat feeds

  phase: enum                            # Where in the kill chain
    # discovery | initial_access | exploration | exploitation
    # collection | exfiltration | persistence | lateral

  action: string                         # Specific action performed
    # ssh_auth_attempt | ssh_command | smb_tree_connect
    # file_read | file_write | http_request | dns_query | ...

  detail: object                         # Action-specific structured data
  tools_observed: array                  # Tool signatures identified
  mitre_technique: string                # ATT&CK technique ID
  engage_activity: string                # Engage activity code
  raw_data: string                       # Original log line (preserved)
```

### 6.2 Interaction Sessions

Events are grouped into sessions. A session represents a single adversary engagement with a decoy from initial connection through disconnection.

```yaml
InteractionSession:
  session_id: string
  decoy_id: string
  start_time: datetime
  end_time: datetime
  duration_seconds: integer

  source: SourceContext                   # Same source block as events

  events: array[TelemetryEvent]
  event_count: integer
  phases_observed: array[enum]           # Which kill chain phases appeared

  behavioral_fingerprint:
    command_sequence_hash: string         # Hash of ordered command list
    timing_profile:                      # Inter-command timing distribution
      mean_ms: float
      stddev_ms: float
      min_ms: float
      max_ms: float
    credential_pattern: string           # Pattern of auth attempts
    tool_signatures: array[string]

  risk_score: float                      # 0.0 - 1.0
  classification:
    sophistication: enum                 # opportunistic | commodity | targeted | advanced
    inferred_objectives: array[string]
    ttps: array[MitreTechnique]
```

### 6.3 Pipeline Architecture

The telemetry pipeline follows a publish-subscribe model with enrichment stages:

```
Decoy Pod
  → Sidecar Adapter (translates native logs to common schema)
  → NATS (message bus, subject: cicdecoy.events.{protocol})
  → CTI Enrichment Service
      → GeoIP lookup
      → ASN resolution
      → Threat feed correlation
      → MITRE ATT&CK technique classification
      → MITRE Engage outcome tracking
      → Session assembly
  → TimescaleDB (time-series storage)
  → Consumers:
      → Dashboard (SSE/WebSocket)
      → SIEM exporter (Elasticsearch, Splunk, Sentinel)
      → STIX/TAXII export
      → Strategic assessment generator
```

The adapter pattern is critical. Thin sidecar containers translate third-party honeypot output (Cowrie, Dionaea, OpenCanary, or any future decoy) into the common event schema and publish to NATS. This means CI/CDecoy is not just a honeypot. It is an intelligence platform that happens to ship with honeypots. Any decoy that can produce logs can be wrapped in an adapter and integrated into the pipeline.

---

## 7. MITRE Framework Integration

### 7.1 MITRE ATT&CK Mapping

Every observed adversary action maps to ATT&CK technique IDs. The mapping is a static, maintainable table, not a probabilistic model. Operators should know exactly why each mapping exists and should extend it based on their threat environment.

| Observed Action | ATT&CK Technique | Tactic |
|----------------|-------------------|--------|
| SSH brute force | T1110.001 | Credential Access |
| SSH password spray | T1110.003 | Credential Access |
| `whoami`, `id` | T1033 | Discovery |
| `uname -a`, `cat /etc/os-release` | T1082 | Discovery |
| `cat /etc/passwd`, `cat /etc/shadow` | T1003.008 | Credential Access |
| `cat /etc/hosts`, `arp -a` | T1018 | Discovery |
| `wget`, `curl` to external host | T1105 | Command and Control |
| Write to `~/.ssh/authorized_keys` | T1098.004 | Persistence |
| Write to `/etc/crontab`, crontab edit | T1053.003 | Persistence |
| `history -c`, `rm ~/.bash_history` | T1070.003 | Defense Evasion |
| `nmap`, port scanning patterns | T1046 | Discovery |
| SMB share enumeration | T1135 | Discovery |
| `base64`, `openssl enc` | T1132.001 | Command and Control |
| Kerberoasting (TGS request for honey SPN) | T1558.003 | Credential Access |
| Honeytoken AWS credential use | T1552.001 | Credential Access |

### 7.2 MITRE Engage Integration

Every deception operation maps to Engage activities, approaches, and goals. This is how you measure whether your deception program is producing the outcomes it was designed to produce.

**Engage Categories:**

- **Prepare:** Strategic planning, defining operational goals, designing engagement infrastructure.
- **Expose:** Surfacing adversaries. Deploying lures and decoy credentials that cause adversaries to reveal their presence.
- **Affect:** Degrading adversary operations. Feeding false information that causes them to waste time and resources on targets that are not real.
- **Elicit:** Intelligence collection. Capturing adversary TTPs, tooling, and objectives through controlled engagement.
- **Understand:** Analysis and assessment. Synthesizing observations into actionable intelligence about adversary capabilities and intent.

**Mapping in manifests:**

Every decoy manifest includes an `engage` block that maps the decoy to specific Engage activities and defines measurable hypotheses. The CTI enrichment pipeline tracks which Engage activities were exercised, how many times, and with what outcomes.

---

## 8. Analysis and Intelligence Production

### 8.1 Adversary Profiling

The analyzer builds adversary profiles from behavioral patterns observed across sessions. A profile includes:

- **Sophistication rating:** Opportunistic (automated scanning, default credentials), Commodity (known tools, scripted behavior), Targeted (customized tools, specific objectives), Advanced (OPSEC-aware, anti-forensics, novel techniques).
- **Tool identification:** Signatures of known tools observed in session transcripts: Nmap, Hydra, Metasploit, Cobalt Strike, Mimikatz, BloodHound, and custom tooling identified by behavioral fingerprint.
- **Operational security indicators:** History clearing, timestomping, anti-forensics, use of encrypted channels, VPN/proxy usage patterns.
- **Inferred objectives:** Derived from observed tactics: credential harvesting, data exfiltration, foothold establishment, lateral movement, reconnaissance.

**Sophistication scoring heuristic:**

The scoring is additive based on observed indicators. Automated scanners using default credentials score as opportunistic. Hands-on-keyboard sessions with more than 20 commands that span multiple decoys and include OPSEC indicators score as advanced. The thresholds are tunable per deployment.

### 8.2 Campaign Correlation

Sessions are correlated into campaigns based on shared indicators: source IP ranges, credential sets, tool signatures, behavioral fingerprints, and timing patterns. The same credential set tried across three honeypots in the same subnet within an hour is not three alerts. It is one campaign with a lateral movement pattern.

### 8.3 Strategic Assessment

The `StrategicAssessment` is the top-level intelligence product. It is the deliverable that makes deception operationally valuable.

```yaml
StrategicAssessment:
  assessment_id: string
  period:
    start: datetime
    end: datetime
  
  hypotheses_tested:
    - hypothesis: "Adversaries target DMZ SSH services"
      status: confirmed | refuted | inconclusive
      evidence_summary: string
      sessions_supporting: array[session_id]

  detection_gaps_discovered:
    - description: string
      recommended_action: string
      priority: high | medium | low

  hunt_recommendations:
    - hypothesis: string
      indicators: array[string]
      suggested_data_sources: array[string]

  posture_adjustments:
    - action: deploy | retire | rotate | retier
      target: string
      rationale: string

  metrics:
    total_sessions: integer
    unique_sources: integer
    techniques_observed: array[string]
    avg_session_duration: float
    engagement_depth:                    # How far into the kill chain
      discovery_only: integer
      post_auth: integer
      tool_deployment: integer
      persistence_attempt: integer
```

---

## 9. Deployment Architecture

### 9.1 Container-Native

DaC is designed for container-native deployment on lightweight Kubernetes distributions (k3s). Decoys run as pods managed by a custom Kubernetes operator. The operator watches for `Decoy` CRDs and reconciles them into running pods with the correct configuration, resource limits, and sidecar adapters.

```
kubectl get decoys

NAME            TIER   PROTOCOL   ZONE   STATUS    SESSIONS   AGE
ssh-dmz-01      3      ssh        dmz    Running   47         6d
http-web-01     2      http       web    Running   312        13d
smb-share-01    2      smb        corp   Running   8          6d
rdp-ws-01       1      rdp        corp   Running   2          20d
```

### 9.2 Operator Responsibilities

The CI/CDecoy operator handles:

- Creating ConfigMaps with decoy specifications (profile, response databases, manifest).
- Creating Deployments with the correct decoy image per protocol and tier.
- Creating Services to expose decoy ports.
- Setting resource limits per fidelity tier (Tier 1: 32MB, Tier 2: 128MB, Tier 3: 512MB+).
- Handling spec updates via rolling restart.
- Handling deletion with full resource cleanup.
- Scheduling rotation based on lifecycle configuration.
- Running periodic health checks and fingerprint validation.

### 9.3 Fidelity Testing in CI

Before any decoy gets promoted to production, CI pipelines run fidelity tests from a fingerprinting suite. These tests verify that the decoy does not exhibit known fingerprinting signatures that would allow an adversary to identify it as a trap.

Fidelity tests include: banner consistency, timing distribution analysis, response accuracy for common commands, filesystem plausibility, process listing coherence, and protocol-level compliance checks.

A decoy that fails fidelity tests does not deploy. This is enforced by admission webhook in the cluster and by pipeline gates in CI.

---

## 10. Schema Reference

### 10.1 Field Types and Validation

```yaml
Decoy:
  spec:
    service:
      type:        enum [ssh, http, https, smb, mysql, postgres, rdp, ftp, dns, custom]
      port:        integer (1-65535), required
    fidelity:
      tier:        enum [1, 2, 3], required
      scripted:    object (required if tier=2)
      adaptive:    object (required if tier=3)
    identity:
      hostname:    string, required, maxLength=253
      os.family:   enum [linux, windows], required
    authentication:
      mode:        enum [open, selective, realistic, closed], required
    telemetry:
      sessionCapture:
        fullTranscript:  boolean, default=true
    resources:
      requests:    Kubernetes resource requirements
      limits:      Kubernetes resource requirements
    lifecycle:
      rotation:
        interval:  duration string (e.g., "168h")

DecoyProfile:
  spec:
    system:        object, required
    users:         array, required, minItems=1
    software:      object, required
    narrative:     string, required

HoneyToken:
  spec:
    type:          enum [aws-credential, kubeconfig, api-key, database-cred, ssh-key, document]
    content:       object, required
    tracking:      object, required
    alertOn:       array, required, minItems=1

DecoyFleet:
  spec:
    replicas:      integer, required, min=1, max=500
    templateRef:   string, required
    variance:      object (randomization parameters)
    placement:     object (scheduling constraints)
    rotation:      object (fleet rotation strategy)
```

### 10.2 Validation Rules

The CI/CDecoy admission webhook and CI pipeline enforce:

1. Every `Decoy` must have a non-empty `engage.hypothesis`.
2. Tier 2 decoys must reference a valid `DecoyProfile`.
3. Tier 3 decoys must specify an `adaptive.model` that is available on the cluster.
4. `HoneyToken` resources must have at least one `alertOn` condition.
5. `DecoyFleet` variance percentages must sum to 1.0.
6. Resource limits must meet minimum requirements per tier.
7. Namespaces must be explicitly labeled for deception use.
8. Port conflicts within a namespace are rejected.

### 10.3 Status and Conditions

```yaml
DecoyStatus:
  phase: Pending | Running | Degraded | Rotating
  ready: boolean
  podName: string
  podIP: string
  lastHealthCheck: datetime
  sessionCount: integer
  lastRotation: datetime
  conditions:
    - type: FidelityValid
      status: "True"
      lastTransitionTime: datetime
    - type: TelemetryFlowing
      status: "True"
      lastTransitionTime: datetime
```

---

## 11. Integration Patterns

### 11.1 SIEM/SOAR Integration

The SIEM integration layer is a pluggable exporter that subscribes to NATS subjects and pushes events to external systems. The exporter is a separate, independent consumer. The core pipeline never accumulates vendor-specific dependencies.

Reference exporters are provided for common targets. The exporter interface is documented so teams can write exporters for Splunk, Sentinel, Chronicle, or whatever their SOC runs.

### 11.2 Incident Response

A deception alert is different from a SIEM alert in a way that changes how it should be triaged. A SIEM alert begins with a question: *is this real?* Deception alerts begin from a different premise: *something happened that has no legitimate explanation.*

When a honeytoken fires, containment is informed rather than blind. The analyst knows which asset was touched, can scope the compromise to a specific system and timeframe, and has structured data about the adversary's behavior. The deception telemetry converts a slow, uncertain investigation into a fast, directed one.

### 11.3 STIX/TAXII Export

Strategic assessments and adversary profiles are exportable in STIX 2.1 format for sharing through TAXII feeds or integration with threat intelligence platforms. The mapping from DaC's internal models to STIX objects (Threat Actor, Attack Pattern, Indicator, Observed Data) is maintained as part of the CTI enrichment pipeline.

---

## 12. Operational Guidance

### 12.1 Start Small

Do not attempt to deploy a full deception network on day one. Start with honeytokens. They are the highest-value, lowest-effort deception asset. Seed fake credentials in likely discovery paths, wire up alerting, and validate the pipeline works end-to-end. Then add Tier 1 honeypots for network coverage. Then add Tier 2 in high-value segments. Tier 3 is for when you have a confirmed adversary in the environment and want maximum intelligence yield.

### 12.2 Rotate Everything

Static deception environments get fingerprinted. Rotation is not optional for any serious deployment. Hostnames, IPs, credentials, banners, and filesystem contents should change on a schedule. The rotation schedule should be shorter than the expected dwell time of adversaries in your threat model.

### 12.3 Measure or Remove

Every decoy must be producing measurable value. If a decoy has been deployed for a quarter and has never been interacted with, either the placement is wrong, the hypothesis was incorrect, or the threat model does not include that vector. Retire it or redeploy it somewhere else. Deception assets that accumulate without measurement are liabilities, not defenses.

### 12.4 The Hypothesis Is the Discipline

If you find yourself deploying a decoy because "it seems like a good idea" without a written hypothesis and collection requirement, stop. The hypothesis is what separates an intelligence operation from a science fair project. Write down what you expect to learn. Write down what absence of interaction would mean. Review the hypothesis when you review the data.

---

## Appendix A: Glossary

| Term | Definition |
|------|-----------|
| Breadcrumb | An artifact planted in a real system to guide adversaries toward deception infrastructure |
| CTI | Cyber Threat Intelligence: structured intelligence about adversary capabilities, intent, and behavior |
| DaC | Deception as Code, this specification |
| Decoy | Any deception asset: honeypot, honeytoken, breadcrumb, lure, honey record, or decoy data |
| Fidelity | How convincing a decoy is under adversary scrutiny |
| Honeytoken | A credential, key, or artifact that produces an alert when used |
| Honeypot | A fake system that emulates a real service to capture adversary behavior |
| Lure | A data artifact designed to attract adversary interaction |
| MITRE ATT&CK | Adversary tactics, techniques, and procedures knowledge base |
| MITRE Engage | Adversary engagement framework for planning and measuring deception operations |
| Strategic Assessment | The top-level intelligence product of a DaC deployment |

## Appendix B: Example Deployment Scenarios

### B.1 Network Lateral Movement Detection

Deploy SSH, SMB, and RDP honeypots across internal network segments with breadcrumbs on developer workstations pointing to them. Hypothesis: adversaries who gain initial access to the corporate network will attempt lateral movement using stolen credentials. Collection requirements: credential patterns, protocol preferences, movement sequence.

### B.2 Credential Harvesting Detection

Deploy Kerberoastable AD service accounts, honey AWS credentials on endpoints, and fake GitHub PATs in internal repositories. Hypothesis: adversaries with domain access will enumerate and attempt to use high-value credentials. Collection requirements: which credential types are targeted, time from initial access to credential theft, external infrastructure used for testing stolen credentials.

### B.3 Cloud-Native Deception

Deploy honey S3 buckets with tracking-enabled objects, honey IAM roles with CloudTrail monitoring, and fake Lambda functions that log invocations. Hypothesis: adversaries who compromise cloud credentials will enumerate and attempt to access cloud resources. Collection requirements: API call patterns, resource enumeration sequence, data exfiltration targets.

---

*Deception as Code is a specification maintained as part of the CI/CDecoy project. It is published as a standalone standard independent of any single implementation.*