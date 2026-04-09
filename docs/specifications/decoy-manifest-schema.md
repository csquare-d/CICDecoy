# CI/CDecoy — Decoy Manifest Schema

## Overview

Decoy manifests are Kubernetes Custom Resource Definitions (CRDs) that declaratively
define deception assets. They follow the standard k8s resource pattern — operators
write YAML, commit it to Git, and the CI/CDecoy operator reconciles the desired state
into running decoy pods on the cluster.

The schema is designed around three principles:
1. **Familiar** — looks like any other k8s manifest
2. **Layered** — simple decoys need minimal config, complex ones unlock more fields
3. **Composable** — profiles, templates, and honeytokens can be mixed and referenced

---

## CRD Group & Versions

```yaml
apiVersion: cicdecoy.io/v1alpha1
kind: Decoy | DecoyTemplate | HoneyToken | DecoyProfile | DecoyFleet
```

---

## Core Resource: `Decoy`

```yaml
apiVersion: cicdecoy.io/v1alpha1
kind: Decoy
metadata:
  name: ssh-dmz-01
  namespace: decoys-production
  labels:
    cicdecoy.io/tier: "3"               # Fidelity tier: 1, 2, or 3
    cicdecoy.io/zone: "dmz"             # Network zone
    cicdecoy.io/campaign: "q1-threat-hunt"  # Optional campaign grouping
  annotations:
    cicdecoy.io/description: "Simulated dev jump box in DMZ"
    cicdecoy.io/owner: "blue-team"
spec:

  # ┌──────────────────────────────────────────────────────┐
  # │  SERVICE DEFINITION                                   │
  # │  What protocol does this decoy emulate?               │
  # └──────────────────────────────────────────────────────┘
  service:
    type: ssh                            # ssh | http | https | smb | mysql
                                         # | postgres | rdp | ftp | dns | custom
    port: 22
    additionalPorts:                     # Optional: expose multiple services
      - port: 80
        type: http
      - port: 443
        type: https

  # ┌──────────────────────────────────────────────────────┐
  # │  FIDELITY CONFIGURATION                               │
  # │  How convincing should this decoy be?                 │
  # └──────────────────────────────────────────────────────┘
  fidelity:
    tier: 3                              # 1 = beacon, 2 = scripted, 3 = adaptive

    # Tier 1 — Beacon (connection logging only)
    # No additional config needed. Just listens and logs.

    # Tier 2 — Scripted (deterministic response trees)
    scripted:
      responseSet: "openssh-8.9"         # Pre-built response library
      customResponses:                   # Override specific commands
        - match: "uname -a"
          response: "Linux dev-jump-01 5.15.0-91-generic #101-Ubuntu SMP x86_64"
        - match: "cat /etc/hostname"
          response: "dev-jump-01"

    # Tier 3 — Adaptive (LLM-backed)
    adaptive:
      profileRef: "dev-workstation"      # Reference to a DecoyProfile resource
      inferenceConfig:
        maxSessionTokens: 8192           # Context window budget per session
        temperature: 0.3                 # Low = more deterministic/consistent
        cacheDeterministic: true         # Cache responses for common commands
      fastPath:                          # Commands handled WITHOUT LLM inference
        enabled: true
        commands:                        # Explicit fast-path overrides
          - match: "^ls"
            source: filesystem           # Serve from virtual filesystem state
          - match: "^pwd$"
            source: state                # Serve from session state
          - match: "^whoami$"
            source: state
          - match: "^id$"
            source: state
          - match: "^cat /etc/(passwd|hostname|os-release)"
            source: profile              # Serve from profile definition
      guardrails:
        preventRealCommands: true        # Never execute actual system commands
        filterPatterns:                  # Strip from LLM output if present
          - "(?i)honeypot"
          - "(?i)decoy"
          - "(?i)cicdecoy"
          - "(?i)I('m| am) an AI"
        maxResponseLines: 500            # Cap output length
        disallowedPaths:                 # LLM must not reveal these exist
          - "/opt/cicdecoy"
          - "/var/log/decoy"

  # ┌──────────────────────────────────────────────────────┐
  # │  IDENTITY                                             │
  # │  What does this machine look like?                    │
  # └──────────────────────────────────────────────────────┘
  identity:
    hostname: "dev-jump-01"
    domain: "corp.internal"
    os:
      family: linux                      # linux | windows
      distribution: "Ubuntu"
      version: "22.04.3 LTS"
      kernel: "5.15.0-91-generic"
      arch: "x86_64"
    network:
      ipStrategy: dhcp                   # dhcp | static | hostNetwork
      staticIP: null
      macPrefix: "02:42:ac"             # First 3 octets for realistic MAC
      interfaces:
        - name: eth0
          type: ethernet
        - name: docker0
          type: bridge
    fingerprint:
      tcpWindowSize: 65535              # OS fingerprint tuning for nmap
      ttl: 64                           # Linux default
      tcpOptions: "mss,nop,nop,sackOK"
      sshBanner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
      httpServer: "Apache/2.4.52 (Ubuntu)"

  # ┌──────────────────────────────────────────────────────┐
  # │  AUTHENTICATION                                       │
  # │  How should login attempts be handled?                │
  # └──────────────────────────────────────────────────────┘
  authentication:
    mode: selective                      # open | selective | realistic | closed
                                         #   open       — accept everything
                                         #   selective  — accept specific creds
                                         #   realistic  — accept after N attempts
                                         #   closed     — reject all (log attempts)
    credentials:                         # For selective/realistic modes
      - username: admin
        password: admin123
        shell: /bin/bash
        uid: 1000
        home: /home/admin
      - username: deploy
        password: "D3pl0y_2024!"
        shell: /bin/bash
        uid: 1001
        home: /home/deploy
      - username: root
        password: "toor"
        shell: /bin/bash
        uid: 0
        home: /root
    realisticAuth:
      failBeforeSuccess: 2              # Reject first N attempts, then accept
      lockoutAfter: 10                  # Lock account after N total failures
      lockoutDuration: 300              # Seconds
    captureNTLM: true                   # For SMB: capture NTLM hashes
    logAllAttempts: true                # Log every auth attempt with full detail

  # ┌──────────────────────────────────────────────────────┐
  # │  FILESYSTEM                                           │
  # │  What does the virtual filesystem look like?          │
  # └──────────────────────────────────────────────────────┘
  filesystem:
    base: "ubuntu-22.04-minimal"         # Pre-built filesystem skeleton
    overlays:                            # Layer additional content
      - type: profile                    # Pull from DecoyProfile
        profileRef: "dev-workstation"
      - type: inline                     # Define directly in manifest
        files:
          - path: /home/admin/.ssh/authorized_keys
            content: |
              ssh-rsa AAAAB3NzaC1yc2E... admin@dev-jump-01
            permissions: "0600"
            owner: admin
          - path: /home/admin/.bash_history
            content: |
              ssh db-prod-01.corp.internal
              kubectl get pods -n production
              docker ps
              cat /opt/app/config/database.yml
              scp deploy@build-server:/artifacts/latest.tar.gz .
            permissions: "0600"
            owner: admin
          - path: /opt/app/config/database.yml
            content: |
              production:
                adapter: mysql2
                host: db-prod-01.corp.internal
                database: app_production
                username: app_user
                password: "Pr0d_DB_2024!#"
            permissions: "0640"
            owner: deploy
      - type: honeytoken                 # Embed honeytoken files
        tokenRefs:
          - "aws-creds-canary-01"
          - "kubeconfig-canary-01"
        placements:
          - tokenRef: "aws-creds-canary-01"
            path: /home/admin/.aws/credentials
          - tokenRef: "kubeconfig-canary-01"
            path: /home/admin/.kube/config
    processes:                           # Fake process table entries
      - pid: 1
        command: "/sbin/init"
        user: root
      - pid: 892
        command: "/usr/sbin/sshd -D"
        user: root
      - pid: 1205
        command: "/usr/sbin/cron -f"
        user: root
      - pid: 4521
        command: "docker-containerd"
        user: root
      - pid: 4890
        command: "node /opt/app/server.js"
        user: deploy

  # ┌──────────────────────────────────────────────────────┐
  # │  NETWORK BEHAVIOR                                     │
  # │  How does the decoy behave on the network?            │
  # └──────────────────────────────────────────────────────┘
  networkBehavior:
    beaconTraffic:
      enabled: true                      # Generate fake outbound traffic
      targets:                           # So the decoy looks "alive"
        - host: "dns.corp.internal"
          port: 53
          protocol: udp
          interval: 30s
        - host: "ntp.corp.internal"
          port: 123
          protocol: udp
          interval: 60s
    dnsRecords:                          # Register in internal DNS
      enabled: true
      names:
        - "dev-jump-01.corp.internal"
        - "jump.dev.corp.internal"
    discoverability:
      arpRespond: true                   # Respond to ARP requests
      pingRespond: true
      nbnsRespond: false                 # NetBIOS name resolution (Windows)

  # ┌──────────────────────────────────────────────────────┐
  # │  TELEMETRY & CTI                                      │
  # │  What data gets collected and where does it go?       │
  # └──────────────────────────────────────────────────────┘
  telemetry:
    sessionCapture:
      fullTranscript: true               # Log complete session I/O
      keystrokeTimings: true             # Capture inter-keystroke intervals
      fileUploads: true                  # Capture files attackers upload/create
      fileUploadMaxSize: "10Mi"
      screenshotOnConnect: false         # For RDP decoys: screenshot client
    exporters:
      - type: nats
        endpoint: "nats://msg-bus.cicdecoy-system:4222"
        subject: "decoy.events.ssh-dmz-01"
      - type: otel
        endpoint: "http://otel-collector.cicdecoy-system:4318"
    alerting:
      immediateAlert:                    # Fire alert instantly on these events
        - event: auth.success            # Any successful login
          severity: high
        - event: command.exec            # Commands matching patterns
          patterns:
            - "wget|curl.*http"
            - "chmod.*\\+x"
            - "nc.*-e|ncat|socat"
            - "/dev/tcp/"
            - "base64.*decode"
          severity: critical
        - event: file.exfil              # Honeytoken file accessed
          severity: critical
        - event: lateral.attempt         # SSH/RDP to other hosts from decoy
          severity: critical
      channels:
        - type: webhook
          url: "https://hooks.slack.com/services/..."
        - type: siem
          integration: splunk
          index: "deception_alerts"

  # ┌──────────────────────────────────────────────────────┐
  # │  RESOURCES & SCHEDULING                               │
  # │  Cluster resource allocation                          │
  # └──────────────────────────────────────────────────────┘
  resources:
    requests:
      cpu: "100m"
      memory: "128Mi"
    limits:
      cpu: "500m"
      memory: "512Mi"
    scheduling:
      nodeSelector:
        cicdecoy.io/role: "decoy-node"
      tolerations:
        - key: "cicdecoy.io/decoy"
          operator: Exists
          effect: NoSchedule
      antiAffinity: true                 # Don't co-locate with other decoys

  # ┌──────────────────────────────────────────────────────┐
  # │  LIFECYCLE                                            │
  # │  How is this decoy managed over time?                 │
  # └──────────────────────────────────────────────────────┘
  lifecycle:
    rotation:
      enabled: true
      interval: 168h                     # Rotate identity every 7 days
      strategy: gradual                  # gradual | immediate
                                         # gradual: spin up new, drain old
                                         # immediate: swap in place
    healthCheck:
      enabled: true
      interval: 60s
      fingerPrintValidation: true        # Periodically verify own fingerprint
    autoScaling:
      enabled: false                     # Scale decoy replicas based on activity
      minReplicas: 1
      maxReplicas: 3
      scaleOnMetric: "connections_per_minute"
      threshold: 50

---

## Supporting Resource: `DecoyProfile`

Profiles define the "personality" of an adaptive decoy — the system context
that shapes LLM responses.

```yaml
apiVersion: cicdecoy.io/v1alpha1
kind: DecoyProfile
metadata:
  name: dev-workstation
  namespace: cicdecoy-system
spec:
  description: "Mid-level developer's Ubuntu workstation"

  system:
    os: "Ubuntu 22.04.3 LTS"
    kernel: "5.15.0-91-generic"
    hostname: "{{ .decoy.identity.hostname }}"  # Templated from parent Decoy
    uptime: "43 days, 7:22"
    timezone: "America/New_York"
    locale: "en_US.UTF-8"

  users:
    - name: admin
      fullName: "Alex Chen"
      groups: ["sudo", "docker", "developers"]
      shell: /bin/bash
      lastLogin: "2024-01-15 09:32:01"
    - name: deploy
      fullName: "Deploy Service"
      groups: ["docker"]
      shell: /bin/bash
      lastLogin: "2024-01-14 03:00:00"

  software:
    packages:
      - { name: "openssh-server", version: "8.9p1" }
      - { name: "docker-ce", version: "24.0.7" }
      - { name: "nodejs", version: "18.19.0" }
      - { name: "python3", version: "3.10.12" }
      - { name: "git", version: "2.34.1" }
      - { name: "kubectl", version: "1.28.4" }
      - { name: "vim", version: "8.2.4919" }
      - { name: "tmux", version: "3.2a" }
    services:
      - { name: "sshd", status: "active", port: 22 }
      - { name: "docker", status: "active" }
      - { name: "cron", status: "active" }
      - { name: "node-app", status: "active", port: 3000 }

  environment:
    variables:
      NODE_ENV: "production"
      DOCKER_HOST: "unix:///var/run/docker.sock"
      KUBECONFIG: "/home/admin/.kube/config"
      AWS_DEFAULT_REGION: "us-east-1"
    crontab:
      - "0 3 * * * /home/deploy/scripts/backup.sh >> /var/log/backup.log 2>&1"
      - "*/5 * * * * /opt/app/healthcheck.sh"

  narrative: |
    This is a developer workstation used by a mid-level engineer named Alex Chen
    on the platform team. The machine runs a Node.js application that serves an
    internal dashboard. Alex uses this box to manage Kubernetes deployments and
    occasionally SSHes to production database servers. Docker is used for local
    development. The machine has been running stably for about 43 days since the
    last system update. There are deployment scripts in /home/deploy/scripts/ and
    the main application lives in /opt/app/. The AWS credentials in ~/.aws/ are
    used for S3 artifact uploads during the CI process.

---

## Supporting Resource: `HoneyToken`

```yaml
apiVersion: cicdecoy.io/v1alpha1
kind: HoneyToken
metadata:
  name: aws-creds-canary-01
  namespace: cicdecoy-system
  labels:
    cicdecoy.io/type: "credential"
    cicdecoy.io/sensitivity: "high"
spec:
  type: aws-credential                   # aws-credential | kubeconfig | api-key
                                         # | database-cred | ssh-key | document
  content:
    template: aws-credentials
    values:
      accessKeyId: "AKIAIOSFODNN7CANARY1"     # Fake but realistic format
      secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bCanaryPurposeKey01"
      region: "us-east-1"

  tracking:
    canaryProvider: custom               # custom | thinkst | aws-cloudtrail
    callbackURL: "https://cti.cicdecoy.internal/honeytoken/trigger"
    customWebhook:
      url: "https://hooks.slack.com/services/..."
      headers:
        X-Token-ID: "aws-creds-canary-01"

  alertOn:
    - apiCall                            # Any AWS API call with these creds
    - networkEgress                      # Creds leave the decoy network
    - credentialStuffing                 # Creds appear in external breach data
```

---

## Fleet Resource: `DecoyFleet`

Deploy many decoys from a single manifest with variance.

```yaml
apiVersion: cicdecoy.io/v1alpha1
kind: DecoyFleet
metadata:
  name: internal-network-sweep
  namespace: decoys-production
spec:
  replicas: 15
  templateRef: "ssh-server"             # Base DecoyTemplate

  variance:
    hostnames:
      pattern: "srv-{{ .zone }}-{{ .seq | printf \"%02d\" }}"
      zones: ["dev", "staging", "prod"]
    ports:
      ssh: [22, 2222, 22222]            # Randomize across these
    profiles:
      pool:                             # Randomly assign from pool
        - "dev-workstation"
        - "db-server"
        - "ci-runner"
        - "legacy-webserver"
    fidelity:
      distribution:                     # 60% tier 1, 30% tier 2, 10% tier 3
        tier1: 0.6
        tier2: 0.3
        tier3: 0.1

  placement:
    spreadAcross: "zones"               # Distribute across network zones
    avoidSubnets:                       # Don't deploy in these ranges
      - "10.0.1.0/24"                   # Real production servers
      - "10.0.2.0/24"                   # Management network

  rotation:
    enabled: true
    interval: 336h                      # Rotate fleet every 2 weeks
    strategy: rolling                   # Replace 20% at a time
    rollPercentage: 20
```

---

## Schema Reference (OpenAPI v3)

```yaml
# Abbreviated schema — key fields with types and validation

Decoy:
  spec:
    service:
      type:        enum [ssh, http, https, smb, mysql, postgres, rdp, ftp, dns, custom]
      port:        integer (1-65535) required
    fidelity:
      tier:        enum [1, 2, 3] required
      scripted:    object (required if tier=2)
      adaptive:    object (required if tier=3)
    identity:
      hostname:    string required maxLength=253
      os.family:   enum [linux, windows] required
    authentication:
      mode:        enum [open, selective, realistic, closed] required
    filesystem:
      base:        string (reference to base filesystem image)
    telemetry:
      sessionCapture:
        fullTranscript:  boolean default=true
    resources:
      requests:    k8s resource requirements
      limits:      k8s resource requirements
    lifecycle:
      rotation:
        interval:  duration string (e.g., "168h")

DecoyProfile:
  spec:
    system:        object required
    users:         array required minItems=1
    software:      object required
    narrative:     string required (LLM system prompt context)

HoneyToken:
  spec:
    type:          enum [aws-credential, kubeconfig, api-key, database-cred, ssh-key, document]
    content:       object required
    tracking:      object required
    alertOn:       array required minItems=1

DecoyFleet:
  spec:
    replicas:      integer required min=1 max=500
    templateRef:   string required
    variance:      object (randomization parameters)
    placement:     object (scheduling constraints)
```

---

## Validation Rules

The CI/CDecoy admission webhook and CI pipeline enforce these rules:

1. **Tier consistency** — If `tier: 3`, `adaptive` config must be present and
   reference a valid `DecoyProfile`. If `tier: 2`, `scripted.responseSet` must exist.
2. **Port conflicts** — No two Decoys in the same namespace can claim the same
   IP + port combination.
3. **Fingerprint coherence** — `identity.os.family: linux` cannot have
   `fingerprint.sshBanner` containing "Windows". TTL must match OS family defaults.
4. **Resource budgets** — Tier 3 decoys must request minimum 256Mi memory.
   Tier 1 decoys cannot request more than 64Mi.
5. **Guardrail presence** — Tier 3 decoys must define `guardrails.filterPatterns`
   with at least the default deny list (honeypot, decoy, AI references).
6. **Honeytoken uniqueness** — Each HoneyToken `accessKeyId` or equivalent
   identifier must be globally unique for tracking purposes.
7. **Fleet limits** — `DecoyFleet.replicas` × resource requests must fit within
   the namespace resource quota.
