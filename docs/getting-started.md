# Getting Started

This guide walks you through installing CI/CDecoy on a k3s cluster, deploying your first decoy, and verifying the CTI pipeline is working.

## Prerequisites

**Infrastructure:**
- A k3s cluster (single node is fine for evaluation; 3+ nodes recommended for production)
- At least 8 GB RAM available on the cluster (16 GB recommended)
- 50 GB storage for TimescaleDB and NATS persistence
- `kubectl` configured and connected to your cluster
- Helm 3.x installed

**Optional:**
- A GPU node if you want fast Tier 3 inference (CPU works but is slower)
- MaxMind GeoLite2 license key for GeoIP enrichment
- SIEM credentials (Splunk HEC token, Elastic API key, etc.) for CTI export

## Step 1: Install the Platform

```bash
# Create the system namespace
kubectl create namespace cicdecoy-system

# Label at least one node for platform components
kubectl label node <your-node> cicdecoy.io/role=platform

# Label nodes for decoy workloads (can be the same node for evaluation)
kubectl label node <your-node> cicdecoy.io/role=decoy-node

# Install CI/CDecoy via Helm
helm install cicdecoy oci://ghcr.io/cicdecoy/charts/cicdecoy \
  --namespace cicdecoy-system \
  --wait --timeout 600s
```

For production deployments, use the production values file:

```bash
helm install cicdecoy oci://ghcr.io/cicdecoy/charts/cicdecoy \
  --namespace cicdecoy-system \
  -f values-production.yaml \
  --wait --timeout 600s
```

Verify the installation:

```bash
# All pods should be Running
kubectl get pods -n cicdecoy-system

# Expected output:
# cicdecoy-operator-xxx       1/1  Running
# cicdecoy-inference-xxx      1/1  Running
# cicdecoy-collector-xxx      1/1  Running
# cicdecoy-enrichment-xxx     1/1  Running
# cicdecoy-output-xxx         1/1  Running
# cicdecoy-dashboard-xxx      1/1  Running
# cicdecoy-nats-0             1/1  Running
# cicdecoy-timescaledb-0      1/1  Running
# cicdecoy-ollama-0           1/1  Running

# Or use the CLI
cicdecoy status health
```

## Step 2: Deploy a Tier 1 Beacon

Start simple. A Tier 1 beacon just listens on a port and logs connections. No interactive responses, minimal resources.

```yaml
# tier1-beacon.yaml
apiVersion: cicdecoy.io/v1alpha1
kind: Decoy
metadata:
  name: ssh-beacon-01
  namespace: decoys-production
  labels:
    cicdecoy.io/tier: "1"
    cicdecoy.io/zone: "dmz"
spec:
  service:
    type: ssh
    port: 22
  fidelity:
    tier: 1
  identity:
    hostname: "file-server-07"
    os:
      family: linux
    fingerprint:
      sshBanner: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
  authentication:
    mode: closed
    logAllAttempts: true
  telemetry:
    sessionCapture:
      fullTranscript: true
    exporters:
      - type: nats
        endpoint: "nats://cicdecoy-nats.cicdecoy-system:4222"
        subject: "decoy.events.ssh-beacon-01"
  resources:
    requests:
      cpu: "50m"
      memory: "32Mi"
    limits:
      cpu: "100m"
      memory: "64Mi"
```

```bash
kubectl apply -f tier1-beacon.yaml

# Watch it come online
kubectl get decoy ssh-beacon-01 -n decoys-production -w

# Check it's listening
cicdecoy status decoys
```

## Step 3: Deploy a Tier 2 Scripted Decoy

Tier 2 decoys handle common commands with deterministic responses. More convincing than a beacon but no LLM cost.

```yaml
# tier2-ssh.yaml
apiVersion: cicdecoy.io/v1alpha1
kind: Decoy
metadata:
  name: ssh-scripted-01
  namespace: decoys-production
  labels:
    cicdecoy.io/tier: "2"
spec:
  service:
    type: ssh
    port: 2222
  fidelity:
    tier: 2
    scripted:
      responseSet: "openssh-8.9"
      customResponses:
        - match: "uname -a"
          response: "Linux app-server-02 5.15.0-91-generic #101-Ubuntu SMP x86_64"
        - match: "cat /etc/hostname"
          response: "app-server-02"
  identity:
    hostname: "app-server-02"
    os:
      family: linux
      distribution: "Ubuntu"
      version: "22.04 LTS"
    fingerprint:
      sshBanner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
  authentication:
    mode: selective
    credentials:
      - username: deploy
        password: "d3pl0y_2024"
        shell: /bin/bash
        home: /home/deploy
    logAllAttempts: true
  telemetry:
    sessionCapture:
      fullTranscript: true
      keystrokeTimings: true
    exporters:
      - type: nats
        endpoint: "nats://cicdecoy-nats.cicdecoy-system:4222"
        subject: "decoy.events.ssh-scripted-01"
```

```bash
kubectl apply -f tier2-ssh.yaml

# Test it (from another machine or pod):
ssh deploy@<decoy-ip> -p 2222
# Password: d3pl0y_2024
```

## Step 4: Deploy a Tier 3 Adaptive Decoy

This is the high-fidelity experience. First, create a profile that defines the decoy's personality, then reference it in the decoy manifest.

```yaml
# profile.yaml
apiVersion: cicdecoy.io/v1alpha1
kind: DecoyProfile
metadata:
  name: dev-workstation
  namespace: cicdecoy-system
spec:
  description: "Developer workstation with common tools"
  system:
    os: "Ubuntu 22.04.3 LTS"
    kernel: "5.15.0-91-generic"
    uptime: "67 days, 3:14"
  users:
    - name: jchen
      fullName: "Jamie Chen"
      groups: ["sudo", "docker", "developers"]
      shell: /bin/bash
  software:
    packages:
      - { name: "openssh-server", version: "8.9p1" }
      - { name: "docker-ce", version: "24.0.7" }
      - { name: "python3", version: "3.10.12" }
      - { name: "nodejs", version: "18.19.0" }
      - { name: "git", version: "2.34.1" }
    services:
      - { name: "sshd", status: "active", port: 22 }
      - { name: "docker", status: "active" }
  narrative: |
    A mid-level developer's workstation. Jamie uses this for Python
    and Node.js development, with Docker for local testing. There are
    project repos in ~/projects/ and some deployment scripts.
```

```yaml
# tier3-adaptive.yaml
apiVersion: cicdecoy.io/v1alpha1
kind: Decoy
metadata:
  name: ssh-adaptive-01
  namespace: decoys-production
  labels:
    cicdecoy.io/tier: "3"
spec:
  service:
    type: ssh
    port: 22
  fidelity:
    tier: 3
    adaptive:
      profileRef: "dev-workstation"
      inferenceConfig:
        maxSessionTokens: 8192
        temperature: 0.3
      fastPath:
        enabled: true
        commands:
          - { match: "^ls", source: filesystem }
          - { match: "^pwd$", source: state }
          - { match: "^whoami$", source: state }
          - { match: "^cat /etc/", source: profile }
      guardrails:
        preventRealCommands: true
        filterPatterns:
          - "(?i)honeypot"
          - "(?i)decoy"
          - "(?i)I('m| am) an AI"
          - "(?i)language model"
        maxResponseLines: 500
  identity:
    hostname: "dev-ws-03"
    os:
      family: linux
      distribution: "Ubuntu"
      version: "22.04.3 LTS"
  authentication:
    mode: realistic
    credentials:
      - username: jchen
        password: "Jch3n_2024!"
        shell: /bin/bash
        uid: 1000
        home: /home/jchen
    realisticAuth:
      failBeforeSuccess: 1
  telemetry:
    sessionCapture:
      fullTranscript: true
      keystrokeTimings: true
      fileUploads: true
    exporters:
      - type: nats
        endpoint: "nats://cicdecoy-nats.cicdecoy-system:4222"
        subject: "decoy.events.ssh-adaptive-01"
    alerting:
      immediateAlert:
        - event: auth.success
          severity: high
        - event: command.exec
          patterns: ["wget|curl.*http", "chmod.*\\+x", "ssh.*@"]
          severity: critical
  resources:
    requests:
      cpu: "200m"
      memory: "256Mi"
    limits:
      cpu: "1000m"
      memory: "1Gi"
```

```bash
kubectl apply -f profile.yaml
kubectl apply -f tier3-adaptive.yaml

# Wait for it to be ready
kubectl wait --for=condition=ready decoy ssh-adaptive-01 \
  -n decoys-production --timeout=120s
```

## Step 5: Verify the CTI Pipeline

```bash
# Open the dashboard
kubectl port-forward svc/cicdecoy-dashboard 3000:3000 -n cicdecoy-system
# Open http://localhost:3000

# Watch for events
cicdecoy sessions watch

# After some interactions, check for generated intelligence
cicdecoy intel iocs --since 1h
cicdecoy intel mitre

# Export STIX bundle
cicdecoy intel export --format stix -o /tmp/cicdecoy-intel.json
```

## Step 6: Validate Decoy Fidelity

Before deploying to production, validate your decoys pass fidelity tests:

```bash
# Lint manifests
cicdecoy validate -d decoys/deployments/production/

# Run fidelity tests against staging
cicdecoy validate -d decoys/deployments/staging/ --fidelity-test

# Manual nmap check
nmap -sV -O -p 22 <decoy-ip>
# Should identify as the configured OS, not as a honeypot
```

## What's Next

- Read [Decoy Authoring](decoy-authoring.md) to learn the full manifest schema
- Read [Profile Authoring](profile-authoring.md) to create convincing Tier 3 personalities
- Set up [CTI Integration](cti-integration.md) to push intelligence to your SIEM
- Review the [Threat Model](threat-model.md) for security considerations
- Use `DecoyFleet` resources to deploy many decoys at scale
