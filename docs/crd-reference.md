# CRD Reference

CI/CDecoy defines five Custom Resource Definitions (CRDs) under the `cicdecoy.io` API group. All use `v1alpha1` and are namespaced.

| Kind | Short Name | Purpose |
|------|-----------|---------|
| [Decoy](#decoy) | `dy` | Core deception unit — a single honeypot service |
| [DecoyTemplate](#decoytemplate) | `dt` | Reusable parameterized decoy configuration |
| [DecoyProfile](#decoyprofile) | `dp` | OS personality and fingerprint for Tier 3 decoys |
| [HoneyToken](#honeytoken) | `ht` | Canary credential with trigger tracking |
| [DecoyFleet](#decoyfleet) | `df` | Deploy multiple decoys from a template |

```bash
# Quick access
kubectl get decoys                   # or: kubectl get dy
kubectl get decoytemplates           # or: kubectl get dt
kubectl get decoyprofiles            # or: kubectl get dp
kubectl get honeytokens              # or: kubectl get ht
kubectl get decoyfleets              # or: kubectl get df
kubectl get cicdecoy                 # all CRDs in the cicdecoy category
```

---

## Decoy

The core resource. Each Decoy represents a single honeypot service deployed as a Kubernetes Deployment + Service.

**Printer Columns:** Tier, Service, Zone, Status, Interactions, Age

### Minimal Example

```yaml
apiVersion: cicdecoy.io/v1alpha1
kind: Decoy
metadata:
  name: ssh-bastion-01
spec:
  service:
    type: ssh
    port: 22
  fidelity:
    tier: 2
```

### Full Example

```yaml
apiVersion: cicdecoy.io/v1alpha1
kind: Decoy
metadata:
  name: dev-ws-03
  namespace: decoy-dmz
  labels:
    cicdecoy.io/zone: dmz
spec:
  service:
    type: ssh
    port: 22
    banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
    tlsSecret: decoy-tls-cert

  fidelity:
    tier: 3
    adaptive:
      model: "llama3.1:8b"
      maxLatencyMs: 200
      cacheCommonCommands: true
      inferenceConfig:
        endpoint: "http://inference:8000"
        maxSessionTokens: 8192
        temperature: 0.3
    scriptedResponses: openssh-8.9-responses

  identity:
    hostname: dev-ws-03
    companyName: "Acme Corp"
    os:
      family: linux
      distro: "Ubuntu 22.04.3 LTS"
      kernel: "5.15.0-91-generic"
    profileRef: ubuntu-developer

  authentication:
    mode: selective
    captureAll: true
    allowCredentials:
      - username: admin
        password: admin123
      - username: deploy
        password: d3pl0y!

  http:
    loginPortals: "corporate,aws,gitlab"
    serverHeader: "nginx/1.24.0"

  filesystem:
    base: ubuntu-22.04-minimal
    honeytokens:
      - path: /home/admin/.aws/credentials
        tokenRef: aws-canary-01
      - path: /home/admin/.kube/config
        content: |
          apiVersion: v1
          kind: Config
          clusters:
          - cluster:
              server: https://10.0.1.100:6443

  telemetry:
    sessionCapture:
      fullTranscript: true
      keystrokeTimings: true
      fileUploads: true
    exporter:
      type: nats
      endpoint: nats://nats:4222
      subject: cicdecoy.decoy.events.dev-ws-03

  network:
    expose: loadbalancer
    allowEgressCIDRs:
      - "10.0.0.0/8"
    denyEgressExcept:
      - "decoy-dmz/nats"

  engage:
    activity: EAC0006
    approach: EAP0004
    goal: EGA0004
    hypothesis: "Advanced actors will attempt lateral movement via SSH"
    collection_requirements:
      - "Tool signatures"
      - "Credential reuse patterns"
    null_criteria: "No interactions after 30 days"
```

### Spec Reference

#### service (required)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | enum | Yes | `ssh`, `http`, `https`, `mysql`, `postgres`, `redis`, `smb`, `ftp`, `rdp`, `telnet`, `smtp`, `dns`, `custom` |
| `port` | integer | Yes | 1-65535 |
| `banner` | string | No | Custom service banner (max 256 chars) |
| `tlsSecret` | string | No | Kubernetes Secret name containing TLS cert |

#### fidelity (required)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `tier` | integer | Yes | `1` (beacon), `2` (scripted), `3` (adaptive/LLM) |
| `adaptive` | object | No | Tier 3 configuration (see below) |
| `scriptedResponses` | string | No | ConfigMap name for scripted response database |

**adaptive:**

| Field | Type | Description |
|-------|------|-------------|
| `model` | string | LLM model identifier (max 128 chars, pattern: `^[a-zA-Z0-9._:/-]+$`) |
| `maxLatencyMs` | integer | Maximum acceptable inference latency |
| `cacheCommonCommands` | boolean | Cache deterministic command responses |
| `inferenceConfig.endpoint` | string | Inference service URL (max 2048 chars) |
| `inferenceConfig.maxSessionTokens` | integer | Token budget per session (0-1000000) |
| `inferenceConfig.temperature` | number | Response variability (0.0-2.0) |

#### identity (optional)

| Field | Type | Description |
|-------|------|-------------|
| `hostname` | string | Max 63 chars, pattern: `^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$` |
| `companyName` | string | Company name for HTTP decoy branding (max 256 chars) |
| `os.family` | enum | `linux`, `windows`, `macos`, `network` |
| `os.distro` | string | Distribution name (max 64 chars) |
| `os.kernel` | string | Kernel version (max 128 chars) |
| `profileRef` | string | Reference to a DecoyProfile resource |

#### authentication (optional)

| Field | Type | Description |
|-------|------|-------------|
| `mode` | enum | `open` (accept all), `selective` (predefined only), `realistic` (N failures then accept), `closed` (reject all) |
| `allowCredentials` | array | Max 500 entries. Each: `{username, password}` |
| `captureAll` | boolean | Log all auth attempts regardless of mode |

#### http (optional)

| Field | Type | Description |
|-------|------|-------------|
| `loginPortals` | string | Comma-separated portal types: `corporate`, `aws`, `gitlab`, `jenkins`, `outlook`, `grafana`, `phpmyadmin`, `wordpress` (max 1024 chars) |
| `serverHeader` | string | HTTP Server response header (max 256 chars) |

#### filesystem (optional)

| Field | Type | Description |
|-------|------|-------------|
| `base` | string | Base filesystem skeleton name |
| `honeytokens` | array | Max 100 entries. Each: `{path (max 512), tokenRef, content (max 65536)}` |

#### telemetry (optional)

| Field | Type | Description |
|-------|------|-------------|
| `sessionCapture.fullTranscript` | boolean | Record full command/response transcripts |
| `sessionCapture.keystrokeTimings` | boolean | Record inter-keystroke intervals |
| `sessionCapture.fileUploads` | boolean | Capture uploaded files |
| `exporter.type` | enum | `nats`, `kafka`, `syslog`, `webhook` |
| `exporter.endpoint` | string | Destination URL/address (max 2048 chars) |
| `exporter.subject` | string | NATS subject or topic (max 256 chars, pattern: `^[a-zA-Z0-9._>*-]+$`) |

#### network (optional)

| Field | Type | Description |
|-------|------|-------------|
| `expose` | enum | `clusterip`, `nodeport`, `loadbalancer`, `hostport` |
| `nodePort` | integer | Static NodePort assignment |
| `allowEgressCIDRs` | array | Max 50 CIDRs (pattern: `^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$`) |
| `denyEgressExcept` | array | Max 50 namespace/service pairs |

#### engage (optional)

MITRE Engage framework mapping for strategic intent documentation.

| Field | Type | Description |
|-------|------|-------------|
| `activity` | string | Engage Activity code (e.g., `EAC0006`) |
| `approach` | string | Engage Approach code (e.g., `EAP0004`) |
| `goal` | string | Engage Goal code (e.g., `EGA0004`) |
| `hypothesis` | string | What you expect to learn |
| `collection_requirements` | array | Max 50 strings: what data to collect |
| `null_criteria` | string | When to decommission the decoy |

### Status

| Field | Type | Description |
|-------|------|-------------|
| `phase` | enum | `Pending`, `Deploying`, `Active`, `Degraded`, `Retired` |
| `interactionCount` | integer | Total attacker interactions |
| `lastInteraction` | date-time | Timestamp of most recent interaction |
| `podName` | string | Name of the running Pod |
| `conditions` | array | Standard Kubernetes conditions: `{type, status, lastTransitionTime, reason, message}` |

---

## DecoyTemplate

Reusable decoy configuration with parameterization. Referenced by DecoyFleet and Hydra strategies.

### Example

```yaml
apiVersion: cicdecoy.io/v1alpha1
kind: DecoyTemplate
metadata:
  name: tier2-ssh-workstation
spec:
  description: "Standard SSH workstation decoy for DMZ deployment"
  template:
    service:
      type: ssh
      port: 22
    fidelity:
      tier: 2
    identity:
      os:
        family: linux
        distro: "Ubuntu 22.04 LTS"
    authentication:
      mode: selective
      allowCredentials:
        - username: admin
          password: admin123
    telemetry:
      sessionCapture:
        fullTranscript: true
      exporter:
        type: nats
  parameters:
    - name: hostname
      required: true
      description: "Unique hostname for this decoy"
    - name: zone
      required: false
      default: "dmz"
      description: "Network zone label"
```

### Spec Reference

| Field | Type | Description |
|-------|------|-------------|
| `description` | string | Human-readable description |
| `template` | object | Decoy spec structure (same schema as Decoy.spec) |
| `parameters` | array | Parameterization: `{name, required, default, description}` |

---

## DecoyProfile

OS personality and fingerprint definition. Referenced by Decoy via `spec.identity.profileRef`. Mounted into the inference service as context for LLM response generation.

### Example

```yaml
apiVersion: cicdecoy.io/v1alpha1
kind: DecoyProfile
metadata:
  name: ubuntu-developer
spec:
  description: "Mid-level developer workstation running Ubuntu 22.04"
  os:
    family: linux
    distro: "Ubuntu 22.04.3 LTS"
    kernel: "5.15.0-91-generic"
  packages:
    - name: docker-ce
      version: "24.0.7"
    - name: python3
      version: "3.10.12"
    - name: nodejs
      version: "18.19.0"
    - name: kubectl
      version: "1.28.4"
  users:
    - username: admin
      uid: 1000
      shell: /bin/bash
      home: /home/admin
    - username: deploy
      uid: 1001
      shell: /bin/bash
      home: /home/deploy
  filesystem:
    layout: "ubuntu-22.04-minimal"
    extraPaths:
      - /opt/app
      - /var/lib/docker
      - /home/admin/.docker
  networkFingerprint:
    ttl: 64
    windowSize: 65535
    mss: 1460
    nmap_os_match: "Linux 5.15"
```

### Spec Reference

| Field | Type | Description |
|-------|------|-------------|
| `description` | string | Profile description |
| `os.family` | string | OS family |
| `os.distro` | string | Distribution |
| `os.kernel` | string | Kernel version |
| `packages` | array | `{name, version}` — installed software |
| `users` | array | `{username, uid, shell, home}` — system users |
| `filesystem.layout` | string | Base filesystem OCI image reference |
| `filesystem.extraPaths` | array | Additional directory paths to create |
| `networkFingerprint.ttl` | integer | TCP TTL value |
| `networkFingerprint.windowSize` | integer | TCP window size |
| `networkFingerprint.mss` | integer | TCP MSS |
| `networkFingerprint.nmap_os_match` | string | Expected nmap OS match string |

---

## HoneyToken

Canary credential with lifecycle tracking. Placed in decoy filesystems and monitored for access.

**Printer Columns:** Type, Triggered, Age

### Example

```yaml
apiVersion: cicdecoy.io/v1alpha1
kind: HoneyToken
metadata:
  name: aws-canary-01
  labels:
    cicdecoy.io/type: credential
    cicdecoy.io/sensitivity: high
spec:
  type: aws-key
  value: |
    [default]
    aws_access_key_id = AKIAIOSFODNN7CANARY1
    aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bCanaryKey01
  placement:
    - target: dev-ws-03
      path: /home/admin/.aws/credentials
    - target: ssh-bastion-01
      path: /home/deploy/.aws/credentials
  alertOnAccess: true
  expiresAfter: "720h"
```

### Spec Reference

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | enum | Yes | `aws-key`, `ssh-key`, `api-token`, `database-cred`, `certificate`, `kubeconfig`, `env-var`, `file` |
| `value` | string | No | Token content. Auto-generated if omitted. |
| `placement` | array | No | `{target (decoy name), path (filesystem path)}` |
| `alertOnAccess` | boolean | No | Default `true`. Emit alert when token is accessed. |
| `expiresAfter` | string | No | Duration until expiry (e.g., `720h`, `30d`) |

### Status

| Field | Type | Description |
|-------|------|-------------|
| `triggerCount` | integer | Number of times the token was accessed/used |
| `lastTriggered` | date-time | Most recent trigger timestamp |
| `generatedValue` | string | Auto-generated value (if `value` was omitted) |

---

## DecoyFleet

Deploy multiple decoys from a single template with naming patterns and zone distribution.

**Printer Columns:** Ready, Total, Age

### Example

```yaml
apiVersion: cicdecoy.io/v1alpha1
kind: DecoyFleet
metadata:
  name: dmz-ssh-fleet
spec:
  count: 5
  templateRef: tier2-ssh-workstation
  namingPattern: "{{ .Zone }}-ssh-{{ .Index }}"
  zones:
    - dmz-east
    - dmz-west
  parameterOverrides:
    tier: 2
    port: 22
    replicas: 1
```

### Spec Reference

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `count` | integer | Yes | Number of decoys to create (minimum 1) |
| `templateRef` | string | Yes | Name of DecoyTemplate resource |
| `namingPattern` | string | No | Go template for decoy names. Variables: `.Zone`, `.Index` |
| `zones` | array | No | Zone labels for distribution |
| `parameterOverrides.tier` | integer | No | Override tier (1, 2, or 3) |
| `parameterOverrides.port` | integer | No | Override port (1-65535) |
| `parameterOverrides.replicas` | integer | No | Replicas per decoy (1-10) |

### Status

| Field | Type | Description |
|-------|------|-------------|
| `readyCount` | string | "3/5" format showing ready vs. total |
| `decoys` | array | Names of created Decoy resources |

---

## Implementation Status

| CRD | Operator Reconciliation | CLI Support | Dashboard |
|-----|------------------------|-------------|-----------|
| **Decoy** | Full | deploy, destroy, status, validate | Fleet view |
| **DecoyTemplate** | Not yet (v0.5.0) | Referenced by deploy | Not yet |
| **DecoyProfile** | Not yet (v0.5.0) | profile list/show | Not yet |
| **HoneyToken** | Not yet (v0.2.0) | honeytoken list/triggers | Not yet |
| **DecoyFleet** | Not yet (v0.5.0) | fleet list/scale/rotate | Fleet view (read-only) |
