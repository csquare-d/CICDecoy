# Falco Integration — Container Escape Detection

CI/CDecoy uses [Falco](https://falco.org) to detect container escape attempts from decoy pods. When an attacker breaks out of the application-layer deception and interacts with the real container OS, Falco detects the kernel-level syscalls and routes alerts through the CTI pipeline for correlation with the active decoy session.

## Architecture

```
Falco (eBPF on each node)
    ↓ syscall alerts
falcosidekick
    ↓ NATS publish
cicdecoy.security.falco.{node}.{pod}
    ↓ FALCO_ALERTS stream
CTI Pipeline (falco_correlator.py)
    ↓ correlated alert
TimescaleDB (falco_alerts table)
```

## What It Detects

| Rule | Severity | ATT&CK | Description |
|------|----------|--------|-------------|
| Write to kernel interface | CRITICAL | T1611 | Writes to /proc/sys, /sys, /dev |
| Mount syscall | CRITICAL | T1611 | mount() from decoy container |
| Ptrace | CRITICAL | T1055 | ptrace() across namespace boundary |
| Kernel module load | CRITICAL | T1611 | init_module/finit_module from container |
| Unexpected shell | CRITICAL | T1059.004 | Real shell spawn (not emulated) |
| Outbound to internal | CRITICAL | T1021 | Lateral movement from decoy |
| Internet connection | CRITICAL | T1048 | Any non-RFC1918 egress |
| Escape recon | WARNING | T1082 | Reads .dockerenv, /proc/1/cgroup, etc. |
| Privilege escalation | CRITICAL | T1548 | setuid/setgid/capset from decoy |
| Binary execution | HIGH | T1204.002 | Unknown binary runs in container |

## Prerequisites

- Kubernetes cluster (k3s, EKS, GKE, etc.)
- CI/CDecoy deployed via Helm chart
- Helm 3.x

Falco is **not bundled** with CI/CDecoy. It runs as a DaemonSet on every node and needs kernel-level access (eBPF). This is intentional, most organizations already have Falco or a similar runtime security tool, and bundling it would create conflicts.

## Quick Start

### 1. Install Falco + falcosidekick

```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update

helm install falco falcosecurity/falco \
  --namespace cicdecoy-falco \
  --create-namespace \
  --set driver.kind=ebpf \
  --set falcosidekick.enabled=true \
  --set "falcosidekick.config.nats.hostport=cicdecoy-nats.cicdecoy-system.svc.cluster.local:4222" \
  --set "falcosidekick.config.nats.minimumpriority=warning" \
  --set tty=true
```

### 2. Load CI/CDecoy custom rules

The custom rules file detects escape-specific behaviors scoped to decoy pods:

```bash
# Copy rules to the Falco ConfigMap
kubectl create configmap cicdecoy-falco-rules \
  --from-file=cicdecoy-rules.yaml=config/falco-rules.yaml \
  --namespace cicdecoy-falco

# Patch Falco to mount the custom rules
kubectl patch daemonset falco -n cicdecoy-falco --type=json -p='[
  {"op": "add", "path": "/spec/template/spec/volumes/-", "value": {"name": "cicdecoy-rules", "configMap": {"name": "cicdecoy-falco-rules"}}},
  {"op": "add", "path": "/spec/template/spec/containers/0/volumeMounts/-", "value": {"name": "cicdecoy-rules", "mountPath": "/etc/falco/rules.d/cicdecoy-rules.yaml", "subPath": "cicdecoy-rules.yaml"}}
]'
```

Or use a values file for a cleaner install:

```yaml
# platform/falco/values.yaml
driver:
  kind: ebpf

falco:
  rules_file:
    - /etc/falco/falco_rules.yaml
    - /etc/falco/rules.d/cicdecoy-rules.yaml
  json_output: true
  json_include_output_property: true

customRules:
  cicdecoy-rules.yaml: |
    # Paste contents of config/falco-rules.yaml here

falcosidekick:
  enabled: true
  config:
    nats:
      hostport: "cicdecoy-nats.cicdecoy-system.svc.cluster.local:4222"
      minimumpriority: "warning"
```

### 3. Verify the pipeline

```bash
# Check Falco is running
kubectl get pods -n cicdecoy-falco

# Check NATS stream exists
kubectl exec -it deploy/cicdecoy-nats -n cicdecoy-system -- \
  nats stream info FALCO_ALERTS

# Check correlator is subscribed
kubectl logs deploy/cicdecoy-cti-pipeline -n cicdecoy-system | grep -i falco

# Watch for alerts
kubectl exec -it deploy/cicdecoy-nats -n cicdecoy-system -- \
  nats sub "cicdecoy.security.falco.>" --last=10
```

### 4. Enable in Helm values

Falco correlation is enabled by default in the CTI pipeline:

```yaml
# values.yaml
ctiPipeline:
  falcoCorrelator:
    enabled: true
    subject: "cicdecoy.security.falco.>"
```

## Local Development (docker-compose)

For local testing without Kubernetes, use the `security` profile:

```bash
docker compose --profile security up -d
```

This starts falcosidekick and a test event generator that publishes sample Falco alerts to NATS. You can also manually inject test alerts:

```bash
make falco-test
```

Query the database for correlated alerts:

```bash
make db-falco
make db-escapes
```

## How Correlation Works

When a Falco alert arrives:

1. **Pod extraction** — the correlator extracts `k8s.pod.name` from the alert
2. **Session lookup** — queries `decoy_events` for active sessions on that pod (1-hour lookback)
3. **ATT&CK mapping** — maps the Falco rule to MITRE ATT&CK techniques
4. **Engage update** — sets `deception_maintained = false` and `escape_attempted = true`
5. **Event injection** — writes a synthetic `escape_attempt` event to the session timeline
6. **Storage** — persists the raw alert to `falco_alerts` table with correlation metadata

This gives IR teams the complete picture: application-layer TTPs + kernel-layer escape attempts in a single session timeline.

## Network Policy Considerations

If `networkPolicy.enabled: true` in your values, ensure falcosidekick can reach NATS. The default policy allows egress to port 4222 within `10.0.0.0/8`. If Falco runs in a separate namespace, you may need to add an explicit NetworkPolicy:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-falcosidekick-to-nats
  namespace: cicdecoy-falco
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: falcosidekick
  policyTypes: [Egress]
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              app.kubernetes.io/part-of: cicdecoy
      ports:
        - port: 4222
          protocol: TCP
```

## Troubleshooting

| Problem | Check |
|---------|-------|
| No alerts in NATS | `kubectl logs -n cicdecoy-falco deploy/falco-falcosidekick` — verify NATS connection |
| Alerts arrive but not correlated | CTI pipeline logs — ensure `FALCO_ENABLED=true` and pod names match |
| Falco not detecting events | `kubectl logs -n cicdecoy-falco ds/falco` — check eBPF driver loaded |
| Rules not loading | `kubectl exec ds/falco -n cicdecoy-falco -- falco --list` — verify custom rules mounted |
