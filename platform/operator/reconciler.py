"""
CI/CDecoy Operator — Reconciler

Watches Decoy custom resources and reconciles them into:
  1. A Deployment (decoy container + telemetry sidecar)
  2. A Service (exposing the decoy port)
  3. A NetworkPolicy (per-decoy egress rules if specified)

Built on kopf (Kubernetes Operator Pythonic Framework).
"""

import json
import logging
import os
import re
from datetime import UTC, datetime
from pathlib import Path

import kopf
import kubernetes
import yaml

logger = logging.getLogger("cicdecoy.operator")

# Characters that must not appear in Kubernetes env-var values injected
# from CRD specs. Newlines could inject additional env vars; control
# characters have no legitimate use in these fields.
_UNSAFE_ENV_RE = re.compile(r"[\x00-\x1f\x7f\u2028\u2029]")


def _sanitize_env_value(value: str) -> str:
    """Strip control characters (including newlines) from env var values."""
    return _UNSAFE_ENV_RE.sub("", value)


def _infer_token_type(path: str, content: str) -> str:
    """Infer honeytoken type from file path and content patterns."""
    p = path.lower()
    c = (content or "")[:500]  # safe version, not lowered (for case-sensitive checks like AKIA)
    c_lower = c.lower()
    if ".aws/credentials" in p or "AKIA" in c:
        return "aws-key"
    if any(k in p for k in ("id_rsa", "id_ed25519", "id_ecdsa")) or ("BEGIN" in c[:50] and "PRIVATE KEY" in c[:100]):
        return "ssh-key"
    if p.endswith(".env") or "DATABASE_URL=" in c or "SECRET_KEY=" in c:
        return "env-var"
    if ".kube/config" in p or "kubeconfig" in p:
        return "kubeconfig"
    if any(k in p for k in (".pgpass", "credentials", "password")):
        return "database-cred"
    if any(k in c_lower for k in ("api_key", "api-key", "bearer", "token")):
        return "api-token"
    return "file"


# Service URLs — read from env vars set by the Helm chart so that
# non-default release names resolve correctly.
NATS_URL = os.environ.get("NATS_URL", "nats://cicdecoy-nats:4222")
NATS_TOKEN = os.environ.get("NATS_TOKEN", "")
INFERENCE_URL = os.environ.get("INFERENCE_URL", "http://cicdecoy-inference:8000")

# Loaded from /etc/cicdecoy/images.yaml (mounted ConfigMap)
IMAGE_CONFIG: dict = {}
TELEMETRY_SIDECAR_IMAGE: str = ""


@kopf.on.startup()
def configure(settings: kopf.OperatorSettings, **_):
    settings.posting.enabled = True
    settings.persistence.finalizer = "cicdecoy.io/finalizer"
    # Load image config
    global IMAGE_CONFIG, TELEMETRY_SIDECAR_IMAGE
    config_path = Path("/etc/cicdecoy/images.yaml")
    if config_path.exists():
        IMAGE_CONFIG = yaml.safe_load(config_path.read_text())
        TELEMETRY_SIDECAR_IMAGE = IMAGE_CONFIG.pop("telemetrySidecar", "")
    logger.info("Operator started, image config loaded: %s", list(IMAGE_CONFIG.keys()))


def _build_credentials_secret(name: str, namespace: str, credentials: list) -> dict:
    """Build a Secret manifest for decoy credentials."""
    secret_name = f"{name}-credentials"
    return {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {"name": secret_name, "namespace": namespace},
        "type": "Opaque",
        "stringData": {"credentials": json.dumps(credentials)},
    }


def _build_decoy_deployment(name: str, namespace: str, spec: dict, labels: dict) -> dict:
    """Translate a Decoy spec into a Deployment manifest."""
    svc_type = spec["service"]["type"]
    port = spec["service"]["port"]
    tier = spec["fidelity"]["tier"]
    image = IMAGE_CONFIG.get(svc_type)
    if not image:
        image = IMAGE_CONFIG.get("fallback", "busybox")
        logger.warning(
            "Decoy %s: no image configured for type '%s', using fallback: %s",
            name,
            svc_type,
            image,
        )

    # Environment variables derived from the decoy spec
    env = [
        {"name": "DECOY_NAME", "value": name},
        {"name": "DECOY_SERVICE_TYPE", "value": svc_type},
        {"name": "DECOY_PORT", "value": str(port)},
        {"name": "DECOY_TIER", "value": str(tier)},
        {"name": "NATS_URL", "value": NATS_URL},
        {"name": "NATS_ENDPOINT", "value": NATS_URL},
        *([{"name": "NATS_TOKEN", "value": NATS_TOKEN}] if NATS_TOKEN else []),
    ]
    env.append({"name": "METRICS_PORT", "value": "9091"})

    if spec["service"].get("banner"):
        env.append({"name": "DECOY_BANNER", "value": _sanitize_env_value(spec["service"]["banner"])})

    identity = spec.get("identity", {})
    if identity.get("hostname"):
        env.append({"name": "DECOY_HOSTNAME", "value": _sanitize_env_value(identity["hostname"])})
    if identity.get("os", {}).get("distro"):
        env.append({"name": "DECOY_OS_DISTRO", "value": _sanitize_env_value(identity["os"]["distro"])})
    if identity.get("profileRef"):
        env.append({"name": "DECOY_PROFILE_REF", "value": _sanitize_env_value(identity["profileRef"])})

    auth = spec.get("authentication", {})
    if auth.get("mode"):
        env.append({"name": "DECOY_AUTH_MODE", "value": _sanitize_env_value(auth["mode"])})
    if auth.get("allowCredentials"):
        secret_name = f"{name}-credentials"
        env.append(
            {
                "name": "DECOY_CREDENTIALS",
                "valueFrom": {"secretKeyRef": {"name": secret_name, "key": "credentials"}},
            }
        )

    # Tier 3 adaptive config
    adaptive = spec.get("fidelity", {}).get("adaptive", {})
    if adaptive:
        env.append({"name": "DECOY_ADAPTIVE_MODEL", "value": _sanitize_env_value(adaptive.get("model", ""))})
        env.append({"name": "DECOY_MAX_LATENCY_MS", "value": str(adaptive.get("maxLatencyMs", 200))})
        env.append({"name": "INFERENCE_URL", "value": INFERENCE_URL})

    # HTTP / HTTPS decoy overrides
    if svc_type in ("http", "https"):
        image = IMAGE_CONFIG.get(svc_type, IMAGE_CONFIG.get("http", image))
        http_spec = spec.get("http", {})
        env.extend(
            [
                {"name": "NATS_URL", "value": NATS_URL},
                {"name": "HTTP_PORT", "value": str(port)},
                {"name": "COMPANY_NAME", "value": _sanitize_env_value(identity.get("companyName", "Acme Corp"))},
                {
                    "name": "LOGIN_PORTALS",
                    "value": _sanitize_env_value(http_spec.get("loginPortals", "corporate,aws,gitlab")),
                },
                {"name": "SERVER_HEADER", "value": _sanitize_env_value(http_spec.get("serverHeader", "nginx/1.24.0"))},
            ]
        )
        exporter_cfg = spec.get("telemetry", {}).get("exporter", {})
        if exporter_cfg.get("subject"):
            env.append({"name": "NATS_SUBJECT", "value": _sanitize_env_value(exporter_cfg["subject"])})
        # Override METRICS_PORT for HTTP decoys
        for e in env:
            if e.get("name") == "METRICS_PORT":
                e["value"] = "9092"
                break

    # Honeytoken manifest — serialize inline honeytokens for the decoy to seed
    honeytokens = spec.get("filesystem", {}).get("honeytokens", [])
    if honeytokens:
        manifest = []
        for ht in honeytokens:
            ht_path = ht.get("path", "")
            ht_content = ht.get("content", "")
            if not ht_path:
                continue
            manifest.append(
                {
                    "path": ht_path,
                    "content": ht_content,
                    "token_name": ht.get("tokenRef") or os.path.basename(ht_path).replace(".", "-"),
                    "token_type": _infer_token_type(ht_path, ht_content),
                    "alert_on_access": ht.get("alertOnAccess", True),
                }
            )
        if manifest:
            manifest_json = json.dumps(manifest)
            if len(manifest_json.encode()) > 262144:  # 256 KiB
                logger.warning(
                    "Decoy %s: HONEYTOKEN_MANIFEST is %d bytes (max 256KiB); "
                    "consider reducing honeytoken count or content size",
                    name,
                    len(manifest_json.encode()),
                )
            env.append(
                {
                    "name": "HONEYTOKEN_MANIFEST",
                    "value": manifest_json,
                }
            )

    # Main decoy container
    container_ports = [{"containerPort": port, "name": "service"}]
    metrics_port = 9092 if svc_type in ("http", "https") else 9091
    container_ports.append({"containerPort": metrics_port, "name": "metrics"})

    decoy_container = {
        "name": "decoy",
        "image": image,
        "ports": container_ports,
        "env": env,
        "resources": {
            "requests": {"cpu": "50m", "memory": "64Mi"},
            "limits": {"cpu": "200m", "memory": "128Mi"},
        },
        "securityContext": {
            "allowPrivilegeEscalation": False,
            "readOnlyRootFilesystem": True,
            "runAsNonRoot": True,
            "runAsUser": 65532,
            "capabilities": {"drop": ["ALL"]},
        },
        "volumeMounts": [
            {"name": "tmp", "mountPath": "/tmp"},
            {"name": "data", "mountPath": "/var/lib/cicdecoy"},
        ],
    }

    # SSH decoy probes: TCP check on the service port
    if svc_type == "ssh":
        decoy_container["readinessProbe"] = {
            "tcpSocket": {"port": port},
            "initialDelaySeconds": 5,
            "periodSeconds": 10,
        }
        decoy_container["livenessProbe"] = {
            "tcpSocket": {"port": port},
            "initialDelaySeconds": 15,
            "periodSeconds": 30,
        }

    # HTTP decoy health probes
    if svc_type in ("http", "https"):
        health_probe = {
            "httpGet": {"path": "/api/v1/health", "port": port},
        }
        decoy_container["livenessProbe"] = health_probe
        decoy_container["readinessProbe"] = health_probe

    # Telemetry sidecar
    telemetry_env = [
        {"name": "DECOY_NAME", "value": name},
        {"name": "NATS_URL", "value": NATS_URL},
    ]
    exporter = spec.get("telemetry", {}).get("exporter", {})
    if exporter.get("subject"):
        telemetry_env.append({"name": "NATS_SUBJECT", "value": _sanitize_env_value(exporter["subject"])})
    session = spec.get("telemetry", {}).get("sessionCapture", {})
    if session.get("fullTranscript"):
        telemetry_env.append({"name": "CAPTURE_TRANSCRIPT", "value": "true"})
    if session.get("keystrokeTimings"):
        telemetry_env.append({"name": "CAPTURE_KEYSTROKES", "value": "true"})
    if session.get("fileUploads"):
        telemetry_env.append({"name": "CAPTURE_FILE_UPLOADS", "value": "true"})

    sidecar = {
        "name": "telemetry",
        "image": TELEMETRY_SIDECAR_IMAGE,
        "env": telemetry_env,
        "resources": {
            "requests": {"cpu": "25m", "memory": "32Mi"},
            "limits": {"cpu": "100m", "memory": "64Mi"},
        },
        "securityContext": {
            "allowPrivilegeEscalation": False,
            "readOnlyRootFilesystem": True,
            "runAsNonRoot": True,
            "runAsUser": 65532,
            "capabilities": {"drop": ["ALL"]},
        },
        "livenessProbe": {
            "exec": {
                "command": ["python", "-c", "import os; os.kill(1, 0)"],
            },
            "initialDelaySeconds": 10,
            "periodSeconds": 30,
        },
    }

    managed_labels = {
        **labels,
        "cicdecoy.io/managed": "true",
        "cicdecoy.io/decoy": name,
        "cicdecoy.io/tier": str(tier),
        "cicdecoy.io/service-type": svc_type,
    }

    # Validate hostname: RFC 1123 (lowercase alphanumeric, hyphens, max 63 chars)
    hostname = identity.get("hostname", name)
    if not re.match(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", hostname):
        logger.warning(
            "Decoy %s: invalid hostname '%s', using name as fallback",
            name,
            identity.get("hostname"),
        )
        hostname = name

    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": f"decoy-{name}",
            "namespace": namespace,
            "labels": managed_labels,
            "ownerReferences": [],  # filled by kopf
        },
        "spec": {
            "replicas": 1,
            "selector": {"matchLabels": {"cicdecoy.io/decoy": name}},
            "template": {
                "metadata": {"labels": managed_labels},
                "spec": {
                    "hostname": hostname,
                    "securityContext": {
                        "runAsNonRoot": True,
                        "runAsUser": 65532,
                        "fsGroup": 65532,
                    },
                    "automountServiceAccountToken": False,
                    "containers": [decoy_container] + ([sidecar] if TELEMETRY_SIDECAR_IMAGE else []),
                    "volumes": [
                        {"name": "tmp", "emptyDir": {"sizeLimit": "64Mi"}},
                        {"name": "data", "emptyDir": {"sizeLimit": "16Mi"}},
                    ],
                },
            },
        },
    }


def _build_service(name: str, namespace: str, spec: dict, labels: dict) -> dict:
    """Build a Service for the decoy."""
    port = spec["service"]["port"]
    network = spec.get("network", {})
    svc_type_map = {
        "clusterip": "ClusterIP",
        "nodeport": "NodePort",
        "loadbalancer": "LoadBalancer",
    }
    expose = network.get("expose", "clusterip")
    k8s_type = svc_type_map.get(expose, "ClusterIP")

    svc = {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": f"decoy-{name}",
            "namespace": namespace,
            "labels": {**labels, "cicdecoy.io/managed": "true"},
        },
        "spec": {
            "type": k8s_type,
            "selector": {"cicdecoy.io/decoy": name},
            "ports": [{"name": "service", "port": port, "targetPort": port}],
        },
    }
    if expose == "nodeport" and network.get("nodePort"):
        svc["spec"]["ports"][0]["nodePort"] = network["nodePort"]
    return svc


# ---------------------------------------------------------------------------
# Reconciliation handlers
# ---------------------------------------------------------------------------


@kopf.on.create("cicdecoy.io", "v1alpha1", "decoys")
@kopf.on.update("cicdecoy.io", "v1alpha1", "decoys")
def reconcile_decoy(spec, name, namespace, labels, status, patch, **_):
    """Main reconciliation loop for Decoy resources."""
    logger.info("Reconciling Decoy %s/%s", namespace, name)

    # Validate required spec fields early
    try:
        _ = spec["service"]["type"]
        _ = spec["service"]["port"]
        _ = spec["fidelity"]["tier"]
    except KeyError as e:
        logger.error("Decoy %s: missing required spec field: %s", name, e)
        patch.status["phase"] = "Error"
        patch.status["message"] = f"Missing required field: {e}"
        return

    api = kubernetes.client.AppsV1Api()
    core = kubernetes.client.CoreV1Api()

    try:
        # Build desired state
        deployment = _build_decoy_deployment(name, namespace, spec, labels or {})
        service = _build_service(name, namespace, spec, labels or {})

        # Create/update credentials secret if needed
        auth = spec.get("authentication", {})
        if auth.get("allowCredentials"):
            secret = _build_credentials_secret(name, namespace, auth["allowCredentials"])
            secret_name = f"{name}-credentials"
            try:
                try:
                    core.read_namespaced_secret(secret_name, namespace)
                    kopf.adopt(secret)
                    core.patch_namespaced_secret(secret_name, namespace, secret)
                    logger.info("Updated credentials secret %s", secret_name)
                except kubernetes.client.ApiException as e:
                    if e.status == 404:
                        kopf.adopt(secret)
                        core.create_namespaced_secret(namespace, secret)
                        logger.info("Created credentials secret %s", secret_name)
                    else:
                        raise
            except Exception as e:
                logger.error("Failed to create credentials secret for %s: %s", name, e)
                patch.status["phase"] = "Error"
                patch.status["message"] = f"Secret creation failed: {e}"
                return

        # Apply deployment
        dep_name = f"decoy-{name}"
        try:
            try:
                api.read_namespaced_deployment(dep_name, namespace)
                kopf.adopt(deployment)
                api.patch_namespaced_deployment(dep_name, namespace, deployment)
                logger.info("Updated deployment %s", dep_name)
            except kubernetes.client.ApiException as e:
                if e.status == 404:
                    kopf.adopt(deployment)
                    api.create_namespaced_deployment(namespace, deployment)
                    logger.info("Created deployment %s", dep_name)
                else:
                    raise
        except Exception as e:
            logger.error("Failed to create deployment for %s: %s", name, e)
            patch.status["phase"] = "Error"
            patch.status["message"] = f"Deployment creation failed: {e}"
            return

        # Apply service
        try:
            try:
                core.read_namespaced_service(dep_name, namespace)
                kopf.adopt(service)
                core.patch_namespaced_service(dep_name, namespace, service)
            except kubernetes.client.ApiException as e:
                if e.status == 404:
                    kopf.adopt(service)
                    core.create_namespaced_service(namespace, service)
                else:
                    raise
        except Exception as e:
            logger.error("Failed to create service for %s: %s", name, e)
            patch.status["phase"] = "Error"
            patch.status["message"] = f"Service creation failed: {e}"
            return

        # Check deployment readiness before marking Active
        try:
            dep = api.read_namespaced_deployment(dep_name, namespace)
            ready = (dep.status.ready_replicas or 0) >= (dep.spec.replicas or 1)
        except Exception:
            ready = False

        if ready:
            patch.status["phase"] = "Active"
            patch.status["conditions"] = [
                {
                    "type": "Ready",
                    "status": "True",
                    "lastTransitionTime": datetime.now(UTC).isoformat(),
                    "reason": "ReconcileSuccess",
                    "message": "Decoy pod and service created successfully",
                }
            ]
            logger.info("Decoy %s/%s reconciled → Active", namespace, name)
        else:
            patch.status["phase"] = "Deploying"
            patch.status["conditions"] = [
                {
                    "type": "Ready",
                    "status": "False",
                    "lastTransitionTime": datetime.now(UTC).isoformat(),
                    "reason": "WaitingForPods",
                    "message": "Deployment created, waiting for pods to be ready",
                }
            ]
            logger.info("Decoy %s/%s reconciled → Deploying (waiting for pods)", namespace, name)
        patch.status["podName"] = dep_name

    except kubernetes.client.ApiException as e:
        # Transient API errors (429 rate-limited, 5xx server errors) —
        # let kopf retry with exponential backoff instead of marking
        # the Decoy as permanently failed.
        if e.status in (429, 500, 502, 503, 504):
            logger.warning(
                "Transient API error for Decoy %s/%s: %s %s — will retry",
                namespace,
                name,
                e.status,
                e.reason,
            )
            raise kopf.TemporaryError(
                f"Transient Kubernetes API error: {e.status} {e.reason}",
                delay=min(30, 5 * 2),  # Retry after 10s, kopf applies its own backoff
            ) from e
        # Permanent API errors (400, 403, 404, 409, 422) — mark as Error
        patch.status["phase"] = "Error"
        patch.status["conditions"] = [
            {
                "type": "Ready",
                "status": "False",
                "lastTransitionTime": datetime.now(UTC).isoformat(),
                "reason": "KubernetesAPIError",
                "message": f"Kubernetes API error: {e.status} {e.reason}",
            }
        ]
        logger.error("Permanent API error for Decoy %s/%s: %s %s", namespace, name, e.status, e.reason)
    except (ConnectionError, TimeoutError, OSError) as e:
        # Network-level failures — always transient
        logger.warning(
            "Network error reconciling Decoy %s/%s: %s — will retry",
            namespace,
            name,
            e,
        )
        raise kopf.TemporaryError(
            f"Network error: {e}",
            delay=15,
        ) from e
    except Exception:
        patch.status["phase"] = "Error"
        patch.status["conditions"] = [
            {
                "type": "Ready",
                "status": "False",
                "lastTransitionTime": datetime.now(UTC).isoformat(),
                "reason": "ReconcileError",
                "message": "Reconciliation failed unexpectedly",
            }
        ]
        logger.exception("Failed to reconcile Decoy %s/%s", namespace, name)
        raise


@kopf.on.delete("cicdecoy.io", "v1alpha1", "decoys")
def delete_decoy(name, namespace, **_):
    """Cleanup on Decoy deletion — owned resources are garbage collected by k8s."""
    logger.info("Decoy %s/%s deleted, owned resources will be GC'd", namespace, name)
