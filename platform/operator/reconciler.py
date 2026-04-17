"""
CI/CDecoy Operator — Reconciler

Watches Decoy custom resources and reconciles them into:
  1. A Deployment (decoy container + telemetry sidecar)
  2. A Service (exposing the decoy port)
  3. A NetworkPolicy (per-decoy egress rules if specified)

Built on kopf (Kubernetes Operator Pythonic Framework).
"""

import logging
from datetime import datetime, timezone
from pathlib import Path

import kopf
import kubernetes
import yaml

logger = logging.getLogger("cicdecoy.operator")

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


def _build_decoy_deployment(name: str, namespace: str, spec: dict, labels: dict) -> dict:
    """Translate a Decoy spec into a Deployment manifest."""
    svc_type = spec["service"]["type"]
    port = spec["service"]["port"]
    tier = spec["fidelity"]["tier"]
    image = IMAGE_CONFIG.get(svc_type, IMAGE_CONFIG.get("fallback", "busybox"))

    # Environment variables derived from the decoy spec
    env = [
        {"name": "DECOY_NAME", "value": name},
        {"name": "DECOY_SERVICE_TYPE", "value": svc_type},
        {"name": "DECOY_PORT", "value": str(port)},
        {"name": "DECOY_TIER", "value": str(tier)},
    ]
    env.append({"name": "METRICS_PORT", "value": "9091"})

    if spec["service"].get("banner"):
        env.append({"name": "DECOY_BANNER", "value": spec["service"]["banner"]})

    identity = spec.get("identity", {})
    if identity.get("hostname"):
        env.append({"name": "DECOY_HOSTNAME", "value": identity["hostname"]})
    if identity.get("os", {}).get("distro"):
        env.append({"name": "DECOY_OS_DISTRO", "value": identity["os"]["distro"]})
    if identity.get("profileRef"):
        env.append({"name": "DECOY_PROFILE_REF", "value": identity["profileRef"]})

    auth = spec.get("authentication", {})
    if auth.get("mode"):
        env.append({"name": "DECOY_AUTH_MODE", "value": auth["mode"]})
    if auth.get("allowCredentials"):
        import json
        env.append({"name": "DECOY_CREDENTIALS", "value": json.dumps(auth["allowCredentials"])})

    # Tier 3 adaptive config
    adaptive = spec.get("fidelity", {}).get("adaptive", {})
    if adaptive:
        env.append({"name": "DECOY_ADAPTIVE_MODEL", "value": adaptive.get("model", "")})
        env.append({"name": "DECOY_MAX_LATENCY_MS", "value": str(adaptive.get("maxLatencyMs", 200))})
        env.append({"name": "INFERENCE_URL", "value": "http://cicdecoy-inference:8000"})

    # HTTP / HTTPS decoy overrides
    if svc_type in ("http", "https"):
        image = IMAGE_CONFIG.get(svc_type, IMAGE_CONFIG.get("http", image))
        http_spec = spec.get("http", {})
        env = [
            {"name": "DECOY_NAME", "value": name},
            {"name": "DECOY_HOSTNAME", "value": identity.get("hostname", name)},
            {"name": "NATS_URL", "value": "nats://cicdecoy-nats:4222"},
            {"name": "HTTP_PORT", "value": str(port)},
            {"name": "COMPANY_NAME", "value": identity.get("companyName", "Acme Corp")},
            {"name": "LOGIN_PORTALS", "value": http_spec.get("loginPortals", "corporate,aws,gitlab")},
            {"name": "SERVER_HEADER", "value": http_spec.get("serverHeader", "nginx/1.24.0")},
            {"name": "METRICS_PORT", "value": "9092"},
        ]

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
        {"name": "NATS_URL", "value": "nats://cicdecoy-nats:4222"},
    ]
    exporter = spec.get("telemetry", {}).get("exporter", {})
    if exporter.get("subject"):
        telemetry_env.append({"name": "NATS_SUBJECT", "value": exporter["subject"]})
    session = spec.get("telemetry", {}).get("sessionCapture", {})
    if session.get("fullTranscript"):
        telemetry_env.append({"name": "CAPTURE_TRANSCRIPT", "value": "true"})
    if session.get("keystrokeTimings"):
        telemetry_env.append({"name": "CAPTURE_KEYSTROKES", "value": "true"})

    sidecar = {
        "name": "telemetry",
        "image": TELEMETRY_SIDECAR_IMAGE,
        "env": telemetry_env,
        "resources": {
            "requests": {"cpu": "25m", "memory": "32Mi"},
            "limits": {"cpu": "100m", "memory": "64Mi"},
        },
    }

    managed_labels = {
        **labels,
        "cicdecoy.io/managed": "true",
        "cicdecoy.io/decoy": name,
        "cicdecoy.io/tier": str(tier),
        "cicdecoy.io/service-type": svc_type,
    }

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
                    "hostname": identity.get("hostname", name),
                    "containers": [decoy_container, sidecar],
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
    api = kubernetes.client.AppsV1Api()
    core = kubernetes.client.CoreV1Api()

    try:
        # Build desired state
        deployment = _build_decoy_deployment(name, namespace, spec, labels or {})
        service = _build_service(name, namespace, spec, labels or {})

        # Apply deployment
        dep_name = f"decoy-{name}"
        try:
            api.read_namespaced_deployment(dep_name, namespace)
            api.patch_namespaced_deployment(dep_name, namespace, deployment)
            logger.info("Updated deployment %s", dep_name)
        except kubernetes.client.ApiException as e:
            if e.status == 404:
                kopf.adopt(deployment)
                api.create_namespaced_deployment(namespace, deployment)
                logger.info("Created deployment %s", dep_name)
            else:
                raise

        # Apply service
        try:
            core.read_namespaced_service(dep_name, namespace)
            core.patch_namespaced_service(dep_name, namespace, service)
        except kubernetes.client.ApiException as e:
            if e.status == 404:
                kopf.adopt(service)
                core.create_namespaced_service(namespace, service)
            else:
                raise

        # Update status
        patch.status["phase"] = "Active"
        patch.status["conditions"] = [{
            "type": "Ready",
            "status": "True",
            "lastTransitionTime": datetime.now(timezone.utc).isoformat(),
            "reason": "ReconcileSuccess",
            "message": "Decoy pod and service created successfully",
        }]
        patch.status["podName"] = dep_name
        logger.info("Decoy %s/%s reconciled → Active", namespace, name)

    except Exception as e:
        patch.status["phase"] = "Error"
        patch.status["conditions"] = [{
            "type": "Ready",
            "status": "False",
            "lastTransitionTime": datetime.now(timezone.utc).isoformat(),
            "reason": "ReconcileError",
            "message": str(e)[:256],
        }]
        logger.exception("Failed to reconcile Decoy %s/%s", namespace, name)
        raise


@kopf.on.delete("cicdecoy.io", "v1alpha1", "decoys")
def delete_decoy(name, namespace, **_):
    """Cleanup on Decoy deletion — owned resources are garbage collected by k8s."""
    logger.info("Decoy %s/%s deleted, owned resources will be GC'd", namespace, name)
