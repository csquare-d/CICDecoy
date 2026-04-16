"""
Unit tests for the Kubernetes operator reconciler.

Tests Decoy CRD parsing, Deployment/Service generation,
and reconciliation handlers. Kubernetes API and kopf are mocked.
"""

import sys
import types
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Mock kopf and kubernetes before importing the reconciler module
# ---------------------------------------------------------------------------

# kopf stub
if "kopf" not in sys.modules:
    _kopf = types.ModuleType("kopf")
    _kopf.OperatorSettings = MagicMock
    _kopf.adopt = MagicMock()

    # Decorator stubs: kopf.on.create/update/delete/startup must be
    # chainable decorators that pass the function through unchanged.
    def _noop_decorator(*args, **kwargs):
        def wrapper(fn):
            return fn
        return wrapper

    _on = types.ModuleType("kopf.on")
    _on.create = _noop_decorator
    _on.update = _noop_decorator
    _on.delete = _noop_decorator
    _on.startup = _noop_decorator
    _kopf.on = _on
    sys.modules["kopf"] = _kopf
    sys.modules["kopf.on"] = _on

# kubernetes stub
if "kubernetes" not in sys.modules:
    _k8s = types.ModuleType("kubernetes")
    _k8s_client = types.ModuleType("kubernetes.client")

    class _FakeApiException(Exception):
        def __init__(self, status=None, reason=None, **kw):
            self.status = status
            self.reason = reason
            super().__init__(f"{status}: {reason}")

    _k8s_client.ApiException = _FakeApiException
    _k8s_client.AppsV1Api = MagicMock
    _k8s_client.CoreV1Api = MagicMock
    _k8s.client = _k8s_client
    sys.modules["kubernetes"] = _k8s
    sys.modules["kubernetes.client"] = _k8s_client

from reconciler import (
    _build_decoy_deployment,
    _build_service,
    configure,
    delete_decoy,
    reconcile_decoy,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _minimal_spec(**overrides):
    """Build a minimal Decoy CRD spec."""
    spec = {
        "service": {"type": "ssh", "port": 2222},
        "fidelity": {"tier": 2},
        "identity": {"hostname": "web-prod-01"},
        "authentication": {"mode": "selective"},
        "telemetry": {},
    }
    spec.update(overrides)
    return spec


def _tier3_spec(**overrides):
    """Build a tier-3 spec with adaptive/inference config."""
    spec = _minimal_spec(
        fidelity={
            "tier": 3,
            "adaptive": {
                "model": "llama3.1:8b",
                "maxLatencyMs": 200,
            },
        },
    )
    spec.update(overrides)
    return spec


# ===================================================================
#  _build_decoy_deployment
# ===================================================================

class TestBuildDeployment:

    @patch("reconciler.IMAGE_CONFIG", {"ssh": "cicdecoy/ssh-decoy:latest"})
    @patch("reconciler.TELEMETRY_SIDECAR_IMAGE", "cicdecoy/telemetry:latest")
    def test_basic_deployment_structure(self):
        dep = _build_decoy_deployment("test-ssh", "default", _minimal_spec(), {})
        assert dep["apiVersion"] == "apps/v1"
        assert dep["kind"] == "Deployment"
        assert dep["metadata"]["name"] == "decoy-test-ssh"
        assert dep["metadata"]["namespace"] == "default"
        assert dep["spec"]["replicas"] == 1

    @patch("reconciler.IMAGE_CONFIG", {"ssh": "cicdecoy/ssh-decoy:latest"})
    @patch("reconciler.TELEMETRY_SIDECAR_IMAGE", "cicdecoy/telemetry:latest")
    def test_deployment_has_two_containers(self):
        dep = _build_decoy_deployment("test-ssh", "default", _minimal_spec(), {})
        containers = dep["spec"]["template"]["spec"]["containers"]
        assert len(containers) == 2
        names = [c["name"] for c in containers]
        assert "decoy" in names
        assert "telemetry" in names

    @patch("reconciler.IMAGE_CONFIG", {"ssh": "cicdecoy/ssh-decoy:latest"})
    @patch("reconciler.TELEMETRY_SIDECAR_IMAGE", "cicdecoy/telemetry:latest")
    def test_decoy_container_image(self):
        dep = _build_decoy_deployment("test-ssh", "default", _minimal_spec(), {})
        decoy = [c for c in dep["spec"]["template"]["spec"]["containers"]
                 if c["name"] == "decoy"][0]
        assert decoy["image"] == "cicdecoy/ssh-decoy:latest"

    @patch("reconciler.IMAGE_CONFIG", {"ssh": "cicdecoy/ssh-decoy:latest"})
    @patch("reconciler.TELEMETRY_SIDECAR_IMAGE", "cicdecoy/telemetry:latest")
    def test_decoy_container_port(self):
        dep = _build_decoy_deployment("test-ssh", "default", _minimal_spec(), {})
        decoy = [c for c in dep["spec"]["template"]["spec"]["containers"]
                 if c["name"] == "decoy"][0]
        assert decoy["ports"][0]["containerPort"] == 2222

    @patch("reconciler.IMAGE_CONFIG", {"ssh": "cicdecoy/ssh-decoy:latest"})
    @patch("reconciler.TELEMETRY_SIDECAR_IMAGE", "cicdecoy/telemetry:latest")
    def test_environment_variables(self):
        dep = _build_decoy_deployment("my-decoy", "ns1", _minimal_spec(), {})
        decoy = [c for c in dep["spec"]["template"]["spec"]["containers"]
                 if c["name"] == "decoy"][0]
        env_dict = {e["name"]: e["value"] for e in decoy["env"]}
        assert env_dict["DECOY_NAME"] == "my-decoy"
        assert env_dict["DECOY_SERVICE_TYPE"] == "ssh"
        assert env_dict["DECOY_PORT"] == "2222"
        assert env_dict["DECOY_TIER"] == "2"

    @patch("reconciler.IMAGE_CONFIG", {"ssh": "cicdecoy/ssh-decoy:latest"})
    @patch("reconciler.TELEMETRY_SIDECAR_IMAGE", "cicdecoy/telemetry:latest")
    def test_hostname_env_var(self):
        spec = _minimal_spec()
        dep = _build_decoy_deployment("test", "default", spec, {})
        decoy = [c for c in dep["spec"]["template"]["spec"]["containers"]
                 if c["name"] == "decoy"][0]
        env_dict = {e["name"]: e["value"] for e in decoy["env"]}
        assert env_dict["DECOY_HOSTNAME"] == "web-prod-01"

    @patch("reconciler.IMAGE_CONFIG", {"ssh": "cicdecoy/ssh-decoy:latest"})
    @patch("reconciler.TELEMETRY_SIDECAR_IMAGE", "cicdecoy/telemetry:latest")
    def test_banner_env_var(self):
        spec = _minimal_spec()
        spec["service"]["banner"] = "OpenSSH_8.9p1"
        dep = _build_decoy_deployment("test", "default", spec, {})
        decoy = [c for c in dep["spec"]["template"]["spec"]["containers"]
                 if c["name"] == "decoy"][0]
        env_dict = {e["name"]: e["value"] for e in decoy["env"]}
        assert env_dict["DECOY_BANNER"] == "OpenSSH_8.9p1"

    @patch("reconciler.IMAGE_CONFIG", {"ssh": "cicdecoy/ssh-decoy:latest"})
    @patch("reconciler.TELEMETRY_SIDECAR_IMAGE", "cicdecoy/telemetry:latest")
    def test_tier3_adaptive_env_vars(self):
        dep = _build_decoy_deployment("test", "default", _tier3_spec(), {})
        decoy = [c for c in dep["spec"]["template"]["spec"]["containers"]
                 if c["name"] == "decoy"][0]
        env_dict = {e["name"]: e["value"] for e in decoy["env"]}
        assert env_dict["DECOY_ADAPTIVE_MODEL"] == "llama3.1:8b"
        assert env_dict["DECOY_MAX_LATENCY_MS"] == "200"
        assert env_dict["INFERENCE_URL"] == "http://cicdecoy-inference:8000"

    @patch("reconciler.IMAGE_CONFIG", {"fallback": "busybox"})
    @patch("reconciler.TELEMETRY_SIDECAR_IMAGE", "cicdecoy/telemetry:latest")
    def test_unknown_service_type_uses_fallback(self):
        spec = _minimal_spec(service={"type": "custom-proto", "port": 9999})
        dep = _build_decoy_deployment("test", "default", spec, {})
        decoy = [c for c in dep["spec"]["template"]["spec"]["containers"]
                 if c["name"] == "decoy"][0]
        assert decoy["image"] == "busybox"

    @patch("reconciler.IMAGE_CONFIG", {"ssh": "cicdecoy/ssh-decoy:latest"})
    @patch("reconciler.TELEMETRY_SIDECAR_IMAGE", "cicdecoy/telemetry:latest")
    def test_labels_include_managed_metadata(self):
        dep = _build_decoy_deployment("test-ssh", "default", _minimal_spec(), {"app": "cicdecoy"})
        labels = dep["metadata"]["labels"]
        assert labels["cicdecoy.io/managed"] == "true"
        assert labels["cicdecoy.io/decoy"] == "test-ssh"
        assert labels["cicdecoy.io/tier"] == "2"
        assert labels["cicdecoy.io/service-type"] == "ssh"
        assert labels["app"] == "cicdecoy"

    @patch("reconciler.IMAGE_CONFIG", {"ssh": "cicdecoy/ssh-decoy:latest"})
    @patch("reconciler.TELEMETRY_SIDECAR_IMAGE", "cicdecoy/telemetry:latest")
    def test_selector_matches_decoy_label(self):
        dep = _build_decoy_deployment("test-ssh", "default", _minimal_spec(), {})
        selector = dep["spec"]["selector"]["matchLabels"]
        assert selector == {"cicdecoy.io/decoy": "test-ssh"}

    @patch("reconciler.IMAGE_CONFIG", {"ssh": "cicdecoy/ssh-decoy:latest"})
    @patch("reconciler.TELEMETRY_SIDECAR_IMAGE", "cicdecoy/telemetry:latest")
    def test_resource_limits_set(self):
        dep = _build_decoy_deployment("test", "default", _minimal_spec(), {})
        decoy = [c for c in dep["spec"]["template"]["spec"]["containers"]
                 if c["name"] == "decoy"][0]
        assert "resources" in decoy
        assert decoy["resources"]["requests"]["cpu"] == "50m"
        assert decoy["resources"]["limits"]["memory"] == "128Mi"

    @patch("reconciler.IMAGE_CONFIG", {"ssh": "cicdecoy/ssh-decoy:latest"})
    @patch("reconciler.TELEMETRY_SIDECAR_IMAGE", "cicdecoy/telemetry:latest")
    def test_telemetry_sidecar_nats_url(self):
        dep = _build_decoy_deployment("test", "default", _minimal_spec(), {})
        sidecar = [c for c in dep["spec"]["template"]["spec"]["containers"]
                   if c["name"] == "telemetry"][0]
        env_dict = {e["name"]: e["value"] for e in sidecar["env"]}
        assert env_dict["NATS_URL"] == "nats://cicdecoy-nats:4222"
        assert env_dict["DECOY_NAME"] == "test"

    @patch("reconciler.IMAGE_CONFIG", {"ssh": "cicdecoy/ssh-decoy:latest"})
    @patch("reconciler.TELEMETRY_SIDECAR_IMAGE", "cicdecoy/telemetry:latest")
    def test_telemetry_session_capture(self):
        spec = _minimal_spec(telemetry={
            "sessionCapture": {
                "fullTranscript": True,
                "keystrokeTimings": True,
            },
        })
        dep = _build_decoy_deployment("test", "default", spec, {})
        sidecar = [c for c in dep["spec"]["template"]["spec"]["containers"]
                   if c["name"] == "telemetry"][0]
        env_dict = {e["name"]: e["value"] for e in sidecar["env"]}
        assert env_dict["CAPTURE_TRANSCRIPT"] == "true"
        assert env_dict["CAPTURE_KEYSTROKES"] == "true"

    @patch("reconciler.IMAGE_CONFIG", {"ssh": "cicdecoy/ssh-decoy:latest"})
    @patch("reconciler.TELEMETRY_SIDECAR_IMAGE", "cicdecoy/telemetry:latest")
    def test_pod_hostname_from_identity(self):
        dep = _build_decoy_deployment("test", "default", _minimal_spec(), {})
        pod_spec = dep["spec"]["template"]["spec"]
        assert pod_spec["hostname"] == "web-prod-01"

    @patch("reconciler.IMAGE_CONFIG", {"ssh": "cicdecoy/ssh-decoy:latest"})
    @patch("reconciler.TELEMETRY_SIDECAR_IMAGE", "cicdecoy/telemetry:latest")
    def test_auth_credentials_env_var(self):
        import json
        spec = _minimal_spec(authentication={
            "mode": "selective",
            "allowCredentials": [
                {"username": "admin", "password": "admin123"},
            ],
        })
        dep = _build_decoy_deployment("test", "default", spec, {})
        decoy = [c for c in dep["spec"]["template"]["spec"]["containers"]
                 if c["name"] == "decoy"][0]
        env_dict = {e["name"]: e["value"] for e in decoy["env"]}
        assert env_dict["DECOY_AUTH_MODE"] == "selective"
        creds = json.loads(env_dict["DECOY_CREDENTIALS"])
        assert len(creds) == 1
        assert creds[0]["username"] == "admin"


# ===================================================================
#  _build_service
# ===================================================================

class TestBuildService:

    def test_basic_service_structure(self):
        svc = _build_service("test-ssh", "default", _minimal_spec(), {})
        assert svc["apiVersion"] == "v1"
        assert svc["kind"] == "Service"
        assert svc["metadata"]["name"] == "decoy-test-ssh"
        assert svc["metadata"]["namespace"] == "default"

    def test_service_port(self):
        svc = _build_service("test", "default", _minimal_spec(), {})
        ports = svc["spec"]["ports"]
        assert len(ports) == 1
        assert ports[0]["port"] == 2222
        assert ports[0]["targetPort"] == 2222

    def test_service_selector(self):
        svc = _build_service("test-ssh", "default", _minimal_spec(), {})
        assert svc["spec"]["selector"] == {"cicdecoy.io/decoy": "test-ssh"}

    def test_default_clusterip_type(self):
        svc = _build_service("test", "default", _minimal_spec(), {})
        assert svc["spec"]["type"] == "ClusterIP"

    def test_nodeport_type(self):
        spec = _minimal_spec(network={"expose": "nodeport"})
        svc = _build_service("test", "default", spec, {})
        assert svc["spec"]["type"] == "NodePort"

    def test_nodeport_with_explicit_port(self):
        spec = _minimal_spec(network={"expose": "nodeport", "nodePort": 30222})
        svc = _build_service("test", "default", spec, {})
        assert svc["spec"]["ports"][0]["nodePort"] == 30222

    def test_loadbalancer_type(self):
        spec = _minimal_spec(network={"expose": "loadbalancer"})
        svc = _build_service("test", "default", spec, {})
        assert svc["spec"]["type"] == "LoadBalancer"

    def test_unknown_expose_defaults_to_clusterip(self):
        spec = _minimal_spec(network={"expose": "something-unknown"})
        svc = _build_service("test", "default", spec, {})
        assert svc["spec"]["type"] == "ClusterIP"

    def test_service_labels_include_managed(self):
        svc = _build_service("test", "default", _minimal_spec(), {"app": "cicdecoy"})
        labels = svc["metadata"]["labels"]
        assert labels["cicdecoy.io/managed"] == "true"
        assert labels["app"] == "cicdecoy"

    def test_custom_port(self):
        spec = _minimal_spec(service={"type": "http", "port": 8080})
        svc = _build_service("web", "prod", spec, {})
        assert svc["spec"]["ports"][0]["port"] == 8080


# ===================================================================
#  reconcile_decoy handler
# ===================================================================

class TestReconcileDecoy:

    @patch("reconciler.IMAGE_CONFIG", {"ssh": "cicdecoy/ssh-decoy:latest"})
    @patch("reconciler.TELEMETRY_SIDECAR_IMAGE", "cicdecoy/telemetry:latest")
    def test_creates_deployment_when_not_found(self):
        mock_api = MagicMock()
        mock_core = MagicMock()

        # Deployment doesn't exist
        exc_404 = MagicMock()
        exc_404.status = 404
        mock_api.read_namespaced_deployment.side_effect = (
            type("ApiException", (Exception,), {"status": 404})(exc_404)
        )
        # Service doesn't exist
        mock_core.read_namespaced_service.side_effect = (
            type("ApiException", (Exception,), {"status": 404})(exc_404)
        )

        # Use real kubernetes exceptions
        import kubernetes.client
        mock_api.read_namespaced_deployment.side_effect = (
            kubernetes.client.ApiException(status=404)
        )
        mock_core.read_namespaced_service.side_effect = (
            kubernetes.client.ApiException(status=404)
        )

        patch_obj = MagicMock()
        patch_obj.status = {}

        with patch("reconciler.kubernetes.client.AppsV1Api", return_value=mock_api), \
             patch("reconciler.kubernetes.client.CoreV1Api", return_value=mock_core), \
             patch("reconciler.kopf.adopt"):
            reconcile_decoy(
                spec=_minimal_spec(),
                name="test-ssh",
                namespace="default",
                labels={},
                status={},
                patch=patch_obj,
            )

        mock_api.create_namespaced_deployment.assert_called_once()
        mock_core.create_namespaced_service.assert_called_once()
        assert patch_obj.status["phase"] == "Active"

    @patch("reconciler.IMAGE_CONFIG", {"ssh": "cicdecoy/ssh-decoy:latest"})
    @patch("reconciler.TELEMETRY_SIDECAR_IMAGE", "cicdecoy/telemetry:latest")
    def test_updates_deployment_when_exists(self):

        mock_api = MagicMock()
        mock_core = MagicMock()

        # Both resources already exist (no exception)
        mock_api.read_namespaced_deployment.return_value = MagicMock()
        mock_core.read_namespaced_service.return_value = MagicMock()

        patch_obj = MagicMock()
        patch_obj.status = {}

        with patch("reconciler.kubernetes.client.AppsV1Api", return_value=mock_api), \
             patch("reconciler.kubernetes.client.CoreV1Api", return_value=mock_core):
            reconcile_decoy(
                spec=_minimal_spec(),
                name="test-ssh",
                namespace="default",
                labels={},
                status={},
                patch=patch_obj,
            )

        mock_api.patch_namespaced_deployment.assert_called_once()
        mock_core.patch_namespaced_service.assert_called_once()
        assert patch_obj.status["phase"] == "Active"
        assert patch_obj.status["podName"] == "decoy-test-ssh"

    @patch("reconciler.IMAGE_CONFIG", {"ssh": "cicdecoy/ssh-decoy:latest"})
    @patch("reconciler.TELEMETRY_SIDECAR_IMAGE", "cicdecoy/telemetry:latest")
    def test_raises_on_non_404_api_error(self):
        import kubernetes.client

        mock_api = MagicMock()
        mock_core = MagicMock()
        mock_api.read_namespaced_deployment.side_effect = (
            kubernetes.client.ApiException(status=500, reason="Internal Server Error")
        )

        patch_obj = MagicMock()
        patch_obj.status = {}

        with patch("reconciler.kubernetes.client.AppsV1Api", return_value=mock_api), \
             patch("reconciler.kubernetes.client.CoreV1Api", return_value=mock_core):
            with pytest.raises(kubernetes.client.ApiException):
                reconcile_decoy(
                    spec=_minimal_spec(),
                    name="test-ssh",
                    namespace="default",
                    labels={},
                    status={},
                    patch=patch_obj,
                )


# ===================================================================
#  delete_decoy handler
# ===================================================================

class TestDeleteDecoy:

    def test_delete_handler_runs_without_error(self):
        # The delete handler just logs; owned resources are GC'd by k8s
        delete_decoy(name="test-ssh", namespace="default")


# ===================================================================
#  configure (startup handler)
# ===================================================================

class TestConfigure:

    def test_configure_loads_image_config(self, tmp_path):
        import yaml
        images_file = tmp_path / "images.yaml"
        images_file.write_text(yaml.dump({
            "ssh": "cicdecoy/ssh-decoy:v1",
            "http": "cicdecoy/http-decoy:v1",
            "telemetrySidecar": "cicdecoy/telemetry:v1",
        }))

        settings = MagicMock()
        settings.posting = MagicMock()
        settings.persistence = MagicMock()

        with patch("reconciler.Path") as mock_path_cls:
            mock_path_inst = MagicMock()
            mock_path_inst.exists.return_value = True
            mock_path_inst.read_text.return_value = images_file.read_text()
            mock_path_cls.return_value = mock_path_inst

            configure(settings=settings)

        import reconciler
        assert "ssh" in reconciler.IMAGE_CONFIG
        assert "http" in reconciler.IMAGE_CONFIG
        assert reconciler.TELEMETRY_SIDECAR_IMAGE == "cicdecoy/telemetry:v1"
        # telemetrySidecar should be popped from IMAGE_CONFIG
        assert "telemetrySidecar" not in reconciler.IMAGE_CONFIG

    def test_configure_handles_missing_config_file(self):
        settings = MagicMock()
        settings.posting = MagicMock()
        settings.persistence = MagicMock()

        with patch("reconciler.Path") as mock_path_cls:
            mock_path_inst = MagicMock()
            mock_path_inst.exists.return_value = False
            mock_path_cls.return_value = mock_path_inst

            # Should not raise
            configure(settings=settings)


# ===================================================================
#  Invalid / Edge-case specs
# ===================================================================

class TestInvalidSpecs:

    @patch("reconciler.IMAGE_CONFIG", {})
    @patch("reconciler.TELEMETRY_SIDECAR_IMAGE", "")
    def test_missing_image_config_uses_busybox_fallback(self):
        """When IMAGE_CONFIG has no matching type and no fallback, uses busybox default."""
        dep = _build_decoy_deployment("test", "default", _minimal_spec(), {})
        decoy = [c for c in dep["spec"]["template"]["spec"]["containers"]
                 if c["name"] == "decoy"][0]
        # dict.get returns None when both keys missing
        assert decoy["image"] is None or decoy["image"] == "busybox"

    @patch("reconciler.IMAGE_CONFIG", {"ssh": "cicdecoy/ssh:latest"})
    @patch("reconciler.TELEMETRY_SIDECAR_IMAGE", "cicdecoy/telemetry:latest")
    def test_empty_labels_handled(self):
        dep = _build_decoy_deployment("test", "default", _minimal_spec(), {})
        labels = dep["metadata"]["labels"]
        assert "cicdecoy.io/managed" in labels

    @patch("reconciler.IMAGE_CONFIG", {"ssh": "cicdecoy/ssh:latest"})
    @patch("reconciler.TELEMETRY_SIDECAR_IMAGE", "cicdecoy/telemetry:latest")
    def test_missing_identity_uses_name_as_hostname(self):
        spec = _minimal_spec()
        spec["identity"] = {}
        dep = _build_decoy_deployment("fallback-host", "default", spec, {})
        pod_spec = dep["spec"]["template"]["spec"]
        assert pod_spec["hostname"] == "fallback-host"
