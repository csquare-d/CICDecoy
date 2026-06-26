"""
Unit tests for honeytoken features in the Kubernetes operator reconciler.

Tests _infer_token_type() classification and HONEYTOKEN_MANIFEST env-var
injection in _build_decoy_deployment().
"""

import json
import os
import sys
import types
import unittest
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Mock kopf and kubernetes before importing the reconciler module
# ---------------------------------------------------------------------------

if "kopf" not in sys.modules:
    _kopf = types.ModuleType("kopf")
    _kopf.OperatorSettings = MagicMock
    _kopf.adopt = MagicMock()

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

# Add the operator source directory to sys.path
sys.path.insert(
    0,
    os.path.join(os.path.dirname(__file__), "..", "..", "platform", "operator"),
)

from reconciler import _build_decoy_deployment, _infer_token_type

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


def _get_decoy_env(dep):
    """Extract the decoy container env vars as a dict from a deployment."""
    containers = dep["spec"]["template"]["spec"]["containers"]
    decoy = [c for c in containers if c["name"] == "decoy"][0]
    return {e["name"]: e.get("value") for e in decoy["env"]}


# ===================================================================
#  _infer_token_type
# ===================================================================


class TestInferTokenType(unittest.TestCase):
    """Tests for _infer_token_type(path, content)."""

    def test_infer_aws_key_by_path(self):
        result = _infer_token_type("/home/user/.aws/credentials", "")
        self.assertEqual(result, "aws-key")

    def test_infer_aws_key_by_content(self):
        result = _infer_token_type("/some/random/path", "AKIAIOSFODNN7EXAMPLE")
        self.assertEqual(result, "aws-key")

    def test_infer_ssh_key_by_path(self):
        result = _infer_token_type("/home/user/.ssh/id_rsa", "")
        self.assertEqual(result, "ssh-key")

    def test_infer_ssh_key_by_content(self):
        result = _infer_token_type("/tmp/key", "-----BEGIN RSA PRIVATE KEY-----\nMIIE...")
        self.assertEqual(result, "ssh-key")

    def test_infer_env_var(self):
        result = _infer_token_type("/opt/app/.env", "")
        self.assertEqual(result, "env-var")

    def test_infer_kubeconfig(self):
        result = _infer_token_type("/home/user/.kube/config", "")
        self.assertEqual(result, "kubeconfig")

    def test_infer_database_cred(self):
        result = _infer_token_type("/home/user/.pgpass", "")
        self.assertEqual(result, "database-cred")

    def test_infer_api_token(self):
        result = _infer_token_type("/etc/config", "x-api_key: sk-abc123")
        self.assertEqual(result, "api-token")

    def test_infer_fallback(self):
        result = _infer_token_type("/tmp/random_file.txt", "hello world")
        self.assertEqual(result, "file")


# ===================================================================
#  _build_decoy_deployment — honeytoken manifest injection
# ===================================================================


class TestDeploymentHoneytokenManifest(unittest.TestCase):
    """Tests for HONEYTOKEN_MANIFEST env-var injection in _build_decoy_deployment."""

    @patch("reconciler.IMAGE_CONFIG", {"ssh": "cicdecoy/ssh-decoy:latest"})
    @patch("reconciler.TELEMETRY_SIDECAR_IMAGE", "cicdecoy/telemetry:latest")
    def test_deployment_includes_honeytoken_manifest_env(self):
        spec = _minimal_spec(
            filesystem={
                "honeytokens": [
                    {"path": "/home/user/.aws/credentials", "content": "AKIAIOSFODNN7EXAMPLE"},
                ]
            }
        )
        dep = _build_decoy_deployment("test", "default", spec, {})
        env = _get_decoy_env(dep)
        self.assertIn("HONEYTOKEN_MANIFEST", env)
        manifest = json.loads(env["HONEYTOKEN_MANIFEST"])
        self.assertEqual(len(manifest), 1)
        self.assertEqual(manifest[0]["path"], "/home/user/.aws/credentials")
        self.assertEqual(manifest[0]["content"], "AKIAIOSFODNN7EXAMPLE")

    @patch("reconciler.IMAGE_CONFIG", {"ssh": "cicdecoy/ssh-decoy:latest"})
    @patch("reconciler.TELEMETRY_SIDECAR_IMAGE", "cicdecoy/telemetry:latest")
    def test_deployment_no_honeytokens_no_manifest(self):
        spec = _minimal_spec()  # no filesystem key
        dep = _build_decoy_deployment("test", "default", spec, {})
        env = _get_decoy_env(dep)
        self.assertNotIn("HONEYTOKEN_MANIFEST", env)

    @patch("reconciler.IMAGE_CONFIG", {"ssh": "cicdecoy/ssh-decoy:latest"})
    @patch("reconciler.TELEMETRY_SIDECAR_IMAGE", "cicdecoy/telemetry:latest")
    def test_manifest_includes_inferred_type(self):
        spec = _minimal_spec(
            filesystem={
                "honeytokens": [
                    {"path": "/home/user/.ssh/id_rsa", "content": "-----BEGIN RSA PRIVATE KEY-----"},
                ]
            }
        )
        dep = _build_decoy_deployment("test", "default", spec, {})
        env = _get_decoy_env(dep)
        manifest = json.loads(env["HONEYTOKEN_MANIFEST"])
        self.assertEqual(manifest[0]["token_type"], "ssh-key")

    @patch("reconciler.IMAGE_CONFIG", {"ssh": "cicdecoy/ssh-decoy:latest"})
    @patch("reconciler.TELEMETRY_SIDECAR_IMAGE", "cicdecoy/telemetry:latest")
    def test_manifest_includes_token_name_from_basename(self):
        spec = _minimal_spec(
            filesystem={
                "honeytokens": [
                    {"path": "/home/user/.aws/credentials", "content": "AKIAEXAMPLE"},
                ]
            }
        )
        dep = _build_decoy_deployment("test", "default", spec, {})
        env = _get_decoy_env(dep)
        manifest = json.loads(env["HONEYTOKEN_MANIFEST"])
        # basename("credentials") with dots replaced by hyphens
        self.assertEqual(manifest[0]["token_name"], "credentials")

    @patch("reconciler.IMAGE_CONFIG", {"ssh": "cicdecoy/ssh-decoy:latest"})
    @patch("reconciler.TELEMETRY_SIDECAR_IMAGE", "cicdecoy/telemetry:latest")
    def test_manifest_skips_entries_without_path(self):
        spec = _minimal_spec(
            filesystem={
                "honeytokens": [
                    {"path": "", "content": "should-be-skipped"},
                    {"path": "/home/user/.pgpass", "content": "db-cred-data"},
                ]
            }
        )
        dep = _build_decoy_deployment("test", "default", spec, {})
        env = _get_decoy_env(dep)
        manifest = json.loads(env["HONEYTOKEN_MANIFEST"])
        self.assertEqual(len(manifest), 1)
        self.assertEqual(manifest[0]["path"], "/home/user/.pgpass")


if __name__ == "__main__":
    unittest.main()
