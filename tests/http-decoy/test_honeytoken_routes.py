"""
CI/CDecoy -- Honeytoken Route Tests

Tests for honeytoken integration in the HTTP decoy routes:
 - /.env (admin router)
 - /config.php, /backup.sql (discovery router)
 - _HoneytokenEmitterAdapter bridging class
"""

import json
import os
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

# The conftest.py in this directory ensures http-decoy/ is on sys.path
# and provides the `app` and `client` fixtures.


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ENV_CONTENT = "DB_PASSWORD=hunter2\nSECRET_KEY=abc123\n"
_CONFIG_PHP_CONTENT = "<?php $db_pass = 'r00tme'; ?>"
_BACKUP_SQL_CONTENT = "-- MySQL dump\nINSERT INTO users VALUES ('admin','s3cret');"

_MANIFEST = json.dumps(
    [
        {"path": "/.env", "content": _ENV_CONTENT},
        {"path": "/config.php", "content": _CONFIG_PHP_CONTENT},
        {"path": "/backup.sql", "content": _BACKUP_SQL_CONTENT},
    ]
)


def _make_app_with_honeytokens(mock_nats, manifest_json: str | None = None):
    """Build and return a fresh app instance with honeytoken support.

    When *manifest_json* is provided it is injected via the
    HONEYTOKEN_MANIFEST env var so the registry loads entries.
    """
    from pathlib import Path

    _http_dir = str(Path(__file__).resolve().parents[2] / "http-decoy")
    _lib_dir = str(Path(__file__).resolve().parents[2] / "lib")

    # Flush cached route / main modules so the app is rebuilt cleanly
    for mod_name in list(sys.modules):
        if mod_name.startswith("routes."):
            del sys.modules[mod_name]

    import prometheus_client

    prometheus_client.REGISTRY._names_to_collectors.clear()
    if hasattr(prometheus_client.REGISTRY, "_collector_to_names"):
        prometheus_client.REGISTRY._collector_to_names.clear()

    for mod_name in ["metrics", "main", "telemetry"]:
        sys.modules.pop(mod_name, None)

    if _http_dir in sys.path:
        sys.path.remove(_http_dir)
    sys.path.insert(0, _http_dir)
    if _lib_dir not in sys.path:
        sys.path.insert(0, _lib_dir)

    env_patch = {}
    if manifest_json is not None:
        env_patch["HONEYTOKEN_MANIFEST"] = manifest_json

    with (
        patch("nats.connect", new_callable=AsyncMock) as mock_connect,
        patch.dict(os.environ, env_patch, clear=False),
    ):
        mock_connect.return_value = mock_nats
        import main as http_decoy

        http_decoy.app.state.emitter = MagicMock()
        http_decoy.app.state.emitter.emit = AsyncMock()
        http_decoy.app.state.emitter._nc = mock_nats
        http_decoy.app.state.emitter._connected = True
        http_decoy.app.state.emitter.close = AsyncMock()

        from http_enrichment import HttpRequestClassifier

        http_decoy.app.state.classifier = HttpRequestClassifier()

        from http_session import SessionTracker

        http_decoy.app.state.sessions = SessionTracker("test-secret-key")

        from config import HttpDecoyConfig

        http_decoy.app.state.config = HttpDecoyConfig(
            session_secret="test-secret-key",
            server_header="nginx/1.24.0",
            hostname="webapp-prod-01",
            company_name="Acme Corp",
        )

        # Re-create the registry with the adapter pointing at the mock emitter
        from honeytoken_registry import HoneytokenRegistry

        adapter = http_decoy._HoneytokenEmitterAdapter(http_decoy.app.state.emitter)
        registry = HoneytokenRegistry(adapter)
        registry.load_from_env()
        http_decoy.app.state.honeytoken_registry = registry

        return http_decoy.app


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_nats_ht():
    nc = AsyncMock()
    nc.is_connected = True
    nc.publish = AsyncMock()
    nc.drain = AsyncMock()
    return nc


@pytest.fixture
def app_with_honeytokens(mock_nats_ht):
    """App with HONEYTOKEN_MANIFEST set (registry has entries)."""
    return _make_app_with_honeytokens(mock_nats_ht, manifest_json=_MANIFEST)


@pytest.fixture
def app_without_honeytokens(mock_nats_ht):
    """App with no HONEYTOKEN_MANIFEST (registry is empty)."""
    return _make_app_with_honeytokens(mock_nats_ht, manifest_json=None)


@pytest.fixture
def client_with_ht(app_with_honeytokens):
    transport = ASGITransport(app=app_with_honeytokens)
    return AsyncClient(transport=transport, base_url="http://test")


@pytest.fixture
def client_without_ht(app_without_honeytokens):
    transport = ASGITransport(app=app_without_honeytokens)
    return AsyncClient(transport=transport, base_url="http://test")


# =========================================================================
#  /.env route -- honeytoken present
# =========================================================================


class TestDotEnvHoneytoken:
    @pytest.mark.asyncio
    async def test_env_route_serves_honeytoken_when_configured(self, client_with_ht):
        """With HONEYTOKEN_MANIFEST containing a /.env entry, GET /.env
        should return 200 with the honeytoken content."""
        resp = await client_with_ht.get("/.env")
        assert resp.status_code == 200
        assert resp.text == _ENV_CONTENT

    @pytest.mark.asyncio
    async def test_env_route_returns_403_when_no_honeytoken(self, client_without_ht):
        """Without honeytoken config, GET /.env should still return 403."""
        resp = await client_without_ht.get("/.env")
        assert resp.status_code == 403


# =========================================================================
#  /config.php route -- honeytoken present
# =========================================================================


class TestConfigPhpHoneytoken:
    @pytest.mark.asyncio
    async def test_config_php_serves_honeytoken(self, client_with_ht):
        """With a /config.php honeytoken, GET /config.php returns 200
        with the planted content."""
        resp = await client_with_ht.get("/config.php")
        assert resp.status_code == 200
        assert resp.text == _CONFIG_PHP_CONTENT

    @pytest.mark.asyncio
    async def test_config_php_returns_403_when_no_honeytoken(self, client_without_ht):
        resp = await client_without_ht.get("/config.php")
        assert resp.status_code == 403


# =========================================================================
#  /backup.sql route -- honeytoken present
# =========================================================================


class TestBackupSqlHoneytoken:
    @pytest.mark.asyncio
    async def test_backup_sql_serves_honeytoken(self, client_with_ht):
        """With a /backup.sql honeytoken, GET /backup.sql returns 200
        with the planted content."""
        resp = await client_with_ht.get("/backup.sql")
        assert resp.status_code == 200
        assert resp.text == _BACKUP_SQL_CONTENT

    @pytest.mark.asyncio
    async def test_backup_sql_returns_403_when_no_honeytoken(self, client_without_ht):
        resp = await client_without_ht.get("/backup.sql")
        assert resp.status_code == 403


# =========================================================================
#  Honeytoken access fires an event
# =========================================================================


class TestHoneytokenEvent:
    @pytest.mark.asyncio
    async def test_honeytoken_access_fires_event(self, app_with_honeytokens, client_with_ht):
        """Accessing a honeytoken route should trigger an event emission
        through the adapter -> emitter pipeline."""
        resp = await client_with_ht.get("/.env")
        assert resp.status_code == 200

        emitter = app_with_honeytokens.state.emitter
        # The adapter calls emitter.emit with event_type="honeytoken.accessed"
        calls = emitter.emit.call_args_list
        honeytoken_calls = [
            c
            for c in calls
            if (c.args and c.args[0] == "honeytoken.accessed") or c.kwargs.get("event_type") == "honeytoken.accessed"
        ]
        assert len(honeytoken_calls) >= 1, f"Expected at least one honeytoken.accessed event, got calls: {calls}"

        # Verify the adapter forwarded with severity="critical"
        call = honeytoken_calls[0]
        # The adapter calls: emitter.emit(event_type, session_id, source_ip, data, severity="critical")
        if call.args:
            assert call.args[0] == "honeytoken.accessed"
        if "severity" in call.kwargs:
            assert call.kwargs["severity"] == "critical"
        elif len(call.args) >= 5:
            assert call.args[4] == "critical"


# =========================================================================
#  _HoneytokenEmitterAdapter unit test
# =========================================================================


class TestHoneytokenEmitterAdapter:
    @pytest.mark.asyncio
    async def test_emitter_adapter_bridges_interface(self):
        """_HoneytokenEmitterAdapter should translate the 3-arg registry
        emit(event_type, session_id, data) into the 5-arg HTTP emitter
        emit(event_type, session_id, source_ip, data, severity)."""
        # Import the adapter from the http-decoy main module
        from main import _HoneytokenEmitterAdapter

        mock_emitter = MagicMock()
        mock_emitter.emit = AsyncMock()

        adapter = _HoneytokenEmitterAdapter(mock_emitter)

        data = {
            "token_name": "env",
            "client_ip": "10.0.0.99",
            "username": "attacker",
        }
        await adapter.emit("honeytoken.accessed", "sess-abc", data)

        mock_emitter.emit.assert_awaited_once_with(
            "honeytoken.accessed",
            "sess-abc",
            "10.0.0.99",  # extracted from data["client_ip"]
            data,
            severity="critical",
        )

    @pytest.mark.asyncio
    async def test_emitter_adapter_defaults_unknown_ip(self):
        """When client_ip is missing from data, adapter should use 'unknown'."""
        from main import _HoneytokenEmitterAdapter

        mock_emitter = MagicMock()
        mock_emitter.emit = AsyncMock()

        adapter = _HoneytokenEmitterAdapter(mock_emitter)

        data = {"token_name": "env"}
        await adapter.emit("honeytoken.accessed", "sess-xyz", data)

        # source_ip should be "unknown" when client_ip not in data
        call_args = mock_emitter.emit.call_args
        assert call_args.args[2] == "unknown"
