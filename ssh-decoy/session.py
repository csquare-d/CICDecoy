"""
CI/CDecoy — Session State Manager

Maintains per-session state so the decoy never contradicts itself.
Tracks cwd, environment, command history, files created by attacker,
and any mutations to the virtual environment.
"""

import posixpath
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class SessionState:
    """
    Mutable state for a single attacker session.

    This gets serialized and injected into LLM context on every
    command so responses remain coherent across the session.
    """

    hostname: str
    username: str
    uid: int
    home: str
    cwd: str

    # Connection metadata for SSH env vars
    client_ip: str = "0.0.0.0"
    client_port: int = 0
    server_port: int = 22

    # Environment variables
    env: dict = field(default_factory=lambda: {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": "",      # Set in __post_init__
        "USER": "",      # Set in __post_init__
        "SHELL": "/bin/bash",
        "TERM": "xterm-256color",
        "LANG": "en_US.UTF-8",
        "LOGNAME": "",   # Set in __post_init__
        "PWD": "",       # Set in __post_init__
        "SSH_CLIENT": "",      # Set in __post_init__
        "SSH_CONNECTION": "",  # Set in __post_init__
        "SSH_TTY": "/dev/pts/0",
    })

    # Tracking — bounded deques to prevent unbounded memory growth
    command_history: deque = field(default_factory=lambda: deque(maxlen=5000))
    files_created: deque = field(default_factory=lambda: deque(maxlen=1000))
    files_modified: deque = field(default_factory=lambda: deque(maxlen=1000))
    connections_attempted: deque = field(default_factory=lambda: deque(maxlen=1000))
    start_time: datetime | None = None

    # Sudo state — tracks whether the session has "authenticated" sudo
    sudo_authenticated: bool = False
    sudo_auth_time: datetime | None = None

    def __post_init__(self):
        self.env["HOME"] = self.home
        self.env["USER"] = self.username
        self.env["LOGNAME"] = self.username
        self.env["PWD"] = self.cwd
        self.env["SSH_CLIENT"] = f"{self.client_ip} {self.client_port} {self.server_port}"
        self.env["SSH_CONNECTION"] = f"{self.client_ip} {self.client_port} 0.0.0.0 {self.server_port}"
        self.start_time = datetime.utcnow()

        # Strip any infrastructure env vars that leaked from the container
        _STRIP_PREFIXES = ("NATS_", "INFERENCE_", "DECOY_", "KUBERNETES_", "CICDECOY_",
                           "PROMETHEUS_", "METRICS_", "DB_", "DASHBOARD_", "OTEL_")
        self.env = {k: v for k, v in self.env.items()
                    if not any(k.startswith(p) for p in _STRIP_PREFIXES)}

    def update_from_command(self, command: str, response: str):
        """Update state based on a command that was just executed."""
        self.command_history.append(command)

        parts = command.split()
        if not parts:
            return

        cmd = parts[0]

        # Keep PWD in sync
        self.env["PWD"] = self.cwd

        # Track file creation
        if cmd in ("touch", "mkdir"):
            for target in parts[1:]:
                if not target.startswith("-"):
                    self.files_created.append({
                        "path": self._resolve(target),
                        "command": command,
                        "time": datetime.utcnow().isoformat(),
                    })

        # Track writes via redirection
        if ">" in command or cmd in ("tee", "dd"):
            self.files_modified.append({
                "command": command,
                "time": datetime.utcnow().isoformat(),
            })

        # Track outbound connection attempts
        if cmd in ("ssh", "nc", "ncat", "curl", "wget", "scp", "rsync",
                    "ping", "dig", "nslookup", "telnet", "ftp"):
            self.connections_attempted.append({
                "command": command,
                "time": datetime.utcnow().isoformat(),
            })

    def _resolve(self, path: str) -> str:
        """Resolve a relative path against cwd."""
        if path.startswith("~"):
            path = self.home + path[1:]
        if path.startswith("/"):
            return posixpath.normpath(path)
        if self.cwd == "/":
            return posixpath.normpath(f"/{path}")
        return posixpath.normpath(f"{self.cwd}/{path}")

    def to_context_dict(self) -> dict:
        """Serialize for LLM context injection."""
        return {
            "hostname": self.hostname,
            "username": self.username,
            "uid": self.uid,
            "cwd": self.cwd,
            "home": self.home,
            "env": self.env,
            "recent_commands": self.command_history[-20:],
            "files_created_this_session": self.files_created,
            "outbound_attempts": self.connections_attempted,
        }
