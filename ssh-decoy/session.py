"""
CI/CDecoy — Session State Manager

Maintains per-session state so the decoy never contradicts itself.
Tracks cwd, environment, command history, files created by attacker,
and any mutations to the virtual environment.
"""

import ipaddress
import logging
import posixpath
import re
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime

_session_logger = logging.getLogger("cicdecoy.session")


_UNSAFE_CONTEXT_CHARS = re.compile(
    r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f'
    r'\u200b-\u200f'   # Zero-width and directional chars
    r'\u202a-\u202e'   # Directional formatting
    r'\u2060-\u2064'   # Invisible operators
    r'\u061c'          # Arabic letter mark
    r'\ufeff'          # BOM / zero-width no-break space
    r'\ufff9-\ufffb'   # Interlinear annotation
    r']'
)


def _sanitize_for_context(value: str, max_len: int) -> str:
    """Sanitize a string before injecting into LLM context."""
    # Replace prompt delimiters
    value = value.replace("---", "___")
    # Strip control characters and invisible Unicode characters
    value = _UNSAFE_CONTEXT_CHARS.sub('', value)
    # Truncate
    return value[:max_len]


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
        # Validate client_ip to prevent injection via spoofed peer info
        try:
            ipaddress.ip_address(self.client_ip)
        except (ValueError, TypeError):
            _session_logger.warning(
                "Invalid client_ip %r, defaulting to 0.0.0.0",
                self.client_ip,
            )
            self.client_ip = "0.0.0.0"

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
        """Update state based on a command that was just executed.

        Args:
            command: The command string the attacker ran.
            response: The response shown to the attacker (used for state
                inference like cd detection, not stored to save memory).
        """
        self.command_history.append(command[:4096])  # Cap individual commands to 4KB

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
        recent = list(self.command_history)[-20:]
        sanitized_commands = [
            _sanitize_for_context(c, 1024)
            for c in recent
        ]
        sanitized_files = []
        for entry in self.files_created:
            sanitized_entry = dict(entry)
            if "path" in sanitized_entry:
                sanitized_entry["path"] = _sanitize_for_context(
                    sanitized_entry["path"], 1024)
            if "command" in sanitized_entry:
                sanitized_entry["command"] = _sanitize_for_context(
                    sanitized_entry["command"], 1024)
            sanitized_files.append(sanitized_entry)
        sanitized_connections = []
        for entry in self.connections_attempted:
            sanitized_conn = dict(entry)
            if "command" in sanitized_conn:
                sanitized_conn["command"] = _sanitize_for_context(
                    sanitized_conn["command"], 1024)
            sanitized_connections.append(sanitized_conn)
        return {
            "hostname": _sanitize_for_context(self.hostname, 256),
            "username": _sanitize_for_context(self.username, 256),
            "uid": self.uid,
            "cwd": _sanitize_for_context(self.cwd, 256),
            "home": _sanitize_for_context(self.home, 256),
            "env": {
                k: _sanitize_for_context(v, 256)
                for k, v in self.env.items()
            },
            "recent_commands": sanitized_commands,
            "files_created_this_session": sanitized_files,
            "outbound_attempts": sanitized_connections,
        }
