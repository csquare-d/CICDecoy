"""
CI/CDecoy — Session State Manager

Maintains per-session state so the decoy never contradicts itself.
Tracks cwd, environment, command history, files created by attacker,
and any mutations to the virtual environment.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


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
    })

    # Tracking
    command_history: list = field(default_factory=list)
    files_created: list = field(default_factory=list)
    files_modified: list = field(default_factory=list)
    connections_attempted: list = field(default_factory=list)
    start_time: Optional[datetime] = None

    # Sudo state — tracks whether the session has "authenticated" sudo
    sudo_authenticated: bool = False
    sudo_auth_time: Optional[datetime] = None

    def __post_init__(self):
        self.env["HOME"] = self.home
        self.env["USER"] = self.username
        self.env["LOGNAME"] = self.username
        self.env["PWD"] = self.cwd
        self.start_time = datetime.utcnow()

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
        if path.startswith("/"):
            return path
        if self.cwd == "/":
            return f"/{path}"
        return f"{self.cwd}/{path}"

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