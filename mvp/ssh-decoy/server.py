#!/usr/bin/env python3
"""
CI/CDecoy — SSH Decoy Server (asyncssh implementation)

A working SSH honeypot that handles real connections, captures
credentials, and routes commands through the tiered response system.

Usage:
    DECOY_CONFIG=/etc/cicdecoy/decoy.yaml python server.py

Requires: asyncssh, pyyaml, nats-py
"""

import asyncio
import json
import logging
import os
import random
import signal
import sys
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import asyncssh
import nats
import yaml

from session import SessionState
from filesystem import VirtualFilesystem
from command_router import CommandRouter
from auth_handler import AuthHandler, AuthResult

logger = logging.getLogger("cicdecoy.ssh")


# ─────────────────────────────────────────────────────────
#  Configuration
# ─────────────────────────────────────────────────────────

@dataclass
class DecoyConfig:
    """Parsed from decoy.yaml (mounted from CRD or local config)."""
    name: str = "ssh-decoy"
    hostname: str = "localhost"
    domain: str = "local"
    tier: int = 2
    port: int = 2222
    ssh_banner: str = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
    host_key_path: str = "/etc/cicdecoy/ssh_host_key"

    # Auth
    auth_mode: str = "selective"
    credentials: list = field(default_factory=list)
    fail_before_success: int = 1
    lockout_after: int = 10
    lockout_duration: int = 300

    # Inference (tier 3)
    inference_endpoint: str = "http://inference-gateway:8000"
    profile_name: str = ""
    max_session_tokens: int = 8192
    temperature: float = 0.3

    # Telemetry
    nats_endpoint: str = "nats://localhost:4222"
    nats_subject: str = "cicdecoy.decoy.events"
    capture_keystrokes: bool = True

    # Fast-path
    fast_path_commands: list = field(default_factory=list)

    # Guardrails
    filter_patterns: list = field(default_factory=list)
    disallowed_paths: list = field(default_factory=list)
    max_response_lines: int = 500

    # Scripted responses (tier 2)
    custom_responses: list = field(default_factory=list)

    @classmethod
    def from_file(cls, path: str) -> "DecoyConfig":
        """Load config from YAML file."""
        with open(path) as f:
            raw = yaml.safe_load(f)

        spec = raw.get("spec", raw)
        identity = spec.get("identity", {})
        fidelity = spec.get("fidelity", {})
        auth = spec.get("authentication", {})
        adaptive = fidelity.get("adaptive", {})
        scripted = fidelity.get("scripted", {})
        telemetry = spec.get("telemetry", {})

        fast_path = []
        if adaptive.get("fastPath", {}).get("enabled"):
            for rule in adaptive["fastPath"].get("commands", []):
                fast_path.append({"match": rule["match"], "source": rule["source"]})

        nats_endpoint = "nats://localhost:4222"
        nats_subject = "cicdecoy.decoy.events"
        for exp in telemetry.get("exporters", []):
            if exp.get("type") == "nats":
                nats_endpoint = exp["endpoint"]
                nats_subject = exp.get("subject", nats_subject)

        return cls(
            name=raw.get("metadata", {}).get("name", "ssh-decoy"),
            hostname=identity.get("hostname", "localhost"),
            domain=identity.get("domain", "local"),
            tier=fidelity.get("tier", 2),
            port=spec.get("service", {}).get("port", 2222),
            ssh_banner=identity.get("fingerprint", {}).get(
                "sshBanner", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
            ),
            auth_mode=auth.get("mode", "selective"),
            credentials=auth.get("credentials", []),
            fail_before_success=auth.get("realisticAuth", {}).get("failBeforeSuccess", 1),
            lockout_after=auth.get("realisticAuth", {}).get("lockoutAfter", 10),
            lockout_duration=auth.get("realisticAuth", {}).get("lockoutDuration", 300),
            inference_endpoint=adaptive.get("inferenceConfig", {}).get(
                "endpoint", "http://inference-gateway:8000"
            ),
            profile_name=adaptive.get("profileRef", ""),
            max_session_tokens=adaptive.get("inferenceConfig", {}).get("maxSessionTokens", 8192),
            temperature=adaptive.get("inferenceConfig", {}).get("temperature", 0.3),
            nats_endpoint=nats_endpoint,
            nats_subject=nats_subject,
            capture_keystrokes=telemetry.get("sessionCapture", {}).get("keystrokeTimings", True),
            fast_path_commands=fast_path,
            filter_patterns=adaptive.get("guardrails", {}).get("filterPatterns", []),
            disallowed_paths=adaptive.get("guardrails", {}).get("disallowedPaths", []),
            max_response_lines=adaptive.get("guardrails", {}).get("maxResponseLines", 500),
            custom_responses=scripted.get("customResponses", []),
        )

    @classmethod
    def defaults(cls) -> "DecoyConfig":
        """Minimal working config for development."""
        return cls(
            credentials=[
                {"username": "admin", "password": "admin123",
                 "shell": "/bin/bash", "uid": 1000, "home": "/home/admin"},
                {"username": "root", "password": "toor",
                 "shell": "/bin/bash", "uid": 0, "home": "/root"},
            ]
        )


# ─────────────────────────────────────────────────────────
#  Event Emitter
# ─────────────────────────────────────────────────────────

class EventEmitter:
    """Publishes structured events to NATS."""

    def __init__(self, config: DecoyConfig):
        self.config = config
        self.nc: Optional[nats.NATS] = None
        self._connected = False

    async def connect(self):
        try:
            self.nc = await nats.connect(
                self.config.nats_endpoint,
                reconnect_time_wait=2,
                max_reconnect_attempts=10,
            )
            self._connected = True
            logger.info(f"NATS connected: {self.config.nats_endpoint}")
        except Exception as e:
            logger.warning(f"NATS connection failed: {e} — events will be logged only")
            self._connected = False

    async def emit(self, event_type: str, session_id: str, data: dict):
        event = {
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": "1.0",
            "source": {
                "decoy": self.config.name,
                "tier": self.config.tier,
            },
            "session_id": session_id,
            "event_type": event_type,
            "data": data,
        }

        subject = f"{self.config.nats_subject}.{self.config.name}.{event_type}"

        if self._connected and self.nc:
            try:
                await self.nc.publish(
                    subject,
                    json.dumps(event).encode(),
                )
            except Exception as e:
                logger.warning(f"NATS publish failed: {e}")

        logger.info(f"EVENT {event_type} session={session_id[:8]} {json.dumps(data)}")

    async def close(self):
        if self.nc and self._connected:
            await self.nc.drain()


# ─────────────────────────────────────────────────────────
#  SSH Server (asyncssh)
# ─────────────────────────────────────────────────────────

class DecoySSHServer(asyncssh.SSHServer):
    """
    asyncssh server callbacks. One instance per connection.

    Handles authentication and creates sessions.
    """

    def __init__(self, config: DecoyConfig, auth_handler: AuthHandler,
                 emitter: EventEmitter, router: CommandRouter,
                 filesystem: VirtualFilesystem):
        self._config = config
        self._auth = auth_handler
        self._emitter = emitter
        self._router = router
        self._fs = filesystem
        self._client_ip = "unknown"
        self._client_port = 0
        self._conn_id = str(uuid.uuid4())
        self._authenticated_user: Optional[str] = None

    def connection_made(self, conn: asyncssh.SSHServerConnection):
        """Called when a new TCP connection arrives."""
        self._conn = conn
        peername = conn.get_extra_info("peername")
        if peername:
            self._client_ip = peername[0]
            self._client_port = peername[1]

        logger.info(f"Connection from {self._client_ip}:{self._client_port}")

        asyncio.ensure_future(self._emitter.emit(
            "connection.new", self._conn_id, {
                "client_ip": self._client_ip,
                "client_port": self._client_port,
            }
        ))

    def connection_lost(self, exc):
        reason = str(exc) if exc else "clean"
        logger.info(f"Connection lost from {self._client_ip}: {reason}")

    def begin_auth(self, username: str) -> bool:
        return True

    def password_auth_supported(self) -> bool:
        return True

    async def validate_password(self, username: str, password: str) -> bool:
        """
        Called by asyncssh when client attempts password auth.

        Enforces a constant-time floor matching real OpenSSH PAM delay to
        prevent user-enumeration via timing side-channel.
        """
        MIN_AUTH_DELAY = 0.3  # seconds — matches OpenSSH PAM default

        start = time.monotonic()
        result: AuthResult = self._auth.check_password(
            username, password, self._client_ip
        )

        # Pad to constant time floor before returning
        elapsed = time.monotonic() - start
        if elapsed < MIN_AUTH_DELAY:
            await asyncio.sleep(MIN_AUTH_DELAY - elapsed)

        await self._emitter.emit(
            "auth.success" if result.accepted else "auth.failure",
            self._conn_id, {
                "client_ip": self._client_ip,
                "username": username,
                "password": password,
                "accepted": result.accepted,
                "reason": result.reason,
            }
        )

        if result.accepted:
            self._authenticated_user = username

        return result.accepted

    def public_key_auth_supported(self) -> bool:
        return True

    async def validate_public_key(self, username: str, key: asyncssh.SSHKey) -> bool:
        """Log the key attempt but reject (force password auth)."""
        fingerprint = key.get_fingerprint()
        await self._emitter.emit("auth.failure", self._conn_id, {
            "client_ip": self._client_ip,
            "username": username,
            "method": "publickey",
            "key_fingerprint": fingerprint,
            "accepted": False,
        })
        return False

    def session_requested(self) -> bool:
        return True

    def server_requested(self, dest_host: str, dest_port: int,
                         orig_host: str, orig_port: int) -> bool:
        """Reject all TCP forwarding / tunneling attempts."""
        asyncio.ensure_future(self._emitter.emit(
            "tunnel.attempt", self._conn_id, {
                "client_ip": self._client_ip,
                "dest": f"{dest_host}:{dest_port}",
            }
        ))
        return False


# ─────────────────────────────────────────────────────────
#  Interactive Session
# ─────────────────────────────────────────────────────────

class DecoySSHSession:
    """
    Handles an interactive shell session.

    Plain class — NOT a subclass of asyncssh.SSHServerProcess.
    asyncssh calls the process_factory coroutine; we construct this
    object there and call _run() directly.
    """

    def __init__(self, config: DecoyConfig, emitter: EventEmitter,
                 router: CommandRouter, filesystem: VirtualFilesystem,
                 username: str, client_ip: str):
        self._config = config
        self._emitter = emitter
        self._router = router
        self._fs = filesystem
        self._username = username
        self._client_ip = client_ip
        self._session_id = str(uuid.uuid4())
        self._start_time = time.time()
        self._command_count = 0

        # Resolve uid/home from credential list
        uid = 1000
        home = f"/home/{username}"
        for cred in config.credentials:
            if cred.get("username") == username:
                uid = cred.get("uid", 1000)
                home = cred.get("home", f"/home/{username}")
                break

        self._state = SessionState(
            hostname=config.hostname,
            username=username,
            uid=uid,
            home=home,
            cwd=home,
        )

    async def _run(self, process: asyncssh.SSHServerProcess):
        """Main session loop."""
        await self._emitter.emit("session.start", self._session_id, {
            "client_ip": self._client_ip,
            "username": self._username,
            "tier": self._config.tier,
        })

        # ── Last-login line + MOTD (matches real Ubuntu sshd behaviour) ──
        last_login_time = datetime.now().strftime("%a %b %d %H:%M:%S %Y")
        last_login_ip = (
            f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
        )
        process.stdout.write(
            f"Last login: {last_login_time} from {last_login_ip}\r\n"
        )
        motd = self._fs.read_file("/etc/motd")
        if motd:
            for line in motd.splitlines():
                process.stdout.write(line + "\r\n")
        # ─────────────────────────────────────────────────────────────────

        prompt = self._render_prompt()
        process.stdout.write(prompt)

        try:
            line_buffer = ""

            while not process.stdin.at_eof():
                try:
                    data = await asyncio.wait_for(
                        process.stdin.read(1024),
                        timeout=300,
                    )
                except asyncio.TimeoutError:
                    process.stdout.write("\r\nConnection timed out.\r\n")
                    break

                if not data:
                    break

                for ch in data:
                    if ch == "\r" or ch == "\n":
                        process.stdout.write("\r\n")
                        command = line_buffer.strip()
                        line_buffer = ""

                        if not command:
                            process.stdout.write(prompt)
                            continue

                        if command in ("exit", "logout", "quit"):
                            await self._emitter.emit(
                                "session.end", self._session_id, {
                                    "reason": "user_exit",
                                    "command_count": self._command_count,
                                    "duration_seconds": round(
                                        time.time() - self._start_time, 2
                                    ),
                                }
                            )
                            process.stdout.write("logout\r\n")
                            process.exit(0)
                            return

                        self._command_count += 1
                        response = await self._handle_command(command)

                        if response:
                            for line in response.split("\n"):
                                process.stdout.write(line + "\r\n")

                        process.stdout.write(prompt)

                    elif ch == "\x7f" or ch == "\x08":  # Backspace
                        if line_buffer:
                            line_buffer = line_buffer[:-1]
                            process.stdout.write("\x08 \x08")

                    elif ch == "\x03":  # Ctrl+C
                        line_buffer = ""
                        process.stdout.write("^C\r\n" + prompt)

                    elif ch == "\x04":  # Ctrl+D
                        if not line_buffer:
                            process.stdout.write("logout\r\n")
                            process.exit(0)
                            return

                    elif ch == "\t":  # Tab — stub
                        pass

                    elif ord(ch) >= 32:  # Printable
                        line_buffer += ch
                        process.stdout.write(ch)

        except asyncssh.BreakReceived:
            pass
        except asyncssh.TerminalSizeChanged:
            pass
        except Exception as e:
            logger.error(f"Session error: {e}", exc_info=True)
            await self._emitter.emit("session.error", self._session_id, {
                "error": str(e),
            })
        finally:
            await self._emitter.emit("session.end", self._session_id, {
                "reason": "disconnect",
                "command_count": self._command_count,
                "duration_seconds": round(time.time() - self._start_time, 2),
            })
            process.exit(0)

    async def _handle_command(self, command: str) -> str:
        """Route command, apply guardrails, emit telemetry."""
        start = time.time()

        await self._emitter.emit("command.exec", self._session_id, {
            "command": command,
            "cwd": self._state.cwd,
            "command_index": self._command_count,
        })

        await self._check_alerts(command)

        response = await self._router.route(
            command=command,
            session_state=self._state,
            filesystem=self._fs,
            tier=self._config.tier,
        )

        self._state.update_from_command(command, response)

        elapsed = time.time() - start
        await self._inject_latency(command, elapsed)

        await self._emitter.emit("command.response", self._session_id, {
            "command": command,
            "response_length": len(response),
            "latency_ms": int((time.time() - start) * 1000),
            "source": self._router.last_source,
        })

        return response

    async def _check_alerts(self, command: str):
        """Fire alerts for high-severity behaviours."""
        patterns = {
            "lateral_movement":     (r"ssh\s+\w+@|rdp|psexec", "T1021"),
            "reverse_shell":        (r"nc\s.*-e|/dev/tcp/|socat|bash\s+-i", "T1059.004"),
            "download":             (r"wget\s+http|curl\s+.*http", "T1105"),
            "privilege_escalation": (r"sudo|su\s+-|chmod\s+[47]", "T1548"),
            "credential_access":    (r"cat.*/etc/shadow|\.aws/|\.ssh/id_", "T1552"),
        }

        for behavior, (pattern, technique) in patterns.items():
            if re.search(pattern, command, re.IGNORECASE):
                severity = "critical" if behavior in (
                    "reverse_shell", "lateral_movement"
                ) else "high"
                await self._emitter.emit("alert", self._session_id, {
                    "severity": severity,
                    "behavior": behavior,
                    "command": command,
                    "mitre_technique": technique,
                    "client_ip": self._client_ip,
                })

    async def _inject_latency(self, command: str, elapsed: float):
        """Make response timing realistic."""
        cmd = command.split()[0] if command.split() else ""

        if cmd in ("pwd", "whoami", "id", "hostname", "echo"):
            target = 0.02
        elif cmd in ("ls", "cat", "head", "tail"):
            target = 0.05
        elif cmd in ("find", "grep", "locate"):
            target = random.uniform(0.2, 0.8)
        elif cmd in ("ssh", "curl", "wget", "ping"):
            target = random.uniform(0.5, 3.0)
        else:
            target = random.uniform(0.03, 0.15)

        target += random.uniform(-0.01, 0.02)
        remaining = target - elapsed
        if remaining > 0:
            await asyncio.sleep(remaining)

    def _render_prompt(self) -> str:
        """
        Render a coloured bash prompt matching Ubuntu 22.04's default PS1.
        Root gets bold red; regular users get bold green. CWD is bold blue.
        """
        cwd = self._state.cwd
        home = self._state.home
        if cwd.startswith(home):
            cwd = "~" + cwd[len(home):]

        user   = self._state.username
        host   = self._config.hostname
        suffix = "#" if self._state.uid == 0 else "$"

        if self._state.uid == 0:
            # Root: bold red user@host
            user_host = f"\x1b[01;31m{user}@{host}\x1b[00m"
        else:
            # Normal: bold green user@host
            user_host = f"\x1b[01;32m{user}@{host}\x1b[00m"

        cwd_colored = f"\x1b[01;34m{cwd}\x1b[00m"
        return f"{user_host}:{cwd_colored}{suffix} "


# ─────────────────────────────────────────────────────────
#  Server Factory
# ─────────────────────────────────────────────────────────

def create_server_factory(config, auth_handler, emitter, router, filesystem):
    def factory():
        return DecoySSHServer(config, auth_handler, emitter, router, filesystem)
    return factory


def create_process_factory(config, emitter, router, filesystem):
    """
    Returns a coroutine that asyncssh calls when a shell is requested.

    Username is read from the process object — the correct asyncssh API —
    rather than from conn.get_extra_info("username") which is not a
    standard key and returns None silently.
    """
    async def handle_client(process: asyncssh.SSHServerProcess):
        username  = process.get_extra_info("username") or "unknown"
        peername  = process.get_extra_info("peername")
        client_ip = peername[0] if peername else "unknown"

        session = DecoySSHSession(
            config, emitter, router, filesystem,
            username, client_ip,
        )
        await session._run(process)

    return handle_client


# ─────────────────────────────────────────────────────────
#  Host Key Management
# ─────────────────────────────────────────────────────────

def ensure_host_key(path: str) -> asyncssh.SSHKey:
    """Load or generate an SSH host key."""
    key_path = Path(path)
    if key_path.exists():
        logger.info(f"Loading host key from {path}")
        return asyncssh.read_private_key(path)

    logger.info(f"Generating new host key at {path}")
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key = asyncssh.generate_private_key("ssh-rsa", 2048)
    key_path.write_bytes(key.export_private_key())
    key_path.chmod(0o600)
    return key


# ─────────────────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────────────────

async def main():
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        stream=sys.stdout,
    )

    config_path = os.environ.get("DECOY_CONFIG", "")
    if config_path and Path(config_path).exists():
        logger.info(f"Loading config from {config_path}")
        config = DecoyConfig.from_file(config_path)
    else:
        logger.info("Using default config (development mode)")
        config = DecoyConfig.defaults()

    # Override from env vars (container deployment)
    config.port               = int(os.environ.get("DECOY_PORT",       config.port))
    config.name               = os.environ.get("DECOY_NAME",           config.name)
    config.hostname           = os.environ.get("DECOY_HOSTNAME",       config.hostname)
    config.tier               = int(os.environ.get("DECOY_TIER",       config.tier))
    config.nats_endpoint      = os.environ.get("NATS_ENDPOINT",        config.nats_endpoint)
    config.inference_endpoint = os.environ.get("INFERENCE_ENDPOINT",   config.inference_endpoint)
    config.profile_name       = os.environ.get("DECOY_PROFILE",        config.profile_name)

    emitter = EventEmitter(config)
    await emitter.connect()

    auth_handler = AuthHandler(config)
    router = CommandRouter(config)
    await router.initialize()

    filesystem = VirtualFilesystem.from_profile(config.profile_name)

    host_key = ensure_host_key(
        os.environ.get("HOST_KEY_PATH", config.host_key_path)
    )

    logger.info(
        f"Starting CI/CDecoy SSH server: "
        f"name={config.name} tier={config.tier} port={config.port} "
        f"hostname={config.hostname} auth_mode={config.auth_mode}"
    )

    await emitter.emit("decoy.online", "system", {
        "decoy_name": config.name,
        "tier": config.tier,
        "port": config.port,
    })

    server = await asyncssh.create_server(
        create_server_factory(config, auth_handler, emitter, router, filesystem),
        host="0.0.0.0",
        port=config.port,
        server_host_keys=[host_key],
        process_factory=create_process_factory(config, emitter, router, filesystem),
        server_version=config.ssh_banner,
        login_timeout=60,
        keepalive_interval=30,
        # Disable SFTP and SCP — log attempts via server_requested()
        sftp_factory=None,
        allow_scp=False,
    )

    logger.info(f"SSH server listening on 0.0.0.0:{config.port}")

    loop = asyncio.get_event_loop()
    shutdown_event = asyncio.Event()

    def signal_handler():
        logger.info("Shutdown signal received")
        shutdown_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, signal_handler)

    await shutdown_event.wait()

    logger.info("Shutting down...")
    server.close()
    await server.wait_closed()
    await emitter.close()
    logger.info("Server stopped")


if __name__ == "__main__":
    asyncio.run(main())