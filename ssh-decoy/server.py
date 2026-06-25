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
import hashlib
import json
import logging
import os
import posixpath
import random
import re
import shlex
import signal
import stat as stat_mod
import subprocess
import sys
import threading
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import asyncssh
import nats
import yaml
from auth_handler import AuthHandler, AuthResult
from command_router import CommandRouter
from cow_filesystem import SessionFilesystem
from filesystem import VirtualFilesystem
from metrics import (
    ACTIVE_SESSIONS,
    AUTH_ATTEMPTS,
    COMMANDS_PROCESSED,
    CREDENTIALS_CAPTURED,
    SESSION_DURATION,
    SESSIONS_TOTAL,
)
from session import SessionState

logger = logging.getLogger("cicdecoy.ssh")

# Tracks unique (username, password) pairs seen across all connections
# so CREDENTIALS_CAPTURED only increments on genuinely new credentials.
# Uses an OrderedDict as a bounded LRU cache to prevent unbounded memory growth.
_CREDENTIALS_SEEN: OrderedDict[tuple[str, str], None] = OrderedDict()
_MAX_CREDENTIALS_CACHE = 10_000
_credentials_lock = asyncio.Lock()

MAX_CONNECTIONS = 100  # Maximum concurrent SSH connections
MAX_CHANNELS_PER_CONNECTION = 5  # Maximum concurrent channels per SSH connection
MAX_CONCURRENT_SESSIONS = 50  # Maximum concurrent interactive sessions (subset of connections)
_active_connections = 0
_active_sessions = 0
_connections_lock = threading.Lock()

# Maximum seconds a connection may remain idle (no data received)
# before the server forcibly closes it.
CONNECTION_TIMEOUT = 600  # 10 minutes
MAX_LINE_LENGTH = 65536  # 64 KB — prevent memory exhaustion from unbounded input


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
    ssh_banner: str = "OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
    host_key_path: str = "/etc/cicdecoy/ssh_host_key"

    # Algorithm lists matching OpenSSH 8.9 defaults to resist fingerprinting.
    # Setting to () means "use asyncssh defaults" (i.e. no override).
    kex_algs: tuple = (
        "curve25519-sha256",
        "curve25519-sha256@libssh.org",
        "ecdh-sha2-nistp256",
        "ecdh-sha2-nistp384",
        "ecdh-sha2-nistp521",
        "diffie-hellman-group-exchange-sha256",
        "diffie-hellman-group16-sha512",
        "diffie-hellman-group18-sha512",
        "diffie-hellman-group14-sha256",
    )
    encryption_algs: tuple = (
        "chacha20-poly1305@openssh.com",
        "aes128-ctr",
        "aes192-ctr",
        "aes256-ctr",
        "aes128-gcm@openssh.com",
        "aes256-gcm@openssh.com",
    )
    mac_algs: tuple = (
        "umac-64-etm@openssh.com",
        "umac-128-etm@openssh.com",
        "hmac-sha2-256-etm@openssh.com",
        "hmac-sha2-512-etm@openssh.com",
        "hmac-sha1-etm@openssh.com",
        "umac-64@openssh.com",
        "umac-128@openssh.com",
        "hmac-sha2-256",
        "hmac-sha2-512",
        "hmac-sha1",
    )
    compression_algs: tuple = (
        "none",
        "zlib@openssh.com",
    )

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

    # Fast-path
    fast_path_commands: list = field(default_factory=list)

    # Guardrails — compiled regex patterns for response filtering.
    # Raw patterns are pre-compiled during config loading; invalid
    # patterns are logged and skipped (ReDoS mitigation).
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
        for exp in telemetry.get("exporter", telemetry.get("exporters", [])):
            if exp.get("type") == "nats":
                nats_endpoint = exp["endpoint"]
                nats_subject = exp.get("subject", nats_subject)

        # ── FIX: Strip "SSH-2.0-" prefix if present ──────────────
        # asyncssh auto-prepends "SSH-2.0-" to server_version, so if
        # the config/CRD has the full banner string we must strip it
        # to avoid the doubled "SSH-2.0-SSH-2.0-..." banner.
        raw_banner = identity.get("fingerprint", {}).get(
            "sshBanner", "OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
        )
        ssh_banner = _strip_ssh2_prefix(raw_banner)

        # ── Algorithm overrides from CRD fingerprint section ─────
        fp = identity.get("fingerprint", {})
        algo_overrides: dict = {}
        for yaml_key, field_name in (
            ("kexAlgorithms",        "kex_algs"),
            ("encryptionAlgorithms", "encryption_algs"),
            ("macAlgorithms",        "mac_algs"),
            ("compressionAlgorithms","compression_algs"),
        ):
            val = fp.get(yaml_key)
            if val:
                algo_overrides[field_name] = tuple(val)

        return cls(
            name=raw.get("metadata", {}).get("name", "ssh-decoy"),
            hostname=identity.get("hostname", "localhost"),
            domain=identity.get("domain", "local"),
            tier=fidelity.get("tier", 2),
            port=spec.get("service", {}).get("port", 2222),
            ssh_banner=ssh_banner,
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
            fast_path_commands=fast_path,
            filter_patterns=_compile_filter_patterns(
                adaptive.get("guardrails", {}).get("filterPatterns", [])
            ),
            disallowed_paths=adaptive.get("guardrails", {}).get("disallowedPaths", []),
            max_response_lines=adaptive.get("guardrails", {}).get("maxResponseLines", 500),
            custom_responses=scripted.get("customResponses", []),
            **algo_overrides,
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


def _strip_ssh2_prefix(banner: str) -> str:
    """
    Remove the SSH protocol prefix that asyncssh will re-add.

    asyncssh.create_server(server_version=...) prepends "SSH-2.0-"
    automatically.  If the config already contains the prefix we get
    the doubled banner:  SSH-2.0-SSH-2.0-OpenSSH_8.9p1 ...

    This function strips any leading "SSH-2.0-" (case-insensitive)
    so the resulting wire banner is always correct.
    """
    prefix = "SSH-2.0-"
    while banner.upper().startswith(prefix.upper()):
        banner = banner[len(prefix):]
    return banner


def _compile_filter_patterns(raw_patterns: list[str]) -> list[re.Pattern]:
    """
    Pre-compile guardrail filter patterns, skipping invalid ones.

    ReDoS mitigation: patterns are compiled once at startup.  Invalid
    regex patterns are logged and silently dropped so a bad config
    entry doesn't crash the server.
    """
    compiled = []
    for pat in raw_patterns:
        try:
            compiled.append(re.compile(pat))
        except re.error as e:
            logger.warning(f"Skipping invalid filter pattern {pat!r}: {e}")
    return compiled


# ─────────────────────────────────────────────────────────
#  Event Emitter
# ─────────────────────────────────────────────────────────

class EventEmitter:
    """Publishes structured events to NATS."""

    def __init__(self, config: DecoyConfig):
        self.config = config
        self.nc: nats.NATS | None = None
        self._connected = False

    async def connect(self):
        try:
            nats_token = os.environ.get("NATS_TOKEN", "")
            logger.info(f"Connecting to NATS: {self.config.nats_endpoint} (auth={'token' if nats_token else 'none'})")
            connect_kwargs = {
                "servers": self.config.nats_endpoint,
                "reconnect_time_wait": 2,
                "max_reconnect_attempts": 10,
            }
            if nats_token:
                connect_kwargs["token"] = nats_token
            self.nc = await nats.connect(**connect_kwargs)
            self._connected = True
            logger.info(f"NATS connected: {self.config.nats_endpoint}")
        except Exception as e:
            logger.warning(f"NATS connection failed: {e} — events will be logged only")
            self._connected = False

    async def emit(self, event_type: str, session_id: str, data: dict):
        event = {
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.now(UTC).isoformat(),
            "version": "1.0",
            "source": {
                "decoy": self.config.name,
                "tier": self.config.tier,
            },
            "session_id": session_id,
            "event_type": event_type,
            "data": data,
        }

        safe_name = self.config.name.replace(">", "").replace("*", "").replace(" ", "_")
        subject = f"{self.config.nats_subject}.{safe_name}.{event_type}"

        if self._connected and self.nc:
            try:
                await self.nc.publish(
                    subject,
                    json.dumps(event, default=str).encode(),
                )
            except Exception as e:
                logger.warning(f"NATS publish failed: {e}")

        logger.info(f"EVENT {event_type} session={session_id[:8]} {json.dumps(data, default=str)}")

    async def close(self):
        if self.nc and self._connected:
            await self.nc.drain()


# ─────────────────────────────────────────────────────────
#  SSH Server (asyncssh)
# ─────────────────────────────────────────────────────────

_pending_emits: set[asyncio.Task] = set()
_MAX_PENDING_EMITS = 5_000


def _track_emit(task: asyncio.Task) -> bool:
    """Register a fire-and-forget emit task with backpressure.

    Returns False (and drops the event) if the queue is already at capacity.
    """
    if len(_pending_emits) > _MAX_PENDING_EMITS:
        logger.warning("Telemetry queue overflow (%d pending), dropping event", len(_pending_emits))
        task.cancel()
        return False
    _pending_emits.add(task)
    task.add_done_callback(_log_emit_error)
    return True


def _log_emit_error(task: asyncio.Task):
    """Done callback for fire-and-forget emit tasks — logs failures and cleans up."""
    _pending_emits.discard(task)
    if task.cancelled():
        return
    exc = task.exception()
    if exc:
        logger.warning(f"Telemetry emit failed: {exc}")


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
        # ── Per-connection copy-on-write filesystem ───────────
        # Wrap the shared, immutable VirtualFilesystem in a
        # SessionFilesystem overlay so every channel on this
        # connection (shell, SFTP, SCP) mutates the same layer.
        self._fs = SessionFilesystem(filesystem)
        self._client_ip = "unknown"
        self._client_port = 0
        self._conn_id = str(uuid.uuid4())
        self._authenticated_user: str | None = None
        self._channel_count = 0

    def connection_made(self, conn: asyncssh.SSHServerConnection):
        """Called when a new TCP connection arrives."""
        global _active_connections
        self._conn = conn
        peername = conn.get_extra_info("peername")
        if peername:
            self._client_ip = peername[0]
            self._client_port = peername[1]

        with _connections_lock:
            _active_connections += 1
            if _active_connections >= MAX_CONNECTIONS:
                _active_connections -= 1  # Don't count rejected connection
                logger.warning(
                    f"Connection limit reached ({MAX_CONNECTIONS}), "
                    f"rejecting {self._client_ip}:{self._client_port}"
                )
                conn.close()
                return
            elif _active_connections > MAX_CONNECTIONS * 0.9:
                logger.info("Connection count at %d/%d", _active_connections, MAX_CONNECTIONS)

        logger.info(f"Connection from {self._client_ip}:{self._client_port}")

        task = asyncio.ensure_future(self._emitter.emit(
            "connection.new", self._conn_id, {
                "client_ip": self._client_ip,
                "client_port": self._client_port,
            }
        ))
        _track_emit(task)

    def connection_lost(self, exc):
        global _active_connections
        with _connections_lock:
            _active_connections -= 1
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

        # Enforce constant-time floor, then add jitter on top
        elapsed = time.monotonic() - start
        floor_delay = max(0, MIN_AUTH_DELAY - elapsed)
        if floor_delay > 0:
            await asyncio.sleep(floor_delay)
        # Add jitter AFTER the floor to prevent fingerprinting
        # (total time is always >= MIN_AUTH_DELAY, plus random extra)
        await asyncio.sleep(random.uniform(0.01, 0.08))

        await self._emitter.emit(
            "auth.success" if result.accepted else "auth.failure",
            self._conn_id, {
                "client_ip": self._client_ip,
                "username": username,
                "password_hash": hashlib.sha256(password.encode()).hexdigest(),
                "accepted": result.accepted,
                "reason": result.reason,
            }
        )

        # ── Metrics ──────────────────────────────────────────
        AUTH_ATTEMPTS.labels(
            method="password",
            result="success" if result.accepted else "failed",
        ).inc()

        cred_key = (username.strip(), password.strip())
        async with _credentials_lock:
            if cred_key not in _CREDENTIALS_SEEN:
                _CREDENTIALS_SEEN[cred_key] = None
                if len(_CREDENTIALS_SEEN) > _MAX_CREDENTIALS_CACHE:
                    _CREDENTIALS_SEEN.popitem(last=False)
                CREDENTIALS_CAPTURED.inc()
            else:
                _CREDENTIALS_SEEN.move_to_end(cred_key)

        if result.accepted:
            SESSIONS_TOTAL.labels(auth_result="success").inc()
            self._authenticated_user = username
        else:
            SESSIONS_TOTAL.labels(auth_result="failed").inc()

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
        AUTH_ATTEMPTS.labels(method="publickey", result="failed").inc()
        return False

    def session_requested(self) -> bool:
        if self._authenticated_user is None:
            return False
        if self._channel_count >= MAX_CHANNELS_PER_CONNECTION:
            logger.warning(
                "Channel limit reached (%d) for %s:%d, rejecting new channel",
                MAX_CHANNELS_PER_CONNECTION, self._client_ip, self._client_port,
            )
            return False
        self._channel_count += 1
        return True

    def server_requested(self, dest_host: str, dest_port: int,
                         orig_host: str, orig_port: int) -> bool:
        """Accept TCP forwarding requests but black-hole the data.

        Returning True avoids a fingerprinting tell (real OpenSSH accepts
        forwarding by default).  No listener is actually created, so the
        forwarded connection silently goes nowhere.
        """
        task = asyncio.ensure_future(self._emitter.emit(
            "tunnel.attempt", self._conn_id, {
                "client_ip": self._client_ip,
                "dest": f"{dest_host}:{dest_port}",
                "direction": "direct",
            }
        ))
        _track_emit(task)
        return True

    def connection_requested(self, dest_host: str, dest_port: int,
                             orig_host: str, orig_port: int) -> bool:
        """Accept reverse (remote) forwarding requests but black-hole data.

        Same rationale as server_requested — accepting prevents
        fingerprinting while the connection is never actually forwarded.
        """
        task = asyncio.ensure_future(self._emitter.emit(
            "tunnel.attempt", self._conn_id, {
                "client_ip": self._client_ip,
                "dest": f"{dest_host}:{dest_port}",
                "direction": "reverse",
            }
        ))
        _track_emit(task)
        return True


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
                 router: CommandRouter, filesystem: SessionFilesystem,
                 username: str, client_ip: str, client_port: int = 0):
        self._config = config
        self._emitter = emitter
        self._router = router
        # ── Per-connection copy-on-write filesystem ─────────────
        # Reuse the connection-level SessionFilesystem overlay so
        # shell, SFTP, and SCP all share the same mutable layer.
        self._fs = filesystem
        self._username = username
        self._client_ip = client_ip
        self._client_port = client_port
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

        # Server listen port (used for SSH_CONNECTION)
        server_port = config.port

        self._state = SessionState(
            hostname=config.hostname,
            username=username,
            uid=uid,
            home=home,
            cwd=home,
            client_ip=client_ip,
            client_port=client_port,
            server_port=server_port,
        )

    async def _run(self, process: asyncssh.SSHServerProcess):
        """Main session loop."""
        try:
            process.channel.set_echo(False)
            process.channel.set_line_mode(False)
        except AttributeError:
            pass
        await self._emitter.emit("session.start", self._session_id, {
            "client_ip": self._client_ip,
            "username": self._username,
            "tier": self._config.tier,
        })
        ACTIVE_SESSIONS.inc()

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
            last_activity = time.time()

            while not process.stdin.at_eof():
                # ── Connection-level inactivity timeout ─────────────
                # If no data has been received for CONNECTION_TIMEOUT
                # seconds, close the connection to prevent idle sessions
                # from consuming resources indefinitely.
                elapsed = time.time() - last_activity
                if elapsed > CONNECTION_TIMEOUT:
                    process.stdout.write(
                        "\r\nConnection timed out due to inactivity.\r\n"
                    )
                    break

                # ── Read with timeout, handling asyncssh signals ─────
                # TerminalSizeChanged and BreakReceived are raised by
                # asyncssh during read().  They MUST be caught here —
                # inside the loop — so the session continues instead
                # of exiting.
                try:
                    data = await asyncio.wait_for(
                        process.stdin.read(1024),
                        timeout=300,
                    )
                except asyncssh.TerminalSizeChanged:
                    # Window resized — just continue.
                    # exc.width, exc.height available if we need them.
                    continue
                except asyncssh.BreakReceived:
                    # SSH break signal — treat like Ctrl+C
                    line_buffer = ""
                    process.stdout.write("^C\r\n" + prompt)
                    continue
                except TimeoutError:
                    # Check connection-level timeout on read timeout
                    if time.time() - last_activity > CONNECTION_TIMEOUT:
                        process.stdout.write(
                            "\r\nConnection timed out due to inactivity.\r\n"
                        )
                        break
                    process.stdout.write("\r\nConnection timed out.\r\n")
                    break

                if not data:
                    break

                last_activity = time.time()

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

                        try:
                            response = await self._handle_command(command)
                        except Exception as cmd_err:
                            logger.error(
                                "Command handler error: %s",
                                cmd_err, exc_info=True,
                            )
                            response = ""

                        if response:
                            for line in response.split("\n"):
                                process.stdout.write(line + "\r\n")

                        # Re-render prompt (cwd may have changed)
                        prompt = self._render_prompt()
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

                    elif ch == "\x09":  # Tab completion
                        try:
                            if not line_buffer:
                                pass  # Empty buffer: do nothing
                            elif " " not in line_buffer:
                                # Command completion
                                prefix = line_buffer
                                matches = [c for c in self._router.known_commands
                                           if c.startswith(prefix)]
                                if len(matches) == 1:
                                    suffix = matches[0][len(prefix):] + " "
                                    line_buffer += suffix
                                    process.stdout.write(suffix)
                                elif matches:
                                    process.stdout.write(
                                        "\r\n" + "  ".join(matches)
                                        + "\r\n" + prompt + line_buffer)
                            else:
                                # Path completion
                                import posixpath
                                parts = line_buffer.rsplit(" ", 1)
                                partial = parts[1] if len(parts) > 1 else ""
                                if "/" in partial:
                                    parent_path = posixpath.dirname(partial)
                                    base = posixpath.basename(partial)
                                else:
                                    parent_path = self._state.cwd
                                    base = partial
                                if not parent_path.startswith("/"):
                                    parent_path = posixpath.join(
                                        self._state.cwd, parent_path)
                                node = self._fs.get_node(parent_path)
                                if node and node.is_dir:
                                    matches = sorted([
                                        n.name for n in node.children.values()
                                        if n.name.startswith(base)])
                                    if len(matches) == 1:
                                        suffix = matches[0][len(base):]
                                        child = node.children.get(matches[0])
                                        if child and child.is_dir:
                                            suffix += "/"
                                        line_buffer += suffix
                                        process.stdout.write(suffix)
                                    elif matches:
                                        process.stdout.write(
                                            "\r\n" + "  ".join(matches)
                                            + "\r\n" + prompt + line_buffer)
                        except Exception:
                            pass  # Tab completion failure must never crash the session

                    elif ch == "\x1b":  # Escape sequence start — consume
                        pass

                    elif ord(ch) >= 32:  # Printable
                        if len(line_buffer) >= MAX_LINE_LENGTH:
                            process.stdout.write("\a")  # Bell — reject excess input
                            continue
                        line_buffer += ch
                        process.stdout.write(ch)

        except (asyncssh.ConnectionLost, asyncssh.DisconnectError):
            # Client disconnected — normal, not an error
            logger.info(f"Client disconnected: session={self._session_id[:8]}")
        except Exception as e:
            logger.error(f"Session error: {e}", exc_info=True)
            await self._emitter.emit("session.error", self._session_id, {
                "error": str(e),
            })
        finally:
            # ── Emit filesystem delta for forensic replay ────
            delta = self._fs.get_delta()
            if delta["mutation_count"] > 0:
                await self._emitter.emit(
                    "session.fs_delta", self._session_id, {
                        "files_created": delta["files_created"],
                        "files_modified": delta["files_modified"],
                        "dirs_created": delta["dirs_created"],
                        "paths_deleted": delta["paths_deleted"],
                        "mutation_count": delta["mutation_count"],
                    }
                )
                logger.info(
                    f"Session {self._session_id[:8]} filesystem delta: "
                    f"{delta['mutation_count']} mutations, "
                    f"{len(delta['files_created'])} files created, "
                    f"{len(delta['paths_deleted'])} paths deleted"
                )

            await self._emitter.emit("session.end", self._session_id, {
                "reason": "disconnect",
                "command_count": self._command_count,
                "duration_seconds": round(time.time() - self._start_time, 2),
                "fs_mutations": delta["mutation_count"],
            })
            # ── Metrics: session teardown ───────────────────
            ACTIVE_SESSIONS.dec()
            SESSION_DURATION.observe(time.time() - self._start_time)
            try:
                process.exit(0)
            except Exception:
                logger.debug("Process already closed during exit")

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

        COMMANDS_PROCESSED.labels(tier=str(self._config.tier)).inc()

        # Apply guardrail filters — strip patterns that would break immersion
        response = self._apply_guardrails(response)

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

    def _apply_guardrails(self, response: str) -> str:
        """Strip patterns from responses that would reveal the honeypot."""
        if not response:
            return response

        # Cap response length before applying regex filters to prevent ReDoS
        if len(response) > 100_000:
            response = response[:100_000]

        # ReDoS mitigation: patterns are pre-compiled at config load time;
        # invalid patterns were already filtered out.  We still wrap in
        # try/except for defensive safety.
        for compiled_pat in self._config.filter_patterns:
            try:
                response = compiled_pat.sub("[FILTERED]", response)
            except (re.error, RecursionError):
                pass

        # Truncate excessively long output
        lines = response.split("\n")
        if len(lines) > self._config.max_response_lines:
            response = "\n".join(lines[:self._config.max_response_lines])

        return response

    # Pre-compiled alert patterns — avoids re-compiling on every command
    _ALERT_PATTERNS = {
        "lateral_movement":     (re.compile(r"ssh\s+\w+@|rdp|psexec", re.IGNORECASE), "T1021"),
        "reverse_shell":        (re.compile(r"nc\s.*-e|/dev/tcp/|socat|bash\s+-i", re.IGNORECASE), "T1059.004"),
        "download":             (re.compile(r"wget\s+http|curl\s+.*http", re.IGNORECASE), "T1105"),
        "privilege_escalation": (re.compile(r"sudo|su\s+-|chmod\s+[47]", re.IGNORECASE), "T1548"),
        "credential_access":    (re.compile(r"cat.*/etc/shadow|\.aws/|\.ssh/id_", re.IGNORECASE), "T1552"),
        "exfiltration":         (re.compile(r"scp\s|rsync\s|curl.*-d|curl.*--data", re.IGNORECASE), "T1048"),
        "defense_evasion":      (re.compile(r"history\s+-c|unset\s+HISTFILE|rm.*\.bash_history", re.IGNORECASE), "T1070"),
        "discovery":            (re.compile(r"cat\s+/etc/passwd|id\b|ifconfig|ip\s+addr", re.IGNORECASE), "T1087"),
    }

    async def _check_alerts(self, command: str):
        """Fire alerts for high-severity behaviours."""
        for behavior, (compiled_pattern, technique) in self._ALERT_PATTERNS.items():
            if compiled_pattern.search(command):
                severity = "critical" if behavior in (
                    "reverse_shell", "lateral_movement", "exfiltration"
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

        if cmd in ("pwd", "whoami", "id", "hostname", "echo", "true",
                    "false", ":", "cd", "export", "unset"):
            target = 0.02
        elif cmd in ("ls", "cat", "head", "tail", "stat", "file"):
            target = 0.05
        elif cmd in ("find", "grep", "locate", "du"):
            target = random.uniform(0.2, 0.8)
        elif cmd in ("ssh", "curl", "wget", "ping", "dig", "nslookup",
                      "traceroute", "scp"):
            target = random.uniform(0.5, 3.0)
        elif cmd in ("ps", "top", "free", "df", "mount", "lsblk",
                      "systemctl", "service", "netstat", "ss"):
            target = random.uniform(0.05, 0.2)
        elif cmd in ("apt", "apt-get", "dpkg", "pip", "pip3"):
            target = random.uniform(0.3, 1.0)
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
        if cwd == home:
            cwd = "~"
        elif cwd.startswith(home + "/"):
            cwd = "~" + cwd[len(home):]

        user   = self._state.username
        host   = self._config.hostname
        suffix = "#" if self._state.uid == 0 else "$"

        if self._state.uid == 0:
            user_host = f"\x1b[01;31m{user}@{host}\x1b[00m"
        else:
            user_host = f"\x1b[01;32m{user}@{host}\x1b[00m"

        cwd_colored = f"\x1b[01;34m{cwd}\x1b[00m"
        return f"{user_host}:{cwd_colored}{suffix} "


# ─────────────────────────────────────────────────────────
#  SFTP Subsystem
# ─────────────────────────────────────────────────────────

# Maximum bytes we'll accept per SFTP write to prevent memory exhaustion.
_SFTP_MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB


class DecoySFTPServer(asyncssh.SFTPServer):
    """Minimal SFTP server backed by the per-session virtual filesystem.

    Provides directory listing, file reads, and write capture.  All
    operations emit telemetry so the SOC can see exactly what the
    attacker touched via SFTP.

    Note: asyncssh SFTPServer receives all paths as ``bytes`` and
    delegates read/write/close to server-level methods that receive
    the opaque file object returned by ``open()``.
    """

    def __init__(self, chan: asyncssh.SSHServerChannel):
        # Do NOT pass a chroot — we handle path resolution ourselves.
        super().__init__(chan)

        conn = chan.get_connection()
        owner = conn.get_owner()  # DecoySSHServer instance
        self._decoy_fs = owner._fs  # Reuse connection-level overlay (shared with shell & SCP)
        self._emitter = owner._emitter
        self._conn_id = owner._conn_id
        self._client_ip = owner._client_ip

        # Resolve home directory for the authenticated user
        username = conn.get_extra_info("username") or "unknown"
        self._home = f"/home/{username}"
        for cred in owner._config.credentials:
            if cred.get("username") == username:
                self._home = cred.get("home", self._home)
                break

        self._emit_sftp("sftp.session_start", {"client_ip": self._client_ip})

    # ── Helpers ──────────────────────────────────────────

    def _emit_sftp(self, event_type: str, data: dict):
        """Fire-and-forget telemetry for SFTP operations."""
        task = asyncio.ensure_future(
            self._emitter.emit(event_type, self._conn_id, data)
        )
        _track_emit(task)

    def _to_str(self, path: bytes | str) -> str:
        """Decode a bytes path from asyncssh to str for the virtual FS."""
        if isinstance(path, bytes):
            return path.decode("utf-8", errors="replace")
        return path

    def _resolve(self, path: bytes | str) -> str:
        """Resolve a client-supplied path against the session home."""
        p = self._to_str(path)
        if not posixpath.isabs(p):
            p = posixpath.join(self._home, p)
        resolved = posixpath.normpath(p)
        # Enforce home-directory boundary
        if not resolved.startswith(self._home + "/") and resolved != self._home:
            resolved = self._home
        return resolved

    def _node_to_attrs(self, node) -> asyncssh.SFTPAttrs:
        """Convert an FSNode to asyncssh SFTPAttrs."""
        try:
            perm_int = int(node.permissions, 8) if node.permissions else 0o644
        except (ValueError, TypeError):
            perm_int = 0o644
        if node.is_dir:
            perm_int |= stat_mod.S_IFDIR
        else:
            perm_int |= stat_mod.S_IFREG
        return asyncssh.SFTPAttrs(
            size=node.size if not node.is_dir else 4096,
            uid=0, gid=0,
            permissions=perm_int,
        )

    # ── SFTPServer overrides ─────────────────────────────
    # All path parameters arrive as ``bytes`` from asyncssh.

    def stat(self, path: bytes) -> asyncssh.SFTPAttrs:
        resolved = self._resolve(path)
        self._emit_sftp("sftp.stat", {"path": resolved})
        node = self._decoy_fs.get_node(resolved)
        if node is None:
            raise asyncssh.SFTPNoSuchFile(f"No such file: {resolved}")
        return self._node_to_attrs(node)

    def lstat(self, path: bytes) -> asyncssh.SFTPAttrs:
        # No symlink support — same as stat
        return self.stat(path)

    async def scandir(self, path: bytes):
        """Yield SFTPName entries for directory listing."""
        resolved = self._resolve(path)
        self._emit_sftp("sftp.listdir", {"path": resolved})
        node = self._decoy_fs.get_node(resolved)
        if node is None:
            raise asyncssh.SFTPNoSuchFile(f"No such directory: {resolved}")
        if not node.is_dir:
            raise asyncssh.SFTPFailure(f"Not a directory: {resolved}")

        # Yield '.' and '..'
        self_attrs = self._node_to_attrs(node)
        yield asyncssh.SFTPName(b".", b"", self_attrs)
        parent_path = posixpath.dirname(resolved.rstrip("/")) or "/"
        parent_node = self._decoy_fs.get_node(parent_path)
        parent_attrs = self._node_to_attrs(parent_node) if parent_node else self_attrs
        yield asyncssh.SFTPName(b"..", b"", parent_attrs)

        for name, child in sorted(node.children.items()):
            attrs = self._node_to_attrs(child)
            yield asyncssh.SFTPName(
                name.encode("utf-8") if isinstance(name, str) else name,
                b"", attrs,
            )

    def open(self, path: bytes, pflags: int, attrs: asyncssh.SFTPAttrs):
        resolved = self._resolve(path)
        self._emit_sftp("sftp.open", {"path": resolved, "pflags": pflags})

        writing = bool(pflags & (asyncssh.FXF_WRITE | asyncssh.FXF_CREAT))

        node = self._decoy_fs.get_node(resolved)

        if writing and node is None:
            self._decoy_fs.create_file(resolved, content="")
            node = self._decoy_fs.get_node(resolved)

        if node is None:
            raise asyncssh.SFTPNoSuchFile(f"No such file: {resolved}")
        if node.is_dir:
            raise asyncssh.SFTPFailure(f"Is a directory: {resolved}")

        return _DecoySFTPHandle(resolved, node, writing)

    def read(self, file_obj: '_DecoySFTPHandle', offset: int,
             size: int) -> bytes:
        content = file_obj.node.content or ""
        data = content.encode("utf-8", errors="replace")
        return data[offset:offset + size]

    def write(self, file_obj: '_DecoySFTPHandle', offset: int,
              data: bytes) -> int:
        if offset > _SFTP_MAX_FILE_SIZE:
            raise asyncssh.SFTPFailure("Offset too large")
        file_obj.write_buf.append((offset, data))
        file_obj.total_written += len(data)
        # Cap both total bytes AND number of write operations
        if file_obj.total_written > _SFTP_MAX_FILE_SIZE:
            raise asyncssh.SFTPFailure("File too large")
        if len(file_obj.write_buf) > 10_000:  # Max 10K write ops per file
            raise asyncssh.SFTPFailure("Too many write operations")
        return len(data)

    def close(self, file_obj: '_DecoySFTPHandle'):
        if file_obj.writing and file_obj.write_buf:
            # Reconstruct file from offset-keyed writes
            file_obj.write_buf.sort(key=lambda x: x[0])
            # Warn about offset anomalies (gaps/overlaps)
            for i in range(len(file_obj.write_buf) - 1):
                end = file_obj.write_buf[i][0] + len(file_obj.write_buf[i][1])
                next_start = file_obj.write_buf[i + 1][0]
                if end != next_start:
                    logger.debug("SFTP write offset anomaly at byte %d (expected %d, got %d)",
                                 end, end, next_start)
                    break  # Log once, don't spam
            content = b"".join(chunk for _, chunk in file_obj.write_buf)
            try:
                text = content.decode("utf-8", errors="replace")
            except Exception:
                text = content.hex()
            self._decoy_fs.create_file(file_obj.path, content=text)
            self._emit_sftp("sftp.file_written", {
                "path": file_obj.path,
                "size": len(content),
            })

    def mkdir(self, path: bytes, attrs: asyncssh.SFTPAttrs):
        resolved = self._resolve(path)
        self._emit_sftp("sftp.mkdir", {"path": resolved})
        ok = self._decoy_fs.create_directory(resolved)
        if not ok:
            raise asyncssh.SFTPFailure(f"mkdir failed: {resolved}")

    def rmdir(self, path: bytes):
        resolved = self._resolve(path)
        self._emit_sftp("sftp.rmdir", {"path": resolved})
        ok = self._decoy_fs.remove_directory(resolved)
        if not ok:
            raise asyncssh.SFTPFailure(f"rmdir failed: {resolved}")

    def remove(self, path: bytes):
        resolved = self._resolve(path)
        self._emit_sftp("sftp.remove", {"path": resolved})
        ok = self._decoy_fs.remove_file(resolved)
        if not ok:
            raise asyncssh.SFTPFailure(f"remove failed: {resolved}")

    def rename(self, oldpath: bytes, newpath: bytes):
        """Rename a file.

        Note: this is not atomic, but each SFTP session gets its own
        CoW filesystem overlay, so concurrent sessions are isolated.
        """
        old_resolved = self._resolve(oldpath)
        new_resolved = self._resolve(newpath)
        self._emit_sftp("sftp.rename", {
            "old": old_resolved, "new": new_resolved,
        })
        content = self._decoy_fs.read_file(old_resolved)
        if content is None:
            raise asyncssh.SFTPNoSuchFile(f"No such file: {old_resolved}")
        self._decoy_fs.create_file(new_resolved, content=content)
        self._decoy_fs.remove_file(old_resolved)

    def realpath(self, path: bytes) -> bytes:
        resolved = self._resolve(path)
        return resolved.encode("utf-8")

    def exit(self):
        """Called when the SFTP session ends — emit filesystem delta."""
        delta = self._decoy_fs.get_delta()
        if delta["mutation_count"] > 0:
            self._emit_sftp("sftp.fs_delta", {
                "files_created": delta["files_created"],
                "files_modified": delta["files_modified"],
                "dirs_created": delta["dirs_created"],
                "paths_deleted": delta["paths_deleted"],
                "mutation_count": delta["mutation_count"],
            })


class _DecoySFTPHandle:
    """Opaque file handle passed to DecoySFTPServer.read/write/close."""

    __slots__ = ("path", "node", "writing", "write_buf", "total_written")

    def __init__(self, path: str, node, writing: bool):
        self.path = path
        self.node = node
        self.writing = writing
        self.write_buf: list[tuple[int, bytes]] = []
        self.total_written = 0


# ─────────────────────────────────────────────────────────
#  SCP Subsystem (handled via exec channel)
# ─────────────────────────────────────────────────────────

async def _handle_scp(process: asyncssh.SSHServerProcess, command: str,
                      config: DecoyConfig, emitter: EventEmitter,
                      filesystem: SessionFilesystem, username: str,
                      client_ip: str):
    """Handle SCP protocol over an exec channel.

    SCP uses a simple binary protocol over stdin/stdout:
      - Server sends 0x00 to acknowledge readiness
      - For uploads (scp -t): client sends C<mode> <size> <name>,
        then the file data, then 0x00
      - For downloads (scp -f): server sends C<mode> <size> <name>,
        then file data, then 0x00

    Reuses the connection-level SessionFilesystem overlay so SCP
    mutations are visible to shell and SFTP on the same connection.
    """
    session_id = str(uuid.uuid4())
    fs = filesystem

    # Resolve home for the user
    home = f"/home/{username}"
    for cred in config.credentials:
        if cred.get("username") == username:
            home = cred.get("home", home)
            break

    # Parse the scp command to determine mode and target path
    try:
        parts = shlex.split(command)
    except ValueError:
        parts = command.split()

    # Find -t (upload to server) or -f (download from server)
    mode = None
    target_path = None
    for i, part in enumerate(parts):
        if part == "-t":
            mode = "upload"
            if i + 1 < len(parts):
                target_path = parts[i + 1]
        elif part == "-f":
            mode = "download"
            if i + 1 < len(parts):
                target_path = parts[i + 1]

    if target_path and not target_path.startswith("/"):
        target_path = posixpath.join(home, target_path)

    # Normalize and enforce home-directory boundary
    if target_path:
        normalized = posixpath.normpath(target_path)
        if not normalized.startswith(home + "/") and normalized != home:
            process.stdout.write("\x01scp: permission denied\n")
            process.close()
            return
        target_path = normalized

    await emitter.emit("scp.start", session_id, {
        "client_ip": client_ip,
        "mode": mode or "unknown",
        "target": target_path or "unknown",
        "raw_command": command,
    })

    if mode == "upload":
        await _scp_receive(process, fs, emitter, session_id,
                           target_path or home, client_ip)
    elif mode == "download":
        await _scp_send(process, fs, emitter, session_id,
                        target_path or "/dev/null", client_ip)
    else:
        # Unknown SCP mode — just acknowledge and close
        process.stdout.write("\x00")
        process.exit(0)
        return

    # Emit filesystem delta
    delta = fs.get_delta()
    if delta["mutation_count"] > 0:
        await emitter.emit("scp.fs_delta", session_id, {
            "files_created": delta["files_created"],
            "mutation_count": delta["mutation_count"],
        })

    process.exit(0)


async def _scp_receive(process, fs, emitter, session_id, target_path, client_ip):
    """Handle SCP upload (scp -t): receive files from client."""
    # Send initial acknowledgement
    process.stdout.write("\x00")

    try:
        while not process.stdin.at_eof():
            # Read the control line (e.g., "C0644 12345 filename\n")
            line = ""
            while True:
                ch = await asyncio.wait_for(process.stdin.read(1), timeout=30)
                if isinstance(ch, bytes):
                    ch = ch.decode("utf-8", errors="replace")
                if not ch:
                    return
                if ch == "\n":
                    break
                line += ch

            line = line.strip()
            if not line:
                continue

            if line.startswith("C"):
                # File transfer: C<perms> <size> <filename>
                parts = line.split(" ", 2)
                if len(parts) < 3:
                    process.stdout.write("\x01scp: protocol error\n")
                    return
                perms = parts[0][1:]  # strip 'C'
                try:
                    file_size = int(parts[1])
                except ValueError:
                    process.stdout.write("\x01scp: invalid size\n")
                    return
                if file_size < 0:
                    process.stdout.write("\x01scp: invalid file size\n")
                    return
                if file_size > _SFTP_MAX_FILE_SIZE:
                    file_size = _SFTP_MAX_FILE_SIZE
                filename = parts[2]

                # Reject path traversal attempts in SCP filenames
                if '/' in filename or '..' in filename or '\x00' in filename:
                    process.stdout.write("\x01scp: invalid filename\n")
                    return
                if not filename or not filename.strip():
                    process.stdout.write("\x01scp: invalid filename\n")
                    return

                # Acknowledge the header
                process.stdout.write("\x00")

                # Read the file data
                data = b""
                remaining = file_size
                while remaining > 0:
                    chunk = await asyncio.wait_for(
                        process.stdin.read(min(remaining, 65536)),
                        timeout=30,
                    )
                    if not chunk:
                        break
                    data += chunk.encode("utf-8", errors="surrogateescape") \
                        if isinstance(chunk, str) else chunk
                    remaining -= len(chunk)

                # Read trailing NUL byte
                try:
                    await asyncio.wait_for(process.stdin.read(1), timeout=5)
                except (TimeoutError, asyncssh.DisconnectError):
                    pass

                # Store in virtual filesystem
                if fs.is_directory(target_path):
                    file_path = posixpath.join(target_path, filename)
                else:
                    file_path = target_path

                try:
                    text_content = data.decode("utf-8", errors="replace")
                except Exception:
                    text_content = data.hex()

                fs.create_file(file_path, content=text_content,
                               permissions=f"0{perms}")

                await emitter.emit("scp.file_received", session_id, {
                    "client_ip": client_ip,
                    "path": file_path,
                    "size": len(data),
                    "filename": filename,
                })

                # Acknowledge file received
                process.stdout.write("\x00")

            elif line.startswith("D"):
                # Directory creation: D<perms> 0 <dirname>
                parts = line.split(" ", 2)
                if len(parts) >= 3:
                    dirname = parts[2]
                    # Validate dirname the same way as filenames
                    if '/' in dirname or '..' in dirname or '\x00' in dirname:
                        process.stdout.write("\x01scp: invalid directory name\n")
                        return
                    if not dirname or not dirname.strip():
                        process.stdout.write("\x01scp: invalid directory name\n")
                        return
                    dir_path = posixpath.join(target_path, dirname)
                    fs.create_directory(dir_path)
                process.stdout.write("\x00")

            elif line.startswith("E"):
                # End of directory
                process.stdout.write("\x00")

            elif line == "\x00":
                continue
            else:
                # Unknown control — acknowledge anyway
                process.stdout.write("\x00")

    except (TimeoutError, asyncssh.ConnectionLost, asyncssh.DisconnectError):
        pass


async def _scp_send(process, fs, emitter, session_id, target_path, client_ip):
    """Handle SCP download (scp -f): send file to client."""
    await emitter.emit("scp.file_requested", session_id, {
        "client_ip": client_ip,
        "path": target_path,
    })

    node = fs.get_node(target_path)
    if node is None:
        process.stderr.write(f"scp: {target_path}: No such file or directory\n")
        process.exit(1)
        return

    if node.is_dir:
        process.stderr.write(f"scp: {target_path}: not a regular file\n")
        process.exit(1)
        return

    content = (node.content or "").encode("utf-8", errors="replace")
    filename = node.name

    # Wait for client readiness (NUL byte)
    try:
        await asyncio.wait_for(process.stdin.read(1), timeout=10)
    except (TimeoutError, asyncssh.DisconnectError):
        return

    # Send file header
    process.stdout.write(f"C0{node.permissions or '644'} {len(content)} {filename}\n")

    # Wait for ack
    try:
        await asyncio.wait_for(process.stdin.read(1), timeout=10)
    except (TimeoutError, asyncssh.DisconnectError):
        return

    # Send file content
    process.stdout.write(content.decode("utf-8", errors="replace"))
    process.stdout.write("\x00")

    # Wait for final ack
    try:
        await asyncio.wait_for(process.stdin.read(1), timeout=10)
    except (TimeoutError, asyncssh.DisconnectError):
        pass


# ─────────────────────────────────────────────────────────
#  Server Factory
# ─────────────────────────────────────────────────────────

def create_server_factory(config, auth_handler, emitter, router, filesystem):
    def factory():
        return DecoySSHServer(config, auth_handler, emitter, router, filesystem)
    return factory


def create_process_factory(config, emitter, router, filesystem):
    """
    Returns a coroutine that asyncssh calls when a shell or exec is requested.

    Intercepts SCP exec requests and routes them to the SCP handler
    instead of the interactive shell.
    """
    async def handle_client(process: asyncssh.SSHServerProcess):
        username  = process.get_extra_info("username") or "unknown"
        peername  = process.get_extra_info("peername")
        client_ip = peername[0] if peername else "unknown"
        client_port = peername[1] if peername and len(peername) > 1 else 0

        # Retrieve the per-connection SessionFilesystem overlay from
        # the DecoySSHServer so shell, SFTP, and SCP all share it.
        conn = process.channel.get_connection()
        owner = conn.get_owner()
        session_fs = owner._fs

        # ── SCP interception ────────────────────────────────
        # When the client runs "scp file user@host:path", the SSH
        # client opens an exec channel with the command "scp -t path"
        # (or "scp -f path" for downloads).  Detect this and route
        # to the SCP protocol handler instead of the shell.
        command = process.command
        if command and re.match(r'^\s*scp\s+', command):
            await _handle_scp(
                process, command.strip(), config, emitter,
                session_fs, username, client_ip,
            )
            return

        global _active_sessions
        with _connections_lock:
            if _active_sessions >= MAX_CONCURRENT_SESSIONS:
                logger.warning(
                    "Session limit reached (%d), rejecting %s:%d",
                    MAX_CONCURRENT_SESSIONS, client_ip, client_port,
                )
                process.exit(1)
                return
            _active_sessions += 1

        try:
            session = DecoySSHSession(
                config, emitter, router, session_fs,
                username, client_ip, client_port,
            )
            await session._run(process)
        finally:
            with _connections_lock:
                _active_sessions -= 1

    return handle_client


# ─────────────────────────────────────────────────────────
#  Host Key Management
# ─────────────────────────────────────────────────────────

def ensure_host_key(key_path_str: str):
    key_path = Path(key_path_str)
    if not key_path.exists():
        logger.info(f"Generating new host key at {key_path}")
        key_path.parent.mkdir(parents=True, exist_ok=True)
        key = asyncssh.generate_private_key("ssh-ed25519", comment="cicdecoy-host-key")
        key_path.write_bytes(key.export_private_key())
    return asyncssh.read_private_key(str(key_path))


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
    try:
        config.tier           = int(os.environ.get("DECOY_TIER",       config.tier))
    except (ValueError, TypeError):
        raise ValueError(f"DECOY_TIER must be an integer (1, 2, or 3), got: {os.environ.get('DECOY_TIER')!r}") from None
    if config.tier not in (1, 2, 3):
        raise ValueError(f"Invalid DECOY_TIER={config.tier}, must be 1, 2, or 3")
    config.nats_endpoint      = os.environ.get("NATS_URL",          os.environ.get("NATS_ENDPOINT",      config.nats_endpoint))
    config.inference_endpoint = os.environ.get("INFERENCE_URL",     os.environ.get("INFERENCE_ENDPOINT", config.inference_endpoint))
    config.profile_name       = os.environ.get("DECOY_PROFILE_REF", os.environ.get("DECOY_PROFILE",      config.profile_name))

    # ── FIX: Also strip SSH-2.0- from env-overridden banner ──
    banner_env = os.environ.get("DECOY_BANNER") or os.environ.get("SSH_BANNER")
    if banner_env:
        config.ssh_banner = _strip_ssh2_prefix(banner_env)

    emitter = EventEmitter(config)
    await emitter.connect()

    auth_handler = AuthHandler(config)
    router = CommandRouter(config)
    await router.initialize()

    filesystem = VirtualFilesystem.from_profile(config.profile_name)

    host_key = ensure_host_key(
        os.environ.get("HOST_KEY_PATH", config.host_key_path)
    )

    from prometheus_client import start_http_server
    metrics_port = int(os.environ.get("METRICS_PORT", "9091"))
    start_http_server(metrics_port)
    logger.info(f"Prometheus metrics on :{metrics_port}")

    logger.info(
        f"Starting CI/CDecoy SSH server: "
        f"name={config.name} tier={config.tier} port={config.port} "
        f"hostname={config.hostname} auth_mode={config.auth_mode} "
        f"banner={config.ssh_banner}"
    )

    await emitter.emit("decoy.online", "system", {
        "decoy_name": config.name,
        "tier": config.tier,
        "port": config.port,
    })

    # Build optional algorithm overrides — only pass non-empty tuples so
    # asyncssh falls back to its own defaults when no override is set.
    # Filter configured algorithms against what asyncssh actually supports
    # to avoid ValueError on newer versions that drop legacy algorithms.
    from asyncssh.mac import get_mac_algs
    from asyncssh.kex import get_kex_algs
    from asyncssh.encryption import get_encryption_algs
    from asyncssh.compression import get_compression_algs

    def _filter_algs(configured, available_fn):
        available = {a.decode() if isinstance(a, bytes) else a for a in available_fn()}
        return [a for a in configured if a in available]

    algo_kwargs: dict = {}
    if config.kex_algs:
        filtered = _filter_algs(config.kex_algs, get_kex_algs)
        if filtered:
            algo_kwargs["kex_algs"] = filtered
    if config.encryption_algs:
        filtered = _filter_algs(config.encryption_algs, get_encryption_algs)
        if filtered:
            algo_kwargs["encryption_algs"] = filtered
    if config.mac_algs:
        filtered = _filter_algs(config.mac_algs, get_mac_algs)
        if filtered:
            algo_kwargs["mac_algs"] = filtered
    if config.compression_algs:
        filtered = _filter_algs(config.compression_algs, get_compression_algs)
        if filtered:
            algo_kwargs["compression_algs"] = filtered

    server = await asyncssh.create_server(
        create_server_factory(config, auth_handler, emitter, router, filesystem),
        host="0.0.0.0",
        port=config.port,
        server_host_keys=[host_key],
        process_factory=create_process_factory(config, emitter, router, filesystem),
        server_version=config.ssh_banner,
        login_timeout=60,
        keepalive_interval=30,
        sftp_factory=DecoySFTPServer,
        allow_scp=True,
        **algo_kwargs,
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
    try:
        await asyncio.wait_for(server.wait_closed(), timeout=10.0)
    except TimeoutError:
        logger.warning("Shutdown timeout — forcing close")
    # Drain any pending telemetry emit tasks before closing NATS
    if _pending_emits:
        logger.info("Draining %d pending emit tasks...", len(_pending_emits))
        try:
            await asyncio.wait_for(
                asyncio.gather(*_pending_emits, return_exceptions=True),
                timeout=5.0,
            )
        except TimeoutError:
            logger.warning("Timed out waiting for pending emit tasks")
    await router.shutdown()
    await emitter.close()
    logger.info("Server stopped")


if __name__ == "__main__":
    asyncio.run(main())
