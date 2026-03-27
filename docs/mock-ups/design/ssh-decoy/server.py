# CI/CDecoy — SSH Decoy Server
# images/ssh-decoy/src/server.py
#
# High-fidelity SSH honeypot with tiered response handling.
# Tier 1: Log connections only
# Tier 2: Scripted deterministic responses
# Tier 3: LLM-backed adaptive responses with full session state

import asyncio
import json
import logging
import os
import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import paramiko
import nats
from nats.aio.client import Client as NATSClient

from session import SessionState
from filesystem import VirtualFilesystem
from command_router import CommandRouter
from auth_handler import AuthHandler

logger = logging.getLogger("cicdecoy.ssh")


# ─────────────────────────────────────────────────────────
#  Configuration (loaded from Decoy CRD spec at startup)
# ─────────────────────────────────────────────────────────

@dataclass
class DecoyConfig:
    """Parsed from the Decoy CRD manifest."""
    name: str
    hostname: str
    domain: str
    tier: int                                     # 1, 2, or 3
    port: int = 22
    ssh_banner: str = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
    host_key_path: str = "/etc/cicdecoy/ssh_host_rsa_key"

    # Auth config
    auth_mode: str = "realistic"                  # open | selective | realistic | closed
    credentials: list = field(default_factory=list)
    fail_before_success: int = 2
    lockout_after: int = 10
    lockout_duration: int = 300

    # Inference config (tier 3)
    inference_endpoint: str = "http://inference-gateway:8000"
    profile_name: str = ""
    max_session_tokens: int = 8192
    temperature: float = 0.3

    # Telemetry
    nats_endpoint: str = "nats://msg-bus:4222"
    nats_subject: str = "decoy.events"
    capture_keystrokes: bool = True
    capture_uploads: bool = True

    # Fast-path commands (regex → source mapping)
    fast_path_commands: list = field(default_factory=list)

    # Guardrails
    filter_patterns: list = field(default_factory=list)
    disallowed_paths: list = field(default_factory=list)
    max_response_lines: int = 500

    @classmethod
    def from_crd(cls, crd_path: str) -> "DecoyConfig":
        """Load configuration from mounted CRD spec."""
        import yaml
        with open(crd_path) as f:
            spec = yaml.safe_load(f)
        # Parse CRD fields into config — abbreviated for prototype
        return cls(
            name=spec.get("metadata", {}).get("name", "unknown"),
            hostname=spec.get("spec", {}).get("identity", {}).get("hostname", "localhost"),
            domain=spec.get("spec", {}).get("identity", {}).get("domain", "local"),
            tier=spec.get("spec", {}).get("fidelity", {}).get("tier", 1),
            port=spec.get("spec", {}).get("service", {}).get("port", 22),
        )


# ─────────────────────────────────────────────────────────
#  Event Emitter — all interaction data flows through here
# ─────────────────────────────────────────────────────────

class EventEmitter:
    """Publishes structured events to the message bus for CTI processing."""

    def __init__(self, config: DecoyConfig):
        self.config = config
        self.nc: Optional[NATSClient] = None

    async def connect(self):
        self.nc = await nats.connect(self.config.nats_endpoint)
        logger.info(f"Connected to NATS at {self.config.nats_endpoint}")

    async def emit(self, event_type: str, session_id: str, data: dict):
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "decoy": self.config.name,
            "hostname": self.config.hostname,
            "session_id": session_id,
            "event_type": event_type,
            "tier": self.config.tier,
            "data": data,
        }
        subject = f"{self.config.nats_subject}.{self.config.name}.{event_type}"
        await self.nc.publish(subject, json.dumps(event).encode())
        logger.debug(f"Emitted {event_type} for session {session_id[:8]}")

    async def close(self):
        if self.nc:
            await self.nc.close()


# ─────────────────────────────────────────────────────────
#  SSH Session Handler — per-connection logic
# ─────────────────────────────────────────────────────────

class DecoySSHSession:
    """
    Handles a single attacker SSH session.

    Each session maintains its own state (cwd, env vars, command history)
    and routes commands through the appropriate tier handler.
    """

    def __init__(
        self,
        config: DecoyConfig,
        emitter: EventEmitter,
        router: CommandRouter,
        channel: paramiko.Channel,
        username: str,
        client_ip: str,
    ):
        self.config = config
        self.emitter = emitter
        self.router = router
        self.channel = channel
        self.username = username
        self.client_ip = client_ip
        self.session_id = str(uuid.uuid4())
        self.start_time = time.time()
        self.command_count = 0

        # Initialize session state
        self.state = SessionState(
            hostname=config.hostname,
            username=username,
            uid=self._resolve_uid(username),
            home=self._resolve_home(username),
            cwd=self._resolve_home(username),
        )

        # Initialize virtual filesystem from profile
        self.filesystem = VirtualFilesystem.from_profile(config.profile_name)

    def _resolve_uid(self, username: str) -> int:
        for cred in self.config.credentials:
            if cred.get("username") == username:
                return cred.get("uid", 1000)
        return 1000

    def _resolve_home(self, username: str) -> str:
        for cred in self.config.credentials:
            if cred.get("username") == username:
                return cred.get("home", f"/home/{username}")
        return f"/home/{username}"

    async def handle(self):
        """Main session loop — read commands, generate responses."""
        await self.emitter.emit("session.start", self.session_id, {
            "client_ip": self.client_ip,
            "username": self.username,
            "tier": self.config.tier,
        })

        # Send initial prompt
        prompt = self._render_prompt()
        self.channel.sendall(prompt.encode())

        buffer = b""
        last_keystroke = time.time()

        try:
            while True:
                # Read from channel with timeout
                data = self.channel.recv(4096)
                if not data:
                    break

                # Keystroke timing capture
                now = time.time()
                if self.config.capture_keystrokes:
                    await self.emitter.emit("keystroke", self.session_id, {
                        "data": data.hex(),
                        "interval_ms": int((now - last_keystroke) * 1000),
                    })
                last_keystroke = now

                # Buffer until newline (command submission)
                buffer += data

                # Echo characters back (terminal emulation)
                self.channel.sendall(data)

                if b"\r" in buffer or b"\n" in buffer:
                    command = buffer.decode("utf-8", errors="replace").strip()
                    buffer = b""

                    if not command:
                        self.channel.sendall(b"\r\n" + prompt.encode())
                        continue

                    # Handle special commands
                    if command in ("exit", "logout", "quit"):
                        await self.emitter.emit("session.end", self.session_id, {
                            "reason": "user_exit",
                            "command_count": self.command_count,
                            "duration_seconds": time.time() - self.start_time,
                        })
                        self.channel.sendall(b"\r\nlogout\r\n")
                        break

                    # Process command through router
                    self.command_count += 1
                    response = await self._process_command(command)

                    # Send response
                    self.channel.sendall(b"\r\n")
                    if response:
                        # Normalize line endings for terminal
                        for line in response.split("\n"):
                            self.channel.sendall(line.encode() + b"\r\n")

                    self.channel.sendall(prompt.encode())

        except Exception as e:
            logger.error(f"Session {self.session_id[:8]} error: {e}")
            await self.emitter.emit("session.error", self.session_id, {
                "error": str(e),
            })
        finally:
            await self.emitter.emit("session.end", self.session_id, {
                "reason": "disconnect",
                "command_count": self.command_count,
                "duration_seconds": time.time() - self.start_time,
            })
            self.channel.close()

    async def _process_command(self, command: str) -> str:
        """
        Route a command through the tier-appropriate handler.

        Flow:
        1. Log the raw command
        2. Check fast-path (deterministic, no LLM)
        3. If no fast-path match, dispatch to tier handler
        4. Apply guardrails to response
        5. Update session state
        6. Log the response
        """
        start = time.time()

        # Emit command event
        await self.emitter.emit("command.exec", self.session_id, {
            "command": command,
            "cwd": self.state.cwd,
            "command_index": self.command_count,
        })

        # Check for alert-worthy patterns
        await self._check_alert_patterns(command)

        # Route through command router
        response = await self.router.route(
            command=command,
            session_state=self.state,
            filesystem=self.filesystem,
            tier=self.config.tier,
        )

        # Apply guardrails (tier 3 only — LLM output filtering)
        if self.config.tier == 3:
            response = self._apply_guardrails(response)

        # Update session state based on command
        self.state.update_from_command(command, response)

        # Add realistic latency if response was too fast
        elapsed = time.time() - start
        await self._inject_latency(command, elapsed)

        # Emit response event
        await self.emitter.emit("command.response", self.session_id, {
            "command": command,
            "response_length": len(response),
            "latency_ms": int((time.time() - start) * 1000),
            "source": self.router.last_source,   # "fast_path" | "scripted" | "llm"
        })

        return response

    def _apply_guardrails(self, response: str) -> str:
        """Filter LLM output to prevent breaking character."""
        for pattern in self.config.filter_patterns:
            if re.search(pattern, response):
                logger.warning(f"Guardrail triggered: {pattern}")
                # Replace the problematic content rather than blocking entirely
                response = re.sub(pattern, "", response)

        # Truncate excessive output
        lines = response.split("\n")
        if len(lines) > self.config.max_response_lines:
            response = "\n".join(lines[:self.config.max_response_lines])

        # Check for disallowed path references
        for path in self.config.disallowed_paths:
            if path in response:
                response = response.replace(path, "/usr/local/lib")

        return response

    async def _check_alert_patterns(self, command: str):
        """Check for high-severity attacker behaviors."""
        alert_patterns = {
            "lateral_movement": r"ssh\s+\w+@|rdp|psexec|wmi",
            "reverse_shell": r"nc\s.*-e|/dev/tcp/|socat|bash\s+-i",
            "download": r"wget\s+http|curl\s+.*http|fetch\s+http",
            "privilege_escalation": r"sudo|su\s+-|chmod\s+[47]|setuid",
            "credential_access": r"cat.*/etc/shadow|mimikatz|hashdump",
            "tool_deployment": r"chmod\s+\+x|\.\/\w+|python\s+-c",
            "data_staging": r"tar\s+[cx]|zip|base64|xxd",
            "reconnaissance": r"nmap|masscan|enum4linux|gobuster",
            "aws_access": r"aws\s+(iam|ec2|s3|sts)",
            "k8s_access": r"kubectl\s+(exec|get\s+secret|apply)",
        }

        for behavior, pattern in alert_patterns.items():
            if re.search(pattern, command, re.IGNORECASE):
                await self.emitter.emit("alert", self.session_id, {
                    "severity": "critical" if behavior in (
                        "reverse_shell", "credential_access", "lateral_movement"
                    ) else "high",
                    "behavior": behavior,
                    "command": command,
                    "mitre_technique": self._map_mitre(behavior),
                })

    @staticmethod
    def _map_mitre(behavior: str) -> str:
        """Quick mapping to MITRE ATT&CK technique IDs."""
        mapping = {
            "lateral_movement": "T1021",
            "reverse_shell": "T1059.004",
            "download": "T1105",
            "privilege_escalation": "T1548",
            "credential_access": "T1003",
            "tool_deployment": "T1204.002",
            "data_staging": "T1074",
            "reconnaissance": "T1046",
            "aws_access": "T1078.004",
            "k8s_access": "T1609",
        }
        return mapping.get(behavior, "T0000")

    async def _inject_latency(self, command: str, elapsed: float):
        """
        Make response timing realistic.

        Real servers have variable latency. Instant responses are suspicious.
        Simple commands (ls, pwd) should be fast. Complex operations (find,
        grep over many files) should be slower.
        """
        target_latency = 0.02  # 20ms base for simple commands

        if re.match(r"^(find|grep|locate|updatedb)", command):
            target_latency = 0.3 + (0.5 * hash(command) % 100) / 100
        elif re.match(r"^(cat|head|tail)", command):
            target_latency = 0.05
        elif re.match(r"^(apt|yum|pip|npm)", command):
            target_latency = 1.0 + (2.0 * hash(command) % 100) / 100
        elif re.match(r"^(ansible|terraform|docker)", command):
            target_latency = 0.5

        # Add jitter (±15%)
        import random
        jitter = target_latency * random.uniform(-0.15, 0.15)
        target_latency += jitter

        remaining = target_latency - elapsed
        if remaining > 0:
            await asyncio.sleep(remaining)

    def _render_prompt(self) -> str:
        """Generate a realistic bash prompt."""
        user = self.state.username
        host = self.config.hostname
        cwd = self.state.cwd

        # Shorten home directory to ~
        home = self.state.home
        if cwd.startswith(home):
            cwd = "~" + cwd[len(home):]

        if self.state.uid == 0:
            return f"{user}@{host}:{cwd}# "
        return f"{user}@{host}:{cwd}$ "


# ─────────────────────────────────────────────────────────
#  SSH Server Interface — Paramiko callbacks
# ─────────────────────────────────────────────────────────

class DecoySSHServerInterface(paramiko.ServerInterface):
    """Paramiko server interface with credential capture."""

    def __init__(self, config: DecoyConfig, auth_handler: AuthHandler, client_ip: str):
        self.config = config
        self.auth_handler = auth_handler
        self.client_ip = client_ip
        self.authenticated_user: Optional[str] = None

    def check_auth_password(self, username: str, password: str) -> int:
        result = self.auth_handler.check_password(
            username, password, self.client_ip
        )
        if result.accepted:
            self.authenticated_user = username
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username: str, key: paramiko.PKey) -> int:
        # Log the public key for intelligence
        self.auth_handler.log_pubkey_attempt(
            username, key.get_base64(), self.client_ip
        )
        # For now, reject pubkey auth (force password for credential capture)
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel: paramiko.Channel) -> bool:
        return True

    def check_channel_pty_request(
        self, channel, term, width, height, pixelwidth, pixelheight, modes
    ) -> bool:
        return True

    def get_banner(self):
        return ("", "en-US")


# ─────────────────────────────────────────────────────────
#  Main Server Loop
# ─────────────────────────────────────────────────────────

class SSHDecoyServer:
    """
    Main entry point for the SSH decoy.

    Listens for connections, performs the SSH handshake,
    and spawns a DecoySSHSession per authenticated client.
    """

    def __init__(self, config: DecoyConfig):
        self.config = config
        self.emitter = EventEmitter(config)
        self.auth_handler = AuthHandler(config)
        self.router = CommandRouter(config)
        self.host_key = paramiko.RSAKey.generate(2048)

        # Load persistent host key if available
        if os.path.exists(config.host_key_path):
            self.host_key = paramiko.RSAKey(filename=config.host_key_path)

    async def start(self):
        """Start the SSH server."""
        await self.emitter.connect()
        await self.router.initialize()

        logger.info(
            f"CI/CDecoy SSH server starting: "
            f"name={self.config.name} "
            f"tier={self.config.tier} "
            f"port={self.config.port} "
            f"hostname={self.config.hostname}"
        )

        server = await asyncio.start_server(
            self._handle_connection,
            "0.0.0.0",
            self.config.port,
        )

        await self.emitter.emit("decoy.online", "system", {
            "decoy_name": self.config.name,
            "tier": self.config.tier,
            "port": self.config.port,
        })

        async with server:
            await server.serve_forever()

    async def _handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        """Handle an incoming TCP connection."""
        peername = writer.get_extra_info("peername")
        client_ip = peername[0] if peername else "unknown"

        logger.info(f"Connection from {client_ip}")

        await self.emitter.emit("connection.new", "pre-auth", {
            "client_ip": client_ip,
            "client_port": peername[1] if peername else 0,
        })

        try:
            # Wrap in paramiko Transport
            transport = paramiko.Transport(writer)
            transport.local_version = self.config.ssh_banner
            transport.add_server_key(self.host_key)

            # Set up server interface with auth handling
            server_interface = DecoySSHServerInterface(
                self.config, self.auth_handler, client_ip
            )
            transport.start_server(server=server_interface)

            # Wait for auth (with timeout)
            channel = transport.accept(timeout=60)
            if channel is None:
                logger.info(f"No channel from {client_ip} — auth timeout or rejection")
                transport.close()
                return

            # Auth succeeded — create session
            session = DecoySSHSession(
                config=self.config,
                emitter=self.emitter,
                router=self.router,
                channel=channel,
                username=server_interface.authenticated_user,
                client_ip=client_ip,
            )

            await session.handle()

        except paramiko.SSHException as e:
            logger.info(f"SSH error from {client_ip}: {e}")
            await self.emitter.emit("connection.error", "pre-auth", {
                "client_ip": client_ip,
                "error": str(e),
            })
        except Exception as e:
            logger.error(f"Unexpected error from {client_ip}: {e}")
        finally:
            writer.close()
            await writer.wait_closed()


# ─────────────────────────────────────────────────────────
#  Entrypoint
# ─────────────────────────────────────────────────────────

async def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    config_path = os.environ.get("DECOY_CONFIG", "/etc/cicdecoy/decoy.yaml")
    config = DecoyConfig.from_crd(config_path)

    server = SSHDecoyServer(config)
    await server.start()


if __name__ == "__main__":
    asyncio.run(main())
