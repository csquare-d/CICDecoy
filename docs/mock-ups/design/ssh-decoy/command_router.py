# CI/CDecoy — Command Router
# images/ssh-decoy/src/command_router.py
#
# Dispatches incoming commands to the appropriate handler based on
# fidelity tier and fast-path configuration. This is the core decision
# engine that determines whether a command gets a deterministic response
# or goes to the LLM.

import re
import json
import logging
import httpx
from dataclasses import dataclass
from typing import Optional

from session import SessionState
from filesystem import VirtualFilesystem

logger = logging.getLogger("cicdecoy.router")


@dataclass
class RouteResult:
    response: str
    source: str        # "fast_path" | "scripted" | "llm" | "builtin"
    cache_hit: bool = False


class CommandRouter:
    """
    Three-tier command routing:

    1. Built-in handlers — shell builtins (cd, export, alias) that
       modify session state. Always handled locally.

    2. Fast-path — commands matching configured patterns get answered
       from the virtual filesystem or session state. Zero inference cost,
       sub-millisecond latency.

    3. Tier dispatch:
       - Tier 1: returns empty (connection-only logging)
       - Tier 2: scripted response lookup
       - Tier 3: LLM inference with full session context
    """

    def __init__(self, config):
        self.config = config
        self.last_source: str = "unknown"
        self.http_client: Optional[httpx.AsyncClient] = None

        # Compile fast-path patterns once at init
        self.fast_path_rules = []
        for rule in config.fast_path_commands:
            self.fast_path_rules.append({
                "pattern": re.compile(rule["match"]),
                "source": rule["source"],
            })

        # Scripted response sets (tier 2)
        self.scripted_responses: dict = {}

        # LLM response cache (tier 3)
        self.response_cache: dict = {}

    async def initialize(self):
        """Load scripted responses and set up HTTP client for inference."""
        if self.config.tier >= 2:
            await self._load_scripted_responses()
        if self.config.tier == 3:
            self.http_client = httpx.AsyncClient(
                base_url=self.config.inference_endpoint,
                timeout=30.0,
            )
        logger.info(f"Command router initialized for tier {self.config.tier}")

    async def route(
        self,
        command: str,
        session_state: SessionState,
        filesystem: VirtualFilesystem,
        tier: int,
    ) -> str:
        """
        Main routing logic.

        Returns the command output string (what the attacker sees).
        """
        # ── Stage 1: Built-in shell commands ──
        builtin_result = self._handle_builtin(command, session_state, filesystem)
        if builtin_result is not None:
            self.last_source = "builtin"
            return builtin_result

        # ── Stage 2: Fast-path check ──
        for rule in self.fast_path_rules:
            if rule["pattern"].match(command):
                result = self._handle_fast_path(
                    command, rule["source"], session_state, filesystem
                )
                if result is not None:
                    self.last_source = "fast_path"
                    return result

        # ── Stage 3: Tier-specific dispatch ──
        if tier == 1:
            # Tier 1 — beacon only. Log but don't respond meaningfully.
            self.last_source = "tier1_stub"
            return f"-bash: {command.split()[0]}: command not found"

        elif tier == 2:
            # Tier 2 — scripted responses
            result = self._handle_scripted(command, session_state)
            self.last_source = "scripted"
            return result

        elif tier == 3:
            # Tier 3 — LLM inference
            result = await self._handle_adaptive(command, session_state, filesystem)
            self.last_source = "llm"
            return result

        return ""

    # ─────────────────────────────────────────────────
    #  Built-in Shell Commands
    # ─────────────────────────────────────────────────

    def _handle_builtin(
        self,
        command: str,
        state: SessionState,
        fs: VirtualFilesystem,
    ) -> Optional[str]:
        """Handle commands that modify session state (not system commands)."""
        parts = command.split()
        cmd = parts[0] if parts else ""

        if cmd == "cd":
            return self._builtin_cd(parts, state, fs)
        elif cmd == "export":
            return self._builtin_export(parts, state)
        elif cmd == "unset":
            return self._builtin_unset(parts, state)
        elif cmd == "history":
            return self._builtin_history(state)
        elif cmd == "alias":
            return ""  # Silently accept
        elif cmd == "source" or cmd == ".":
            return ""  # Silently accept
        elif cmd == "echo":
            return self._builtin_echo(parts, state)

        return None  # Not a builtin — continue to next stage

    def _builtin_cd(
        self, parts: list, state: SessionState, fs: VirtualFilesystem
    ) -> str:
        if len(parts) < 2 or parts[1] == "~":
            state.cwd = state.home
            return ""

        target = parts[1]

        # Resolve relative paths
        if not target.startswith("/"):
            if state.cwd == "/":
                target = f"/{target}"
            else:
                target = f"{state.cwd}/{target}"

        # Normalize path (handle .., .)
        target = self._normalize_path(target)

        # Check if directory exists in virtual filesystem
        if fs.is_directory(target):
            state.cwd = target
            return ""
        else:
            return f"-bash: cd: {parts[1]}: No such file or directory"

    def _builtin_export(self, parts: list, state: SessionState) -> str:
        for part in parts[1:]:
            if "=" in part:
                key, value = part.split("=", 1)
                state.env[key] = value
        return ""

    def _builtin_unset(self, parts: list, state: SessionState) -> str:
        for part in parts[1:]:
            state.env.pop(part, None)
        return ""

    def _builtin_history(self, state: SessionState) -> str:
        lines = []
        for i, cmd in enumerate(state.command_history, 1):
            lines.append(f"  {i:4d}  {cmd}")
        return "\n".join(lines)

    def _builtin_echo(self, parts: list, state: SessionState) -> str:
        text = " ".join(parts[1:])
        # Expand environment variables
        for key, value in state.env.items():
            text = text.replace(f"${key}", value)
            text = text.replace(f"${{{key}}}", value)
        return text

    @staticmethod
    def _normalize_path(path: str) -> str:
        components = path.split("/")
        normalized = []
        for comp in components:
            if comp == "" or comp == ".":
                continue
            elif comp == "..":
                if normalized:
                    normalized.pop()
            else:
                normalized.append(comp)
        return "/" + "/".join(normalized)

    # ─────────────────────────────────────────────────
    #  Fast-Path Handlers
    # ─────────────────────────────────────────────────

    def _handle_fast_path(
        self,
        command: str,
        source: str,
        state: SessionState,
        fs: VirtualFilesystem,
    ) -> Optional[str]:
        """
        Answer from virtual filesystem or session state.
        No LLM needed — instant response.
        """
        parts = command.split()
        cmd = parts[0]

        if source == "filesystem":
            return self._fast_path_filesystem(command, parts, state, fs)
        elif source == "state":
            return self._fast_path_state(command, parts, state)
        elif source == "profile":
            return self._fast_path_profile(command, parts, state, fs)
        elif source == "dynamic":
            return self._fast_path_dynamic(command, parts)

        return None

    def _fast_path_filesystem(
        self, command: str, parts: list, state: SessionState, fs: VirtualFilesystem
    ) -> str:
        cmd = parts[0]

        if cmd == "ls":
            flags = [p for p in parts[1:] if p.startswith("-")]
            targets = [p for p in parts[1:] if not p.startswith("-")]
            target = targets[0] if targets else state.cwd

            if not target.startswith("/"):
                target = f"{state.cwd}/{target}"
            target = self._normalize_path(target)

            long_format = any("-l" in f or "-la" in f or "-al" in f for f in flags)
            show_hidden = any("-a" in f or "-la" in f or "-al" in f for f in flags)

            return fs.list_directory(target, long_format=long_format, show_hidden=show_hidden)

        elif cmd == "cat":
            if len(parts) < 2:
                return ""
            target = parts[1]
            if not target.startswith("/"):
                target = f"{state.cwd}/{target}"
            target = self._normalize_path(target)
            content = fs.read_file(target)
            if content is None:
                return f"cat: {parts[1]}: No such file or directory"
            return content

        elif cmd in ("head", "tail"):
            if len(parts) < 2:
                return ""
            target = parts[-1]
            if not target.startswith("/"):
                target = f"{state.cwd}/{target}"
            target = self._normalize_path(target)
            content = fs.read_file(target)
            if content is None:
                return f"{cmd}: {parts[-1]}: No such file or directory"
            lines = content.split("\n")
            n = 10  # default
            for i, p in enumerate(parts):
                if p == "-n" and i + 1 < len(parts):
                    try:
                        n = int(parts[i + 1])
                    except ValueError:
                        pass
            if cmd == "head":
                return "\n".join(lines[:n])
            return "\n".join(lines[-n:])

        return ""

    def _fast_path_state(
        self, command: str, parts: list, state: SessionState
    ) -> str:
        cmd = parts[0]
        if cmd == "pwd":
            return state.cwd
        elif cmd == "whoami":
            return state.username
        elif cmd == "id":
            return (
                f"uid={state.uid}({state.username}) "
                f"gid={state.uid}({state.username}) "
                f"groups={state.uid}({state.username})"
            )
        elif cmd == "hostname":
            return state.hostname
        return ""

    def _fast_path_profile(
        self, command: str, parts: list, state: SessionState, fs: VirtualFilesystem
    ) -> str:
        """Serve from pre-built profile data (ps, df, free, etc.)."""
        cmd = parts[0]
        profile_data = fs.get_profile_data()

        if cmd == "ps" and profile_data.get("processes"):
            return self._format_ps_output(profile_data["processes"])
        elif cmd in ("df", "df -h") and profile_data.get("disk"):
            return profile_data["disk"]
        elif cmd.startswith("free") and profile_data.get("memory"):
            return profile_data["memory"]
        elif cmd == "uptime" and profile_data.get("uptime"):
            return profile_data["uptime"]

        # Fallback: check if profile has a static response
        static = profile_data.get("static_responses", {})
        if command in static:
            return static[command]

        return ""

    def _fast_path_dynamic(self, command: str, parts: list) -> str:
        """Generate dynamic responses (date, etc.)."""
        from datetime import datetime
        cmd = parts[0]
        if cmd == "date":
            return datetime.now().strftime("%a %b %d %H:%M:%S %Z %Y")
        return ""

    @staticmethod
    def _format_ps_output(processes: list) -> str:
        lines = [f"{'USER':<12} {'PID':>6} {'%CPU':>5} {'%MEM':>5}  {'COMMAND'}"]
        for proc in processes:
            lines.append(
                f"{proc['user']:<12} {proc['pid']:>6} "
                f"{'0.0':>5} {'0.1':>5}  {proc['command']}"
            )
        return "\n".join(lines)

    # ─────────────────────────────────────────────────
    #  Scripted Responses (Tier 2)
    # ─────────────────────────────────────────────────

    def _handle_scripted(self, command: str, state: SessionState) -> str:
        """Look up response from scripted response set."""
        # Exact match first
        if command in self.scripted_responses:
            return self.scripted_responses[command]

        # Pattern match
        for pattern, response in self.scripted_responses.items():
            if pattern.startswith("regex:"):
                if re.match(pattern[6:], command):
                    return response

        # Default: command not found
        cmd = command.split()[0] if command.split() else command
        return f"-bash: {cmd}: command not found"

    async def _load_scripted_responses(self):
        """Load scripted response set from config."""
        # In production, this loads from a response library file
        # For now, populate with basics
        self.scripted_responses = {
            "uname -a": (
                f"Linux {self.config.hostname} 5.15.0-91-generic "
                "#101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 "
                "x86_64 x86_64 GNU/Linux"
            ),
            "uname -r": "5.15.0-91-generic",
            "cat /etc/os-release": (
                'PRETTY_NAME="Ubuntu 22.04.3 LTS"\n'
                'NAME="Ubuntu"\nVERSION_ID="22.04"\nVERSION="22.04.3 LTS '
                '(Jammy Jellyfish)"\nID=ubuntu\nID_LIKE=debian'
            ),
            "cat /etc/hostname": self.config.hostname,
        }

        # Load custom responses from config
        if hasattr(self.config, "custom_responses"):
            for resp in self.config.custom_responses:
                self.scripted_responses[resp["match"]] = resp["response"]

    # ─────────────────────────────────────────────────
    #  Adaptive / LLM Responses (Tier 3)
    # ─────────────────────────────────────────────────

    async def _handle_adaptive(
        self,
        command: str,
        state: SessionState,
        fs: VirtualFilesystem,
    ) -> str:
        """
        Send command to the LLM inference service with full session context.

        The inference service handles:
        - System prompt construction from profile
        - Session state injection
        - Response generation
        - Caching of deterministic responses
        """
        # Check local cache first
        cache_key = f"{state.cwd}:{command}"
        if cache_key in self.response_cache:
            self.last_source = "llm_cache"
            return self.response_cache[cache_key]

        # Build inference request
        request_payload = {
            "command": command,
            "profile": self.config.profile_name,
            "session_context": {
                "hostname": state.hostname,
                "username": state.username,
                "uid": state.uid,
                "cwd": state.cwd,
                "env": state.env,
                "command_history": state.command_history[-20:],  # Last 20 commands
                "filesystem_snapshot": fs.get_context_snapshot(state.cwd),
            },
            "config": {
                "max_tokens": self.config.max_session_tokens,
                "temperature": self.config.temperature,
            },
        }

        try:
            response = await self.http_client.post(
                "/v1/command",
                json=request_payload,
            )
            response.raise_for_status()
            result = response.json()

            output = result.get("output", "")
            cacheable = result.get("cacheable", False)

            if cacheable:
                self.response_cache[cache_key] = output

            return output

        except httpx.HTTPError as e:
            logger.error(f"Inference request failed: {e}")
            # Graceful degradation: fall back to scripted
            return self._handle_scripted(command, state)

        except Exception as e:
            logger.error(f"Unexpected inference error: {e}")
            return f"-bash: {command.split()[0]}: command not found"
