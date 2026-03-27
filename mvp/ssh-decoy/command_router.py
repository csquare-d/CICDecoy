"""
CI/CDecoy — Command Router (MVP)

Dispatches commands through: builtins → fast-path → tier handler.
This version properly loads profiles and handles all three tiers.
"""

import json
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Optional

import httpx

from session import SessionState
from filesystem import VirtualFilesystem

logger = logging.getLogger("cicdecoy.router")


class CommandRouter:

    def __init__(self, config):
        self.config = config
        self.last_source: str = "unknown"
        self.http_client: Optional[httpx.AsyncClient] = None

        # Compile fast-path patterns
        self.fast_path_rules = []
        for rule in config.fast_path_commands:
            try:
                self.fast_path_rules.append({
                    "pattern": re.compile(rule["match"]),
                    "source": rule["source"],
                })
            except re.error as e:
                logger.warning(f"Invalid fast-path pattern '{rule['match']}': {e}")

        self.scripted_responses: dict = {}
        self.response_cache: dict = {}

    async def initialize(self):
        """Set up scripted responses and HTTP client."""
        self._load_scripted_responses()
        if self.config.tier == 3:
            self.http_client = httpx.AsyncClient(
                base_url=self.config.inference_endpoint,
                timeout=30.0,
            )
        logger.info(f"Router initialized: tier={self.config.tier} "
                     f"fast_path_rules={len(self.fast_path_rules)} "
                     f"scripted_responses={len(self.scripted_responses)}")

    async def route(
        self,
        command: str,
        session_state: SessionState,
        filesystem: VirtualFilesystem,
        tier: int,
    ) -> str:
        """
        Main routing logic. Handles shell pipelines and compound
        operators before dispatching individual commands.
        """
        # Strip inline comments
        command = command.split("#")[0].strip()
        if not command:
            return ""

        # Handle semicolon-separated sequences: cmd1 ; cmd2 ; cmd3
        if ";" in command:
            parts = [p.strip() for p in command.split(";") if p.strip()]
            outputs = []
            for part in parts:
                out = await self._route_single(part, session_state, filesystem, tier)
                if out:
                    outputs.append(out)
            return "\n".join(outputs)

        # Handle &&: run second only if first "succeeds"
        if " && " in command:
            left, right = command.split(" && ", 1)
            first = await self._route_single(left.strip(), session_state, filesystem, tier)
            if first is not None and "command not found" not in first and "No such file" not in first:
                second = await self._route_single(right.strip(), session_state, filesystem, tier)
                return "\n".join(o for o in [first, second] if o)
            return first or ""

        # Handle ||: run second only if first fails
        if " || " in command:
            left, right = command.split(" || ", 1)
            first = await self._route_single(left.strip(), session_state, filesystem, tier)
            if first and "command not found" not in first and "No such file" not in first:
                return first
            return await self._route_single(right.strip(), session_state, filesystem, tier)

        # Handle pipes: execute left side, discard right (realistic stub)
        if " | " in command:
            left = command.split(" | ")[0].strip()
            return await self._route_single(left, session_state, filesystem, tier)

        return await self._route_single(command, session_state, filesystem, tier)

    async def _route_single(
        self,
        command: str,
        session_state: SessionState,
        filesystem: VirtualFilesystem,
        tier: int,
    ) -> str:
        """Route a single, pipeline-free command."""

        # Stage 1: Builtins
        result = self._handle_builtin(command, session_state, filesystem)
        if result is not None:
            self.last_source = "builtin"
            return result

        # Stage 2: Fast-path
        for rule in self.fast_path_rules:
            if rule["pattern"].match(command):
                result = self._handle_fast_path(
                    command, rule["source"], session_state, filesystem
                )
                if result is not None:
                    self.last_source = "fast_path"
                    return result

        # Stage 3: Tier dispatch
        if tier == 1:
            self.last_source = "tier1_stub"
            cmd = command.split()[0] if command.split() else command
            return f"-bash: {cmd}: command not found"

        elif tier == 2:
            result = self._handle_scripted(command, session_state)
            self.last_source = "scripted"
            return result

        elif tier == 3:
            result = await self._handle_adaptive(command, session_state, filesystem)
            self.last_source = "llm"
            return result

        return ""

    # ── Builtins ─────────────────────────────────────

    def _handle_builtin(self, command: str, state: SessionState,
                        fs: VirtualFilesystem) -> Optional[str]:
        parts = command.split()
        if not parts:
            return ""
        cmd = parts[0]

        if cmd == "cd":
            return self._builtin_cd(parts, state, fs)
        elif cmd == "export":
            for p in parts[1:]:
                if "=" in p:
                    k, v = p.split("=", 1)
                    state.env[k] = v.strip("'\"")
            return ""
        elif cmd == "unset":
            for p in parts[1:]:
                state.env.pop(p, None)
            return ""
        elif cmd == "history":
            lines = [f"  {i+1:4d}  {c}" for i, c in enumerate(state.command_history)]
            return "\n".join(lines)
        elif cmd == "echo":
            text = " ".join(parts[1:])
            for k, v in state.env.items():
                text = text.replace(f"${k}", v).replace(f"${{{k}}}", v)
            text = text.strip("'\"")
            return text
        elif cmd in ("alias", "source", "."):
            return ""
        elif cmd == "type":
            if len(parts) > 1:
                target = parts[1]
                builtins = {"cd", "echo", "export", "unset", "alias", "source",
                            "history", "type", "exit", "logout"}
                if target in builtins:
                    return f"{target} is a shell builtin"
                return f"{target} is /usr/bin/{target}"
            return ""

        return None  # Not a builtin

    def _builtin_cd(self, parts: list, state: SessionState,
                    fs: VirtualFilesystem) -> str:
        if len(parts) < 2 or parts[1] == "~":
            state.cwd = state.home
            return ""

        target = parts[1]
        if target == "-":
            state.cwd = state.home
            return state.cwd

        if not target.startswith("/"):
            if state.cwd == "/":
                target = f"/{target}"
            else:
                target = f"{state.cwd}/{target}"

        target = self._normalize_path(target)

        if fs.is_directory(target):
            state.cwd = target
            return ""
        return f"-bash: cd: {parts[1]}: No such file or directory"

    @staticmethod
    def _normalize_path(path: str) -> str:
        parts = path.split("/")
        result = []
        for p in parts:
            if p == "" or p == ".":
                continue
            elif p == "..":
                if result:
                    result.pop()
            else:
                result.append(p)
        return "/" + "/".join(result)

    # ── Fast-path ────────────────────────────────────

    def _handle_fast_path(self, command: str, source: str,
                          state: SessionState,
                          fs: VirtualFilesystem) -> Optional[str]:
        parts = command.split()
        cmd = parts[0]

        if source == "filesystem":
            return self._fast_path_fs(command, parts, state, fs)
        elif source == "state":
            return self._fast_path_state(cmd, state)
        elif source == "profile":
            return self._fast_path_profile(command, fs)
        elif source == "dynamic":
            return self._fast_path_dynamic(cmd)
        return None

    def _fast_path_fs(self, command: str, parts: list,
                      state: SessionState, fs: VirtualFilesystem) -> str:
        cmd = parts[0]

        if cmd == "ls":
            flags = [p for p in parts[1:] if p.startswith("-")]
            targets = [p for p in parts[1:] if not p.startswith("-")]
            target = targets[0] if targets else state.cwd

            if not target.startswith("/"):
                target = f"{state.cwd}/{target}" if state.cwd != "/" else f"/{target}"
            target = self._normalize_path(target)

            long_fmt = any(f in fl for fl in flags for f in ("-l", "-la", "-al", "-lh"))
            hidden = any(f in fl for fl in flags for f in ("-a", "-la", "-al"))

            raw = fs.list_directory(target, long_format=long_fmt, show_hidden=hidden)

            # Colorize short listing when the terminal supports it
            if not long_fmt and raw and "cannot access" not in raw:
                term = state.env.get("TERM", "xterm-256color")
                if term not in ("dumb", ""):
                    raw = self._colorize_ls(raw, target, fs)

            return raw

        elif cmd == "cat":
            if len(parts) < 2:
                return ""
            target = parts[1]
            if not target.startswith("/"):
                target = f"{state.cwd}/{target}" if state.cwd != "/" else f"/{target}"
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
                target = f"{state.cwd}/{target}" if state.cwd != "/" else f"/{target}"
            target = self._normalize_path(target)
            content = fs.read_file(target)
            if content is None:
                return f"{cmd}: cannot open '{parts[-1]}' for reading: No such file or directory"
            lines = content.split("\n")
            n = 10
            for i, p in enumerate(parts):
                if p == "-n" and i + 1 < len(parts):
                    try:
                        n = int(parts[i + 1])
                    except ValueError:
                        pass
            return "\n".join(lines[:n] if cmd == "head" else lines[-n:])

        return ""

    @staticmethod
    def _colorize_ls(listing: str, path: str, fs: VirtualFilesystem) -> str:
        """
        Apply ANSI colors to a short ls listing.
        Directories → bold blue, executables → bold green, others plain.
        Matches Ubuntu's default LS_COLORS.
        """
        BLUE  = "\x1b[01;34m"
        GREEN = "\x1b[01;32m"
        RESET = "\x1b[0m"

        node = fs.get_node(path)
        if node is None or not node.is_dir:
            return listing

        colored = []
        for name in listing.split("  "):
            name = name.strip()
            if not name:
                continue
            child = node.children.get(name)
            if child and child.is_dir:
                colored.append(f"{BLUE}{name}{RESET}")
            elif child and child.permissions[-1:] in ("5", "7"):
                # owner/group/other execute bit set
                colored.append(f"{GREEN}{name}{RESET}")
            else:
                colored.append(name)

        return "  ".join(colored)

    def _fast_path_state(self, cmd: str, state: SessionState) -> str:
        if cmd == "pwd":
            return state.cwd
        elif cmd == "whoami":
            return state.username
        elif cmd == "id":
            return (f"uid={state.uid}({state.username}) "
                    f"gid={state.uid}({state.username}) "
                    f"groups={state.uid}({state.username})")
        elif cmd == "hostname":
            return state.hostname
        return ""

    def _fast_path_profile(self, command: str, fs: VirtualFilesystem) -> str:
        """Serve from static profile responses or profile data."""
        profile = fs.get_profile_data()
        static = profile.get("static_responses", {})

        if command in static:
            return static[command]

        cmd = command.split()[0]
        for key, val in static.items():
            if key.startswith(cmd):
                return val

        if cmd == "ps":
            procs = profile.get("processes", [])
            if procs:
                lines = [f"{'USER':<12}{'PID':>6} {'%CPU':>5} {'%MEM':>5}  {'COMMAND'}"]
                for p in procs:
                    lines.append(
                        f"{p['user']:<12}{p['pid']:>6} {'0.0':>5} {'0.1':>5}  {p['command']}")
                return "\n".join(lines)

        if command.startswith("cat /etc/"):
            path = command.split(None, 1)[1] if " " in command else ""
            content = fs.read_file(path)
            if content:
                return content

        return ""

    def _fast_path_dynamic(self, cmd: str) -> str:
        if cmd == "date":
            return datetime.now().strftime("%a %b %d %H:%M:%S %Z %Y")
        return ""

    # ── Scripted (Tier 2) ────────────────────────────

    def _load_scripted_responses(self):
        """Build the scripted response table."""
        self.scripted_responses = {
            "uname -a": (
                f"Linux {self.config.hostname} 5.15.0-91-generic "
                "#101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 "
                "x86_64 x86_64 x86_64 GNU/Linux"
            ),
            "uname -r": "5.15.0-91-generic",
            "uname": "Linux",
            "cat /etc/hostname": self.config.hostname,
            "arch": "x86_64",
            "nproc": "4",
        }

        for resp in self.config.custom_responses:
            self.scripted_responses[resp["match"]] = resp["response"]

    def _handle_scripted(self, command: str, state: SessionState) -> str:
        if command in self.scripted_responses:
            return self.scripted_responses[command]

        for key, response in self.scripted_responses.items():
            if command.startswith(key.split()[0]) and key in command:
                return response

        cmd = command.split()[0] if command.split() else command
        return f"-bash: {cmd}: command not found"

    # ── Adaptive / LLM (Tier 3) ─────────────────────

    async def _handle_adaptive(self, command: str, state: SessionState,
                               fs: VirtualFilesystem) -> str:
        cache_key = f"{state.cwd}:{command}"
        if cache_key in self.response_cache:
            self.last_source = "llm_cache"
            return self.response_cache[cache_key]

        if not self.http_client:
            return self._handle_scripted(command, state)

        payload = {
            "command": command,
            "profile": self.config.profile_name,
            "session_context": {
                "hostname": state.hostname,
                "username": state.username,
                "uid": state.uid,
                "cwd": state.cwd,
                "env": state.env,
                "command_history": state.command_history[-20:],
                "filesystem_snapshot": fs.get_context_snapshot(state.cwd),
            },
            "config": {
                "max_tokens": self.config.max_session_tokens,
                "temperature": self.config.temperature,
            },
        }

        try:
            response = await self.http_client.post("/v1/command", json=payload)
            response.raise_for_status()
            result = response.json()
            output = result.get("output", "")

            if result.get("cacheable", False):
                self.response_cache[cache_key] = output

            return output

        except Exception as e:
            logger.warning(f"Inference failed, falling back to scripted: {e}")
            return self._handle_scripted(command, state)