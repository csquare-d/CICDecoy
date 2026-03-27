"""
CI/CDecoy — High-Fidelity Scripted Engine

The bridge between dumb Tier 2 and expensive Tier 3. Uses:
1. Captured response databases (real outputs from real systems)
2. Command decomposition (parse flags/args, compose responses)
3. Template responses (generate output from filesystem + profile state)
4. Fuzzy matching (handle command variations without exact matches)

This replaces the flat key-value lookup in the basic scripted handler
while reusing all the session state and filesystem infrastructure
from the Tier 3 code path.
"""

import json
import logging
import os
import random
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from session import SessionState
from filesystem import VirtualFilesystem

logger = logging.getLogger("cicdecoy.hifi")


class HighFidelityEngine:
    """
    Scripted response engine that feels like a real system.

    Resolution order for incoming commands:
    1. Exact match in response database
    2. Normalized match (strip whitespace, collapse flags)
    3. Command decomposition (parse cmd + flags + args, compose)
    4. Template generation (build output from system state)
    5. Fuzzy match (closest command in database)
    6. Realistic error ("command not found" or "permission denied")
    """

    def __init__(self, response_db_path: Optional[str] = None):
        self.responses: dict[str, dict] = {}   # command → {output, exit_code, ...}
        self.prefix_index: dict[str, list] = {} # first word → [commands]
        self.templates: dict[str, callable] = {}
        self._loaded = False

        if response_db_path:
            self.load_database(response_db_path)

        self._register_templates()

    def load_database(self, path: str):
        """Load a captured response database JSON."""
        try:
            with open(path) as f:
                data = json.load(f)
            for cmd, resp in data.get("responses", {}).items():
                self.responses[cmd] = resp
            self._build_prefix_index()
            self._loaded = True
            logger.info(f"Loaded response database: {len(self.responses)} commands from {path}")
        except Exception as e:
            logger.warning(f"Failed to load response database {path}: {e}")

    def load_all_databases(self, directory: str):
        """Load all .json response databases from a directory."""
        db_dir = Path(directory)
        if not db_dir.is_dir():
            return
        for path in sorted(db_dir.glob("*.json")):
            self.load_database(str(path))

    def _build_prefix_index(self):
        """Index commands by their first word for fast lookup."""
        self.prefix_index.clear()
        for cmd in self.responses:
            first = cmd.split()[0] if cmd.split() else cmd
            if first not in self.prefix_index:
                self.prefix_index[first] = []
            self.prefix_index[first].append(cmd)

    # ── Main entry point ─────────────────────────────

    def handle(self, command: str, state: SessionState,
               filesystem: VirtualFilesystem) -> Optional[str]:
        """
        Try to handle a command through the scripted engine.

        Returns the response string, or None if no match found
        (caller should fall back to "command not found").
        """
        command = command.strip()
        if not command:
            return ""

        # 1. Exact match
        if command in self.responses:
            return self._render(command, self.responses[command], state)

        # 2. Normalized match (handle whitespace/flag order variations)
        normalized = self._normalize_command(command)
        if normalized in self.responses:
            return self._render(command, self.responses[normalized], state)

        # 3. Command decomposition — try to compose a response
        composed = self._try_decompose(command, state, filesystem)
        if composed is not None:
            return composed

        # 4. Template generation
        templated = self._try_template(command, state, filesystem)
        if templated is not None:
            return templated

        # 5. Fuzzy match — find the closest command in the database
        fuzzy = self._fuzzy_match(command)
        if fuzzy is not None:
            return self._render(command, self.responses[fuzzy], state)

        # 6. No match — return None (caller generates error)
        return None

    # ── Resolution strategies ────────────────────────

    def _render(self, original_cmd: str, response: dict,
                state: SessionState) -> str:
        """Render a stored response, applying hostname/user substitutions."""
        output = response.get("output", "")

        # Apply state-based substitutions
        # (captured from real system, may have that system's hostname)
        output = self._substitute_identity(output, state)

        return output

    def _substitute_identity(self, output: str, state: SessionState) -> str:
        """Replace captured system identity with decoy identity."""
        # These get replaced with actual values when the database
        # is loaded with sanitize_database() in the capture tool.
        # This handles any remaining dynamic substitutions.
        return output

    def _normalize_command(self, command: str) -> str:
        """Normalize a command for matching."""
        # Collapse multiple spaces
        normalized = " ".join(command.split())
        # Sort short flags (ls -la == ls -al)
        parts = normalized.split()
        if len(parts) >= 2:
            cmd = parts[0]
            flags = []
            args = []
            for p in parts[1:]:
                if p.startswith("-") and not p.startswith("--"):
                    flags.append(p)
                else:
                    args.append(p)
            if flags:
                # Merge single-char flags: ["-l", "-a"] → "-al"
                merged = "-" + "".join(
                    sorted(set(c for f in flags for c in f[1:]))
                )
                normalized = " ".join([cmd, merged] + args)
        return normalized

    def _try_decompose(self, command: str, state: SessionState,
                       fs: VirtualFilesystem) -> Optional[str]:
        """
        Parse command structure and compose response from parts.

        Handles cases like:
        - `ls -la /var/log` → we have `ls -la /` but not this specific path
        - `cat /some/file` → check filesystem
        - `grep pattern file` → search filesystem content
        """
        parts = command.split()
        if not parts:
            return None
        cmd = parts[0]

        # Handle pipes — execute left side only, simulate the pipe
        if "|" in command:
            return self._handle_pipe(command, state, fs)

        # Handle redirects — execute command, suppress output
        if ">" in command or ">>" in command:
            # Strip redirect, execute base command, return empty
            base = re.split(r'\s*>{1,2}\s*', command)[0].strip()
            result = self.handle(base, state, fs)
            return "" if result is not None else None

        # Handle semicolons — execute both
        if ";" in command:
            results = []
            for subcmd in command.split(";"):
                subcmd = subcmd.strip()
                if subcmd:
                    r = self.handle(subcmd, state, fs)
                    if r:
                        results.append(r)
            return "\n".join(results) if results else ""

        # Handle && and ||
        if "&&" in command:
            subcmds = [s.strip() for s in command.split("&&")]
            results = []
            for subcmd in subcmds:
                r = self.handle(subcmd, state, fs)
                if r is None:
                    return None  # Command failed, stop chain
                results.append(r)
            return "\n".join(r for r in results if r)

        # Try prefix match — same command, different arguments
        if cmd in self.prefix_index:
            candidates = self.prefix_index[cmd]

            # For commands where the argument is a path,
            # check if we have a response for a parent path
            if len(parts) > 1:
                arg = parts[-1]
                if arg.startswith("/"):
                    # Try increasingly specific paths
                    for candidate in candidates:
                        cand_parts = candidate.split()
                        if len(cand_parts) > 1 and cand_parts[-1] == arg:
                            return self._render(command, self.responses[candidate], state)

        return None

    def _handle_pipe(self, command: str, state: SessionState,
                     fs: VirtualFilesystem) -> Optional[str]:
        """Handle piped commands by executing left side and filtering."""
        pipe_parts = [p.strip() for p in command.split("|")]
        if len(pipe_parts) < 2:
            return None

        # Execute left side
        left_output = self.handle(pipe_parts[0], state, fs)
        if left_output is None:
            return None

        # Apply right side as a filter
        right = pipe_parts[1].strip()
        right_parts = right.split()
        right_cmd = right_parts[0] if right_parts else ""

        if right_cmd == "grep" and len(right_parts) >= 2:
            pattern = right_parts[1].strip("'\"")
            invert = "-v" in right_parts
            try:
                regex = re.compile(pattern, re.IGNORECASE)
                lines = left_output.split("\n")
                if invert:
                    filtered = [l for l in lines if not regex.search(l)]
                else:
                    filtered = [l for l in lines if regex.search(l)]
                return "\n".join(filtered)
            except re.error:
                # Treat as literal string match
                lines = left_output.split("\n")
                filtered = [l for l in lines if pattern in l]
                return "\n".join(filtered)

        elif right_cmd == "head":
            n = 10
            for i, p in enumerate(right_parts):
                if p == "-n" and i + 1 < len(right_parts):
                    try: n = int(right_parts[i + 1])
                    except: pass
                elif p.startswith("-") and p[1:].isdigit():
                    n = int(p[1:])
            return "\n".join(left_output.split("\n")[:n])

        elif right_cmd == "tail":
            n = 10
            for i, p in enumerate(right_parts):
                if p == "-n" and i + 1 < len(right_parts):
                    try: n = int(right_parts[i + 1])
                    except: pass
                elif p.startswith("-") and p[1:].isdigit():
                    n = int(p[1:])
            return "\n".join(left_output.split("\n")[-n:])

        elif right_cmd == "wc":
            lines = left_output.split("\n")
            if "-l" in right_parts:
                return str(len(lines))
            words = sum(len(l.split()) for l in lines)
            chars = len(left_output)
            return f"  {len(lines)}  {words} {chars}"

        elif right_cmd == "sort":
            lines = left_output.split("\n")
            reverse = "-r" in right_parts
            return "\n".join(sorted(lines, reverse=reverse))

        elif right_cmd == "uniq":
            lines = left_output.split("\n")
            seen = set()
            result = []
            for line in lines:
                if line not in seen:
                    seen.add(line)
                    result.append(line)
            return "\n".join(result)

        elif right_cmd == "awk" and len(right_parts) >= 2:
            # Very basic: awk '{print $N}'
            match = re.search(r"print \$(\d+)", right_parts[1])
            if match:
                col = int(match.group(1)) - 1
                lines = left_output.split("\n")
                result = []
                for line in lines:
                    fields = line.split()
                    if col < len(fields):
                        result.append(fields[col])
                return "\n".join(result)

        elif right_cmd == "tee":
            # tee outputs to stdout AND file — just return the input
            return left_output

        # Unknown pipe target — just return left side output
        return left_output

    def _try_template(self, command: str, state: SessionState,
                      fs: VirtualFilesystem) -> Optional[str]:
        """Generate response from templates using system state."""
        parts = command.split()
        if not parts:
            return None
        cmd = parts[0]

        if cmd in self.templates:
            try:
                return self.templates[cmd](command, parts, state, fs)
            except Exception as e:
                logger.debug(f"Template error for {cmd}: {e}")
                return None

        return None

    def _fuzzy_match(self, command: str) -> Optional[str]:
        """Find the closest matching command in the database."""
        parts = command.split()
        if not parts:
            return None
        cmd = parts[0]

        # Look for same base command with similar flags
        if cmd in self.prefix_index:
            candidates = self.prefix_index[cmd]

            # Prefer commands with the most flag overlap
            cmd_flags = set(p for p in parts[1:] if p.startswith("-"))

            best_match = None
            best_score = -1

            for candidate in candidates:
                cand_parts = candidate.split()
                cand_flags = set(p for p in cand_parts[1:] if p.startswith("-"))
                overlap = len(cmd_flags & cand_flags)
                if overlap > best_score:
                    best_score = overlap
                    best_match = candidate

            if best_match and best_score > 0:
                return best_match

            # If no flag overlap, return the simplest version
            # (e.g., for `netstat -tlnp4`, return `netstat -tlnp` response)
            if candidates:
                simplest = min(candidates, key=len)
                return simplest

        return None

    # ── Template generators ──────────────────────────

    def _register_templates(self):
        """Register template response generators."""
        self.templates["find"] = self._template_find
        self.templates["grep"] = self._template_grep
        self.templates["wc"] = self._template_wc
        self.templates["file"] = self._template_file
        self.templates["stat"] = self._template_stat
        self.templates["which"] = self._template_which
        self.templates["type"] = self._template_type
        self.templates["whereis"] = self._template_whereis
        self.templates["touch"] = self._template_touch
        self.templates["mkdir"] = self._template_mkdir
        self.templates["rm"] = self._template_rm
        self.templates["cp"] = self._template_cp
        self.templates["mv"] = self._template_mv
        self.templates["chmod"] = self._template_chmod
        self.templates["ping"] = self._template_ping
        self.templates["curl"] = self._template_curl
        self.templates["wget"] = self._template_wget
        self.templates["ssh"] = self._template_ssh
        self.templates["scp"] = self._template_scp
        self.templates["nc"] = self._template_nc
        self.templates["nmap"] = self._template_nmap

    def _template_find(self, cmd: str, parts: list,
                       state: SessionState, fs: VirtualFilesystem) -> str:
        """Simulate find by walking the virtual filesystem."""
        # Very basic: find <path> -name <pattern>
        search_path = "/"
        name_pattern = None
        for i, p in enumerate(parts[1:], 1):
            if p == "-name" and i + 1 < len(parts):
                name_pattern = parts[i + 1].strip("'\"")
            elif not p.startswith("-") and i == 1:
                search_path = p

        if not name_pattern:
            return ""

        # Simple glob-to-regex conversion
        regex = name_pattern.replace(".", "\\.").replace("*", ".*")
        results = []
        self._walk_fs(fs, search_path, regex, results, depth=0, max_depth=5)
        return "\n".join(results[:20])  # Cap at 20 results

    def _walk_fs(self, fs: VirtualFilesystem, path: str,
                 pattern: str, results: list, depth: int, max_depth: int):
        """Recursively walk the virtual filesystem."""
        if depth > max_depth:
            return
        node = fs._resolve(path)
        if not node or not node.is_dir:
            return
        for name, child in node.children.items():
            child_path = f"{path}/{name}" if path != "/" else f"/{name}"
            if re.match(pattern, name):
                results.append(child_path)
            if child.is_dir:
                self._walk_fs(fs, child_path, pattern, results, depth + 1, max_depth)

    def _template_grep(self, cmd: str, parts: list,
                       state: SessionState, fs: VirtualFilesystem) -> str:
        """Simulate grep by searching file contents."""
        if len(parts) < 3:
            return "Usage: grep [OPTION]... PATTERNS [FILE]..."

        # Parse basic flags
        recursive = "-r" in parts or "-R" in parts
        ignore_case = "-i" in parts
        non_flag_args = [p for p in parts[1:] if not p.startswith("-")]

        if len(non_flag_args) < 2:
            return ""

        pattern = non_flag_args[0].strip("'\"")
        target = non_flag_args[1]

        if not target.startswith("/"):
            target = f"{state.cwd}/{target}" if state.cwd != "/" else f"/{target}"

        content = fs.read_file(target)
        if content is None:
            return f"grep: {non_flag_args[1]}: No such file or directory"

        flags = re.IGNORECASE if ignore_case else 0
        try:
            regex = re.compile(pattern, flags)
        except re.error:
            regex = re.compile(re.escape(pattern), flags)

        results = []
        for line in content.split("\n"):
            if regex.search(line):
                results.append(line)

        return "\n".join(results)

    def _template_wc(self, cmd: str, parts: list,
                     state: SessionState, fs: VirtualFilesystem) -> str:
        if len(parts) < 2:
            return ""
        target = parts[-1]
        if target.startswith("-"):
            return ""
        if not target.startswith("/"):
            target = f"{state.cwd}/{target}" if state.cwd != "/" else f"/{target}"
        content = fs.read_file(target)
        if content is None:
            return f"wc: {parts[-1]}: No such file or directory"
        lines = content.split("\n")
        words = sum(len(l.split()) for l in lines)
        chars = len(content)
        if "-l" in parts:
            return f"{len(lines)} {parts[-1]}"
        return f"  {len(lines)}  {words} {chars} {parts[-1]}"

    def _template_file(self, cmd: str, parts: list,
                       state: SessionState, fs: VirtualFilesystem) -> str:
        if len(parts) < 2:
            return ""
        target = parts[1]
        if fs.is_directory(target):
            return f"{target}: directory"
        content = fs.read_file(target)
        if content is None:
            return f"{target}: cannot open (No such file or directory)"
        if content.startswith("#!/bin/bash") or content.startswith("#!/bin/sh"):
            return f"{target}: Bourne-Again shell script, ASCII text executable"
        if content.startswith("{"):
            return f"{target}: JSON data, ASCII text"
        if content.startswith("---") or ":" in content.split("\n")[0]:
            return f"{target}: YAML data, ASCII text"
        return f"{target}: ASCII text"

    def _template_stat(self, cmd: str, parts: list,
                       state: SessionState, fs: VirtualFilesystem) -> str:
        if len(parts) < 2:
            return ""
        target = parts[1]
        node = fs._resolve(target)
        if not node:
            return f"stat: cannot statx '{target}': No such file or directory"
        ftype = "directory" if node.is_dir else "regular file"
        return (
            f"  File: {target}\n"
            f"  Size: {node.size}\tBlocks: {node.size // 512 + 1}\t"
            f"IO Block: 4096   {ftype}\n"
            f"Access: ({node.permissions}/{node.permissions})"
            f"  Uid: (    0/    {node.owner})"
            f"  Gid: (    0/    {node.group})\n"
            f"Modify: 2024-01-15 09:00:00.000000000 +0000"
        )

    def _template_which(self, cmd: str, parts: list,
                        state: SessionState, fs: VirtualFilesystem) -> str:
        if len(parts) < 2:
            return ""
        target = parts[1]
        common = {
            "python3": "/usr/bin/python3", "python": "/usr/bin/python3",
            "node": "/usr/bin/node", "npm": "/usr/bin/npm",
            "docker": "/usr/bin/docker", "git": "/usr/bin/git",
            "curl": "/usr/bin/curl", "wget": "/usr/bin/wget",
            "vim": "/usr/bin/vim", "nano": "/usr/bin/nano",
            "ssh": "/usr/bin/ssh", "scp": "/usr/bin/scp",
            "bash": "/usr/bin/bash", "sh": "/usr/bin/sh",
            "ls": "/usr/bin/ls", "cat": "/usr/bin/cat",
            "grep": "/usr/bin/grep", "find": "/usr/bin/find",
            "awk": "/usr/bin/awk", "sed": "/usr/bin/sed",
            "tar": "/usr/bin/tar", "gzip": "/usr/bin/gzip",
            "make": "/usr/bin/make", "gcc": "/usr/bin/gcc",
        }
        if target in common:
            return common[target]
        if fs.is_file(f"/usr/bin/{target}"):
            return f"/usr/bin/{target}"
        if fs.is_file(f"/usr/local/bin/{target}"):
            return f"/usr/local/bin/{target}"
        return f"{target} not found"

    def _template_type(self, cmd: str, parts: list,
                       state: SessionState, fs: VirtualFilesystem) -> str:
        if len(parts) < 2:
            return ""
        target = parts[1]
        builtins = {"cd", "echo", "export", "unset", "alias", "history",
                    "source", "type", "exit", "logout", "jobs", "fg", "bg"}
        if target in builtins:
            return f"{target} is a shell builtin"
        path = self._template_which(cmd, ["which", target], state, fs)
        if "not found" in path:
            return f"-bash: type: {target}: not found"
        return f"{target} is {path}"

    def _template_whereis(self, cmd: str, parts: list,
                          state: SessionState, fs: VirtualFilesystem) -> str:
        if len(parts) < 2:
            return ""
        target = parts[1]
        path = self._template_which(cmd, ["which", target], state, fs)
        if "not found" in path:
            return f"{target}:"
        return f"{target}: {path}"

    # ── Mutation templates (touch, mkdir, rm, etc.) ──

    def _template_touch(self, cmd: str, parts: list,
                        state: SessionState, fs: VirtualFilesystem) -> str:
        for target in parts[1:]:
            if not target.startswith("-"):
                path = target if target.startswith("/") else f"{state.cwd}/{target}"
                fs.create_file(path, "", state.username)
        return ""

    def _template_mkdir(self, cmd: str, parts: list,
                        state: SessionState, fs: VirtualFilesystem) -> str:
        for target in parts[1:]:
            if not target.startswith("-"):
                path = target if target.startswith("/") else f"{state.cwd}/{target}"
                fs.create_directory(path, state.username)
        return ""

    def _template_rm(self, cmd: str, parts: list,
                     state: SessionState, fs: VirtualFilesystem) -> str:
        # Don't actually remove from fs — just acknowledge
        return ""

    def _template_cp(self, cmd: str, parts: list,
                     state: SessionState, fs: VirtualFilesystem) -> str:
        return ""

    def _template_mv(self, cmd: str, parts: list,
                     state: SessionState, fs: VirtualFilesystem) -> str:
        return ""

    def _template_chmod(self, cmd: str, parts: list,
                        state: SessionState, fs: VirtualFilesystem) -> str:
        return ""

    # ── Network command templates ────────────────────

    def _template_ping(self, cmd: str, parts: list,
                       state: SessionState, fs: VirtualFilesystem) -> str:
        target = parts[-1] if len(parts) > 1 else "localhost"
        count = 3
        for i, p in enumerate(parts):
            if p == "-c" and i + 1 < len(parts):
                try: count = int(parts[i + 1])
                except: pass

        lines = [f"PING {target} ({target}) 56(84) bytes of data."]
        for seq in range(1, min(count, 4) + 1):
            ms = round(random.uniform(0.5, 45.0), 1)
            lines.append(
                f"64 bytes from {target}: icmp_seq={seq} ttl=64 time={ms} ms"
            )
            time.sleep(0.3)  # Simulate real ping timing
        lines.append(f"\n--- {target} ping statistics ---")
        lines.append(f"{count} packets transmitted, {count} received, 0% packet loss")
        return "\n".join(lines)

    def _template_curl(self, cmd: str, parts: list,
                       state: SessionState, fs: VirtualFilesystem) -> str:
        # Simulate connection timeout for external URLs
        url = next((p for p in parts[1:] if not p.startswith("-")), "")
        if "localhost" in url or "127.0.0.1" in url:
            return '{"status":"ok"}'
        time.sleep(random.uniform(1.0, 3.0))
        return f"curl: (28) Connection timed out after 30001 milliseconds"

    def _template_wget(self, cmd: str, parts: list,
                       state: SessionState, fs: VirtualFilesystem) -> str:
        url = next((p for p in parts[1:] if not p.startswith("-")), "")
        time.sleep(random.uniform(1.0, 3.0))
        return (f"--{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}--  {url}\n"
                f"Resolving {url.split('/')[2] if '/' in url else url}... failed: "
                f"Connection timed out.\nwget: unable to resolve host address '{url}'")

    def _template_ssh(self, cmd: str, parts: list,
                      state: SessionState, fs: VirtualFilesystem) -> str:
        target = parts[-1] if len(parts) > 1 else ""
        time.sleep(random.uniform(2.0, 5.0))
        host = target.split("@")[-1] if "@" in target else target
        return f"ssh: connect to host {host} port 22: Connection timed out"

    def _template_scp(self, cmd: str, parts: list,
                      state: SessionState, fs: VirtualFilesystem) -> str:
        time.sleep(random.uniform(2.0, 5.0))
        return "ssh: connect to host: Connection timed out\nlost connection"

    def _template_nc(self, cmd: str, parts: list,
                     state: SessionState, fs: VirtualFilesystem) -> str:
        time.sleep(random.uniform(1.0, 3.0))
        return "(UNKNOWN) [0.0.0.0] 0 (?) : Connection timed out"

    def _template_nmap(self, cmd: str, parts: list,
                       state: SessionState, fs: VirtualFilesystem) -> str:
        target = parts[-1] if len(parts) > 1 else "127.0.0.1"
        time.sleep(random.uniform(2.0, 5.0))
        return (
            f"Starting Nmap 7.80 ( https://nmap.org )\n"
            f"Note: Host seems down. If it is really up, but blocking our ping probes,\n"
            f"try -Pn\n"
            f"Nmap done: 1 IP address (0 hosts up) scanned in 3.04 seconds"
        )
