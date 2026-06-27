"""
CI/CDecoy — Command Router

Dispatches commands through:
  1. Builtins (cd, export, echo, history, etc.)
  2. Fast-path filesystem commands (ls, cat, head, tail)
  3. Common-command handlers (~60 commands attackers typically run)
  4. Tier dispatch (scripted / LLM / stub)

Unrecognized commands ALWAYS return "command not found" — never crash.
"""

import asyncio
import fnmatch
import logging
import os
import random
import re
from collections import OrderedDict
from datetime import datetime, timedelta

import httpx
from filesystem import VirtualFilesystem
from hifi_engine import HighFidelityEngine
from session import SessionState

logger = logging.getLogger("cicdecoy.router")

_MAX_RESPONSE_CACHE = 1000
MAX_INPUT_LENGTH = 1000  # Skip regex matching for oversized input
MAX_PIPE_DEPTH = 20


class CommandRouter:
    def __init__(self, config):
        self.config = config
        self.hifi_engine = HighFidelityEngine()
        self.last_source: str = "unknown"
        self.http_client: httpx.AsyncClient | None = None
        response_db_dir = os.environ.get("RESPONSE_DB_DIR", "/app/responses")
        self.hifi_engine.load_all_databases(response_db_dir)
        logger.info(f"HiFi engine: {len(self.hifi_engine.responses)} responses loaded")

        # Compile fast-path patterns
        self.fast_path_rules = []
        for rule in config.fast_path_commands:
            pattern_str = rule.get("match", "")
            if len(pattern_str) > 500:
                logger.warning(f"Fast-path pattern too long ({len(pattern_str)} chars), skipping")
                continue
            try:
                self.fast_path_rules.append(
                    {
                        "pattern": re.compile(pattern_str),
                        "source": rule["source"],
                    }
                )
            except re.error as e:
                logger.warning(f"Invalid fast-path pattern '{pattern_str}': {e}")

        self.scripted_responses: dict = {}
        self.response_cache: OrderedDict = OrderedDict()

        # Expose known command names for tab completion.
        self.known_commands: list[str] = sorted(
            [
                "ls",
                "cat",
                "head",
                "tail",
                "touch",
                "mkdir",
                "rm",
                "rmdir",
                "cp",
                "mv",
                "chmod",
                "chown",
                "find",
                "grep",
                "wc",
                "file",
                "stat",
                "du",
                "ln",
                "readlink",
                "realpath",
                "basename",
                "dirname",
                "whoami",
                "pwd",
                "id",
                "groups",
                "uname",
                "hostname",
                "uptime",
                "w",
                "who",
                "last",
                "ps",
                "top",
                "kill",
                "free",
                "df",
                "mount",
                "lsblk",
                "dmesg",
                "arch",
                "nproc",
                "lscpu",
                "date",
                "cal",
                "ifconfig",
                "ip",
                "netstat",
                "ss",
                "ping",
                "curl",
                "wget",
                "ssh",
                "scp",
                "nc",
                "ncat",
                "dig",
                "nslookup",
                "route",
                "traceroute",
                "arp",
                "apt",
                "apt-get",
                "dpkg",
                "yum",
                "pip",
                "pip3",
                "systemctl",
                "service",
                "crontab",
                "journalctl",
                "su",
                "iptables",
                "sestatus",
                "aa-status",
                "getent",
                "which",
                "whereis",
                "man",
                "less",
                "more",
                "vi",
                "vim",
                "nano",
                "python",
                "python3",
                "perl",
                "gcc",
                "make",
                "git",
                "tar",
                "gzip",
                "gunzip",
                "zip",
                "unzip",
                "base64",
                "md5sum",
                "sha256sum",
                "tee",
                "xargs",
                "sleep",
                "clear",
                "reset",
                "screen",
                "tmux",
                "docker",
                "kubectl",
                "aws",
                "lsof",
                "nmap",
                "node",
                "npm",
                "go",
                "java",
                "lsb_release",
                "hostnamectl",
                "timedatectl",
                "snap",
                "strings",
                "xxd",
                "strace",
                # Builtins
                "cd",
                "export",
                "unset",
                "history",
                "echo",
                "alias",
                "set",
                "type",
                "read",
                "false",
                "test",
                "eval",
                "jobs",
                "umask",
                "ulimit",
                "exit",
                "logout",
                "sudo",
                "seq",
                "time",
                "diff",
            ]
        )

    async def initialize(self):
        """Set up scripted responses and HTTP client."""
        self._load_scripted_responses()
        if self.config.tier == 3:
            self.http_client = httpx.AsyncClient(
                base_url=self.config.inference_endpoint,
                timeout=10.0,
            )
        logger.info(
            f"Router initialized: tier={self.config.tier} "
            f"fast_path_rules={len(self.fast_path_rules)} "
            f"scripted_responses={len(self.scripted_responses)}"
        )

    async def shutdown(self):
        """Close resources held by the router (e.g. HTTP client)."""
        if self.http_client:
            try:
                await self.http_client.aclose()
            except Exception as e:
                logger.warning(f"Error closing HTTP client: {e}")
            self.http_client = None

    async def route(
        self,
        command: str,
        session_state: SessionState,
        filesystem: VirtualFilesystem,
        tier: int,
    ) -> str:
        """
        Main routing logic.  Handles shell operators before dispatch.
        """
        # Strip inline comments (but not inside quotes — good enough for honepot)
        if "#" in command:
            command = command.split("#")[0].strip()
        if not command:
            return ""

        # Handle variable assignment: FOO=bar cmd ...
        var_assign = re.match(r"^(\w+=\S+\s+)+(.+)", command)
        if var_assign:
            # Set vars, then run the remaining command
            assigns, rest = command.rsplit(None, 1) if " " in command else (command, "")
            # Actually, let's just strip leading VAR=val pairs
            parts = command.split()
            real_parts = []
            for p in parts:
                if re.match(r"^\w+=", p) and not real_parts:
                    k, v = p.split("=", 1)
                    session_state.env[k] = v[:8192]
                else:
                    real_parts.append(p)
            if real_parts:
                command = " ".join(real_parts)
            else:
                return ""

        # Handle subshell $(...) and backticks — just strip them
        command = re.sub(r"\$\((.+?)\)", r"\1", command)

        # Handle for loops: for VAR in item1 item2 ...; do CMD; done
        for_match = re.match(r"^for\s+(\w+)\s+in\s+(.+?);\s*do\s+(.+?);\s*done$", command)
        if for_match:
            var_name = for_match.group(1)
            items_raw = for_match.group(2).strip()
            body = for_match.group(3)
            # Expand seq N M / $(seq N M) in the items list
            seq_match = re.match(r"^(?:\$\()?\s*seq\s+(\d+)\s+(\d+)\s*\)?$", items_raw)
            if seq_match:
                lo, hi = int(seq_match.group(1)), int(seq_match.group(2))
                hi = min(hi, lo + 99)  # Cap range
                items = [str(i) for i in range(lo, hi + 1)]
            else:
                items = items_raw.split()
            outputs = []
            for item in items[:100]:  # Cap iterations to prevent DoS
                session_state.env[var_name] = item[:8192]
                expanded = body.replace(f"${var_name}", item).replace(f"${{{var_name}}}", item)
                out = await self._route_single(expanded, session_state, filesystem, tier)
                if out:
                    outputs.append(out)
            return "\n".join(outputs)

        # Handle while loops: while CMD; do CMD; done
        while_match = re.match(r"^while\s+(.+?);\s*do\s+(.+?);\s*done$", command)
        if while_match:
            condition = while_match.group(1)
            body = while_match.group(2)
            outputs = []
            for _ in range(100):  # Hard cap to prevent infinite loops
                result = await self._route_single(condition, session_state, filesystem, tier)
                if result is None or self._is_error(result):
                    break
                out = await self._route_single(body, session_state, filesystem, tier)
                if out:
                    outputs.append(out)
            return "\n".join(outputs)

        # Handle if/then/else: if CMD; then CMD; [else CMD;] fi
        if_match = re.match(r"^if\s+(.+?);\s*then\s+(.+?)(?:;\s*else\s+(.+?))?;\s*fi$", command)
        if if_match:
            condition = if_match.group(1)
            then_cmd = if_match.group(2)
            else_cmd = if_match.group(3)
            result = await self._route_single(condition, session_state, filesystem, tier)
            if result is not None and not self._is_error(result):
                return await self._route_single(then_cmd, session_state, filesystem, tier)
            elif else_cmd:
                return await self._route_single(else_cmd, session_state, filesystem, tier)
            return ""

        # Handle semicolons: cmd1 ; cmd2 ; cmd3
        if ";" in command:
            parts = [p.strip() for p in command.split(";") if p.strip()]
            outputs = []
            for part in parts:
                out = await self._route_single(part, session_state, filesystem, tier)
                if out:
                    outputs.append(out)
            return "\n".join(outputs)

        # Handle &&
        if " && " in command:
            left, right = command.split(" && ", 1)
            first = await self._route_single(left.strip(), session_state, filesystem, tier)
            if first is not None and not self._is_error(first):
                second = await self._route_single(right.strip(), session_state, filesystem, tier)
                return "\n".join(o for o in [first, second] if o)
            return first or ""

        # Handle ||
        if " || " in command:
            left, right = command.split(" || ", 1)
            first = await self._route_single(left.strip(), session_state, filesystem, tier)
            if first and not self._is_error(first):
                return first
            return await self._route_single(right.strip(), session_state, filesystem, tier)

        # Handle pipes: execute left, pipe-aware stubs for right side
        if " | " in command:
            segments = [s.strip() for s in command.split(" | ")]
            if len(segments) > MAX_PIPE_DEPTH:
                return "-bash: pipe limit exceeded"
            result = await self._route_single(segments[0], session_state, filesystem, tier)
            # Apply simple pipe filters
            for seg in segments[1:]:
                result = self._apply_pipe(seg, result or "")
            return result

        # Handle output redirection
        if ">>" in command:
            parts = command.split(">>", 1)
            cmd_part = parts[0].strip()
            file_part = parts[1].strip()
            output = await self._route_single(cmd_part, session_state, filesystem, tier)
            self._handle_redirect_append(file_part, output or "", session_state, filesystem)
            return ""

        if ">" in command and "2>" not in command:
            parts = command.split(">", 1)
            cmd_part = parts[0].strip()
            file_part = parts[1].strip()
            output = await self._route_single(cmd_part, session_state, filesystem, tier) if cmd_part else ""
            self._handle_redirect_write(file_part, output or "", session_state, filesystem)
            return ""

        return await self._route_single(command, session_state, filesystem, tier)

    async def _route_single(
        self,
        command: str,
        session_state: SessionState,
        filesystem: VirtualFilesystem,
        tier: int,
    ) -> str:
        """Route a single, pipeline-free command."""

        # Strip sudo prefix — handle it realistically
        if command.startswith("sudo "):
            sudo_result = self._handle_sudo(command, session_state)
            if sudo_result is not None:
                return sudo_result
            # If sudo "succeeds", strip it and run the inner command as normal
            command = command[5:].strip()
            if command.startswith("-"):
                # Handle sudo flags: -u user, -i, -s, etc.
                parts = command.split(None, 1)
                if parts[0] in ("-i", "-s"):
                    return ""  # Just opens a shell — prompt handles it
                if parts[0] == "-u" and len(parts) > 1:
                    remainder = parts[1].split(None, 1)
                    command = remainder[1] if len(remainder) > 1 else ""
                    if not command:
                        return ""

        if not command:
            return ""

        # Expand glob patterns before dispatching
        if any(c in command for c in ("*", "?", "[")):
            command = self._expand_globs(command, session_state, filesystem)

        parts = command.split()
        cmd = parts[0]

        # Handle 'time' prefix — execute the rest and append timing
        if cmd == "time" and len(parts) > 1:
            import time as _time

            start = _time.monotonic()
            inner_cmd = " ".join(parts[1:])
            inner_result = await self.route(
                command=inner_cmd,
                session_state=session_state,
                filesystem=filesystem,
                tier=tier,
            )
            elapsed = _time.monotonic() - start
            timing = f"\nreal\t0m{elapsed:.3f}s\n" f"user\t0m{elapsed * 0.6:.3f}s\n" f"sys\t0m{elapsed * 0.15:.3f}s"
            return (inner_result or "") + timing

        # Stage 1: Shell builtins
        result = self._handle_builtin(command, session_state, filesystem)
        if result is not None:
            self.last_source = "builtin"
            return result

        # Stage 2: Fast-path rules from config
        if len(command) > MAX_INPUT_LENGTH:
            logger.warning("Input too long for regex matching (%d chars), skipping", len(command))
            return f"-bash: {cmd}: command not found"
        for rule in self.fast_path_rules:
            if rule["pattern"].match(command):
                result = self._handle_fast_path(command, rule["source"], session_state, filesystem)
                if result is not None:
                    self.last_source = "fast_path"
                    return result

        # Stage 3: Common command handlers (the big coverage expansion)
        result = self._handle_common(command, parts, session_state, filesystem)
        if result is not None:
            self.last_source = "common"
            return result

        hifi_result = self.hifi_engine.handle(command, session_state, filesystem)
        if hifi_result is not None:
            self.last_source = "hifi"
            return hifi_result

        # Stage 4: Tier dispatch
        if tier == 1:
            self.last_source = "tier1_stub"
            return f"-bash: {cmd}: command not found"

        elif tier == 2:
            result = self._handle_scripted(command, session_state)
            self.last_source = "scripted"
            return result

        elif tier == 3:
            result = await self._handle_adaptive(command, session_state, filesystem)
            self.last_source = "llm"
            return result

        # Final fallback — should never reach here, but never crash
        self.last_source = "fallback"
        return f"-bash: {cmd}: command not found"

    @staticmethod
    def _is_error(output: str) -> bool:
        """Check if output looks like an error (for && / || logic)."""
        return any(
            s in output
            for s in (
                "command not found",
                "No such file",
                "Permission denied",
                "not found",
                "cannot access",
                "Operation not permitted",
            )
        )

    def _expand_globs(
        self,
        command: str,
        session_state: SessionState,
        filesystem: VirtualFilesystem,
    ) -> str:
        """Expand glob patterns (*, ?, [) against the virtual filesystem."""
        tokens = command.split()
        if not tokens:
            return command
        expanded = [tokens[0]]  # Keep the command name as-is
        for token in tokens[1:]:
            if token.startswith("-"):
                expanded.append(token)
                continue
            if any(c in token for c in ("*", "?", "[")):
                # Split token into directory part and pattern part
                if "/" in token:
                    dir_part, pattern = token.rsplit("/", 1)
                    if not dir_part.startswith("/"):
                        dir_part = self._normalize_path(f"{session_state.cwd}/{dir_part}")
                else:
                    dir_part = session_state.cwd
                    pattern = token
                node = filesystem.get_node(dir_part)
                if node and node.is_dir:
                    matches = sorted(name for name in node.children if fnmatch.fnmatch(name, pattern))[:100]
                    if matches:
                        prefix = "" if dir_part == session_state.cwd else (f"{dir_part}/" if "/" in token else "")
                        expanded.extend(f"{prefix}{m}" for m in matches)
                        continue
                # No matches — keep literal token (bash default)
                expanded.append(token)
            else:
                expanded.append(token)
        return " ".join(expanded)

    # ══════════════════════════════════════════════════
    #  PIPE FILTERS
    # ══════════════════════════════════════════════════

    @staticmethod
    def _apply_pipe(pipe_cmd: str, input_text: str) -> str:
        """Apply simple pipe filters to output text."""
        parts = pipe_cmd.split()
        if not parts:
            return input_text
        cmd = parts[0]

        if cmd == "grep" and len(parts) >= 2:
            # Handle -v (invert), -i (case-insensitive), -c (count)
            flags = [p for p in parts[1:] if p.startswith("-")]
            args = [p for p in parts[1:] if not p.startswith("-")]
            if not args:
                return input_text
            pattern = args[0].strip("'\"")
            if len(pattern) > 200:
                return input_text  # Reject overly complex patterns (ReDoS)
            invert = any("-v" in f for f in flags)
            nocase = any("-i" in f for f in flags)
            count_only = any("-c" in f for f in flags)
            flag = re.IGNORECASE if nocase else 0
            lines = input_text.splitlines()
            matched = []
            try:
                compiled = re.compile(pattern, flag)
            except re.error:
                return input_text  # Invalid regex — pass through
            for line in lines:
                found = bool(compiled.search(line))
                if found != invert:
                    matched.append(line)
            if count_only:
                return str(len(matched)) + "\n"
            return "\n".join(matched) + "\n" if matched else ""

        elif cmd == "head":
            n = 10
            for i, p in enumerate(parts):
                if p == "-n" and i + 1 < len(parts):
                    try:
                        n = min(int(parts[i + 1]), 100_000)
                    except ValueError:
                        pass
                elif p.startswith("-") and p[1:].isdigit():
                    n = min(int(p[1:]), 100_000)
            selected = input_text.splitlines()[:n]
            result = "\n".join(selected)
            return result + "\n" if result else ""

        elif cmd == "tail":
            n = 10
            for i, p in enumerate(parts):
                if p == "-n" and i + 1 < len(parts):
                    try:
                        n = min(int(parts[i + 1]), 100_000)
                    except ValueError:
                        pass
                elif p.startswith("-") and p[1:].isdigit():
                    n = min(int(p[1:]), 100_000)
            selected = input_text.splitlines()[-n:]
            result = "\n".join(selected)
            return result + "\n" if result else ""

        elif cmd == "wc":
            lines = input_text.split("\n")
            # Match real wc: a trailing newline means the last empty
            # element doesn't count as a line.  Real wc counts '\n' chars.
            lcount = input_text.count("\n")
            wcount = len(input_text.split())
            ccount = len(input_text.encode("utf-8"))

            # Determine which columns to show.  Merged flags like -lw
            # are common, so scan every flag token for the characters.
            flag_chars = set()
            for p in parts[1:]:
                if p.startswith("-") and not p.startswith("--"):
                    flag_chars.update(p[1:])
            flag_l = "l" in flag_chars
            flag_w = "w" in flag_chars
            flag_c = "c" in flag_chars
            flag_m = "m" in flag_chars  # character count (same as -c for us)
            if not (flag_l or flag_w or flag_c or flag_m):
                # No flags → show all three (line, word, byte)
                flag_l = flag_w = flag_c = True

            cols = []
            if flag_l:
                cols.append(f"{lcount:>7}")
            if flag_w:
                cols.append(f"{wcount:>7}")
            if flag_c or flag_m:
                cols.append(f"{ccount:>7}")
            return "".join(cols) + "\n"

        elif cmd == "sort":
            lines = input_text.splitlines()
            # Parse flags — handle both separate and merged forms
            flag_chars = set()
            for p in parts[1:]:
                if p.startswith("-") and not p.startswith("--"):
                    flag_chars.update(p[1:])
            reverse = "r" in flag_chars
            unique = "u" in flag_chars
            numeric = "n" in flag_chars

            if numeric:

                def _num_key(line):
                    """Extract leading number for numeric sort."""
                    m = re.match(r"\s*(-?\d+(?:\.\d+)?)", line)
                    return float(m.group(1)) if m else 0.0

                result = sorted(lines, key=_num_key, reverse=reverse)
            else:
                result = sorted(lines, reverse=reverse)

            if unique:
                seen = set()
                deduped = []
                for line in result:
                    if line not in seen:
                        seen.add(line)
                        deduped.append(line)
                result = deduped
            return "\n".join(result) + "\n" if result else ""

        elif cmd == "uniq":
            lines = input_text.splitlines()
            # Parse flags
            flag_chars = set()
            for p in parts[1:]:
                if p.startswith("-") and not p.startswith("--"):
                    flag_chars.update(p[1:])
            count_mode = "c" in flag_chars
            dupes_only = "d" in flag_chars

            # Collapse adjacent duplicates, optionally counting
            groups = []  # list of (count, line)
            prev = None
            cnt = 0
            for line in lines:
                if line == prev:
                    cnt += 1
                else:
                    if prev is not None:
                        groups.append((cnt, prev))
                    prev = line
                    cnt = 1
            if prev is not None:
                groups.append((cnt, prev))

            result = []
            for cnt, line in groups:
                if dupes_only and cnt < 2:
                    continue
                if count_mode:
                    result.append(f"{cnt:>7} {line}")
                else:
                    result.append(line)
            return "\n".join(result) + "\n" if result else ""

        elif cmd == "awk":
            return CommandRouter._pipe_awk(parts, input_text)

        elif cmd == "sed":
            # Very basic s/old/new/ support
            if len(parts) >= 2:
                sed_expr = parts[1].strip("'\"")
                m = re.match(r"s([/|])(.+?)\1(.*?)\1([g]?)", sed_expr)
                if m:
                    old, new, flags = m.group(2), m.group(3), m.group(4)
                    if len(old) > 200:
                        return input_text  # Reject overly complex patterns (ReDoS)
                    count = 0 if "g" in flags else 1
                    try:
                        return re.sub(old, new, input_text, count=count)
                    except re.error:
                        return input_text
            return input_text

        elif cmd == "tee":
            # tee just passes through (file writing handled at redirect level)
            return input_text

        elif cmd == "cut":
            # Parse -d (delimiter) and -f (field selection)
            delim = "\t"
            field_spec = ""
            for i, p in enumerate(parts):
                if p == "-d" and i + 1 < len(parts):
                    delim = parts[i + 1].strip("'\"")
                elif p.startswith("-d"):
                    delim = p[2:].strip("'\"")
                elif p == "-f" and i + 1 < len(parts):
                    field_spec = parts[i + 1]
                elif p.startswith("-f"):
                    field_spec = p[2:]

            if not field_spec:
                return input_text

            # Parse field spec: supports single (3), list (1,3,5),
            # range (2-4), open range (-3, 4-), and combos (1,3-5)
            selected_indices = set()
            max_possible = 1000  # upper bound for open ranges
            for part in field_spec.split(","):
                part = part.strip()
                if "-" in part:
                    bounds = part.split("-", 1)
                    try:
                        start = int(bounds[0]) if bounds[0] else 1
                        end = int(bounds[1]) if bounds[1] else max_possible
                    except ValueError:
                        continue
                    start = max(1, min(start, max_possible))
                    end = max(1, min(end, max_possible))
                    for n in range(start, end + 1):
                        selected_indices.add(n)
                elif part.isdigit():
                    selected_indices.add(int(part))

            if not selected_indices:
                return input_text

            lines = input_text.splitlines()
            result = []
            for line in lines:
                fields = line.split(delim)
                picked = []
                for idx in sorted(selected_indices):
                    if idx - 1 < len(fields):
                        picked.append(fields[idx - 1])
                result.append(delim.join(picked))
            return "\n".join(result) + "\n" if result else ""

        elif cmd == "tr":
            # basic tr 'a' 'b'
            if len(parts) >= 3:
                old_chars = parts[1].strip("'\"")
                new_chars = parts[2].strip("'\"")
                # Pad new_chars if shorter (real tr repeats the last char)
                if len(new_chars) < len(old_chars):
                    new_chars = new_chars + new_chars[-1:] * (len(old_chars) - len(new_chars))
                try:
                    table = str.maketrans(old_chars, new_chars[: len(old_chars)])
                    return input_text.translate(table)
                except ValueError:
                    return input_text  # Mismatched lengths — pass through
            return input_text

        elif cmd == "xargs":
            return input_text

        elif cmd == "less" or cmd == "more":
            return input_text

        # Unknown pipe command — just pass through
        return input_text

    @staticmethod
    def _pipe_awk(parts: list, input_text: str) -> str:
        """Realistic awk subset covering common attacker usage patterns.

        Supports:
          - Field printing:  awk '{print $1}'  awk '{print $1, $3}'
          - Custom delimiter: awk -F: '{print $1}'
          - Last field:  awk '{print $NF}'
          - Line numbers: awk '{print NR, $0}'
          - Pattern match: awk '/regex/'  awk '/regex/{print $2}'
          - Negation:    awk '!/regex/'
          - NR filter:   awk 'NR==3'  awk 'NR>2'
          - END block:   awk 'END{print NR}'
          - BEGIN block:  awk 'BEGIN{OFS=":"}{print $1,$2}'
          - Multiple print args with custom OFS
        """
        # Re-parse from the original pipe_cmd to handle quoted programs.
        # parts = pipe_cmd.split() loses quote grouping, so reconstruct
        # the program by extracting -F flag first, then joining the rest.
        raw = " ".join(parts[1:])  # everything after 'awk'

        # Parse -F (field separator)
        fs = None  # default: whitespace
        fs_match = re.match(r"-F\s*(\S+)\s*(.*)", raw)
        if fs_match:
            fs = fs_match.group(1).strip("'\"")
            raw = fs_match.group(2)

        # Extract the program: everything between outer quotes
        program = raw.strip().strip("'\"")

        if not program:
            return input_text

        lines = input_text.split("\n")
        # Remove trailing empty line from trailing newline
        if lines and lines[-1] == "":
            lines = lines[:-1]

        output_lines = []
        ofs = " "  # output field separator

        # Parse BEGIN block for OFS
        begin_match = re.match(r"BEGIN\s*\{([^}]*)\}\s*(.*)", program)
        main_program = program
        if begin_match:
            begin_body = begin_match.group(1)
            main_program = begin_match.group(2)
            # Parse OFS="x"
            ofs_match = re.search(r'OFS\s*=\s*"([^"]*)"', begin_body)
            if ofs_match:
                ofs = ofs_match.group(1)

        # Check for END-only block
        end_match = re.match(r"END\s*\{([^}]*)\}", main_program)
        if end_match:
            end_body = end_match.group(1)
            nr = len(lines)
            # Handle 'print NR'
            if "NR" in end_body:
                return str(nr) + "\n"
            return str(nr) + "\n"

        # Parse pattern and action from main program
        # Forms: '{print $1}', '/pat/{print $1}', '!/pat/', 'NR==3', '/pat/'
        pattern_re = None
        negate_pattern = False
        nr_op = None
        nr_val = 0
        action = None

        # Pattern: /regex/{action} or !/regex/{action}
        pat_act = re.match(r"(!?)/([^/]*)/(.*)", main_program)
        if pat_act:
            negate_pattern = pat_act.group(1) == "!"
            if len(pat_act.group(2)) > 200:
                return input_text
            try:
                pattern_re = re.compile(pat_act.group(2))
            except re.error:
                return input_text
            rest = pat_act.group(3).strip()
            if rest.startswith("{") and rest.endswith("}"):
                action = rest[1:-1].strip()
            elif not rest:
                action = "print $0"  # default: print matching line
        # NR filter: NR==3, NR>2, NR>=2, NR<5, NR<=5
        elif main_program.startswith("NR"):
            nr_match = re.match(r"NR\s*(==|>=?|<=?)\s*(\d+)\s*(.*)", main_program)
            if nr_match:
                nr_op = nr_match.group(1)
                nr_val = int(nr_match.group(2))
                rest = nr_match.group(3).strip()
                if rest.startswith("{") and rest.endswith("}"):
                    action = rest[1:-1].strip()
                else:
                    action = "print $0"
        # Action only: {print $1}
        elif main_program.startswith("{") and main_program.endswith("}"):
            action = main_program[1:-1].strip()
        else:
            return input_text

        if action is None:
            action = "print $0"

        for nr, line in enumerate(lines, 1):
            # Apply pattern filter
            if pattern_re is not None:
                matched = bool(pattern_re.search(line))
                if negate_pattern:
                    matched = not matched
                if not matched:
                    continue

            # Apply NR filter
            if nr_op is not None:
                if nr_op == "==" and nr != nr_val:
                    continue
                elif nr_op == ">" and not (nr > nr_val):
                    continue
                elif nr_op == ">=" and not (nr >= nr_val):
                    continue
                elif nr_op == "<" and not (nr < nr_val):
                    continue
                elif nr_op == "<=" and not (nr <= nr_val):
                    continue

            # Split line into fields
            if fs:
                fields = line.split(fs)
            else:
                fields = line.split()

            # Execute action
            if action.startswith("print"):
                print_args = action[5:].strip()
                if not print_args:
                    print_args = "$0"
                output_parts = []
                for arg in re.split(r"[,\s]+", print_args):
                    arg = arg.strip()
                    if not arg:
                        continue
                    if arg == "$0":
                        output_parts.append(line)
                    elif arg == "$NF":
                        output_parts.append(fields[-1] if fields else "")
                    elif arg == "NR":
                        output_parts.append(str(nr))
                    elif arg.startswith("$"):
                        try:
                            idx = int(arg[1:])
                            if 1 <= idx <= len(fields):
                                output_parts.append(fields[idx - 1])
                            else:
                                output_parts.append("")
                        except ValueError:
                            output_parts.append(arg)
                    elif arg.startswith('"') and arg.endswith('"'):
                        output_parts.append(arg[1:-1])
                    else:
                        output_parts.append(arg)
                output_lines.append(ofs.join(output_parts))
            else:
                # Unknown action — just output the line
                output_lines.append(line)

        return "\n".join(output_lines) + "\n" if output_lines else ""

    # ══════════════════════════════════════════════════
    #  REDIRECTION HANDLERS
    # ══════════════════════════════════════════════════

    def _handle_redirect_write(self, target: str, content: str, state: SessionState, fs: VirtualFilesystem):
        target = target.strip()
        if not target.startswith("/"):
            target = f"{state.cwd}/{target}" if state.cwd != "/" else f"/{target}"
        target = self._normalize_path(target)
        fs.create_file(target, content, owner=state.username)

    def _handle_redirect_append(self, target: str, content: str, state: SessionState, fs: VirtualFilesystem):
        target = target.strip()
        if not target.startswith("/"):
            target = f"{state.cwd}/{target}" if state.cwd != "/" else f"/{target}"
        target = self._normalize_path(target)
        fs.append_file(target, content)

    # ══════════════════════════════════════════════════
    #  SUDO HANDLER
    # ══════════════════════════════════════════════════

    def _handle_sudo(self, command: str, state: SessionState) -> str | None:
        """
        Handle sudo. If uid==0 already, just strip it.
        Otherwise return a password prompt failure (we can't do interactive
        password prompts in this line-buffered model, so simulate failure
        or success based on config).
        """
        if state.uid == 0:
            return None  # Root doesn't need sudo — strip and continue

        # For non-root users, simulate the "sorry, try again" dance
        # unless we've already "authenticated" in this session
        if not state.sudo_authenticated:
            state.sudo_authenticated = True  # Let them through next time
            return (
                f"[sudo] password for {state.username}: \n"
                "Sorry, try again.\n"
                f"[sudo] password for {state.username}: \n"
                f"sudo: 1 incorrect password attempt"
            )

        return None  # Authenticated — strip sudo and run

    # ══════════════════════════════════════════════════
    #  STAGE 1: SHELL BUILTINS
    # ══════════════════════════════════════════════════

    def _handle_builtin(self, command: str, state: SessionState, fs: VirtualFilesystem) -> str | None:
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
                    state.env[k] = v.strip("'\"")[:8192]
            return ""
        elif cmd == "unset":
            for p in parts[1:]:
                state.env.pop(p, None)
            return ""
        elif cmd == "history":
            lines = []
            for i, c in enumerate(state.command_history):
                lines.append(f"  {i+1:4d}  {c}")
            # Include the 'history' command itself
            lines.append(f"  {len(state.command_history)+1:4d}  history")
            return "\n".join(lines)
        elif cmd == "echo":
            text = " ".join(parts[1:])
            # Expand env vars — single pass only.  $() and backtick
            # patterns in variable VALUES are intentionally NOT
            # re-expanded; this is a honeypot and we control the env
            # dict, so there is no command injection risk.
            for k, v in state.env.items():
                text = text.replace(f"${k}", v).replace(f"${{{k}}}", v)
            text = text[:65536]
            # Handle -n flag (no newline — we just return without trailing \n)
            if text.startswith("-n "):
                text = text[3:]
            # Handle -e flag (interpret escapes)
            if text.startswith("-e "):
                text = text[3:]
                text = text.replace("\\n", "\n").replace("\\t", "\t")
            text = text.strip("'\"")
            return text
        elif cmd == "alias":
            if len(parts) == 1:
                return (
                    "alias egrep='egrep --color=auto'\n"
                    "alias fgrep='fgrep --color=auto'\n"
                    "alias grep='grep --color=auto'\n"
                    "alias l='ls -CF'\n"
                    "alias la='ls -A'\n"
                    "alias ll='ls -alF'\n"
                    "alias ls='ls --color=auto'"
                )
            return ""
        elif cmd in ("source", "."):
            return ""
        elif cmd == "set":
            if len(parts) == 1:
                # Show all environment variables
                lines = [f"{k}={v}" for k, v in sorted(state.env.items())]
                return "\n".join(lines)
            return ""
        elif cmd in ("env", "printenv"):
            if len(parts) == 1:
                lines = [f"{k}={v}" for k, v in sorted(state.env.items())]
                return "\n".join(lines)
            # printenv VAR
            if len(parts) == 2:
                return state.env.get(parts[1], "")
            return ""
        elif cmd == "type":
            if len(parts) > 1:
                target = parts[1]
                shell_builtins = {
                    "cd",
                    "echo",
                    "export",
                    "unset",
                    "alias",
                    "source",
                    "history",
                    "type",
                    "exit",
                    "logout",
                    "set",
                    "env",
                    "printenv",
                    "read",
                    "eval",
                    "exec",
                    "trap",
                    "wait",
                    "jobs",
                    "fg",
                    "bg",
                    "umask",
                    "ulimit",
                    "hash",
                    "test",
                    "true",
                    "false",
                    ":",
                    "[",
                }
                if target in shell_builtins:
                    return f"{target} is a shell builtin"
                # Check known commands
                known_bins = {
                    "ls",
                    "cat",
                    "grep",
                    "find",
                    "ps",
                    "top",
                    "kill",
                    "ssh",
                    "scp",
                    "curl",
                    "wget",
                    "python3",
                    "python",
                    "perl",
                    "gcc",
                    "make",
                    "git",
                    "vim",
                    "nano",
                    "awk",
                    "sed",
                    "tar",
                    "gzip",
                    "gunzip",
                    "zip",
                    "unzip",
                    "chmod",
                    "chown",
                    "cp",
                    "mv",
                    "rm",
                    "touch",
                    "mkdir",
                    "rmdir",
                    "head",
                    "tail",
                    "wc",
                    "sort",
                    "uniq",
                    "diff",
                    "file",
                    "stat",
                    "du",
                    "df",
                    "free",
                    "mount",
                    "umount",
                    "ifconfig",
                    "ip",
                    "netstat",
                    "ss",
                    "ping",
                    "dig",
                    "nslookup",
                    "systemctl",
                    "service",
                    "apt",
                    "dpkg",
                    "snap",
                    "uname",
                    "hostname",
                    "uptime",
                    "w",
                    "who",
                    "last",
                    "date",
                    "cal",
                    "bc",
                    "man",
                    "less",
                    "more",
                    "tee",
                    "xargs",
                    "cut",
                    "tr",
                    "base64",
                    "kubectl",
                    "aws",
                    "node",
                    "npm",
                    "go",
                    "java",
                    "nmap",
                    "lsb_release",
                    "hostnamectl",
                    "timedatectl",
                    "strings",
                    "xxd",
                    "strace",
                    "docker",
                }
                if target in known_bins:
                    return f"{target} is /usr/bin/{target}"
                return f"-bash: type: {target}: not found"
            return ""
        elif cmd == "read":
            return ""
        elif cmd in ("true", ":"):
            return ""
        elif cmd == "false":
            return ""
        elif cmd == "test" or cmd == "[":
            return ""
        elif cmd == "eval":
            return ""
        elif cmd == "jobs":
            return ""
        elif cmd in ("fg", "bg"):
            return "-bash: fg: current: no such job"
        elif cmd == "umask":
            if len(parts) == 1:
                return "0022"
            return ""
        elif cmd == "ulimit":
            if "-a" in parts:
                return (
                    "core file size          (blocks, -c) 0\n"
                    "data seg size           (kbytes, -d) unlimited\n"
                    "scheduling priority             (-e) 0\n"
                    "file size               (blocks, -f) unlimited\n"
                    "pending signals                 (-i) 31398\n"
                    "max locked memory       (kbytes, -l) 65536\n"
                    "max memory size         (kbytes, -m) unlimited\n"
                    "open files                      (-n) 1024\n"
                    "pipe size            (512 bytes, -p) 8\n"
                    "POSIX message queues     (bytes, -q) 819200\n"
                    "real-time priority              (-r) 0\n"
                    "stack size              (kbytes, -s) 8192\n"
                    "cpu time               (seconds, -t) unlimited\n"
                    "max user processes              (-u) 31398\n"
                    "virtual memory          (kbytes, -v) unlimited\n"
                    "file locks                      (-x) unlimited"
                )
            return "unlimited"

        return None  # Not a builtin

    def _builtin_cd(self, parts: list, state: SessionState, fs: VirtualFilesystem) -> str:
        if len(parts) < 2 or parts[1] == "~":
            state.cwd = state.home
            return ""

        target = parts[1]
        if target == "-":
            # Should swap with OLDPWD — just go home for now
            old = state.env.get("OLDPWD", state.home)
            state.env["OLDPWD"] = state.cwd
            state.cwd = old
            return state.cwd

        if target.startswith("~"):
            target = state.home + target[1:]

        if not target.startswith("/"):
            if state.cwd == "/":
                target = f"/{target}"
            else:
                target = f"{state.cwd}/{target}"

        target = self._normalize_path(target)

        if fs.is_directory(target):
            state.env["OLDPWD"] = state.cwd
            state.cwd = target
            return ""
        elif fs.is_file(target):
            return f"-bash: cd: {parts[1]}: Not a directory"
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

    # ══════════════════════════════════════════════════
    #  STAGE 2: FAST-PATH (from config rules)
    # ══════════════════════════════════════════════════

    def _handle_fast_path(self, command: str, source: str, state: SessionState, fs: VirtualFilesystem) -> str | None:
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

    def _fast_path_fs(self, command: str, parts: list, state: SessionState, fs: VirtualFilesystem) -> str:
        cmd = parts[0]

        if cmd == "ls":
            return self._cmd_ls(parts, state, fs)
        elif cmd == "cat":
            return self._cmd_cat(parts, state, fs)
        elif cmd in ("head", "tail"):
            return self._cmd_head_tail(cmd, parts, state, fs)
        return ""

    def _fast_path_state(self, cmd: str, state: SessionState) -> str:
        if cmd == "pwd":
            return state.cwd
        elif cmd == "whoami":
            return state.username
        elif cmd == "id":
            gid = state.uid
            groups = f"{gid}({state.username})"
            if state.uid == 0:
                groups = "0(root)"
            return f"uid={state.uid}({state.username}) " f"gid={gid}({state.username}) " f"groups={groups}"
        elif cmd == "hostname":
            return state.hostname
        return ""

    def _fast_path_profile(self, command: str, fs: VirtualFilesystem) -> str:
        profile = fs.get_profile_data()
        static = profile.get("static_responses", {})

        if command in static:
            return static[command]

        cmd = command.split()[0]
        for key, val in static.items():
            if key.startswith(cmd):
                return val

        if cmd == "ps":
            return self._render_ps(command, profile)

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

    # ══════════════════════════════════════════════════
    #  STAGE 3: COMMON COMMAND HANDLERS
    # ══════════════════════════════════════════════════

    def _handle_common(self, command: str, parts: list, state: SessionState, fs: VirtualFilesystem) -> str | None:
        """
        Handle the ~60 most common commands attackers run.
        Returns None if the command is not recognized here (falls through
        to tier dispatch).
        """
        cmd = parts[0]
        dispatch = {
            # Filesystem
            "ls": lambda: self._cmd_ls(parts, state, fs),
            "cat": lambda: self._cmd_cat(parts, state, fs),
            "head": lambda: self._cmd_head_tail("head", parts, state, fs),
            "tail": lambda: self._cmd_head_tail("tail", parts, state, fs),
            "touch": lambda: self._cmd_touch(parts, state, fs),
            "mkdir": lambda: self._cmd_mkdir(parts, state, fs),
            "rm": lambda: self._cmd_rm(parts, state, fs),
            "rmdir": lambda: self._cmd_rmdir(parts, state, fs),
            "cp": lambda: self._cmd_cp(parts, state, fs),
            "mv": lambda: self._cmd_mv(parts, state, fs),
            "chmod": lambda: self._cmd_chmod(parts, state, fs),
            "chown": lambda: self._cmd_chown(parts, state, fs),
            "find": lambda: self._cmd_find(parts, state, fs),
            "grep": lambda: self._cmd_grep(parts, state, fs),
            "wc": lambda: self._cmd_wc(parts, state, fs),
            "file": lambda: self._cmd_file(parts, state, fs),
            "stat": lambda: self._cmd_stat(parts, state, fs),
            "du": lambda: self._cmd_du(parts, state, fs),
            "ln": lambda: "",  # Stub
            "readlink": lambda: "",
            "realpath": lambda: self._resolve_target(parts, state),
            "basename": lambda: os.path.basename(parts[1]) if len(parts) > 1 else "",
            "dirname": lambda: os.path.dirname(parts[1]) if len(parts) > 1 else ".",
            # System info — identity
            "whoami": lambda: state.username,
            "pwd": lambda: state.cwd,
            "id": lambda: self._cmd_id(state),
            "groups": lambda: state.username,
            # System info
            "uname": lambda: self._cmd_uname(parts),
            "hostname": lambda: state.hostname,
            "uptime": lambda: self._cmd_uptime(fs),
            "w": lambda: self._cmd_w(state, fs),
            "who": lambda: self._cmd_who(state),
            "last": lambda: self._cmd_last(state),
            "ps": lambda: self._cmd_ps(command, fs),
            "top": lambda: self._cmd_top(state, fs),
            "kill": lambda: "",
            "free": lambda: self._cmd_free(command, fs),
            "df": lambda: self._cmd_df(command, fs),
            "mount": lambda: self._cmd_mount(),
            "lsblk": lambda: self._cmd_lsblk(),
            "dmesg": lambda: self._cmd_dmesg(),
            "arch": lambda: "x86_64",
            "nproc": lambda: "4",
            "lscpu": lambda: self._cmd_lscpu(),
            "date": lambda: datetime.now().strftime("%a %b %d %H:%M:%S %Z %Y"),
            "cal": lambda: self._cmd_cal(),
            # Network
            "ifconfig": lambda: self._cmd_ifconfig(fs),
            "ip": lambda: self._cmd_ip(parts, fs),
            "netstat": lambda: self._cmd_netstat(parts),
            "ss": lambda: self._cmd_ss(parts),
            "ping": lambda: self._cmd_ping(parts),
            "curl": lambda: self._cmd_curl(parts),
            "wget": lambda: self._cmd_wget(parts),
            "ssh": lambda: self._cmd_ssh(parts),
            "scp": lambda: self._cmd_scp(parts),
            "nc": lambda: self._cmd_nc(parts),
            "ncat": lambda: self._cmd_nc(parts),
            "dig": lambda: self._cmd_dig(parts),
            "nslookup": lambda: self._cmd_nslookup(parts),
            "route": lambda: self._cmd_route(),
            "traceroute": lambda: self._cmd_traceroute(parts),
            "arp": lambda: self._cmd_arp(),
            # Package / service management
            "apt": lambda: self._cmd_apt(parts),
            "apt-get": lambda: self._cmd_apt(parts),
            "dpkg": lambda: self._cmd_dpkg(parts),
            "yum": lambda: "-bash: yum: command not found",
            "pip": lambda: self._cmd_pip(parts),
            "pip3": lambda: self._cmd_pip(parts),
            "systemctl": lambda: self._cmd_systemctl(parts),
            "service": lambda: self._cmd_service(parts),
            "crontab": lambda: self._cmd_crontab(parts, state),
            "journalctl": lambda: self._cmd_journalctl(parts),
            # Security / priv-esc
            "su": lambda: self._cmd_su(parts, state),
            "iptables": lambda: self._cmd_iptables(parts, state),
            "sestatus": lambda: "SELinux status:                 disabled",
            "aa-status": lambda: self._cmd_aa_status(),
            "getent": lambda: self._cmd_getent(parts, fs),
            # Misc tools
            "which": lambda: self._cmd_which(parts),
            "whereis": lambda: self._cmd_whereis(parts),
            "man": lambda: f"No manual entry for {parts[1]}" if len(parts) > 1 else "What manual page do you want?",
            "less": lambda: self._cmd_cat(parts, state, fs),
            "more": lambda: self._cmd_cat(parts, state, fs),
            "vi": lambda: "",
            "vim": lambda: "",
            "nano": lambda: "",
            "python": lambda: self._cmd_python(parts),
            "python3": lambda: self._cmd_python(parts),
            "perl": lambda: self._cmd_perl(parts),
            "gcc": lambda: self._cmd_gcc(parts),
            "make": lambda: self._cmd_make(parts),
            "git": lambda: self._cmd_git(parts),
            "tar": lambda: self._cmd_tar(parts),
            "gzip": lambda: "",
            "gunzip": lambda: "",
            "zip": lambda: "zip: command not found" if not fs.file_exists("/usr/bin/zip") else "",
            "unzip": lambda: "",
            "base64": lambda: "",
            "md5sum": lambda: self._cmd_hash(parts, "md5"),
            "sha256sum": lambda: self._cmd_hash(parts, "sha256"),
            "tee": lambda: "",
            "xargs": lambda: "",
            "sleep": lambda: "",
            "clear": lambda: "\x1b[2J\x1b[H",
            "reset": lambda: "",
            "screen": lambda: "Cannot make directory '/run/screen': Permission denied",
            "tmux": lambda: "no server running on /tmp/tmux-1000/default",
            "docker": lambda: self._cmd_docker(parts, state),
            "kubectl": lambda: self._cmd_kubectl(parts),
            "aws": lambda: self._cmd_aws(parts),
            "lsof": lambda: self._cmd_lsof(parts),
            "nmap": lambda: self._cmd_nmap(parts),
            "node": lambda: self._cmd_node(parts),
            "npm": lambda: self._cmd_npm(parts),
            "go": lambda: self._cmd_go(parts),
            "java": lambda: self._cmd_java(parts),
            "lsb_release": lambda: self._cmd_lsb_release(parts),
            "hostnamectl": lambda: self._cmd_hostnamectl(state),
            "timedatectl": lambda: self._cmd_timedatectl(),
            "snap": lambda: self._cmd_snap(parts),
            "strings": lambda: self._cmd_strings(parts),
            "xxd": lambda: self._cmd_xxd(parts),
            "strace": lambda: self._cmd_strace(parts, state),
            "seq": lambda: self._cmd_seq(parts),
            "diff": lambda: self._cmd_diff(parts, fs),
            "time": lambda: None,  # Handled specially in _route_single()
        }

        handler = dispatch.get(cmd)
        if handler:
            return handler()

        return None  # Not a common command — fall through to tier dispatch

    # ── Filesystem Commands ──────────────────────────

    def _cmd_ls(self, parts: list, state: SessionState, fs: VirtualFilesystem) -> str:
        flags = [p for p in parts[1:] if p.startswith("-")]
        targets = [p for p in parts[1:] if not p.startswith("-")]
        target = targets[0] if targets else state.cwd

        if not target.startswith("/"):
            target = f"{state.cwd}/{target}" if state.cwd != "/" else f"/{target}"
        target = self._normalize_path(target)

        all_flags = "".join(flags)
        long_fmt = "l" in all_flags
        hidden = "a" in all_flags
        raw = fs.list_directory(target, long_format=long_fmt, show_hidden=hidden)

        if not long_fmt and raw and "cannot access" not in raw:
            term = state.env.get("TERM", "xterm-256color")
            if term not in ("dumb", ""):
                raw = self._colorize_ls(raw, target, fs)

        return raw

    @staticmethod
    def _colorize_ls(listing: str, path: str, fs: VirtualFilesystem) -> str:
        BLUE = "\x1b[01;34m"
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
                colored.append(f"{GREEN}{name}{RESET}")
            else:
                colored.append(name)

        return "  ".join(colored)

    # Device file paths that require special read behavior
    _DEV_FILES = {
        "/dev/null": lambda: "",
        "/dev/zero": lambda: "\x00" * 256,
        "/dev/full": lambda: "",
        "/dev/stdin": lambda: "",
        "/dev/stdout": lambda: "",
        "/dev/stderr": lambda: "",
        "/dev/tty": lambda: "",
        "/dev/random": lambda: os.urandom(256).hex(),
        "/dev/urandom": lambda: os.urandom(256).hex(),
    }

    def _cmd_cat(self, parts: list, state: SessionState, fs: VirtualFilesystem) -> str:
        if len(parts) < 2:
            return ""
        target = parts[-1]  # Handle flags before filename
        if target.startswith("-"):
            return ""
        if not target.startswith("/"):
            target = f"{state.cwd}/{target}" if state.cwd != "/" else f"/{target}"
        target = self._normalize_path(target)

        # Handle device files with special behavior
        if target in self._DEV_FILES:
            return self._DEV_FILES[target]()

        content = fs.read_file(target)
        if content is None:
            if fs.is_directory(target):
                return f"cat: {parts[-1]}: Is a directory"
            return f"cat: {parts[-1]}: No such file or directory"
        return content

    def _cmd_head_tail(self, which: str, parts: list, state: SessionState, fs: VirtualFilesystem) -> str:
        if len(parts) < 2:
            return ""
        target = parts[-1]
        if not target.startswith("/"):
            target = f"{state.cwd}/{target}" if state.cwd != "/" else f"/{target}"
        target = self._normalize_path(target)
        content = fs.read_file(target)
        if content is None:
            return f"{which}: cannot open '{parts[-1]}' for reading: " "No such file or directory"
        lines = content.split("\n")
        n = 10
        for i, p in enumerate(parts):
            if p == "-n" and i + 1 < len(parts):
                try:
                    n = min(int(parts[i + 1]), 100_000)
                except ValueError:
                    pass
            elif p.startswith("-") and p[1:].isdigit():
                n = min(int(p[1:]), 100_000)
        return "\n".join(lines[:n] if which == "head" else lines[-n:])

    def _cmd_touch(self, parts: list, state: SessionState, fs: VirtualFilesystem) -> str:
        if len(parts) < 2:
            return "touch: missing file operand"
        for target in parts[1:]:
            if target.startswith("-"):
                continue
            path = self._resolve_target_path(target, state)
            if not fs.file_exists(path):
                fs.create_file(path, "", owner=state.username)
        return ""

    def _cmd_mkdir(self, parts: list, state: SessionState, fs: VirtualFilesystem) -> str:
        if len(parts) < 2:
            return "mkdir: missing operand"
        parents = "-p" in parts
        for target in parts[1:]:
            if target.startswith("-"):
                continue
            path = self._resolve_target_path(target, state)
            if fs.file_exists(path):
                if not parents:
                    return f"mkdir: cannot create directory '{target}': File exists"
            else:
                ok = fs.create_directory(path, owner=state.username, parents=parents)
                if not ok and not parents:
                    return f"mkdir: cannot create directory '{target}': " "No such file or directory"
        return ""

    def _cmd_rm(self, parts: list, state: SessionState, fs: VirtualFilesystem) -> str:
        if len(parts) < 2:
            return "rm: missing operand"
        flags = "".join(p for p in parts[1:] if p.startswith("-"))
        recursive = "r" in flags or "R" in flags
        force = "f" in flags

        for target in parts[1:]:
            if target.startswith("-"):
                continue
            path = self._resolve_target_path(target, state)
            if fs.is_directory(path):
                if not recursive:
                    return f"rm: cannot remove '{target}': Is a directory"
                fs.remove_directory(path, recursive=True)
            elif fs.is_file(path):
                fs.remove_file(path)
            elif not force:
                return f"rm: cannot remove '{target}': No such file or directory"
        return ""

    def _cmd_rmdir(self, parts: list, state: SessionState, fs: VirtualFilesystem) -> str:
        if len(parts) < 2:
            return "rmdir: missing operand"
        for target in parts[1:]:
            if target.startswith("-"):
                continue
            path = self._resolve_target_path(target, state)
            if not fs.is_directory(path):
                return f"rmdir: failed to remove '{target}': No such file or directory"
            node = fs.get_node(path)
            if node and node.children:
                return f"rmdir: failed to remove '{target}': Directory not empty"
            fs.remove_directory(path)
        return ""

    def _cmd_cp(self, parts: list, state: SessionState, fs: VirtualFilesystem) -> str:
        args = [p for p in parts[1:] if not p.startswith("-")]
        if len(args) < 2:
            return "cp: missing file operand"
        src_path = self._resolve_target_path(args[0], state)
        dst_path = self._resolve_target_path(args[1], state)
        content = fs.read_file(src_path)
        if content is None:
            return f"cp: cannot stat '{args[0]}': No such file or directory"
        if fs.is_directory(dst_path):
            dst_path = f"{dst_path}/{os.path.basename(src_path)}"
        fs.create_file(dst_path, content, owner=state.username)
        return ""

    def _cmd_mv(self, parts: list, state: SessionState, fs: VirtualFilesystem) -> str:
        args = [p for p in parts[1:] if not p.startswith("-")]
        if len(args) < 2:
            return "mv: missing file operand"
        src_path = self._resolve_target_path(args[0], state)
        dst_path = self._resolve_target_path(args[1], state)
        content = fs.read_file(src_path)
        if content is None and not fs.is_directory(src_path):
            return f"mv: cannot stat '{args[0]}': No such file or directory"
        if content is not None:
            if fs.is_directory(dst_path):
                dst_path = f"{dst_path}/{os.path.basename(src_path)}"
            fs.create_file(dst_path, content, owner=state.username)
            fs.remove_file(src_path)
        return ""

    def _cmd_chmod(self, parts: list, state: SessionState, fs: VirtualFilesystem) -> str:
        args = [p for p in parts[1:] if not p.startswith("-")]
        if len(args) < 2:
            return "chmod: missing operand"
        mode = args[0]
        for target in args[1:]:
            path = self._resolve_target_path(target, state)
            node = fs.get_node(path)
            if node is None:
                return f"chmod: cannot access '{target}': No such file or directory"
            if state.uid != 0 and node.owner != state.username:
                return f"chmod: changing permissions of '{target}': Operation not permitted"
            if not fs.chmod(path, mode):
                return f"chmod: cannot access '{target}': No such file or directory"
        return ""

    def _cmd_chown(self, parts: list, state: SessionState, fs: VirtualFilesystem) -> str:
        if state.uid != 0:
            return "chown: changing ownership: Operation not permitted"
        args = [p for p in parts[1:] if not p.startswith("-")]
        if len(args) < 2:
            return "chown: missing operand"
        owner_spec = args[0]
        owner = owner_spec.split(":")[0] if ":" in owner_spec else owner_spec
        group = owner_spec.split(":")[1] if ":" in owner_spec else None
        for target in args[1:]:
            path = self._resolve_target_path(target, state)
            if not fs.chown(path, owner, group):
                return f"chown: cannot access '{target}': No such file or directory"
        return ""

    def _cmd_find(self, parts: list, state: SessionState, fs: VirtualFilesystem) -> str:
        # Basic find stub — look for -name or -perm patterns
        search_dir = state.cwd
        name_pattern = None
        type_filter = None

        i = 1
        while i < len(parts):
            p = parts[i]
            if not p.startswith("-") and i == 1:
                search_dir = self._resolve_target_path(p, state)
            elif p == "-name" and i + 1 < len(parts):
                name_pattern = parts[i + 1].strip("'\"")
                i += 1
            elif p == "-perm" and i + 1 < len(parts):
                # perm_pattern parsed but not yet used in filtering
                i += 1
            elif p == "-type" and i + 1 < len(parts):
                type_filter = parts[i + 1]
                i += 1
            i += 1

        results = []
        self._find_recursive(fs, search_dir, name_pattern, type_filter, results, depth=0, max_depth=5)
        return "\n".join(results[:100])  # Cap output

    def _find_recursive(self, fs, path, name_pattern, type_filter, results, depth, max_depth):
        if depth > max_depth:
            return
        node = fs.get_node(path)
        if node is None:
            return

        # Check current node
        matches = True
        if name_pattern:
            matches = fnmatch.fnmatch(node.name, name_pattern)
        if type_filter:
            if type_filter == "d" and not node.is_dir:
                matches = False
            elif type_filter == "f" and node.is_dir:
                matches = False

        if matches and depth > 0:  # Don't include the search root
            results.append(node.path)

        if node.is_dir:
            for child in node.children.values():
                self._find_recursive(fs, child.path, name_pattern, type_filter, results, depth + 1, max_depth)

    def _cmd_grep(self, parts: list, state: SessionState, fs: VirtualFilesystem) -> str:
        if len(parts) < 3:
            return "Usage: grep [OPTION]... PATTERN [FILE]..."
        flags = [p for p in parts[1:] if p.startswith("-")]
        args = [p for p in parts[1:] if not p.startswith("-")]
        if len(args) < 2:
            return ""
        pattern = args[0].strip("'\"")
        if len(pattern) > 200:
            return "grep: pattern too long"
        target = self._resolve_target_path(args[1], state)
        content = fs.read_file(target)
        if content is None:
            return f"grep: {args[1]}: No such file or directory"
        nocase = any("-i" in f for f in flags)
        invert = any("-v" in f for f in flags)
        flag = re.IGNORECASE if nocase else 0
        try:
            compiled = re.compile(pattern, flag)
        except re.error:
            return f"grep: Invalid regular expression: '{pattern}'"
        matched = []
        for line in content.split("\n"):
            found = bool(compiled.search(line))
            if found != invert:
                matched.append(line)
        return "\n".join(matched)

    def _cmd_wc(self, parts: list, state: SessionState, fs: VirtualFilesystem) -> str:
        if len(parts) < 2:
            return ""
        target = parts[-1]
        if target.startswith("-"):
            return ""
        path = self._resolve_target_path(target, state)
        content = fs.read_file(path)
        if content is None:
            return f"wc: {target}: No such file or directory"
        lines = content.count("\n")
        words = len(content.split())
        chars = len(content)
        all_flags = "".join(parts[1:-1])
        if "-l" in all_flags:
            return f"{lines} {target}"
        if "-w" in all_flags:
            return f"{words} {target}"
        return f"  {lines}  {words} {chars} {target}"

    def _cmd_file(self, parts: list, state: SessionState, fs: VirtualFilesystem) -> str:
        if len(parts) < 2:
            return "Usage: file [-bchiklLNnprsvzZ0] [--apple] [--mime-encoding] [--mime-type] [-e testname] [-F separator] [-f namefile] [-m magicfiles] file ..."
        target = parts[-1]
        path = self._resolve_target_path(target, state)
        if fs.is_directory(path):
            return f"{target}: directory"
        node = fs.get_node(path)
        if node is None:
            return f"{target}: cannot open (No such file or directory)"
        content = node.content or ""
        if not content:
            return f"{target}: empty"
        if content.startswith("#!"):
            return f"{target}: script, ASCII text executable"
        return f"{target}: ASCII text"

    def _cmd_stat(self, parts: list, state: SessionState, fs: VirtualFilesystem) -> str:
        if len(parts) < 2:
            return "stat: missing operand"
        target = parts[-1]
        path = self._resolve_target_path(target, state)
        node = fs.get_node(path)
        if node is None:
            return f"stat: cannot stat '{target}': No such file or directory"
        ftype = "directory" if node.is_dir else "regular file"
        return (
            f"  File: {node.name}\n"
            f"  Size: {node.size:<14}Blocks: {node.size // 512:<11}"
            f"IO Block: 4096   {ftype}\n"
            f"Access: ({node.permissions}/{('d' if node.is_dir else '-')}"
            f"{self._perm_str(node.permissions)})  "
            f"Uid: ({node.owner})   Gid: ({node.group})\n"
            f"Modify: {node.modified}"
        )

    @staticmethod
    def _perm_str(octal: str) -> str:
        r = ""
        for d in octal[-3:]:
            n = int(d)
            r += "r" if n & 4 else "-"
            r += "w" if n & 2 else "-"
            r += "x" if n & 1 else "-"
        return r

    def _cmd_du(self, parts: list, state: SessionState, fs: VirtualFilesystem) -> str:
        target = state.cwd
        args = [p for p in parts[1:] if not p.startswith("-")]
        if args:
            target = self._resolve_target_path(args[0], state)
        node = fs.get_node(target)
        if node is None:
            return f"du: cannot access '{args[0] if args else '.'}': No such file or directory"
        total = self._calc_size(node)
        human = "-h" in "".join(parts)
        if human:
            return f"{self._human_size(total)}\t{target}"
        return f"{total // 1024}\t{target}"

    def _calc_size(self, node) -> int:
        if not node.is_dir:
            return node.size
        total = 4096
        for child in node.children.values():
            total += self._calc_size(child)
        return total

    @staticmethod
    def _human_size(size: int) -> str:
        for unit in ("", "K", "M", "G"):
            if abs(size) < 1024:
                return f"{size}{unit}"
            size //= 1024
        return f"{size}T"

    # ── System Info Commands ─────────────────────────

    def _cmd_id(self, state: SessionState) -> str:
        gid = state.uid
        groups = f"{gid}({state.username})"
        if state.uid == 0:
            groups = "0(root)"
        return f"uid={state.uid}({state.username}) " f"gid={gid}({state.username}) " f"groups={groups}"

    def _cmd_uname(self, parts: list) -> str:
        hostname = self.config.hostname
        kernel = "5.15.0-91-generic"
        if len(parts) == 1:
            return "Linux"
        flags = "".join(parts[1:])
        if "a" in flags:
            return (
                f"Linux {hostname} {kernel} "
                "#101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 "
                "x86_64 x86_64 x86_64 GNU/Linux"
            )
        if "r" in flags:
            return kernel
        if "n" in flags:
            return hostname
        if "m" in flags:
            return "x86_64"
        if "s" in flags:
            return "Linux"
        if "v" in flags:
            return "#101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023"
        return "Linux"

    def _cmd_uptime(self, fs: VirtualFilesystem) -> str:
        profile = fs.get_profile_data()
        cached = profile.get("uptime")
        if cached:
            return cached
        now = datetime.now().strftime("%H:%M:%S")
        days = random.randint(5, 90)
        hours = random.randint(0, 23)
        mins = random.randint(0, 59)
        return f" {now} up {days} days, {hours}:{mins:02d},  " f"1 user,  load average: 0.08, 0.04, 0.01"

    def _cmd_w(self, state: SessionState, fs: VirtualFilesystem) -> str:
        uptime_str = self._cmd_uptime(fs).strip()
        login_time = (datetime.now() - timedelta(minutes=random.randint(1, 120))).strftime("%H:%M")
        return (
            f" {uptime_str}\n"
            f"USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n"
            f"{state.username:<8} pts/0    "
            f"{random.randint(10,192)}.{random.randint(0,255)}."
            f"{random.randint(0,255)}.{random.randint(1,254):<15} "
            f"{login_time}    0.00s  0.04s  0.00s w"
        )

    def _cmd_who(self, state: SessionState) -> str:
        login_time = datetime.now().strftime("%Y-%m-%d %H:%M")
        return (
            f"{state.username:<12} pts/0        {login_time} "
            f"({random.randint(10,192)}.{random.randint(0,255)}."
            f"{random.randint(0,255)}.{random.randint(1,254)})"
        )

    def _cmd_last(self, state: SessionState) -> str:
        lines = []
        now = datetime.now()
        for i in range(8):
            dt = now - timedelta(days=i, hours=random.randint(0, 12))
            ip = f"{random.randint(10,192)}.{random.randint(0,255)}." f"{random.randint(0,255)}.{random.randint(1,254)}"
            day = dt.strftime("%a %b %d")
            time_str = dt.strftime("%H:%M")
            duration = f"{random.randint(0,4):02d}:{random.randint(0,59):02d}"
            user = state.username if i < 3 else random.choice(["root", state.username])
            lines.append(
                f"{user:<10} pts/{i:<3} {ip:<16} {day} {time_str}   " f"still logged in"
                if i == 0
                else f"{user:<10} pts/{i:<3} {ip:<16} {day} {time_str} - "
                f"{(dt + timedelta(minutes=random.randint(5,300))).strftime('%H:%M')}  "
                f"({duration})"
            )
        lines.append("")
        lines.append("wtmp begins Mon Jan  1 00:00:01 2024")
        return "\n".join(lines)

    def _cmd_ps(self, command: str, fs: VirtualFilesystem) -> str:
        return self._render_ps(command, fs.get_profile_data())

    def _render_ps(self, command: str, profile: dict) -> str:
        procs = profile.get(
            "processes",
            [
                {"pid": 1, "command": "/sbin/init", "user": "root"},
                {"pid": 452, "command": "/usr/sbin/sshd -D", "user": "root"},
            ],
        )
        if "aux" in command or "-ef" in command:
            lines = [
                f"{'USER':<12}{'PID':>6} {'%CPU':>5} {'%MEM':>5} "
                f"{'VSZ':>8} {'RSS':>6} {'TTY':<8}{'STAT':<5}"
                f"{'START':>6} {'TIME':>5}  {'COMMAND'}"
            ]
            for p in procs:
                vsz = random.randint(2000, 500000)
                rss = random.randint(500, vsz // 2)
                lines.append(
                    f"{p['user']:<12}{p['pid']:>6} {'0.0':>5} {'0.1':>5} "
                    f"{vsz:>8} {rss:>6} {'?':<8}{'Ss':<5}"
                    f"{'Jan01':>6} {'0:02':>5}  {p['command']}"
                )
            return "\n".join(lines)
        else:
            lines = [f"  {'PID':>5} {'TTY':<8} {'TIME':>8} {'CMD'}"]
            lines.append(f"  {os.getpid():>5} {'pts/0':<8} {'00:00:00':>8} -bash")
            return "\n".join(lines)

    def _cmd_top(self, state: SessionState, fs: VirtualFilesystem) -> str:
        # Return a single snapshot (non-interactive)
        uptime = self._cmd_uptime(fs).strip()
        return (
            f"top - {uptime}\n"
            f"Tasks:  87 total,   1 running,  86 sleeping,   0 stopped,   0 zombie\n"
            f"%Cpu(s):  1.2 us,  0.5 sy,  0.0 ni, 98.1 id,  0.1 wa,  0.0 hi,  0.1 si\n"
            f"MiB Mem :   7976.0 total,   3241.5 free,   1247.8 used,   3486.7 buff/cache\n"
            f"MiB Swap:   2048.0 total,   2048.0 free,      0.0 used.   6412.3 avail Mem\n"
            f"\n"
            f"  {'PID':>5} {'USER':<10}{'PR':>3} {'NI':>3} {'VIRT':>8} {'RES':>6} "
            f"{'SHR':>6} {'S':>1} {'%CPU':>5} {'%MEM':>5} {'TIME+':>9} COMMAND\n"
            f"      1 root       20   0   168k  12.2m   8.4m S   0.0   0.2   0:01.23 systemd\n"
            f"    452 root       20   0    15m   5.2m   4.8m S   0.0   0.1   0:00.45 sshd"
        )

    def _cmd_free(self, command: str, fs: VirtualFilesystem) -> str:
        profile = fs.get_profile_data()
        cached = profile.get("memory")
        if cached:
            return cached
        total = 7976
        used = random.randint(800, 2000)
        buff = random.randint(2000, 4000)
        free = total - used - buff
        return (
            f"               total        used        free      shared  buff/cache   available\n"
            f"Mem:          {total}Mi      {used}Mi      {free}Mi       12Mi      {buff}Mi      {total - used - 200}Mi\n"
            f"Swap:         2048Mi         0Mi      2048Mi"
        )

    def _cmd_df(self, command: str, fs: VirtualFilesystem) -> str:
        profile = fs.get_profile_data()
        cached = profile.get("disk")
        if cached:
            return cached
        used_pct = random.randint(15, 55)
        total_g = 50
        used_g = int(total_g * used_pct / 100)
        avail_g = total_g - used_g
        return (
            f"Filesystem      Size  Used Avail Use% Mounted on\n"
            f"udev            3.9G     0  3.9G   0% /dev\n"
            f"tmpfs           798M  1.2M  797M   1% /run\n"
            f"/dev/sda1        {total_g}G   {used_g}G   {avail_g}G  {used_pct}% /\n"
            f"tmpfs           3.9G     0  3.9G   0% /dev/shm\n"
            f"tmpfs           5.0M     0  5.0M   0% /run/lock\n"
            f"/dev/sda15      105M  5.2M  100M   5% /boot/efi"
        )

    def _cmd_mount(self) -> str:
        return (
            "/dev/sda1 on / type ext4 (rw,relatime,errors=remount-ro)\n"
            "sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime)\n"
            "proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)\n"
            "udev on /dev type devtmpfs (rw,nosuid,relatime,size=4016012k)\n"
            "tmpfs on /run type tmpfs (rw,nosuid,nodev,noexec,relatime,size=817168k)\n"
            "tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev)"
        )

    def _cmd_lsblk(self) -> str:
        return (
            "NAME   MAJ:MIN RM  SIZE RO TYPE MOUNTPOINTS\n"
            "sda      8:0    0   50G  0 disk \n"
            "├─sda1   8:1    0 49.9G  0 part /\n"
            "├─sda14  8:14   0    4M  0 part \n"
            "└─sda15  8:15   0  106M  0 part /boot/efi"
        )

    def _cmd_dmesg(self) -> str:
        return (
            "[    0.000000] Linux version 5.15.0-91-generic "
            "(buildd@lcy02-amd64-032) (gcc-11 (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0)\n"
            "[    0.000000] Command line: BOOT_IMAGE=/vmlinuz-5.15.0-91-generic "
            "root=UUID=a1b2c3d4-e5f6-7890-abcd-ef1234567890 ro quiet splash\n"
            "[    0.000000] BIOS-provided physical RAM map:\n"
            "[    0.000000]  BIOS-e820: [mem 0x0000000000000000-0x000000000009fbff] usable\n"
            "[    0.000000] NX (Execute Disable) protection: active\n"
            "[    0.000000] DMI: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.16.0-debian 04/01/2014\n"
            "[    0.000000] Hypervisor detected: KVM\n"
            "[    0.004321] x86/fpu: x87 FPU on chip\n"
            "[    0.004321] x86/fpu: Supporting XSAVE feature 0x001: 'x87 floating point registers'\n"
            "[    0.021987] Calibrating delay loop (skipped), value calculated using timer frequency.. 5999.99 BogoMIPS\n"
            "[    0.043210] pid_max: default: 32768 minimum: 301\n"
            "[    0.098765] Booting paravirtualized kernel on KVM\n"
            "[    0.143210] clocksource: kvm-clock: mask: 0xffffffffffffffff\n"
            "[    0.216842] ACPI: Core revision 20210730\n"
            "[    0.312456] PCI: Using configuration type 1 for base access\n"
            "[    0.456789] clocksource: tsc: mask: 0xffffffffffffffff\n"
            "[    0.567890] Memory: 8119232K/8388096K available\n"
            "[    0.678901] DMAR: No ATSR found\n"
            "[    0.789012] Initialise system trusted keyrings\n"
            "[    0.987654] NET: Registered PF_NETLINK/PF_ROUTE protocol family\n"
            "[    1.023456] PCI: Probing PCI hardware\n"
            "[    1.103526] EXT4-fs (sda1): mounted filesystem with ordered data mode. Opts: (null). Quota mode: none.\n"
            "[    1.234567] systemd[1]: Detected virtualization kvm.\n"
            "[    1.345678] systemd[1]: Set hostname to <dev-ws-03>.\n"
            "[    1.567890] systemd[1]: Reached target Swap.\n"
            "[    1.678901] systemd[1]: Reached target Local File Systems.\n"
            "[    1.890123] e1000 0000:00:03.0 eth0: (PCI:33MHz:32-bit) 02:42:ac:11:00:02\n"
            "[    1.901234] e1000 0000:00:03.0 eth0: Intel(R) PRO/1000 Network Connection\n"
            "[    2.012345] IPv6: ADDRCONF(NETDEV_CHANGE): eth0: link becomes ready\n"
            "[    2.123456] EXT4-fs (sda1): re-mounted. Opts: errors=remount-ro. Quota mode: none.\n"
            '[    2.345678] audit: type=1400 audit(1234567890.123:2): apparmor="STATUS" operation="profile_load" profile="/usr/sbin/sshd"\n'
            "[    2.567890] systemd[1]: Started OpenBSD Secure Shell server.\n"
            "[    2.678901] systemd[1]: Reached target Multi-User System.\n"
            "[    2.789012] systemd[1]: Startup finished in 1.234s (kernel) + 1.567s (userspace) = 2.801s."
        )

    def _cmd_lscpu(self) -> str:
        return (
            "Architecture:                    x86_64\n"
            "CPU op-mode(s):                  32-bit, 64-bit\n"
            "Byte Order:                      Little Endian\n"
            "CPU(s):                          4\n"
            "On-line CPU(s) list:             0-3\n"
            "Thread(s) per core:              1\n"
            "Core(s) per socket:              4\n"
            "Socket(s):                       1\n"
            "Vendor ID:                       GenuineIntel\n"
            "CPU family:                      6\n"
            "Model name:                      Intel(R) Xeon(R) Platinum 8275CL CPU @ 3.00GHz\n"
            "CPU MHz:                         2999.998\n"
            "L1d cache:                       128 KiB\n"
            "L1i cache:                       128 KiB\n"
            "L2 cache:                        4 MiB\n"
            "L3 cache:                        35.8 MiB"
        )

    def _cmd_cal(self) -> str:
        now = datetime.now()
        return f"   {now.strftime('%B %Y')}\nSu Mo Tu We Th Fr Sa\n (use `cal` on a real system)"

    # ── Network Commands ─────────────────────────────

    def _cmd_ifconfig(self, fs: VirtualFilesystem) -> str:
        profile = fs.get_profile_data()
        ifaces = profile.get("interfaces", [])
        if not ifaces:
            ip = f"10.0.{random.randint(0,255)}.{random.randint(2,254)}"
            return (
                f"eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
                f"        inet {ip}  netmask 255.255.255.0  broadcast 10.0.0.255\n"
                f"        inet6 fe80::d0:f1ff:fe9a:c{random.randint(100,999)}  prefixlen 64  scopeid 0x20<link>\n"
                f"        ether 02:42:ac:11:00:02  txqueuelen 0  (Ethernet)\n"
                f"        RX packets {random.randint(10000,500000)}  bytes {random.randint(1000000,90000000)}\n"
                f"        TX packets {random.randint(10000,500000)}  bytes {random.randint(1000000,90000000)}\n"
                f"\n"
                f"lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n"
                f"        inet 127.0.0.1  netmask 255.0.0.0\n"
                f"        inet6 ::1  prefixlen 128  scopeid 0x10<host>\n"
                f"        loop  txqueuelen 1000  (Local Loopback)"
            )
        # Use profile interfaces
        result = []
        for iface in ifaces:
            result.append(
                f"{iface.get('name', 'eth0')}: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
                f"        inet {iface.get('ip', '10.0.0.2')}  "
                f"netmask {iface.get('netmask', '255.255.255.0')}  "
                f"broadcast {iface.get('broadcast', '10.0.0.255')}"
            )
        return "\n\n".join(result)

    def _cmd_ip(self, parts: list, fs: VirtualFilesystem) -> str:
        if len(parts) < 2:
            return "Usage: ip [ OPTIONS ] OBJECT { COMMAND | help }"
        subcmd = parts[1]
        if subcmd in ("addr", "address", "a"):
            ip = f"10.0.{random.randint(0,255)}.{random.randint(2,254)}"
            return (
                f"1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n"
                f"    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n"
                f"    inet 127.0.0.1/8 scope host lo\n"
                f"2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000\n"
                f"    link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff\n"
                f"    inet {ip}/24 brd 10.0.0.255 scope global eth0"
            )
        elif subcmd in ("route", "r"):
            return self._cmd_route()
        elif subcmd == "link":
            return (
                "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT\n"
                "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n"
                "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT\n"
                "    link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff"
            )
        elif subcmd == "neigh":
            gw = "10.0.0.1"
            return f"{gw} dev eth0 lladdr 02:42:d8:09:c1:01 REACHABLE"
        return "Object not recognized"

    def _cmd_netstat(self, parts: list) -> str:
        if "-tlnp" in " ".join(parts) or ("-t" in parts and "-l" in parts):
            return (
                "Active Internet connections (only servers)\n"
                "Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name\n"
                "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      452/sshd\n"
                "tcp6       0      0 :::22                   :::*                    LISTEN      452/sshd"
            )
        return (
            "Active Internet connections (w/o servers)\n"
            "Proto Recv-Q Send-Q Local Address           Foreign Address         State\n"
            "tcp        0      0 10.0.0.2:22             10.0.0.1:49832          ESTABLISHED"
        )

    def _cmd_ss(self, parts: list) -> str:
        if "-tlnp" in " ".join(parts) or ("-t" in parts and "-l" in parts):
            return (
                "State   Recv-Q  Send-Q  Local Address:Port  Peer Address:Port  Process\n"
                'LISTEN  0       128     0.0.0.0:22          0.0.0.0:*          users:(("sshd",pid=452,fd=3))\n'
                'LISTEN  0       128     [::]:22             [::]:*             users:(("sshd",pid=452,fd=4))'
            )
        return (
            "State   Recv-Q  Send-Q  Local Address:Port  Peer Address:Port\n"
            "ESTAB   0       0       10.0.0.2:22         10.0.0.1:49832"
        )

    def _cmd_ping(self, parts: list) -> str:
        if len(parts) < 2:
            return "ping: usage error: Destination address required"
        host = parts[-1]
        ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        rtt = random.uniform(0.5, 45.0)
        return (
            f"PING {host} ({ip}) 56(84) bytes of data.\n"
            f"64 bytes from {ip}: icmp_seq=1 ttl=64 time={rtt:.1f} ms\n"
            f"64 bytes from {ip}: icmp_seq=2 ttl=64 time={rtt + random.uniform(-2,2):.1f} ms\n"
            f"64 bytes from {ip}: icmp_seq=3 ttl=64 time={rtt + random.uniform(-2,2):.1f} ms\n"
            f"\n"
            f"--- {host} ping statistics ---\n"
            f"3 packets transmitted, 3 received, 0% packet loss, time 2003ms\n"
            f"rtt min/avg/max/mdev = {rtt-1:.3f}/{rtt:.3f}/{rtt+1:.3f}/0.543 ms"
        )

    def _cmd_curl(self, parts: list) -> str:
        if len(parts) < 2:
            return "curl: try 'curl --help' for more information"
        url = parts[-1]
        return f"curl: (7) Failed to connect to {url} port 443: Connection refused"

    def _cmd_wget(self, parts: list) -> str:
        if len(parts) < 2:
            return "wget: missing URL"
        url = parts[-1]
        return (
            f"--2024-01-15 12:00:00--  {url}\n"
            f"Resolving {url}... failed: Temporary failure in name resolution.\n"
            f"wget: unable to resolve host address '{url}'"
        )

    def _cmd_ssh(self, parts: list) -> str:
        return "ssh: connect to host: Connection timed out"

    def _cmd_scp(self, parts: list) -> str:
        return "ssh: connect to host: Connection timed out\nlost connection"

    def _cmd_nc(self, parts: list) -> str:
        if len(parts) < 3:
            return ""
        return f"(UNKNOWN) [{parts[-2]}] {parts[-1]} (?) : Connection refused"

    def _cmd_dig(self, parts: list) -> str:
        if len(parts) < 2:
            return ""
        host = parts[-1]
        qid = random.randint(10000, 65535)
        ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        return (
            f"; <<>> DiG 9.18.18-0ubuntu0.22.04.1-Ubuntu <<>> {host}\n"
            f";; global options: +cmd\n"
            f";; Got answer:\n"
            f";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: {qid}\n"
            f";; ANSWER SECTION:\n"
            f"{host}.\t\t300\tIN\tA\t{ip}\n"
            f"\n"
            f";; Query time: {random.randint(1,50)} msec\n"
            f";; SERVER: 10.0.0.2#53(10.0.0.2)\n"
            f";; WHEN: {datetime.now().strftime('%a %b %d %H:%M:%S %Z %Y')}"
        )

    def _cmd_nslookup(self, parts: list) -> str:
        if len(parts) < 2:
            return ""
        host = parts[-1]
        ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        return (
            f"Server:\t\t10.0.0.2\n"
            f"Address:\t10.0.0.2#53\n\n"
            f"Non-authoritative answer:\n"
            f"Name:\t{host}\nAddress: {ip}"
        )

    def _cmd_route(self) -> str:
        return (
            "Kernel IP routing table\n"
            "Destination     Gateway         Genmask         Flags Metric Ref    Use Iface\n"
            "default         10.0.0.1        0.0.0.0         UG    100    0        0 eth0\n"
            "10.0.0.0        0.0.0.0         255.255.255.0   U     100    0        0 eth0"
        )

    def _cmd_traceroute(self, parts: list) -> str:
        if len(parts) < 2:
            return "Usage: traceroute host"
        host = parts[-1]
        lines = [f"traceroute to {host}, 30 hops max, 60 byte packets"]
        for i in range(1, 4):
            ip = f"10.{i}.0.1"
            t = random.uniform(0.5, 5.0)
            lines.append(f" {i}  {ip}  {t:.3f} ms  {t+0.1:.3f} ms  {t+0.2:.3f} ms")
        lines.append(" 4  * * *")
        return "\n".join(lines)

    def _cmd_arp(self) -> str:
        return (
            "Address                  HWtype  HWaddress           Flags Mask            Iface\n"
            "10.0.0.1                 ether   02:42:d8:09:c1:01   C                     eth0"
        )

    # ── Package / Service Commands ───────────────────

    def _cmd_apt(self, parts: list) -> str:
        if len(parts) < 2:
            return "usage: apt [options] command"
        sub = parts[1]
        if sub == "list":
            if "--installed" in parts:
                return (
                    "Listing...\n"
                    "adduser/jammy,now 3.118ubuntu5 all [installed]\n"
                    "apt/jammy-updates,now 2.4.11 amd64 [installed]\n"
                    "base-files/jammy-updates,now 12ubuntu4.4 amd64 [installed]\n"
                    "bash/jammy,now 5.1-6ubuntu1 amd64 [installed]\n"
                    "build-essential/jammy,now 12.9ubuntu3 amd64 [installed]\n"
                    "ca-certificates/jammy-updates,now 20230311ubuntu0.22.04.1 all [installed]\n"
                    "coreutils/jammy,now 8.32-4.1ubuntu1 amd64 [installed]\n"
                    "curl/jammy-updates,now 7.81.0-1ubuntu1.15 amd64 [installed]\n"
                    "docker-ce/jammy,now 5:24.0.7-1~ubuntu.22.04~jammy amd64 [installed]\n"
                    "git/jammy-updates,now 1:2.34.1-1ubuntu1.10 amd64 [installed]\n"
                    "openssh-server/jammy-updates,now 1:8.9p1-3ubuntu0.6 amd64 [installed]\n"
                    "python3/jammy,now 3.10.6-1~22.04 amd64 [installed]\n"
                    "sudo/jammy-updates,now 1.9.9-1ubuntu2.4 amd64 [installed]\n"
                    "vim/jammy-updates,now 2:8.2.3995-1ubuntu2.15 amd64 [installed]\n"
                    "wget/jammy-updates,now 1.21.2-2ubuntu1.1 amd64 [installed]"
                )
            return ""
        if sub in ("install", "remove", "purge"):
            return "E: Could not open lock file /var/lib/dpkg/lock-frontend - open (13: Permission denied)"
        if sub == "update":
            return "Reading package lists... Done\nE: Could not open lock file /var/lib/apt/lists/lock - open (13: Permission denied)"
        if sub == "search" and len(parts) > 2:
            return "Sorting... Done\nFull Text Search... Done"
        if sub == "show" and len(parts) > 2:
            return f"Package: {parts[2]}\nVersion: 1.0\nDescription: No description available"
        return ""

    def _cmd_dpkg(self, parts: list) -> str:
        if "-l" in parts:
            return (
                "Desired=Unknown/Install/Remove/Purge/Hold\n"
                "| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend\n"
                "||/ Name           Version      Architecture Description\n"
                "ii  adduser        3.118ubuntu5 all          add and remove users and groups\n"
                "ii  apt            2.4.11       amd64        commandline package manager\n"
                "ii  base-files     12ubuntu4.4  amd64        Debian base system miscellaneous files\n"
                "ii  bash           5.1-6ubuntu1 amd64        GNU Bourne Again SHell\n"
                "ii  coreutils      8.32-4.1ubun amd64        GNU core utilities\n"
                "ii  openssh-server 1:8.9p1-3ubu amd64        secure shell (SSH) server"
            )
        return ""

    def _cmd_pip(self, parts: list) -> str:
        if len(parts) < 2:
            return "Usage: pip <command> [options]"
        if parts[1] == "list":
            return (
                "Package    Version\n"
                "---------- -------\n"
                "pip        22.0.2\n"
                "setuptools 59.6.0\n"
                "wheel      0.37.1"
            )
        if parts[1] == "install":
            return (
                "WARNING: pip is configured with locations that require TLS/SSL, "
                "however the ssl module in Python is not available."
            )
        return ""

    def _cmd_systemctl(self, parts: list) -> str:
        if len(parts) < 2:
            return "Missing command."
        sub = parts[1]
        if sub == "status" and len(parts) > 2:
            svc = parts[2].replace(".service", "")
            pid = random.randint(400, 9999)
            return (
                f"● {svc}.service - {svc.title()} Service\n"
                f"     Loaded: loaded (/lib/systemd/system/{svc}.service; enabled; vendor preset: enabled)\n"
                f"     Active: active (running) since Mon 2024-01-01 00:00:00 UTC; 14 days ago\n"
                f"   Main PID: {pid} ({svc})\n"
                f"      Tasks: 1 (limit: 4586)\n"
                f"     Memory: 5.2M\n"
                f"        CPU: 1.234s\n"
                f"     CGroup: /system.slice/{svc}.service\n"
                f"             └─{pid} /usr/sbin/{svc}"
            )
        if sub == "list-units":
            return (
                "UNIT                       LOAD   ACTIVE SUB     DESCRIPTION\n"
                "cron.service               loaded active running Regular background program processing daemon\n"
                "dbus.service               loaded active running D-Bus System Message Bus\n"
                "ssh.service                loaded active running OpenBSD Secure Shell server\n"
                "systemd-journald.service   loaded active running Journal Service\n"
                "systemd-logind.service     loaded active running User Login Management"
            )
        if sub in ("start", "stop", "restart", "enable", "disable"):
            if len(parts) < 3:
                return "Too few arguments."
            return ""
        return ""

    def _cmd_service(self, parts: list) -> str:
        if len(parts) < 2:
            return "Usage: service <service> <action>"
        if parts[1] == "--status-all":
            return (
                " [ + ]  apparmor\n"
                " [ + ]  cron\n"
                " [ - ]  dbus\n"
                " [ + ]  kmod\n"
                " [ - ]  procps\n"
                " [ + ]  rsyslog\n"
                " [ + ]  ssh\n"
                " [ + ]  udev\n"
                " [ - ]  ufw"
            )
        svc = parts[1]
        action = parts[-1] if len(parts) > 2 else ""
        if action == "status":
            known_running = {"ssh", "sshd", "cron", "rsyslog", "apparmor", "udev", "nginx", "apache2"}
            if svc in known_running:
                return f" * {svc} is running"
            return f" * {svc} is not running"
        if action in ("start", "stop", "restart"):
            return ""  # Silent success (like real service command)
        return f"Usage: service {svc} {{start|stop|restart|status}}"

    def _cmd_crontab(self, parts: list, state: SessionState) -> str:
        if "-l" in parts:
            if state.username == "root" or state.uid == 0:
                return (
                    "# m h  dom mon dow   command\n"
                    "0 2 * * * /usr/local/bin/backup.sh >> /var/log/backup.log 2>&1\n"
                    "*/5 * * * * /usr/bin/python3 /opt/monitoring/health_check.py\n"
                    "0 0 * * 0 /usr/bin/certbot renew --quiet"
                )
            return f"no crontab for {state.username}"
        if "-e" in parts:
            return "no changes made to crontab"
        if "-r" in parts:
            return ""
        return "crontab: usage error: unrecognized option"

    def _cmd_journalctl(self, parts: list) -> str:
        """Simulate journalctl output with realistic systemd log entries."""
        import random
        from datetime import datetime, timedelta

        lines = []
        now = datetime.now()
        host = self._config.hostname

        entries = [
            ("systemd[1]", "Started SSH Key Generation."),
            ("systemd[1]", "Reached target Multi-User System."),
            ("systemd[1]", "Started OpenBSD Secure Shell server."),
            ("sshd[{pid}]", "Server listening on 0.0.0.0 port 22."),
            ("sshd[{pid}]", "Server listening on :: port 22."),
            ("systemd-logind[{pid}]", "New session {sess} of user {user}."),
            ("systemd-logind[{pid}]", "Session {sess} logged out. Waiting for processes to exit."),
            (
                "systemd-timesyncd[{pid}]",
                "Synchronized to time server for the first time 91.189.89.198:123 (ntp.ubuntu.com).",
            ),
            ("systemd-resolved[{pid}]", "Using DNS server 10.0.0.2 for transaction on link eth0."),
            ("kernel", "Linux version 5.15.0-91-generic (buildd@lcy02-amd64-032)"),
            (
                "kernel",
                "[UFW BLOCK] IN=eth0 OUT= MAC=02:42:ac:11:00:02 SRC={ip} DST=10.0.0.2 PROTO=TCP SPT={sp} DPT={dp}",
            ),
            ("CRON[{pid}]", "(root) CMD (test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily ))"),
            ("systemd[1]", "Starting Daily apt download activities..."),
            ("systemd[1]", "Finished Daily apt download activities."),
            ("systemd[1]", "Starting Cleanup of Temporary Directories..."),
            ("systemd[1]", "Finished Cleanup of Temporary Directories."),
            ("sudo", "  admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/usr/bin/apt update"),
            ("apt-daily[{pid}]", "Processing triggers for man-db (2.10.2-1)..."),
        ]

        # Generate ~40 log lines
        for _i in range(40):
            dt = now - timedelta(
                hours=random.randint(0, 72), minutes=random.randint(0, 59), seconds=random.randint(0, 59)
            )
            ts = dt.strftime("%b %d %H:%M:%S")
            svc, msg = random.choice(entries)
            pid = random.randint(200, 9999)
            sess = random.randint(1, 200)
            user = random.choice(["root", "admin", "deploy"])
            ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            svc = svc.format(pid=pid)
            msg = msg.format(
                pid=pid,
                sess=sess,
                user=user,
                ip=ip,
                sp=random.randint(1024, 65535),
                dp=random.choice([22, 80, 443, 3306]),
            )
            lines.append(f"{ts} {host} {svc}: {msg}")

        lines.sort()

        # Filter by unit if -u flag is specified
        if "-u" in parts:
            idx = parts.index("-u")
            if idx + 1 < len(parts):
                unit = parts[idx + 1].replace(".service", "")
                lines = [line for line in lines if unit in line.lower()]

        # Handle --since flag (just return last N lines)
        if "--since" in parts:
            lines = lines[-15:]

        # Handle -n flag
        if "-n" in parts:
            idx = parts.index("-n")
            if idx + 1 < len(parts):
                try:
                    n = int(parts[idx + 1])
                    lines = lines[-n:]
                except ValueError:
                    pass

        if not lines:
            return "-- No entries --"

        return "\n".join(lines)

    # ── Security Commands ────────────────────────────

    def _cmd_su(self, parts: list, state: SessionState) -> str:
        return "su: Authentication failure"

    def _cmd_iptables(self, parts: list, state: SessionState) -> str:
        if state.uid != 0:
            return "iptables: Permission denied (you must be root)."
        if "-L" in parts:
            return (
                "Chain INPUT (policy ACCEPT)\n"
                "target     prot opt source               destination\n\n"
                "Chain FORWARD (policy DROP)\n"
                "target     prot opt source               destination\n\n"
                "Chain OUTPUT (policy ACCEPT)\n"
                "target     prot opt source               destination"
            )
        return ""

    def _cmd_aa_status(self) -> str:
        return (
            "apparmor module is loaded.\n"
            "5 profiles are loaded.\n"
            "5 profiles are in enforce mode.\n"
            "0 profiles are in complain mode.\n"
            "0 processes are in enforce mode.\n"
            "0 processes are in complain mode.\n"
            "0 processes are unconfined."
        )

    def _cmd_getent(self, parts: list, fs: VirtualFilesystem) -> str:
        if len(parts) < 3:
            return "Usage: getent database [key ...]"
        db = parts[1]
        key = parts[2]
        if db == "passwd":
            content = fs.read_file("/etc/passwd") or ""
            for line in content.split("\n"):
                if line.startswith(f"{key}:"):
                    return line
            return ""
        if db == "group":
            content = fs.read_file("/etc/group") or ""
            for line in content.split("\n"):
                if line.startswith(f"{key}:"):
                    return line
            return ""
        return ""

    # ── Misc Commands ────────────────────────────────

    def _cmd_which(self, parts: list) -> str:
        if len(parts) < 2:
            return ""
        target = parts[1]
        known = {
            "bash": "/usr/bin/bash",
            "sh": "/bin/sh",
            "python3": "/usr/bin/python3",
            "python": "/usr/bin/python3",
            "perl": "/usr/bin/perl",
            "ruby": "/usr/bin/ruby",
            "git": "/usr/bin/git",
            "curl": "/usr/bin/curl",
            "wget": "/usr/bin/wget",
            "ssh": "/usr/bin/ssh",
            "scp": "/usr/bin/scp",
            "vim": "/usr/bin/vim",
            "nano": "/usr/bin/nano",
            "less": "/usr/bin/less",
            "grep": "/usr/bin/grep",
            "find": "/usr/bin/find",
            "awk": "/usr/bin/awk",
            "sed": "/usr/bin/sed",
            "ls": "/usr/bin/ls",
            "cat": "/usr/bin/cat",
            "ps": "/usr/bin/ps",
            "top": "/usr/bin/top",
            "kill": "/usr/bin/kill",
            "tar": "/usr/bin/tar",
            "gzip": "/usr/bin/gzip",
            "chmod": "/usr/bin/chmod",
            "chown": "/usr/bin/chown",
            "cp": "/usr/bin/cp",
            "mv": "/usr/bin/mv",
            "rm": "/usr/bin/rm",
            "mkdir": "/usr/bin/mkdir",
            "touch": "/usr/bin/touch",
            "df": "/usr/bin/df",
            "du": "/usr/bin/du",
            "free": "/usr/bin/free",
            "mount": "/usr/bin/mount",
            "uname": "/usr/bin/uname",
            "hostname": "/usr/bin/hostname",
            "ifconfig": "/usr/sbin/ifconfig",
            "ip": "/usr/sbin/ip",
            "netstat": "/usr/bin/netstat",
            "ss": "/usr/sbin/ss",
            "systemctl": "/usr/bin/systemctl",
            "apt": "/usr/bin/apt",
            "dpkg": "/usr/bin/dpkg",
            "nc": "/usr/bin/nc",
            "kubectl": "/usr/local/bin/kubectl",
            "aws": "/usr/local/bin/aws",
            "node": "/usr/bin/node",
            "npm": "/usr/bin/npm",
            "go": "/usr/local/go/bin/go",
            "java": "/usr/bin/java",
            "nmap": "/usr/bin/nmap",
            "lsb_release": "/usr/bin/lsb_release",
            "hostnamectl": "/usr/bin/hostnamectl",
            "timedatectl": "/usr/bin/timedatectl",
            "snap": "/usr/bin/snap",
            "printenv": "/usr/bin/printenv",
            "strace": "/usr/bin/strace",
            "strings": "/usr/bin/strings",
            "xxd": "/usr/bin/xxd",
            "docker": "/usr/bin/docker",
            "make": "/usr/bin/make",
            "gcc": "/usr/bin/gcc",
            "seq": "/usr/bin/seq",
            "diff": "/usr/bin/diff",
            "time": "/usr/bin/time",
        }
        if target in known:
            return known[target]
        return f"{target} not found"

    def _cmd_whereis(self, parts: list) -> str:
        if len(parts) < 2:
            return ""
        target = parts[1]
        return f"{target}: /usr/bin/{target} /usr/share/man/man1/{target}.1.gz"

    def _cmd_python(self, parts: list) -> str:
        if len(parts) == 1:
            return (
                "Python 3.10.12 (main, Nov 20 2023, 15:14:05) "
                "[GCC 11.4.0] on linux\n"
                'Type "help", "copyright", "credits" or "license" for more information.\n'
                ">>> (interactive mode not supported)"
            )
        if parts[1] == "--version" or parts[1] == "-V":
            return "Python 3.10.12"
        if parts[1] == "-c" and len(parts) > 2:
            code = " ".join(parts[2:]).strip("'\"")
            if "import os" in code and "system" in code:
                return ""
            # Extract simple print() calls
            m = re.search(r"""print\s*\(\s*(['"])(.*?)\1\s*\)""", code)
            if m:
                return m.group(2)
            # Handle print with f-string or concatenation — just extract
            m = re.search(r"""print\s*\(\s*(.+?)\s*\)""", code)
            if m:
                inner = m.group(1).strip("'\"")
                return inner
            if "import" in code:
                return ""
            return ""
        if parts[1] == "-m" and len(parts) > 2:
            mod = parts[2]
            if mod == "http.server":
                return "Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ..."
            if mod == "json.tool":
                return ""
            return f"/usr/bin/python3: No module named {mod}"
        return ""

    def _cmd_perl(self, parts: list) -> str:
        if len(parts) == 1:
            return ""
        if parts[1] == "-v":
            return "This is perl 5, version 34, subversion 0 (v5.34.0) " "built for x86_64-linux-gnu-thread-multi"
        if parts[1] == "-e":
            return ""
        return ""

    def _cmd_git(self, parts: list) -> str:
        if len(parts) < 2:
            return "usage: git [--version] [--help] [-C <path>] <command> [<args>]"
        sub = parts[1]
        if sub == "--version":
            return "git version 2.34.1"
        if sub == "clone":
            return "fatal: could not create work tree dir: Permission denied"
        if sub in ("status", "log", "branch", "diff", "stash", "pull", "push", "fetch", "merge", "rebase", "checkout"):
            return "fatal: not a git repository (or any of the parent directories): .git"
        if sub == "remote" or sub == "tag":
            return "fatal: not a git repository (or any of the parent directories): .git"
        if sub == "config":
            if "--list" in parts or "-l" in parts:
                return (
                    "user.name=developer\n"
                    "user.email=developer@example.com\n"
                    "core.editor=vim\n"
                    "init.defaultBranch=main"
                )
            if "--global" in parts and len(parts) > 3:
                return ""
            return "fatal: not a git repository (or any of the parent directories): .git"
        if sub == "init":
            return "Initialized empty Git repository in .git/"
        return f"git: '{sub}' is not a git command. See 'git --help'."

    def _cmd_tar(self, parts: list) -> str:
        if len(parts) < 2:
            return "tar: You must specify one of the options"
        return ""

    def _cmd_hash(self, parts: list, algo: str) -> str:
        if len(parts) < 2:
            return ""
        target = parts[-1]
        import hashlib

        fake_hash = hashlib.new(algo, target.encode()).hexdigest()
        return f"{fake_hash}  {target}"

    def _cmd_docker(self, parts: list, state: SessionState) -> str:
        if len(parts) < 2:
            return "Usage: docker [OPTIONS] COMMAND"
        sub = parts[1]
        if sub == "--version":
            return "Docker version 24.0.7, build afdd53b"
        if sub == "ps":
            return "CONTAINER ID   IMAGE   COMMAND   CREATED   STATUS   PORTS   NAMES"
        if sub == "images":
            return "REPOSITORY   TAG   IMAGE ID   CREATED   SIZE"
        if sub == "info":
            return (
                "Client: Docker Engine - Community\n"
                " Version:    24.0.7\n"
                " Context:    default\n"
                "\n"
                "Server:\n"
                " Containers: 0\n"
                "  Running: 0\n"
                "  Paused: 0\n"
                "  Stopped: 0\n"
                " Images: 3\n"
                " Server Version: 24.0.7\n"
                " Storage Driver: overlay2\n"
                "  Backing Filesystem: extfs\n"
                " Operating System: Ubuntu 22.04.3 LTS\n"
                " OSType: linux\n"
                " Architecture: x86_64\n"
                " CPUs: 4\n"
                " Total Memory: 7.793GiB"
            )
        if sub == "compose":
            if len(parts) > 2 and parts[2] == "version":
                return "Docker Compose version v2.21.0"
            return "Docker Compose version v2.21.0"
        if sub in ("run", "exec", "logs", "stop", "start", "restart", "rm", "pull", "build"):
            if state.uid != 0:
                return (
                    "Got permission denied while trying to connect to the "
                    "Docker daemon socket at unix:///var/run/docker.sock: "
                    'Post "http://%2Fvar%2Frun%2Fdocker.sock/v1.24/'
                    f'{sub}": dial unix /var/run/docker.sock: connect: '
                    "permission denied"
                )
            return ""
        if sub in ("network", "volume", "system", "inspect"):
            if state.uid != 0:
                return (
                    "Got permission denied while trying to connect to the "
                    "Docker daemon socket. Is the docker daemon running?"
                )
            return ""
        return (
            "Got permission denied while trying to connect to the Docker daemon socket. "
            "Is the docker daemon running?"
        )

    def _cmd_lsof(self, parts: list) -> str:
        if "-i" in parts:
            return (
                "COMMAND  PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\n"
                "sshd     452 root    3u  IPv4  12345      0t0  TCP *:ssh (LISTEN)\n"
                "sshd     452 root    4u  IPv6  12346      0t0  TCP *:ssh (LISTEN)"
            )
        return ""

    # ── Dev Toolchain Commands ───────────────────────

    def _cmd_kubectl(self, parts: list) -> str:
        if len(parts) < 2:
            return (
                "kubectl controls the Kubernetes cluster manager.\n"
                "\n"
                " Find more information at: https://kubernetes.io/docs/reference/kubectl/\n"
                "\n"
                "Basic Commands (Beginner):\n"
                "  create        Create a resource from a file or from stdin\n"
                "  expose        Take a replication controller, service, deployment or pod\n"
                "  run           Run a particular image on the cluster\n"
                "  set           Set specific features on objects\n"
                "\n"
                "Usage:\n"
                "  kubectl [flags] [options]"
            )
        sub = parts[1]
        if sub == "version":
            return (
                "Client Version: v1.28.4\n"
                "Kustomize Version: v5.0.4-0.20230601165947-6ce0bf390ce3\n"
                "The connection to the server localhost:8080 was refused - "
                "did you specify the right host or port?"
            )
        if sub == "config":
            if len(parts) > 2 and parts[2] == "view":
                return (
                    "apiVersion: v1\n"
                    "clusters:\n"
                    "- cluster:\n"
                    "    server: https://127.0.0.1:6443\n"
                    "  name: default\n"
                    "contexts:\n"
                    "- context:\n"
                    "    cluster: default\n"
                    "    user: default\n"
                    "  name: default\n"
                    "current-context: default\n"
                    "kind: Config\n"
                    "preferences: {}"
                )
            return ""
        if sub in ("get", "describe", "delete", "apply", "logs", "exec", "port-forward", "scale", "rollout"):
            return (
                "The connection to the server localhost:8080 was refused - " "did you specify the right host or port?"
            )
        if sub == "cluster-info":
            return (
                "The connection to the server localhost:8080 was refused - " "did you specify the right host or port?"
            )
        return "The connection to the server localhost:8080 was refused - " "did you specify the right host or port?"

    def _cmd_aws(self, parts: list) -> str:
        if len(parts) < 2:
            return (
                "usage: aws [options] <command> <subcommand> "
                "[<subcommand> ...] [parameters]\n"
                "To see help text, you can run:\n"
                "\n"
                "  aws help\n"
                "  aws <command> help\n"
                "  aws <command> <subcommand> help"
            )
        if parts[1] == "--version":
            return "aws-cli/2.13.0 Python/3.11.4 Linux/5.15.0-91-generic exe/x86_64.ubuntu.22 prompt/off"
        if parts[1] == "sts" and len(parts) > 2 and parts[2] == "get-caller-identity":
            return "\nUnable to locate credentials. You can configure " 'credentials by running "aws configure".'
        if parts[1] == "s3":
            return "\nUnable to locate credentials. You can configure " 'credentials by running "aws configure".'
        if parts[1] == "configure":
            if len(parts) > 2 and parts[2] == "list":
                return (
                    "      Name                    Value             Type    Location\n"
                    "      ----                    -----             ----    --------\n"
                    "   profile                <not set>             None    None\n"
                    "access_key                <not set>             None    None\n"
                    "secret_key                <not set>             None    None\n"
                    "    region                us-east-1      config-file    ~/.aws/config"
                )
            return ""
        if parts[1] == "ec2" or parts[1] == "iam" or parts[1] == "lambda":
            return "\nUnable to locate credentials. You can configure " 'credentials by running "aws configure".'
        return "\nUnable to locate credentials. You can configure " 'credentials by running "aws configure".'

    def _cmd_nmap(self, parts: list) -> str:
        if len(parts) < 2:
            return (
                "Nmap 7.80 ( https://nmap.org )\n"
                "Usage: nmap [Scan Type(s)] [Options] {target specification}\n"
                "TARGET SPECIFICATION:\n"
                "  Can pass hostnames, IP addresses, networks, etc.\n"
                "EXAMPLES:\n"
                "  nmap -v -A scanme.nmap.org\n"
                "  nmap -v -sn 192.168.0.0/16 10.0.0.0/8\n"
                "  nmap -v -iR 10000 -Pn -p 80\n"
                "SEE THE MAN PAGE (https://nmap.org/book/man.html) "
                "FOR MORE OPTIONS AND EXAMPLES"
            )
        target = parts[-1]
        return (
            f"Starting Nmap 7.80 ( https://nmap.org ) at "
            f"{datetime.now().strftime('%Y-%m-%d %H:%M')} UTC\n"
            f"Nmap scan report for {target}\n"
            f"Host is up (0.0023s latency).\n"
            f"Not shown: 998 closed ports\n"
            f"PORT   STATE SERVICE\n"
            f"22/tcp open  ssh\n"
            f"80/tcp open  http\n"
            f"\n"
            f"Nmap done: 1 IP address (1 host up) scanned in 1.23 seconds"
        )

    def _cmd_node(self, parts: list) -> str:
        if len(parts) == 1:
            return (
                "Welcome to Node.js v18.19.0.\n"
                'Type ".help" for more information.\n'
                "> (interactive mode not supported)"
            )
        if parts[1] == "--version" or parts[1] == "-v":
            return "v18.19.0"
        if parts[1] == "-e" and len(parts) > 2:
            code = " ".join(parts[2:]).strip("'\"")
            m = re.search(r"""console\.log\s*\(\s*(['"])(.*?)\1\s*\)""", code)
            if m:
                return m.group(2)
            m = re.search(r"""console\.log\s*\(\s*(.+?)\s*\)""", code)
            if m:
                inner = m.group(1).strip("'\"")
                return inner
            return ""
        if parts[1] == "-p" and len(parts) > 2:
            code = " ".join(parts[2:]).strip("'\"")
            return code
        return ""

    def _cmd_npm(self, parts: list) -> str:
        if len(parts) < 2:
            return "Usage: npm <command>"
        if parts[1] == "--version" or parts[1] == "-v":
            return "10.2.3"
        if parts[1] == "list" or parts[1] == "ls":
            if "-g" in parts or "--global" in parts:
                return "/usr/lib\n" "├── corepack@0.22.0\n" "├── npm@10.2.3\n" "└── yarn@1.22.21"
            return "/home/developer/project\n" "└── (empty)"
        if parts[1] == "init":
            return "This utility will walk you through creating a package.json file."
        if parts[1] == "install" or parts[1] == "i":
            return "npm warn No package.json found in current directory"
        if parts[1] == "run":
            return "npm error Missing script"
        if parts[1] == "config" and len(parts) > 2:
            if parts[2] == "list":
                return (
                    '; "builtin" config from /usr/lib/node_modules/npm/npmrc\n'
                    "\n"
                    'prefix = "/usr/local"\n'
                    "\n"
                    "; node bin location = /usr/bin/node\n"
                    "; node version = v18.19.0\n"
                    "; npm local prefix = /home/developer\n"
                    "; npm version = 10.2.3"
                )
        return ""

    def _cmd_go(self, parts: list) -> str:
        if len(parts) < 2:
            return (
                "Go is a tool for managing Go source code.\n"
                "\n"
                "Usage:\n"
                "\n"
                "\tgo <command> [arguments]\n"
                "\n"
                "The commands are:\n"
                "\n"
                "\tbuild       compile packages and dependencies\n"
                "\trun         compile and run Go program\n"
                "\ttest        test packages\n"
                "\tmod         module maintenance\n"
                "\tget         add dependencies to current module"
            )
        if parts[1] == "version":
            return "go version go1.21.5 linux/amd64"
        if parts[1] == "env":
            return (
                "GO111MODULE=''\n"
                "GOARCH='amd64'\n"
                "GOBIN=''\n"
                "GOCACHE='/home/developer/.cache/go-build'\n"
                "GOMODCACHE='/home/developer/go/pkg/mod'\n"
                "GOOS='linux'\n"
                "GOPATH='/home/developer/go'\n"
                "GOROOT='/usr/local/go'\n"
                "GOVERSION='go1.21.5'"
            )
        if parts[1] in ("build", "run", "test"):
            return "go: go.mod file not found in current directory or any parent directory"
        if parts[1] == "mod" and len(parts) > 2 and parts[2] == "init":
            return ""
        return ""

    def _cmd_java(self, parts: list) -> str:
        if len(parts) == 1:
            return (
                "Usage: java [options] <mainclass> [args...]\n"
                "           (to execute a class)\n"
                "   or  java [options] -jar <jarfile> [args...]\n"
                "           (to execute a jar file)"
            )
        if parts[1] == "-version" or parts[1] == "--version":
            return (
                'openjdk version "17.0.9" 2023-10-17\n'
                "OpenJDK Runtime Environment (build 17.0.9+9-Ubuntu-122.04)\n"
                "OpenJDK 64-Bit Server VM (build 17.0.9+9-Ubuntu-122.04, mixed mode, sharing)"
            )
        if parts[1] == "-jar":
            if len(parts) < 3:
                return "Error: -jar requires jar file specification"
            return f"Error: Unable to access jarfile {parts[2]}"
        return ""

    def _cmd_gcc(self, parts: list) -> str:
        if len(parts) == 1:
            return "gcc: fatal error: no input files\ncompilation terminated."
        if parts[1] == "--version" or parts[1] == "-v":
            return (
                "gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0\n"
                "Copyright (C) 2021 Free Software Foundation, Inc.\n"
                "This is free software; see the source for copying conditions.  There is NO\n"
                "warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE."
            )
        return ""

    def _cmd_make(self, parts: list) -> str:
        if len(parts) == 1:
            return "make: *** No targets specified and no makefile found.  Stop."
        if parts[1] == "--version" or parts[1] == "-v":
            return (
                "GNU Make 4.3\n"
                "Built for x86_64-pc-linux-gnu\n"
                "Copyright (C) 1988-2020 Free Software Foundation, Inc.\n"
                "License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>\n"
                "This is free software: you are free to change and redistribute it.\n"
                "There is NO WARRANTY, to the extent permitted by law."
            )
        return ""

    def _cmd_lsb_release(self, parts: list) -> str:
        if len(parts) < 2 or "-a" in parts:
            return (
                "No LSB modules are available.\n"
                "Distributor ID:\tUbuntu\n"
                "Description:\tUbuntu 22.04.3 LTS\n"
                "Release:\t22.04\n"
                "Codename:\tjammy"
            )
        if "-r" in parts:
            return "Release:\t22.04"
        if "-d" in parts:
            return "Description:\tUbuntu 22.04.3 LTS"
        if "-c" in parts:
            return "Codename:\tjammy"
        if "-i" in parts:
            return "Distributor ID:\tUbuntu"
        if "-s" in parts:
            return "22.04"
        return (
            "No LSB modules are available.\n"
            "Distributor ID:\tUbuntu\n"
            "Description:\tUbuntu 22.04.3 LTS\n"
            "Release:\t22.04\n"
            "Codename:\tjammy"
        )

    def _cmd_hostnamectl(self, state: SessionState) -> str:
        return (
            f" Static hostname: {state.hostname}\n"
            f"       Icon name: computer-vm\n"
            f"         Chassis: vm\n"
            f"      Machine ID: a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4\n"
            f"         Boot ID: 1a2b3c4d5e6f1a2b3c4d5e6f1a2b3c4d\n"
            f"  Virtualization: kvm\n"
            f"Operating System: Ubuntu 22.04.3 LTS\n"
            f"          Kernel: Linux 5.15.0-91-generic\n"
            f"    Architecture: x86-64"
        )

    def _cmd_timedatectl(self) -> str:
        now = datetime.now()
        return (
            f"               Local time: {now.strftime('%a %Y-%m-%d %H:%M:%S')} UTC\n"
            f"           Universal time: {now.strftime('%a %Y-%m-%d %H:%M:%S')} UTC\n"
            f"                 RTC time: {now.strftime('%a %Y-%m-%d %H:%M:%S')}\n"
            f"                Time zone: Etc/UTC (UTC, +0000)\n"
            f"System clock synchronized: yes\n"
            f"              NTP service: active\n"
            f"          RTC in local TZ: no"
        )

    def _cmd_snap(self, parts: list) -> str:
        if len(parts) < 2:
            return "Usage: snap <command> [<options>...]"
        if parts[1] == "list":
            return (
                "Name               Version        Rev    Tracking       Publisher   Notes\n"
                "bare               1.0            5      latest/stable  canonical✓  base\n"
                "core22             20231123       1033   latest/stable  canonical✓  base\n"
                "lxd                5.20-533fae5   27043  5.20/stable    canonical✓  -\n"
                "snapd              2.61.1         20671  latest/stable  canonical✓  snapd"
            )
        if parts[1] == "version":
            return "snap    2.61.1\n" "snapd   2.61.1\n" "series  16\n" "ubuntu  22.04\n" "kernel  5.15.0-91-generic"
        if parts[1] in ("install", "remove", "refresh"):
            return "error: access denied (try with sudo)"
        return ""

    def _cmd_strings(self, parts: list) -> str:
        if len(parts) < 2:
            return "Usage: strings [option(s)] [file(s)]"
        return f"strings: '{parts[-1]}': No such file"

    def _cmd_xxd(self, parts: list) -> str:
        if len(parts) < 2:
            return "Usage: xxd [options] [infile [outfile]]"
        return f"xxd: {parts[-1]}: No such file or directory"

    def _cmd_strace(self, parts: list, state: SessionState) -> str:
        if state.uid != 0:
            return "strace: test_ptrace_get_syscall_info: PTRACE_TRACEME: Operation not permitted"
        if len(parts) < 2:
            return "strace: must have PROG [ARGS] or -p PID"
        # Return a minimal but realistic-looking strace snippet
        target = parts[-1]
        return (
            f'execve("/usr/bin/{target}", ["{target}"], 0x7ffd8e3a1e80 /* 23 vars */) = 0\n'
            f"brk(NULL)                               = 0x55a4d8c23000\n"
            f'access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)\n'
            f'openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3\n'
            f'openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3\n'
            f"mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f1234560000\n"
            f"+++ exited with 0 +++"
        )

    def _cmd_seq(self, parts: list) -> str:
        """Generate number sequences: seq LAST, seq FIRST LAST, seq FIRST INCREMENT LAST."""
        try:
            if len(parts) == 2:
                return "\n".join(str(i) for i in range(1, int(parts[1]) + 1))
            elif len(parts) == 3:
                return "\n".join(str(i) for i in range(int(parts[1]), int(parts[2]) + 1))
            elif len(parts) == 4:
                start, step, end = int(parts[1]), int(parts[2]), int(parts[3])
                result = []
                i = start
                while (step > 0 and i <= end) or (step < 0 and i >= end):
                    result.append(str(i))
                    i += step
                    if len(result) > 10000:  # Safety cap
                        break
                return "\n".join(result)
            return ""
        except (ValueError, TypeError):
            return "seq: invalid argument"

    def _cmd_diff(self, parts: list, fs: VirtualFilesystem) -> str:
        """Compare two files (basic stub)."""
        if len(parts) < 3:
            return "diff: missing operand\nUsage: diff FILE1 FILE2"
        f1, f2 = parts[1], parts[2]
        c1 = fs.read_file(f1)
        c2 = fs.read_file(f2)
        if c1 is None:
            return f"diff: {f1}: No such file or directory"
        if c2 is None:
            return f"diff: {f2}: No such file or directory"
        if c1 == c2:
            return ""  # No output means identical (like real diff)
        # Show basic unified diff header
        lines1 = c1.splitlines()
        lines2 = c2.splitlines()
        result = [f"--- {f1}", f"+++ {f2}"]
        for i, (l1, l2) in enumerate(zip(lines1, lines2, strict=False)):
            if l1 != l2:
                result.append(f"@@ -{i+1} +{i+1} @@")
                result.append(f"-{l1}")
                result.append(f"+{l2}")
        if len(lines1) != len(lines2):
            result.append(f"@@ Files have different lengths ({len(lines1)} vs {len(lines2)} lines) @@")
        return "\n".join(result)

    # ── Helpers ──────────────────────────────────────

    def _resolve_target(self, parts: list, state: SessionState) -> str:
        """Resolve a path argument for commands like realpath."""
        if len(parts) < 2:
            return state.cwd
        return self._resolve_target_path(parts[1], state)

    def _resolve_target_path(self, target: str, state: SessionState) -> str:
        """Resolve a potentially relative path to absolute."""
        if target.startswith("~"):
            target = state.home + target[1:]
        if not target.startswith("/"):
            if state.cwd == "/":
                target = f"/{target}"
            else:
                target = f"{state.cwd}/{target}"
        return self._normalize_path(target)

    # ══════════════════════════════════════════════════
    #  STAGE 4: TIER DISPATCH (scripted / LLM)
    # ══════════════════════════════════════════════════

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
        # Exact match
        if command in self.scripted_responses:
            return self.scripted_responses[command]

        # Exact command-name match (compare first word only to avoid
        # overly broad prefix matching, e.g. "ls" matching "lsof").
        cmd_word = command.split()[0] if command.split() else command
        for key, response in self.scripted_responses.items():
            if cmd_word == key.split()[0] and key in command:
                return response

        # Graceful fallback — never crash, always return command not found
        cmd = command.split()[0] if command.split() else command
        return f"-bash: {cmd}: command not found"

    # ── Adaptive / LLM (Tier 3) ─────────────────────

    async def _handle_adaptive(self, command: str, state: SessionState, fs: VirtualFilesystem) -> str:
        cache_key = f"{state.cwd}:{command}"
        if cache_key in self.response_cache:
            self.last_source = "llm_cache"
            self.response_cache.move_to_end(cache_key)
            # Mask timing — add artificial delay so cache hits don't appear
            # instantaneous (which would fingerprint the LLM + cache architecture)
            await asyncio.sleep(random.uniform(0.1, 0.4))
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
                "command_history": list(state.command_history)[-20:],
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

            if len(output) > 65_536:  # 64 KB max per cached entry
                output = output[:65_536]

            if result.get("cacheable", False):
                self.response_cache[cache_key] = output
                if len(self.response_cache) > _MAX_RESPONSE_CACHE:
                    self.response_cache.popitem(last=False)

            return output

        except Exception as e:
            logger.warning(f"Inference failed, falling back to scripted: {e}")
            # Add jitter to mask inference failure timing
            await asyncio.sleep(random.uniform(0.1, 0.8))
            return self._handle_scripted(command, state)
