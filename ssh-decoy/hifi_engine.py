"""
CI/CDecoy — High-Fidelity Scripted Engine

Resolution chain for incoming commands:
1. Exact match in response database
2. Normalized match (collapse whitespace, sort short flags)
3. Template generation (build output from filesystem + session state)
4. Fuzzy match (closest command in database by base command + flag overlap)
5. Return None → caller falls through to tier dispatch

NOTE: Pipe chains, redirects, and shell operators are already handled
by command_router.py's top-level parser. By the time a command reaches
this engine, it's a single command (post-split). The engine's job is to
produce realistic output for commands the common handlers don't cover.

Filesystem parameter accepts both VirtualFilesystem (base, read-only)
and SessionFilesystem (COW overlay). Both expose the same public API.
"""

import json
import logging
import os
import random
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from session import SessionState

logger = logging.getLogger("cicdecoy.hifi")


class HighFidelityEngine:

    def __init__(self):
        self.responses: dict[str, dict] = {}    # command → {output, exit_code}
        self.prefix_index: dict[str, list] = {} # first_word → [commands]
        self.templates: dict[str, callable] = {}
        self._loaded = False
        self._register_templates()

    # ── Database loading ─────────────────────────────

    def load_database(self, path: str):
        """Load a captured response database JSON."""
        try:
            with open(path) as f:
                data = json.load(f)
            for cmd, resp in data.get("responses", {}).items():
                # Normalize storage: ensure dict format
                if isinstance(resp, str):
                    resp = {"output": resp, "exit_code": 0}
                self.responses[cmd] = resp
            self._build_prefix_index()
            self._loaded = True
            logger.info(f"Loaded response DB: {len(self.responses)} commands from {path}")
        except Exception as e:
            logger.warning(f"Failed to load response DB {path}: {e}")

    def load_all_databases(self, directory: str):
        """Load all .json response databases from a directory."""
        db_dir = Path(directory)
        if not db_dir.is_dir():
            logger.info(f"Response DB directory not found: {directory}")
            return
        count = 0
        for path in sorted(db_dir.glob("*.json")):
            self.load_database(str(path))
            count += 1
        if count == 0:
            logger.info(f"No .json files in {directory}")

    def _build_prefix_index(self):
        """Index commands by their first word for fast lookup."""
        self.prefix_index.clear()
        for cmd in self.responses:
            first = cmd.split()[0] if cmd.split() else cmd
            self.prefix_index.setdefault(first, []).append(cmd)

    # ── Main entry point ─────────────────────────────

    def handle(self, command: str, state: SessionState, filesystem) -> Optional[str]:
        """
        Try to handle a command through the scripted engine.

        Returns the response string, or None if no match found.
        The caller (command_router.py) should fall through to tier
        dispatch if None is returned.

        The `filesystem` parameter works with both VirtualFilesystem
        and SessionFilesystem — both have the same public API.
        """
        command = command.strip()
        if not command:
            return ""

        # 1. Exact match
        if command in self.responses:
            return self._render(self.responses[command], state)

        # 2. Normalized match (whitespace + flag reordering)
        normalized = self._normalize_command(command)
        if normalized != command and normalized in self.responses:
            return self._render(self.responses[normalized], state)

        # 3. Template generation
        templated = self._try_template(command, state, filesystem)
        if templated is not None:
            return templated

        # 4. Fuzzy match (same base command, closest flags)
        fuzzy_key = self._fuzzy_match(command)
        if fuzzy_key is not None:
            return self._render(self.responses[fuzzy_key], state)

        # 5. No match
        return None

    # ── Resolution strategies ────────────────────────

    def _render(self, response: dict, state: SessionState) -> str:
        """Render a stored response with identity substitutions."""
        output = response.get("output", "")
        return self._substitute_identity(output, state)

    def _substitute_identity(self, output: str, state: SessionState) -> str:
        """Replace placeholder tokens with session-specific values."""
        replacements = {
            "{{HOSTNAME}}": state.hostname,
            "{{USERNAME}}": state.username,
            "{{UID}}": str(state.uid),
            "{{HOME}}": state.home,
            "{{CWD}}": state.cwd,
            "{{SHELL}}": state.env.get("SHELL", "/bin/bash"),
        }
        for token, value in replacements.items():
            output = output.replace(token, value)
        return output

    def _normalize_command(self, command: str) -> str:
        """Normalize for matching: collapse spaces, sort short flags."""
        parts = " ".join(command.split()).split()
        if len(parts) < 2:
            return " ".join(parts)

        cmd = parts[0]
        flags = []
        args = []
        for p in parts[1:]:
            if p.startswith("-") and not p.startswith("--") and len(p) > 1:
                flags.append(p)
            else:
                args.append(p)

        if flags:
            # Merge short flags: ["-l", "-a"] → "-al"
            all_chars = sorted(set(c for f in flags for c in f[1:]))
            merged = "-" + "".join(all_chars)
            return " ".join([cmd, merged] + args)

        return " ".join(parts)

    def _fuzzy_match(self, command: str) -> Optional[str]:
        """Find closest command in DB by base command + flag overlap."""
        parts = command.split()
        if not parts:
            return None
        cmd = parts[0]

        candidates = self.prefix_index.get(cmd)
        if not candidates:
            return None

        cmd_flags = set(p for p in parts[1:] if p.startswith("-"))
        cmd_args = [p for p in parts[1:] if not p.startswith("-")]

        best_match = None
        best_score = -1

        for candidate in candidates:
            cand_parts = candidate.split()
            cand_flags = set(p for p in cand_parts[1:] if p.startswith("-"))

            # Score: flag overlap + bonus for same arg count
            overlap = len(cmd_flags & cand_flags)
            cand_args = [p for p in cand_parts[1:] if not p.startswith("-")]
            arg_bonus = 0.5 if len(cmd_args) == len(cand_args) else 0

            score = overlap + arg_bonus
            if score > best_score:
                best_score = score
                best_match = candidate

        # Require at least some overlap, or fall back to simplest variant
        if best_match and best_score > 0:
            return best_match

        # No flag overlap: return the bare command variant if it exists
        if cmd in self.responses:
            return cmd

        # Return simplest variant as last resort
        if candidates:
            return min(candidates, key=len)

        return None

    # ── Template generators ──────────────────────────

    def _register_templates(self):
        """Register dynamic response generators."""
        self.templates = {
            "ping": self._tpl_ping,
            "traceroute": self._tpl_traceroute,
            "nslookup": self._tpl_nslookup,
            "dig": self._tpl_dig,
            "nmap": self._tpl_nmap,
            "curl": self._tpl_curl,
            "wget": self._tpl_wget,
            "find": self._tpl_find,
            "grep": self._tpl_grep,
            "wc": self._tpl_wc,
            "file": self._tpl_file,
            "stat": self._tpl_stat,
            "du": self._tpl_du,
            "head": self._tpl_head,
            "tail": self._tpl_tail,
            "strings": self._tpl_strings,
            "xxd": self._tpl_xxd,
        }

    def _try_template(self, command: str, state: SessionState, fs) -> Optional[str]:
        """Try template generators."""
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

    # ── Network templates ────────────────────────────

    def _tpl_ping(self, cmd: str, parts: list, state: SessionState, fs) -> str:
        target = parts[-1] if len(parts) > 1 else "127.0.0.1"
        # Parse count flag
        count = 4
        for i, p in enumerate(parts):
            if p == "-c" and i + 1 < len(parts):
                try:
                    count = min(int(parts[i + 1]), 10)
                except ValueError:
                    pass

        lines = [f"PING {target} ({target}) 56(84) bytes of data."]
        times = []
        for seq in range(1, count + 1):
            t = round(random.uniform(0.3, 45.0), 1)
            times.append(t)
            lines.append(
                f"64 bytes from {target}: icmp_seq={seq} ttl={random.randint(48, 64)} time={t} ms"
            )
        lines.append("")
        lines.append(f"--- {target} ping statistics ---")
        avg = round(sum(times) / len(times), 3)
        mn = round(min(times), 3)
        mx = round(max(times), 3)
        lines.append(f"{count} packets transmitted, {count} received, 0% packet loss, time {count * 1000}ms")
        lines.append(f"rtt min/avg/max/mdev = {mn}/{avg}/{mx}/{round(mx - mn, 3)} ms")
        return "\n".join(lines)

    def _tpl_traceroute(self, cmd: str, parts: list, state: SessionState, fs) -> str:
        target = parts[-1] if len(parts) > 1 else "8.8.8.8"
        lines = [f"traceroute to {target} ({target}), 30 hops max, 60 byte packets"]
        hops = random.randint(8, 16)
        for i in range(1, hops + 1):
            if i <= 2:
                ip = f"10.0.{random.randint(0,3)}.{random.randint(1,5)}"
            elif i == hops:
                ip = target
            else:
                ip = f"{random.choice([72,104,142,216])}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
            t1 = round(random.uniform(0.5, 80.0), 3)
            t2 = round(t1 + random.uniform(-1, 3), 3)
            t3 = round(t1 + random.uniform(-1, 3), 3)
            lines.append(f" {i:2d}  {ip}  {t1} ms  {t2} ms  {t3} ms")
        return "\n".join(lines)

    def _tpl_nslookup(self, cmd: str, parts: list, state: SessionState, fs) -> str:
        target = parts[-1] if len(parts) > 1 else "localhost"
        ip = f"{random.randint(50,200)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
        return (
            f"Server:\t\t127.0.0.53\nServer:\t\t127.0.0.53#53\n\n"
            f"Non-authoritative answer:\n"
            f"Name:\t{target}\nAddress: {ip}\n"
        )

    def _tpl_dig(self, cmd: str, parts: list, state: SessionState, fs) -> str:
        target = parts[-1] if len(parts) > 1 and not parts[-1].startswith("-") else "localhost"
        ip = f"{random.randint(50,200)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
        qtime = random.randint(5, 80)
        return (
            f"; <<>> DiG 9.18.18-0ubuntu0.22.04.1-Ubuntu <<>> {target}\n"
            f";; global options: +cmd\n"
            f";; Got answer:\n"
            f";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: {random.randint(10000,65000)}\n"
            f";; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1\n\n"
            f";; ANSWER SECTION:\n"
            f"{target}.\t\t{random.randint(60,3600)}\tIN\tA\t{ip}\n\n"
            f";; Query time: {qtime} msec\n"
            f";; SERVER: 127.0.0.53#53(127.0.0.53) (UDP)\n"
            f";; WHEN: {datetime.now(timezone.utc).strftime('%a %b %d %H:%M:%S UTC %Y')}\n"
            f";; MSG SIZE  rcvd: {random.randint(50, 120)}\n"
        )

    def _tpl_nmap(self, cmd: str, parts: list, state: SessionState, fs) -> str:
        target = parts[-1] if len(parts) > 1 and not parts[-1].startswith("-") else "127.0.0.1"
        return (
            f"Starting Nmap 7.80 ( https://nmap.org )\n"
            f"Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn\n"
            f"Nmap done: 1 IP address (0 hosts up) scanned in {round(random.uniform(2, 8), 2)} seconds"
        )

    def _tpl_curl(self, cmd: str, parts: list, state: SessionState, fs) -> Optional[str]:
        # Only handle URLs, not local file operations
        url = None
        for p in parts[1:]:
            if p.startswith("http://") or p.startswith("https://"):
                url = p
                break
        if not url:
            return None  # Let common handlers or tier dispatch handle it
        # Simulate connection timeout
        return f"curl: (28) Connection timed out after 10001 milliseconds"

    def _tpl_wget(self, cmd: str, parts: list, state: SessionState, fs) -> Optional[str]:
        url = None
        for p in parts[1:]:
            if p.startswith("http://") or p.startswith("https://"):
                url = p
                break
        if not url:
            return None
        filename = url.rsplit("/", 1)[-1] or "index.html"
        return (
            f"--{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}--  {url}\n"
            f"Resolving {url.split('/')[2]}... failed: Connection timed out.\n"
            f"wget: unable to resolve host address '{url.split('/')[2]}'"
        )

    # ── Filesystem templates ─────────────────────────

    def _tpl_find(self, cmd: str, parts: list, state: SessionState, fs) -> Optional[str]:
        """Walk the virtual filesystem for find results."""
        search_path = "/"
        name_pattern = None
        type_filter = None

        i = 1
        while i < len(parts):
            p = parts[i]
            if p == "-name" and i + 1 < len(parts):
                name_pattern = parts[i + 1].strip("'\"")
                i += 2
            elif p == "-type" and i + 1 < len(parts):
                type_filter = parts[i + 1]
                i += 2
            elif not p.startswith("-"):
                search_path = p
                i += 1
            else:
                i += 1

        results = []
        self._walk_fs(fs, search_path, name_pattern, type_filter, results, depth=0, max_depth=5)
        if not results:
            return ""
        return "\n".join(sorted(results)[:100])

    def _walk_fs(self, fs, path: str, name_pat: Optional[str],
                 type_filter: Optional[str], results: list,
                 depth: int, max_depth: int):
        """Recursively walk filesystem for find template."""
        if depth > max_depth:
            return
        try:
            entries = fs.list_directory(path)
        except Exception:
            return

        for entry in entries:
            entry_name = entry if isinstance(entry, str) else getattr(entry, "name", str(entry))
            full_path = f"{path.rstrip('/')}/{entry_name}"

            is_dir = False
            try:
                is_dir = fs.is_directory(full_path)
            except Exception:
                pass

            # Apply filters
            if type_filter == "f" and is_dir:
                pass  # skip dirs when -type f
            elif type_filter == "d" and not is_dir:
                pass  # skip files when -type d
            else:
                if name_pat:
                    # Convert glob to regex
                    regex = name_pat.replace(".", r"\.").replace("*", ".*").replace("?", ".")
                    if re.match(regex, entry_name):
                        results.append(full_path)
                else:
                    results.append(full_path)

            if is_dir and depth < max_depth:
                self._walk_fs(fs, full_path, name_pat, type_filter, results, depth + 1, max_depth)

    def _tpl_grep(self, cmd: str, parts: list, state: SessionState, fs) -> Optional[str]:
        """Search file contents in the virtual filesystem."""
        # Parse grep args
        pattern = None
        target_files = []
        recursive = False
        ignore_case = False
        invert = False
        count_only = False
        line_numbers = False

        i = 1
        while i < len(parts):
            p = parts[i]
            if p in ("-r", "-R", "--recursive"):
                recursive = True
            elif p in ("-i", "--ignore-case"):
                ignore_case = True
            elif p in ("-v", "--invert-match"):
                invert = True
            elif p in ("-c", "--count"):
                count_only = True
            elif p in ("-n", "--line-number"):
                line_numbers = True
            elif p.startswith("-") and not p.startswith("--"):
                # Merged flags like -rni
                if "r" in p or "R" in p:
                    recursive = True
                if "i" in p:
                    ignore_case = True
                if "v" in p:
                    invert = True
                if "c" in p:
                    count_only = True
                if "n" in p:
                    line_numbers = True
            elif pattern is None:
                pattern = p.strip("'\"")
            else:
                target_files.append(p)
            i += 1

        if not pattern:
            return None

        if not target_files:
            return None  # grep with no file args reads stdin — not applicable here

        flags = re.IGNORECASE if ignore_case else 0
        try:
            regex = re.compile(pattern, flags)
        except re.error:
            return f"grep: Invalid regular expression: '{pattern}'"

        results = []
        for filepath in target_files:
            try:
                content = fs.read_file(filepath)
                if content is None:
                    results.append(f"grep: {filepath}: No such file or directory")
                    continue

                lines = content.split("\n")
                matched = 0
                for lnum, line in enumerate(lines, 1):
                    match = bool(regex.search(line))
                    if invert:
                        match = not match
                    if match:
                        matched += 1
                        if not count_only:
                            prefix = ""
                            if len(target_files) > 1:
                                prefix = f"{filepath}:"
                            if line_numbers:
                                prefix += f"{lnum}:"
                            results.append(f"{prefix}{line}")

                if count_only:
                    prefix = f"{filepath}:" if len(target_files) > 1 else ""
                    results.append(f"{prefix}{matched}")
            except Exception:
                results.append(f"grep: {filepath}: Permission denied")

        return "\n".join(results) if results else ""

    def _tpl_wc(self, cmd: str, parts: list, state: SessionState, fs) -> Optional[str]:
        """Word/line/byte count on virtual files."""
        files = [p for p in parts[1:] if not p.startswith("-")]
        if not files:
            return None

        flag_l = "-l" in cmd
        flag_w = "-w" in cmd
        flag_c = "-c" in cmd
        if not (flag_l or flag_w or flag_c):
            flag_l = flag_w = flag_c = True  # default: all three

        results = []
        totals = [0, 0, 0]
        for filepath in files:
            try:
                content = fs.read_file(filepath)
                if content is None:
                    results.append(f"wc: {filepath}: No such file or directory")
                    continue
                lines = content.count("\n")
                words = len(content.split())
                chars = len(content)
                totals[0] += lines
                totals[1] += words
                totals[2] += chars

                cols = []
                if flag_l:
                    cols.append(f"{lines:>7}")
                if flag_w:
                    cols.append(f"{words:>7}")
                if flag_c:
                    cols.append(f"{chars:>7}")
                cols.append(f" {filepath}")
                results.append("".join(cols))
            except Exception:
                results.append(f"wc: {filepath}: Permission denied")

        if len(files) > 1:
            cols = []
            if flag_l:
                cols.append(f"{totals[0]:>7}")
            if flag_w:
                cols.append(f"{totals[1]:>7}")
            if flag_c:
                cols.append(f"{totals[2]:>7}")
            cols.append(" total")
            results.append("".join(cols))

        return "\n".join(results)

    def _tpl_head(self, cmd: str, parts: list, state: SessionState, fs) -> Optional[str]:
        """Return first N lines of a file."""
        n = 10
        filepath = None
        i = 1
        while i < len(parts):
            if parts[i] == "-n" and i + 1 < len(parts):
                try:
                    n = int(parts[i + 1])
                except ValueError:
                    pass
                i += 2
            elif parts[i].startswith("-") and parts[i][1:].isdigit():
                n = int(parts[i][1:])
                i += 1
            elif not parts[i].startswith("-"):
                filepath = parts[i]
                i += 1
            else:
                i += 1

        if not filepath:
            return None
        try:
            content = fs.read_file(filepath)
            if content is None:
                return f"head: cannot open '{filepath}' for reading: No such file or directory"
            return "\n".join(content.split("\n")[:n])
        except Exception:
            return f"head: cannot open '{filepath}' for reading: Permission denied"

    def _tpl_tail(self, cmd: str, parts: list, state: SessionState, fs) -> Optional[str]:
        """Return last N lines of a file."""
        n = 10
        filepath = None
        i = 1
        while i < len(parts):
            if parts[i] == "-n" and i + 1 < len(parts):
                try:
                    n = int(parts[i + 1])
                except ValueError:
                    pass
                i += 2
            elif parts[i].startswith("-") and parts[i][1:].isdigit():
                n = int(parts[i][1:])
                i += 1
            elif not parts[i].startswith("-"):
                filepath = parts[i]
                i += 1
            else:
                i += 1

        if not filepath:
            return None
        try:
            content = fs.read_file(filepath)
            if content is None:
                return f"tail: cannot open '{filepath}' for reading: No such file or directory"
            lines = content.split("\n")
            return "\n".join(lines[-n:])
        except Exception:
            return f"tail: cannot open '{filepath}' for reading: Permission denied"

    def _tpl_file(self, cmd: str, parts: list, state: SessionState, fs) -> Optional[str]:
        """Identify file type."""
        files = [p for p in parts[1:] if not p.startswith("-")]
        if not files:
            return None

        results = []
        for filepath in files:
            if fs.is_directory(filepath):
                results.append(f"{filepath}: directory")
            elif fs.file_exists(filepath):
                content = fs.read_file(filepath) or ""
                if content.startswith("#!"):
                    shell = content.split("\n")[0][2:].strip()
                    results.append(f"{filepath}: {shell} script, ASCII text executable")
                elif content.startswith("ELF"):
                    results.append(f"{filepath}: ELF 64-bit LSB pie executable, x86-64")
                elif filepath.endswith((".py",)):
                    results.append(f"{filepath}: Python script, ASCII text executable")
                elif filepath.endswith((".sh",)):
                    results.append(f"{filepath}: Bourne-Again shell script, ASCII text executable")
                elif filepath.endswith((".conf", ".cfg", ".ini", ".yaml", ".yml", ".json", ".txt", ".log")):
                    results.append(f"{filepath}: ASCII text")
                else:
                    results.append(f"{filepath}: ASCII text")
            else:
                results.append(f"{filepath}: cannot open `{filepath}' (No such file or directory)")

        return "\n".join(results)

    def _tpl_stat(self, cmd: str, parts: list, state: SessionState, fs) -> Optional[str]:
        """Stat a file."""
        files = [p for p in parts[1:] if not p.startswith("-")]
        if not files:
            return None

        results = []
        for filepath in files:
            node = fs.get_node(filepath) if hasattr(fs, "get_node") else None
            if node is None:
                results.append(f"stat: cannot statx '{filepath}': No such file or directory")
                continue

            size = getattr(node, "size", 0) or 0
            perms = getattr(node, "permissions", "0644")
            owner = getattr(node, "owner", "root")
            group = getattr(node, "group", "root")
            modified = getattr(node, "modified", "2024-01-15 10:30:00")
            is_dir = getattr(node, "is_dir", False)
            ftype = "directory" if is_dir else "regular file"

            results.append(
                f"  File: {filepath}\n"
                f"  Size: {size}\t\tBlocks: {(size // 512) + 1}\t\tIO Block: 4096   {ftype}\n"
                f"Access: ({perms}/{'drwxr-xr-x' if is_dir else '-rw-r--r--'})\tUid: (    0/  {owner})\tGid: (    0/  {group})\n"
                f"Access: {modified}\n"
                f"Modify: {modified}\n"
                f"Change: {modified}\n"
                f" Birth: -"
            )

        return "\n".join(results)

    def _tpl_du(self, cmd: str, parts: list, state: SessionState, fs) -> Optional[str]:
        """Disk usage estimation."""
        target = "."
        human = "-h" in cmd or "--human-readable" in cmd
        summary = "-s" in cmd or "--summarize" in cmd

        for p in parts[1:]:
            if not p.startswith("-"):
                target = p
                break

        if summary:
            size = random.randint(4, 2048)
            if human:
                if size > 1024:
                    return f"{size / 1024:.1f}G\t{target}"
                return f"{size}M\t{target}"
            return f"{size * 1024}\t{target}"

        # Walk a few directories
        results = []
        try:
            entries = fs.list_directory(target)
            for entry in entries[:20]:
                entry_name = entry if isinstance(entry, str) else getattr(entry, "name", str(entry))
                path = f"{target.rstrip('/')}/{entry_name}"
                size = random.randint(4, 512)
                if human:
                    results.append(f"{size}K\t{path}")
                else:
                    results.append(f"{size}\t{path}")
        except Exception:
            pass

        total = random.randint(1024, 8192)
        if human:
            results.append(f"{total / 1024:.1f}M\t{target}")
        else:
            results.append(f"{total}\t{target}")
        return "\n".join(results)

    def _tpl_strings(self, cmd: str, parts: list, state: SessionState, fs) -> Optional[str]:
        """Extract strings from a file."""
        filepath = None
        for p in parts[1:]:
            if not p.startswith("-"):
                filepath = p
                break
        if not filepath:
            return None
        try:
            content = fs.read_file(filepath)
            if content is None:
                return f"strings: '{filepath}': No such file"
            # Return printable strings
            strings = re.findall(r'[\x20-\x7e]{4,}', content)
            return "\n".join(strings[:50])
        except Exception:
            return f"strings: '{filepath}': Permission denied"

    def _tpl_xxd(self, cmd: str, parts: list, state: SessionState, fs) -> Optional[str]:
        """Hex dump of a file."""
        filepath = None
        for p in parts[1:]:
            if not p.startswith("-"):
                filepath = p
                break
        if not filepath:
            return None
        try:
            content = fs.read_file(filepath)
            if content is None:
                return f"xxd: {filepath}: No such file or directory"
            data = content.encode()[:256]
            lines = []
            for offset in range(0, len(data), 16):
                chunk = data[offset:offset + 16]
                hex_part = " ".join(f"{b:02x}" for b in chunk)
                ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
                lines.append(f"{offset:08x}: {hex_part:<48s}  {ascii_part}")
            return "\n".join(lines)
        except Exception:
            return f"xxd: {filepath}: Permission denied"