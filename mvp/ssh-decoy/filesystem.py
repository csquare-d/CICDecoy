"""
CI/CDecoy — Virtual Filesystem (MVP)

Builds an in-memory filesystem from base skeleton + profile JSON.
"""

import json
import logging
import os
import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

logger = logging.getLogger("cicdecoy.filesystem")


@dataclass
class FSNode:
    name: str
    path: str
    is_dir: bool = False
    content: Optional[str] = None
    size: int = 0
    owner: str = "root"
    group: str = "root"
    permissions: str = "0644"
    modified: str = ""
    children: dict = field(default_factory=dict)

    def __post_init__(self):
        if not self.modified:
            days_ago = random.randint(1, 180)
            dt = datetime.utcnow() - timedelta(days=days_ago)
            self.modified = dt.strftime("%b %d %H:%M")
        if self.content and not self.size:
            self.size = len(self.content.encode("utf-8", errors="replace"))
        if self.is_dir and self.permissions == "0644":
            self.permissions = "0755"


class VirtualFilesystem:

    def __init__(self):
        self.root = FSNode(name="/", path="/", is_dir=True, permissions="0755")
        self.profile_data: dict = {}

    @classmethod
    def from_profile(cls, profile_name: str) -> "VirtualFilesystem":
        fs = cls()
        fs._build_base_skeleton()

        if profile_name:
            fs._load_profile(profile_name)

        return fs

    # ── Public API ───────────────────────────────────

    def is_directory(self, path: str) -> bool:
        node = self._resolve(path)
        return node is not None and node.is_dir

    def is_file(self, path: str) -> bool:
        node = self._resolve(path)
        return node is not None and not node.is_dir

    def read_file(self, path: str) -> Optional[str]:
        node = self._resolve(path)
        if node is None or node.is_dir:
            return None
        return node.content or ""

    def list_directory(self, path: str, long_format: bool = False,
                       show_hidden: bool = False) -> str:
        node = self._resolve(path)
        if node is None:
            return f"ls: cannot access '{path}': No such file or directory"
        if not node.is_dir:
            return self._format_long(node) if long_format else node.name

        entries = sorted(node.children.values(), key=lambda n: n.name)
        if not show_hidden:
            entries = [e for e in entries if not e.name.startswith(".")]

        if not entries:
            return ""

        if long_format:
            lines = [f"total {len(entries) * 4}"]
            for e in entries:
                lines.append(self._format_long(e))
            return "\n".join(lines)
        return "  ".join(e.name for e in entries)

    def create_file(self, path: str, content: str = "", owner: str = "root"):
        parent_path = os.path.dirname(path)
        filename = os.path.basename(path)
        parent = self._resolve(parent_path)
        if parent and parent.is_dir:
            parent.children[filename] = FSNode(
                name=filename, path=path, content=content, owner=owner,
                modified=datetime.utcnow().strftime("%b %d %H:%M"),
            )

    def create_directory(self, path: str, owner: str = "root"):
        parent_path = os.path.dirname(path)
        dirname = os.path.basename(path)
        parent = self._resolve(parent_path)
        if parent and parent.is_dir:
            parent.children[dirname] = FSNode(
                name=dirname, path=path, is_dir=True, owner=owner,
                permissions="0755",
                modified=datetime.utcnow().strftime("%b %d %H:%M"),
            )

    def get_context_snapshot(self, cwd: str) -> dict:
        snapshot = {"cwd": cwd, "cwd_contents": [], "parent_contents": []}
        cwd_node = self._resolve(cwd)
        if cwd_node and cwd_node.is_dir:
            for name, child in cwd_node.children.items():
                snapshot["cwd_contents"].append({
                    "name": name,
                    "type": "dir" if child.is_dir else "file",
                    "size": child.size,
                    "owner": child.owner,
                })
        return snapshot

    def get_profile_data(self) -> dict:
        return self.profile_data

    # ── Filesystem Construction ──────────────────────

    def _build_base_skeleton(self):
        dirs = [
            "/bin", "/boot", "/dev", "/etc", "/etc/ssh", "/etc/apt",
            "/etc/default", "/etc/network", "/etc/systemd", "/etc/cron.d",
            "/home", "/lib", "/lib64", "/media", "/mnt", "/opt",
            "/proc", "/root", "/run", "/sbin", "/srv", "/sys", "/tmp",
            "/usr", "/usr/bin", "/usr/lib", "/usr/local", "/usr/local/bin",
            "/usr/sbin", "/usr/share", "/var", "/var/cache", "/var/lib",
            "/var/log", "/var/mail", "/var/run", "/var/spool", "/var/tmp",
            "/var/backups",
        ]
        for d in dirs:
            self._ensure_dir(d)

        # Standard files
        self._add_file("/etc/passwd", self._gen_passwd(), "root", "0644")
        self._add_file("/etc/group", self._gen_group(), "root", "0644")
        self._add_file("/etc/shadow", "", "root", "0640")  # Readable but empty
        self._add_file("/etc/hostname", "localhost", "root", "0644")
        self._add_file("/etc/hosts",
                        "127.0.0.1\tlocalhost\n::1\t\tlocalhost", "root", "0644")
        self._add_file("/etc/resolv.conf",
                        "nameserver 10.0.0.2\nsearch corp.internal", "root", "0644")
        self._add_file("/etc/issue", "Ubuntu 22.04.3 LTS \\n \\l\n\n", "root", "0644")
        self._add_file("/etc/os-release", (
            'PRETTY_NAME="Ubuntu 22.04.3 LTS"\n'
            'NAME="Ubuntu"\nVERSION_ID="22.04"\n'
            'VERSION="22.04.3 LTS (Jammy Jellyfish)"\n'
            'ID=ubuntu\nID_LIKE=debian\n'
            'HOME_URL="https://www.ubuntu.com/"\n'
            'SUPPORT_URL="https://help.ubuntu.com/"'
        ), "root", "0644")
        self._add_file("/etc/shells",
                        "/bin/sh\n/bin/bash\n/usr/bin/bash\n/bin/zsh",
                        "root", "0644")
        # /var/log files
        self._add_file("/var/log/syslog", "", "root", "0640")
        self._add_file("/var/log/auth.log", "", "root", "0640")
        self._add_file("/var/log/kern.log", "", "root", "0640")

    def _load_profile(self, profile_name: str):
        """Load profile JSON from the profiles directory."""
        profiles_dir = os.environ.get("PROFILES_DIR", "/etc/cicdecoy/profiles")
        profile_path = Path(profiles_dir) / f"{profile_name}.json"

        if not profile_path.exists():
            logger.warning(f"Profile not found: {profile_path}")
            self._set_default_profile_data()
            return

        try:
            with open(profile_path) as f:
                profile = json.load(f)
        except Exception as e:
            logger.error(f"Failed to load profile {profile_path}: {e}")
            self._set_default_profile_data()
            return

        logger.info(f"Loaded profile: {profile_name}")

        # Update hostname
        hostname = profile.get("system", {}).get("hostname", "localhost")
        self._add_file("/etc/hostname", hostname, "root", "0644")

        # Update /etc/passwd with profile users
        passwd_lines = self._gen_passwd()
        for user in profile.get("users", []):
            uid = user.get("uid", 1000)
            home = user.get("home", f"/home/{user['name']}")
            shell = user.get("shell", "/bin/bash")
            full_name = user.get("fullName", "")
            passwd_lines += f"{user['name']}:x:{uid}:{uid}:{full_name}:{home}:{shell}\n"

            # Create home directory
            self._ensure_dir(home)
            self._ensure_dir(f"{home}/.ssh")

            self._add_file(f"{home}/.bashrc", self._gen_bashrc(user["name"]),
                           user["name"], "0644")
            self._add_file(f"{home}/.profile",
                           "# ~/.profile\n. ~/.bashrc\n", user["name"], "0644")

        self._add_file("/etc/passwd", passwd_lines, "root", "0644")

        # Update /etc/hosts if present in profile
        hosts_content = profile.get("filesystem_extras", {}).get("/etc/hosts")
        if hosts_content:
            self._add_file("/etc/hosts", hosts_content, "root", "0644")

        # Add filesystem extras from profile
        for filepath, content in profile.get("filesystem_extras", {}).items():
            if filepath == "/etc/hosts":
                continue  # Already handled
            parent = os.path.dirname(filepath)
            self._ensure_dir(parent)
            # Determine owner from path
            owner = "root"
            for user in profile.get("users", []):
                if filepath.startswith(user.get("home", f"/home/{user['name']}")):
                    owner = user["name"]
                    break
            self._add_file(filepath, content, owner, "0644")

        # Build profile data for fast-path responses
        procs = [
            {"pid": 1, "command": "/sbin/init", "user": "root"},
            {"pid": 452, "command": "/usr/sbin/sshd -D", "user": "root"},
            {"pid": 610, "command": "/usr/sbin/cron -f", "user": "root"},
        ]
        for svc in profile.get("software", {}).get("services", []):
            procs.append({
                "pid": random.randint(1000, 9999),
                "command": f"/usr/sbin/{svc['name']}",
                "user": "root",
            })

        self.profile_data = {
            "processes": procs,
            "uptime": profile.get("static_responses", {}).get("uptime",
                f" {datetime.now().strftime('%H:%M:%S')} up "
                f"{profile.get('system', {}).get('uptime', '1 day')}, "
                "1 user, load average: 0.08, 0.04, 0.01"),
            "memory": profile.get("static_responses", {}).get("free -h", ""),
            "disk": profile.get("static_responses", {}).get("df -h", ""),
            "static_responses": profile.get("static_responses", {}),
        }

    def _set_default_profile_data(self):
        self.profile_data = {
            "processes": [
                {"pid": 1, "command": "/sbin/init", "user": "root"},
                {"pid": 452, "command": "/usr/sbin/sshd -D", "user": "root"},
            ],
            "static_responses": {},
        }

    # ── Tree helpers ─────────────────────────────────

    def _resolve(self, path: str) -> Optional[FSNode]:
        if path == "/":
            return self.root
        parts = [p for p in path.split("/") if p]
        current = self.root
        for part in parts:
            if not current.is_dir or part not in current.children:
                return None
            current = current.children[part]
        return current

    def _ensure_dir(self, path: str):
        parts = [p for p in path.split("/") if p]
        current = self.root
        built = ""
        for part in parts:
            built += f"/{part}"
            if part not in current.children:
                current.children[part] = FSNode(
                    name=part, path=built, is_dir=True,
                    owner="root", permissions="0755",
                )
            current = current.children[part]

    def _add_file(self, path: str, content: str, owner: str = "root",
                  permissions: str = "0644"):
        parent = os.path.dirname(path)
        filename = os.path.basename(path)
        self._ensure_dir(parent)
        parent_node = self._resolve(parent)
        if parent_node:
            parent_node.children[filename] = FSNode(
                name=filename, path=path, content=content,
                owner=owner, permissions=permissions,
            )

    def _format_long(self, node: FSNode) -> str:
        perm_str = ("d" if node.is_dir else "-") + _perm_bits(node.permissions)
        links = "2" if node.is_dir else "1"
        return (f"{perm_str} {links:>3} {node.owner:<8} {node.group:<8} "
                f"{node.size:>8} {node.modified} {node.name}")

    @staticmethod
    def _gen_passwd() -> str:
        return (
            "root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
            "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
            "sync:x:4:65534:sync:/bin:/bin/sync\n"
            "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
            "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
            "sshd:x:110:65534::/run/sshd:/usr/sbin/nologin\n"
        )

    @staticmethod
    def _gen_group() -> str:
        return (
            "root:x:0:\n"
            "daemon:x:1:\n"
            "sudo:x:27:\n"
            "docker:x:998:\n"
            "developers:x:1001:\n"
        )

    @staticmethod
    def _gen_bashrc(username: str) -> str:
        return (
            "# ~/.bashrc\n"
            '[ -z "$PS1" ] && return\n'
            "HISTCONTROL=ignoredups:ignorespace\n"
            "HISTSIZE=1000\n"
            "HISTFILESIZE=2000\n"
            "shopt -s histappend checkwinsize\n"
            "PS1='\\u@\\h:\\w\\$ '\n"
            "alias ll='ls -alF'\nalias la='ls -A'\nalias l='ls -CF'\n"
            "alias grep='grep --color=auto'\n"
        )


def _perm_bits(octal: str) -> str:
    result = ""
    for digit in octal[-3:]:
        d = int(digit)
        result += "r" if d & 4 else "-"
        result += "w" if d & 2 else "-"
        result += "x" if d & 1 else "-"
    return result
