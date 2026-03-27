# CI/CDecoy — Virtual Filesystem
# images/ssh-decoy/src/filesystem.py
#
# In-memory filesystem that provides convincing responses to ls, cat, etc.
# Built from base OS skeletons + profile overlays + honeytoken placements.
# Supports attacker mutations (touch, mkdir, write) within the session.

import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional
import random

logger = logging.getLogger("cicdecoy.filesystem")


@dataclass
class FSNode:
    """A single filesystem entry (file or directory)."""
    name: str
    path: str
    is_dir: bool = False
    content: Optional[str] = None
    size: int = 0
    owner: str = "root"
    group: str = "root"
    permissions: str = "0644"
    modified: str = ""
    children: dict = field(default_factory=dict)   # name → FSNode (dirs only)
    is_honeytoken: bool = False
    honeytoken_ref: Optional[str] = None

    def __post_init__(self):
        if not self.modified:
            # Random date in the last 6 months for realism
            days_ago = random.randint(1, 180)
            dt = datetime.utcnow() - timedelta(days=days_ago)
            self.modified = dt.strftime("%b %d %H:%M")
        if self.content and not self.size:
            self.size = len(self.content.encode())
        if self.is_dir and self.permissions == "0644":
            self.permissions = "0755"


class VirtualFilesystem:
    """
    Virtual filesystem built from layered overlays.

    Construction order:
    1. Base OS skeleton (ubuntu-22.04-minimal, etc.)
    2. Profile overlay (software, configs for the "personality")
    3. Inline file overlays from manifest
    4. Honeytoken placements
    5. Runtime mutations from attacker activity
    """

    def __init__(self):
        self.root = FSNode(name="/", path="/", is_dir=True, owner="root",
                           permissions="0755")
        self.profile_data: dict = {}

    @classmethod
    def from_profile(cls, profile_name: str) -> "VirtualFilesystem":
        """Build filesystem from a named profile."""
        fs = cls()
        fs._build_base_skeleton()

        if profile_name:
            fs._apply_profile(profile_name)

        return fs

    # ─────────────────────────────────────────────
    #  Public API (called by command router)
    # ─────────────────────────────────────────────

    def is_directory(self, path: str) -> bool:
        node = self._resolve_node(path)
        return node is not None and node.is_dir

    def is_file(self, path: str) -> bool:
        node = self._resolve_node(path)
        return node is not None and not node.is_dir

    def read_file(self, path: str) -> Optional[str]:
        """Read file content. Returns None if not found."""
        node = self._resolve_node(path)
        if node is None or node.is_dir:
            return None
        return node.content or ""

    def list_directory(
        self, path: str, long_format: bool = False, show_hidden: bool = False
    ) -> str:
        """Generate ls output for a directory."""
        node = self._resolve_node(path)
        if node is None:
            return f"ls: cannot access '{path}': No such file or directory"
        if not node.is_dir:
            if long_format:
                return self._format_long_entry(node)
            return node.name

        entries = []
        for name, child in sorted(node.children.items()):
            if not show_hidden and name.startswith("."):
                continue
            entries.append(child)

        if not entries:
            return ""

        if long_format:
            lines = [f"total {len(entries) * 4}"]
            for entry in entries:
                lines.append(self._format_long_entry(entry))
            return "\n".join(lines)
        else:
            return "  ".join(e.name for e in entries)

    def create_file(self, path: str, content: str = "", owner: str = "root"):
        """Create a file (from attacker touch/write commands)."""
        parent_path = os.path.dirname(path)
        filename = os.path.basename(path)
        parent = self._resolve_node(parent_path)
        if parent and parent.is_dir:
            parent.children[filename] = FSNode(
                name=filename,
                path=path,
                content=content,
                owner=owner,
                modified=datetime.utcnow().strftime("%b %d %H:%M"),
            )

    def create_directory(self, path: str, owner: str = "root"):
        """Create a directory."""
        parent_path = os.path.dirname(path)
        dirname = os.path.basename(path)
        parent = self._resolve_node(parent_path)
        if parent and parent.is_dir:
            parent.children[dirname] = FSNode(
                name=dirname,
                path=path,
                is_dir=True,
                owner=owner,
                permissions="0755",
                modified=datetime.utcnow().strftime("%b %d %H:%M"),
            )

    def get_context_snapshot(self, cwd: str) -> dict:
        """
        Generate a filesystem context for LLM injection.

        Rather than dumping the entire tree (too large for context),
        provide the immediate vicinity: cwd contents, parent contents,
        and any recently accessed paths.
        """
        snapshot = {"cwd": cwd, "cwd_contents": [], "parent_contents": []}

        cwd_node = self._resolve_node(cwd)
        if cwd_node and cwd_node.is_dir:
            for name, child in cwd_node.children.items():
                snapshot["cwd_contents"].append({
                    "name": name,
                    "type": "dir" if child.is_dir else "file",
                    "size": child.size,
                    "owner": child.owner,
                })

        parent = os.path.dirname(cwd)
        parent_node = self._resolve_node(parent)
        if parent_node and parent_node.is_dir:
            for name, child in parent_node.children.items():
                snapshot["parent_contents"].append({
                    "name": name,
                    "type": "dir" if child.is_dir else "file",
                })

        return snapshot

    def get_profile_data(self) -> dict:
        return self.profile_data

    # ─────────────────────────────────────────────
    #  Filesystem Construction
    # ─────────────────────────────────────────────

    def _build_base_skeleton(self):
        """Create a minimal Linux filesystem tree."""
        base_dirs = [
            "/bin", "/boot", "/dev", "/etc", "/etc/ssh", "/etc/apt",
            "/etc/default", "/etc/network", "/etc/systemd",
            "/home", "/lib", "/lib64", "/media", "/mnt",
            "/opt", "/proc", "/root", "/run", "/sbin",
            "/srv", "/sys", "/tmp", "/usr", "/usr/bin",
            "/usr/lib", "/usr/local", "/usr/local/bin",
            "/usr/sbin", "/usr/share", "/var", "/var/cache",
            "/var/lib", "/var/log", "/var/mail", "/var/run",
            "/var/spool", "/var/tmp",
        ]

        for dir_path in base_dirs:
            self._ensure_dir(dir_path)

        # Standard files
        self._add_file("/etc/passwd", self._generate_passwd(), "root", "0644")
        self._add_file("/etc/hostname", "localhost", "root", "0644")
        self._add_file("/etc/hosts",
                       "127.0.0.1\tlocalhost\n::1\t\tlocalhost", "root", "0644")
        self._add_file("/etc/resolv.conf",
                       "nameserver 10.0.0.2\nsearch corp.internal", "root", "0644")
        self._add_file("/etc/issue", "Ubuntu 22.04.3 LTS \\n \\l\n", "root", "0644")
        self._add_file("/etc/os-release", (
            'PRETTY_NAME="Ubuntu 22.04.3 LTS"\n'
            'NAME="Ubuntu"\nVERSION_ID="22.04"\n'
            'VERSION="22.04.3 LTS (Jammy Jellyfish)"\n'
            'ID=ubuntu\nID_LIKE=debian\n'
            'HOME_URL="https://www.ubuntu.com/"\n'
            'SUPPORT_URL="https://help.ubuntu.com/"'
        ), "root", "0644")

    def _apply_profile(self, profile_name: str):
        """
        Layer profile-specific content onto the filesystem.

        In production this loads from the DecoyProfile CRD.
        This prototype builds inline for demonstration.
        """
        profile_path = f"/etc/cicdecoy/profiles/{profile_name}.json"
        if os.path.exists(profile_path):
            with open(profile_path) as f:
                profile = json.load(f)
                self._apply_profile_data(profile)
        else:
            logger.warning(f"Profile {profile_name} not found, using defaults")

        # Store profile metadata for fast-path responses
        self.profile_data = {
            "processes": [
                {"pid": 1, "command": "/sbin/init", "user": "root"},
                {"pid": 452, "command": "/usr/sbin/sshd -D", "user": "root"},
                {"pid": 610, "command": "/usr/sbin/cron -f", "user": "root"},
            ],
            "uptime": " 14:03:22 up 127 days,  8:14,  1 user,  load average: 0.08, 0.03, 0.01",
            "memory": (
                "               total        used        free      shared  buff/cache   available\n"
                "Mem:           7.8Gi       2.1Gi       3.4Gi       142Mi       2.3Gi       5.3Gi\n"
                "Swap:          2.0Gi          0B       2.0Gi"
            ),
            "disk": (
                "Filesystem      Size  Used Avail Use% Mounted on\n"
                "/dev/sda1        50G   18G   30G  38% /\n"
                "tmpfs           3.9G     0  3.9G   0% /dev/shm\n"
                "/dev/sda2       200G   43G  147G  23% /opt"
            ),
        }

    def _apply_profile_data(self, profile: dict):
        """Apply structured profile data to filesystem."""
        # Create user home directories
        for user in profile.get("users", []):
            home = f"/home/{user['name']}"
            self._ensure_dir(home)
            self._ensure_dir(f"{home}/.ssh")
            self._add_file(f"{home}/.bashrc",
                           self._generate_bashrc(user["name"]),
                           user["name"], "0644")
            self._add_file(f"{home}/.profile",
                           "# ~/.profile\n", user["name"], "0644")

        # Update hostname in standard files
        hostname = profile.get("system", {}).get("hostname", "localhost")
        self._add_file("/etc/hostname", hostname, "root", "0644")

    # ─────────────────────────────────────────────
    #  Helpers
    # ─────────────────────────────────────────────

    def _resolve_node(self, path: str) -> Optional[FSNode]:
        """Walk the tree to find a node by path."""
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
        """Create directory and all parents."""
        parts = [p for p in path.split("/") if p]
        current = self.root

        built_path = ""
        for part in parts:
            built_path += f"/{part}"
            if part not in current.children:
                current.children[part] = FSNode(
                    name=part, path=built_path, is_dir=True,
                    owner="root", permissions="0755",
                )
            current = current.children[part]

    def _add_file(
        self, path: str, content: str, owner: str = "root",
        permissions: str = "0644",
        is_honeytoken: bool = False, honeytoken_ref: str = None,
    ):
        parent_path = os.path.dirname(path)
        filename = os.path.basename(path)
        self._ensure_dir(parent_path)
        parent = self._resolve_node(parent_path)
        if parent:
            parent.children[filename] = FSNode(
                name=filename,
                path=path,
                content=content,
                owner=owner,
                permissions=permissions,
                is_honeytoken=is_honeytoken,
                honeytoken_ref=honeytoken_ref,
            )

    @staticmethod
    def _format_long_entry(node: FSNode) -> str:
        """Format a single ls -l line."""
        if node.is_dir:
            perms = "d" + _permission_string(node.permissions)
            links = "2"
        else:
            perms = "-" + _permission_string(node.permissions)
            links = "1"

        return (
            f"{perms} {links:>3} {node.owner:<8} {node.group:<8} "
            f"{node.size:>8} {node.modified} {node.name}"
        )

    @staticmethod
    def _generate_passwd() -> str:
        return (
            "root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
            "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
            "sync:x:4:65534:sync:/bin:/bin/sync\n"
            "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
            "sshd:x:110:65534::/run/sshd:/usr/sbin/nologin\n"
        )

    @staticmethod
    def _generate_bashrc(username: str) -> str:
        return (
            "# ~/.bashrc\n"
            "[ -z \"$PS1\" ] && return\n"
            "HISTCONTROL=ignoredups:ignorespace\n"
            "HISTSIZE=1000\n"
            "HISTFILESIZE=2000\n"
            "shopt -s histappend checkwinsize\n"
            f"PS1='\\u@\\h:\\w\\$ '\n"
            "alias ll='ls -alF'\nalias la='ls -A'\nalias l='ls -CF'\n"
        )


def _permission_string(octal: str) -> str:
    """Convert '0755' → 'rwxr-xr-x'."""
    result = ""
    for digit in octal[-3:]:
        d = int(digit)
        result += "r" if d & 4 else "-"
        result += "w" if d & 2 else "-"
        result += "x" if d & 1 else "-"
    return result
