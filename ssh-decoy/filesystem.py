"""
CI/CDecoy — Virtual Filesystem

Builds an in-memory filesystem from base skeleton + profile JSON.
Supports runtime mutation (create/delete files and dirs) so attacker
actions persist within a session.
"""

import json
import logging
import os
import random
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

logger = logging.getLogger("cicdecoy.filesystem")


@dataclass
class FSNode:
    name: str
    path: str
    is_dir: bool = False
    content: str | None = None
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

    def get_node(self, path: str) -> FSNode | None:
        """Resolve a path and return the FSNode, or None."""
        return self._resolve(path)

    def is_directory(self, path: str) -> bool:
        node = self._resolve(path)
        return node is not None and node.is_dir

    def is_file(self, path: str) -> bool:
        node = self._resolve(path)
        return node is not None and not node.is_dir

    def file_exists(self, path: str) -> bool:
        """Return True if path exists (file or directory)."""
        return self._resolve(path) is not None

    def read_file(self, path: str) -> str | None:
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

    def create_file(self, path: str, content: str = "", owner: str = "root",
                    permissions: str = "0644"):
        parent_path = os.path.dirname(path)
        filename = os.path.basename(path)
        parent = self._resolve(parent_path)
        if parent and parent.is_dir:
            parent.children[filename] = FSNode(
                name=filename, path=path, content=content, owner=owner,
                permissions=permissions,
                modified=datetime.utcnow().strftime("%b %d %H:%M"),
            )
            return True
        return False

    def append_file(self, path: str, content: str):
        """Append content to an existing file, or create it."""
        node = self._resolve(path)
        if node and not node.is_dir:
            node.content = (node.content or "") + content
            node.size = len(node.content.encode("utf-8", errors="replace"))
            node.modified = datetime.utcnow().strftime("%b %d %H:%M")
            return True
        return self.create_file(path, content)

    def create_directory(self, path: str, owner: str = "root",
                         parents: bool = False):
        if parents:
            self._ensure_dir(path, owner=owner)
            return True

        parent_path = os.path.dirname(path)
        dirname = os.path.basename(path)
        parent = self._resolve(parent_path)
        if parent and parent.is_dir:
            if dirname in parent.children:
                return False  # Already exists
            parent.children[dirname] = FSNode(
                name=dirname, path=path, is_dir=True, owner=owner,
                permissions="0755",
                modified=datetime.utcnow().strftime("%b %d %H:%M"),
            )
            return True
        return False

    def remove_file(self, path: str) -> bool:
        """Remove a file (not a directory)."""
        parent_path = os.path.dirname(path)
        filename = os.path.basename(path)
        parent = self._resolve(parent_path)
        if parent and parent.is_dir and filename in parent.children:
            node = parent.children[filename]
            if not node.is_dir:
                del parent.children[filename]
                return True
        return False

    def remove_directory(self, path: str, recursive: bool = False) -> bool:
        """Remove a directory. If recursive=False, must be empty."""
        if path == "/":
            return False
        parent_path = os.path.dirname(path)
        dirname = os.path.basename(path)
        parent = self._resolve(parent_path)
        if parent and parent.is_dir and dirname in parent.children:
            node = parent.children[dirname]
            if not node.is_dir:
                return False
            if not recursive and node.children:
                return False
            del parent.children[dirname]
            return True
        return False

    def chmod(self, path: str, permissions: str) -> bool:
        node = self._resolve(path)
        if node:
            node.permissions = permissions
            return True
        return False

    def chown(self, path: str, owner: str, group: str | None = None) -> bool:
        node = self._resolve(path)
        if node:
            node.owner = owner
            if group:
                node.group = group
            return True
        return False

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
            "/proc", "/root", "/root/.ssh",
            "/run", "/sbin", "/srv", "/sys", "/tmp",
            "/usr", "/usr/bin", "/usr/lib", "/usr/local", "/usr/local/bin",
            "/usr/sbin", "/usr/share", "/var", "/var/cache", "/var/lib",
            "/var/log", "/var/mail", "/var/run", "/var/spool", "/var/tmp",
            "/var/backups",
        ]
        for d in dirs:
            self._ensure_dir(d)

        # ── Standard files ───────────────────────────
        self._add_file("/etc/passwd", self._gen_passwd(), "root", "0644")
        self._add_file("/etc/group", self._gen_group(), "root", "0644")
        self._add_file("/etc/shadow", "", "root", "0640")
        self._add_file("/etc/hostname", "localhost", "root", "0644")
        self._add_file("/etc/hosts",
                        "127.0.0.1\tlocalhost\n"
                        "127.0.1.1\tlocalhost\n"
                        "::1\t\tlocalhost ip6-localhost ip6-loopback\n"
                        "ff02::1\t\tip6-allnodes\n"
                        "ff02::2\t\tip6-allrouters",
                        "root", "0644")
        self._add_file("/etc/resolv.conf",
                        "nameserver 10.0.0.2\nsearch corp.internal",
                        "root", "0644")
        self._add_file("/etc/issue",
                        "Ubuntu 22.04.3 LTS \\n \\l\n\n", "root", "0644")
        self._add_file("/etc/os-release", (
            'PRETTY_NAME="Ubuntu 22.04.3 LTS"\n'
            'NAME="Ubuntu"\nVERSION_ID="22.04"\n'
            'VERSION="22.04.3 LTS (Jammy Jellyfish)"\n'
            'ID=ubuntu\nID_LIKE=debian\n'
            'HOME_URL="https://www.ubuntu.com/"\n'
            'SUPPORT_URL="https://help.ubuntu.com/"\n'
            'BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"'
        ), "root", "0644")
        self._add_file("/etc/lsb-release", (
            "DISTRIB_ID=Ubuntu\n"
            "DISTRIB_RELEASE=22.04\n"
            "DISTRIB_CODENAME=jammy\n"
            "DISTRIB_DESCRIPTION=\"Ubuntu 22.04.3 LTS\""
        ), "root", "0644")
        self._add_file("/etc/shells",
                        "/bin/sh\n/bin/bash\n/usr/bin/bash\n/bin/zsh",
                        "root", "0644")
        self._add_file("/etc/fstab", (
            "# /etc/fstab: static file system information.\n"
            "UUID=a1b2c3d4-e5f6-7890-abcd-ef1234567890 / ext4 errors=remount-ro 0 1\n"
            "/dev/sda2 none swap sw 0 0"
        ), "root", "0644")
        self._add_file("/etc/timezone", "Etc/UTC", "root", "0644")
        self._add_file("/etc/localtime", "", "root", "0644")
        self._add_file("/etc/machine-id",
                        "a1b2c3d4e5f67890abcdef1234567890", "root", "0444")
        self._add_file("/etc/ssh/sshd_config", (
            "# OpenBSD Secure Shell server configuration\n"
            "Port 22\n"
            "PermitRootLogin prohibit-password\n"
            "PubkeyAuthentication yes\n"
            "PasswordAuthentication yes\n"
            "ChallengeResponseAuthentication no\n"
            "UsePAM yes\n"
            "X11Forwarding yes\n"
            "PrintMotd no\n"
            "AcceptEnv LANG LC_*\n"
            "Subsystem sftp /usr/lib/openssh/sftp-server"
        ), "root", "0644")
        self._add_file("/etc/crontab", (
            "# /etc/crontab: system-wide crontab\n"
            "SHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n"
            "\n# m h dom mon dow user  command\n"
            "17 * * * * root cd / && run-parts --report /etc/cron.hourly\n"
            "25 6 * * * root test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )\n"
            "47 6 * * 7 root test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )\n"
            "52 6 1 * * root test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )\n"
        ), "root", "0644")

        # /dev device stubs — prevent honeypot detection via device file tests
        self._ensure_dir("/dev/pts")
        self._ensure_dir("/dev/shm")
        self._add_file("/dev/null", "", "root", "0666")
        self._add_file("/dev/zero", "", "root", "0666")
        self._add_file("/dev/random", "", "root", "0666")
        self._add_file("/dev/urandom", "", "root", "0666")
        self._add_file("/dev/tty", "", "root", "0666")
        self._add_file("/dev/stdin", "", "root", "0777")
        self._add_file("/dev/stdout", "", "root", "0777")
        self._add_file("/dev/stderr", "", "root", "0777")
        self._add_file("/dev/full", "", "root", "0666")

        # /proc stubs
        self._add_file("/proc/version",
                        "Linux version 5.15.0-91-generic "
                        "(buildd@lcy02-amd64-032) "
                        "(gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, "
                        "GNU ld (GNU Binutils for Ubuntu) 2.38) "
                        "#101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023",
                        "root", "0444")
        self._add_file("/proc/cpuinfo", self._gen_cpuinfo(), "root", "0444")
        self._add_file("/proc/meminfo", self._gen_meminfo(), "root", "0444")

        # /proc/self stubs — prevent honeypot detection via process introspection
        self._ensure_dir("/proc/self")
        self._add_file("/proc/self/status",
                        "Name:\tbash\n"
                        "Umask:\t0022\n"
                        "State:\tS (sleeping)\n"
                        "Tgid:\t1\n"
                        "Ngid:\t0\n"
                        "Pid:\t1\n"
                        "PPid:\t0\n"
                        "TracerPid:\t0\n"
                        "Uid:\t0\t0\t0\t0\n"
                        "Gid:\t0\t0\t0\t0\n"
                        "VmPeak:\t   12340 kB\n"
                        "VmSize:\t   12340 kB\n"
                        "VmRSS:\t    8192 kB\n"
                        "Threads:\t1\n",
                        "root", "0444")
        self._add_file("/proc/self/cmdline", "-bash\x00", "root", "0444")
        self._add_file("/proc/self/exe", "/bin/bash", "root", "0444")
        self._add_file("/proc/self/comm", "bash", "root", "0444")

        # /var/log stubs
        self._add_file("/var/log/syslog", "", "root", "0640")
        self._add_file("/var/log/auth.log", "", "root", "0640")
        self._add_file("/var/log/kern.log", "", "root", "0640")
        self._add_file("/var/log/dpkg.log", "", "root", "0640")
        self._add_file("/var/log/apt/history.log", "", "root", "0640")

        # Root home
        self._add_file("/root/.bashrc", self._gen_bashrc("root"), "root", "0644")
        self._add_file("/root/.profile",
                        "# ~/.profile\nif [ -f ~/.bashrc ]; then . ~/.bashrc; fi\n"
                        "mesg n 2>/dev/null || true",
                        "root", "0644")

    def _load_profile(self, profile_name: str):
        """Load profile JSON from the profiles directory."""
        profiles_dir = os.environ.get("PROFILES_DIR", "/etc/cicdecoy/profiles")

        if not re.match(r'^[a-zA-Z0-9_-]+$', profile_name):
            logger.error(f"Invalid profile name (must be alphanumeric/dash/underscore): {profile_name}")
            self._set_default_profile_data()
            return

        profile_path = Path(profiles_dir) / f"{profile_name}.json"

        # Ensure resolved path is still within profiles_dir
        if not str(profile_path.resolve()).startswith(str(Path(profiles_dir).resolve())):
            logger.error(f"Profile path escapes profiles directory: {profile_name}")
            self._set_default_profile_data()
            return

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
            passwd_lines += (
                f"{user['name']}:x:{uid}:{uid}:{full_name}:{home}:{shell}\n"
            )

            # Create home directory with standard dotfiles
            self._ensure_dir(home)
            self._ensure_dir(f"{home}/.ssh")
            self._ensure_dir(f"{home}/.local")
            self._ensure_dir(f"{home}/.config")

            self._add_file(f"{home}/.bashrc",
                           self._gen_bashrc(user["name"]),
                           user["name"], "0644")
            self._add_file(f"{home}/.profile",
                           "# ~/.profile\n. ~/.bashrc\n",
                           user["name"], "0644")
            self._add_file(f"{home}/.bash_history", "", user["name"], "0600")

        self._add_file("/etc/passwd", passwd_lines, "root", "0644")

        # Update /etc/hosts if present in profile
        hosts_content = profile.get("filesystem_extras", {}).get("/etc/hosts")
        if hosts_content:
            self._add_file("/etc/hosts", hosts_content, "root", "0644")

        # Add filesystem extras from profile
        for filepath, content in profile.get("filesystem_extras", {}).items():
            if filepath == "/etc/hosts":
                continue
            parent = os.path.dirname(filepath)
            self._ensure_dir(parent)
            owner = "root"
            for user in profile.get("users", []):
                if filepath.startswith(user.get("home", f"/home/{user['name']}")):
                    owner = user["name"]
                    break
            self._add_file(filepath, content, owner, "0644")

        # Build profile data for system-info commands
        procs = [
            {"pid": 1, "command": "/sbin/init", "user": "root"},
            {"pid": 452, "command": "/usr/sbin/sshd -D", "user": "root"},
            {"pid": 610, "command": "/usr/sbin/cron -f", "user": "root"},
            {"pid": 620, "command": "/lib/systemd/systemd-journald",
             "user": "root"},
            {"pid": 645, "command": "/lib/systemd/systemd-logind",
             "user": "root"},
            {"pid": 680, "command": "/usr/bin/dbus-daemon --system",
             "user": "messagebus"},
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
                f"{profile.get('system', {}).get('uptime', '14 days, 5:23')}, "
                "1 user,  load average: 0.08, 0.04, 0.01"),
            "memory": profile.get("static_responses", {}).get("free -h", ""),
            "disk": profile.get("static_responses", {}).get("df -h", ""),
            "static_responses": profile.get("static_responses", {}),
            "interfaces": profile.get("system", {}).get("interfaces", []),
        }

    def _set_default_profile_data(self):
        self.profile_data = {
            "processes": [
                {"pid": 1, "command": "/sbin/init", "user": "root"},
                {"pid": 452, "command": "/usr/sbin/sshd -D", "user": "root"},
                {"pid": 610, "command": "/usr/sbin/cron -f", "user": "root"},
                {"pid": 620, "command": "/lib/systemd/systemd-journald",
                 "user": "root"},
                {"pid": 645, "command": "/lib/systemd/systemd-logind",
                 "user": "root"},
            ],
            "static_responses": {},
            "interfaces": [],
        }

    # ── Tree helpers ─────────────────────────────────

    def _resolve(self, path: str) -> FSNode | None:
        if path == "/":
            return self.root
        parts = [p for p in path.split("/") if p]
        current = self.root
        for part in parts:
            if not current.is_dir or part not in current.children:
                return None
            current = current.children[part]
        return current

    def _ensure_dir(self, path: str, owner: str = "root"):
        parts = [p for p in path.split("/") if p]
        current = self.root
        built = ""
        for part in parts:
            built += f"/{part}"
            if part not in current.children:
                current.children[part] = FSNode(
                    name=part, path=built, is_dir=True,
                    owner=owner, permissions="0755",
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

    # ── Content generators ───────────────────────────

    @staticmethod
    def _gen_passwd() -> str:
        return (
            "root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
            "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
            "sync:x:4:65534:sync:/bin:/bin/sync\n"
            "games:x:5:60:games:/usr/games:/usr/sbin/nologin\n"
            "man:x:6:12:man:/var/cache/man:/usr/sbin/nologin\n"
            "lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\n"
            "mail:x:8:8:mail:/var/mail:/usr/sbin/nologin\n"
            "news:x:10:10:news:/var/spool/news:/usr/sbin/nologin\n"
            "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
            "backup:x:34:34:backup:/var/backups:/usr/sbin/nologin\n"
            "list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin\n"
            "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
            "systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin\n"
            "systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin\n"
            "messagebus:x:102:105::/nonexistent:/usr/sbin/nologin\n"
            "sshd:x:110:65534::/run/sshd:/usr/sbin/nologin\n"
        )

    @staticmethod
    def _gen_group() -> str:
        return (
            "root:x:0:\n"
            "daemon:x:1:\n"
            "bin:x:2:\n"
            "sys:x:3:\n"
            "adm:x:4:\n"
            "sudo:x:27:\n"
            "www-data:x:33:\n"
            "backup:x:34:\n"
            "shadow:x:42:\n"
            "docker:x:998:\n"
            "developers:x:1001:\n"
        )

    @staticmethod
    def _gen_bashrc(username: str) -> str:
        return (
            "# ~/.bashrc: executed by bash(1) for non-login shells.\n\n"
            "# If not running interactively, don't do anything\n"
            '[ -z "$PS1" ] && return\n\n'
            "# don't put duplicate lines or lines starting with space in the history.\n"
            "HISTCONTROL=ignoreboth\n\n"
            "# append to the history file, don't overwrite it\n"
            "shopt -s histappend\n\n"
            "HISTSIZE=1000\n"
            "HISTFILESIZE=2000\n\n"
            "# check the window size after each command\n"
            "shopt -s checkwinsize\n\n"
            "# set a fancy prompt\n"
            "PS1='\\u@\\h:\\w\\$ '\n\n"
            "# enable color support\n"
            "alias ls='ls --color=auto'\n"
            "alias ll='ls -alF'\n"
            "alias la='ls -A'\n"
            "alias l='ls -CF'\n"
            "alias grep='grep --color=auto'\n"
            "alias fgrep='fgrep --color=auto'\n"
            "alias egrep='egrep --color=auto'\n"
        )

    @staticmethod
    def _gen_cpuinfo() -> str:
        core_template = (
            "processor\t: {n}\n"
            "vendor_id\t: GenuineIntel\n"
            "cpu family\t: 6\n"
            "model\t\t: 85\n"
            "model name\t: Intel(R) Xeon(R) Platinum 8275CL CPU @ 3.00GHz\n"
            "stepping\t: 7\n"
            "cpu MHz\t\t: 2999.998\n"
            "cache size\t: 36608 KB\n"
            "physical id\t: 0\n"
            "siblings\t: 4\n"
            "core id\t\t: {n}\n"
            "cpu cores\t: 4\n"
            "bogomips\t: 5999.99\n"
            "flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss ht syscall nx pdpe1gb rdtscp lm constant_tsc arch_perfmon rep_good nopl xtopology\n"
        )
        return "\n".join(core_template.format(n=i) for i in range(4))

    @staticmethod
    def _gen_meminfo() -> str:
        total_kb = 8167452
        free_kb = random.randint(2000000, 4000000)
        avail_kb = free_kb + random.randint(500000, 1500000)
        buffers_kb = random.randint(50000, 200000)
        cached_kb = random.randint(1000000, 2500000)
        return (
            f"MemTotal:       {total_kb} kB\n"
            f"MemFree:        {free_kb} kB\n"
            f"MemAvailable:   {avail_kb} kB\n"
            f"Buffers:        {buffers_kb} kB\n"
            f"Cached:         {cached_kb} kB\n"
            f"SwapTotal:      2097148 kB\n"
            f"SwapFree:       2097148 kB\n"
        )


def _perm_bits(octal: str) -> str:
    result = ""
    for digit in octal[-3:]:
        d = int(digit)
        result += "r" if d & 4 else "-"
        result += "w" if d & 2 else "-"
        result += "x" if d & 1 else "-"
    return result
