#!/usr/bin/env python3
"""
CI/CDecoy — Response Capture Tool

Connects to a real system (or a VM you control) and captures command
outputs to build a scripted response database. This is how you create
high-fidelity Tier 2 response sets without an LLM.

Usage:
    # Capture from a live system:
    python capture_responses.py \
        --host 192.168.1.100 \
        --user admin \
        --key ~/.ssh/id_rsa \
        --profile dev-workstation \
        --output responses/ubuntu-22.04-full.json

    # Capture from localhost (for building from a VM):
    python capture_responses.py \
        --local \
        --profile dev-workstation \
        --output responses/ubuntu-22.04-full.json

    # Merge additional captures into existing database:
    python capture_responses.py \
        --host 192.168.1.100 \
        --user admin \
        --existing responses/ubuntu-22.04-full.json \
        --commands-file extra-commands.txt \
        --output responses/ubuntu-22.04-full.json

The output JSON is used directly by the high-fidelity scripted engine.
"""

import argparse
import json
import logging
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

logger = logging.getLogger("cicdecoy.capture")

# ─────────────────────────────────────────────────────────
#  Command Sets — what to capture from the target system
# ─────────────────────────────────────────────────────────

# Commands organized by category. Each attacker reconnaissance
# phase maps to a set of commands they'd typically run.

RECON_COMMANDS = [
    # Identity
    "whoami", "id", "groups", "hostname", "hostname -f",
    "uname", "uname -a", "uname -r", "uname -m", "uname -n",
    "arch", "nproc",

    # System info
    "cat /etc/os-release", "cat /etc/issue", "cat /etc/hostname",
    "cat /etc/machine-id", "lsb_release -a",
    "hostnamectl", "timedatectl",
    "uptime", "date", "date -u", "w", "last -5",
    "cat /proc/version", "cat /proc/cpuinfo",
    "lscpu",

    # Users & auth
    "cat /etc/passwd", "cat /etc/group", "cat /etc/shadow",
    "cat /etc/sudoers", "getent passwd", "getent group",
    "who", "users", "finger",
    "cat /etc/login.defs",

    # Network
    "ifconfig", "ifconfig -a",
    "ip addr", "ip a", "ip addr show",
    "ip route", "ip route show", "ip r",
    "ip link", "ip link show",
    "ip neigh", "ip neigh show",
    "cat /etc/resolv.conf", "cat /etc/hosts",
    "cat /etc/networks",
    "netstat -tlnp", "netstat -anp", "netstat -rn",
    "ss -tlnp", "ss -anp", "ss -s",
    "arp -a", "route -n",
    "cat /etc/network/interfaces",
    "cat /etc/netplan/01-netcfg.yaml",
    "iptables -L -n", "iptables -L -n -v",
    "nft list ruleset",

    # Filesystem
    "df -h", "df -i",
    "mount", "cat /etc/fstab",
    "lsblk", "lsblk -f",
    "fdisk -l",
    "du -sh /home/*", "du -sh /tmp", "du -sh /var/log",
    "findmnt",

    # Memory & processes
    "free -h", "free -m",
    "cat /proc/meminfo",
    "ps aux", "ps -ef", "ps auxf",
    "top -b -n 1 | head -30",
    "pstree",

    # Services
    "systemctl list-units --type=service --state=running",
    "systemctl list-units --type=service",
    "systemctl status sshd", "systemctl status cron",
    "service --status-all",
    "cat /etc/crontab", "crontab -l",
    "ls /etc/cron.d/", "ls /etc/cron.daily/",

    # Software
    "dpkg -l | head -50", "dpkg -l | wc -l",
    "apt list --installed 2>/dev/null | head -50",
    "pip3 list 2>/dev/null", "pip list 2>/dev/null",
    "npm -g list 2>/dev/null",
    "which python3", "python3 --version",
    "which node", "node --version",
    "which docker", "docker --version",
    "which git", "git --version",
    "which curl", "which wget",
    "which gcc", "which make",
    "which java", "java -version 2>&1",
    "which go", "go version 2>/dev/null",
    "which ruby", "ruby --version 2>/dev/null",

    # Docker (if present)
    "docker ps", "docker ps -a",
    "docker images", "docker images -a",
    "docker network ls",
    "docker volume ls",
    "docker info 2>/dev/null | head -20",

    # Kubernetes (if present)
    "kubectl version --short 2>/dev/null",
    "kubectl get nodes 2>/dev/null",
    "kubectl get pods --all-namespaces 2>/dev/null",
    "kubectl config get-contexts 2>/dev/null",

    # SSH
    "cat /etc/ssh/sshd_config",
    "ls -la ~/.ssh/",
    "cat ~/.ssh/authorized_keys 2>/dev/null",
    "cat ~/.ssh/config 2>/dev/null",
    "ssh-keygen -l -f /etc/ssh/ssh_host_rsa_key.pub 2>/dev/null",

    # Environment
    "env", "printenv",
    "echo $PATH", "echo $HOME", "echo $SHELL", "echo $USER",
    "echo $LANG", "echo $TERM",
    "locale",
    "cat ~/.bashrc", "cat ~/.bash_profile", "cat ~/.profile",
    "cat ~/.bash_history 2>/dev/null | tail -30",

    # Logs (may need root)
    "ls -la /var/log/",
    "tail -20 /var/log/syslog 2>/dev/null",
    "tail -20 /var/log/auth.log 2>/dev/null",
    "journalctl --no-pager -n 20 2>/dev/null",
    "dmesg | tail -20",

    # Security / capabilities
    "sudo -l 2>/dev/null",
    "cat /etc/pam.d/common-auth 2>/dev/null",
    "sestatus 2>/dev/null",
    "aa-status 2>/dev/null",
    "ls -la /etc/apparmor.d/ 2>/dev/null",
    "getfattr -d -m '' /usr/bin/passwd 2>/dev/null",
    "find / -perm -4000 -type f 2>/dev/null | head -20",
    "find / -perm -2000 -type f 2>/dev/null | head -20",
    "cat /proc/self/status | grep -i cap",
    "capsh --print 2>/dev/null",

    # Common file listings
    "ls -la /", "ls -la /etc/", "ls -la /home/",
    "ls -la /opt/", "ls -la /var/", "ls -la /tmp/",
    "ls -la /usr/local/bin/", "ls -la /root/ 2>/dev/null",
]

# Commands that are context-sensitive (need arguments from the system)
DYNAMIC_COMMANDS = {
    # These get expanded based on what's found on the system
    "ls_home_dirs": "for d in /home/*/; do echo '=== '$d' ==='; ls -la $d; done",
    "systemctl_services": "systemctl list-units --type=service --state=running --no-pager",
    "listening_ports": "ss -tlnp | grep LISTEN",
    "installed_packages_count": "dpkg -l 2>/dev/null | wc -l || rpm -qa 2>/dev/null | wc -l",
}


# ─────────────────────────────────────────────────────────
#  Response Database Format
# ─────────────────────────────────────────────────────────

@dataclass
class CapturedResponse:
    """A single captured command-response pair."""
    command: str
    output: str
    exit_code: int = 0
    duration_ms: int = 0
    category: str = "general"
    # Metadata for template generation
    is_empty: bool = False
    is_error: bool = False
    line_count: int = 0

@dataclass
class ResponseDatabase:
    """Complete response database for a response set."""
    name: str                                    # e.g., "ubuntu-22.04-full"
    description: str = ""
    source_os: str = ""
    source_kernel: str = ""
    source_hostname: str = ""
    captured_at: str = ""
    command_count: int = 0
    responses: dict = field(default_factory=dict)  # command → CapturedResponse

    def to_json(self) -> str:
        data = {
            "name": self.name,
            "description": self.description,
            "source_os": self.source_os,
            "source_kernel": self.source_kernel,
            "source_hostname": self.source_hostname,
            "captured_at": self.captured_at,
            "command_count": len(self.responses),
            "responses": {},
        }
        for cmd, resp in self.responses.items():
            data["responses"][cmd] = {
                "output": resp.output,
                "exit_code": resp.exit_code,
                "duration_ms": resp.duration_ms,
                "category": resp.category,
                "is_error": resp.is_error,
                "line_count": resp.line_count,
            }
        return json.dumps(data, indent=2)

    @classmethod
    def from_json(cls, path: str) -> "ResponseDatabase":
        with open(path) as f:
            data = json.load(f)
        db = cls(
            name=data["name"],
            description=data.get("description", ""),
            source_os=data.get("source_os", ""),
            source_kernel=data.get("source_kernel", ""),
            source_hostname=data.get("source_hostname", ""),
            captured_at=data.get("captured_at", ""),
        )
        for cmd, resp_data in data.get("responses", {}).items():
            db.responses[cmd] = CapturedResponse(
                command=cmd,
                output=resp_data["output"],
                exit_code=resp_data.get("exit_code", 0),
                duration_ms=resp_data.get("duration_ms", 0),
                category=resp_data.get("category", "general"),
                is_error=resp_data.get("is_error", False),
                line_count=resp_data.get("line_count", 0),
            )
        return db


# ─────────────────────────────────────────────────────────
#  Capture Backends
# ─────────────────────────────────────────────────────────

class LocalCapture:
    """Capture responses from the local machine."""

    def run(self, command: str, timeout: int = 10) -> CapturedResponse:
        start = time.time()
        try:
            result = subprocess.run(
                command, shell=True, capture_output=True,
                text=True, timeout=timeout,
            )
            duration = int((time.time() - start) * 1000)
            output = result.stdout
            if result.returncode != 0 and result.stderr:
                output = result.stderr if not output else output
            return CapturedResponse(
                command=command,
                output=output.rstrip("\n"),
                exit_code=result.returncode,
                duration_ms=duration,
                is_empty=len(output.strip()) == 0,
                is_error=result.returncode != 0,
                line_count=len(output.strip().split("\n")) if output.strip() else 0,
            )
        except subprocess.TimeoutExpired:
            return CapturedResponse(
                command=command, output="", exit_code=124,
                duration_ms=timeout * 1000, is_error=True,
            )
        except Exception as e:
            return CapturedResponse(
                command=command, output=str(e), exit_code=1, is_error=True,
            )


class SSHCapture:
    """Capture responses from a remote system via SSH."""

    def __init__(self, host: str, user: str, key_path: Optional[str] = None,
                 password: Optional[str] = None, port: int = 22):
        self.host = host
        self.user = user
        self.key_path = key_path
        self.password = password
        self.port = port

    def run(self, command: str, timeout: int = 10) -> CapturedResponse:
        ssh_cmd = ["ssh", "-o", "StrictHostKeyChecking=no",
                    "-o", "BatchMode=yes",
                    "-p", str(self.port)]
        if self.key_path:
            ssh_cmd.extend(["-i", self.key_path])
        ssh_cmd.extend([f"{self.user}@{self.host}", command])

        start = time.time()
        try:
            result = subprocess.run(
                ssh_cmd, capture_output=True, text=True, timeout=timeout,
            )
            duration = int((time.time() - start) * 1000)
            output = result.stdout
            if result.returncode != 0 and result.stderr:
                output = result.stderr if not output else output
            return CapturedResponse(
                command=command,
                output=output.rstrip("\n"),
                exit_code=result.returncode,
                duration_ms=duration,
                is_empty=len(output.strip()) == 0,
                is_error=result.returncode != 0,
                line_count=len(output.strip().split("\n")) if output.strip() else 0,
            )
        except subprocess.TimeoutExpired:
            return CapturedResponse(
                command=command, output="", exit_code=124,
                duration_ms=timeout * 1000, is_error=True,
            )
        except Exception as e:
            return CapturedResponse(
                command=command, output=str(e), exit_code=1, is_error=True,
            )


# ─────────────────────────────────────────────────────────
#  Capture Orchestrator
# ─────────────────────────────────────────────────────────

def categorize_command(command: str) -> str:
    """Assign a category to a command for organization."""
    categories = {
        "identity":   ["whoami", "id", "groups", "hostname", "uname"],
        "system":     ["cat /etc/os", "cat /etc/issue", "uptime", "date",
                       "lsb_release", "hostnamectl", "timedatectl", "cat /proc"],
        "users":      ["cat /etc/passwd", "cat /etc/group", "cat /etc/shadow",
                       "who", "users", "last", "getent", "finger"],
        "network":    ["ifconfig", "ip addr", "ip route", "netstat", "ss ",
                       "arp", "route", "cat /etc/resolv", "cat /etc/hosts",
                       "iptables", "nft"],
        "filesystem": ["df", "mount", "lsblk", "fdisk", "du ", "findmnt",
                       "cat /etc/fstab"],
        "processes":  ["free", "ps ", "top", "pstree", "cat /proc/mem"],
        "services":   ["systemctl", "service", "crontab", "cat /etc/cron",
                       "ls /etc/cron"],
        "software":   ["dpkg", "apt ", "pip", "npm", "which", "python",
                       "node ", "docker", "git ", "java", "go ", "ruby"],
        "docker":     ["docker ps", "docker images", "docker network",
                       "docker volume", "docker info"],
        "kubernetes": ["kubectl"],
        "ssh":        ["cat /etc/ssh", "ls.*ssh", "ssh-keygen"],
        "environment":["env", "printenv", "echo $", "locale", "cat ~/"],
        "logs":       ["tail.*log", "journalctl", "dmesg", "ls.*log"],
        "security":   ["sudo", "pam", "sestatus", "aa-status", "apparmor",
                       "find.*perm", "capsh", "getfattr"],
        "listing":    ["ls -la"],
    }
    for cat, patterns in categories.items():
        for pattern in patterns:
            if pattern in command:
                return cat
    return "general"


def run_capture(
    backend,
    commands: list[str],
    existing_db: Optional[ResponseDatabase] = None,
    profile_name: str = "",
) -> ResponseDatabase:
    """Run all commands and build the response database."""
    if existing_db:
        db = existing_db
    else:
        db = ResponseDatabase(
            name=f"{profile_name or 'custom'}-responses",
            captured_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        )

    # Capture basic system info first
    os_info = backend.run("cat /etc/os-release")
    kernel_info = backend.run("uname -r")
    hostname_info = backend.run("hostname")
    db.source_os = os_info.output.split("\n")[0] if os_info.output else "unknown"
    db.source_kernel = kernel_info.output.strip() if kernel_info.output else "unknown"
    db.source_hostname = hostname_info.output.strip() if hostname_info.output else "unknown"

    total = len(commands)
    success = 0
    errors = 0

    for i, command in enumerate(commands):
        progress = f"[{i+1}/{total}]"
        logger.info(f"{progress} Capturing: {command}")

        response = backend.run(command)
        response.category = categorize_command(command)

        if response.is_error and response.exit_code == 124:
            logger.warning(f"{progress} Timeout: {command}")
            errors += 1
            continue

        db.responses[command] = response
        success += 1

        # Brief delay to avoid overwhelming the target
        time.sleep(0.1)

    db.command_count = len(db.responses)
    db.description = (
        f"Captured {success} responses from {db.source_hostname} "
        f"({db.source_os}), {errors} errors"
    )

    logger.info(f"Capture complete: {success} success, {errors} errors")
    return db


# ─────────────────────────────────────────────────────────
#  Post-Processing
# ─────────────────────────────────────────────────────────

def sanitize_database(db: ResponseDatabase, replacements: dict) -> ResponseDatabase:
    """
    Replace real values with decoy values in captured responses.

    Example replacements:
    {
        "real-hostname": "decoy-hostname",
        "192.168.1.100": "10.0.1.50",
        "real-user": "admin",
    }
    """
    for cmd, response in db.responses.items():
        output = response.output
        for real, fake in replacements.items():
            output = output.replace(real, fake)
        response.output = output

    # Also sanitize metadata
    for real, fake in replacements.items():
        db.source_hostname = db.source_hostname.replace(real, fake)
        db.source_os = db.source_os.replace(real, fake)

    return db


# ─────────────────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────────────────

def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    parser = argparse.ArgumentParser(
        description="Capture command responses for CI/CDecoy response databases"
    )
    parser.add_argument("--host", help="Remote host to capture from")
    parser.add_argument("--user", default="root", help="SSH username")
    parser.add_argument("--key", help="SSH private key path")
    parser.add_argument("--port", type=int, default=22, help="SSH port")
    parser.add_argument("--local", action="store_true", help="Capture from localhost")
    parser.add_argument("--profile", default="", help="Profile name for labeling")
    parser.add_argument("--output", required=True, help="Output JSON path")
    parser.add_argument("--existing", help="Existing database to merge into")
    parser.add_argument("--commands-file", help="Extra commands file (one per line)")
    parser.add_argument("--sanitize", help="JSON file with string replacements")

    args = parser.parse_args()

    # Choose backend
    if args.local:
        backend = LocalCapture()
    elif args.host:
        backend = SSHCapture(args.host, args.user, args.key, port=args.port)
    else:
        parser.error("Specify --host or --local")
        return

    # Build command list
    commands = list(RECON_COMMANDS)
    if args.commands_file:
        with open(args.commands_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    commands.append(line)

    # Load existing database if merging
    existing = None
    if args.existing and Path(args.existing).exists():
        existing = ResponseDatabase.from_json(args.existing)
        logger.info(f"Loaded existing database: {existing.command_count} responses")

    # Run capture
    db = run_capture(backend, commands, existing, args.profile)

    # Sanitize if requested
    if args.sanitize:
        with open(args.sanitize) as f:
            replacements = json.load(f)
        db = sanitize_database(db, replacements)
        logger.info(f"Applied {len(replacements)} sanitization rules")

    # Save
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w") as f:
        f.write(db.to_json())

    logger.info(f"Saved {db.command_count} responses to {args.output}")


if __name__ == "__main__":
    main()
