"""
CI/CDecoy — CTI Enrichment

Classifies attacker behavior into MITRE ATT&CK techniques,
detects offensive tool signatures, and assigns severity.

Two analysis modes:
  1. Command-level:  classify_command() — per-command enrichment
  2. Delta-level:    classify_fs_delta() — per-session filesystem analysis

The delta classifier examines what the attacker left on disk:
file paths, content, permissions, and mutation patterns. This
catches indicators that command-level analysis misses — tools
downloaded but not yet executed, persistence mechanisms installed
via redirection, credential material staged for exfiltration.

Used by the CTI collector pipeline to enrich events before storage.
"""

import re
import logging
from typing import Optional

logger = logging.getLogger("cicdecoy.enrichment")


# ═══════════════════════════════════════════════════════
#  MITRE ATT&CK — Command-to-Technique Mapping
# ═══════════════════════════════════════════════════════

MITRE_COMMAND_MAP = [
    # Discovery
    (r"\bwhoami\b", "T1033", "System Owner/User Discovery", "discovery"),
    (r"\bid\b", "T1033", "System Owner/User Discovery", "discovery"),
    (r"\buname\b", "T1082", "System Information Discovery", "discovery"),
    (r"\bhostname\b", "T1082", "System Information Discovery", "discovery"),
    (r"\bcat\s+/etc/(passwd|shadow|group)", "T1003.008", "/etc/passwd and /etc/shadow", "credential-access"),
    (r"\bcat\s+/etc/(issue|os-release|lsb-release)", "T1082", "System Information Discovery", "discovery"),
    (r"\bls\b.*\b(/root|/home|\.ssh|\.gnupg)", "T1083", "File and Directory Discovery", "discovery"),
    (r"\bfind\b.*\.(pem|key|crt|p12|pfx)", "T1083", "File and Directory Discovery", "discovery"),
    (r"\bnetstat\b|\bss\b", "T1049", "System Network Connections Discovery", "discovery"),
    (r"\bifconfig\b|\bip\s+addr", "T1016", "System Network Configuration Discovery", "discovery"),
    (r"\bps\b\s+aux", "T1057", "Process Discovery", "discovery"),
    (r"\bdf\b|\bmount\b", "T1082", "System Information Discovery", "discovery"),
    (r"\benv\b|\bprintenv\b", "T1082", "System Information Discovery", "discovery"),
    (r"\bw\b$|\bwho\b", "T1033", "System Owner/User Discovery", "discovery"),
    (r"\blast\b|\blastlog\b", "T1033", "System Owner/User Discovery", "discovery"),
    (r"\bcat\s+/proc/", "T1082", "System Information Discovery", "discovery"),
    (r"\blsblk\b|\bfdisk\b|\blsusb\b|\blspci\b", "T1082", "System Information Discovery", "discovery"),
    (r"\barp\b|\broute\b|\bip\s+route", "T1016", "System Network Configuration Discovery", "discovery"),
    # Credential access
    (r"\bcat\s+.*\.ssh/(id_rsa|id_ed25519|authorized_keys)", "T1552.004", "Private Keys", "credential-access"),
    (r"\bsudo\b", "T1548.003", "Sudo and Sudo Caching", "privilege-escalation"),
    (r"\bpasswd\b", "T1003", "OS Credential Dumping", "credential-access"),
    # Execution
    (r"\bwget\b|\bcurl\b.*\b(http|ftp)://", "T1105", "Ingress Tool Transfer", "command-and-control"),
    (r"\bchmod\s+\+x\b", "T1059.004", "Unix Shell", "execution"),
    (r"\bbash\s+-[ci]\b|\bsh\s+-[ci]\b", "T1059.004", "Unix Shell", "execution"),
    (r"\bpython[23]?\s+-c\b", "T1059.006", "Python", "execution"),
    (r"\bperl\s+-e\b", "T1059", "Command and Scripting Interpreter", "execution"),
    (r"\bnc\b.*-[el]|\bncat\b", "T1059.004", "Unix Shell", "execution"),
    # Lateral movement
    (r"\bssh\b\s+\w+@", "T1021.004", "SSH", "lateral-movement"),
    (r"\bscp\b\s+", "T1021.004", "SSH", "lateral-movement"),
    (r"\brsync\b.*@", "T1021.004", "SSH", "lateral-movement"),
    # Collection / Exfiltration
    (r"\btar\b.*\b(czf|cjf|cf)\b", "T1560.001", "Archive via Utility", "collection"),
    (r"\bzip\b|\bgzip\b", "T1560.001", "Archive via Utility", "collection"),
    (r"\bbase64\b", "T1132.001", "Standard Encoding", "command-and-control"),
    # Persistence
    (r"\bcrontab\b", "T1053.003", "Cron", "persistence"),
    (r"\.bashrc|\.bash_profile|\.profile", "T1546.004", "Unix Shell Configuration Modification", "persistence"),
    (r"\bsystemctl\b.*enable", "T1543.002", "Systemd Service", "persistence"),
    # Defense evasion
    (r"\bunset\s+HISTFILE|\bexport\s+HISTFILE=/dev/null", "T1070.003", "Clear Command History", "defense-evasion"),
    (r"\bhistory\s+-c\b", "T1070.003", "Clear Command History", "defense-evasion"),
    (r"\brm\s+.*\.bash_history", "T1070.003", "Clear Command History", "defense-evasion"),
    (r"\biptables\b.*-D|\biptables\b.*-F", "T1562.004", "Disable or Modify System Firewall", "defense-evasion"),
]


# ═══════════════════════════════════════════════════════
#  MITRE ATT&CK — Filesystem Path Indicators
#
#  These classify attacker intent based on WHERE they
#  write files, not what commands they typed.
# ═══════════════════════════════════════════════════════

# (path_pattern, technique_id, technique_name, tactic)
MITRE_PATH_MAP = [
    # Persistence — SSH authorized_keys injection
    (r"\.ssh/authorized_keys$", "T1098.004",
     "SSH Authorized Keys", "persistence"),

    # Persistence — cron
    (r"/etc/cron\.|/var/spool/cron|/etc/crontab",
     "T1053.003", "Cron", "persistence"),

    # Persistence — init/systemd
    (r"/etc/init\.d/|/etc/systemd/system/|/lib/systemd/system/",
     "T1543.002", "Systemd Service", "persistence"),

    # Persistence — shell profile modification
    (r"\.(bashrc|bash_profile|profile|zshrc)$",
     "T1546.004", "Unix Shell Configuration Modification", "persistence"),

    # Persistence — LD_PRELOAD / linker hijack
    (r"/etc/ld\.so\.(preload|conf)",
     "T1574.006", "Dynamic Linker Hijacking", "persistence"),

    # Credential access — writing/reading key material
    (r"\.ssh/(id_rsa|id_ed25519|id_ecdsa)$",
     "T1552.004", "Private Keys", "credential-access"),
    (r"\.(pem|key|p12|pfx|keystore)$",
     "T1552.004", "Private Keys", "credential-access"),

    # Credential access — cloud/service credentials
    (r"\.aws/(credentials|config)$",
     "T1552.001", "Credentials In Files", "credential-access"),
    (r"\.kube/config$",
     "T1552.001", "Credentials In Files", "credential-access"),
    (r"\.docker/config\.json$",
     "T1552.001", "Credentials In Files", "credential-access"),
    (r"\.git-credentials$|\.netrc$",
     "T1552.001", "Credentials In Files", "credential-access"),
    (r"\.env$|\.env\.\w+$",
     "T1552.001", "Credentials In Files", "credential-access"),

    # Execution — staging in world-writable dirs
    (r"^/(tmp|dev/shm|var/tmp)/.*\.(sh|py|pl|elf|bin)$",
     "T1059.004", "Unix Shell", "execution"),

    # Defense evasion — log tampering
    (r"/var/log/(auth|syslog|kern|wtmp|btmp|lastlog)",
     "T1070.002", "Clear Linux or Mac System Logs", "defense-evasion"),

    # Defense evasion — history deletion
    (r"\.bash_history$",
     "T1070.003", "Clear Command History", "defense-evasion"),

    # Collection — staging archives
    (r"^/(tmp|dev/shm)/.*\.(tar|gz|zip|7z|bz2)$",
     "T1074.001", "Local Data Staging", "collection"),

    # Impact — web shells
    (r"/var/www/.*\.(php|jsp|aspx|py)$",
     "T1505.003", "Web Shell", "persistence"),

    # Credential access — shadow/passwd modification
    (r"^/etc/(shadow|passwd|sudoers)$",
     "T1003.008", "/etc/passwd and /etc/shadow", "credential-access"),
]

# ═══════════════════════════════════════════════════════
#  Filesystem Content Indicators
#
#  These classify attacker intent based on WHAT they
#  wrote to files (content analysis on previews).
# ═══════════════════════════════════════════════════════

# (content_pattern, technique_id, technique_name, tactic, description)
CONTENT_INDICATORS = [
    # Reverse shells
    (r"(bash\s+-i|/dev/tcp/|nc\s.*-e\s+/bin|socat\s|mkfifo\s.*nc\s|"
     r"python.*socket.*connect|perl.*socket.*INET|"
     r"ruby.*TCPSocket|php.*fsockopen)",
     "T1059.004", "Unix Shell", "execution",
     "reverse-shell-payload"),

    # Bind shells
    (r"(nc\s+-l|ncat\s+-l|socat\s+TCP-LISTEN)",
     "T1059.004", "Unix Shell", "execution",
     "bind-shell-payload"),

    # Crypto miners
    (r"(stratum\+tcp://|xmrig|minergate|coinhive|"
     r"cryptonight|hashrate|pool\.mining)",
     "T1496", "Resource Hijacking", "impact",
     "cryptominer"),

    # SSH keys (attacker injecting their own key)
    (r"ssh-(rsa|ed25519|ecdsa)\s+\S{20,}",
     "T1098.004", "SSH Authorized Keys", "persistence",
     "ssh-key-injection"),

    # Encoded payloads
    (r"(base64\s+-d|echo\s+[A-Za-z0-9+/]{40,}=*\s*\|\s*base64)",
     "T1140", "Deobfuscate/Decode Files or Information", "defense-evasion",
     "encoded-payload"),

    # Cron persistence
    (r"(\*\s+\*\s+\*\s+\*\s+\*|@reboot|@hourly|@daily)",
     "T1053.003", "Cron", "persistence",
     "cron-entry"),

    # LD_PRELOAD injection
    (r"/etc/ld\.so\.preload|LD_PRELOAD",
     "T1574.006", "Dynamic Linker Hijacking", "persistence",
     "ld-preload-injection"),

    # Kernel module loading
    (r"(insmod|modprobe)\s+\S+\.ko",
     "T1547.006", "Kernel Modules and Extensions", "persistence",
     "kernel-module"),

    # Credential harvesting scripts
    (r"(cat|grep|find).*(/etc/shadow|\.aws/credentials|\.ssh/id_|"
     r"\.kube/config|\.docker/config|\.gnupg/)",
     "T1552", "Unsecured Credentials", "credential-access",
     "credential-harvester"),

    # Download-and-execute patterns
    (r"(curl|wget)\s+.*\|\s*(bash|sh|python|perl)",
     "T1105", "Ingress Tool Transfer", "command-and-control",
     "download-and-execute"),

    # Systemd service installation
    (r"\[Service\]|\[Unit\]",
     "T1543.002", "Systemd Service", "persistence",
     "systemd-unit-file"),

    # PAM backdoor
    (r"pam_unix\.so|pam_exec\.so",
     "T1556.003", "Pluggable Authentication Modules", "credential-access",
     "pam-backdoor"),
]


# ═══════════════════════════════════════════════════════
#  Tool Signature Detection
# ═══════════════════════════════════════════════════════

TOOL_SIGNATURES = [
    (r"\bnmap\b", "nmap"),
    (r"\bnikto\b", "nikto"),
    (r"\bmetasploit\b|\bmsfconsole\b|\bmsfvenom\b", "metasploit"),
    (r"\bhydra\b", "hydra"),
    (r"\bgobuster\b|\bdirbuster\b|\bffuf\b", "gobuster"),
    (r"\blinpeas\b|\blinenum\b|\blinux-exploit-suggester\b", "linpeas"),
    (r"\bpspy\b", "pspy"),
    (r"\bmimikatz\b", "mimikatz"),
    (r"\bjohn\b|\bhashcat\b", "password-cracker"),
    (r"\bsqlmap\b", "sqlmap"),
    (r"\bburp\b", "burpsuite"),
    (r"\bchisel\b|\bsocat\b", "tunneling-tool"),
    (r"\bwpsc?an\b", "wpscan"),
    (r"\benum4linux\b|\bsmbclient\b", "smb-enum"),
]

# Tool detection in filenames (what they dropped, not what they typed)
TOOL_FILE_SIGNATURES = [
    (r"linpeas", "linpeas"),
    (r"linenum", "linenum"),
    (r"linux.?exploit.?suggest", "linux-exploit-suggester"),
    (r"pspy", "pspy"),
    (r"chisel", "chisel"),
    (r"socat", "socat"),
    (r"mimikatz|mimi\.exe", "mimikatz"),
    (r"msfvenom|meterpreter|msfconsole", "metasploit"),
    (r"reverse.?shell|rev.?shell|rshell", "reverse-shell-script"),
    (r"xmrig|miner", "cryptominer"),
    (r"nmap", "nmap"),
    (r"hydra", "hydra"),
    (r"gobuster|ffuf|dirbuster", "web-fuzzer"),
    (r"john|hashcat", "password-cracker"),
    (r"sqlmap", "sqlmap"),
    (r"enum4linux", "smb-enum"),
    (r"nc\.openbsd|ncat|netcat", "netcat"),
    (r"\.ko$", "kernel-module"),
    (r"\.so$", "shared-library"),
    (r"id_rsa|id_ed25519|id_ecdsa", "ssh-key"),
    (r"authorized_keys", "ssh-authorized-keys"),
]


# ═══════════════════════════════════════════════════════
#  Severity
# ═══════════════════════════════════════════════════════

SEVERITY_MAP = {
    "discovery": "low",
    "credential-access": "high",
    "privilege-escalation": "high",
    "execution": "medium",
    "lateral-movement": "high",
    "command-and-control": "high",
    "collection": "medium",
    "persistence": "medium",
    "exfiltration": "critical",
    "defense-evasion": "medium",
    "impact": "critical",
}

SEVERITY_RANK = {
    "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4,
}


# ═══════════════════════════════════════════════════════
#  COMMAND-LEVEL CLASSIFICATION (existing API)
# ═══════════════════════════════════════════════════════

def classify_command(command: str) -> dict:
    """
    Classify a single command into MITRE techniques and detect tools.
    Returns enrichment dict to merge into the event before storage.
    """
    techniques = []
    seen_ids = set()
    tools = []
    max_severity = "info"

    for pattern, tech_id, tech_name, tactic in MITRE_COMMAND_MAP:
        if re.search(pattern, command):
            if tech_id not in seen_ids:
                techniques.append({
                    "technique_id": tech_id,
                    "technique_name": tech_name,
                    "tactic": tactic,
                })
                seen_ids.add(tech_id)
                sev = SEVERITY_MAP.get(tactic, "info")
                if SEVERITY_RANK.get(sev, 0) > SEVERITY_RANK.get(max_severity, 0):
                    max_severity = sev

    for pattern, tool_name in TOOL_SIGNATURES:
        if re.search(pattern, command, re.IGNORECASE):
            if tool_name not in tools:
                tools.append(tool_name)

    return {
        "mitre_techniques": techniques,
        "tool_signatures": tools,
        "severity": max_severity,
    }


# ═══════════════════════════════════════════════════════
#  DELTA-LEVEL CLASSIFICATION (new)
# ═══════════════════════════════════════════════════════

def classify_fs_delta(delta: dict) -> dict:
    """
    Classify a session's filesystem delta into MITRE techniques,
    detect tools from filenames/content, and assess overall severity.

    Input: the delta dict from SessionFilesystem.get_delta()
      {
        "files_created":  [{path, content_preview, size, owner, permissions}],
        "files_modified": [{path, content_preview, size, owner, permissions}],
        "dirs_created":   ["/path/..."],
        "paths_deleted":  ["/path/..."],
        "mutation_log":   [{op, path, time, ...}],
        "mutation_count": int,
      }

    Returns:
      {
        "mitre_techniques": [{technique_id, technique_name, tactic, source}],
        "tool_signatures":  [str],
        "severity":         str,
        "indicators":       [{type, path, detail}],
        "tags":             [str],
      }
    """
    techniques = []
    seen_tech_ids = set()
    tools = []
    seen_tools = set()
    indicators = []
    max_severity = "info"

    def _add_technique(tech_id, tech_name, tactic, source_path):
        nonlocal max_severity
        if tech_id not in seen_tech_ids:
            techniques.append({
                "technique_id": tech_id,
                "technique_name": tech_name,
                "tactic": tactic,
                "source": source_path,
            })
            seen_tech_ids.add(tech_id)
            sev = SEVERITY_MAP.get(tactic, "info")
            if SEVERITY_RANK.get(sev, 0) > SEVERITY_RANK.get(max_severity, 0):
                max_severity = sev

    def _add_tool(tool_name):
        if tool_name not in seen_tools:
            tools.append(tool_name)
            seen_tools.add(tool_name)

    # ── Analyze created files ────────────────────────
    for entry in delta.get("files_created", []):
        path = entry.get("path", "")
        content = entry.get("content_preview", "")
        size = entry.get("size", 0)
        owner = entry.get("owner", "")
        perms = entry.get("permissions", "")

        # Path-based classification
        for pattern, tech_id, tech_name, tactic in MITRE_PATH_MAP:
            if re.search(pattern, path):
                _add_technique(tech_id, tech_name, tactic, path)
                indicators.append({
                    "type": "path_match",
                    "path": path,
                    "detail": f"{tactic}: {tech_name}",
                })

        # Tool detection from filename
        filename = path.rsplit("/", 1)[-1].lower() if "/" in path else path.lower()
        for pattern, tool_name in TOOL_FILE_SIGNATURES:
            if re.search(pattern, filename, re.IGNORECASE):
                _add_tool(tool_name)
                indicators.append({
                    "type": "tool_filename",
                    "path": path,
                    "detail": tool_name,
                })

        # Content-based classification
        if content:
            for pattern, tech_id, tech_name, tactic, desc in CONTENT_INDICATORS:
                if re.search(pattern, content, re.IGNORECASE):
                    _add_technique(tech_id, tech_name, tactic, path)
                    indicators.append({
                        "type": "content_match",
                        "path": path,
                        "detail": desc,
                    })

            # Tool detection from content
            for pattern, tool_name in TOOL_SIGNATURES:
                if re.search(pattern, content, re.IGNORECASE):
                    _add_tool(tool_name)

        # Executable permissions on created files → execution staging
        if perms and perms[-3:] in ("755", "777", "775", "711"):
            if path.startswith(("/tmp", "/dev/shm", "/var/tmp")):
                _add_technique(
                    "T1059.004", "Unix Shell", "execution", path)
                indicators.append({
                    "type": "executable_staged",
                    "path": path,
                    "detail": f"executable ({perms}) in world-writable dir",
                })

    # ── Analyze modified files ───────────────────────
    for entry in delta.get("files_modified", []):
        path = entry.get("path", "")
        content = entry.get("content_preview", "")

        # Same path-based classification
        for pattern, tech_id, tech_name, tactic in MITRE_PATH_MAP:
            if re.search(pattern, path):
                _add_technique(tech_id, tech_name, tactic, path)
                indicators.append({
                    "type": "file_modified",
                    "path": path,
                    "detail": f"{tactic}: {tech_name}",
                })

        # Content-based on modified files
        if content:
            for pattern, tech_id, tech_name, tactic, desc in CONTENT_INDICATORS:
                if re.search(pattern, content, re.IGNORECASE):
                    _add_technique(tech_id, tech_name, tactic, path)
                    indicators.append({
                        "type": "content_match",
                        "path": path,
                        "detail": desc,
                    })

    # ── Analyze deleted paths ────────────────────────
    for path in delta.get("paths_deleted", []):
        # Log deletion is defense evasion
        if re.search(r"/var/log/", path):
            _add_technique(
                "T1070.002", "Clear Linux or Mac System Logs",
                "defense-evasion", path)
            indicators.append({
                "type": "log_deleted",
                "path": path,
                "detail": "log file deletion",
            })

        # History deletion
        if re.search(r"\.bash_history$|\.history$", path):
            _add_technique(
                "T1070.003", "Clear Command History",
                "defense-evasion", path)
            indicators.append({
                "type": "history_deleted",
                "path": path,
                "detail": "command history deletion",
            })

        # System file deletion
        if re.search(r"^/etc/(resolv\.conf|hosts|passwd|shadow|iptables)", path):
            _add_technique(
                "T1562", "Impair Defenses",
                "defense-evasion", path)
            indicators.append({
                "type": "system_file_deleted",
                "path": path,
                "detail": "critical system file deletion",
            })

    # ── Analyze directory creation patterns ──────────
    for path in delta.get("dirs_created", []):
        # Hidden directories in /tmp or home dirs → staging
        dirname = path.rsplit("/", 1)[-1] if "/" in path else path
        if dirname.startswith(".") and path.startswith(("/tmp", "/dev/shm", "/var/tmp")):
            _add_technique(
                "T1074.001", "Local Data Staging",
                "collection", path)
            indicators.append({
                "type": "hidden_staging_dir",
                "path": path,
                "detail": "hidden directory in world-writable location",
            })

    # ── Mutation pattern analysis ────────────────────
    mutation_log = delta.get("mutation_log", [])
    mutation_count = delta.get("mutation_count", 0)

    # High-volume mutations suggest automated tooling
    if mutation_count >= 20:
        indicators.append({
            "type": "high_mutation_volume",
            "path": "",
            "detail": f"{mutation_count} filesystem mutations (likely automated)",
        })

    # Rapid file creation in /tmp → tool deployment
    tmp_creates = [
        m for m in mutation_log
        if m.get("op") == "create_file"
        and m.get("path", "").startswith(("/tmp", "/dev/shm", "/var/tmp"))
    ]
    if len(tmp_creates) >= 5:
        _add_technique(
            "T1074.001", "Local Data Staging",
            "collection", "/tmp")
        indicators.append({
            "type": "bulk_tmp_staging",
            "path": "/tmp",
            "detail": f"{len(tmp_creates)} files staged in temp directories",
        })

    # Build tags from observed tactics
    tags = list(dict.fromkeys(
        t["tactic"] for t in techniques
    ))

    return {
        "mitre_techniques": techniques,
        "tool_signatures": tools,
        "severity": max_severity,
        "indicators": indicators,
        "tags": tags,
    }


# ═══════════════════════════════════════════════════════
#  KILL CHAIN DETECTION
# ═══════════════════════════════════════════════════════

def detect_kill_chain(techniques: list) -> tuple:
    """
    Detect if a set of techniques spans 3+ attack phases,
    indicating kill chain progression.

    Returns (detected: bool, phases: list)
    """
    phase_order = [
        "discovery", "credential-access", "privilege-escalation",
        "execution", "lateral-movement", "command-and-control",
        "collection", "exfiltration", "persistence", "defense-evasion",
        "impact",
    ]
    observed = list(dict.fromkeys(
        t["tactic"] for t in techniques if t.get("tactic") in phase_order
    ))
    return len(observed) >= 3, observed


def merge_session_enrichment(
    command_techniques: list,
    delta_enrichment: dict,
) -> dict:
    """
    Merge command-level and delta-level enrichment into a single
    session-level assessment.  Deduplicates techniques, takes the
    highest severity, and runs kill chain detection across both.

    Intended to be called when building the final decoy_sessions
    record after the session ends.
    """
    seen_ids = set()
    all_techniques = []

    # Command-level techniques first
    for t in command_techniques:
        tid = t.get("technique_id")
        if tid and tid not in seen_ids:
            all_techniques.append(t)
            seen_ids.add(tid)

    # Delta-level techniques (may add new ones)
    for t in delta_enrichment.get("mitre_techniques", []):
        tid = t.get("technique_id")
        if tid and tid not in seen_ids:
            all_techniques.append(t)
            seen_ids.add(tid)

    # Merge tools
    all_tools = list(dict.fromkeys(
        delta_enrichment.get("tool_signatures", [])
    ))

    # Highest severity wins
    cmd_severity = max(
        (SEVERITY_RANK.get(
            SEVERITY_MAP.get(t.get("tactic", ""), "info"), 0)
         for t in command_techniques),
        default=0,
    )
    delta_severity = SEVERITY_RANK.get(
        delta_enrichment.get("severity", "info"), 0)
    final_rank = max(cmd_severity, delta_severity)
    final_severity = next(
        (k for k, v in SEVERITY_RANK.items() if v == final_rank),
        "info",
    )

    # Kill chain across everything
    chain_detected, phases = detect_kill_chain(all_techniques)

    # All tags
    tags = list(dict.fromkeys(
        t.get("tactic", "") for t in all_techniques if t.get("tactic")
    ))

    return {
        "mitre_techniques": all_techniques,
        "tool_signatures": all_tools,
        "severity": final_severity,
        "kill_chain_detected": chain_detected,
        "attack_phases": phases,
        "tags": tags,
        "indicators": delta_enrichment.get("indicators", []),
    }


# ═══════════════════════════════════════════════════════
#  EVENT-LEVEL ENRICHMENT (existing API, unchanged)
# ═══════════════════════════════════════════════════════

def enrich_event(raw: dict) -> dict:
    """
    Full enrichment pass on a raw event dict.
    Extracts the command, classifies it, and merges results back.
    Returns the enriched event.
    """
    data = raw.get("data", raw)
    command = (
        data.get("command", "")
        or data.get("input", "")
        or raw.get("raw_data", {}).get("command", "")
        or ""
    )

    if not command:
        return {
            "mitre_techniques": [],
            "tool_signatures": [],
            "severity": data.get("severity", "info"),
            "tags": [],
        }

    result = classify_command(command)

    tags = list(set(t["tactic"] for t in result["mitre_techniques"]))

    base_severity = data.get("severity", "info")
    if SEVERITY_RANK.get(result["severity"], 0) > SEVERITY_RANK.get(base_severity, 0):
        final_severity = result["severity"]
    else:
        final_severity = base_severity

    return {
        "mitre_techniques": result["mitre_techniques"],
        "tool_signatures": result["tool_signatures"],
        "severity": final_severity,
        "tags": tags,
    }


def enrich_fs_delta_event(raw: dict) -> dict:
    """
    Enrichment pass for a session.fs_delta event.

    Input: raw event dict with data containing the COW delta.
    Returns enrichment dict to merge into the event before storage.
    """
    data = raw.get("data", {})
    return classify_fs_delta(data)