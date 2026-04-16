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

Changes from baseline:
  - Expanded MITRE ATT&CK coverage (~70+ patterns, up from ~40)
  - Multi-factor severity: per-technique overrides + target sensitivity boosts
  - Privilege escalation tactic (sudo abuse, SUID/setgid, SUID enumeration)
  - Obfuscation/encoding detection (base64 pipe-to-shell, xxd, T1027/T1140)
  - SSH tunneling detection (ssh -L/-R/-D → T1572 Protocol Tunneling)
  - Credential searching (grep -r password/secret/AKIA, bash_history reading)
  - Environment variable harvesting (env/printenv in cloud contexts)
  - Timestomping detection (touch -t → T1070.006)
  - Tool-to-technique bridging (nmap → T1046, hydra → T1110)
  - Dangerous kill chain progression detection
  - Tool category metadata for session-level analysis
"""

import ipaddress
import logging
import os
import re
import threading
from typing import Optional

try:
    import geoip2.database
    import geoip2.errors
    _GEOIP2_AVAILABLE = True
except ImportError:
    _GEOIP2_AVAILABLE = False

logger = logging.getLogger("cicdecoy.enrichment")


# ═══════════════════════════════════════════════════════
#  GeoIP Enrichment
# ═══════════════════════════════════════════════════════

GEOIP_DB_PATH = os.environ.get(
    "GEOIP_DB_PATH", "/opt/geoip/GeoLite2-City.mmdb"
)

_geoip_reader = None
_geoip_init_attempted = False
_geoip_lock = threading.Lock()


def _get_geoip_reader():
    """Lazily initialise the GeoIP reader. Returns None if unavailable."""
    global _geoip_reader, _geoip_init_attempted
    with _geoip_lock:
        if _geoip_init_attempted:
            return _geoip_reader
        _geoip_init_attempted = True
        if not _GEOIP2_AVAILABLE:
            logger.warning("geoip2 package not installed — geo enrichment disabled")
            return _geoip_reader
        try:
            _geoip_reader = geoip2.database.Reader(GEOIP_DB_PATH)
            logger.info("GeoIP database loaded: %s", GEOIP_DB_PATH)
        except FileNotFoundError:
            logger.warning(
                "GeoIP database not found at %s — geo enrichment disabled",
                GEOIP_DB_PATH,
            )
        except Exception as e:
            logger.warning("GeoIP initialisation failed: %s — geo enrichment disabled", e)
        return _geoip_reader


def _is_private_ip(ip_str: str) -> bool:
    """Return True if the IP is private, reserved, loopback, or link-local."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.is_private or addr.is_reserved or addr.is_loopback or addr.is_link_local
    except ValueError:
        return True  # Unparseable → treat as non-routable


def geoip_enrich(ip_str: str) -> dict:
    """Look up GeoIP data for an IP address.

    Returns a dict suitable for storing in the ``geo`` JSONB column::

        {
            "country": "US",
            "country_name": "United States",
            "city": "San Francisco",
            "latitude": 37.7749,
            "longitude": -122.4194,
            "asn": 13335,
            "org": "Cloudflare, Inc.",
        }

    For private/reserved IPs the dict contains ``{"private": true}``.
    If the GeoIP database is unavailable or the lookup fails, an empty
    dict is returned (enrichment is best-effort, never fatal).
    """
    if not ip_str:
        return {}

    if _is_private_ip(ip_str):
        return {"private": True}

    reader = _get_geoip_reader()
    if reader is None:
        return {}

    geo: dict = {}
    try:
        resp = reader.city(ip_str)
        geo["country"] = resp.country.iso_code or ""
        geo["country_name"] = resp.country.name or ""
        geo["city"] = resp.city.name or ""
        geo["latitude"] = resp.location.latitude
        geo["longitude"] = resp.location.longitude
    except Exception as e:
        # Covers geoip2.errors.AddressNotFoundError and any other failure
        if "AddressNotFoundError" in type(e).__name__:
            logger.debug("GeoIP: address not found for %s", ip_str)
        else:
            logger.debug("GeoIP lookup failed for %s: %s", ip_str, e)
        return {}

    # ASN lookup — GeoLite2-City doesn't include ASN, but the reader
    # may be a combined database.  Best-effort; skip on error.
    try:
        asn_resp = reader.asn(ip_str)
        geo["asn"] = asn_resp.autonomous_system_number
        geo["org"] = asn_resp.autonomous_system_organization or ""
    except Exception:
        pass

    return geo


# ═══════════════════════════════════════════════════════
#  MITRE ATT&CK — Command-to-Technique Mapping
# ═══════════════════════════════════════════════════════

MITRE_COMMAND_MAP = [

    # ── Discovery ─────────────────────────────────────

    (r"\bwhoami\b", "T1033", "System Owner/User Discovery", "discovery"),
    (r"\bid\b", "T1033", "System Owner/User Discovery", "discovery"),
    (r"\buname\b", "T1082", "System Information Discovery", "discovery"),
    (r"\bhostname\b", "T1082", "System Information Discovery", "discovery"),
    (r"\bcat\s+/etc/(issue|os-release|lsb-release)", "T1082", "System Information Discovery", "discovery"),
    (r"\bls\b.*(/root|/home|\.ssh|\.gnupg)", "T1083", "File and Directory Discovery", "discovery"),
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
    # NEW: Expanded discovery
    (r"\b(find|locate)\b.*(-name|-type|-perm)", "T1083", "File and Directory Discovery", "discovery"),
    (r"\b(groups|cat\s+/etc/group)\b", "T1069", "Permission Groups Discovery", "discovery"),
    (r"\b(dpkg\s+-l|rpm\s+-qa|pip3?\s+list|apt\s+list)", "T1518", "Software Discovery", "discovery"),
    (r"\b(systemctl\s+list|service\s+--status-all|chkconfig\s+--list)", "T1007", "System Service Discovery", "discovery"),
    (r"\b(dmidecode|virt-what|systemd-detect-virt)\b", "T1497", "Virtualization/Sandbox Evasion", "discovery"),
    # NEW: Tool-to-technique bridging — nmap as technique, not just tool sig
    (r"\bnmap\b", "T1046", "Network Service Discovery", "discovery"),

    # ── Credential Access ─────────────────────────────

    (r"\bcat\s+/etc/(passwd|shadow|group)", "T1003.008", "/etc/passwd and /etc/shadow", "credential-access"),
    (r"\bcat\s+.*\.ssh/(id_rsa|id_ed25519|authorized_keys)", "T1552.004", "Private Keys", "credential-access"),
    (r"\bpasswd\b", "T1003", "OS Credential Dumping", "credential-access"),
    # NEW: Cloud metadata
    (r"169\.254\.169\.254", "T1552.005", "Cloud Instance Metadata API", "credential-access"),
    # NEW: Credential file searching (grep for secrets)
    (r"\bgrep\b.*-r.*\b(password|secret|token|api.?key|AKIA|credential)", "T1552.001", "Credentials In Files", "credential-access"),
    # NEW: Bash/shell history reading (attackers mine for typed passwords)
    (r"\bcat\s+.*\.(bash_history|zsh_history|history)\b", "T1552.003", "Bash History", "credential-access"),
    (r"\bcat\s+.*/\.bash_history\b", "T1552.003", "Bash History", "credential-access"),
    # NEW: Private key file access beyond just .ssh/
    (r"\bcat\s+.*\.(pem|key|p12|pfx|jks)\b", "T1552.004", "Private Keys", "credential-access"),
    # NEW: Browser/keychain credential stores
    (r"(chrome|firefox|mozilla|\.local/share/keyrings)", "T1555", "Credentials from Password Stores", "credential-access"),
    # NEW: Brute force — hydra as technique, not just tool sig
    (r"\bhydra\b", "T1110", "Brute Force", "credential-access"),

    # ── Privilege Escalation (NEW section) ────────────

    (r"\bsudo\b", "T1548.003", "Sudo and Sudo Caching", "privilege-escalation"),
    (r"\bchmod\s+[u+]*s\b|\bchmod\s+[0-7]*4[0-7]{3}\b", "T1548.001", "Setuid and Setgid", "privilege-escalation"),
    (r"\bfind\b.*-perm\s+(-4000|-u=s)", "T1548.001", "Setuid and Setgid", "privilege-escalation"),

    # ── Execution ─────────────────────────────────────

    (r"\bwget\b|\bcurl\b.*\b(http|ftp)://", "T1105", "Ingress Tool Transfer", "command-and-control"),
    (r"\bchmod\s+\+x\b", "T1059.004", "Unix Shell", "execution"),
    (r"\bbash\s+-[ci]\b|\bsh\s+-[ci]\b", "T1059.004", "Unix Shell", "execution"),
    (r"\bpython[23]?\s+-c\b", "T1059.006", "Python", "execution"),
    (r"\bpython3?\s+-m\s+http\.server", "T1059.006", "Python", "execution"),
    (r"\bperl\s+-e\b", "T1059", "Command and Scripting Interpreter", "execution"),
    (r"\bruby\s+-e\b", "T1059", "Command and Scripting Interpreter", "execution"),
    (r"\bnc\b.*-[el]|\bncat\b", "T1059.004", "Unix Shell", "execution"),
    # NEW: base64 pipe-to-shell (obfuscated execution)
    (r"base64\s+(-d|--decode).*\|\s*(bash|sh|python|perl)", "T1027", "Obfuscated Files or Information", "execution"),
    (r"echo\s+.*\|\s*base64\s+(-d|--decode).*\|\s*(bash|sh)", "T1027", "Obfuscated Files or Information", "execution"),

    # ── Lateral Movement ──────────────────────────────

    (r"\bssh\b\s+.*\w+@", "T1021.004", "SSH", "lateral-movement"),
    (r"\bscp\b\s+", "T1021.004", "SSH", "lateral-movement"),
    (r"\brsync\b.*@", "T1021.004", "SSH", "lateral-movement"),
    # NEW: SSH tunneling (port forwarding, SOCKS proxy)
    (r"\bssh\b\s+.*(-L\s+|-R\s+|-D\s+|-w\s+)", "T1572", "Protocol Tunneling", "command-and-control"),

    # ── Collection / Exfiltration ─────────────────────

    (r"\btar\b.*\b(czf|cjf|cf)\b", "T1560.001", "Archive via Utility", "collection"),
    (r"\bzip\b|\bgzip\b", "T1560.001", "Archive via Utility", "collection"),
    (r"\bbase64\b", "T1132.001", "Standard Encoding", "command-and-control"),
    # NEW: Exfiltration to cloud storage
    (r"\b(aws\s+s3\s+cp|gsutil\s+cp|az\s+storage\s+blob)", "T1567", "Exfiltration to Cloud Storage", "exfiltration"),
    # NEW: Exfiltration via curl POST
    (r"curl\s+.*(-X\s+POST|--data|--data-binary|-d\s+@)", "T1041", "Exfiltration Over C2 Channel", "exfiltration"),
    # NEW: Exfiltration over alternative protocol (nc/ncat with redirect)
    (r"\b(nc|ncat)\b.*(<|>|\|)", "T1048", "Exfiltration Over Alternative Protocol", "exfiltration"),

    # ── Persistence ───────────────────────────────────

    (r"\bcrontab\b", "T1053.003", "Cron", "persistence"),
    (r"\.bashrc|\.bash_profile|\.profile", "T1546.004", "Unix Shell Configuration Modification", "persistence"),
    (r"\bsystemctl\b.*enable", "T1543.002", "Systemd Service", "persistence"),
    # NEW: Account creation
    (r"\b(useradd|adduser)\b", "T1136", "Create Account", "persistence"),
    # NEW: at scheduled task
    (r"\bat\s+\d", "T1053.001", "At", "persistence"),

    # ── Defense Evasion ───────────────────────────────

    (r"\bunset\s+HISTFILE|\bexport\s+HISTFILE=/dev/null", "T1070.003", "Clear Command History", "defense-evasion"),
    (r"\bhistory\s+-c\b", "T1070.003", "Clear Command History", "defense-evasion"),
    (r"\brm\s+.*\.bash_history", "T1070.003", "Clear Command History", "defense-evasion"),
    (r"\biptables\b.*-D|\biptables\b.*-F", "T1562.004", "Disable or Modify System Firewall", "defense-evasion"),
    # NEW: Timestomping
    (r"\btouch\s+-t\s+\d{8,}", "T1070.006", "Timestomp", "defense-evasion"),
    # NEW: Log file deletion
    (r"\brm\s+.*(/var/log/|/var/audit/|\.log\b)", "T1070.004", "File Deletion", "defense-evasion"),
    # NEW: Deobfuscation/decoding (standalone, not piped to shell)
    (r"\b(base64\s+(-d|--decode)|xxd\s+-r|openssl\s+(base64|enc)\s+-d)\b", "T1140", "Deobfuscate/Decode Files or Information", "defense-evasion"),

    # ── Impact (NEW section) ──────────────────────────

    (r"\b(rm\s+-rf\s+/|shred\s+|dd\s+if=/dev/(zero|urandom))", "T1485", "Data Destruction", "impact"),
    (r"\b(openssl\s+enc|gpg\s+-c)\b.*\.(tar|zip|gz|sql|csv|db)", "T1486", "Data Encrypted for Impact", "impact"),
    (r"\b(systemctl\s+stop|kill\s+-9|killall)\b", "T1489", "Service Stop", "impact"),
]


# ═══════════════════════════════════════════════════════
#  Per-Technique Severity Overrides
#
#  The default severity comes from SEVERITY_MAP[tactic].
#  These overrides let specific techniques be higher or
#  lower than their tactic's baseline — e.g. cat /etc/shadow
#  is "high" not because all credential-access is high but
#  because T1003 specifically warrants it.
# ═══════════════════════════════════════════════════════

TECHNIQUE_SEVERITY_OVERRIDES = {
    # Critical — active exfiltration, data destruction, ransomware
    "T1485": "critical",   # Data Destruction
    "T1486": "critical",   # Data Encrypted for Impact
    "T1567": "critical",   # Exfil to Cloud Storage
    "T1041": "critical",   # Exfil Over C2 Channel
    "T1048": "critical",   # Exfil Over Alt Protocol
    # High — credential access, lateral movement, tool transfer, reverse shells
    "T1003": "high",       # Credential Dumping
    "T1003.008": "high",   # /etc/passwd and /etc/shadow
    "T1552.004": "high",   # Private Keys
    "T1552.001": "high",   # Credentials In Files
    "T1552.005": "high",   # Cloud Instance Metadata
    "T1555": "high",       # Credentials from Password Stores
    "T1110": "high",       # Brute Force
    "T1136": "high",       # Create Account
    "T1548.001": "high",   # Setuid and Setgid
    "T1027": "high",       # Obfuscated Files (base64 pipe-to-shell)
    # Medium — priv-esc recon, VM evasion, timestomping
    "T1548.003": "medium", # Sudo (includes sudo -l which is just recon)
    "T1497": "medium",     # Virtualization/Sandbox Evasion
    "T1046": "medium",     # Network Service Discovery (nmap)
    "T1070.006": "medium", # Timestomp
    "T1489": "medium",     # Service Stop
    # Low — overrides for discovery-tactic techniques that don't need "low"
    # (most discovery is already "low" via SEVERITY_MAP, these are here
    #  for documentation completeness)
}


# ═══════════════════════════════════════════════════════
#  Target Sensitivity Boosts
#
#  If a command touches certain high-value targets, its
#  severity is boosted to at least the specified level
#  regardless of the base technique severity.
# ═══════════════════════════════════════════════════════

_TARGET_BOOST_PATTERNS = [
    (re.compile(r"/etc/shadow|/etc/gshadow", re.I), "high"),
    (re.compile(r"\.ssh/id_rsa|\.ssh/id_ed25519|\.ssh/id_ecdsa", re.I), "high"),
    (re.compile(r"\.(pem|key|p12|pfx)\b", re.I), "high"),
    (re.compile(r"\.aws/credentials|\.kube/config|\.gcp/", re.I), "high"),
    (re.compile(r"169\.254\.169\.254", re.I), "high"),
    (re.compile(r"\.bash_history|\.zsh_history", re.I), "medium"),
    (re.compile(r"/dev/shm/|/tmp/\.", re.I), "medium"),
    (re.compile(r"/var/log/|/var/audit/", re.I), "medium"),
]


def _target_severity_boost(command: str) -> str:
    """Return the highest target-sensitivity boost for a command."""
    boost = "info"
    for pattern, level in _TARGET_BOOST_PATTERNS:
        if pattern.search(command):
            if SEVERITY_RANK.get(level, 0) > SEVERITY_RANK.get(boost, 0):
                boost = level
    return boost


# ═══════════════════════════════════════════════════════
#  MITRE ATT&CK — Filesystem Path Indicators
# ═══════════════════════════════════════════════════════

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
# ═══════════════════════════════════════════════════════

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

    # NEW: AWS key patterns in file content
    (r"AKIA[0-9A-Z]{16}",
     "T1552.001", "Credentials In Files", "credential-access",
     "aws-access-key"),

    # NEW: Private key headers
    (r"BEGIN\s+(RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY",
     "T1552.004", "Private Keys", "credential-access",
     "private-key-material"),

    # NEW: Password patterns
    (r"\bpassword\s*[:=]",
     "T1552.001", "Credentials In Files", "credential-access",
     "plaintext-password"),
]


# ═══════════════════════════════════════════════════════
#  Tool Signature Detection
# ═══════════════════════════════════════════════════════

TOOL_SIGNATURES = [
    (r"\bnmap\b", "nmap"),
    (r"\bnikto\b", "nikto"),
    (r"\bmetasploit\b|\bmsfconsole\b|\bmsfvenom\b|\bmeterpreter\b", "metasploit"),
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
    # NEW: Additional tools
    (r"\bmasscan\b", "masscan"),
    (r"\brushscan\b", "rustscan"),
    (r"\bzmap\b", "zmap"),
    (r"\bcrackmapexec\b|\bcme\b", "crackmapexec"),
    (r"\b(impacket|secretsdump|psexec\.py|wmiexec\.py|smbexec\.py)\b", "impacket"),
    (r"\b(cobalt.?strike|beacon\.exe|cobaltstrike)\b", "cobalt-strike"),
    (r"\bsliver\b", "sliver"),
    (r"\bhavoc\b", "havoc"),
    (r"\b(powershell.?empire|starkiller)\b", "empire"),
    (r"\bligolo\b", "ligolo"),
    (r"\bngrok\b", "ngrok"),
    (r"\bproxychains\b", "proxychains"),
    (r"\brclone\b", "rclone"),
    (r"\b(mega-cmd|megacmd|mega-put)\b", "megacmd"),
    (r"\b(bloodhound|sharphound)\b", "bloodhound"),
    (r"\brubeus\b", "rubeus"),
    (r"\bseatbelt\b", "seatbelt"),
    (r"\bunix-privesc-check\b", "unix-privesc-check"),
    (r"\bldapdomaindump\b", "ldapdomaindump"),
]


# Tool categories — consumed by session_analyzer for behavioral scoring.
# Keys match the tool name strings in TOOL_SIGNATURES and TOOL_FILE_SIGNATURES.
# This is additive metadata, not a change to the classify_command() return type.
TOOL_CATEGORIES = {
    # Reconnaissance
    "nmap": "reconnaissance", "masscan": "reconnaissance",
    "rustscan": "reconnaissance", "zmap": "reconnaissance",
    "nikto": "reconnaissance",
    # Enumeration
    "linpeas": "enumeration", "linenum": "enumeration",
    "pspy": "enumeration", "enum4linux": "enumeration",
    "smb-enum": "enumeration", "ldapdomaindump": "enumeration",
    "unix-privesc-check": "enumeration",
    "linux-exploit-suggester": "enumeration",
    # Credential
    "hydra": "credential", "password-cracker": "credential",
    "crackmapexec": "credential", "impacket": "credential",
    "mimikatz": "credential",
    # C2
    "metasploit": "c2", "cobalt-strike": "c2", "sliver": "c2",
    "havoc": "c2", "empire": "c2",
    # Tunneling
    "tunneling-tool": "tunnel", "ligolo": "tunnel",
    "ngrok": "tunnel", "proxychains": "tunnel",
    # Exfiltration
    "rclone": "exfiltration", "megacmd": "exfiltration",
    # Post-exploitation
    "bloodhound": "post_exploit", "rubeus": "post_exploit",
    "seatbelt": "post_exploit",
    # Web
    "gobuster": "web", "wpscan": "web", "sqlmap": "web",
    "burpsuite": "web",
    # Other
    "cryptominer": "impact",
}


# Tool detection in filenames
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
    # NEW
    (r"bloodhound|sharphound", "bloodhound"),
    (r"rubeus", "rubeus"),
    (r"cobalt|beacon", "cobalt-strike"),
    (r"sliver", "sliver"),
    (r"rclone", "rclone"),
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


def _max_severity(*levels: str) -> str:
    """Return the highest severity from the given levels."""
    best = "info"
    for lvl in levels:
        if SEVERITY_RANK.get(lvl, 0) > SEVERITY_RANK.get(best, 0):
            best = lvl
    return best


# ═══════════════════════════════════════════════════════
#  COMMAND-LEVEL CLASSIFICATION
# ═══════════════════════════════════════════════════════

def classify_command(command: str) -> dict:
    """
    Classify a single command into MITRE techniques and detect tools.

    Returns:
        {
            "mitre_techniques": [{"technique_id", "technique_name", "tactic"}, ...],
            "tool_signatures": [str, ...],
            "severity": str,
        }
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

                # Severity: check per-technique override first, then tactic default
                tech_sev = TECHNIQUE_SEVERITY_OVERRIDES.get(tech_id)
                if tech_sev is None:
                    tech_sev = SEVERITY_MAP.get(tactic, "info")
                if SEVERITY_RANK.get(tech_sev, 0) > SEVERITY_RANK.get(max_severity, 0):
                    max_severity = tech_sev

    for pattern, tool_name in TOOL_SIGNATURES:
        if re.search(pattern, command, re.IGNORECASE):
            if tool_name not in tools:
                tools.append(tool_name)

    # Target sensitivity boost — elevates severity if touching sensitive targets
    target_boost = _target_severity_boost(command)
    max_severity = _max_severity(max_severity, target_boost)

    # Tool-based severity boost — C2 tools → critical, attack tools → high
    for tool in tools:
        cat = TOOL_CATEGORIES.get(tool, "")
        if cat == "c2":
            max_severity = _max_severity(max_severity, "critical")
        elif cat in ("credential", "post_exploit", "exfiltration"):
            max_severity = _max_severity(max_severity, "high")

    return {
        "mitre_techniques": techniques,
        "tool_signatures": tools,
        "severity": max_severity,
    }


# ═══════════════════════════════════════════════════════
#  DELTA-LEVEL CLASSIFICATION (unchanged API, expanded maps)
# ═══════════════════════════════════════════════════════

def classify_fs_delta(delta: dict) -> dict:
    """
    Classify a session's filesystem delta into MITRE techniques,
    detect tools from filenames/content, and assess overall severity.

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
            # Use override severity if available, else tactic default
            sev = TECHNIQUE_SEVERITY_OVERRIDES.get(
                tech_id, SEVERITY_MAP.get(tactic, "info"))
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

        for pattern, tech_id, tech_name, tactic in MITRE_PATH_MAP:
            if re.search(pattern, path):
                _add_technique(tech_id, tech_name, tactic, path)
                indicators.append({
                    "type": "path_match",
                    "path": path,
                    "detail": f"{tactic}: {tech_name}",
                })

        filename = path.rsplit("/", 1)[-1].lower() if "/" in path else path.lower()
        for pattern, tool_name in TOOL_FILE_SIGNATURES:
            if re.search(pattern, filename, re.IGNORECASE):
                _add_tool(tool_name)
                indicators.append({
                    "type": "tool_filename",
                    "path": path,
                    "detail": tool_name,
                })

        if content:
            for pattern, tech_id, tech_name, tactic, desc in CONTENT_INDICATORS:
                if re.search(pattern, content, re.IGNORECASE):
                    _add_technique(tech_id, tech_name, tactic, path)
                    indicators.append({
                        "type": "content_match",
                        "path": path,
                        "detail": desc,
                    })

            for pattern, tool_name in TOOL_SIGNATURES:
                if re.search(pattern, content, re.IGNORECASE):
                    _add_tool(tool_name)

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

        for pattern, tech_id, tech_name, tactic in MITRE_PATH_MAP:
            if re.search(pattern, path):
                _add_technique(tech_id, tech_name, tactic, path)
                indicators.append({
                    "type": "file_modified",
                    "path": path,
                    "detail": f"{tactic}: {tech_name}",
                })

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
        if re.search(r"/var/log/", path):
            _add_technique(
                "T1070.002", "Clear Linux or Mac System Logs",
                "defense-evasion", path)
            indicators.append({
                "type": "log_deleted", "path": path,
                "detail": "log file deletion",
            })

        if re.search(r"\.bash_history$|\.history$", path):
            _add_technique(
                "T1070.003", "Clear Command History",
                "defense-evasion", path)
            indicators.append({
                "type": "history_deleted", "path": path,
                "detail": "command history deletion",
            })

        if re.search(r"^/etc/(resolv\.conf|hosts|passwd|shadow|iptables)", path):
            _add_technique(
                "T1562", "Impair Defenses",
                "defense-evasion", path)
            indicators.append({
                "type": "system_file_deleted", "path": path,
                "detail": "critical system file deletion",
            })

    # ── Analyze directory creation patterns ──────────
    for path in delta.get("dirs_created", []):
        dirname = path.rsplit("/", 1)[-1] if "/" in path else path
        if dirname.startswith(".") and path.startswith(("/tmp", "/dev/shm", "/var/tmp")):
            _add_technique(
                "T1074.001", "Local Data Staging",
                "collection", path)
            indicators.append({
                "type": "hidden_staging_dir", "path": path,
                "detail": "hidden directory in world-writable location",
            })

    # ── Mutation pattern analysis ────────────────────
    mutation_log = delta.get("mutation_log", [])
    mutation_count = delta.get("mutation_count", 0)

    if mutation_count >= 20:
        indicators.append({
            "type": "high_mutation_volume", "path": "",
            "detail": f"{mutation_count} filesystem mutations (likely automated)",
        })

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
            "type": "bulk_tmp_staging", "path": "/tmp",
            "detail": f"{len(tmp_creates)} files staged in temp directories",
        })

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


# Dangerous progressions — used by the session analyzer, not by detect_kill_chain
# (detect_kill_chain's return signature is frozen as (bool, list))
DANGEROUS_PROGRESSIONS = [
    ({"discovery", "credential-access", "lateral-movement"}, "critical",
     "Kill chain: discovery → credential-access → lateral-movement"),
    ({"discovery", "credential-access", "exfiltration"}, "critical",
     "Kill chain: discovery → credential-access → exfiltration"),
    ({"execution", "persistence", "defense-evasion"}, "high",
     "Kill chain: execution → persistence → defense-evasion"),
    ({"credential-access", "lateral-movement", "collection"}, "critical",
     "Kill chain: credential-access → lateral-movement → collection"),
    ({"discovery", "privilege-escalation", "persistence"}, "high",
     "Kill chain: discovery → privilege-escalation → persistence"),
    ({"privilege-escalation", "credential-access", "lateral-movement"}, "critical",
     "Kill chain: privilege-escalation → credential-access → lateral-movement"),
]


def detect_dangerous_progressions(phases: set) -> list:
    """
    Check for specific dangerous kill chain progressions.

    Args:
        phases: set of tactic names observed in a session

    Returns:
        list of (severity, description) tuples for matched progressions
    """
    results = []
    for required_phases, severity, description in DANGEROUS_PROGRESSIONS:
        if required_phases.issubset(phases):
            results.append((severity, description))
    return results


# ═══════════════════════════════════════════════════════
#  SESSION MERGE
# ═══════════════════════════════════════════════════════

def merge_session_enrichment(
    command_techniques: list,
    delta_enrichment: dict,
) -> dict:
    """
    Merge command-level and delta-level enrichment into a single
    session-level assessment.  Deduplicates techniques, takes the
    highest severity, and runs kill chain detection across both.
    """
    seen_ids = set()
    all_techniques = []

    for t in command_techniques:
        tid = t.get("technique_id")
        if tid and tid not in seen_ids:
            all_techniques.append(t)
            seen_ids.add(tid)

    for t in delta_enrichment.get("mitre_techniques", []):
        tid = t.get("technique_id")
        if tid and tid not in seen_ids:
            all_techniques.append(t)
            seen_ids.add(tid)

    all_tools = list(dict.fromkeys(
        delta_enrichment.get("tool_signatures", [])
    ))

    cmd_severity = max(
        (SEVERITY_RANK.get(
            TECHNIQUE_SEVERITY_OVERRIDES.get(
                t.get("technique_id", ""),
                SEVERITY_MAP.get(t.get("tactic", ""), "info")),
            0)
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

    chain_detected, phases = detect_kill_chain(all_techniques)

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
#  EVENT-LEVEL ENRICHMENT
# ═══════════════════════════════════════════════════════

def enrich_event(raw: dict) -> dict:
    """
    Full enrichment pass on a raw event dict.
    Extracts the command, classifies it, and merges results back.

    Returns:
        {"mitre_techniques": [...], "tool_signatures": [...],
         "severity": str, "tags": [...], "geo": {...}}
    """
    data = raw.get("data", raw)
    command = (
        data.get("command", "")
        or data.get("input", "")
        or raw.get("raw_data", {}).get("command", "")
        or ""
    )

    # ── GeoIP enrichment ────────────────────────────
    source_ip = (
        data.get("client_ip", "")
        or raw.get("source_ip", "")
        or ""
    )
    geo = geoip_enrich(source_ip)

    if not command:
        return {
            "mitre_techniques": [],
            "tool_signatures": [],
            "severity": data.get("severity", "info"),
            "tags": [],
            "geo": geo,
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
        "geo": geo,
    }


def enrich_fs_delta_event(raw: dict) -> dict:
    """
    Enrichment pass for a session.fs_delta event.
    """
    data = raw.get("data", {})
    return classify_fs_delta(data)