"""
CI/CDecoy — HTTP Decoy Enrichment

Analyzes incoming HTTP requests and classifies attacker behavior using
MITRE ATT&CK techniques. Used by the telemetry module to enrich events
before publishing to NATS.

Classification combines five signal sources:
  1. Request path      — config leaks, admin panels, source exposure
  2. User-Agent        — scanner/tool fingerprinting
  3. HTTP method       — unusual verbs (TRACE, PROPFIND, etc.)
  4. Query string      — injection patterns (SQLi, XSS, traversal)
  5. Request body      — injection patterns in POST data
"""

import logging
import re

logger = logging.getLogger("cicdecoy.http.enrichment")

# ═══════════════════════════════════════════════════════
#  Severity ordering
# ═══════════════════════════════════════════════════════

_SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _higher_severity(a: str, b: str) -> str:
    """Return whichever severity is higher."""
    return a if _SEVERITY_ORDER.get(a, 0) >= _SEVERITY_ORDER.get(b, 0) else b


# ═══════════════════════════════════════════════════════
#  Path-based rules (compiled once)
# ═══════════════════════════════════════════════════════

_PATH_RULES: list[tuple[re.Pattern, dict]] = []


def _path(pattern: str, technique_id: str, technique_name: str,
           tactic: str, severity: str, tags: list[str]) -> None:
    """Register a path detection rule."""
    _PATH_RULES.append((
        re.compile(pattern, re.IGNORECASE),
        {
            "technique_id": technique_id,
            "technique_name": technique_name,
            "tactic": tactic,
            "severity": severity,
            "tags": tags,
        },
    ))


# --- critical --------------------------------------------------------
_path(
    r"^/\.env",
    "T1190", "Exploit Public-Facing Application",
    "initial-access", "critical", ["config-exposure"],
)
_path(
    r"^/(config\.php|wp-config\.php)",
    "T1190", "Exploit Public-Facing Application",
    "initial-access", "critical", ["config-exposure"],
)
_path(
    r"^/\.(git|svn)(/|$)",
    "T1190", "Exploit Public-Facing Application",
    "initial-access", "critical", ["source-exposure", "git-dump"],
)
_path(
    r"^/(backup|dump|db)\.sql",
    "T1005", "Data from Local System",
    "collection", "critical", ["database-dump"],
)

# --- high -------------------------------------------------------------
_path(
    r"^/wp-(login\.php|admin)",
    "T1078", "Valid Accounts",
    "credential-access", "high", ["wordpress", "brute-force"],
)
_path(
    r"^/(phpmyadmin|pma|dbadmin)",
    "T1078", "Valid Accounts",
    "credential-access", "high", ["database-admin"],
)
_path(
    r"^/(admin|administrator|manager)(/|$)",
    "T1078", "Valid Accounts",
    "credential-access", "high", ["admin-panel"],
)
_path(
    r"^/(actuator/env|debug/|trace/)",
    "T1082", "System Information Discovery",
    "discovery", "high", ["debug-endpoint"],
)

# --- medium -----------------------------------------------------------
_path(
    r"^/api/v1/(auth/|login)",
    "T1078", "Valid Accounts",
    "credential-access", "medium", ["api-auth"],
)
_path(
    r"^/api/v1/(users|config)",
    "T1087", "Account Discovery",
    "discovery", "medium", ["api-enum"],
)
_path(
    r"^/api/v1/graphql",
    "T1190", "Exploit Public-Facing Application",
    "initial-access", "medium", ["graphql-probe"],
)
_path(
    r"^/(server-status|server-info)",
    "T1082", "System Information Discovery",
    "discovery", "medium", ["server-info"],
)

# --- low --------------------------------------------------------------
_path(
    r"^/(robots\.txt|sitemap\.xml)",
    "T1595", "Active Scanning",
    "reconnaissance", "low", ["recon"],
)


# ═══════════════════════════════════════════════════════
#  User-Agent detection rules
# ═══════════════════════════════════════════════════════

_UA_RULES: list[tuple[re.Pattern, str, list[str]]] = [
    (re.compile(r"sqlmap", re.I),           "sqlmap",           ["sqli-scanner"]),
    (re.compile(r"nikto", re.I),            "Nikto",            ["vuln-scanner"]),
    (re.compile(r"nmap", re.I),             "Nmap",             ["port-scanner"]),
    (re.compile(r"(dirbuster|gobuster|dirb|ffuf)", re.I),
                                             "directory bruter", ["dir-brute"]),
    (re.compile(r"wpscan", re.I),           "WPScan",           ["wordpress-scanner"]),
    (re.compile(r"masscan", re.I),          "Masscan",          ["mass-scanner"]),
    (re.compile(r"nuclei", re.I),           "Nuclei",           ["vuln-scanner"]),
    (re.compile(r"burp(suite)?", re.I),     "Burp Suite",       ["proxy-tool"]),
    (re.compile(r"python-requests", re.I),  "Python script",    ["scripted"]),
    (re.compile(r"python-urllib", re.I),     "Python script",    ["scripted"]),
    (re.compile(r"curl/", re.I),            "CLI tool",         ["cli-tool"]),
    (re.compile(r"wget/", re.I),            "CLI tool",         ["cli-tool"]),
    (re.compile(r"Go-http-client", re.I),   "Go script",        ["scripted"]),
]


# ═══════════════════════════════════════════════════════
#  Injection detection rules
# ═══════════════════════════════════════════════════════

_INJECTION_RULES: list[tuple[re.Pattern, str, str, str]] = [
    # SQLi
    (re.compile(r"""\bOR\s+\d+\s*=\s*\d+""", re.I),
     "sqli", "T1190", "Exploit Public-Facing Application"),
    (re.compile(r"""['"]?\s*OR\s+['"]['"]\s*=\s*['"]""", re.I),
     "sqli", "T1190", "Exploit Public-Facing Application"),
    (re.compile(r"UNION\s+(ALL\s+)?SELECT", re.I),
     "sqli", "T1190", "Exploit Public-Facing Application"),
    (re.compile(r";\s*DROP\s+TABLE", re.I),
     "sqli", "T1190", "Exploit Public-Facing Application"),

    # XSS
    (re.compile(r"<\s*script", re.I),
     "xss", "T1059.007", "Command and Scripting Interpreter: JavaScript"),
    (re.compile(r"javascript\s*:", re.I),
     "xss", "T1059.007", "Command and Scripting Interpreter: JavaScript"),
    (re.compile(r"on(error|load)\s*=", re.I),
     "xss", "T1059.007", "Command and Scripting Interpreter: JavaScript"),

    # Path traversal
    (re.compile(r"\.\./|\.\.\\"),
     "path-traversal", "T1083", "File and Directory Discovery"),
    (re.compile(r"/etc/passwd|/proc/self"),
     "path-traversal", "T1083", "File and Directory Discovery"),

    # Log4Shell / SSTI
    (re.compile(r"\$\{jndi:", re.I),
     "log4shell", "T1190", "Exploit Public-Facing Application"),
    (re.compile(r"\$\{env:", re.I),
     "ssti", "T1190", "Exploit Public-Facing Application"),

    # Template injection
    (re.compile(r"\{\{"),
     "template-injection", "T1190", "Exploit Public-Facing Application"),
    (re.compile(r"\{%"),
     "template-injection", "T1190", "Exploit Public-Facing Application"),
    (re.compile(r"\$\{[^}]{2,}"),
     "template-injection", "T1190", "Exploit Public-Facing Application"),
]


# ═══════════════════════════════════════════════════════
#  Method-based rules
# ═══════════════════════════════════════════════════════

_DISCOVERY_METHODS = {"OPTIONS", "TRACE", "DEBUG"}
_DANGEROUS_METHODS = {"PUT", "DELETE"}
_WEBDAV_METHODS = {"PROPFIND", "MKCOL"}


# ═══════════════════════════════════════════════════════
#  Classifier
# ═══════════════════════════════════════════════════════

class HttpRequestClassifier:
    """Classify HTTP requests into ATT&CK techniques and severity levels."""

    # ── path analysis ────────────────────────────────

    def classify_path(self, path: str) -> dict:
        """Match request path against known suspicious patterns."""
        for pattern, result in _PATH_RULES:
            if pattern.search(path):
                return dict(result)  # shallow copy
        return {
            "technique_id": None,
            "technique_name": None,
            "tactic": None,
            "severity": "info",
            "tags": [],
        }

    # ── user-agent analysis ──────────────────────────

    def classify_user_agent(self, ua: str) -> dict:
        """Detect scanners and attack tools from User-Agent string."""
        if not ua or ua.strip() == "-":
            return {
                "tool_signature": "No UA",
                "tags": ["suspicious", "no-user-agent"],
            }

        for pattern, tool, tags in _UA_RULES:
            if pattern.search(ua):
                return {
                    "tool_signature": tool,
                    "tags": list(tags),
                }

        return {
            "tool_signature": None,
            "tags": [],
        }

    # ── injection detection ──────────────────────────

    def detect_injection(self, value: str) -> list[str]:
        """Detect common injection patterns in query params or POST body.

        Returns a list of matched injection type strings (e.g. "sqli", "xss").
        """
        if not value:
            return []

        found: list[str] = []
        seen: set[str] = set()
        for pattern, inj_type, _, _ in _INJECTION_RULES:
            if inj_type not in seen and pattern.search(value):
                found.append(inj_type)
                seen.add(inj_type)
        return found

    def _injection_classifications(self, value: str) -> list[dict]:
        """Return full classification dicts for all injection matches."""
        if not value:
            return []

        results: list[dict] = []
        seen: set[str] = set()
        for pattern, inj_type, technique_id, technique_name in _INJECTION_RULES:
            if inj_type not in seen and pattern.search(value):
                seen.add(inj_type)
                results.append({
                    "technique_id": technique_id,
                    "technique_name": technique_name,
                    "tactic": "initial-access",
                    "severity": "high",
                    "tags": [inj_type],
                })
        return results

    # ── method analysis ──────────────────────────────

    def classify_method(self, method: str, path: str) -> dict:
        """Classify based on HTTP method."""
        method_upper = method.upper()

        if method_upper in _DISCOVERY_METHODS:
            return {
                "technique_id": "T1082",
                "technique_name": "System Information Discovery",
                "tactic": "discovery",
                "severity": "medium",
                "tags": ["unusual-method"],
            }

        if method_upper in _DANGEROUS_METHODS:
            return {
                "technique_id": "T1190",
                "technique_name": "Exploit Public-Facing Application",
                "tactic": "initial-access",
                "severity": "high",
                "tags": ["dangerous-method"],
            }

        if method_upper in _WEBDAV_METHODS:
            return {
                "technique_id": "T1595",
                "technique_name": "Active Scanning",
                "tactic": "reconnaissance",
                "severity": "medium",
                "tags": ["webdav-probe"],
            }

        return {
            "technique_id": None,
            "technique_name": None,
            "tactic": None,
            "severity": "info",
            "tags": [],
        }

    # ── combined classification ──────────────────────

    def classify(self, method: str, path: str, headers: dict,
                 body: str | None = None, query: str | None = None) -> dict:
        """Classify an HTTP request by combining all signal sources.

        Returns:
            {
                "technique_id": "T1190" | None,
                "technique_name": str | None,
                "tactic": str | None,
                "severity": "info" | "low" | "medium" | "high" | "critical",
                "tags": list[str],
                "tool_signature": str | None,
            }
        """
        # Gather individual classifications
        path_cls = self.classify_path(path)
        method_cls = self.classify_method(method, path)
        ua = headers.get("User-Agent", headers.get("user-agent", ""))
        ua_cls = self.classify_user_agent(ua)

        # Start with the highest-severity ATT&CK classification
        best = path_cls
        best_sev = best["severity"]

        # Compare method classification
        if _SEVERITY_ORDER.get(method_cls["severity"], 0) > _SEVERITY_ORDER.get(best_sev, 0):
            best = method_cls
            best_sev = best["severity"]

        # Check query and body injections
        injection_sources: list[dict] = []
        if query:
            injection_sources.extend(self._injection_classifications(query))
        if body:
            injection_sources.extend(self._injection_classifications(body))

        for inj in injection_sources:
            if _SEVERITY_ORDER.get(inj["severity"], 0) > _SEVERITY_ORDER.get(best_sev, 0):
                best = inj
                best_sev = inj["severity"]

        # Accumulate all tags
        all_tags: list[str] = []
        all_tags.extend(path_cls.get("tags", []))
        all_tags.extend(method_cls.get("tags", []))
        all_tags.extend(ua_cls.get("tags", []))
        for inj in injection_sources:
            all_tags.extend(inj.get("tags", []))

        # Deduplicate while preserving order
        seen_tags: set[str] = set()
        unique_tags: list[str] = []
        for tag in all_tags:
            if tag not in seen_tags:
                seen_tags.add(tag)
                unique_tags.append(tag)

        return {
            "technique_id": best.get("technique_id"),
            "technique_name": best.get("technique_name"),
            "tactic": best.get("tactic"),
            "severity": best_sev,
            "tags": unique_tags,
            "tool_signature": ua_cls.get("tool_signature"),
        }
