# CI/CDecoy — Response Filter
# inference/src/response_filter.py
#
# Guardrails for LLM output. Prevents the model from breaking character,
# leaking infrastructure details, or producing responses that would
# fingerprint the decoy as non-genuine.

import re
import logging

logger = logging.getLogger("cicdecoy.filter")


class ResponseFilter:
    """
    Multi-pass filter applied to all LLM responses before they
    reach the attacker.

    Filter stages:
    1. Character break detection — catch the LLM saying "I'm an AI"
    2. Infrastructure leak prevention — redact real decoy paths
    3. Format normalization — strip markdown, code fences, etc.
    4. Consistency enforcement — detect contradictions
    5. Length enforcement — prevent token-wasting verbosity
    """

    # Patterns that indicate the LLM has broken character.
    # Ordered by severity.
    CHARACTER_BREAK_PATTERNS = [
        (r"(?i)\bI('m| am) an? (AI|artificial|language model|LLM|chatbot)\b",
         "ai_identity_leak"),
        (r"(?i)\bI can('t| ?not) (actually|really) (execute|run|access)\b",
         "capability_denial"),
        (r"(?i)\b(simulated?|emulat(e|ed|ing)|pretend|fake|honeypot|decoy)\b",
         "deception_reveal"),
        (r"(?i)\b(as a language model|as an AI|in (this|my) simulation)\b",
         "meta_reference"),
        (r"(?i)\bI don'?t (actually )?have (access to|a real)\b",
         "reality_break"),
        (r"(?i)\bcicdecoy\b",
         "platform_name_leak"),
        (r"(?i)\bthis (is|appears to be) (a )?(test|simulation|exercise)\b",
         "simulation_acknowledgment"),
    ]

    # Paths and strings that must never appear in output
    REDACT_PATTERNS = [
        r"/opt/cicdecoy\S*",
        r"/var/log/decoy\S*",
        r"/etc/cicdecoy\S*",
        r"inference-gateway\S*",
        r"cicdecoy-system",
        r"decoy-operator",
        r"nats://msg-bus\S*",
        r"otel-collector\S*",
    ]

    # Markdown/formatting artifacts the LLM might produce
    FORMAT_CLEANUP_PATTERNS = [
        (r"^```\w*\n?", ""),            # Opening code fence
        (r"\n?```$", ""),                # Closing code fence
        (r"^\*\*(.+?)\*\*$", r"\1"),    # Bold markdown
        (r"^#+\s+", ""),                 # Heading markers
        (r"^>\s+", ""),                  # Blockquotes
    ]

    def __init__(self):
        self.filter_count = 0
        self.break_count = 0

    def apply(self, response: str, profile: str = "") -> str:
        """Apply all filter stages to an LLM response."""
        original = response

        # Stage 1: Character break detection
        response = self._filter_character_breaks(response)

        # Stage 2: Infrastructure leak redaction
        response = self._redact_infrastructure(response)

        # Stage 3: Format normalization
        response = self._clean_formatting(response)

        # Stage 4: Length enforcement
        response = self._enforce_length(response, max_lines=500)

        # Stage 5: Strip leading/trailing whitespace and empty lines
        response = response.strip()

        if response != original:
            self.filter_count += 1
            logger.debug(f"Response filtered (total: {self.filter_count})")

        return response

    def _filter_character_breaks(self, text: str) -> str:
        """
        Detect and handle LLM character breaks.

        Strategy: If the model starts explaining it's an AI, we need
        to replace the entire response with a plausible error or
        empty output — not just redact the phrase, which would leave
        an incoherent response.
        """
        for pattern, break_type in self.CHARACTER_BREAK_PATTERNS:
            if re.search(pattern, text):
                self.break_count += 1
                logger.warning(
                    f"Character break detected: {break_type} "
                    f"(total: {self.break_count})"
                )
                # If the whole response is a character break, replace entirely
                if len(text) < 200 or text.count('\n') < 3:
                    return ""

                # For longer responses where only part broke character,
                # try to salvage by removing the offending lines
                lines = text.split("\n")
                clean_lines = []
                for line in lines:
                    if not re.search(pattern, line):
                        clean_lines.append(line)
                text = "\n".join(clean_lines)

        return text

    def _redact_infrastructure(self, text: str) -> str:
        """Remove any references to real decoy infrastructure."""
        for pattern in self.REDACT_PATTERNS:
            text = re.sub(pattern, "/usr/local/lib", text)
        return text

    def _clean_formatting(self, text: str) -> str:
        """Strip markdown and other LLM formatting artifacts."""
        for pattern, replacement in self.FORMAT_CLEANUP_PATTERNS:
            text = re.sub(pattern, replacement, text, flags=re.MULTILINE)
        return text

    def _enforce_length(self, text: str, max_lines: int = 500) -> str:
        """Prevent excessively long responses."""
        lines = text.split("\n")
        if len(lines) > max_lines:
            return "\n".join(lines[:max_lines])
        return text


# ─────────────────────────────────────────────────────────

# CI/CDecoy — Timing Model
# inference/src/timing.py
#
# Injects realistic latency so responses don't arrive suspiciously
# fast (or slow).

class TimingModel:
    """
    Model for realistic command response timing.

    Real servers have characteristic latency profiles:
    - Simple builtins: 1-5ms
    - File reads: 5-50ms (depends on size)
    - Process listing: 20-100ms
    - Network operations: 100ms-30s (timeouts)
    - Package managers: 500ms-60s

    The inference service already has inherent latency from LLM
    generation. This model tells the decoy how much ADDITIONAL
    delay to add (or whether the LLM was too slow and we need
    to log a warning).
    """

    # Target latencies in seconds by command category
    LATENCY_PROFILES = {
        "instant":  {"min": 0.001, "max": 0.005, "mean": 0.003},
        "fast":     {"min": 0.005, "max": 0.050, "mean": 0.020},
        "moderate": {"min": 0.050, "max": 0.300, "mean": 0.100},
        "slow":     {"min": 0.300, "max": 2.000, "mean": 0.800},
        "network":  {"min": 0.500, "max": 30.00, "mean": 3.000},
        "heavy":    {"min": 1.000, "max": 60.00, "mean": 5.000},
    }

    # Command → category mapping
    COMMAND_CATEGORIES = {
        "instant": ["pwd", "whoami", "id", "hostname", "echo", "true",
                     "false", "cd", "export", "unset", "alias"],
        "fast":    ["ls", "cat", "head", "tail", "wc", "date", "uptime",
                     "uname", "env", "printenv", "basename", "dirname"],
        "moderate":["ps", "df", "free", "mount", "lsblk", "ip", "ss",
                    "netstat", "systemctl", "journalctl", "docker"],
        "slow":    ["find", "grep", "locate", "du", "tar", "zip",
                    "ansible", "terraform", "kubectl"],
        "network": ["ssh", "scp", "curl", "wget", "ping", "nmap",
                    "nc", "telnet", "dig", "nslookup"],
        "heavy":   ["apt", "yum", "pip", "npm", "make", "gcc",
                    "docker build", "docker pull"],
    }

    def get_target_latency(self, command: str) -> dict:
        """Return the target latency profile for a command."""
        cmd = command.split()[0] if command.split() else command

        for category, commands in self.COMMAND_CATEGORIES.items():
            if cmd in commands:
                return self.LATENCY_PROFILES[category]

        return self.LATENCY_PROFILES["moderate"]
