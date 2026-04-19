# CI/CDecoy — Response Filter
# inference/src/response_filter.py
#
# Guardrails for LLM output. Prevents the model from breaking character,
# leaking infrastructure details, or producing responses that would
# fingerprint the decoy as non-genuine.

import logging
import re

from metrics import FILTER_VIOLATIONS

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
            FILTER_VIOLATIONS.labels(violation_type="content_filter").inc()
            logger.debug(f"Response filtered (total: {self.filter_count})")

        return response

    def _filter_character_breaks(self, text: str) -> str:
        """
        Detect and handle LLM character breaks.

        Strategy: If the model starts explaining it's an AI, we need
        to replace the entire response with a plausible error or
        empty output — not just redact the phrase, which would leave
        an incoherent response.

        For long responses, ALL patterns are checked cumulatively and
        any matching lines are flagged for removal. If too much is
        removed, the response is considered compromised and blanked.
        """
        if not text:
            return text

        lines = text.split("\n")
        matched_any = False
        indices_to_remove: set[int] = set()

        for pattern, break_type in self.CHARACTER_BREAK_PATTERNS:
            if re.search(pattern, text):
                matched_any = True
                self.break_count += 1
                FILTER_VIOLATIONS.labels(violation_type="character_break").inc()
                logger.warning(
                    f"Character break detected: {break_type} "
                    f"(total: {self.break_count})"
                )
                # If the whole response is a character break, replace entirely
                if len(text) < 200 or text.count('\n') < 3:
                    return ""
                # For longer responses, mark matching lines for removal
                for i, line in enumerate(lines):
                    if re.search(pattern, line):
                        indices_to_remove.add(i)

        if not matched_any:
            return text

        # Remove all flagged lines
        cleaned_lines = [line for i, line in enumerate(lines) if i not in indices_to_remove]

        # Heuristic: if we removed >50% of lines, the response is too compromised
        if len(cleaned_lines) < len(lines) * 0.7:
            return ""

        return "\n".join(cleaned_lines)

    def _redact_infrastructure(self, text: str) -> str:
        """Remove any references to real decoy infrastructure."""
        for pattern in self.REDACT_PATTERNS:
            text = re.sub(pattern, "[REDACTED]", text)
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

