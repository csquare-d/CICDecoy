# CI/CDecoy — Prompt Engine
# inference/src/prompt_engine.py
#
# Constructs system and user prompts for the LLM based on the
# decoy profile and session context. This is where the "personality"
# of the decoy gets translated into LLM instructions.

import json
import logging
import os
import re
import unicodedata

logger = logging.getLogger("cicdecoy.prompt")

# ── Prompt injection sanitization ───────────────────────────────
# Attacker-controlled strings (commands, usernames, env vars, file
# names) are injected into the LLM prompt.  We must prevent them
# from breaking out of the data context.

# Patterns that could trick the LLM into switching roles
_INJECTION_PATTERNS = re.compile(
    r"(?i)"
    r"(?:"
    r"ignore\b.*?\bprevious\b.*?\binstructions"
    r"|you\s+are\s+(?:now|no\s+longer)\b"
    r"|system\s*:"
    r"|assistant\s*:"
    r"|user\s*:"
    r"|<\|?(?:system|im_start|im_end)\|?>"
    r"|<<\s*SYS\s*>>"
    r"|\[INST\]"
    r"|CRITICAL\s+RULES"
    r"|COMMAND\s+TO\s+EXECUTE"
    r"|OUTPUT\s*:"
    r")"
)


def _sanitize_prompt_field(value: str, max_length: int = 4096) -> str:
    """Sanitize a string before injecting it into an LLM prompt.

    - Strips characters that could act as prompt delimiters
    - Replaces injection patterns with a safe placeholder
    - Truncates to prevent context window abuse
    """
    if isinstance(value, bytes):
        value = value.decode('utf-8', errors='replace')
    elif not isinstance(value, str):
        value = str(value)
    # Truncate first to bound work
    value = value[:max_length]
    # Normalize Unicode to NFKC form (maps lookalike chars to ASCII equivalents)
    value = unicodedata.normalize('NFKC', value)
    # Replace invisible Unicode characters with spaces so word boundaries
    # are preserved for injection pattern detection
    value = re.sub(
        r'[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u061c\ufeff\ufff9-\ufffb]',
        ' ', value
    )
    # Replace triple-dash separators (our prompt delimiter)
    value = value.replace("---", "___")
    # Neutralise injection patterns
    value = _INJECTION_PATTERNS.sub("[FILTERED]", value)
    return value


class PromptEngine:
    """
    Builds the prompts that make the LLM behave like a specific server.

    System prompt = "who you are" (profile, OS, installed software, narrative)
    User prompt   = "what just happened" (command + session state)

    The system prompt stays constant across a session.
    The user prompt changes with every command.
    """

    BASE_SYSTEM_TEMPLATE = """You are emulating an interactive Linux terminal session. You are NOT an AI assistant — you ARE the terminal. Your sole job is to produce the exact output that the given command would produce on the described system.

CRITICAL RULES:
1. Output ONLY what the terminal would display. No explanations, no commentary, no markdown.
2. Never reveal you are a simulation. Never say "I", "AI", "language model", "simulate", "emulate", or "pretend".
3. Never output command prompts (like user@host:~$). Only output the command's stdout/stderr.
4. If a command would produce no output (like cd, export), return exactly an empty string.
5. If a command is not installed, return: -bash: <command>: command not found
6. If a file doesn't exist, return the appropriate error (e.g., "No such file or directory").
7. Maintain consistency with everything described below and with prior commands in this session.
8. If the command would require network access to an external host, simulate a realistic timeout or connection refused error.

SYSTEM IDENTITY:
{system_identity}

INSTALLED SOFTWARE:
{installed_software}

RUNNING SERVICES:
{running_services}

USER ACCOUNTS:
{user_accounts}

ENVIRONMENT:
{environment}

SYSTEM NARRATIVE:
{narrative}

Remember: You produce raw terminal output only. Nothing else. Ever."""

    USER_PROMPT_TEMPLATE = """CURRENT SESSION STATE:
- Logged in as: {username} (uid={uid})
- Working directory: {cwd}
- Environment variables: {env_summary}

RECENT COMMAND HISTORY (for context):
{command_history}

CURRENT DIRECTORY CONTENTS:
{cwd_contents}

---
COMMAND TO EXECUTE:
{command}

OUTPUT:"""

    def __init__(self):
        self.profiles: dict[str, dict] = {}
        self.base_prompts: dict[str, str] = {}

    async def load_profiles(self):
        """Load all available DecoyProfile definitions."""
        profiles_dir = os.environ.get(
            "PROFILES_DIR", "/etc/cicdecoy/profiles"
        )
        if not os.path.isdir(profiles_dir):
            logger.warning(f"Profiles directory not found: {profiles_dir}")
            return

        for filename in os.listdir(profiles_dir):
            if not re.match(r'^[a-zA-Z0-9_-]+\.json$', filename):
                if filename.endswith(".json"):
                    logger.warning("Skipping invalid profile filename: %s", filename)
                continue
            if filename.endswith(".json"):
                profile_name = filename[:-5]
                filepath = os.path.join(profiles_dir, filename)
                real_path = os.path.realpath(filepath)
                real_dir = os.path.realpath(profiles_dir)
                if not real_path.startswith(real_dir + os.sep):
                    logger.warning("Profile path escapes directory: %s", filename)
                    continue
                try:
                    with open(filepath) as f:
                        loaded = json.load(f)
                    required_keys = {"system", "users"}
                    missing = required_keys - set(loaded.keys())
                    if missing:
                        logger.warning(
                            f"Profile {profile_name} missing keys: {missing}, skipping"
                        )
                        continue
                    self.profiles[profile_name] = loaded
                    logger.info(f"Loaded profile: {profile_name}")
                except Exception as e:
                    logger.error(f"Failed to load profile {filename}: {e}")

        # Also load any prompt template overrides
        prompts_dir = os.environ.get(
            "PROMPTS_DIR", "/etc/cicdecoy/prompts"
        )
        if os.path.isdir(prompts_dir):
            for filename in os.listdir(prompts_dir):
                if filename.endswith(".txt"):
                    filepath = os.path.join(prompts_dir, filename)
                    real_path = os.path.realpath(filepath)
                    real_dir = os.path.realpath(prompts_dir)
                    if not real_path.startswith(real_dir + os.sep):
                        logger.warning("Prompt path escapes directory: %s", filename)
                        continue
                    try:
                        with open(filepath) as f:
                            self.base_prompts[filename[:-4]] = f.read()
                    except Exception as e:
                        logger.error(f"Failed to load prompt template {filename}: {e}")
                        continue

    def build_system_prompt(
        self,
        profile_name: str,
        hostname: str,
        username: str,
    ) -> str:
        """
        Construct the system prompt from a profile.

        This prompt tells the LLM everything about the machine
        it's pretending to be. It stays constant across all
        commands in a session.
        """
        profile = self.profiles.get(profile_name)
        if profile is None:
            logger.warning(f"Profile '{profile_name}' not found, using defaults")
            profile = {}
        system = profile.get("system", {})
        users = profile.get("users", [])
        software = profile.get("software", {})
        env = profile.get("environment", {})
        narrative = _sanitize_prompt_field(profile.get("narrative", "A standard Linux server."), 1024)

        # Format system identity
        system_identity = (
            f"Hostname: {_sanitize_prompt_field(hostname, 256)}\n"
            f"OS: {_sanitize_prompt_field(system.get('os', 'Ubuntu 22.04 LTS'), 256)}\n"
            f"Kernel: {_sanitize_prompt_field(system.get('kernel', '5.15.0-generic'), 256)}\n"
            f"Architecture: x86_64\n"
            f"Uptime: {_sanitize_prompt_field(system.get('uptime', '30 days'), 256)}\n"
            f"Timezone: {_sanitize_prompt_field(system.get('timezone', 'UTC'), 64)}"
        )

        # Format installed software
        packages = software.get("packages", [])
        sw_lines = []
        for pkg in packages:
            name = _sanitize_prompt_field(str(pkg.get('name', '')), 128)
            version = _sanitize_prompt_field(str(pkg.get('version', '')), 64)
            sw_lines.append(f"- {name} {version}")
        installed_software = "\n".join(sw_lines) if sw_lines else "Standard Ubuntu packages"

        # Format running services
        services = software.get("services", [])
        svc_lines = []
        for svc in services:
            svc_name = _sanitize_prompt_field(str(svc.get('name', '')), 128)
            status = _sanitize_prompt_field(str(svc.get('status', 'active')), 32)
            port_str = f" (port {_sanitize_prompt_field(str(svc.get('port', '')), 16)})" if svc.get("port") else ""
            svc_lines.append(f"- {svc_name}: {status}{port_str}")
        running_services = "\n".join(svc_lines) if svc_lines else "sshd, cron"

        # Format user accounts
        user_lines = []
        for user in users:
            uname = _sanitize_prompt_field(str(user.get('name', '')), 64)
            fullname = _sanitize_prompt_field(str(user.get('fullName', '')), 128)
            groups = ", ".join(_sanitize_prompt_field(str(g), 32) for g in user.get("groups", []))
            shell = _sanitize_prompt_field(str(user.get('shell', '/bin/bash')), 64)
            user_lines.append(f"- {uname} ({fullname}) groups=[{groups}] shell={shell}")
        user_accounts = "\n".join(user_lines)

        # Format environment
        env_vars = env.get("variables", {})
        crontab = env.get("crontab", [])
        env_str = "Variables:\n"
        for k, v in env_vars.items():
            env_str += f"  {_sanitize_prompt_field(str(k), 64)}={_sanitize_prompt_field(str(v), 256)}\n"
        if crontab:
            env_str += "Crontab entries:\n"
            for entry in crontab:
                env_str += f"  {_sanitize_prompt_field(str(entry), 256)}\n"

        return self.BASE_SYSTEM_TEMPLATE.format(
            system_identity=system_identity,
            installed_software=installed_software,
            running_services=running_services,
            user_accounts=user_accounts,
            environment=env_str,
            narrative=narrative,
        )

    def build_user_prompt(
        self,
        command: str,
        session_context,  # SessionContext pydantic model
    ) -> str:
        """
        Construct the per-command user prompt.

        Includes current session state so the LLM's response
        is consistent with what happened earlier in the session.
        """
        # Format command history (last 10 for context window efficiency)
        history = list(session_context.command_history)[-10:]
        history_str = "\n".join(
            f"  {i+1}. {_sanitize_prompt_field(cmd, 1024)}"
            for i, cmd in enumerate(history)
        ) if history else "  (no previous commands)"

        # Format cwd contents from filesystem snapshot
        fs = session_context.filesystem_snapshot
        cwd_entries = fs.get("cwd_contents", [])
        cwd_str = ""
        for entry in cwd_entries[:30]:  # Cap at 30 entries to save tokens
            type_indicator = "d" if entry.get("type") == "dir" else "-"
            name = _sanitize_prompt_field(entry.get("name", ""), 256)
            owner = _sanitize_prompt_field(entry.get("owner", ""), 32)
            cwd_str += (
                f"  {type_indicator} {owner:<8} "
                f"{entry.get('size', 0):>8}  {name}\n"
            )
        if not cwd_str:
            cwd_str = "  (empty directory)"

        # Summarize env (only relevant vars, not the full set)
        env = session_context.env or {}
        relevant_keys = [
            "PATH", "HOME", "USER", "PWD", "KUBECONFIG",
            "AWS_DEFAULT_REGION", "AWS_PROFILE", "NODE_ENV",
            "ANSIBLE_INVENTORY", "VAULT_ADDR",
        ]
        env_summary = ", ".join(
            f"{k}={_sanitize_prompt_field(v, 256)}"
            for k, v in env.items()
            if k in relevant_keys
        )

        return self.USER_PROMPT_TEMPLATE.format(
            username=_sanitize_prompt_field(session_context.username, 64),
            uid=session_context.uid,
            cwd=_sanitize_prompt_field(session_context.cwd, 512),
            env_summary=env_summary,
            command_history=history_str,
            cwd_contents=cwd_str,
            command=_sanitize_prompt_field(command, 4096),
        )
