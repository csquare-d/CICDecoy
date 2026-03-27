# CI/CDecoy — Prompt Engine
# inference/src/prompt_engine.py
#
# Constructs system and user prompts for the LLM based on the
# decoy profile and session context. This is where the "personality"
# of the decoy gets translated into LLM instructions.

import json
import logging
import os
from typing import Optional

logger = logging.getLogger("cicdecoy.prompt")


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
            if filename.endswith(".json"):
                profile_name = filename[:-5]
                filepath = os.path.join(profiles_dir, filename)
                try:
                    with open(filepath) as f:
                        self.profiles[profile_name] = json.load(f)
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
                    with open(os.path.join(prompts_dir, filename)) as f:
                        self.base_prompts[filename[:-4]] = f.read()

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
        profile = self.profiles.get(profile_name, {})
        system = profile.get("system", {})
        users = profile.get("users", [])
        software = profile.get("software", {})
        env = profile.get("environment", {})
        narrative = profile.get("narrative", "A standard Linux server.")

        # Format system identity
        system_identity = (
            f"Hostname: {hostname}\n"
            f"OS: {system.get('os', 'Ubuntu 22.04 LTS')}\n"
            f"Kernel: {system.get('kernel', '5.15.0-generic')}\n"
            f"Architecture: x86_64\n"
            f"Uptime: {system.get('uptime', '30 days')}\n"
            f"Timezone: {system.get('timezone', 'UTC')}"
        )

        # Format installed software
        packages = software.get("packages", [])
        sw_lines = []
        for pkg in packages:
            sw_lines.append(f"- {pkg['name']} {pkg.get('version', '')}")
        installed_software = "\n".join(sw_lines) if sw_lines else "Standard Ubuntu packages"

        # Format running services
        services = software.get("services", [])
        svc_lines = []
        for svc in services:
            port_str = f" (port {svc['port']})" if svc.get("port") else ""
            svc_lines.append(
                f"- {svc['name']}: {svc.get('status', 'active')}{port_str}"
            )
        running_services = "\n".join(svc_lines) if svc_lines else "sshd, cron"

        # Format user accounts
        user_lines = []
        for user in users:
            groups = ", ".join(user.get("groups", []))
            user_lines.append(
                f"- {user['name']} ({user.get('fullName', '')}) "
                f"groups=[{groups}] shell={user.get('shell', '/bin/bash')}"
            )
        user_accounts = "\n".join(user_lines)

        # Format environment
        env_vars = env.get("variables", {})
        crontab = env.get("crontab", [])
        env_str = "Variables:\n"
        for k, v in env_vars.items():
            env_str += f"  {k}={v}\n"
        if crontab:
            env_str += "Crontab entries:\n"
            for entry in crontab:
                env_str += f"  {entry}\n"

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
        history = session_context.command_history[-10:]
        history_str = "\n".join(
            f"  {i+1}. {cmd}" for i, cmd in enumerate(history)
        ) if history else "  (no previous commands)"

        # Format cwd contents from filesystem snapshot
        fs = session_context.filesystem_snapshot
        cwd_entries = fs.get("cwd_contents", [])
        cwd_str = ""
        for entry in cwd_entries[:30]:  # Cap at 30 entries to save tokens
            type_indicator = "d" if entry.get("type") == "dir" else "-"
            cwd_str += (
                f"  {type_indicator} {entry['owner']:<8} "
                f"{entry.get('size', 0):>8}  {entry['name']}\n"
            )
        if not cwd_str:
            cwd_str = "  (empty directory)"

        # Summarize env (only relevant vars, not the full set)
        env = session_context.env
        relevant_keys = [
            "PATH", "HOME", "USER", "PWD", "KUBECONFIG",
            "AWS_DEFAULT_REGION", "AWS_PROFILE", "NODE_ENV",
            "ANSIBLE_INVENTORY", "VAULT_ADDR",
        ]
        env_summary = ", ".join(
            f"{k}={v}" for k, v in env.items()
            if k in relevant_keys
        )

        return self.USER_PROMPT_TEMPLATE.format(
            username=session_context.username,
            uid=session_context.uid,
            cwd=session_context.cwd,
            env_summary=env_summary,
            command_history=history_str,
            cwd_contents=cwd_str,
            command=command,
        )
