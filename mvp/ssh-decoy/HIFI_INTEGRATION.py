"""
CI/CDecoy — Command Router Integration Patch

This shows the changes needed in command_router.py to integrate
the high-fidelity scripted engine. The resolution order becomes:

  1. Built-in (cd, export, echo) — modifies session state
  2. Fast-path (ls, cat, pwd)   — served from virtual filesystem
  3. High-fidelity engine       — response DB + decomposition + templates
  4. Basic scripted fallback    — simple key-value (Tier 2 original)
  5. LLM inference              — Tier 3 only
  6. "command not found"        — final fallback

The high-fidelity engine handles:
  - Exact/fuzzy matches against captured response databases
  - Pipe chains (ps aux | grep python | wc -l)
  - Command composition (find, grep, wc against virtual filesystem)
  - Network commands with realistic timeouts
  - File mutations (touch, mkdir) that update the virtual filesystem
"""

# ── Add to CommandRouter.__init__ ─────────────────────

# from hifi_engine import HighFidelityEngine
#
# class CommandRouter:
#     def __init__(self, config):
#         ...existing code...
#
#         # High-fidelity scripted engine (new)
#         self.hifi_engine = HighFidelityEngine()

# ── Add to CommandRouter.initialize ───────────────────

# async def initialize(self):
#     ...existing code...
#
#     # Load response databases
#     response_db_dir = os.environ.get("RESPONSE_DB_DIR", "/etc/cicdecoy/responses")
#     if Path(response_db_dir).is_dir():
#         self.hifi_engine.load_all_databases(response_db_dir)
#     else:
#         logger.info("No response databases found — high-fidelity engine has templates only")

# ── Replace the route() method ────────────────────────

async def route_with_hifi(self, command, session_state, filesystem, tier):
    """
    Updated routing with high-fidelity engine inserted.
    """
    # Stage 1: Built-in shell commands (unchanged)
    result = self._handle_builtin(command, session_state, filesystem)
    if result is not None:
        self.last_source = "builtin"
        return result

    # Stage 2: Fast-path (unchanged)
    for rule in self.fast_path_rules:
        if rule["pattern"].match(command):
            result = self._handle_fast_path(
                command, rule["source"], session_state, filesystem
            )
            if result is not None:
                self.last_source = "fast_path"
                return result

    # Stage 3: HIGH-FIDELITY SCRIPTED ENGINE (new)
    # This handles response DB matches, pipe chains, templates,
    # file mutations, and network command simulation.
    hifi_result = self.hifi_engine.handle(command, session_state, filesystem)
    if hifi_result is not None:
        self.last_source = "hifi_scripted"
        return hifi_result

    # Stage 4: Tier-specific dispatch
    if tier == 1:
        self.last_source = "tier1_stub"
        cmd = command.split()[0] if command.split() else command
        return f"-bash: {cmd}: command not found"

    elif tier == 2:
        # Basic scripted (original Tier 2 — catches anything hifi missed)
        result = self._handle_scripted(command, session_state)
        self.last_source = "scripted"
        return result

    elif tier == 3:
        # LLM inference (only for truly novel commands)
        result = await self._handle_adaptive(command, session_state, filesystem)
        self.last_source = "llm"
        return result

    return ""


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  MANIFEST SCHEMA ADDITION
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#
#  The decoy manifest schema gets a new field under fidelity.scripted:
#
#  fidelity:
#    tier: 2
#    scripted:
#      responseSet: "ubuntu-22.04-full"    # Captured response database
#      highFidelity: true                   # Activate stateful engine
#      profileRef: "dev-workstation"        # Same profiles as Tier 3
#      responseDatabases:                   # Additional response DBs to load
#        - "docker-24.0"
#        - "kubernetes-1.28"
#        - "ansible-2.15"
#      customResponses:                     # Manual overrides (highest priority)
#        - match: "cat /opt/app/secret.key"
#          response: "sk-proj-4f8a2b..."
#      fastPath:                            # Same fast-path as Tier 3
#        enabled: true
#        commands:
#          - { match: "^ls", source: filesystem }
#          - { match: "^pwd$", source: state }
#
#  The highFidelity flag tells the operator to:
#  1. Mount the response database into the container
#  2. Mount the profile (same as Tier 3)
#  3. Initialize the full virtual filesystem
#  4. Enable the HighFidelityEngine in the command router
#
#  But NOT start the LLM inference service or connect to it.
#
#  Resource cost is identical to basic Tier 2 (~128MB RAM)
#  because there's no inference overhead.


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  RESPONSE DATABASE BUILD WORKFLOW
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#
#  Building a response database for a new decoy persona:
#
#  1. PROVISION a VM that matches your target profile
#     - Ubuntu 22.04, install the same packages, create same users
#     - Or use an existing dev/staging box (with permission)
#
#  2. CAPTURE responses:
#     python tools/capture_responses.py \
#       --host 192.168.1.100 --user admin --key ~/.ssh/id_rsa \
#       --profile dev-workstation \
#       --output responses/ubuntu-22.04-dev.json
#
#  3. ADD custom commands relevant to your profile:
#     echo "docker ps" >> extra-commands.txt
#     echo "kubectl get pods -n production" >> extra-commands.txt
#     echo "cat /opt/app/config.json" >> extra-commands.txt
#     python tools/capture_responses.py \
#       --host 192.168.1.100 --user admin --key ~/.ssh/id_rsa \
#       --existing responses/ubuntu-22.04-dev.json \
#       --commands-file extra-commands.txt \
#       --output responses/ubuntu-22.04-dev.json
#
#  4. SANITIZE to replace real values with decoy values:
#     # sanitize.json:
#     # {
#     #   "real-hostname": "dev-ws-03",
#     #   "192.168.1.100": "10.0.1.50",
#     #   "real-user": "admin"
#     # }
#     python tools/capture_responses.py \
#       --host 192.168.1.100 --user admin --key ~/.ssh/id_rsa \
#       --existing responses/ubuntu-22.04-dev.json \
#       --sanitize sanitize.json \
#       --output responses/ubuntu-22.04-dev.json
#
#  5. MOUNT in the decoy container:
#     Mount the JSON as /etc/cicdecoy/responses/ubuntu-22.04-dev.json
#     Reference in manifest: responseSet: "ubuntu-22.04-dev"
#
#  6. TEST fidelity:
#     cicdecoy validate -f decoy.yaml --fidelity-test
#
#
#  The response database is VERSION CONTROLLED alongside the decoy
#  manifests. A change to the database triggers the same CI/CD
#  pipeline as a manifest change — fidelity tests run automatically.
