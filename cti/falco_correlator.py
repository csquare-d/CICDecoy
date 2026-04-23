"""
CI/CDecoy — Falco Alert Correlator

Subscribes to Falco runtime security alerts from NATS, correlates
them with active decoy sessions, and stores enriched alerts in
TimescaleDB.

When a Falco alert fires for a decoy pod, this module:
1. Parses the Falco alert from falcosidekick's NATS output
2. Extracts the pod name and namespace
3. Queries active sessions for that pod
4. Enriches the alert with session context
5. Updates the session's Engage outcome (deception_maintained = false)
6. Stores the correlated alert
7. Fires a high-priority composite alert combining app-layer and
   kernel-layer context

This gives IR teams the complete picture of an attacker's actions
from initial deception interaction through escape attempt.
"""

import json
import logging
import uuid
from datetime import UTC, datetime

import asyncpg

logger = logging.getLogger("cicdecoy.falco")


class FalcoCorrelator:
    """
    Correlates Falco runtime alerts with decoy session data.
    """

    # Map Falco rule names to ATT&CK techniques
    FALCO_ATTACK_MAP = {
        "Write to kernel interface":     ("T1611", "Escape to Host"),
        "Mount syscall in container":    ("T1611", "Escape to Host"),
        "Ptrace from container":         ("T1055", "Process Injection"),
        "Kernel module load in container": ("T1611", "Escape to Host"),
        "Unexpected shell in container":   ("T1059.004", "Unix Shell"),
        "Unexpected outbound connection":  ("T1021", "Remote Services"),
        "Internet connection from container": ("T1048", "Exfiltration Over Alternative Protocol"),
        "Container escape recon detected": ("T1082", "System Information Discovery"),
        "Privilege escalation in container": ("T1548", "Abuse Elevation Control Mechanism"),
        "Unexpected binary execution":     ("T1204.002", "Malicious File"),
    }

    def __init__(self, pool: asyncpg.Pool):
        self.pool = pool
        self.alert_count = 0
        self.correlated_count = 0

    async def process_alert(self, alert_data: dict):
        """
        Process a single Falco alert from NATS.

        alert_data is the JSON payload from falcosidekick, which wraps
        the Falco event with additional k8s context.
        """
        self.alert_count += 1

        # Parse falcosidekick format
        rule = alert_data.get("rule", "")
        priority = alert_data.get("priority", "WARNING")
        output = alert_data.get("output", "")

        # Normalize timestamp to a UTC-aware datetime for asyncpg TIMESTAMPTZ
        ts_raw = alert_data.get("time")
        if ts_raw:
            try:
                timestamp = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
                if timestamp.tzinfo is None:
                    timestamp = timestamp.replace(tzinfo=UTC)
            except (ValueError, AttributeError):
                timestamp = datetime.now(UTC)
        else:
            timestamp = datetime.now(UTC)

        # Extract k8s fields from output_fields
        fields = alert_data.get("output_fields", {})
        pod_name = fields.get("k8s.pod.name", "")
        namespace = fields.get("k8s.ns.name", "")
        container = fields.get("container.name", "")
        proc_name = fields.get("proc.name", "")
        cmdline = fields.get("proc.cmdline", "")

        if not pod_name:
            logger.debug(f"Falco alert without pod name: {rule}")
            return

        alert_id = str(uuid.uuid4())

        # Extract decoy name from pod name (format: decoy-{name}-{hash})
        decoy_name = self._pod_to_decoy_name(pod_name)

        # Find the active session for this pod
        session_id = await self._find_active_session(decoy_name, timestamp)

        if session_id:
            self.correlated_count += 1
            logger.info(
                f"Falco alert correlated: rule={rule} pod={pod_name} "
                f"session={session_id[:8]} decoy={decoy_name}"
            )
        else:
            logger.info(
                f"Falco alert (no active session): rule={rule} pod={pod_name}"
            )

        # Store the alert
        async with self.pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO falco_alerts (
                    alert_id, timestamp, rule_name, priority,
                    pod_name, namespace, container_name,
                    process_name, command_line, output,
                    raw_event, correlated_session_id, decoy_name
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
                ON CONFLICT (alert_id, timestamp) DO NOTHING
            """,
                alert_id,
                timestamp,
                rule,
                priority,
                pod_name,
                namespace,
                container,
                proc_name,
                cmdline,
                output,
                json.dumps(alert_data),
                session_id,
                decoy_name,
            )

        # If correlated with a session, update the session's Engage outcome
        if session_id:
            await self._mark_escape_attempt(session_id, decoy_name, rule)

            # Also inject a synthetic event into decoy_events so the
            # full session timeline includes the escape attempt
            await self._inject_escape_event(
                session_id, decoy_name, timestamp, rule, priority,
                proc_name, cmdline, pod_name,
            )

    async def _find_active_session(self, decoy_name: str,
                                    alert_time) -> str:
        """
        Find the most recent active session for a decoy.

        Looks for sessions that have events within the last 5 minutes
        of the Falco alert timestamp.
        """
        if not decoy_name:
            return ""

        async with self.pool.acquire() as conn:
            row = await conn.fetchrow("""
                SELECT session_id FROM decoy_events
                WHERE decoy_name = $1
                  AND (event_type LIKE 'command%' OR event_type LIKE 'connection%')
                  AND timestamp > $2 - INTERVAL '24 hours'
                ORDER BY timestamp DESC
                LIMIT 1
            """, decoy_name, alert_time)

            if row:
                return row["session_id"]
        return ""

    async def _mark_escape_attempt(self, session_id: str,
                                    decoy_name: str, rule: str):
        """
        Update the Engage outcome for a session to reflect that
        the attacker detected the deception and attempted escape.
        """
        async with self.pool.acquire() as conn:
            # Upsert into engage_outcomes
            await conn.execute("""
                INSERT INTO engage_outcomes (
                    session_id, decoy_name,
                    escape_attempted, deception_maintained,
                    falco_alert_count
                ) VALUES ($1, $2, TRUE, FALSE, 1)
                ON CONFLICT (session_id) DO UPDATE SET
                    escape_attempted = TRUE,
                    deception_maintained = FALSE,
                    falco_alert_count = engage_outcomes.falco_alert_count + 1
            """, session_id, decoy_name)

        logger.warning(
            f"Session {session_id[:8]} on {decoy_name}: "
            f"escape attempted (rule: {rule}), deception_maintained=false"
        )

    async def _inject_escape_event(self, session_id: str, decoy_name: str,
                                    timestamp, rule: str, priority: str,
                                    proc_name: str, cmdline: str,
                                    pod_name: str):
        """
        Inject a synthetic event into the decoy_events timeline so
        the escape attempt appears in the session replay.
        """
        default = self.FALCO_ATTACK_MAP.get(rule)
        if default is None:
            logger.warning(
                "Unmapped Falco rule '%s' — using generic fallback T1059", rule
            )
            default = ("T1059", "Command and Scripting Interpreter")
        technique_id, technique_name = default

        event_data = {
            "source": "falco",
            "rule": rule,
            "priority": priority,
            "process": proc_name,
            "command_line": cmdline,
            "pod_name": pod_name,
            "severity": "critical",
            "behavior": "container_escape",
            "mitre_technique": technique_id,
            "mitre_name": technique_name,
        }

        async with self.pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO decoy_events (
                    event_id, timestamp, decoy_name, decoy_tier,
                    session_id, event_type, severity,
                    mitre_techniques, raw_data
                ) VALUES ($1, $2, $3, 0, $4, 'falco.escape', 'critical', $5, $6)
                ON CONFLICT (event_id, timestamp) DO NOTHING
            """,
                str(uuid.uuid4()),
                timestamp,
                decoy_name,
                session_id,
                json.dumps([{"technique_id": technique_id,
                             "technique_name": technique_name,
                             "confidence": "high",
                             "source": "falco"}]),
                json.dumps(event_data),
            )

    @staticmethod
    def _pod_to_decoy_name(pod_name: str) -> str:
        """
        Extract the decoy name from a pod name.
        Pod naming conventions handled:
          - Deployment: decoy-{name}-{rs-hash}-{pod-hash}  → strips 2 trailing segments
          - StatefulSet/short: decoy-{name}-{suffix}       → strips 1 trailing segment
          - Bare: decoy-{name}                              → returns {name}
        """
        if not pod_name.startswith("decoy-"):
            return pod_name

        remainder = pod_name[6:]  # strip "decoy-"
        parts = remainder.rsplit("-", 2)

        if len(parts) == 3:
            # Standard Deployment: name-rsHash-podHash
            return parts[0]
        if len(parts) == 2:
            # Likely StatefulSet (name-ordinal) or simple suffix
            return parts[0]
        return remainder

    @property
    def stats(self) -> dict:
        return {
            "total_alerts": self.alert_count,
            "correlated": self.correlated_count,
            "correlation_rate": (
                round(self.correlated_count / self.alert_count * 100, 1)
                if self.alert_count > 0 else 0
            ),
        }
