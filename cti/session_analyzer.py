"""
CI/CDecoy — Session-Level Analysis

Maintains in-memory state per session and produces verdicts on each event.
Called from pipeline.py AFTER per-event enrichment (enrich_event).

This module is stateful — it accumulates data across events within a session.
enrichment.py remains stateless and per-event.

Usage from pipeline.py:
    from session_analyzer import SessionAnalyzer
    analyzer = SessionAnalyzer()

    # In _process_message, after enrichment:
    verdict = await analyzer.ingest(session_id, enriched_payload)
    if verdict["alert_triggers"]:
        for alert in verdict["alert_triggers"]:
            await nc.publish(f"cicdecoy.alert.session.{alert['alert_type']}", ...)

    # On session.end event:
    summary = await analyzer.close_session(session_id)
"""

import asyncio
import hashlib
import json
import logging
import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field

from enrichment import (
    DANGEROUS_PROGRESSIONS,
    SEVERITY_RANK,
    TOOL_CATEGORIES,
    detect_kill_chain,
)

logger = logging.getLogger("cicdecoy.session_analyzer")


# ═══════════════════════════════════════════════════════
#  Session State
# ═══════════════════════════════════════════════════════

@dataclass
class SessionState:
    """Accumulated state for a single attacker session."""
    session_id: str
    start_time: float = field(default_factory=time.time)
    last_event_time: float = field(default_factory=time.time)
    event_count: int = 0
    command_count: int = 0
    phases_seen: set = field(default_factory=set)
    techniques_seen: list = field(default_factory=list)
    technique_ids_seen: set = field(default_factory=set)
    tool_signatures: list = field(default_factory=list)   # flat strings
    tool_names_seen: set = field(default_factory=set)
    max_severity: str = "info"
    command_timestamps: list = field(default_factory=list)
    phase_transitions: list = field(default_factory=list)  # (timestamp, tactic)
    has_evasion: bool = False
    has_sensitive_target: bool = False
    previous_alerts: list = field(default_factory=list)


# ═══════════════════════════════════════════════════════
#  Session Analyzer
# ═══════════════════════════════════════════════════════

_SENSITIVE_TARGETS = {
    "/etc/shadow", "/etc/gshadow", ".ssh/id_rsa",
    ".aws/credentials", ".kube/config", "169.254.169.254",
}

_EVASION_TACTICS = {"defense-evasion"}

MAX_SESSIONS = 10_000
IDLE_TIMEOUT = 1800  # 30 minutes


class SessionAnalyzer:

    def __init__(self, max_sessions: int = MAX_SESSIONS,
                 idle_timeout: int = IDLE_TIMEOUT):
        self._sessions: dict[str, SessionState] = {}
        self._closed_sessions: set = set()
        self._max_sessions = max_sessions
        self._idle_timeout = idle_timeout
        self._lock = asyncio.Lock()
        self._processed_event_ids: OrderedDict[str, float] = OrderedDict()
        self._evicted_summaries: deque[dict] = deque(maxlen=10_000)

    @property
    def active_session_count(self) -> int:
        return len(self._sessions)

    async def ingest(self, session_id: str, enriched_event: dict) -> dict:
        """Process an enriched event and return a session-level verdict.

        Args:
            session_id: The session identifier.
            enriched_event: Dict with keys mitre_techniques, tool_signatures,
                           severity, tags, event_type, data/raw_data.

        Returns:
            Verdict dict with kill_chain_detected, behavioral_score,
            session_classification, alert_triggers, etc.
        """
        if not session_id:
            return self._empty_verdict()

        if session_id in self._closed_sessions:
            return self._empty_verdict()

        # Deduplicate events to guard against NATS retransmissions
        event_id = enriched_event.get("event_id") or enriched_event.get("id", "")
        if not event_id:
            event_id = hashlib.sha256(
                json.dumps(enriched_event, sort_keys=True, default=str).encode()
            ).hexdigest()[:32]

        async with self._lock:
            if event_id in self._processed_event_ids:
                return self._empty_verdict()
            self._processed_event_ids[event_id] = time.monotonic()
            # Evict entries older than 10 minutes (NATS redelivery window)
            if len(self._processed_event_ids) > 100_000:
                cutoff = time.monotonic() - 600  # 10 minutes
                to_remove = [
                    k for k, ts in self._processed_event_ids.items()
                    if ts < cutoff
                ]
                for k in to_remove:
                    del self._processed_event_ids[k]
                # If still over limit after time-based eviction, trim oldest
                if len(self._processed_event_ids) > 100_000:
                    to_remove = list(self._processed_event_ids.keys())[:50_000]
                    for k in to_remove:
                        del self._processed_event_ids[k]
            state = self._get_or_create(session_id)
            self._update_state(state, enriched_event)
            return self._compute_verdict(state)

    async def close_session(self, session_id: str) -> dict | None:
        """Close a session and return a final summary.

        Removes the session from memory. Returns None if not found.
        """
        async with self._lock:
            state = self._sessions.pop(session_id, None)
            if state is None:
                return None

            self._closed_sessions.add(session_id)
            # Cap the closed set to prevent unbounded growth
            if len(self._closed_sessions) > 50_000:
                # Clear half — these are old enough
                to_remove = list(self._closed_sessions)[:25_000]
                for s in to_remove:
                    self._closed_sessions.discard(s)

            verdict = self._compute_verdict(state)
            classification = self._classify(state)
            duration = state.last_event_time - state.start_time

            return {
                "session_id": session_id,
                "duration_seconds": round(duration, 2),
                "event_count": state.event_count,
                "command_count": state.command_count,
                "phases_seen": sorted(state.phases_seen),
                "phase_count": len(state.phases_seen),
                "techniques_observed": state.techniques_seen,
                "tool_signatures": state.tool_signatures,
                "max_severity": state.max_severity,
                "classification": classification,
                "kill_chain": verdict.get("kill_chain_detected", False),
                "behavioral_score": verdict.get("behavioral_score", 0.0),
                "alerts_generated": len(state.previous_alerts),
            }

    async def sweep_idle(self) -> list[dict]:
        """Evict idle sessions. Returns summaries for evicted sessions.

        Performs eviction entirely under the lock to prevent TOCTOU races
        where a session could be modified between identification and removal.
        """
        summaries = []
        async with self._lock:
            now = time.time()
            to_evict = [
                sid for sid, state in self._sessions.items()
                if (now - state.last_event_time) > self._idle_timeout
            ]
            for sid in to_evict:
                state = self._sessions.pop(sid, None)
                if state is None:
                    continue
                verdict = self._compute_verdict(state)
                classification = self._classify(state)
                duration = state.last_event_time - state.start_time
                summaries.append({
                    "session_id": sid,
                    "duration_seconds": round(duration, 2),
                    "event_count": state.event_count,
                    "command_count": state.command_count,
                    "phases_seen": sorted(state.phases_seen),
                    "phase_count": len(state.phases_seen),
                    "techniques_observed": state.techniques_seen,
                    "tool_signatures": state.tool_signatures,
                    "max_severity": state.max_severity,
                    "classification": classification,
                    "kill_chain": verdict.get("kill_chain_detected", False),
                    "behavioral_score": verdict.get("behavioral_score", 0.0),
                    "alerts_generated": len(state.previous_alerts),
                })
        return summaries

    # ── Internal: state management ────────────────────

    def _get_or_create(self, session_id: str) -> SessionState:
        if session_id not in self._sessions:
            if len(self._sessions) >= self._max_sessions:
                evicted = self._evict_lru()
                if evicted:
                    if len(self._evicted_summaries) >= self._evicted_summaries.maxlen:
                        logger.warning(
                            "Evicted summaries deque full (%d) — oldest summary will be lost. "
                            "Persistence may be falling behind.",
                            len(self._evicted_summaries),
                        )
                    self._evicted_summaries.append(evicted)
            self._sessions[session_id] = SessionState(session_id=session_id)
        return self._sessions[session_id]

    def _evict_lru(self) -> dict | None:
        """Evict the least-recently-used session. Returns summary for persistence.

        Called while self._lock is already held, so we pop directly
        instead of calling close_session (which would deadlock).
        """
        if not self._sessions:
            return None
        oldest_sid = min(
            self._sessions,
            key=lambda s: self._sessions[s].last_event_time,
        )
        state = self._sessions.pop(oldest_sid)
        verdict = self._compute_verdict(state)
        classification = self._classify(state)
        duration = state.last_event_time - state.start_time
        return {
            "session_id": oldest_sid,
            "duration_seconds": round(duration, 2),
            "event_count": state.event_count,
            "command_count": state.command_count,
            "phases_seen": sorted(state.phases_seen),
            "phase_count": len(state.phases_seen),
            "techniques_observed": state.techniques_seen,
            "tool_signatures": state.tool_signatures,
            "max_severity": state.max_severity,
            "classification": classification,
            "kill_chain": verdict.get("kill_chain_detected", False),
            "behavioral_score": verdict.get("behavioral_score", 0.0),
            "alerts_generated": len(state.previous_alerts),
        }

    async def drain_evicted(self) -> list[dict]:
        """Return and clear any summaries from LRU eviction."""
        async with self._lock:
            evicted = list(self._evicted_summaries)
            self._evicted_summaries.clear()
            return evicted

    def _update_state(self, state: SessionState, event: dict) -> None:
        now = time.time()
        state.last_event_time = now
        state.event_count += 1

        event_type = event.get("event_type", "")
        if "command" in event_type:
            state.command_count += 1
            state.command_timestamps.append(now)

        # Accumulate techniques
        for tech in event.get("mitre_techniques", []):
            tid = tech.get("technique_id", "")
            tactic = tech.get("tactic", "")
            if tid and tid not in state.technique_ids_seen:
                state.techniques_seen.append(tech)
                state.technique_ids_seen.add(tid)
            if tactic:
                if tactic not in state.phases_seen:
                    state.phase_transitions.append((now, tactic))
                state.phases_seen.add(tactic)
                if tactic in _EVASION_TACTICS:
                    state.has_evasion = True

        # Accumulate tool signatures (flat strings)
        for tool_name in event.get("tool_signatures", []):
            if tool_name and tool_name not in state.tool_names_seen:
                state.tool_signatures.append(tool_name)
                state.tool_names_seen.add(tool_name)

        # Track severity
        event_sev = event.get("severity") or "info"
        if SEVERITY_RANK.get(event_sev, 0) > SEVERITY_RANK.get(state.max_severity, 0):
            state.max_severity = event_sev

        # Check for sensitive target access
        data = event.get("data") or event.get("raw_data") or {}
        if isinstance(data, dict):
            command = data.get("command", "") or data.get("input", "") or ""
            if command and any(target in command for target in _SENSITIVE_TARGETS):
                state.has_sensitive_target = True

    # ── Internal: verdict computation ─────────────────

    def _compute_verdict(self, state: SessionState) -> dict:
        detected, phases = detect_kill_chain(state.techniques_seen)
        score = self._behavioral_score(state)
        classification = self._classify(state)
        alerts = self._check_alerts(state, detected, set(phases), score)

        return {
            "kill_chain_detected": detected,
            "kill_chain_phases": len(state.phases_seen),
            "phase_progression": [t for _, t in state.phase_transitions],
            "session_severity": state.max_severity,
            "behavioral_score": round(score, 3),
            "session_classification": classification,
            "alert_triggers": alerts,
        }

    def _behavioral_score(self, state: SessionState) -> float:
        """Behavioral suspicion score (0.0 – 1.0).

        Factors (weights sum to 1.0):
          Phase diversity:        0.25
          Tool detection:         0.20
          Command tempo:          0.15
          Severity accumulation:  0.20
          Target sensitivity:     0.10
          Evasion indicators:     0.10
        """
        score = 0.0

        # Phase diversity (0.25)
        phase_count = len(state.phases_seen)
        score += min(phase_count / 5.0, 1.0) * 0.25

        # Tool detection (0.20)
        if state.tool_signatures:
            has_c2 = any(
                TOOL_CATEGORIES.get(t) == "c2" for t in state.tool_signatures
            )
            score += 0.20 if has_c2 else 0.15

        # Command tempo (0.15)
        if len(state.command_timestamps) >= 2:
            intervals = [
                state.command_timestamps[i] - state.command_timestamps[i - 1]
                for i in range(1, len(state.command_timestamps))
            ]
            avg = sum(intervals) / len(intervals) if intervals else 0
            if 0 < avg < 1.0:
                score += 0.10   # automated
            elif 1.0 <= avg <= 30.0:
                score += 0.15   # manual operator — more deliberate
            elif 30.0 < avg <= 60.0:
                score += 0.05

        # Severity accumulation (0.20)
        sev_val = SEVERITY_RANK.get(state.max_severity, 0)
        score += (sev_val / 4.0) * 0.20

        # Target sensitivity (0.10)
        if state.has_sensitive_target:
            score += 0.10

        # Evasion indicators (0.10)
        if state.has_evasion:
            score += 0.10

        return min(score, 1.0)

    def _classify(self, state: SessionState) -> str:
        """Classify into: scanner, basic_operator, manual_operator, advanced_threat."""
        duration = state.last_event_time - state.start_time
        phase_count = len(state.phases_seen)
        has_enum_tools = any(
            TOOL_CATEGORIES.get(t) in ("enumeration", "reconnaissance")
            for t in state.tool_signatures
        )
        has_c2 = any(
            TOOL_CATEGORIES.get(t) == "c2" for t in state.tool_signatures
        )

        if (state.has_evasion and phase_count >= 3) or has_c2:
            return "advanced_threat"

        if state.command_count <= 5 and duration < 30 and phase_count <= 1:
            return "scanner"

        if has_enum_tools and not state.has_evasion:
            return "basic_operator"

        if state.command_count >= 3 and phase_count >= 2:
            return "manual_operator"

        if state.command_count <= 3:
            return "scanner"

        return "manual_operator"

    def _check_alerts(self, state: SessionState, kc_detected: bool,
                      phases: set, score: float) -> list:
        """Check alert thresholds. Only returns NEW alerts."""
        alerts = []

        if kc_detected and "kill_chain_basic" not in state.previous_alerts:
            alerts.append({
                "alert_type": "kill_chain",
                "severity": "high",
                "session_id": state.session_id,
                "message": f"Kill chain detected: {len(phases)} phases observed",
                "phases": sorted(phases),
            })
            state.previous_alerts.append("kill_chain_basic")

        # Dangerous progression alerts
        for required_phases, sev, description in DANGEROUS_PROGRESSIONS:
            if required_phases.issubset(state.phases_seen):
                alert_key = f"progression:{description}"
                if alert_key not in state.previous_alerts:
                    alerts.append({
                        "alert_type": "dangerous_progression",
                        "severity": sev,
                        "session_id": state.session_id,
                        "message": description,
                    })
                    state.previous_alerts.append(alert_key)

        # High behavioral score
        if score >= 0.7 and "high_score" not in state.previous_alerts:
            alerts.append({
                "alert_type": "high_behavioral_score",
                "severity": "high",
                "session_id": state.session_id,
                "message": f"Session behavioral score: {score:.2f}",
                "classification": self._classify(state),
            })
            state.previous_alerts.append("high_score")

        # C2 tool detection
        has_c2 = any(
            TOOL_CATEGORIES.get(t) == "c2" for t in state.tool_signatures
        )
        if has_c2 and "c2_detected" not in state.previous_alerts:
            c2_tools = [
                t for t in state.tool_signatures
                if TOOL_CATEGORIES.get(t) == "c2"
            ]
            alerts.append({
                "alert_type": "c2_framework_detected",
                "severity": "critical",
                "session_id": state.session_id,
                "message": f"C2 framework detected: {', '.join(c2_tools)}",
            })
            state.previous_alerts.append("c2_detected")

        return alerts

    def _empty_verdict(self) -> dict:
        return {
            "kill_chain_detected": False,
            "kill_chain_phases": 0,
            "phase_progression": [],
            "session_severity": "info",
            "behavioral_score": 0.0,
            "session_classification": "unknown",
            "alert_triggers": [],
        }
