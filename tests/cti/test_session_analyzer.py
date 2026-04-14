"""
CI/CDecoy — Session Analyzer Tests

Tests for session-level behavioral analysis, kill chain tracking,
classification, and alerting. Imports from cti/session_analyzer.py.
"""

import pytest
import time

from session_analyzer import SessionAnalyzer
from enrichment import TOOL_CATEGORIES


def make_event(event_type="command.exec", command="",
               mitre=None, tools=None, severity="info"):
    """Build a minimal enriched event payload matching pipeline output."""
    return {
        "event_type": event_type,
        "mitre_techniques": mitre or [],
        "tool_signatures": tools or [],    # flat strings
        "severity": severity,
        "tags": [],
        "data": {"command": command},
    }


def tech(tid, name, tactic):
    return {"technique_id": tid, "technique_name": name, "tactic": tactic}


# ══════════════════════════════════════════════════════
#  Basic Ingest
# ══════════════════════════════════════════════════════

class TestBasicIngest:

    def test_empty_session_id(self):
        sa = SessionAnalyzer()
        v = sa.ingest("", make_event())
        assert v["kill_chain_detected"] is False
        assert v["session_classification"] == "unknown"

    def test_single_event(self):
        sa = SessionAnalyzer()
        v = sa.ingest("s1", make_event(
            mitre=[tech("T1033", "x", "discovery")], severity="low"))
        assert v["kill_chain_detected"] is False
        assert v["session_severity"] == "low"

    def test_phase_accumulation(self):
        sa = SessionAnalyzer()
        sa.ingest("s1", make_event(
            mitre=[tech("T1033", "x", "discovery")], severity="low"))
        v = sa.ingest("s1", make_event(
            mitre=[tech("T1003", "x", "credential-access")], severity="high"))
        assert v["kill_chain_phases"] == 2
        assert v["session_severity"] == "high"

    def test_technique_deduplication(self):
        sa = SessionAnalyzer()
        sa.ingest("s1", make_event(
            mitre=[tech("T1033", "x", "discovery")]))
        sa.ingest("s1", make_event(
            mitre=[tech("T1033", "x", "discovery")]))
        assert len(sa._sessions["s1"].techniques_seen) == 1


# ══════════════════════════════════════════════════════
#  Kill Chain Detection
# ══════════════════════════════════════════════════════

class TestSessionKillChain:

    def test_three_phases_triggers(self):
        sa = SessionAnalyzer()
        sa.ingest("s1", make_event(mitre=[tech("T1033", "x", "discovery")]))
        sa.ingest("s1", make_event(mitre=[tech("T1003", "x", "credential-access")]))
        v = sa.ingest("s1", make_event(mitre=[tech("T1021.004", "x", "lateral-movement")]))
        assert v["kill_chain_detected"] is True

    def test_dangerous_progression_alert(self):
        sa = SessionAnalyzer()
        sa.ingest("s1", make_event(mitre=[tech("T1033", "x", "discovery")]))
        sa.ingest("s1", make_event(mitre=[tech("T1003", "x", "credential-access")]))
        v = sa.ingest("s1", make_event(mitre=[tech("T1021.004", "x", "lateral-movement")]))
        assert any(a["alert_type"] == "dangerous_progression" for a in v["alert_triggers"])

    def test_alert_fires_once(self):
        sa = SessionAnalyzer()
        sa.ingest("s1", make_event(mitre=[tech("T1033", "x", "discovery")]))
        sa.ingest("s1", make_event(mitre=[tech("T1003", "x", "credential-access")]))
        v1 = sa.ingest("s1", make_event(mitre=[tech("T1021.004", "x", "lateral-movement")]))
        v2 = sa.ingest("s1", make_event(mitre=[tech("T1059.004", "x", "execution")]))
        kc1 = [a for a in v1["alert_triggers"] if a["alert_type"] == "kill_chain"]
        kc2 = [a for a in v2["alert_triggers"] if a["alert_type"] == "kill_chain"]
        assert len(kc1) == 1
        assert len(kc2) == 0

    def test_privesc_kill_chain(self):
        sa = SessionAnalyzer()
        sa.ingest("s1", make_event(mitre=[tech("T1033", "x", "discovery")]))
        sa.ingest("s1", make_event(mitre=[tech("T1548.003", "Sudo", "privilege-escalation")]))
        v = sa.ingest("s1", make_event(mitre=[tech("T1053.003", "Cron", "persistence")]))
        assert v["kill_chain_detected"] is True
        assert "privilege-escalation" in v["phase_progression"]


# ══════════════════════════════════════════════════════
#  Behavioral Scoring
# ══════════════════════════════════════════════════════

class TestBehavioralScoring:

    def test_benign_low_score(self):
        sa = SessionAnalyzer()
        v = sa.ingest("s1", make_event(command="ls"))
        assert v["behavioral_score"] < 0.2

    def test_tool_increases_score(self):
        sa1 = SessionAnalyzer()
        v1 = sa1.ingest("s-no", make_event(severity="low"))
        sa2 = SessionAnalyzer()
        v2 = sa2.ingest("s-tool", make_event(
            tools=["nmap"], severity="low"))
        assert v2["behavioral_score"] > v1["behavioral_score"]

    def test_c2_boosts_more(self):
        sa = SessionAnalyzer()
        v = sa.ingest("s1", make_event(
            tools=["metasploit"], severity="critical"))
        assert v["behavioral_score"] >= 0.3

    def test_score_capped(self):
        sa = SessionAnalyzer()
        for i, (tac, sev) in enumerate([
            ("discovery", "low"), ("credential-access", "high"),
            ("lateral-movement", "high"), ("execution", "high"),
            ("persistence", "medium"), ("defense-evasion", "medium"),
            ("exfiltration", "critical"), ("impact", "critical"),
        ]):
            sa.ingest("s1", make_event(
                mitre=[tech(f"T{i}", "x", tac)],
                tools=["metasploit"], severity=sev))
        v = sa.ingest("s1", make_event())
        assert v["behavioral_score"] <= 1.0


# ══════════════════════════════════════════════════════
#  Session Classification
# ══════════════════════════════════════════════════════

class TestClassification:

    def test_scanner(self):
        sa = SessionAnalyzer()
        sa.ingest("s1", make_event(command="whoami",
            mitre=[tech("T1033", "x", "discovery")], severity="low"))
        v = sa.ingest("s1", make_event(command="id",
            mitre=[tech("T1033", "x", "discovery")], severity="low"))
        assert v["session_classification"] == "scanner"

    def test_basic_operator(self):
        sa = SessionAnalyzer()
        sa.ingest("s1", make_event(command="whoami",
            mitre=[tech("T1033", "x", "discovery")]))
        sa.ingest("s1", make_event(command="wget linpeas",
            mitre=[tech("T1105", "x", "command-and-control")],
            tools=["linpeas"], severity="high"))
        v = sa.ingest("s1", make_event(command="bash linpeas",
            mitre=[tech("T1059.004", "x", "execution")]))
        assert v["session_classification"] == "basic_operator"

    def test_advanced_threat_c2(self):
        sa = SessionAnalyzer()
        v = sa.ingest("s1", make_event(
            tools=["cobalt-strike"], severity="critical"))
        assert v["session_classification"] == "advanced_threat"

    def test_advanced_threat_evasion(self):
        sa = SessionAnalyzer()
        sa.ingest("s1", make_event(mitre=[tech("T1033", "x", "discovery")]))
        sa.ingest("s1", make_event(mitre=[tech("T1003", "x", "credential-access")]))
        sa.ingest("s1", make_event(mitre=[tech("T1070.003", "x", "defense-evasion")]))
        v = sa.ingest("s1", make_event(mitre=[tech("T1021.004", "x", "lateral-movement")]))
        assert v["session_classification"] == "advanced_threat"

    def test_manual_operator(self):
        sa = SessionAnalyzer()
        sa.ingest("s1", make_event(command="whoami",
            mitre=[tech("T1033", "x", "discovery")]))
        sa.ingest("s1", make_event(command="cat /etc/passwd",
            mitre=[tech("T1003.008", "x", "credential-access")]))
        v = sa.ingest("s1", make_event(command="ps aux",
            mitre=[tech("T1057", "x", "discovery")]))
        assert v["session_classification"] == "manual_operator"


# ══════════════════════════════════════════════════════
#  Session Close / Summary
# ══════════════════════════════════════════════════════

class TestSessionClose:

    def test_close_returns_summary(self):
        sa = SessionAnalyzer()
        sa.ingest("s1", make_event(command="whoami",
            mitre=[tech("T1033", "x", "discovery")]))
        summary = sa.close_session("s1")
        assert summary is not None
        assert summary["session_id"] == "s1"
        assert summary["event_count"] == 1
        assert summary["command_count"] == 1

    def test_close_removes_from_memory(self):
        sa = SessionAnalyzer()
        sa.ingest("s1", make_event())
        sa.close_session("s1")
        assert "s1" not in sa._sessions

    def test_close_nonexistent(self):
        sa = SessionAnalyzer()
        assert sa.close_session("nope") is None

    def test_active_count(self):
        sa = SessionAnalyzer()
        sa.ingest("s1", make_event())
        sa.ingest("s2", make_event())
        assert sa.active_session_count == 2
        sa.close_session("s1")
        assert sa.active_session_count == 1


# ══════════════════════════════════════════════════════
#  LRU Eviction / Idle Sweep
# ══════════════════════════════════════════════════════

class TestEviction:

    def test_lru(self):
        sa = SessionAnalyzer(max_sessions=2)
        sa.ingest("s1", make_event())
        sa.ingest("s2", make_event())
        sa.ingest("s3", make_event())
        assert "s1" not in sa._sessions
        assert "s3" in sa._sessions

    def test_idle_sweep(self):
        sa = SessionAnalyzer(idle_timeout=0)
        sa.ingest("s1", make_event())
        time.sleep(0.01)
        summaries = sa.sweep_idle()
        assert len(summaries) == 1
        assert sa.active_session_count == 0


# ══════════════════════════════════════════════════════
#  C2 Alert
# ══════════════════════════════════════════════════════

class TestC2Alert:

    def test_c2_triggers_alert(self):
        sa = SessionAnalyzer()
        v = sa.ingest("s1", make_event(tools=["sliver"], severity="critical"))
        assert any(a["alert_type"] == "c2_framework_detected" for a in v["alert_triggers"])

    def test_c2_fires_once(self):
        sa = SessionAnalyzer()
        v1 = sa.ingest("s1", make_event(tools=["sliver"]))
        v2 = sa.ingest("s1", make_event(tools=["sliver"]))
        c2_1 = [a for a in v1["alert_triggers"] if a["alert_type"] == "c2_framework_detected"]
        c2_2 = [a for a in v2["alert_triggers"] if a["alert_type"] == "c2_framework_detected"]
        assert len(c2_1) == 1
        assert len(c2_2) == 0


# ══════════════════════════════════════════════════════
#  Phase Progression
# ══════════════════════════════════════════════════════

class TestPhaseProgression:

    def test_ordered(self):
        sa = SessionAnalyzer()
        sa.ingest("s1", make_event(mitre=[tech("T1033", "x", "discovery")]))
        sa.ingest("s1", make_event(mitre=[tech("T1003", "x", "credential-access")]))
        v = sa.ingest("s1", make_event(mitre=[tech("T1021.004", "x", "lateral-movement")]))
        assert v["phase_progression"] == ["discovery", "credential-access", "lateral-movement"]

    def test_no_dup_phases(self):
        sa = SessionAnalyzer()
        sa.ingest("s1", make_event(mitre=[tech("T1033", "x", "discovery")]))
        sa.ingest("s1", make_event(mitre=[tech("T1082", "y", "discovery")]))
        v = sa.ingest("s1", make_event(mitre=[tech("T1003", "x", "credential-access")]))
        assert v["phase_progression"] == ["discovery", "credential-access"]