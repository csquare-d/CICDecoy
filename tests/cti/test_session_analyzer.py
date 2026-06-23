"""
CI/CDecoy — Session Analyzer Tests

Tests for session-level behavioral analysis, kill chain tracking,
classification, and alerting. Imports from cti/session_analyzer.py.
"""

import time

import pytest
from session_analyzer import SessionAnalyzer


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

    @pytest.mark.asyncio
    async def test_empty_session_id(self):
        sa = SessionAnalyzer()
        v = await sa.ingest("", make_event())
        assert v["kill_chain_detected"] is False
        assert v["session_classification"] == "unknown"

    @pytest.mark.asyncio
    async def test_single_event(self):
        sa = SessionAnalyzer()
        v = await sa.ingest("s1", make_event(
            mitre=[tech("T1033", "x", "discovery")], severity="low"))
        assert v["kill_chain_detected"] is False
        assert v["session_severity"] == "low"

    @pytest.mark.asyncio
    async def test_phase_accumulation(self):
        sa = SessionAnalyzer()
        await sa.ingest("s1", make_event(
            mitre=[tech("T1033", "x", "discovery")], severity="low"))
        v = await sa.ingest("s1", make_event(
            mitre=[tech("T1003", "x", "credential-access")], severity="high"))
        assert v["kill_chain_phases"] == 2
        assert v["session_severity"] == "high"

    @pytest.mark.asyncio
    async def test_technique_deduplication(self):
        sa = SessionAnalyzer()
        await sa.ingest("s1", make_event(
            mitre=[tech("T1033", "x", "discovery")]))
        await sa.ingest("s1", make_event(
            mitre=[tech("T1033", "x", "discovery")]))
        assert len(sa._sessions["s1"].techniques_seen) == 1


# ══════════════════════════════════════════════════════
#  Kill Chain Detection
# ══════════════════════════════════════════════════════

class TestSessionKillChain:

    @pytest.mark.asyncio
    async def test_three_phases_triggers(self):
        sa = SessionAnalyzer()
        await sa.ingest("s1", make_event(mitre=[tech("T1033", "x", "discovery")]))
        await sa.ingest("s1", make_event(mitre=[tech("T1003", "x", "credential-access")]))
        v = await sa.ingest("s1", make_event(mitre=[tech("T1021.004", "x", "lateral-movement")]))
        assert v["kill_chain_detected"] is True

    @pytest.mark.asyncio
    async def test_dangerous_progression_alert(self):
        sa = SessionAnalyzer()
        await sa.ingest("s1", make_event(mitre=[tech("T1033", "x", "discovery")]))
        await sa.ingest("s1", make_event(mitre=[tech("T1003", "x", "credential-access")]))
        v = await sa.ingest("s1", make_event(mitre=[tech("T1021.004", "x", "lateral-movement")]))
        assert any(a["alert_type"] == "dangerous_progression" for a in v["alert_triggers"])

    @pytest.mark.asyncio
    async def test_alert_fires_once(self):
        sa = SessionAnalyzer()
        await sa.ingest("s1", make_event(mitre=[tech("T1033", "x", "discovery")]))
        await sa.ingest("s1", make_event(mitre=[tech("T1003", "x", "credential-access")]))
        v1 = await sa.ingest("s1", make_event(mitre=[tech("T1021.004", "x", "lateral-movement")]))
        v2 = await sa.ingest("s1", make_event(mitre=[tech("T1059.004", "x", "execution")]))
        kc1 = [a for a in v1["alert_triggers"] if a["alert_type"] == "kill_chain"]
        kc2 = [a for a in v2["alert_triggers"] if a["alert_type"] == "kill_chain"]
        assert len(kc1) == 1
        assert len(kc2) == 0

    @pytest.mark.asyncio
    async def test_privesc_kill_chain(self):
        sa = SessionAnalyzer()
        await sa.ingest("s1", make_event(mitre=[tech("T1033", "x", "discovery")]))
        await sa.ingest("s1", make_event(mitre=[tech("T1548.003", "Sudo", "privilege-escalation")]))
        v = await sa.ingest("s1", make_event(mitre=[tech("T1053.003", "Cron", "persistence")]))
        assert v["kill_chain_detected"] is True
        assert "privilege-escalation" in v["phase_progression"]


# ══════════════════════════════════════════════════════
#  Behavioral Scoring
# ══════════════════════════════════════════════════════

class TestBehavioralScoring:

    @pytest.mark.asyncio
    async def test_benign_low_score(self):
        sa = SessionAnalyzer()
        v = await sa.ingest("s1", make_event(command="ls"))
        assert v["behavioral_score"] < 0.2

    @pytest.mark.asyncio
    async def test_tool_increases_score(self):
        sa1 = SessionAnalyzer()
        v1 = await sa1.ingest("s-no", make_event(severity="low"))
        sa2 = SessionAnalyzer()
        v2 = await sa2.ingest("s-tool", make_event(
            tools=["nmap"], severity="low"))
        assert v2["behavioral_score"] > v1["behavioral_score"]

    @pytest.mark.asyncio
    async def test_c2_boosts_more(self):
        sa = SessionAnalyzer()
        v = await sa.ingest("s1", make_event(
            tools=["metasploit"], severity="critical"))
        assert v["behavioral_score"] >= 0.3

    @pytest.mark.asyncio
    async def test_score_capped(self):
        sa = SessionAnalyzer()
        for i, (tac, sev) in enumerate([
            ("discovery", "low"), ("credential-access", "high"),
            ("lateral-movement", "high"), ("execution", "high"),
            ("persistence", "medium"), ("defense-evasion", "medium"),
            ("exfiltration", "critical"), ("impact", "critical"),
        ]):
            await sa.ingest("s1", make_event(
                mitre=[tech(f"T{i}", "x", tac)],
                tools=["metasploit"], severity=sev))
        v = await sa.ingest("s1", make_event())
        assert v["behavioral_score"] <= 1.0


# ══════════════════════════════════════════════════════
#  Session Classification
# ══════════════════════════════════════════════════════

class TestClassification:

    @pytest.mark.asyncio
    async def test_scanner(self):
        sa = SessionAnalyzer()
        await sa.ingest("s1", make_event(command="whoami",
            mitre=[tech("T1033", "x", "discovery")], severity="low"))
        v = await sa.ingest("s1", make_event(command="id",
            mitre=[tech("T1033", "x", "discovery")], severity="low"))
        assert v["session_classification"] == "scanner"

    @pytest.mark.asyncio
    async def test_basic_operator(self):
        sa = SessionAnalyzer()
        await sa.ingest("s1", make_event(command="whoami",
            mitre=[tech("T1033", "x", "discovery")]))
        await sa.ingest("s1", make_event(command="wget linpeas",
            mitre=[tech("T1105", "x", "command-and-control")],
            tools=["linpeas"], severity="high"))
        v = await sa.ingest("s1", make_event(command="bash linpeas",
            mitre=[tech("T1059.004", "x", "execution")]))
        assert v["session_classification"] == "basic_operator"

    @pytest.mark.asyncio
    async def test_advanced_threat_c2(self):
        sa = SessionAnalyzer()
        v = await sa.ingest("s1", make_event(
            tools=["cobalt-strike"], severity="critical"))
        assert v["session_classification"] == "advanced_threat"

    @pytest.mark.asyncio
    async def test_advanced_threat_evasion(self):
        sa = SessionAnalyzer()
        await sa.ingest("s1", make_event(mitre=[tech("T1033", "x", "discovery")]))
        await sa.ingest("s1", make_event(mitre=[tech("T1003", "x", "credential-access")]))
        await sa.ingest("s1", make_event(mitre=[tech("T1070.003", "x", "defense-evasion")]))
        v = await sa.ingest("s1", make_event(mitre=[tech("T1021.004", "x", "lateral-movement")]))
        assert v["session_classification"] == "advanced_threat"

    @pytest.mark.asyncio
    async def test_manual_operator(self):
        sa = SessionAnalyzer()
        await sa.ingest("s1", make_event(command="whoami",
            mitre=[tech("T1033", "x", "discovery")]))
        await sa.ingest("s1", make_event(command="cat /etc/passwd",
            mitre=[tech("T1003.008", "x", "credential-access")]))
        v = await sa.ingest("s1", make_event(command="ps aux",
            mitre=[tech("T1057", "x", "discovery")]))
        assert v["session_classification"] == "manual_operator"


# ══════════════════════════════════════════════════════
#  Session Close / Summary
# ══════════════════════════════════════════════════════

class TestSessionClose:

    @pytest.mark.asyncio
    async def test_close_returns_summary(self):
        sa = SessionAnalyzer()
        await sa.ingest("s1", make_event(command="whoami",
            mitre=[tech("T1033", "x", "discovery")]))
        summary = await sa.close_session("s1")
        assert summary is not None
        assert summary["session_id"] == "s1"
        assert summary["event_count"] == 1
        assert summary["command_count"] == 1

    @pytest.mark.asyncio
    async def test_close_removes_from_memory(self):
        sa = SessionAnalyzer()
        await sa.ingest("s1", make_event())
        await sa.close_session("s1")
        assert "s1" not in sa._sessions

    @pytest.mark.asyncio
    async def test_close_nonexistent(self):
        sa = SessionAnalyzer()
        assert await sa.close_session("nope") is None

    @pytest.mark.asyncio
    async def test_active_count(self):
        sa = SessionAnalyzer()
        await sa.ingest("s1", make_event(command="cmd1"))
        await sa.ingest("s2", make_event(command="cmd2"))
        assert sa.active_session_count == 2
        await sa.close_session("s1")
        assert sa.active_session_count == 1


# ══════════════════════════════════════════════════════
#  LRU Eviction / Idle Sweep
# ══════════════════════════════════════════════════════

class TestEviction:

    @pytest.mark.asyncio
    async def test_lru(self):
        sa = SessionAnalyzer(max_sessions=2)
        await sa.ingest("s1", make_event(command="cmd1"))
        await sa.ingest("s2", make_event(command="cmd2"))
        await sa.ingest("s3", make_event(command="cmd3"))
        assert "s1" not in sa._sessions
        assert "s3" in sa._sessions

    @pytest.mark.asyncio
    async def test_lru_eviction_produces_summary(self):
        sa = SessionAnalyzer(max_sessions=2)
        await sa.ingest("s1", make_event(
            command="cmd1",
            mitre=[tech("T1033", "x", "discovery")], severity="low"))
        await sa.ingest("s2", make_event(command="cmd2"))
        # s3 triggers eviction of s1
        await sa.ingest("s3", make_event(command="cmd3"))
        evicted = await sa.drain_evicted()
        assert len(evicted) == 1
        assert evicted[0]["session_id"] == "s1"
        assert evicted[0]["event_count"] == 1
        assert "discovery" in evicted[0]["phases_seen"]
        # Drain again should be empty
        assert await sa.drain_evicted() == []

    @pytest.mark.asyncio
    async def test_idle_sweep(self):
        sa = SessionAnalyzer(idle_timeout=0)
        await sa.ingest("s1", make_event())
        time.sleep(0.01)
        summaries = await sa.sweep_idle()
        assert len(summaries) == 1
        assert sa.active_session_count == 0


# ══════════════════════════════════════════════════════
#  C2 Alert
# ══════════════════════════════════════════════════════

class TestC2Alert:

    @pytest.mark.asyncio
    async def test_c2_triggers_alert(self):
        sa = SessionAnalyzer()
        v = await sa.ingest("s1", make_event(tools=["sliver"], severity="critical"))
        assert any(a["alert_type"] == "c2_framework_detected" for a in v["alert_triggers"])

    @pytest.mark.asyncio
    async def test_c2_fires_once(self):
        sa = SessionAnalyzer()
        v1 = await sa.ingest("s1", make_event(tools=["sliver"]))
        v2 = await sa.ingest("s1", make_event(tools=["sliver"]))
        c2_1 = [a for a in v1["alert_triggers"] if a["alert_type"] == "c2_framework_detected"]
        c2_2 = [a for a in v2["alert_triggers"] if a["alert_type"] == "c2_framework_detected"]
        assert len(c2_1) == 1
        assert len(c2_2) == 0


# ══════════════════════════════════════════════════════
#  Phase Progression
# ══════════════════════════════════════════════════════

class TestPhaseProgression:

    @pytest.mark.asyncio
    async def test_ordered(self):
        sa = SessionAnalyzer()
        await sa.ingest("s1", make_event(mitre=[tech("T1033", "x", "discovery")]))
        await sa.ingest("s1", make_event(mitre=[tech("T1003", "x", "credential-access")]))
        v = await sa.ingest("s1", make_event(mitre=[tech("T1021.004", "x", "lateral-movement")]))
        assert v["phase_progression"] == ["discovery", "credential-access", "lateral-movement"]

    @pytest.mark.asyncio
    async def test_no_dup_phases(self):
        sa = SessionAnalyzer()
        await sa.ingest("s1", make_event(mitre=[tech("T1033", "x", "discovery")]))
        await sa.ingest("s1", make_event(mitre=[tech("T1082", "y", "discovery")]))
        v = await sa.ingest("s1", make_event(mitre=[tech("T1003", "x", "credential-access")]))
        assert v["phase_progression"] == ["discovery", "credential-access"]


# ══════════════════════════════════════════════════════
#  Deque Bounds
# ══════════════════════════════════════════════════════

class TestDequeBounds:

    @pytest.mark.asyncio
    async def test_techniques_bounded(self):
        """techniques_seen should not exceed maxlen of 500."""
        sa = SessionAnalyzer()
        for i in range(600):
            e = make_event(mitre=[tech(f"T{i:04d}", f"Tech {i}", "discovery")])
            e["event_id"] = f"evt-{i}"
            await sa.ingest("s1", e)
        assert len(sa._sessions["s1"].techniques_seen) <= 500

    @pytest.mark.asyncio
    async def test_tool_signatures_bounded(self):
        """tool_signatures should not exceed maxlen of 200."""
        sa = SessionAnalyzer()
        for i in range(300):
            e = make_event(tools=[f"tool_{i}"])
            e["event_id"] = f"tool-evt-{i}"
            await sa.ingest("s1", e)
        assert len(sa._sessions["s1"].tool_signatures) <= 200

    @pytest.mark.asyncio
    async def test_command_timestamps_bounded(self):
        """command_timestamps should not exceed maxlen of 1000."""
        sa = SessionAnalyzer()
        for i in range(1200):
            e = make_event(command=f"cmd_{i}")
            e["event_id"] = f"cmd-evt-{i}"
            await sa.ingest("s1", e)
        assert len(sa._sessions["s1"].command_timestamps) <= 1000
