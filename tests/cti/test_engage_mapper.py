"""
CI/CDecoy — Engage Mapper Tests

Tests for MITRE Engage mapping, effectiveness scoring, session-to-engagement
correlation, and campaign-level analysis. Imports from cti/engage_mapper.py.
"""

import pytest

from engage_mapper import (
    EngageEntry,
    EngageEnricher,
    EngageOutcome,
    EngageCampaignAnalyzer,
    map_decoy_to_engage,
    GOALS,
    APPROACHES,
    ACTIVITIES,
    DECOY_TYPE_MAPPING,
    HONEYTOKEN_MAPPING,
    FLEET_MAPPING,
)


# ══════════════════════════════════════════════════════
#  Engage Taxonomy Sanity Checks
# ══════════════════════════════════════════════════════


class TestEngageTaxonomy:

    def test_goals_have_correct_category(self):
        for entry in GOALS.values():
            assert entry.category == "goal"

    def test_approaches_have_correct_category(self):
        for entry in APPROACHES.values():
            assert entry.category == "approach"

    def test_activities_have_correct_category(self):
        for entry in ACTIVITIES.values():
            assert entry.category == "activity"

    def test_goal_ids_start_with_ega(self):
        for gid in GOALS:
            assert gid.startswith("EGA")

    def test_approach_ids_start_with_eap(self):
        for aid in APPROACHES:
            assert aid.startswith("EAP")

    def test_activity_ids_start_with_eac(self):
        for aid in ACTIVITIES:
            assert aid.startswith("EAC")

    def test_engage_entry_fields(self):
        entry = EngageEntry("EGA0001", "Prepare", "description", "goal")
        assert entry.id == "EGA0001"
        assert entry.name == "Prepare"
        assert entry.description == "description"
        assert entry.category == "goal"


# ══════════════════════════════════════════════════════
#  Decoy-Level Engage Mapping (map_decoy_to_engage)
# ══════════════════════════════════════════════════════


class TestMapDecoyToEngage:

    def test_tier1_basic_mapping(self):
        spec = {"fidelity": {"tier": 1}}
        result = map_decoy_to_engage(spec)
        assert "EAC0005" in result["activities"]   # Lure
        assert "EAC0007" in result["activities"]   # Network Monitoring
        assert "EGA0005" in result["goals"]         # Detect

    def test_tier2_includes_persona(self):
        spec = {"fidelity": {"tier": 2}}
        result = map_decoy_to_engage(spec)
        assert "EAC0001" in result["activities"]   # Persona Creation
        assert "EGA0002" in result["goals"]         # Expose

    def test_tier3_pocket_lure(self):
        spec = {"fidelity": {"tier": 3}}
        result = map_decoy_to_engage(spec)
        assert "EAC0006" in result["activities"]   # Pocket Lure
        assert "EAP0002" in result["approaches"]   # Motivation
        assert "EGA0004" in result["goals"]         # Elicit

    def test_unknown_tier_defaults_to_empty(self):
        """An unrecognized tier produces no tier-based mappings."""
        spec = {"fidelity": {"tier": 99}}
        result = map_decoy_to_engage(spec)
        assert result["activities"] == []
        assert result["approaches"] == []
        assert result["goals"] == []

    def test_missing_fidelity_defaults_to_tier1(self):
        spec = {}
        result = map_decoy_to_engage(spec)
        # Default tier is 1
        assert "EAC0005" in result["activities"]

    def test_honeytoken_overlay_adds_credential_activities(self):
        spec = {
            "fidelity": {"tier": 1},
            "filesystem": {
                "overlays": [
                    {"type": "honeytoken", "tokenRefs": ["aws-prod-admin"]},
                ]
            },
        }
        result = map_decoy_to_engage(spec)
        assert "EAC0003" in result["activities"]   # Decoy Credentials
        assert "EAC0008" in result["activities"]   # Credential Monitoring

    def test_multiple_honeytoken_refs(self):
        spec = {
            "fidelity": {"tier": 1},
            "filesystem": {
                "overlays": [
                    {"type": "honeytoken", "tokenRefs": ["cred-a", "cred-b"]},
                ]
            },
        }
        result = map_decoy_to_engage(spec)
        # Activities are deduplicated
        assert result["activities"].count("EAC0003") == 1

    def test_non_honeytoken_overlay_ignored(self):
        spec = {
            "fidelity": {"tier": 1},
            "filesystem": {
                "overlays": [{"type": "static", "path": "/etc/motd"}]
            },
        }
        result = map_decoy_to_engage(spec)
        # Should just have tier 1 activities
        assert "EAC0003" not in result["activities"]

    def test_open_auth_adds_introduced_vulnerabilities(self):
        spec = {
            "fidelity": {"tier": 1},
            "authentication": {"mode": "open"},
        }
        result = map_decoy_to_engage(spec)
        assert "EAC0010" in result["activities"]   # Introduced Vulnerabilities

    def test_selective_auth_adds_introduced_vulnerabilities(self):
        spec = {
            "fidelity": {"tier": 2},
            "authentication": {"mode": "selective"},
        }
        result = map_decoy_to_engage(spec)
        assert "EAC0010" in result["activities"]

    def test_closed_auth_no_introduced_vulnerabilities(self):
        spec = {
            "fidelity": {"tier": 1},
            "authentication": {"mode": "closed"},
        }
        result = map_decoy_to_engage(spec)
        assert "EAC0010" not in result["activities"]

    def test_beacon_traffic_adds_burn_in(self):
        spec = {
            "fidelity": {"tier": 1},
            "networkBehavior": {"beaconTraffic": {"enabled": True}},
        }
        result = map_decoy_to_engage(spec)
        assert "EAC0011" in result["activities"]   # Burn-In

    def test_no_beacon_no_burn_in(self):
        spec = {
            "fidelity": {"tier": 1},
            "networkBehavior": {"beaconTraffic": {"enabled": False}},
        }
        result = map_decoy_to_engage(spec)
        assert "EAC0011" not in result["activities"]

    def test_results_are_sorted_and_deduplicated(self):
        spec = {
            "fidelity": {"tier": 3},
            "filesystem": {
                "overlays": [
                    {"type": "honeytoken", "tokenRefs": ["a", "b", "c"]},
                ]
            },
            "authentication": {"mode": "open"},
            "networkBehavior": {"beaconTraffic": {"enabled": True}},
        }
        result = map_decoy_to_engage(spec)
        # Verify sorted
        assert result["activities"] == sorted(result["activities"])
        assert result["approaches"] == sorted(result["approaches"])
        assert result["goals"] == sorted(result["goals"])
        # Verify no duplicates
        assert len(result["activities"]) == len(set(result["activities"]))


# ══════════════════════════════════════════════════════
#  Engage Enricher — Session-Level Enrichment
# ══════════════════════════════════════════════════════


class TestEngageEnricher:

    def setup_method(self):
        self.enricher = EngageEnricher()

    def _make_session(self, **overrides):
        base = {
            "session_id": "sess-abc123",
            "decoy_name": "ssh-decoy-01",
            "decoy_tier": 2,
            "duration_seconds": 60,
            "command_count": 5,
            "mitre_techniques": [],
            "tools_detected": [],
            "honeytokens_accessed": [],
            "credentials_captured": [],
            "alerts": [],
        }
        base.update(overrides)
        return base

    # ── Activity Mapping ──

    def test_tier1_session_gets_lure_activity(self):
        outcome = self.enricher.enrich_session(self._make_session(decoy_tier=1))
        activity_ids = [a["id"] for a in outcome.activities_exercised]
        assert "EAC0005" in activity_ids   # Lure

    def test_tier2_session_gets_lure_activity(self):
        outcome = self.enricher.enrich_session(self._make_session(decoy_tier=2))
        activity_ids = [a["id"] for a in outcome.activities_exercised]
        assert "EAC0005" in activity_ids

    def test_tier3_session_gets_pocket_lure(self):
        outcome = self.enricher.enrich_session(self._make_session(decoy_tier=3))
        activity_ids = [a["id"] for a in outcome.activities_exercised]
        assert "EAC0006" in activity_ids   # Pocket Lure
        assert "EAC0005" not in activity_ids

    def test_commands_captured_adds_network_monitoring(self):
        outcome = self.enricher.enrich_session(
            self._make_session(command_count=3))
        activity_ids = [a["id"] for a in outcome.activities_exercised]
        assert "EAC0007" in activity_ids   # Network Monitoring

    def test_zero_commands_no_network_monitoring(self):
        outcome = self.enricher.enrich_session(
            self._make_session(command_count=0))
        activity_ids = [a["id"] for a in outcome.activities_exercised]
        assert "EAC0007" not in activity_ids

    def test_credentials_captured_adds_persona_creation(self):
        outcome = self.enricher.enrich_session(
            self._make_session(credentials_captured=["admin:password"]))
        activity_ids = [a["id"] for a in outcome.activities_exercised]
        assert "EAC0001" in activity_ids   # Persona Creation

    def test_honeytokens_adds_decoy_credentials_and_monitoring(self):
        outcome = self.enricher.enrich_session(
            self._make_session(honeytokens_accessed=["aws-canary-01"]))
        activity_ids = [a["id"] for a in outcome.activities_exercised]
        assert "EAC0003" in activity_ids   # Decoy Credentials
        assert "EAC0008" in activity_ids   # Credential Monitoring

    def test_file_reads_add_decoy_content(self):
        alerts = [
            {"event_type": "file.read", "path": "/etc/shadow"},
            {"event_type": "file.read", "path": "/home/admin/.ssh/id_rsa"},
        ]
        outcome = self.enricher.enrich_session(
            self._make_session(alerts=alerts))
        activity_ids = [a["id"] for a in outcome.activities_exercised]
        assert "EAC0004" in activity_ids   # Decoy Content

    def test_no_file_reads_no_decoy_content(self):
        alerts = [{"event_type": "command.exec", "command": "whoami"}]
        outcome = self.enricher.enrich_session(
            self._make_session(alerts=alerts))
        activity_ids = [a["id"] for a in outcome.activities_exercised]
        assert "EAC0004" not in activity_ids

    # ── Approach Mapping ──

    def test_reassurance_requires_3_commands_and_deception_maintained(self):
        outcome = self.enricher.enrich_session(
            self._make_session(command_count=3))
        approach_ids = [a["id"] for a in outcome.approaches_demonstrated]
        assert "EAP0001" in approach_ids   # Reassurance

    def test_reassurance_not_triggered_with_few_commands(self):
        outcome = self.enricher.enrich_session(
            self._make_session(command_count=2))
        approach_ids = [a["id"] for a in outcome.approaches_demonstrated]
        assert "EAP0001" not in approach_ids

    def test_motivation_from_honeytokens(self):
        outcome = self.enricher.enrich_session(
            self._make_session(honeytokens_accessed=["token-1"]))
        approach_ids = [a["id"] for a in outcome.approaches_demonstrated]
        assert "EAP0002" in approach_ids   # Motivation

    def test_motivation_from_lateral_movement(self):
        techniques = [
            {"technique_id": "T1021.004", "technique_name": "SSH", "tactic": "lateral-movement"}
        ]
        outcome = self.enricher.enrich_session(
            self._make_session(mitre_techniques=techniques))
        approach_ids = [a["id"] for a in outcome.approaches_demonstrated]
        assert "EAP0002" in approach_ids

    def test_direction_from_commands(self):
        outcome = self.enricher.enrich_session(
            self._make_session(command_count=1))
        approach_ids = [a["id"] for a in outcome.approaches_demonstrated]
        assert "EAP0004" in approach_ids   # Direction

    def test_collection_from_ttps(self):
        techniques = [
            {"technique_id": "T1082", "technique_name": "System Info", "tactic": "discovery"}
        ]
        outcome = self.enricher.enrich_session(
            self._make_session(mitre_techniques=techniques))
        approach_ids = [a["id"] for a in outcome.approaches_demonstrated]
        assert "EAP0005" in approach_ids   # Collection

    def test_collection_from_tools(self):
        outcome = self.enricher.enrich_session(
            self._make_session(tools_detected=["nmap"]))
        approach_ids = [a["id"] for a in outcome.approaches_demonstrated]
        assert "EAP0005" in approach_ids

    # ── Goal Mapping ──

    def test_detect_always_achieved(self):
        outcome = self.enricher.enrich_session(self._make_session())
        goal_ids = [g["id"] for g in outcome.goals_achieved]
        assert "EGA0005" in goal_ids   # Detect

    def test_expose_requires_3_ttps(self):
        techniques = [
            {"technique_id": "T1082", "technique_name": "x", "tactic": "discovery"},
            {"technique_id": "T1033", "technique_name": "x", "tactic": "discovery"},
            {"technique_id": "T1003", "technique_name": "x", "tactic": "credential-access"},
        ]
        outcome = self.enricher.enrich_session(
            self._make_session(mitre_techniques=techniques))
        goal_ids = [g["id"] for g in outcome.goals_achieved]
        assert "EGA0002" in goal_ids   # Expose

    def test_expose_not_with_few_ttps(self):
        techniques = [
            {"technique_id": "T1082", "technique_name": "x", "tactic": "discovery"},
            {"technique_id": "T1033", "technique_name": "x", "tactic": "discovery"},
        ]
        outcome = self.enricher.enrich_session(
            self._make_session(mitre_techniques=techniques))
        goal_ids = [g["id"] for g in outcome.goals_achieved]
        assert "EGA0002" not in goal_ids

    def test_elicit_requires_long_engagement_and_many_commands(self):
        outcome = self.enricher.enrich_session(
            self._make_session(duration_seconds=150, command_count=10))
        goal_ids = [g["id"] for g in outcome.goals_achieved]
        assert "EGA0004" in goal_ids   # Elicit

    def test_elicit_not_with_short_session(self):
        outcome = self.enricher.enrich_session(
            self._make_session(duration_seconds=60, command_count=10))
        goal_ids = [g["id"] for g in outcome.goals_achieved]
        assert "EGA0004" not in goal_ids

    def test_elicit_not_with_few_commands(self):
        outcome = self.enricher.enrich_session(
            self._make_session(duration_seconds=150, command_count=9))
        goal_ids = [g["id"] for g in outcome.goals_achieved]
        assert "EGA0004" not in goal_ids

    def test_affect_requires_long_duration(self):
        outcome = self.enricher.enrich_session(
            self._make_session(duration_seconds=301))
        goal_ids = [g["id"] for g in outcome.goals_achieved]
        assert "EGA0003" in goal_ids   # Affect

    def test_affect_not_with_short_duration(self):
        outcome = self.enricher.enrich_session(
            self._make_session(duration_seconds=300))
        goal_ids = [g["id"] for g in outcome.goals_achieved]
        assert "EGA0003" not in goal_ids

    # ── Lateral Movement Detection ──

    def test_lateral_movement_detected_t1021(self):
        techniques = [
            {"technique_id": "T1021", "technique_name": "Remote Services", "tactic": "lateral-movement"}
        ]
        outcome = self.enricher.enrich_session(
            self._make_session(mitre_techniques=techniques))
        assert outcome.lateral_movement_attempted is True

    def test_lateral_movement_detected_subtechnique(self):
        techniques = [
            {"technique_id": "T1021.004", "technique_name": "SSH", "tactic": "lateral-movement"}
        ]
        outcome = self.enricher.enrich_session(
            self._make_session(mitre_techniques=techniques))
        assert outcome.lateral_movement_attempted is True

    def test_no_lateral_movement(self):
        techniques = [
            {"technique_id": "T1082", "technique_name": "SysInfo", "tactic": "discovery"}
        ]
        outcome = self.enricher.enrich_session(
            self._make_session(mitre_techniques=techniques))
        assert outcome.lateral_movement_attempted is False

    # ── Operational Metrics ──

    def test_metrics_correctly_counted(self):
        session = self._make_session(
            mitre_techniques=[
                {"technique_id": "T1082", "technique_name": "x", "tactic": "discovery"},
            ],
            tools_detected=["nmap", "linpeas"],
            honeytokens_accessed=["aws-token"],
            credentials_captured=["admin:pass"],
            command_count=7,
            duration_seconds=120,
        )
        outcome = self.enricher.enrich_session(session)
        assert outcome.ttps_observed == 1
        assert outcome.tools_identified == 2
        assert outcome.honeytokens_triggered == 1
        assert outcome.credentials_harvested == 1
        assert outcome.commands_captured == 7
        assert outcome.engagement_duration_seconds == 120


# ══════════════════════════════════════════════════════
#  Intelligence Value Scoring
# ══════════════════════════════════════════════════════


class TestIntelligenceScoring:

    def setup_method(self):
        self.enricher = EngageEnricher()

    def _make_session(self, **overrides):
        base = {
            "session_id": "sess-score",
            "decoy_name": "ssh-decoy-01",
            "decoy_tier": 2,
            "duration_seconds": 30,
            "command_count": 2,
            "mitre_techniques": [],
            "tools_detected": [],
            "honeytokens_accessed": [],
            "credentials_captured": [],
            "alerts": [],
        }
        base.update(overrides)
        return base

    def test_low_value_minimal_session(self):
        outcome = self.enricher.enrich_session(self._make_session())
        assert outcome.intelligence_value == "low"

    def test_medium_value_some_ttps(self):
        techniques = [
            {"technique_id": f"T{i}", "technique_name": "x", "tactic": "discovery"}
            for i in range(3)
        ]
        outcome = self.enricher.enrich_session(
            self._make_session(mitre_techniques=techniques))
        assert outcome.intelligence_value == "medium"

    def test_high_value_ttps_and_tools(self):
        techniques = [
            {"technique_id": f"T{i}", "technique_name": "x", "tactic": "discovery"}
            for i in range(3)
        ]
        # Score: 3 TTPs × 2 = 6, 2 tools × 3 = 6, total = 12 >= 10 threshold
        outcome = self.enricher.enrich_session(
            self._make_session(mitre_techniques=techniques,
                               tools_detected=["nmap", "hydra"]))
        assert outcome.intelligence_value == "high"

    def test_critical_value_honeytokens_and_lateral(self):
        techniques = [
            {"technique_id": "T1021", "technique_name": "Remote", "tactic": "lateral-movement"},
            {"technique_id": "T1082", "technique_name": "x", "tactic": "discovery"},
            {"technique_id": "T1033", "technique_name": "x", "tactic": "discovery"},
        ]
        outcome = self.enricher.enrich_session(
            self._make_session(
                mitre_techniques=techniques,
                honeytokens_accessed=["token-a", "token-b"],
                tools_detected=["nmap"],
                duration_seconds=400,
                command_count=25,
            ))
        assert outcome.intelligence_value == "critical"

    def test_honeytoken_has_high_scoring_weight(self):
        """A single honeytoken trigger should provide significant scoring."""
        outcome = self.enricher.enrich_session(
            self._make_session(honeytokens_accessed=["canary-1"]))
        # 5 points from honeytoken alone => "medium"
        assert outcome.intelligence_value == "medium"

    def test_long_duration_adds_score(self):
        """Sessions over 300s get an extra scoring boost."""
        techniques = [
            {"technique_id": f"T{i}", "technique_name": "x", "tactic": "discovery"}
            for i in range(3)
        ]
        outcome = self.enricher.enrich_session(
            self._make_session(
                mitre_techniques=techniques,
                duration_seconds=400,
            ))
        # 6 from TTPs + 3 from duration = 9 => medium
        assert outcome.intelligence_value in ("medium", "high")


# ══════════════════════════════════════════════════════
#  Serialization (to_dict)
# ══════════════════════════════════════════════════════


class TestEngageSerialization:

    def test_to_dict_structure(self):
        enricher = EngageEnricher()
        outcome = enricher.enrich_session({
            "session_id": "sess-dict-test",
            "decoy_name": "test-decoy",
            "decoy_tier": 1,
            "duration_seconds": 10,
            "command_count": 1,
            "mitre_techniques": [],
            "tools_detected": [],
            "honeytokens_accessed": [],
            "credentials_captured": [],
            "alerts": [],
        })
        result = enricher.to_dict(outcome)

        assert result["session_id"] == "sess-dict-test"
        assert result["decoy_name"] == "test-decoy"
        assert "timestamp" in result
        assert "engage" in result
        assert "metrics" in result
        assert set(result["engage"].keys()) == {"activities", "approaches", "goals"}
        assert "intelligence_value" in result["metrics"]
        assert "deception_maintained" in result["metrics"]
        assert "lateral_movement_attempted" in result["metrics"]

    def test_to_dict_preserves_all_metrics(self):
        enricher = EngageEnricher()
        outcome = EngageOutcome(
            session_id="s1",
            decoy_name="d1",
            engagement_duration_seconds=999,
            commands_captured=42,
            credentials_harvested=3,
            honeytokens_triggered=2,
            ttps_observed=7,
            tools_identified=4,
            lateral_movement_attempted=True,
            deception_maintained=False,
            intelligence_value="critical",
        )
        result = enricher.to_dict(outcome)
        assert result["metrics"]["engagement_duration_seconds"] == 999
        assert result["metrics"]["commands_captured"] == 42
        assert result["metrics"]["credentials_harvested"] == 3
        assert result["metrics"]["honeytokens_triggered"] == 2
        assert result["metrics"]["ttps_observed"] == 7
        assert result["metrics"]["tools_identified"] == 4
        assert result["metrics"]["lateral_movement_attempted"] is True
        assert result["metrics"]["deception_maintained"] is False


# ══════════════════════════════════════════════════════
#  Edge Cases
# ══════════════════════════════════════════════════════


class TestEngageEdgeCases:

    def setup_method(self):
        self.enricher = EngageEnricher()

    def test_empty_session_data(self):
        outcome = self.enricher.enrich_session({})
        assert outcome.session_id == ""
        assert outcome.decoy_name == ""
        assert outcome.commands_captured == 0
        # Should still get Detect goal
        goal_ids = [g["id"] for g in outcome.goals_achieved]
        assert "EGA0005" in goal_ids

    def test_unknown_technique_ids(self):
        techniques = [
            {"technique_id": "T9999", "technique_name": "Unknown", "tactic": "unknown"}
        ]
        outcome = self.enricher.enrich_session({
            "session_id": "s1",
            "decoy_name": "d1",
            "decoy_tier": 1,
            "duration_seconds": 10,
            "command_count": 1,
            "mitre_techniques": techniques,
            "tools_detected": [],
            "honeytokens_accessed": [],
            "credentials_captured": [],
            "alerts": [],
        })
        # Should not crash; unknown techniques don't trigger lateral movement
        assert outcome.lateral_movement_attempted is False
        assert outcome.ttps_observed == 1

    def test_empty_technique_id(self):
        techniques = [{"technique_id": "", "technique_name": "", "tactic": ""}]
        outcome = self.enricher.enrich_session({
            "session_id": "s1",
            "decoy_name": "d1",
            "decoy_tier": 1,
            "duration_seconds": 0,
            "command_count": 0,
            "mitre_techniques": techniques,
            "tools_detected": [],
            "honeytokens_accessed": [],
            "credentials_captured": [],
            "alerts": [],
        })
        assert outcome.lateral_movement_attempted is False

    def test_zero_duration_session(self):
        outcome = self.enricher.enrich_session({
            "session_id": "s-zero",
            "decoy_name": "d1",
            "decoy_tier": 2,
            "duration_seconds": 0,
            "command_count": 0,
            "mitre_techniques": [],
            "tools_detected": [],
            "honeytokens_accessed": [],
            "credentials_captured": [],
            "alerts": [],
        })
        assert outcome.engagement_duration_seconds == 0
        assert outcome.intelligence_value == "low"

    def test_deception_maintained_default(self):
        outcome = self.enricher.enrich_session({
            "session_id": "s1",
            "decoy_name": "d1",
            "decoy_tier": 1,
            "duration_seconds": 10,
            "command_count": 1,
            "mitre_techniques": [],
            "tools_detected": [],
            "honeytokens_accessed": [],
            "credentials_captured": [],
            "alerts": [],
        })
        assert outcome.deception_maintained is True


# ══════════════════════════════════════════════════════
#  Campaign-Level Engage Analysis
# ══════════════════════════════════════════════════════


class TestEngageCampaignAnalyzer:

    def setup_method(self):
        self.analyzer = EngageCampaignAnalyzer()

    def _make_outcome(self, session_id="s1", decoy_name="d1",
                      timestamp="2026-01-15T12:00:00",
                      duration=60, commands=5, ttps=2,
                      tools=1, honeytokens=0, creds=0,
                      lateral=False, deception_held=True,
                      intel_value="medium", activities=None,
                      goals=None):
        o = EngageOutcome(
            session_id=session_id,
            decoy_name=decoy_name,
            timestamp=timestamp,
            engagement_duration_seconds=duration,
            commands_captured=commands,
            ttps_observed=ttps,
            tools_identified=tools,
            honeytokens_triggered=honeytokens,
            credentials_harvested=creds,
            lateral_movement_attempted=lateral,
            deception_maintained=deception_held,
            intelligence_value=intel_value,
        )
        o.activities_exercised = activities or [
            {"id": "EAC0005", "name": "Lure", "evidence": "test"},
        ]
        o.goals_achieved = goals or [
            {"id": "EGA0005", "name": "Detect", "evidence": "test"},
        ]
        return o

    def test_empty_outcomes_returns_minimal(self):
        result = self.analyzer.analyze_campaign([], "empty-campaign")
        assert result["campaign"] == "empty-campaign"
        assert result["sessions"] == 0
        assert "summary" not in result

    def test_single_session_campaign(self):
        outcomes = [self._make_outcome()]
        result = self.analyzer.analyze_campaign(outcomes, "test-campaign")
        assert result["campaign"] == "test-campaign"
        assert result["summary"]["total_sessions"] == 1
        assert result["summary"]["total_commands_captured"] == 5
        assert result["summary"]["total_ttps_observed"] == 2
        assert result["summary"]["deception_success_rate"] == 100.0

    def test_multiple_sessions_aggregation(self):
        outcomes = [
            self._make_outcome(session_id="s1", decoy_name="d1",
                               duration=100, commands=10, ttps=3,
                               timestamp="2026-01-15T10:00:00"),
            self._make_outcome(session_id="s2", decoy_name="d2",
                               duration=200, commands=20, ttps=5,
                               lateral=True,
                               timestamp="2026-01-15T14:00:00"),
        ]
        result = self.analyzer.analyze_campaign(outcomes, "multi")
        assert result["summary"]["total_sessions"] == 2
        assert result["summary"]["total_commands_captured"] == 30
        assert result["summary"]["total_ttps_observed"] == 8
        assert result["summary"]["lateral_movement_attempts"] == 1
        assert result["summary"]["active_decoys"] == 2

    def test_deception_success_rate(self):
        outcomes = [
            self._make_outcome(session_id="s1", deception_held=True),
            self._make_outcome(session_id="s2", deception_held=True),
            self._make_outcome(session_id="s3", deception_held=False),
        ]
        result = self.analyzer.analyze_campaign(outcomes)
        assert result["summary"]["deception_success_rate"] == pytest.approx(66.7, abs=0.1)

    def test_intelligence_value_distribution(self):
        outcomes = [
            self._make_outcome(session_id="s1", intel_value="low"),
            self._make_outcome(session_id="s2", intel_value="medium"),
            self._make_outcome(session_id="s3", intel_value="high"),
            self._make_outcome(session_id="s4", intel_value="critical"),
        ]
        result = self.analyzer.analyze_campaign(outcomes)
        dist = result["intelligence_value_distribution"]
        assert dist["low"] == 1
        assert dist["medium"] == 1
        assert dist["high"] == 1
        assert dist["critical"] == 1

    def test_activity_frequency(self):
        outcomes = [
            self._make_outcome(session_id="s1", activities=[
                {"id": "EAC0005", "name": "Lure", "evidence": "x"},
                {"id": "EAC0007", "name": "Network Monitoring", "evidence": "x"},
            ]),
            self._make_outcome(session_id="s2", activities=[
                {"id": "EAC0005", "name": "Lure", "evidence": "x"},
            ]),
        ]
        result = self.analyzer.analyze_campaign(outcomes)
        assert result["engage_activities"]["EAC0005"]["count"] == 2
        assert result["engage_activities"]["EAC0005"]["percentage"] == 100.0
        assert result["engage_activities"]["EAC0007"]["count"] == 1

    def test_period_timestamps(self):
        outcomes = [
            self._make_outcome(session_id="s1", timestamp="2026-01-10T08:00:00"),
            self._make_outcome(session_id="s2", timestamp="2026-01-15T16:00:00"),
        ]
        result = self.analyzer.analyze_campaign(outcomes)
        assert result["period"]["first_session"] == "2026-01-10T08:00:00"
        assert result["period"]["last_session"] == "2026-01-15T16:00:00"

    def test_engagement_hours_calculation(self):
        outcomes = [
            self._make_outcome(session_id="s1", duration=3600),   # 1 hour
            self._make_outcome(session_id="s2", duration=1800),   # 0.5 hours
        ]
        result = self.analyzer.analyze_campaign(outcomes)
        assert result["summary"]["total_engagement_hours"] == 1.5


# ══════════════════════════════════════════════════════
#  Mapping Configuration Completeness
# ══════════════════════════════════════════════════════


class TestMappingCompleteness:

    def test_decoy_type_mapping_references_valid_activities(self):
        for key, mapping in DECOY_TYPE_MAPPING.items():
            for aid in mapping["activities"]:
                assert aid in ACTIVITIES, f"Invalid activity {aid} in {key}"

    def test_decoy_type_mapping_references_valid_approaches(self):
        for key, mapping in DECOY_TYPE_MAPPING.items():
            for aid in mapping["approaches"]:
                assert aid in APPROACHES, f"Invalid approach {aid} in {key}"

    def test_decoy_type_mapping_references_valid_goals(self):
        for key, mapping in DECOY_TYPE_MAPPING.items():
            for gid in mapping["goals"]:
                assert gid in GOALS, f"Invalid goal {gid} in {key}"

    def test_honeytoken_mapping_references_valid_activities(self):
        for ht_type, mapping in HONEYTOKEN_MAPPING.items():
            for aid in mapping["activities"]:
                assert aid in ACTIVITIES, f"Invalid activity {aid} in {ht_type}"

    def test_fleet_mapping_references_valid_activities(self):
        for strategy, mapping in FLEET_MAPPING.items():
            for aid in mapping["activities"]:
                assert aid in ACTIVITIES, f"Invalid activity {aid} in {strategy}"
