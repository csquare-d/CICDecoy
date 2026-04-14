"""
CI/CDecoy — MITRE Engage Mapping

Maps deception operations to the MITRE Engage framework, answering
"what did our deception achieve?" alongside ATT&CK's "what did the
attacker do?"

Engage Framework Structure:
  Strategic Goals (EGA)  → Why are we doing deception?
  Approaches (EAP)       → How are we achieving those goals?
  Activities (EAC)       → What specific deception actions are we taking?

This module provides:
1. Decoy-level Engage annotation (what each asset is designed to achieve)
2. Interaction-level Engage enrichment (what each session accomplished)
3. Campaign-level Engage scoring (how effective is our deception posture)

Reference: https://engage.mitre.org/
"""

import logging
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime

logger = logging.getLogger("cicdecoy.engage")


# ─────────────────────────────────────────────────────────
#  Engage Taxonomy
# ─────────────────────────────────────────────────────────

@dataclass
class EngageEntry:
    id: str
    name: str
    description: str
    category: str      # "goal" | "approach" | "activity"


# Strategic Goals — the "why"
GOALS = {
    "EGA0001": EngageEntry("EGA0001", "Prepare",
        "Develop and maintain the deception environment", "goal"),
    "EGA0002": EngageEntry("EGA0002", "Expose",
        "Reveal adversary tactics, techniques, and procedures", "goal"),
    "EGA0003": EngageEntry("EGA0003", "Affect",
        "Negatively impact adversary operations", "goal"),
    "EGA0004": EngageEntry("EGA0004", "Elicit",
        "Observe and collect adversary TTPs in a controlled environment", "goal"),
    "EGA0005": EngageEntry("EGA0005", "Detect",
        "Establish or improve detection of adversary activity", "goal"),
}

# Approaches — the "how"
APPROACHES = {
    "EAP0001": EngageEntry("EAP0001", "Reassurance",
        "Add artifacts to the environment that increase adversary confidence "
        "in the legitimacy of the target", "approach"),
    "EAP0002": EngageEntry("EAP0002", "Motivation",
        "Encourage the adversary to take a specific action by making "
        "certain targets or data appear valuable", "approach"),
    "EAP0003": EngageEntry("EAP0003", "Disruption",
        "Impair adversary operations by degrading their tools or access", "approach"),
    "EAP0004": EngageEntry("EAP0004", "Direction",
        "Guide adversary movement toward or away from specific areas "
        "of the environment", "approach"),
    "EAP0005": EngageEntry("EAP0005", "Collection",
        "Gather adversary TTPs, tools, and infrastructure details", "approach"),
}

# Activities — the "what" (deception actions)
ACTIVITIES = {
    # ── Prepare activities ──
    "EAC0001": EngageEntry("EAC0001", "Persona Creation",
        "Create fictitious user accounts and personas", "activity"),
    "EAC0002": EngageEntry("EAC0002", "Network Diversity",
        "Deploy decoys across multiple network segments to create "
        "the appearance of a larger or more diverse environment", "activity"),
    "EAC0003": EngageEntry("EAC0003", "Decoy Credentials",
        "Seed fake credentials in locations adversaries are likely to search", "activity"),
    "EAC0004": EngageEntry("EAC0004", "Decoy Content",
        "Place decoy files, documents, or data to attract adversary interest", "activity"),
    "EAC0005": EngageEntry("EAC0005", "Lure",
        "Deploy a system or service to attract adversary interaction", "activity"),
    "EAC0006": EngageEntry("EAC0006", "Pocket Lure",
        "Deploy a high-interaction system designed for prolonged "
        "adversary engagement and TTP collection", "activity"),

    # ── Detect activities ──
    "EAC0007": EngageEntry("EAC0007", "Network Monitoring",
        "Monitor network traffic to and from deception assets", "activity"),
    "EAC0008": EngageEntry("EAC0008", "Credential Monitoring",
        "Monitor for the use of decoy credentials", "activity"),
    "EAC0009": EngageEntry("EAC0009", "Email Monitoring",
        "Monitor for access to decoy email accounts or content", "activity"),

    # ── Affect activities ──
    "EAC0010": EngageEntry("EAC0010", "Introduced Vulnerabilities",
        "Deliberately introduce vulnerabilities to attract adversary "
        "exploitation attempts", "activity"),
    "EAC0011": EngageEntry("EAC0011", "Burn-In",
        "Allow a decoy to exist in the environment for a period to "
        "establish normalcy before monitoring", "activity"),

    # ── Collect activities ──
    "EAC0012": EngageEntry("EAC0012", "Artifact Diversity",
        "Ensure decoy artifacts vary to prevent adversary pattern "
        "recognition of deception assets", "activity"),
    "EAC0013": EngageEntry("EAC0013", "Attack Vector Migration",
        "Adapt deception assets based on observed adversary behavior", "activity"),

    # ── Expose activities ──
    "EAC0014": EngageEntry("EAC0014", "Software Manipulation",
        "Use decoy software configurations to reveal adversary "
        "exploitation techniques", "activity"),
    "EAC0015": EngageEntry("EAC0015", "Security Controls",
        "Vary security posture across decoys to observe adversary "
        "adaptation to different defensive levels", "activity"),
}


# ─────────────────────────────────────────────────────────
#  Decoy-Level Engage Mapping
#  (What strategic purpose does each decoy serve?)
# ─────────────────────────────────────────────────────────

# Maps decoy characteristics → Engage activities
DECOY_TYPE_MAPPING = {
    # Tier 1 beacons: detection-focused
    ("tier", 1): {
        "activities": ["EAC0005", "EAC0007"],   # Lure + Network Monitoring
        "approaches": ["EAP0004", "EAP0005"],    # Direction + Collection
        "goals": ["EGA0005"],                     # Detect
    },
    # Tier 2 scripted: detection + exposure
    ("tier", 2): {
        "activities": ["EAC0005", "EAC0007", "EAC0001"],
        "approaches": ["EAP0001", "EAP0004", "EAP0005"],
        "goals": ["EGA0005", "EGA0002"],          # Detect + Expose
    },
    # Tier 3 adaptive: full engagement
    ("tier", 3): {
        "activities": ["EAC0006", "EAC0001", "EAC0007"],  # Pocket Lure
        "approaches": ["EAP0001", "EAP0002", "EAP0005"],  # Reassurance + Motivation + Collection
        "goals": ["EGA0002", "EGA0004"],           # Expose + Elicit
    },
}

# Honeytoken types → Engage activities
HONEYTOKEN_MAPPING = {
    "aws-credential": {
        "activities": ["EAC0003", "EAC0008"],     # Decoy Credentials + Credential Monitoring
        "approaches": ["EAP0002", "EAP0005"],      # Motivation + Collection
        "goals": ["EGA0005", "EGA0002"],            # Detect + Expose
    },
    "kubeconfig": {
        "activities": ["EAC0003", "EAC0008"],
        "approaches": ["EAP0002", "EAP0005"],
        "goals": ["EGA0005", "EGA0002"],
    },
    "ssh-key": {
        "activities": ["EAC0003", "EAC0008"],
        "approaches": ["EAP0002", "EAP0005"],
        "goals": ["EGA0005", "EGA0002"],
    },
    "database-cred": {
        "activities": ["EAC0003", "EAC0008"],
        "approaches": ["EAP0002", "EAP0005"],
        "goals": ["EGA0005", "EGA0002"],
    },
    "document": {
        "activities": ["EAC0004"],                  # Decoy Content
        "approaches": ["EAP0002"],                   # Motivation
        "goals": ["EGA0005"],                        # Detect
    },
    "api-key": {
        "activities": ["EAC0003", "EAC0008"],
        "approaches": ["EAP0002", "EAP0005"],
        "goals": ["EGA0005", "EGA0002"],
    },
}

# Fleet-level strategies → Engage activities
FLEET_MAPPING = {
    "network_coverage": {
        "activities": ["EAC0002", "EAC0012"],     # Network Diversity + Artifact Diversity
        "approaches": ["EAP0004"],                  # Direction
        "goals": ["EGA0001", "EGA0005"],            # Prepare + Detect
    },
    "rotation_enabled": {
        "activities": ["EAC0012", "EAC0013"],     # Artifact Diversity + Attack Vector Migration
        "approaches": ["EAP0003"],                  # Disruption
        "goals": ["EGA0003"],                       # Affect
    },
}


def map_decoy_to_engage(decoy_spec: dict) -> dict:
    """
    Given a decoy manifest spec, return its Engage annotations.

    Used by the operator to label decoy pods and by the dashboard
    to display strategic context.
    """
    tier = decoy_spec.get("fidelity", {}).get("tier", 1)
    result = {
        "activities": [],
        "approaches": [],
        "goals": [],
    }

    # Base mapping from tier
    tier_key = ("tier", tier)
    if tier_key in DECOY_TYPE_MAPPING:
        mapping = DECOY_TYPE_MAPPING[tier_key]
        result["activities"].extend(mapping["activities"])
        result["approaches"].extend(mapping["approaches"])
        result["goals"].extend(mapping["goals"])

    # Honeytoken additions
    filesystem = decoy_spec.get("filesystem", {})
    for overlay in filesystem.get("overlays", []):
        if overlay.get("type") == "honeytoken":
            for token_ref in overlay.get("tokenRefs", []):
                # In production, resolve the token type from the CRD
                # For now, assume credential type
                ht_map = HONEYTOKEN_MAPPING.get("aws-credential", {})
                result["activities"].extend(ht_map.get("activities", []))
                result["approaches"].extend(ht_map.get("approaches", []))
                result["goals"].extend(ht_map.get("goals", []))

    # Introduced vulnerabilities (weak auth modes)
    auth_mode = decoy_spec.get("authentication", {}).get("mode", "closed")
    if auth_mode in ("open", "selective"):
        result["activities"].append("EAC0010")  # Introduced Vulnerabilities

    # Network behavior additions
    net = decoy_spec.get("networkBehavior", {})
    if net.get("beaconTraffic", {}).get("enabled"):
        result["activities"].append("EAC0011")  # Burn-In (establishing normalcy)

    # Deduplicate
    result["activities"] = sorted(set(result["activities"]))
    result["approaches"] = sorted(set(result["approaches"]))
    result["goals"] = sorted(set(result["goals"]))

    return result


# ─────────────────────────────────────────────────────────
#  Interaction-Level Engage Enrichment
#  (What did each session accomplish for our deception?)
# ─────────────────────────────────────────────────────────

@dataclass
class EngageOutcome:
    """What a single interaction achieved from the defender's perspective."""
    session_id: str
    decoy_name: str
    timestamp: str = ""

    # Engage classifications
    activities_exercised: list = field(default_factory=list)
    approaches_demonstrated: list = field(default_factory=list)
    goals_achieved: list = field(default_factory=list)

    # Operational metrics
    engagement_duration_seconds: float = 0
    commands_captured: int = 0
    credentials_harvested: int = 0
    honeytokens_triggered: int = 0
    ttps_observed: int = 0
    tools_identified: int = 0
    lateral_movement_attempted: bool = False

    # Effectiveness scoring
    deception_maintained: bool = True    # Did the attacker realize it's fake?
    intelligence_value: str = "low"      # low | medium | high | critical


class EngageEnricher:
    """
    Enriches session data with Engage outcomes.

    Called by the CTI pipeline after ATT&CK mapping, tool identification,
    and behavioral analysis are complete.
    """

    def enrich_session(self, session_data: dict) -> EngageOutcome:
        """
        Analyze a completed session and determine Engage outcomes.

        session_data should contain:
        - session_id, decoy_name, decoy_tier
        - duration_seconds, command_count
        - mitre_techniques (list of technique dicts)
        - tools_detected (list)
        - honeytokens_accessed (list)
        - credentials_captured (list)
        - alerts (list)
        """
        outcome = EngageOutcome(
            session_id=session_data.get("session_id", ""),
            decoy_name=session_data.get("decoy_name", ""),
            timestamp=datetime.utcnow().isoformat(),
            engagement_duration_seconds=session_data.get("duration_seconds", 0),
            commands_captured=session_data.get("command_count", 0),
        )

        tier = session_data.get("decoy_tier", 1)
        techniques = session_data.get("mitre_techniques", [])
        tools = session_data.get("tools_detected", [])
        honeytokens = session_data.get("honeytokens_accessed", [])
        credentials = session_data.get("credentials_captured", [])
        alerts = session_data.get("alerts", [])

        outcome.ttps_observed = len(techniques)
        outcome.tools_identified = len(tools)
        outcome.honeytokens_triggered = len(honeytokens)
        outcome.credentials_harvested = len(credentials)

        # Check for lateral movement
        lateral_techniques = {"T1021", "T1021.004", "T1021.002", "T1021.001"}
        outcome.lateral_movement_attempted = any(
            t.get("technique_id", "").split(".")[0] in lateral_techniques
            or t.get("technique_id", "") in lateral_techniques
            for t in techniques
        )

        # ── Map to Engage Activities ──

        # Any connection = Lure or Pocket Lure worked
        if tier <= 2:
            outcome.activities_exercised.append({
                "id": "EAC0005", "name": "Lure",
                "evidence": f"Adversary engaged with {outcome.decoy_name}",
            })
        else:
            outcome.activities_exercised.append({
                "id": "EAC0006", "name": "Pocket Lure",
                "evidence": f"Adversary engaged in extended session "
                            f"({outcome.engagement_duration_seconds:.0f}s, "
                            f"{outcome.commands_captured} commands)",
            })

        # Network monitoring captured data
        if outcome.commands_captured > 0:
            outcome.activities_exercised.append({
                "id": "EAC0007", "name": "Network Monitoring",
                "evidence": f"Captured {outcome.commands_captured} commands "
                            f"and {outcome.ttps_observed} TTPs",
            })

        # Credential harvesting
        if outcome.credentials_harvested > 0:
            outcome.activities_exercised.append({
                "id": "EAC0001", "name": "Persona Creation",
                "evidence": f"Decoy persona accepted {outcome.credentials_harvested} "
                            f"credential attempt(s)",
            })

        # Honeytoken triggers
        if outcome.honeytokens_triggered > 0:
            outcome.activities_exercised.append({
                "id": "EAC0003", "name": "Decoy Credentials",
                "evidence": f"{outcome.honeytokens_triggered} honeytoken(s) accessed",
            })
            outcome.activities_exercised.append({
                "id": "EAC0008", "name": "Credential Monitoring",
                "evidence": "Honeytoken access detected and tracked",
            })

        # Decoy content accessed (files read)
        file_reads = sum(1 for a in alerts if a.get("event_type") == "file.read")
        if file_reads > 0:
            outcome.activities_exercised.append({
                "id": "EAC0004", "name": "Decoy Content",
                "evidence": f"Adversary read {file_reads} decoy file(s)",
            })

        # ── Map to Engage Approaches ──

        # Reassurance — adversary believed the environment was real
        if outcome.commands_captured >= 3 and outcome.deception_maintained:
            outcome.approaches_demonstrated.append({
                "id": "EAP0001", "name": "Reassurance",
                "evidence": "Adversary executed multiple commands without "
                            "apparent detection of deception",
            })

        # Motivation — adversary pursued high-value targets
        if outcome.honeytokens_triggered > 0 or outcome.lateral_movement_attempted:
            outcome.approaches_demonstrated.append({
                "id": "EAP0002", "name": "Motivation",
                "evidence": "Adversary pursued planted credentials or "
                            "attempted lateral movement to high-value targets",
            })

        # Direction — adversary was channeled toward the decoy
        if outcome.commands_captured > 0:
            outcome.approaches_demonstrated.append({
                "id": "EAP0004", "name": "Direction",
                "evidence": f"Adversary directed to {outcome.decoy_name} "
                            f"and engaged for {outcome.engagement_duration_seconds:.0f}s",
            })

        # Collection — we gathered intelligence
        if outcome.ttps_observed > 0 or outcome.tools_identified > 0:
            outcome.approaches_demonstrated.append({
                "id": "EAP0005", "name": "Collection",
                "evidence": f"Collected {outcome.ttps_observed} TTPs, "
                            f"identified {outcome.tools_identified} tool(s)",
            })

        # ── Map to Engage Goals ──

        # Detect — we detected adversary presence
        outcome.goals_achieved.append({
            "id": "EGA0005", "name": "Detect",
            "evidence": "Adversary activity detected via deception asset",
        })

        # Expose — we revealed adversary TTPs
        if outcome.ttps_observed >= 3:
            outcome.goals_achieved.append({
                "id": "EGA0002", "name": "Expose",
                "evidence": f"Revealed {outcome.ttps_observed} adversary TTPs",
            })

        # Elicit — we drew out adversary behavior
        if outcome.engagement_duration_seconds > 120 and outcome.commands_captured >= 10:
            outcome.goals_achieved.append({
                "id": "EGA0004", "name": "Elicit",
                "evidence": f"Sustained engagement for "
                            f"{outcome.engagement_duration_seconds:.0f}s with "
                            f"{outcome.commands_captured} commands",
            })

        # Affect — we wasted adversary time/resources
        if outcome.engagement_duration_seconds > 300:
            outcome.goals_achieved.append({
                "id": "EGA0003", "name": "Affect",
                "evidence": f"Consumed {outcome.engagement_duration_seconds:.0f}s "
                            f"of adversary time on deception asset",
            })

        # ── Intelligence Value Scoring ──
        outcome.intelligence_value = self._score_intelligence(outcome)

        return outcome

    def _score_intelligence(self, outcome: EngageOutcome) -> str:
        """Score the intelligence value of a session."""
        score = 0

        # TTPs observed
        score += min(outcome.ttps_observed * 2, 10)

        # Tools identified
        score += outcome.tools_identified * 3

        # Honeytokens triggered (very high value)
        score += outcome.honeytokens_triggered * 5

        # Lateral movement (reveals attacker's network knowledge)
        if outcome.lateral_movement_attempted:
            score += 5

        # Duration (longer = more behavioral data)
        if outcome.engagement_duration_seconds > 300:
            score += 3
        elif outcome.engagement_duration_seconds > 60:
            score += 1

        # Command count (more commands = more TTP coverage)
        if outcome.commands_captured > 20:
            score += 3
        elif outcome.commands_captured > 10:
            score += 1

        if score >= 15:
            return "critical"
        elif score >= 10:
            return "high"
        elif score >= 5:
            return "medium"
        return "low"

    def to_dict(self, outcome: EngageOutcome) -> dict:
        """Serialize for storage and reporting."""
        return {
            "session_id": outcome.session_id,
            "decoy_name": outcome.decoy_name,
            "timestamp": outcome.timestamp,
            "engage": {
                "activities": outcome.activities_exercised,
                "approaches": outcome.approaches_demonstrated,
                "goals": outcome.goals_achieved,
            },
            "metrics": {
                "engagement_duration_seconds": outcome.engagement_duration_seconds,
                "commands_captured": outcome.commands_captured,
                "credentials_harvested": outcome.credentials_harvested,
                "honeytokens_triggered": outcome.honeytokens_triggered,
                "ttps_observed": outcome.ttps_observed,
                "tools_identified": outcome.tools_identified,
                "lateral_movement_attempted": outcome.lateral_movement_attempted,
                "deception_maintained": outcome.deception_maintained,
                "intelligence_value": outcome.intelligence_value,
            },
        }


# ─────────────────────────────────────────────────────────
#  Campaign-Level Engage Scoring
#  (How effective is our overall deception posture?)
# ─────────────────────────────────────────────────────────

class EngageCampaignAnalyzer:
    """
    Aggregates Engage outcomes across sessions and decoys to
    measure the effectiveness of deception campaigns.
    """

    def analyze_campaign(self, outcomes: list[EngageOutcome],
                         campaign_name: str = "") -> dict:
        """Generate campaign-level Engage metrics."""
        if not outcomes:
            return {"campaign": campaign_name, "sessions": 0}

        total_sessions = len(outcomes)
        total_duration = sum(o.engagement_duration_seconds for o in outcomes)
        total_commands = sum(o.commands_captured for o in outcomes)
        total_ttps = sum(o.ttps_observed for o in outcomes)
        total_tools = sum(o.tools_identified for o in outcomes)
        total_honeytokens = sum(o.honeytokens_triggered for o in outcomes)
        total_creds = sum(o.credentials_harvested for o in outcomes)
        lateral_count = sum(1 for o in outcomes if o.lateral_movement_attempted)
        deception_held = sum(1 for o in outcomes if o.deception_maintained)

        # Activity frequency
        activity_counts: dict[str, int] = {}
        for outcome in outcomes:
            for activity in outcome.activities_exercised:
                aid = activity["id"]
                activity_counts[aid] = activity_counts.get(aid, 0) + 1

        # Goal achievement
        goal_counts: dict[str, int] = {}
        for outcome in outcomes:
            for goal in outcome.goals_achieved:
                gid = goal["id"]
                goal_counts[gid] = goal_counts.get(gid, 0) + 1

        # Intelligence value distribution
        value_dist = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for outcome in outcomes:
            value_dist[outcome.intelligence_value] += 1

        # Unique decoys that saw activity
        active_decoys = set(o.decoy_name for o in outcomes)

        return {
            "campaign": campaign_name,
            "period": {
                "first_session": min(o.timestamp for o in outcomes),
                "last_session": max(o.timestamp for o in outcomes),
            },
            "summary": {
                "total_sessions": total_sessions,
                "total_engagement_hours": round(total_duration / 3600, 2),
                "total_commands_captured": total_commands,
                "total_ttps_observed": total_ttps,
                "total_tools_identified": total_tools,
                "honeytokens_triggered": total_honeytokens,
                "credentials_harvested": total_creds,
                "lateral_movement_attempts": lateral_count,
                "active_decoys": len(active_decoys),
                "deception_success_rate": round(deception_held / total_sessions * 100, 1),
            },
            "engage_activities": {
                aid: {
                    "name": ACTIVITIES[aid].name if aid in ACTIVITIES else aid,
                    "count": count,
                    "percentage": round(count / total_sessions * 100, 1),
                }
                for aid, count in sorted(activity_counts.items(),
                                          key=lambda x: x[1], reverse=True)
            },
            "engage_goals": {
                gid: {
                    "name": GOALS[gid].name if gid in GOALS else gid,
                    "count": count,
                    "percentage": round(count / total_sessions * 100, 1),
                }
                for gid, count in sorted(goal_counts.items(),
                                          key=lambda x: x[1], reverse=True)
            },
            "intelligence_value_distribution": value_dist,
        }
