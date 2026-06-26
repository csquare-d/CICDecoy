"""
CI/CDecoy — Honeytoken Enrichment Tests

Tests for honeytoken-specific enrichment in cti/enrichment.py:
- severity classification for honeytoken events
- MITRE ATT&CK technique mapping (T1552.001, T1552.004)
- non-honeytoken events are not affected
"""

from enrichment import enrich_event


class TestHoneytokenEnrichment:
    def test_honeytoken_accessed_gets_critical_severity(self):
        """honeytoken.accessed events must be enriched with critical severity."""
        raw = {
            "event_type": "honeytoken.accessed",
            "source_ip": "198.51.100.1",
            "data": {"client_ip": "198.51.100.1", "token_type": "api-key"},
        }
        result = enrich_event(raw)
        assert result["severity"] == "critical"

    def test_honeytoken_accessed_gets_t1552_001(self):
        """honeytoken.accessed events must include T1552.001 (Credentials In Files)."""
        raw = {
            "event_type": "honeytoken.accessed",
            "source_ip": "198.51.100.1",
            "data": {"client_ip": "198.51.100.1", "token_type": "api-key"},
        }
        result = enrich_event(raw)
        technique_ids = [t["technique_id"] for t in result["mitre_techniques"]]
        assert "T1552.001" in technique_ids

    def test_honeytoken_ssh_key_gets_t1552_004(self):
        """honeytoken events with token_type='ssh-key' must also include T1552.004."""
        raw = {
            "event_type": "honeytoken.accessed",
            "source_ip": "198.51.100.1",
            "data": {"client_ip": "198.51.100.1", "token_type": "ssh-key"},
        }
        result = enrich_event(raw)
        technique_ids = [t["technique_id"] for t in result["mitre_techniques"]]
        assert "T1552.004" in technique_ids
        # Should still have T1552.001 as well
        assert "T1552.001" in technique_ids

    def test_honeytoken_non_ssh_key_no_t1552_004(self):
        """honeytoken events with token_type other than 'ssh-key' must NOT include T1552.004."""
        for token_type in ("api-key", "aws-credential", "password", ""):
            raw = {
                "event_type": "honeytoken.accessed",
                "source_ip": "198.51.100.1",
                "data": {"client_ip": "198.51.100.1", "token_type": token_type},
            }
            result = enrich_event(raw)
            technique_ids = [t["technique_id"] for t in result["mitre_techniques"]]
            assert "T1552.004" not in technique_ids, f"T1552.004 should not appear for token_type={token_type!r}"

    def test_non_honeytoken_event_unchanged(self):
        """Normal command events should not be routed through honeytoken enrichment."""
        raw = {
            "event_type": "command",
            "source_ip": "198.51.100.1",
            "data": {"command": "whoami", "client_ip": "198.51.100.1"},
        }
        result = enrich_event(raw)
        # A normal command event should not get "critical" severity from the
        # honeytoken path (whoami is typically info/low).
        assert result["severity"] != "critical"
        # Should not contain "Credential Access" tag from honeytoken path
        # (it might contain it from command classification, but the enrichment
        # path taken should be different).
        # The key assertion: the result comes from command classification, not
        # the honeytoken short-circuit that always returns critical.
        assert result["severity"] in ("info", "low", "medium", "high")
