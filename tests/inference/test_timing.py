"""
Unit tests for the inference timing model.

Tests command categorization, latency profile selection,
timing ranges, and edge cases.
"""

import pytest
from timing import TimingModel

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def model():
    return TimingModel()


# ===================================================================
#  Command Categorization
# ===================================================================

class TestCommandCategorization:

    def test_instant_commands(self, model):
        instant_cmds = ["pwd", "whoami", "id", "hostname", "echo",
                        "true", "false", "cd", "export", "unset", "alias"]
        for cmd in instant_cmds:
            result = model.get_target_latency(cmd)
            assert result == model.LATENCY_PROFILES["instant"], (
                f"{cmd} should be categorized as 'instant'"
            )

    def test_fast_commands(self, model):
        fast_cmds = ["ls", "cat", "head", "tail", "wc", "date",
                     "uptime", "uname", "env", "printenv"]
        for cmd in fast_cmds:
            result = model.get_target_latency(cmd)
            assert result == model.LATENCY_PROFILES["fast"], (
                f"{cmd} should be categorized as 'fast'"
            )

    def test_moderate_commands(self, model):
        moderate_cmds = ["ps", "df", "free", "mount", "lsblk",
                         "ip", "ss", "netstat", "systemctl", "docker"]
        for cmd in moderate_cmds:
            result = model.get_target_latency(cmd)
            assert result == model.LATENCY_PROFILES["moderate"], (
                f"{cmd} should be categorized as 'moderate'"
            )

    def test_slow_commands(self, model):
        slow_cmds = ["find", "grep", "locate", "du", "tar",
                     "zip", "ansible", "terraform", "kubectl"]
        for cmd in slow_cmds:
            result = model.get_target_latency(cmd)
            assert result == model.LATENCY_PROFILES["slow"], (
                f"{cmd} should be categorized as 'slow'"
            )

    def test_network_commands(self, model):
        network_cmds = ["ssh", "scp", "curl", "wget", "ping",
                        "nmap", "nc", "telnet", "dig", "nslookup"]
        for cmd in network_cmds:
            result = model.get_target_latency(cmd)
            assert result == model.LATENCY_PROFILES["network"], (
                f"{cmd} should be categorized as 'network'"
            )

    def test_heavy_commands(self, model):
        heavy_cmds = ["apt", "yum", "pip", "npm", "make", "gcc"]
        for cmd in heavy_cmds:
            result = model.get_target_latency(cmd)
            assert result == model.LATENCY_PROFILES["heavy"], (
                f"{cmd} should be categorized as 'heavy'"
            )


# ===================================================================
#  Latency Profile Values
# ===================================================================

class TestLatencyProfiles:

    def test_all_profiles_have_required_keys(self, model):
        for name, profile in model.LATENCY_PROFILES.items():
            assert "min" in profile, f"Profile '{name}' missing 'min'"
            assert "max" in profile, f"Profile '{name}' missing 'max'"
            assert "mean" in profile, f"Profile '{name}' missing 'mean'"

    def test_min_less_than_max(self, model):
        for name, profile in model.LATENCY_PROFILES.items():
            assert profile["min"] < profile["max"], (
                f"Profile '{name}': min ({profile['min']}) >= max ({profile['max']})"
            )

    def test_mean_between_min_and_max(self, model):
        for name, profile in model.LATENCY_PROFILES.items():
            assert profile["min"] <= profile["mean"] <= profile["max"], (
                f"Profile '{name}': mean ({profile['mean']}) not between "
                f"min ({profile['min']}) and max ({profile['max']})"
            )

    def test_instant_faster_than_fast(self, model):
        assert model.LATENCY_PROFILES["instant"]["max"] <= model.LATENCY_PROFILES["fast"]["max"]

    def test_fast_faster_than_moderate(self, model):
        assert model.LATENCY_PROFILES["fast"]["max"] <= model.LATENCY_PROFILES["moderate"]["max"]

    def test_heavy_is_slowest(self, model):
        heavy_max = model.LATENCY_PROFILES["heavy"]["max"]
        for name, profile in model.LATENCY_PROFILES.items():
            if name != "heavy":
                assert profile["max"] <= heavy_max, (
                    f"Profile '{name}' max ({profile['max']}) exceeds "
                    f"heavy max ({heavy_max})"
                )

    def test_instant_latency_values(self, model):
        profile = model.LATENCY_PROFILES["instant"]
        assert profile["min"] == 0.001
        assert profile["max"] == 0.005
        assert profile["mean"] == 0.003

    def test_network_latency_values(self, model):
        profile = model.LATENCY_PROFILES["network"]
        assert profile["min"] == 0.5
        assert profile["max"] == 30.0


# ===================================================================
#  Command Parsing & Edge Cases
# ===================================================================

class TestCommandParsing:

    def test_command_with_arguments(self, model):
        """Only the first token (the binary name) should be matched."""
        result = model.get_target_latency("ls -la /tmp")
        assert result == model.LATENCY_PROFILES["fast"]

    def test_command_with_many_arguments(self, model):
        result = model.get_target_latency("find / -name '*.py' -type f")
        assert result == model.LATENCY_PROFILES["slow"]

    def test_unknown_command_returns_moderate(self, model):
        result = model.get_target_latency("some_custom_binary --flag")
        assert result == model.LATENCY_PROFILES["moderate"]

    def test_empty_command_returns_moderate(self, model):
        result = model.get_target_latency("")
        assert result == model.LATENCY_PROFILES["moderate"]

    def test_whitespace_only_returns_moderate(self, model):
        # "   ".split() returns [] so command.split()[0] would fail
        # but the code uses `command.split()[0] if command.split() else command`
        result = model.get_target_latency("   ")
        assert result == model.LATENCY_PROFILES["moderate"]

    def test_command_with_path_prefix_not_matched(self, model):
        """/usr/bin/ls won't match 'ls' -- falls back to moderate."""
        result = model.get_target_latency("/usr/bin/ls -la")
        assert result == model.LATENCY_PROFILES["moderate"]

    def test_command_case_sensitive(self, model):
        """Commands are matched case-sensitively; 'LS' is unknown."""
        result = model.get_target_latency("LS -la")
        assert result == model.LATENCY_PROFILES["moderate"]


# ===================================================================
#  Category Completeness
# ===================================================================

class TestCategoryCompleteness:

    def test_all_categories_have_profiles(self, model):
        """Every category in COMMAND_CATEGORIES has a matching profile."""
        for category in model.COMMAND_CATEGORIES:
            assert category in model.LATENCY_PROFILES, (
                f"Category '{category}' has no matching latency profile"
            )

    def test_no_command_in_multiple_categories(self, model):
        """Each command should appear in exactly one category."""
        seen = {}
        for category, commands in model.COMMAND_CATEGORIES.items():
            for cmd in commands:
                assert cmd not in seen, (
                    f"Command '{cmd}' appears in both "
                    f"'{seen[cmd]}' and '{category}'"
                )
                seen[cmd] = category
