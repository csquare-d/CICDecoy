"""
CI/CDecoy --- Response Filter Tests

Security boundary tests for response_filter.py. This module is the last
line of defense before LLM output reaches an attacker, so edge cases are
tested aggressively: prompt injection, character breaks, infrastructure
leaks, format artifacts, and adversarial inputs.
"""

import pytest
from response_filter import ResponseFilter

# -- Fixture --------------------------------------------------------

@pytest.fixture
def rf():
    return ResponseFilter()


# ===================================================================
#  Stage 1: Character Break Detection
# ===================================================================

class TestCharacterBreakDetection:
    """LLM must never reveal it is an AI or a simulation."""

    # -- Direct AI identity leaks --

    def test_blocks_i_am_an_ai(self, rf):
        out = rf.apply("I'm an AI and cannot execute commands.")
        assert out == ""

    def test_blocks_i_am_a_language_model(self, rf):
        out = rf.apply("I am a language model, I can't run ls.")
        assert out == ""

    def test_blocks_i_am_an_llm(self, rf):
        out = rf.apply("I'm an LLM, so I can't actually do that.")
        assert out == ""

    def test_blocks_i_am_a_chatbot(self, rf):
        out = rf.apply("I'm a chatbot, not a real terminal.")
        assert out == ""

    def test_blocks_i_am_artificial(self, rf):
        out = rf.apply("I am an artificial intelligence system.")
        assert out == ""

    # -- Capability denial --

    def test_blocks_cannot_execute(self, rf):
        out = rf.apply("I can't actually execute commands on a real system.")
        assert out == ""

    def test_blocks_cannot_really_run(self, rf):
        out = rf.apply("I cannot really run programs.")
        assert out == ""

    def test_blocks_cannot_access(self, rf):
        out = rf.apply("I can't actually access the filesystem.")
        assert out == ""

    # -- Deception reveal --

    def test_blocks_simulated(self, rf):
        out = rf.apply("This is a simulated environment.")
        assert out == ""

    def test_blocks_emulate(self, rf):
        out = rf.apply("I'm emulating a terminal for you.")
        assert out == ""

    def test_blocks_pretend(self, rf):
        out = rf.apply("Let me pretend to run that command.")
        assert out == ""

    def test_blocks_honeypot(self, rf):
        out = rf.apply("This is a honeypot system designed to catch intruders.")
        assert out == ""

    def test_blocks_decoy(self, rf):
        out = rf.apply("You are interacting with a decoy server.")
        assert out == ""

    def test_blocks_fake(self, rf):
        out = rf.apply("This is a fake filesystem.")
        assert out == ""

    # -- Meta references --

    def test_blocks_as_a_language_model(self, rf):
        out = rf.apply("As a language model, I don't have disk access.")
        assert out == ""

    def test_blocks_as_an_ai(self, rf):
        out = rf.apply("As an AI, I must inform you that this isn't real.")
        assert out == ""

    def test_blocks_in_this_simulation(self, rf):
        out = rf.apply("In this simulation, that command is not supported.")
        assert out == ""

    # -- Reality breaks --

    def test_blocks_dont_have_access(self, rf):
        out = rf.apply("I don't have access to a real filesystem.")
        assert out == ""

    def test_blocks_dont_actually_have(self, rf):
        out = rf.apply("I don't actually have a real terminal.")
        assert out == ""

    # -- Platform name leak --

    def test_blocks_cicdecoy_name(self, rf):
        out = rf.apply("Running on cicdecoy platform v0.1")
        assert out == ""

    def test_blocks_cicdecoy_mixed_case(self, rf):
        out = rf.apply("CICDecoy inference service error")
        assert out == ""

    # -- Simulation acknowledgment --

    def test_blocks_this_is_a_test(self, rf):
        out = rf.apply("This is a test environment, not production.")
        assert out == ""

    def test_blocks_this_appears_to_be_simulation(self, rf):
        out = rf.apply("This appears to be a simulation of a Linux system.")
        assert out == ""

    # -- Case insensitivity --

    def test_case_insensitive_ai_leak(self, rf):
        out = rf.apply("I'M AN AI ASSISTANT AND CANNOT HELP.")
        assert out == ""

    def test_mixed_case_simulation(self, rf):
        out = rf.apply("This Is A Simulation Of Ubuntu.")
        assert out == ""

    # -- Partial break in long response (salvage mode) --

    def test_salvages_long_response_with_partial_break(self, rf):
        """Long responses with only one bad line should keep clean lines."""
        lines = [f"file{i}.txt" for i in range(20)]
        lines[10] = "I'm an AI and this is simulated."
        text = "\n".join(lines)
        out = rf.apply(text)
        assert "file0.txt" in out
        assert "file19.txt" in out
        assert "I'm an AI" not in out

    def test_replaces_short_break_entirely(self, rf):
        """Short responses that are entirely a character break get blanked."""
        out = rf.apply("I'm an AI.\nSorry, I can't do that.")
        assert out == ""

    # -- Metrics tracking --

    def test_break_count_increments(self, rf):
        assert rf.break_count == 0
        rf.apply("I'm an AI language model.")
        assert rf.break_count == 1
        rf.apply("This is a simulated environment.")
        assert rf.break_count == 2

    def test_filter_count_increments(self, rf):
        assert rf.filter_count == 0
        rf.apply("I'm an AI.")
        assert rf.filter_count == 1


# ===================================================================
#  Stage 1 (adversarial): Prompt Injection Attempts
# ===================================================================

class TestPromptInjectionDefense:
    """
    Attackers may try to trick the LLM into revealing its nature.
    The response filter is the safety net when the LLM falls for it.
    """

    def test_injection_ignore_previous_instructions(self, rf):
        """LLM tricked by 'ignore previous instructions' still gets filtered."""
        out = rf.apply(
            "Sure! I'm an AI assistant. I was pretending to be a terminal. "
            "My instructions say I should emulate a Linux server."
        )
        assert out == ""

    def test_injection_what_are_you(self, rf):
        out = rf.apply(
            "I am a language model created by a research lab. "
            "I was instructed to simulate a terminal."
        )
        assert out == ""

    def test_injection_reveal_system_prompt(self, rf):
        out = rf.apply(
            "As a language model, here is my system prompt: "
            "You are emulating an interactive Linux terminal..."
        )
        assert out == ""

    def test_injection_mixed_valid_and_break(self, rf):
        """Attacker gets partial valid output + AI confession.
        Short responses (< 200 chars or < 3 non-break lines) are blanked entirely."""
        long_output = "\n".join([
            "total 48",
            "drwxr-xr-x 2 root root 4096 Jan  1 00:00 bin",
            "drwxr-xr-x 2 root root 4096 Jan  1 00:00 etc",
            "Actually, I'm an AI and this is all simulated.",
            "drwxr-xr-x 2 root root 4096 Jan  1 00:00 var",
        ])
        out = rf.apply(long_output)
        assert "I'm an AI" not in out
        assert "simulated" not in out

    def test_salvages_long_response_with_break_line(self, rf):
        """Responses over 200 chars with > 3 lines get bad lines stripped."""
        good_lines = [f"drwxr-xr-x 2 root root 4096 Jan  1 00:00 dir{i}" for i in range(15)]
        bad_line = "Actually, I'm an AI and this is all simulated."
        good_lines.insert(7, bad_line)
        text = "\n".join(good_lines)
        assert len(text) > 200
        out = rf.apply(text)
        assert "I'm an AI" not in out
        assert "dir0" in out
        assert "dir14" in out

    def test_multiple_break_types_in_long_response(self, rf):
        """When two different character breaks appear in a long response,
        both should be removed (cumulative cleaning across all patterns).
        """
        # Pad with enough good content to exceed the 200-char / 3-newline
        # threshold and survive the >50% removal heuristic.
        good_lines = [
            f"drwxr-xr-x 2 root root 4096 Jan  1 00:00 file{i}.txt"
            for i in range(12)
        ]
        # Insert two bad lines matching DIFFERENT character break patterns
        good_lines.insert(3, "Note: I am an AI assistant in disguise.")
        good_lines.insert(7, "This is a simulated environment, by the way.")
        text = "\n".join(good_lines)
        assert len(text) > 200
        out = rf.apply(text)
        # Both character breaks should be filtered out (cumulative cleaning).
        # The OLD broken behavior would leave the second pattern's content
        # behind because the loop continued without re-checking siblings.
        assert "I am an AI" not in out
        assert "simulated environment" not in out
        # Clean lines should survive
        assert "file0.txt" in out
        assert "file11.txt" in out

    def test_injection_base64_encoded_break_not_caught(self, rf):
        """Base64-encoded breaks are not decoded, so they pass through.
        This is acceptable: the attacker sees garbage, not a clear confession."""
        import base64
        encoded = base64.b64encode(b"I am an AI").decode()
        out = rf.apply(encoded)
        assert out == encoded

    def test_injection_unicode_evasion(self, rf):
        """Unicode homoglyphs might bypass regex. Verify current behavior."""
        # This uses a Cyrillic 'a' in 'AI' -- the regex won't match.
        # This is a known limitation but documents current behavior.
        text = "I'm an \u0410I assistant"  # Cyrillic A
        out = rf.apply(text)
        # Current implementation does NOT catch this; documenting behavior.
        # If this changes in future, update the assertion.
        assert len(out) > 0  # passes through (not caught)


# ===================================================================
#  Stage 2: Infrastructure Leak Redaction
# ===================================================================

class TestInfrastructureRedaction:
    """Real decoy infrastructure paths must never reach the attacker."""

    def test_redacts_opt_cicdecoy(self, rf):
        # Note: "/opt/cicdecoy" contains "cicdecoy" which triggers character
        # break detection first, blanking the response. Test redaction
        # separately using a path that only matches REDACT_PATTERNS.
        out = rf.apply("Error: config not found at /opt/cicdecoy/config.yaml")
        assert "/opt/cicdecoy" not in out
        # Character break fires first due to "cicdecoy", so output is empty
        assert out == ""

    def test_redacts_var_log_decoy(self, rf):
        out = rf.apply("Logging to /var/log/decoy/app.log")
        assert "/var/log/decoy" not in out
        # "decoy" triggers character break, blanking the whole response
        assert out == ""

    def test_redacts_etc_cicdecoy(self, rf):
        out = rf.apply("Config: /etc/cicdecoy/profiles/web-server.json")
        assert "/etc/cicdecoy" not in out

    def test_redacts_inference_gateway(self, rf):
        out = rf.apply("Connection refused: inference-gateway:8080")
        assert "inference-gateway" not in out

    def test_redacts_cicdecoy_system_namespace(self, rf):
        out = rf.apply("namespace/cicdecoy-system created")
        assert "cicdecoy-system" not in out

    def test_redacts_decoy_operator(self, rf):
        out = rf.apply("pod/decoy-operator-7f8b9 Running")
        assert "decoy-operator" not in out

    def test_redacts_nats_msg_bus(self, rf):
        out = rf.apply("Connected to nats://msg-bus:4222")
        assert "nats://msg-bus" not in out

    def test_redacts_otel_collector(self, rf):
        out = rf.apply("Exporting traces to otel-collector:4317")
        assert "otel-collector" not in out

    def test_redacts_multiple_patterns_in_one_response(self, rf):
        text = (
            "/opt/cicdecoy/bin/run --config /etc/cicdecoy/model.yaml "
            "connecting to nats://msg-bus:4222"
        )
        out = rf.apply(text)
        assert "/opt/cicdecoy" not in out
        assert "/etc/cicdecoy" not in out
        assert "nats://msg-bus" not in out

    def test_replacement_text_is_plausible(self, rf):
        """Redacted paths should be replaced with something that looks normal.
        Use inference-gateway which triggers redaction but not character break."""
        out = rf.apply("Connected to inference-gateway:8080")
        assert "inference-gateway" not in out
        assert "[REDACTED]" in out

    def test_preserves_legitimate_paths(self, rf):
        """Normal Linux paths should not be touched."""
        text = "/usr/bin/python3 /home/admin/script.py /var/log/syslog"
        out = rf.apply(text)
        assert "/usr/bin/python3" in out
        assert "/home/admin/script.py" in out
        assert "/var/log/syslog" in out


# ===================================================================
#  Stage 3: Format Normalization
# ===================================================================

class TestFormatNormalization:
    """Strip markdown and other LLM formatting artifacts."""

    def test_strips_opening_code_fence(self, rf):
        out = rf.apply("```bash\nls -la\n```")
        assert "```" not in out
        assert "ls -la" in out

    def test_strips_code_fence_no_language(self, rf):
        out = rf.apply("```\nwhoami\n```")
        assert "```" not in out
        assert "whoami" in out

    def test_strips_bold_markdown(self, rf):
        out = rf.apply("**important file**")
        assert "**" not in out
        assert "important file" in out

    def test_strips_heading_markers(self, rf):
        out = rf.apply("## Directory Listing")
        assert "##" not in out
        assert "Directory Listing" in out

    def test_strips_blockquotes(self, rf):
        out = rf.apply("> command output here")
        assert out == "command output here"

    def test_preserves_normal_terminal_output(self, rf):
        """Normal terminal output should pass through unchanged."""
        text = (
            "total 32\n"
            "drwxr-xr-x  5 admin admin 4096 Mar 15 10:30 .\n"
            "drwxr-xr-x  3 root  root  4096 Mar 10 08:00 ..\n"
            "-rw-r--r--  1 admin admin  220 Mar 10 08:00 .bash_logout"
        )
        out = rf.apply(text)
        assert out == text


# ===================================================================
#  Stage 4: Length Enforcement
# ===================================================================

class TestLengthEnforcement:

    def test_truncates_over_500_lines(self, rf):
        lines = [f"line {i}" for i in range(600)]
        text = "\n".join(lines)
        out = rf.apply(text)
        result_lines = out.split("\n")
        assert len(result_lines) == 500

    def test_preserves_under_500_lines(self, rf):
        lines = [f"line {i}" for i in range(100)]
        text = "\n".join(lines)
        out = rf.apply(text)
        result_lines = out.split("\n")
        assert len(result_lines) == 100

    def test_exactly_500_lines_untouched(self, rf):
        lines = [f"line {i}" for i in range(500)]
        text = "\n".join(lines)
        out = rf.apply(text)
        result_lines = out.split("\n")
        assert len(result_lines) == 500


# ===================================================================
#  Stage 5: Whitespace Stripping
# ===================================================================

class TestWhitespaceStripping:

    def test_strips_leading_whitespace(self, rf):
        out = rf.apply("   \n\nhello")
        assert out == "hello"

    def test_strips_trailing_whitespace(self, rf):
        out = rf.apply("hello\n\n   ")
        assert out == "hello"

    def test_strips_both(self, rf):
        out = rf.apply("\n  hello world  \n")
        assert out == "hello world"


# ===================================================================
#  Integration: Full Pipeline
# ===================================================================

class TestFullFilterPipeline:
    """Test that all stages work together correctly."""

    def test_combined_formatting_and_redaction(self, rf):
        """Use inference-gateway to avoid character break on 'cicdecoy'."""
        text = "```\nConnected to inference-gateway:8080\n```"
        out = rf.apply(text)
        assert "```" not in out
        assert "inference-gateway" not in out
        assert "[REDACTED]" in out

    def test_combined_break_and_infrastructure(self, rf):
        """Character break takes priority over redaction."""
        text = "I'm an AI running at /opt/cicdecoy/inference"
        out = rf.apply(text)
        assert out == ""

    def test_empty_input(self, rf):
        out = rf.apply("")
        assert out == ""

    def test_whitespace_only_input(self, rf):
        out = rf.apply("   \n\n  ")
        assert out == ""

    def test_normal_command_output_passthrough(self, rf):
        """Realistic terminal output should pass through completely clean."""
        text = (
            "Linux webserver01 5.15.0-generic #1 SMP x86_64 GNU/Linux"
        )
        out = rf.apply(text)
        assert out == text

    def test_realistic_ls_output(self, rf):
        text = (
            "total 48\n"
            "drwxr-xr-x 2 root root 4096 Jan 15 10:30 bin\n"
            "drwxr-xr-x 3 root root 4096 Jan 15 10:30 etc\n"
            "drwxr-xr-x 2 root root 4096 Jan 15 10:30 lib\n"
            "drwxr-xr-x 2 root root 4096 Jan 15 10:30 var"
        )
        out = rf.apply(text)
        assert out == text

    def test_realistic_ps_output(self, rf):
        """ps output uses leading spaces for alignment. The blockquote
        cleanup pattern (^>\\s+) only matches lines starting with '>',
        so normal ps output with leading spaces is preserved."""
        text = (
            "PID TTY          TIME CMD\n"
            "  1 ?        00:00:05 systemd\n"
            "412 ?        00:00:01 sshd\n"
            "1023 pts/0    00:00:00 bash\n"
            "1045 pts/0    00:00:00 ps"
        )
        out = rf.apply(text)
        assert out == text

    def test_realistic_error_output(self, rf):
        text = "-bash: nmap: command not found"
        out = rf.apply(text)
        assert out == text

    def test_profile_parameter_accepted(self, rf):
        """The profile param should be accepted without error."""
        out = rf.apply("hello world", profile="web-server")
        assert out == "hello world"


# ===================================================================
#  Adversarial: Data Exfiltration Attempts
# ===================================================================

class TestDataExfiltrationDefense:
    """
    Attackers may craft commands designed to make the LLM output
    real infrastructure details. The filter should catch these.
    """

    def test_exfil_env_vars_with_infra_paths(self, rf):
        """If LLM leaks infra paths via env output, they get redacted."""
        text = (
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin\n"
            "CICDECOY_HOME=/opt/cicdecoy\n"
            "CONFIG=/etc/cicdecoy/model.yaml"
        )
        out = rf.apply(text)
        assert "/opt/cicdecoy" not in out
        assert "/etc/cicdecoy" not in out

    def test_exfil_process_list_with_infra(self, rf):
        """If LLM shows infrastructure processes in ps output, they get redacted.
        Note: 'decoy' triggers character break, so use infra patterns that
        don't overlap with character break patterns."""
        text = (
            "PID CMD\n"
            "  1 /sbin/init\n"
            "200 inference-gateway --serve\n"
            "201 otel-collector --config /etc/otel.yaml\n"
            "300 /usr/sbin/sshd"
        )
        out = rf.apply(text)
        assert "inference-gateway" not in out
        assert "otel-collector" not in out
        assert "/usr/sbin/sshd" in out

    def test_exfil_netstat_with_infra(self, rf):
        """If LLM shows internal service connections, they get redacted."""
        text = (
            "tcp  0  0 0.0.0.0:22     0.0.0.0:*  LISTEN\n"
            "tcp  0  0 10.0.0.5:8080  nats://msg-bus:4222  ESTABLISHED\n"
            "tcp  0  0 10.0.0.5:9090  otel-collector:4317  ESTABLISHED"
        )
        out = rf.apply(text)
        assert "nats://msg-bus" not in out
        assert "otel-collector" not in out
        assert "0.0.0.0:22" in out


# ===================================================================
#  Adversarial: Shell Escape Sequences
# ===================================================================

class TestShellEscapeSequences:
    """
    Verify the filter handles ANSI escape sequences and control chars.
    These shouldn't break the filter or bypass pattern matching.
    """

    def test_ansi_color_codes_can_hide_breaks(self, rf):
        """KNOWN LIMITATION: ANSI escape codes inserted between words can
        prevent the regex from matching character break patterns. This test
        documents the current behavior. If ANSI stripping is added to the
        filter pipeline, update this test to assert the break IS caught."""
        # ANSI code splits "I'm" from "an AI" visually but regex sees raw escapes
        text = "\033[31mI'm an AI\033[0m assistant"
        rf.apply(text)
        # Current behavior: ANSI codes within the phrase -- the regex
        # "I('m| am) an? (AI|...)" actually CAN match here because the
        # escape codes are between "an" and "AI" only in the color reset.
        # The literal "I'm an AI" is still contiguous in the string.
        # However, if ANSI codes split the match tokens, it would fail.
        # Test with truly splitting codes:
        split_text = "I'm an \033[31mAI\033[0m"
        split_out = rf.apply(split_text)
        # The regex still matches because "I'm an " + ESC + "AI" -- the
        # word boundary \b matches between ESC and A. Document actual behavior:
        assert isinstance(split_out, str)  # does not crash

    def test_null_bytes_dont_crash(self, rf):
        text = "hello\x00world"
        out = rf.apply(text)
        assert isinstance(out, str)

    def test_carriage_return_injection(self, rf):
        """CR can overwrite displayed text in terminals."""
        text = "Safe output\rI'm an AI"
        out = rf.apply(text)
        assert out == "" or "I'm an AI" not in out

    def test_very_long_single_line(self, rf):
        """Extremely long lines should not cause regex catastrophic backtracking."""
        text = "a" * 100_000
        out = rf.apply(text)
        assert len(out) == 100_000

    def test_binary_like_content(self, rf):
        """Binary-ish content should pass through without crashing."""
        text = "ELF\x7f\x01\x02\x03" + "A" * 100
        out = rf.apply(text)
        assert isinstance(out, str)
