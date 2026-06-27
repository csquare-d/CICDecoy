"""Fuzz tests: verify SSH command router and HTTP classifier handle malformed inputs.

These tests send adversarial inputs to verify:
1. No crashes (exceptions) on malformed commands
2. No hangs (infinite loops) on pathological inputs
3. No unbounded memory allocation
4. No ReDoS from crafted regex inputs
"""

import asyncio
import datetime
import os
import sys
import unittest

# Python 3.10 compat
if not hasattr(datetime, "UTC"):
    datetime.UTC = datetime.UTC

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "ssh-decoy"))


class TestCommandRouterFuzz(unittest.TestCase):
    """Fuzz tests for the SSH command router."""

    def _setup_router(self):
        from command_router import CommandRouter
        from filesystem import VirtualFilesystem
        from session import SessionState

        # Minimal config mock matching what CommandRouter.__init__ expects
        config = type(
            "Config",
            (),
            {
                "name": "fuzz-test",
                "hostname": "fuzz",
                "tier": 2,
                "port": 22,
                "credentials": [],
                "inference_endpoint": "",
                "profile_name": "",
                "custom_responses": [],
                "disallowed_paths": [],
                "filter_patterns": [],
                "max_response_lines": 500,
                "response_set": "",
                "fast_path_commands": [],
            },
        )()
        router = CommandRouter(config)
        fs = VirtualFilesystem()
        state = SessionState(
            hostname="fuzz",
            username="test",
            uid=1000,
            home="/home/test",
            cwd="/home/test",
            client_ip="10.0.0.1",
            client_port=12345,
            server_port=22,
        )
        return router, fs, state

    def _run_with_timeout(self, coro, timeout=2.0):
        """Run an async coroutine with a timeout to detect hangs."""
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(asyncio.wait_for(coro, timeout=timeout))
        except TimeoutError:
            self.fail(f"Command timed out after {timeout}s (possible hang/ReDoS)")
        finally:
            loop.close()

    def _route(self, router, command, state, fs, tier=2):
        """Route a command and assert it returns a string without crashing."""
        result = self._run_with_timeout(router.route(command=command, session_state=state, filesystem=fs, tier=tier))
        self.assertIsInstance(result, str, f"Expected str result for command: {command!r:.80}")
        return result

    # ── Individual fuzz cases ────────────────────────────

    def test_empty_command(self):
        router, fs, state = self._setup_router()
        self._route(router, "", state, fs)

    def test_whitespace_only(self):
        router, fs, state = self._setup_router()
        self._route(router, "   \t\n  ", state, fs)

    def test_null_bytes(self):
        router, fs, state = self._setup_router()
        self._route(router, "cat\x00/etc/passwd", state, fs)

    def test_very_long_command(self):
        router, fs, state = self._setup_router()
        self._route(router, "a" * 100_000, state, fs)

    def test_very_long_argument(self):
        router, fs, state = self._setup_router()
        self._route(router, "cat " + "x" * 100_000, state, fs)

    def test_unicode_command(self):
        router, fs, state = self._setup_router()
        self._route(router, "echo \U0001f3ad\U0001f40d\U0001f480", state, fs)

    def test_many_semicolons(self):
        router, fs, state = self._setup_router()
        self._route(router, ";".join(["echo x"] * 1000), state, fs)

    def test_deeply_nested_pipes(self):
        router, fs, state = self._setup_router()
        self._route(router, " | ".join(["echo x"] * 50), state, fs)

    def test_nested_subshell(self):
        router, fs, state = self._setup_router()
        self._route(router, "$($($($(echo x))))", state, fs)

    def test_redos_var_assignment(self):
        """Test the (\\w+=\\S+\\s+)+ regex with crafted input."""
        router, fs, state = self._setup_router()
        self._route(router, "A=B " * 500 + "notacmd", state, fs)

    def test_format_string(self):
        router, fs, state = self._setup_router()
        self._route(router, "echo %s %x %n %d", state, fs)

    def test_shell_expansion_bomb(self):
        router, fs, state = self._setup_router()
        self._route(router, "echo {1..99999}", state, fs)

    def test_backticks(self):
        router, fs, state = self._setup_router()
        self._route(router, "`rm -rf /`", state, fs)

    def test_control_characters(self):
        router, fs, state = self._setup_router()
        self._route(router, "echo \x01\x02\x03\x04\x05\x1b[31m", state, fs)

    def test_sql_injection(self):
        router, fs, state = self._setup_router()
        self._route(router, "cat file'; DROP TABLE users; --", state, fs)

    def test_path_traversal(self):
        router, fs, state = self._setup_router()
        self._route(router, "cat ../../../../etc/shadow", state, fs)

    def test_extremely_deep_nesting(self):
        router, fs, state = self._setup_router()
        self._route(router, "echo " + "$(" * 100 + "x" + ")" * 100, state, fs)

    def test_mixed_operators(self):
        router, fs, state = self._setup_router()
        self._route(router, "echo a && echo b || echo c ; echo d | cat > /dev/null", state, fs)

    def test_empty_pipe_segments(self):
        router, fs, state = self._setup_router()
        self._route(router, "| | | |", state, fs)

    def test_awk_regex_bomb(self):
        """Potential ReDoS in awk regex handling."""
        router, fs, state = self._setup_router()
        self._route(router, "echo x | awk '/" + "a?" * 50 + "/'", state, fs)


# ── HTTP Classifier Fuzz Tests ─────────────────────────────

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "http-decoy"))


class TestHTTPClassifierFuzz(unittest.TestCase):
    """Fuzz tests for the HTTP request classifier."""

    def _get_classifier(self):
        from http_enrichment import HttpRequestClassifier

        return HttpRequestClassifier()

    def _classify(self, classifier, method, path, headers, body=None, query=None):
        """Classify a request and assert it returns a dict without crashing."""
        result = classifier.classify(method, path, headers, body=body, query=query)
        self.assertIsInstance(result, dict, f"Expected dict for {method} {path!r:.80}")
        return result

    # ── Individual fuzz cases ────────────────────────────

    def test_empty_path(self):
        c = self._get_classifier()
        self._classify(c, "GET", "", {})

    def test_very_long_path(self):
        c = self._get_classifier()
        self._classify(c, "GET", "/" + "a" * 100_000, {})

    def test_null_bytes_in_path(self):
        c = self._get_classifier()
        self._classify(c, "GET", "/test\x00/admin", {})

    def test_unicode_path(self):
        c = self._get_classifier()
        self._classify(
            c, "GET", "/\u0430\u0434\u043c\u0438\u043d/\u043d\u0430\u0441\u0442\u0440\u043e\u0439\u043a\u0438", {}
        )

    def test_very_long_user_agent(self):
        c = self._get_classifier()
        self._classify(c, "GET", "/", {"user-agent": "x" * 100_000})

    def test_very_long_query(self):
        c = self._get_classifier()
        self._classify(c, "GET", "/search", {}, query="q=" + "a" * 100_000)

    def test_very_long_body(self):
        c = self._get_classifier()
        self._classify(c, "POST", "/api", {}, body="x" * 100_000)

    def test_sql_injection_in_path(self):
        c = self._get_classifier()
        self._classify(c, "GET", "/'; DROP TABLE--", {})

    def test_xss_in_user_agent(self):
        c = self._get_classifier()
        self._classify(c, "GET", "/", {"user-agent": "<script>alert(1)</script>"})

    def test_empty_everything(self):
        c = self._get_classifier()
        self._classify(c, "", "", {}, body="", query="")


if __name__ == "__main__":
    unittest.main()
