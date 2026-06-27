"""Tests for SSH decoy fidelity improvements (v0.2.0)."""

import asyncio
import datetime
import os
import sys
import unittest

# Python 3.10 compat: ensure datetime.UTC exists
if not hasattr(datetime, "UTC"):
    datetime.UTC = datetime.UTC

# Add ssh-decoy to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "ssh-decoy"))

from command_router import CommandRouter
from filesystem import VirtualFilesystem
from session import SessionState


def _build_fs():
    """Create a VirtualFilesystem with the base skeleton populated."""
    fs = VirtualFilesystem()
    fs._build_base_skeleton()
    return fs


class _FakeConfig:
    """Minimal config for CommandRouter (mirrors test_command_router.py)."""

    def __init__(self):
        self.tier = 2
        self.hostname = "test-host"
        self.domain = "test.local"
        self.name = "test-decoy"
        self.profile_name = ""
        self.inference_endpoint = "http://localhost:8000"
        self.max_session_tokens = 4096
        self.temperature = 0.3
        self.fast_path_commands = []
        self.filter_patterns = []
        self.custom_responses = {}


# ═══════════════════════════════════════════════════════════════
# Filesystem stub tests
# ═══════════════════════════════════════════════════════════════


class TestFilesystemStubs(unittest.TestCase):
    """Verify /dev/, /proc/self/, and /etc/sudoers stubs exist."""

    def setUp(self):
        self.fs = _build_fs()

    # ── /dev stubs ──────────────────────────────────────

    def test_dev_null_exists(self):
        self.assertTrue(self.fs.file_exists("/dev/null"))
        content = self.fs.read_file("/dev/null")
        self.assertEqual(content, "")

    def test_dev_zero_exists(self):
        self.assertTrue(self.fs.file_exists("/dev/zero"))

    def test_dev_urandom_exists(self):
        self.assertTrue(self.fs.file_exists("/dev/urandom"))
        content = self.fs.read_file("/dev/urandom")
        self.assertTrue(len(content) > 0)

    def test_dev_random_exists(self):
        self.assertTrue(self.fs.file_exists("/dev/random"))
        content = self.fs.read_file("/dev/random")
        self.assertTrue(len(content) > 0)

    # ── /proc/self stubs ────────────────────────────────

    def test_proc_self_cmdline(self):
        self.assertTrue(self.fs.file_exists("/proc/self/cmdline"))
        content = self.fs.read_file("/proc/self/cmdline")
        self.assertIn("bash", content)

    def test_proc_self_status(self):
        self.assertTrue(self.fs.file_exists("/proc/self/status"))
        content = self.fs.read_file("/proc/self/status")
        self.assertIn("Name:", content)
        self.assertIn("Pid:", content)

    def test_proc_self_maps(self):
        self.assertTrue(self.fs.file_exists("/proc/self/maps"))
        content = self.fs.read_file("/proc/self/maps")
        # Memory mappings contain address ranges and permissions like "r-xp"
        self.assertIn("r--p", content)
        self.assertIn("/usr/bin/bash", content)

    def test_proc_self_environ(self):
        self.assertTrue(self.fs.file_exists("/proc/self/environ"))
        content = self.fs.read_file("/proc/self/environ")
        self.assertTrue(len(content) > 0)

    def test_proc_self_cgroup(self):
        self.assertTrue(self.fs.file_exists("/proc/self/cgroup"))
        content = self.fs.read_file("/proc/self/cgroup")
        self.assertTrue(len(content) > 0)

    # ── /etc/sudoers ────────────────────────────────────

    def test_etc_sudoers(self):
        self.assertTrue(self.fs.file_exists("/etc/sudoers"))
        content = self.fs.read_file("/etc/sudoers")
        self.assertIn("root", content)
        self.assertIn("%sudo", content)

    def test_etc_sudoers_permissions(self):
        node = self.fs.get_node("/etc/sudoers")
        self.assertIsNotNone(node)
        self.assertEqual(node.permissions, "0440")


# ═══════════════════════════════════════════════════════════════
# New command tests
# ═══════════════════════════════════════════════════════════════


class TestNewCommands(unittest.TestCase):
    """Tests for seq, diff, and time commands."""

    def setUp(self):
        self.fs = _build_fs()
        self.config = _FakeConfig()
        self.router = CommandRouter(self.config)
        self.state = SessionState(
            hostname="test-host",
            username="admin",
            uid=1000,
            home="/home/admin",
            cwd="/tmp",
        )
        # Ensure /home/admin exists in the filesystem
        self.fs.create_directory("/home/admin", parents=True)

    def _run(self, command):
        """Run an async route() call synchronously."""
        loop = asyncio.get_event_loop()
        return loop.run_until_complete(self.router.route(command, self.state, self.fs, tier=2))

    # ── seq ─────────────────────────────────────────────

    def test_seq_single_arg(self):
        result = self._run("seq 5")
        self.assertEqual(result, "1\n2\n3\n4\n5")

    def test_seq_two_args(self):
        result = self._run("seq 3 7")
        self.assertEqual(result, "3\n4\n5\n6\n7")

    def test_seq_three_args(self):
        result = self._run("seq 2 2 10")
        self.assertEqual(result, "2\n4\n6\n8\n10")

    def test_seq_invalid(self):
        result = self._run("seq abc")
        self.assertIn("invalid", result.lower())

    # ── diff ────────────────────────────────────────────

    def test_diff_identical_files(self):
        self.fs.create_file("/tmp/a.txt", content="hello\nworld\n")
        self.fs.create_file("/tmp/b.txt", content="hello\nworld\n")
        result = self._run("diff /tmp/a.txt /tmp/b.txt")
        self.assertEqual(result, "")

    def test_diff_different_files(self):
        self.fs.create_file("/tmp/a.txt", content="hello\nworld\n")
        self.fs.create_file("/tmp/b.txt", content="hello\nearth\n")
        result = self._run("diff /tmp/a.txt /tmp/b.txt")
        self.assertIn("---", result)
        self.assertIn("+++", result)

    def test_diff_missing_file(self):
        self.fs.create_file("/tmp/a.txt", content="hello\n")
        result = self._run("diff /tmp/a.txt /tmp/nonexistent.txt")
        self.assertIn("No such file or directory", result)

    # ── time ────────────────────────────────────────────

    def test_time_command(self):
        result = self._run("time echo hello")
        self.assertIn("hello", result)
        self.assertIn("real", result)
        self.assertIn("user", result)
        self.assertIn("sys", result)

    def test_time_no_args(self):
        # 'time' alone: falls through to common dispatch which returns None,
        # then to tier dispatch which returns a stub. Either way it should
        # not crash and should return a string.
        result = self._run("time")
        self.assertIsInstance(result, str)


if __name__ == "__main__":
    unittest.main()
