"""Tests for the HoneytokenRegistry."""

import asyncio
import hashlib
import json
import os
import sys
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

# Add lib and ssh-decoy to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "lib"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "ssh-decoy"))

from honeytoken_registry import HoneytokenEntry, HoneytokenRegistry


class TestHoneytokenEntry(unittest.TestCase):
    def test_dataclass_defaults(self):
        entry = HoneytokenEntry(
            path="/test",
            token_name="test",
            token_type="file",
            content="secret",
            content_hash="abc",
        )
        self.assertTrue(entry.alert_on_access)
        self.assertEqual(entry.metadata, {})


class TestInferTokenType(unittest.TestCase):
    def test_aws_key_by_path(self):
        self.assertEqual(
            HoneytokenRegistry._infer_token_type("/home/user/.aws/credentials", ""),
            "aws-key",
        )

    def test_aws_key_by_content(self):
        self.assertEqual(
            HoneytokenRegistry._infer_token_type("/opt/creds", "AKIAIOSFODNN7EXAMPLE"),
            "aws-key",
        )

    def test_ssh_key_by_path(self):
        self.assertEqual(
            HoneytokenRegistry._infer_token_type("/home/user/.ssh/id_rsa", ""),
            "ssh-key",
        )

    def test_ssh_key_by_content(self):
        self.assertEqual(
            HoneytokenRegistry._infer_token_type("/tmp/key", "-----BEGIN RSA PRIVATE KEY-----"),
            "ssh-key",
        )

    def test_env_var_by_path(self):
        self.assertEqual(
            HoneytokenRegistry._infer_token_type("/opt/app/.env", ""),
            "env-var",
        )

    def test_env_var_by_content(self):
        self.assertEqual(
            HoneytokenRegistry._infer_token_type("/opt/config", "DATABASE_URL=postgres://..."),
            "env-var",
        )

    def test_kubeconfig(self):
        self.assertEqual(
            HoneytokenRegistry._infer_token_type("/home/user/.kube/config", ""),
            "kubeconfig",
        )

    def test_database_cred(self):
        self.assertEqual(
            HoneytokenRegistry._infer_token_type("/home/user/.pgpass", ""),
            "database-cred",
        )

    def test_api_token(self):
        self.assertEqual(
            HoneytokenRegistry._infer_token_type("/etc/token", ""),
            "api-token",
        )

    def test_fallback(self):
        self.assertEqual(
            HoneytokenRegistry._infer_token_type("/tmp/random_file.txt", "hello world"),
            "file",
        )


class TestHoneytokenRegistryLoad(unittest.TestCase):
    def _make_registry(self):
        emitter = MagicMock()
        emitter.emit = AsyncMock()
        return HoneytokenRegistry(emitter)

    def test_load_empty_env(self):
        reg = self._make_registry()
        with patch.dict(os.environ, {}, clear=True):
            reg.load_from_env()
        self.assertEqual(reg.entries_count, 0)

    def test_load_single_token(self):
        manifest = [
            {
                "path": "/home/admin/.aws/credentials",
                "content": "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\n",
            }
        ]
        reg = self._make_registry()
        with patch.dict(os.environ, {"HONEYTOKEN_MANIFEST": json.dumps(manifest)}):
            reg.load_from_env()
        self.assertEqual(reg.entries_count, 1)
        self.assertTrue(reg.is_honeytoken("/home/admin/.aws/credentials"))
        self.assertFalse(reg.is_honeytoken("/home/admin/.bashrc"))

    def test_load_derives_token_name(self):
        manifest = [{"path": "/opt/.env", "content": "SECRET=x"}]
        reg = self._make_registry()
        with patch.dict(os.environ, {"HONEYTOKEN_MANIFEST": json.dumps(manifest)}):
            reg.load_from_env()
        entry = reg._entries["/opt/.env"]
        self.assertEqual(entry.token_name, "env")

    def test_load_uses_explicit_token_name(self):
        manifest = [
            {
                "path": "/opt/.env",
                "content": "SECRET=x",
                "token_name": "prod-env-canary",
            }
        ]
        reg = self._make_registry()
        with patch.dict(os.environ, {"HONEYTOKEN_MANIFEST": json.dumps(manifest)}):
            reg.load_from_env()
        entry = reg._entries["/opt/.env"]
        self.assertEqual(entry.token_name, "prod-env-canary")

    def test_load_infers_type(self):
        manifest = [{"path": "/home/user/.ssh/id_rsa", "content": "-----BEGIN RSA PRIVATE KEY-----"}]
        reg = self._make_registry()
        with patch.dict(os.environ, {"HONEYTOKEN_MANIFEST": json.dumps(manifest)}):
            reg.load_from_env()
        entry = reg._entries["/home/user/.ssh/id_rsa"]
        self.assertEqual(entry.token_type, "ssh-key")

    def test_load_uses_explicit_type(self):
        manifest = [{"path": "/tmp/file", "content": "x", "token_type": "database-cred"}]
        reg = self._make_registry()
        with patch.dict(os.environ, {"HONEYTOKEN_MANIFEST": json.dumps(manifest)}):
            reg.load_from_env()
        entry = reg._entries["/tmp/file"]
        self.assertEqual(entry.token_type, "database-cred")

    def test_load_computes_hash(self):
        content = "my-secret-content"
        manifest = [{"path": "/tmp/file", "content": content}]
        reg = self._make_registry()
        with patch.dict(os.environ, {"HONEYTOKEN_MANIFEST": json.dumps(manifest)}):
            reg.load_from_env()
        expected_hash = hashlib.sha256(content.encode()).hexdigest()
        entry = reg._entries["/tmp/file"]
        self.assertEqual(entry.content_hash, expected_hash)

    def test_load_invalid_json(self):
        reg = self._make_registry()
        with patch.dict(os.environ, {"HONEYTOKEN_MANIFEST": "not-json"}):
            reg.load_from_env()  # Should not raise
        self.assertEqual(reg.entries_count, 0)

    def test_load_multiple_tokens(self):
        manifest = [
            {"path": "/opt/.env", "content": "DB=x"},
            {"path": "/home/user/.ssh/id_rsa", "content": "key"},
            {"path": "/home/user/.aws/credentials", "content": "AKIA..."},
        ]
        reg = self._make_registry()
        with patch.dict(os.environ, {"HONEYTOKEN_MANIFEST": json.dumps(manifest)}):
            reg.load_from_env()
        self.assertEqual(reg.entries_count, 3)

    def test_load_null_content(self):
        """Manifest entry with "content": null should not crash load_from_env."""
        manifest = [
            {"path": "/opt/secret.key", "content": None},
            {"path": "/opt/.env", "content": "VALID=yes"},
        ]
        reg = self._make_registry()
        with patch.dict(os.environ, {"HONEYTOKEN_MANIFEST": json.dumps(manifest)}):
            reg.load_from_env()  # Should not raise
        # At minimum the valid entry should still be loaded
        self.assertTrue(reg.is_honeytoken("/opt/.env"))

    def test_load_path_with_trailing_slash(self):
        """Path with trailing slash should be normalized (slash removed)."""
        manifest = [{"path": "/home/admin/.aws/credentials/", "content": "AKIA..."}]
        reg = self._make_registry()
        with patch.dict(os.environ, {"HONEYTOKEN_MANIFEST": json.dumps(manifest)}):
            reg.load_from_env()
        # posixpath.normpath strips trailing slash
        self.assertTrue(reg.is_honeytoken("/home/admin/.aws/credentials"))
        self.assertEqual(reg.entries_count, 1)

    def test_load_relative_path_rejected(self):
        """Path without leading / should be rejected."""
        manifest = [{"path": "tmp/secret.key", "content": "secret"}]
        reg = self._make_registry()
        with patch.dict(os.environ, {"HONEYTOKEN_MANIFEST": json.dumps(manifest)}):
            reg.load_from_env()
        self.assertEqual(reg.entries_count, 0)

    def test_load_dotdot_path_rejected(self):
        """Path containing .. traversal should be normalized by posixpath.normpath.

        posixpath.normpath resolves '..' so /home/../etc/shadow becomes /etc/shadow.
        The resolved path is absolute and has no '..' components, so it is accepted
        at the normalized location.
        """
        manifest = [{"path": "/home/../etc/shadow", "content": "root:x:..."}]
        reg = self._make_registry()
        with patch.dict(os.environ, {"HONEYTOKEN_MANIFEST": json.dumps(manifest)}):
            reg.load_from_env()
        # normpath resolves /home/../etc/shadow to /etc/shadow and accepts it
        self.assertTrue(reg.is_honeytoken("/etc/shadow"))

    def test_load_very_large_content_rejected(self):
        """Content over 1MB should be rejected."""
        manifest = [{"path": "/opt/large.key", "content": "x" * 1_048_577}]
        reg = self._make_registry()
        with patch.dict(os.environ, {"HONEYTOKEN_MANIFEST": json.dumps(manifest)}):
            reg.load_from_env()
        self.assertEqual(reg.entries_count, 0)
        self.assertFalse(reg.is_honeytoken("/opt/large.key"))

    def test_load_called_twice_clears_state(self):
        """Calling load_from_env twice should clear previous state."""
        manifest1 = [{"path": "/opt/first.key", "content": "first"}]
        manifest2 = [{"path": "/opt/second.key", "content": "second"}]
        reg = self._make_registry()
        with patch.dict(os.environ, {"HONEYTOKEN_MANIFEST": json.dumps(manifest1)}):
            reg.load_from_env()
        self.assertTrue(reg.is_honeytoken("/opt/first.key"))
        with patch.dict(os.environ, {"HONEYTOKEN_MANIFEST": json.dumps(manifest2)}):
            reg.load_from_env()
        # First manifest's entries should be gone
        self.assertFalse(reg.is_honeytoken("/opt/first.key"))
        # Second manifest's entries should be present
        self.assertTrue(reg.is_honeytoken("/opt/second.key"))
        self.assertEqual(reg.entries_count, 1)

    def test_load_entry_with_missing_path(self):
        """Manifest entry with no 'path' key should not crash load_from_env."""
        manifest = [
            {"content": "secret"},
            {"path": "/opt/.env", "content": "VALID=yes"},
        ]
        reg = self._make_registry()
        with patch.dict(os.environ, {"HONEYTOKEN_MANIFEST": json.dumps(manifest)}):
            reg.load_from_env()  # Should not raise
        # The valid entry should still load
        self.assertTrue(reg.is_honeytoken("/opt/.env"))


class TestHoneytokenRegistrySeed(unittest.TestCase):
    def test_seed_calls_add_file(self):
        emitter = MagicMock()
        reg = HoneytokenRegistry(emitter)
        manifest = [
            {"path": "/opt/.env", "content": "SECRET=x"},
            {"path": "/home/user/.ssh/id_rsa", "content": "key-data"},
        ]
        with patch.dict(os.environ, {"HONEYTOKEN_MANIFEST": json.dumps(manifest)}):
            reg.load_from_env()

        fs = MagicMock()
        reg.seed_into_filesystem(fs)

        self.assertEqual(fs._add_file.call_count, 2)
        # Check permissions: SSH key should be 0600, env should be 0640
        calls = {c[0][0]: c[0][3] for c in fs._add_file.call_args_list}
        self.assertEqual(calls["/opt/.env"], "0640")
        self.assertEqual(calls["/home/user/.ssh/id_rsa"], "0600")


class TestHoneytokenRegistryAccess(unittest.TestCase):
    def _make_loaded_registry(self):
        emitter = MagicMock()
        emitter.emit = AsyncMock()
        reg = HoneytokenRegistry(emitter)
        manifest = [{"path": "/opt/.env", "content": "SECRET=x"}]
        with patch.dict(os.environ, {"HONEYTOKEN_MANIFEST": json.dumps(manifest)}):
            reg.load_from_env()
        return reg, emitter

    def test_access_fires_event(self):
        reg, emitter = self._make_loaded_registry()
        asyncio.get_event_loop().run_until_complete(
            reg.on_access("/opt/.env", "session-1", "shell", "10.0.0.1", "admin", "cat /opt/.env")
        )
        emitter.emit.assert_called_once()
        args = emitter.emit.call_args
        self.assertEqual(args[0][0], "honeytoken.accessed")
        self.assertEqual(args[0][1], "session-1")
        data = args[0][2]
        self.assertEqual(data["token_type"], "env-var")
        self.assertEqual(data["access_vector"], "shell")
        self.assertEqual(data["accessed_path"], "/opt/.env")

    def test_access_dedup_same_session(self):
        reg, emitter = self._make_loaded_registry()
        loop = asyncio.get_event_loop()
        loop.run_until_complete(reg.on_access("/opt/.env", "session-1", "shell", "10.0.0.1", "admin"))
        loop.run_until_complete(reg.on_access("/opt/.env", "session-1", "shell", "10.0.0.1", "admin"))
        # Should only fire once
        self.assertEqual(emitter.emit.call_count, 1)

    def test_access_different_sessions(self):
        reg, emitter = self._make_loaded_registry()
        loop = asyncio.get_event_loop()
        loop.run_until_complete(reg.on_access("/opt/.env", "session-1", "shell", "10.0.0.1", "admin"))
        loop.run_until_complete(reg.on_access("/opt/.env", "session-2", "sftp", "10.0.0.2", "deploy"))
        # Should fire for both sessions
        self.assertEqual(emitter.emit.call_count, 2)

    def test_access_non_honeytoken_ignored(self):
        reg, emitter = self._make_loaded_registry()
        asyncio.get_event_loop().run_until_complete(
            reg.on_access("/etc/passwd", "session-1", "shell", "10.0.0.1", "admin")
        )
        emitter.emit.assert_not_called()

    def test_access_alert_disabled(self):
        emitter = MagicMock()
        emitter.emit = AsyncMock()
        reg = HoneytokenRegistry(emitter)
        manifest = [{"path": "/opt/.env", "content": "x", "alert_on_access": False}]
        with patch.dict(os.environ, {"HONEYTOKEN_MANIFEST": json.dumps(manifest)}):
            reg.load_from_env()
        asyncio.get_event_loop().run_until_complete(
            reg.on_access("/opt/.env", "session-1", "shell", "10.0.0.1", "admin")
        )
        emitter.emit.assert_not_called()

    def test_path_normalization(self):
        reg, emitter = self._make_loaded_registry()
        asyncio.get_event_loop().run_until_complete(
            reg.on_access("/opt/./subdir/../.env", "session-1", "shell", "10.0.0.1", "admin")
        )
        emitter.emit.assert_called_once()

    def test_on_access_path_with_trailing_slash(self):
        """Accessing /opt/.env/ should still match /opt/.env via normpath."""
        reg, emitter = self._make_loaded_registry()
        asyncio.get_event_loop().run_until_complete(
            reg.on_access("/opt/.env/", "session-1", "shell", "10.0.0.1", "admin")
        )
        emitter.emit.assert_called_once()

    def test_clear_session_prunes_empty_sets(self):
        """After clearing the only session from a path, that path should be removed from _triggered."""
        reg, emitter = self._make_loaded_registry()
        loop = asyncio.get_event_loop()
        loop.run_until_complete(reg.on_access("/opt/.env", "session-1", "shell", "10.0.0.1", "admin"))
        # Path should be in _triggered
        self.assertIn("/opt/.env", reg._triggered)
        self.assertIn("session-1", reg._triggered["/opt/.env"])
        # Clear the only session
        reg.clear_session("session-1")
        # Path key should be pruned since the set is now empty
        self.assertNotIn("/opt/.env", reg._triggered)

    def test_clear_session_nonexistent_session(self):
        """Clearing a session_id that was never triggered should not crash."""
        reg, emitter = self._make_loaded_registry()
        # No access has been triggered, so no sessions exist
        reg.clear_session("nonexistent-session")  # Should not raise


class TestCowFilesystemCallback(unittest.TestCase):
    def test_read_file_fires_callback(self):
        """Verify the COW filesystem access callback fires on read_file."""
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "ssh-decoy"))
        from cow_filesystem import SessionFilesystem
        from filesystem import VirtualFilesystem

        fs = VirtualFilesystem()
        fs._add_file("/test/file.txt", "content", "root", "0644")

        session_fs = SessionFilesystem(fs)
        accessed_paths = []
        session_fs.set_access_callback(lambda path: accessed_paths.append(path))

        result = session_fs.read_file("/test/file.txt")
        self.assertEqual(result, "content")
        self.assertEqual(accessed_paths, ["/test/file.txt"])

    def test_callback_not_fired_for_missing_file(self):
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "ssh-decoy"))
        from cow_filesystem import SessionFilesystem
        from filesystem import VirtualFilesystem

        fs = VirtualFilesystem()
        session_fs = SessionFilesystem(fs)
        accessed_paths = []
        session_fs.set_access_callback(lambda path: accessed_paths.append(path))

        result = session_fs.read_file("/nonexistent")
        self.assertIsNone(result)
        self.assertEqual(accessed_paths, [])

    def test_no_callback_by_default(self):
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "ssh-decoy"))
        from cow_filesystem import SessionFilesystem
        from filesystem import VirtualFilesystem

        fs = VirtualFilesystem()
        fs._add_file("/test/file.txt", "content", "root", "0644")
        session_fs = SessionFilesystem(fs)
        # Should not raise even without callback set
        result = session_fs.read_file("/test/file.txt")
        self.assertEqual(result, "content")


class TestEnvVarHoneytokens(unittest.TestCase):
    """Tests for environment variable honeytoken support."""

    def _make_env_registry(self):
        emitter = MagicMock()
        emitter.emit = AsyncMock()
        reg = HoneytokenRegistry(emitter)
        manifest = [
            {
                "path": "/proc/self/environ",
                "content": "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI\nDATABASE_URL=postgresql://admin:secret@db:5432/app",
                "token_type": "env-var",
                "token_name": "prod-env-creds",
            }
        ]
        with patch.dict(os.environ, {"HONEYTOKEN_MANIFEST": json.dumps(manifest)}):
            reg.load_from_env()
        return reg, emitter

    def test_env_keys_indexed(self):
        reg, _ = self._make_env_registry()
        self.assertTrue(reg.is_honeytoken_env("AWS_ACCESS_KEY_ID"))
        self.assertTrue(reg.is_honeytoken_env("AWS_SECRET_ACCESS_KEY"))
        self.assertTrue(reg.is_honeytoken_env("DATABASE_URL"))
        self.assertFalse(reg.is_honeytoken_env("HOME"))
        self.assertFalse(reg.is_honeytoken_env("PATH"))

    def test_get_env_entry(self):
        reg, _ = self._make_env_registry()
        entry = reg.get_honeytoken_env_entry("AWS_ACCESS_KEY_ID")
        self.assertIsNotNone(entry)
        self.assertEqual(entry.token_name, "prod-env-creds")
        self.assertEqual(entry.token_type, "env-var")

    def test_get_env_entry_nonexistent(self):
        reg, _ = self._make_env_registry()
        entry = reg.get_honeytoken_env_entry("NONEXISTENT")
        self.assertIsNone(entry)

    def test_seed_into_session(self):
        reg, _ = self._make_env_registry()
        session = MagicMock()
        session.env = {"HOME": "/home/admin", "USER": "admin"}
        reg.seed_into_session(session)
        self.assertEqual(session.env["AWS_ACCESS_KEY_ID"], "AKIAIOSFODNN7EXAMPLE")
        self.assertEqual(session.env["AWS_SECRET_ACCESS_KEY"], "wJalrXUtnFEMI")
        self.assertEqual(session.env["DATABASE_URL"], "postgresql://admin:secret@db:5432/app")
        # Original vars preserved
        self.assertEqual(session.env["HOME"], "/home/admin")

    def test_seed_skips_comments_and_blanks(self):
        emitter = MagicMock()
        emitter.emit = AsyncMock()
        reg = HoneytokenRegistry(emitter)
        manifest = [
            {
                "path": "/env",
                "content": "# comment\n\nVALID_KEY=value\n  \n# another comment",
                "token_type": "env-var",
            }
        ]
        with patch.dict(os.environ, {"HONEYTOKEN_MANIFEST": json.dumps(manifest)}):
            reg.load_from_env()
        session = MagicMock()
        session.env = {}
        reg.seed_into_session(session)
        self.assertEqual(session.env["VALID_KEY"], "value")
        self.assertEqual(len(session.env), 1)

    def test_env_access_fires_event(self):
        reg, emitter = self._make_env_registry()
        asyncio.get_event_loop().run_until_complete(
            reg.on_access("/proc/self/environ", "session-1", "shell", "10.0.0.1", "admin", "env")
        )
        emitter.emit.assert_called_once()
        data = emitter.emit.call_args[0][2]
        self.assertEqual(data["token_name"], "prod-env-creds")
        self.assertEqual(data["access_vector"], "shell")

    def test_content_with_equals_in_value(self):
        emitter = MagicMock()
        emitter.emit = AsyncMock()
        reg = HoneytokenRegistry(emitter)
        manifest = [
            {
                "path": "/env",
                "content": "DB_URL=postgresql://user:p@ss=word@host:5432/db",
                "token_type": "env-var",
            }
        ]
        with patch.dict(os.environ, {"HONEYTOKEN_MANIFEST": json.dumps(manifest)}):
            reg.load_from_env()
        session = MagicMock()
        session.env = {}
        reg.seed_into_session(session)
        self.assertEqual(session.env["DB_URL"], "postgresql://user:p@ss=word@host:5432/db")

    def test_non_env_var_type_not_indexed(self):
        emitter = MagicMock()
        emitter.emit = AsyncMock()
        reg = HoneytokenRegistry(emitter)
        manifest = [{"path": "/home/user/.ssh/id_rsa", "content": "key-data", "token_type": "ssh-key"}]
        with patch.dict(os.environ, {"HONEYTOKEN_MANIFEST": json.dumps(manifest)}):
            reg.load_from_env()
        self.assertFalse(reg.is_honeytoken_env("key-data"))
        self.assertEqual(len(reg._env_key_to_entry), 0)

    def test_parse_env_no_equals_line_skipped(self):
        """Lines without '=' should be skipped entirely."""
        emitter = MagicMock()
        emitter.emit = AsyncMock()
        reg = HoneytokenRegistry(emitter)
        manifest = [
            {
                "path": "/env",
                "content": "NOEQUALS\nVALID=value",
                "token_type": "env-var",
            }
        ]
        with patch.dict(os.environ, {"HONEYTOKEN_MANIFEST": json.dumps(manifest)}):
            reg.load_from_env()
        self.assertFalse(reg.is_honeytoken_env("NOEQUALS"))
        self.assertTrue(reg.is_honeytoken_env("VALID"))

    def test_parse_env_empty_key_skipped(self):
        """Content '=value' (empty key) should be skipped."""
        pairs = HoneytokenRegistry._parse_env_content("=value")
        self.assertEqual(len(pairs), 0)  # empty key is skipped

    def test_parse_env_empty_value_kept(self):
        """Content 'KEY=' should produce KEY with empty string value."""
        pairs = HoneytokenRegistry._parse_env_content("KEY=")
        self.assertEqual(len(pairs), 1)
        self.assertEqual(pairs[0], ("KEY", ""))

    def test_parse_env_double_quotes_stripped(self):
        """Content 'KEY=\"quoted\"' should strip matching double quotes."""
        pairs = HoneytokenRegistry._parse_env_content('KEY="quoted"')
        self.assertEqual(len(pairs), 1)
        self.assertEqual(pairs[0], ("KEY", "quoted"))

    def test_parse_env_single_quotes_stripped(self):
        """Content \"KEY='quoted'\" should strip matching single quotes."""
        pairs = HoneytokenRegistry._parse_env_content("KEY='quoted'")
        self.assertEqual(len(pairs), 1)
        self.assertEqual(pairs[0], ("KEY", "quoted"))

    def test_parse_env_mismatched_quotes_kept(self):
        """Mismatched quotes should be kept as-is."""
        pairs = HoneytokenRegistry._parse_env_content("KEY=\"mixed'")
        self.assertEqual(len(pairs), 1)
        # Mismatched quotes: first char '"' != last char "'" so no stripping
        self.assertEqual(pairs[0], ("KEY", "\"mixed'"))

    def test_seed_into_session_no_env_type_noop(self):
        """Registry with only file-type tokens should not add any env vars."""
        emitter = MagicMock()
        emitter.emit = AsyncMock()
        reg = HoneytokenRegistry(emitter)
        manifest = [
            {"path": "/home/user/.ssh/id_rsa", "content": "key-data", "token_type": "ssh-key"},
            {"path": "/tmp/secret.txt", "content": "secret", "token_type": "file"},
        ]
        with patch.dict(os.environ, {"HONEYTOKEN_MANIFEST": json.dumps(manifest)}):
            reg.load_from_env()
        session = MagicMock()
        session.env = {"HOME": "/root"}
        reg.seed_into_session(session)
        # No env-var type entries, so env should be unchanged
        self.assertEqual(session.env, {"HOME": "/root"})

    def test_get_honeytoken_env_entry_before_load(self):
        """Calling get_honeytoken_env_entry before load_from_env returns None."""
        emitter = MagicMock()
        emitter.emit = AsyncMock()
        reg = HoneytokenRegistry(emitter)
        result = reg.get_honeytoken_env_entry("AWS_ACCESS_KEY_ID")
        self.assertIsNone(result)


class TestHoneytokenDeletion(unittest.TestCase):
    """Tests for on_deleted honeytoken events."""

    def _make_loaded_registry(self):
        emitter = MagicMock()
        emitter.emit = AsyncMock()
        reg = HoneytokenRegistry(emitter)
        manifest = [{"path": "/opt/.env", "content": "SECRET=x"}]
        with patch.dict(os.environ, {"HONEYTOKEN_MANIFEST": json.dumps(manifest)}):
            reg.load_from_env()
        return reg, emitter

    def test_on_deleted_fires_event(self):
        reg, emitter = self._make_loaded_registry()
        asyncio.get_event_loop().run_until_complete(
            reg.on_deleted("/opt/.env", "session-1", "10.0.0.1", "admin", "rm /opt/.env")
        )
        emitter.emit.assert_called_once()
        args = emitter.emit.call_args
        self.assertEqual(args[0][0], "honeytoken.deleted")
        self.assertEqual(args[0][1], "session-1")
        data = args[0][2]
        self.assertEqual(data["access_type"], "file_deleted")
        self.assertEqual(data["accessed_path"], "/opt/.env")

    def test_on_deleted_not_deduplicated(self):
        reg, emitter = self._make_loaded_registry()
        loop = asyncio.get_event_loop()
        loop.run_until_complete(reg.on_deleted("/opt/.env", "session-1", "10.0.0.1", "admin", "rm /opt/.env"))
        loop.run_until_complete(reg.on_deleted("/opt/.env", "session-1", "10.0.0.1", "admin", "rm /opt/.env"))
        # Deletion events are NOT deduplicated, unlike on_access
        self.assertEqual(emitter.emit.call_count, 2)

    def test_on_deleted_non_honeytoken_ignored(self):
        reg, emitter = self._make_loaded_registry()
        asyncio.get_event_loop().run_until_complete(
            reg.on_deleted("/etc/passwd", "session-1", "10.0.0.1", "admin", "rm /etc/passwd")
        )
        emitter.emit.assert_not_called()

    def test_on_deleted_alert_disabled_ignored(self):
        emitter = MagicMock()
        emitter.emit = AsyncMock()
        reg = HoneytokenRegistry(emitter)
        manifest = [{"path": "/opt/.env", "content": "x", "alert_on_access": False}]
        with patch.dict(os.environ, {"HONEYTOKEN_MANIFEST": json.dumps(manifest)}):
            reg.load_from_env()
        asyncio.get_event_loop().run_until_complete(
            reg.on_deleted("/opt/.env", "session-1", "10.0.0.1", "admin", "rm /opt/.env")
        )
        emitter.emit.assert_not_called()


class TestCowFilesystemDeleteCallback(unittest.TestCase):
    """Tests for the COW filesystem delete callback mechanism."""

    def test_delete_callback_fires_on_remove(self):
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "ssh-decoy"))
        from cow_filesystem import SessionFilesystem
        from filesystem import VirtualFilesystem

        fs = VirtualFilesystem()
        fs._add_file("/test/file.txt", "content", "root", "0644")

        session_fs = SessionFilesystem(fs)
        deleted_paths = []
        session_fs.set_delete_callback(lambda path: deleted_paths.append(path))

        result = session_fs.remove_file("/test/file.txt")
        self.assertTrue(result)
        self.assertEqual(deleted_paths, ["/test/file.txt"])

    def test_delete_callback_not_fired_for_nonexistent(self):
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "ssh-decoy"))
        from cow_filesystem import SessionFilesystem
        from filesystem import VirtualFilesystem

        fs = VirtualFilesystem()
        session_fs = SessionFilesystem(fs)
        deleted_paths = []
        session_fs.set_delete_callback(lambda path: deleted_paths.append(path))

        result = session_fs.remove_file("/nonexistent/file.txt")
        self.assertFalse(result)
        self.assertEqual(deleted_paths, [])


if __name__ == "__main__":
    unittest.main()
