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


if __name__ == "__main__":
    unittest.main()
