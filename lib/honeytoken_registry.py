"""Honeytoken registry for the CI/CDecoy SSH decoy.

Tracks which filesystem paths are honeytokens (planted credential files,
keys, configs) and emits high-priority events when an attacker accesses them.
"""

import hashlib
import json
import logging
import os
import posixpath
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("cicdecoy.honeytoken")

MAX_CONTENT_SIZE = 1_048_576  # 1 MB per honeytoken entry


@dataclass
class HoneytokenEntry:
    """A single honeytoken planted in the virtual filesystem."""

    path: str
    token_name: str
    token_type: str
    content: str
    content_hash: str
    alert_on_access: bool = True
    metadata: dict = field(default_factory=dict)


class HoneytokenRegistry:
    """Manages honeytoken lifecycle: loading, seeding, and access detection."""

    def __init__(self, emitter: Any) -> None:
        self._emitter = emitter
        self._entries: dict[str, HoneytokenEntry] = {}
        self._triggered: dict[str, set[str]] = {}
        self._env_key_to_entry: dict[str, HoneytokenEntry] = {}

    def load_from_env(self) -> None:
        """Load honeytoken definitions from the HONEYTOKEN_MANIFEST env var.

        The env var should contain a JSON array of objects, each with at
        minimum ``path`` and ``content`` keys.  Optional keys:
        ``token_name``, ``token_type``, ``alert_on_access``.
        """
        self._entries.clear()
        self._triggered.clear()
        self._env_key_to_entry.clear()

        raw = os.environ.get("HONEYTOKEN_MANIFEST")
        if not raw:
            logger.info("HONEYTOKEN_MANIFEST not set; no honeytokens loaded")
            return

        try:
            items = json.loads(raw)
        except json.JSONDecodeError as exc:
            logger.error("Failed to parse HONEYTOKEN_MANIFEST: %s", exc)
            return

        for item in items:
            try:
                if not isinstance(item, dict):
                    logger.warning("Skipping non-dict honeytoken entry: %s", type(item).__name__)
                    continue

                raw_path = item.get("path")
                if not raw_path:
                    logger.warning("Skipping honeytoken entry with no path")
                    continue
                path = posixpath.normpath(raw_path)
                if not path.startswith("/") or ".." in path.split("/"):
                    logger.error("Rejecting invalid honeytoken path: %s", raw_path)
                    continue

                content = item.get("content") or ""  # handles both missing and null
                content_bytes = len(content.encode("utf-8", errors="replace"))
                if content_bytes > MAX_CONTENT_SIZE:
                    logger.error(
                        "Honeytoken content too large for %s (%d bytes, max %d)", path, content_bytes, MAX_CONTENT_SIZE
                    )
                    continue
                if not content:
                    logger.warning("Honeytoken at %s has empty content", path)
                content_hash = hashlib.sha256(content.encode()).hexdigest()

                token_name = item.get("token_name")
                if not token_name:
                    basename = posixpath.basename(path)
                    token_name = basename.replace(".", "-").replace("_", "-")
                    if token_name.startswith("-"):
                        token_name = token_name[1:]

                token_type = item.get("token_type")
                if not token_type:
                    token_type = HoneytokenRegistry._infer_token_type(path, content)

                alert_on_access = item.get("alert_on_access", True)

                entry = HoneytokenEntry(
                    path=path,
                    token_name=token_name,
                    token_type=token_type,
                    content=content,
                    content_hash=content_hash,
                    alert_on_access=alert_on_access,
                    metadata=item.get("metadata", {}),
                )
                if path in self._entries:
                    logger.warning("Duplicate honeytoken path %s; overwriting previous entry", path)
                self._entries[path] = entry
            except Exception as exc:
                logger.error("Skipping malformed honeytoken entry: %s", exc)

        self._index_env_entries()
        logger.info("Loaded %d honeytoken entries", len(self._entries))

    def _index_env_entries(self) -> None:
        """Pre-parse env-var entries and populate ``_env_key_to_entry``."""
        self._env_key_to_entry.clear()
        for entry in self._entries.values():
            if entry.token_type != "env-var":
                continue
            for key, _value in self._parse_env_content(entry.content):
                self._env_key_to_entry[key] = entry

    @staticmethod
    def _parse_env_content(content: str) -> list[tuple[str, str]]:
        """Parse KEY=value lines from .env-style content.

        Skips empty lines and comments (lines starting with ``#``).
        Returns a list of ``(key, value)`` tuples.
        """
        pairs: list[tuple[str, str]] = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            if not key:
                continue  # skip lines like "=value" with no key
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
                value = value[1:-1]
            pairs.append((key, value))
        return pairs

    def seed_into_session(self, session_state: Any) -> None:
        """Inject env-var honeytokens into a SessionState's env dict.

        For each registry entry with ``token_type == "env-var"``, parses the
        ``content`` as KEY=value lines and sets them in ``session_state.env``.
        The env var names are tracked in ``_env_key_to_entry`` for later
        access monitoring.
        """
        count = 0
        for entry in self._entries.values():
            if entry.token_type != "env-var":
                continue
            for key, value in self._parse_env_content(entry.content):
                session_state.env[key] = value
                self._env_key_to_entry[key] = entry
                count += 1
        logger.info("Seeded %d honeytoken env vars into session", count)

    def is_honeytoken_env(self, var_name: str) -> bool:
        """Check whether *var_name* is a honeytoken environment variable."""
        return var_name in self._env_key_to_entry

    def get_honeytoken_env_entry(self, var_name: str) -> HoneytokenEntry | None:
        """Return the registry entry for a honeytoken env var, or ``None``."""
        return self._env_key_to_entry.get(var_name)

    def seed_into_filesystem(self, fs: Any) -> None:
        """Plant all registered honeytokens into the virtual filesystem."""
        for entry in self._entries.values():
            if entry.token_type == "ssh-key":
                permissions = "0600"
            elif entry.token_type == "env-var":
                permissions = "0640"
            else:
                permissions = "0644"

            # Uses _add_file (not public create_file) because it auto-creates
            # parent directories via _ensure_dir — needed for deep paths like
            # /home/newuser/.aws/credentials where the parent may not exist.
            fs._add_file(entry.path, entry.content, "root", permissions)

        logger.info("Seeded %d honeytokens into virtual filesystem", len(self._entries))

    def is_honeytoken(self, path: str) -> bool:
        """Check whether *path* is a registered honeytoken."""
        return posixpath.normpath(path) in self._entries

    def get_entry(self, path: str) -> HoneytokenEntry | None:
        """Get the honeytoken entry for a path, or None."""
        return self._entries.get(posixpath.normpath(path))

    def clear_session(self, session_id: str) -> None:
        """Remove dedup state for a closed session to prevent memory growth."""
        for sessions in self._triggered.values():
            sessions.discard(session_id)
        # Prune empty sets to avoid accumulating dead entries
        empty_keys = [k for k, v in self._triggered.items() if not v]
        for k in empty_keys:
            del self._triggered[k]

    async def on_deleted(self, path: str, session_id: str, client_ip: str, username: str, command: str = "") -> None:
        """Alert when an attacker deletes a honeytoken file."""
        path = posixpath.normpath(path)
        entry = self._entries.get(path)
        if entry is None or not entry.alert_on_access:
            return

        # Deletion alerts are NOT deduplicated -- each deletion is significant
        data = {
            "token_name": entry.token_name,
            "token_type": entry.token_type,
            "access_type": "file_deleted",
            "access_vector": "shell",
            "accessed_path": path,
            "command": command,
            "content_hash": entry.content_hash,
            "client_ip": client_ip,
            "username": username,
        }

        logger.warning(
            "Honeytoken DELETED: %s by %s@%s",
            entry.token_name,
            username,
            client_ip,
        )

        await self._emitter.emit("honeytoken.deleted", session_id, data)

    async def on_access(
        self,
        path: str,
        session_id: str,
        access_vector: str,
        client_ip: str,
        username: str,
        command: str = "",
    ) -> None:
        """Trigger an alert when a honeytoken is accessed.

        Deduplicates alerts per (path, session_id) so the same session
        reading the same token only fires one event.
        """
        path = posixpath.normpath(path)
        entry = self._entries.get(path)
        if entry is None:
            return

        if not entry.alert_on_access:
            return

        triggered_sessions = self._triggered.setdefault(path, set())
        if session_id in triggered_sessions:
            return

        data = {
            "token_name": entry.token_name,
            "token_type": entry.token_type,
            "access_type": "file_read",
            "access_vector": access_vector,
            "accessed_path": path,
            "command": command,
            "content_hash": entry.content_hash,
            "client_ip": client_ip,
            "username": username,
        }

        logger.warning(
            "Honeytoken accessed: %s by %s@%s via %s",
            entry.token_name,
            username,
            client_ip,
            access_vector,
        )

        await self._emitter.emit("honeytoken.accessed", session_id, data)
        # Mark as triggered AFTER successful emit so a failed emit
        # doesn't permanently suppress the alert for this session
        triggered_sessions.add(session_id)

    @staticmethod
    def _infer_token_type(path: str, content: str) -> str:
        """Guess the token type from the file path and content."""
        path_lower = path.lower()

        # AWS credentials
        if ".aws/credentials" in path_lower or content.startswith("AKIA"):
            return "aws-key"

        # SSH private keys
        if re.search(r"id_(rsa|ed25519)", path_lower) or re.search(r"BEGIN.*PRIVATE KEY", content):
            return "ssh-key"

        # Environment / secret files
        if path_lower.endswith(".env") or "DATABASE_URL=" in content or "SECRET_KEY=" in content:
            return "env-var"

        # Kubernetes config
        if ".kube/config" in path_lower or "kubeconfig" in path_lower:
            return "kubeconfig"

        # Database credentials
        if any(kw in path_lower for kw in ("password", "credential", ".pgpass")):
            return "database-cred"

        # API tokens
        if "token" in path_lower or "api_key" in path_lower:
            return "api-token"

        return "file"

    @property
    def entries_count(self) -> int:
        """Return the number of registered honeytokens."""
        return len(self._entries)
