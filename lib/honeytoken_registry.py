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

    def load_from_env(self) -> None:
        """Load honeytoken definitions from the HONEYTOKEN_MANIFEST env var.

        The env var should contain a JSON array of objects, each with at
        minimum ``path`` and ``content`` keys.  Optional keys:
        ``token_name``, ``token_type``, ``alert_on_access``.
        """
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
            path = posixpath.normpath(item["path"])
            content = item["content"]
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
            self._entries[path] = entry

        logger.info("Loaded %d honeytoken entries", len(self._entries))

    def seed_into_filesystem(self, fs: Any) -> None:
        """Plant all registered honeytokens into the virtual filesystem."""
        for entry in self._entries.values():
            if entry.token_type == "ssh-key":
                permissions = "0600"
            elif entry.token_type == "env-var":
                permissions = "0640"
            else:
                permissions = "0644"

            fs._add_file(entry.path, entry.content, "root", permissions)

        logger.info("Seeded %d honeytokens into virtual filesystem", len(self._entries))

    def is_honeytoken(self, path: str) -> bool:
        """Check whether *path* is a registered honeytoken."""
        return posixpath.normpath(path) in self._entries

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
        triggered_sessions.add(session_id)

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
