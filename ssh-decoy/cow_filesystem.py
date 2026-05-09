"""
CI/CDecoy — Copy-on-Write Session Filesystem

Wraps the shared base VirtualFilesystem with a per-session overlay.
All mutations go to the overlay; reads fall through to the base
unless the path has been overwritten or deleted in this session.

On session teardown, the overlay is serialized as a forensic delta
capturing exactly what the attacker created, modified, and deleted.

Design:
    base (VirtualFilesystem)   ← shared, immutable after boot
          │
    ┌─────┴──────┐
    │ SessionFS  │  ← overlay tree + tombstone set, per session
    └────────────┘

The SessionFilesystem exposes the exact same public API as
VirtualFilesystem so it's a drop-in replacement everywhere the
router and session interact with the filesystem.
"""

import logging
import os
from datetime import datetime

from filesystem import FSNode, VirtualFilesystem, _perm_bits

logger = logging.getLogger("cicdecoy.cow")

MAX_FILES_PER_SESSION = 10_000  # Prevent memory exhaustion from mass file creation


class SessionFilesystem:
    """
    Per-session copy-on-write layer over a shared VirtualFilesystem.

    Invariants:
      - self._base is NEVER mutated.
      - self._overlay is a parallel sparse tree: only paths that this
        session has created or modified exist here.
      - self._tombstones tracks deleted paths.  A read hitting a
        tombstone returns None even if the base has content there.
      - self._mutations is an ordered log of every write operation
        for forensic replay.

    # NOTE: Symlinks not supported — ln -s operations are silently ignored.
    """

    def __init__(self, base: VirtualFilesystem):
        self._base = base
        # Overlay root — only populated on writes
        self._overlay = FSNode(
            name="/", path="/", is_dir=True, permissions="0755",
            modified=datetime.utcnow().strftime("%b %d %H:%M"),
        )
        self._tombstones: set[str] = set()      # Deleted paths
        self._mutations: list[dict] = []         # Ordered write log
        self._overlay_count: int = 0             # Track total overlay nodes

    # ── Public API (mirrors VirtualFilesystem) ───────

    def get_node(self, path: str) -> FSNode | None:
        path = _normalize(path)
        if self._is_tombstoned(path):
            return None
        # Overlay wins
        node = self._resolve_overlay(path)
        if node is not None:
            # If it's a directory, return a merged view
            if node.is_dir:
                return self._merged_dir_node(path, node)
            return node
        # Fall through to base
        base_node = self._base.get_node(path)
        if base_node is not None and base_node.is_dir:
            return self._merged_dir_node(path, None)
        return base_node

    def is_directory(self, path: str) -> bool:
        node = self.get_node(path)
        return node is not None and node.is_dir

    def is_file(self, path: str) -> bool:
        node = self.get_node(path)
        return node is not None and not node.is_dir

    def file_exists(self, path: str) -> bool:
        return self.get_node(path) is not None

    def read_file(self, path: str) -> str | None:
        path = _normalize(path)
        if self._is_tombstoned(path):
            return None
        # Check overlay first
        node = self._resolve_overlay(path)
        if node is not None:
            if node.is_dir:
                return None
            return node.content or ""
        # Fall through to base
        return self._base.read_file(path)

    def list_directory(self, path: str, long_format: bool = False,
                       show_hidden: bool = False) -> str:
        path = _normalize(path)
        node = self.get_node(path)
        if node is None:
            return f"ls: cannot access '{path}': No such file or directory"
        if not node.is_dir:
            return self._format_long(node) if long_format else node.name

        # node.children is the merged view from get_node → _merged_dir_node
        entries = sorted(node.children.values(), key=lambda n: n.name)
        if not show_hidden:
            entries = [e for e in entries if not e.name.startswith(".")]

        if not entries:
            return ""

        if long_format:
            lines = [f"total {len(entries) * 4}"]
            for e in entries:
                lines.append(self._format_long(e))
            return "\n".join(lines)
        return "  ".join(e.name for e in entries)

    def create_file(self, path: str, content: str = "",
                    owner: str = "root", permissions: str = "0644") -> bool:
        path = _normalize(path)

        # Enforce per-session file quota
        if self._overlay_count >= MAX_FILES_PER_SESSION:
            logger.warning("Session file limit reached (%d)", MAX_FILES_PER_SESSION)
            return False

        parent_path = os.path.dirname(path)
        filename = os.path.basename(path)

        # Ensure parent exists in overlay
        parent = self._ensure_overlay_dir(parent_path)
        if parent is None:
            return False

        node = FSNode(
            name=filename, path=path, content=content,
            owner=owner, permissions=permissions,
            modified=datetime.utcnow().strftime("%b %d %H:%M"),
        )
        parent.children[filename] = node
        self._overlay_count += 1

        # Un-tombstone if previously deleted
        self._tombstones.discard(path)

        self._mutations.append({
            "op": "create_file",
            "path": path,
            "owner": owner,
            "size": node.size,
            "time": datetime.utcnow().isoformat(),
        })
        return True

    def append_file(self, path: str, content: str) -> bool:
        path = _normalize(path)
        # Try overlay first
        node = self._resolve_overlay(path)
        # If file is not yet in overlay, appending will create a new overlay
        # node — enforce the per-session file quota before that happens.
        if node is None and self._overlay_count >= MAX_FILES_PER_SESSION:
            logger.warning("Session file limit reached (%d)", MAX_FILES_PER_SESSION)
            return False
        if node and not node.is_dir:
            node.content = (node.content or "") + content
            node.size = len(node.content.encode("utf-8", errors="replace"))
            node.modified = datetime.utcnow().strftime("%b %d %H:%M")
            self._mutations.append({
                "op": "append_file", "path": path,
                "appended_bytes": len(content),
                "time": datetime.utcnow().isoformat(),
            })
            return True

        # If it exists in base and isn't tombstoned, copy-up then append
        if not self._is_tombstoned(path):
            base_node = self._base.get_node(path)
            if base_node and not base_node.is_dir:
                existing = base_node.content or ""
                return self.create_file(
                    path, existing + content,
                    owner=base_node.owner, permissions=base_node.permissions,
                )

        # Doesn't exist anywhere — create
        return self.create_file(path, content)

    def create_directory(self, path: str, owner: str = "root",
                         parents: bool = False) -> bool:
        path = _normalize(path)

        # Enforce per-session file quota
        if self._overlay_count >= MAX_FILES_PER_SESSION:
            logger.warning("Session file limit reached (%d)", MAX_FILES_PER_SESSION)
            return False

        if parents:
            self._ensure_overlay_dir(path, owner=owner)
            self._tombstones.discard(path)
            self._mutations.append({
                "op": "create_dir", "path": path, "parents": True,
                "time": datetime.utcnow().isoformat(),
            })
            return True

        parent_path = os.path.dirname(path)
        dirname = os.path.basename(path)

        # Check if already exists (in either layer)
        if self.file_exists(path):
            return False

        parent = self._ensure_overlay_dir(parent_path)
        if parent is None:
            return False

        parent.children[dirname] = FSNode(
            name=dirname, path=path, is_dir=True, owner=owner,
            permissions="0755",
            modified=datetime.utcnow().strftime("%b %d %H:%M"),
        )
        self._overlay_count += 1
        self._tombstones.discard(path)
        self._mutations.append({
            "op": "create_dir", "path": path,
            "time": datetime.utcnow().isoformat(),
        })
        return True

    def remove_file(self, path: str) -> bool:
        path = _normalize(path)
        existed = False

        # Remove from overlay if present
        parent_path = os.path.dirname(path)
        filename = os.path.basename(path)
        overlay_parent = self._resolve_overlay(parent_path)
        if overlay_parent and overlay_parent.is_dir:
            if filename in overlay_parent.children:
                node = overlay_parent.children[filename]
                if not node.is_dir:
                    del overlay_parent.children[filename]
                    existed = True

        # Check base — if it existed there, tombstone it
        if not existed:
            base_node = self._base.get_node(path)
            if base_node and not base_node.is_dir and not self._is_tombstoned(path):
                existed = True

        if existed:
            self._tombstones.add(path)
            self._mutations.append({
                "op": "delete_file", "path": path,
                "time": datetime.utcnow().isoformat(),
            })
            return True
        return False

    def remove_directory(self, path: str, recursive: bool = False) -> bool:
        path = _normalize(path)
        if path == "/":
            return False

        node = self.get_node(path)
        if node is None or not node.is_dir:
            return False
        if not recursive and node.children:
            return False

        # Tombstone recursively
        if recursive:
            self._tombstone_recursive(path, node)
        else:
            self._tombstones.add(path)

        # Remove from overlay
        parent_path = os.path.dirname(path)
        dirname = os.path.basename(path)
        overlay_parent = self._resolve_overlay(parent_path)
        if overlay_parent and dirname in overlay_parent.children:
            del overlay_parent.children[dirname]

        self._mutations.append({
            "op": "delete_dir", "path": path, "recursive": recursive,
            "time": datetime.utcnow().isoformat(),
        })
        return True

    def chmod(self, path: str, permissions: str) -> bool:
        path = _normalize(path)
        node = self._copy_up(path)
        if node:
            node.permissions = permissions
            self._mutations.append({
                "op": "chmod", "path": path, "permissions": permissions,
                "time": datetime.utcnow().isoformat(),
            })
            return True
        return False

    def chown(self, path: str, owner: str,
              group: str | None = None) -> bool:
        path = _normalize(path)
        node = self._copy_up(path)
        if node:
            node.owner = owner
            if group:
                node.group = group
            self._mutations.append({
                "op": "chown", "path": path,
                "owner": owner, "group": group,
                "time": datetime.utcnow().isoformat(),
            })
            return True
        return False

    def get_context_snapshot(self, cwd: str) -> dict:
        """Snapshot for LLM context — uses merged view."""
        cwd = _normalize(cwd)
        snapshot = {"cwd": cwd, "cwd_contents": [], "parent_contents": []}
        cwd_node = self.get_node(cwd)
        if cwd_node and cwd_node.is_dir:
            for name, child in cwd_node.children.items():
                snapshot["cwd_contents"].append({
                    "name": name,
                    "type": "dir" if child.is_dir else "file",
                    "size": child.size,
                    "owner": child.owner,
                })
        return snapshot

    def get_profile_data(self) -> dict:
        """Delegate to base — profile data is immutable."""
        return self._base.get_profile_data()

    # ── Delta Export (forensics) ─────────────────────

    def get_delta(self) -> dict:
        """
        Serialize the session's filesystem mutations for CTI.

        Returns a dict suitable for JSON serialization and NATS emission.
        Captures:
          - files_created:  [{path, content, owner, permissions, size}]
          - files_modified: [{path, content, owner, permissions, size}]
          - files_deleted:  [path, ...]
          - dirs_created:   [path, ...]
          - dirs_deleted:   [path, ...]
          - mutation_log:   ordered list of all operations
        """
        files_created = []
        files_modified = []
        dirs_created = []

        self._collect_overlay_nodes(self._overlay, "/",
                                     files_created, files_modified,
                                     dirs_created)

        return {
            "files_created": files_created,
            "files_modified": files_modified,
            "dirs_created": dirs_created,
            "paths_deleted": sorted(self._tombstones),
            "mutation_count": len(self._mutations),
            "mutation_log": self._mutations,
        }

    def _collect_overlay_nodes(self, node: FSNode, path: str,
                                files_created: list,
                                files_modified: list,
                                dirs_created: list):
        """Walk the overlay tree and categorize nodes."""
        for name, child in node.children.items():
            child_path = f"{path}/{name}" if path != "/" else f"/{name}"
            child_path = _normalize(child_path)

            if child.is_dir:
                # Check if this dir existed in base
                base_node = self._base.get_node(child_path)
                if base_node is None:
                    dirs_created.append(child_path)
                # Recurse
                self._collect_overlay_nodes(
                    child, child_path,
                    files_created, files_modified, dirs_created,
                )
            else:
                base_node = self._base.get_node(child_path)
                entry = {
                    "path": child_path,
                    "content_preview": (child.content or "")[:500],
                    "size": child.size,
                    "owner": child.owner,
                    "permissions": child.permissions,
                }
                if base_node is None:
                    files_created.append(entry)
                else:
                    files_modified.append(entry)

    # ── Internal: Overlay Tree Operations ────────────

    def _resolve_overlay(self, path: str) -> FSNode | None:
        """Walk the overlay tree for an exact path. Returns None if absent."""
        if path == "/":
            return self._overlay
        parts = [p for p in path.split("/") if p]
        current = self._overlay
        for part in parts:
            if not current.is_dir or part not in current.children:
                return None
            current = current.children[part]
        return current

    def _ensure_overlay_dir(self, path: str,
                            owner: str = "root") -> FSNode | None:
        """
        Ensure a directory path exists in the overlay tree.
        Creates intermediate nodes as needed (like mkdir -p in the overlay).
        Does NOT check the base — this is purely overlay bookkeeping.
        """
        if path == "/":
            return self._overlay
        parts = [p for p in path.split("/") if p]
        current = self._overlay
        built = ""
        for part in parts:
            built += f"/{part}"
            if part not in current.children:
                # Enforce quota for each new overlay node (including intermediates)
                if self._overlay_count >= MAX_FILES_PER_SESSION:
                    logger.warning("Session file limit reached (%d)", MAX_FILES_PER_SESSION)
                    return None
                # Check if this dir exists in base — use its metadata
                base_node = self._base.get_node(built)
                if base_node and base_node.is_dir:
                    # Create a shallow overlay entry (won't copy children)
                    current.children[part] = FSNode(
                        name=part, path=built, is_dir=True,
                        owner=base_node.owner,
                        group=base_node.group,
                        permissions=base_node.permissions,
                        modified=base_node.modified,
                    )
                else:
                    current.children[part] = FSNode(
                        name=part, path=built, is_dir=True,
                        owner=owner, permissions="0755",
                        modified=datetime.utcnow().strftime("%b %d %H:%M"),
                    )
                self._overlay_count += 1
            current = current.children[part]
            if not current.is_dir:
                return None  # Path conflict — file exists where we need a dir
        return current

    def _copy_up(self, path: str) -> FSNode | None:
        """
        Ensure a node exists in the overlay so it can be mutated.
        If it only exists in base, deep-copy it into the overlay.
        Returns the overlay node, or None if the path doesn't exist anywhere.
        """
        path = _normalize(path)
        if self._is_tombstoned(path):
            return None

        # Already in overlay?
        existing = self._resolve_overlay(path)
        if existing is not None:
            return existing

        # Exists in base? Copy up.
        base_node = self._base.get_node(path)
        if base_node is None:
            return None

        parent_path = os.path.dirname(path)
        filename = os.path.basename(path)
        parent = self._ensure_overlay_dir(parent_path)
        if parent is None:
            return None

        # Shallow copy — don't recursively copy children for dirs
        copied = FSNode(
            name=base_node.name,
            path=base_node.path,
            is_dir=base_node.is_dir,
            content=base_node.content,
            size=base_node.size,
            owner=base_node.owner,
            group=base_node.group,
            permissions=base_node.permissions,
            modified=base_node.modified,
        )
        parent.children[filename] = copied
        return copied

    def _merged_dir_node(self, path: str,
                         overlay_node: FSNode | None) -> FSNode | None:
        """
        Build a merged directory view combining base + overlay children,
        minus tombstoned entries.  Returns a synthetic FSNode used only
        for reading (list_directory, get_node).
        """
        path = _normalize(path)
        base_node = self._base.get_node(path)

        # Start with overlay metadata if available, else base
        if overlay_node is not None:
            merged = FSNode(
                name=overlay_node.name, path=path, is_dir=True,
                owner=overlay_node.owner, group=overlay_node.group,
                permissions=overlay_node.permissions,
                modified=overlay_node.modified,
            )
        elif base_node is not None:
            merged = FSNode(
                name=base_node.name, path=path, is_dir=True,
                owner=base_node.owner, group=base_node.group,
                permissions=base_node.permissions,
                modified=base_node.modified,
            )
        else:
            return None

        # Collect base children (not tombstoned)
        if base_node and base_node.is_dir:
            for name, child in base_node.children.items():
                child_path = f"{path}/{name}" if path != "/" else f"/{name}"
                if not self._is_tombstoned(child_path):
                    merged.children[name] = child

        # Overlay children win (overwrite base entries)
        if overlay_node and overlay_node.is_dir:
            for name, child in overlay_node.children.items():
                child_path = f"{path}/{name}" if path != "/" else f"/{name}"
                if not self._is_tombstoned(child_path):
                    merged.children[name] = child

        return merged

    def _is_tombstoned(self, path: str) -> bool:
        """Check if this path or any ancestor has been deleted."""
        if path in self._tombstones:
            return True
        # Check ancestors — if /foo was deleted, /foo/bar is also gone
        parts = path.split("/")
        for i in range(1, len(parts)):
            ancestor = "/".join(parts[:i]) or "/"
            if ancestor in self._tombstones:
                return True
        return False

    def _tombstone_recursive(self, path: str, node: FSNode):
        """Tombstone a path and all its descendants."""
        self._tombstones.add(path)
        if node.is_dir:
            for name, child in node.children.items():
                child_path = f"{path}/{name}" if path != "/" else f"/{name}"
                self._tombstone_recursive(child_path, child)

    # ── Formatting (same as VirtualFilesystem) ───────

    @staticmethod
    def _format_long(node: FSNode) -> str:
        perm_str = ("d" if node.is_dir else "-") + _perm_bits(node.permissions)
        links = "2" if node.is_dir else "1"
        return (f"{perm_str} {links:>3} {node.owner:<8} {node.group:<8} "
                f"{node.size:>8} {node.modified} {node.name}")


def _normalize(path: str) -> str:
    """Normalize a path: resolve . and .., ensure leading /."""
    if '\x00' in path:
        path = path.replace('\x00', '')
    parts = path.split("/")
    result = []
    for p in parts:
        if p == "" or p == ".":
            continue
        elif p == "..":
            if result:
                result.pop()
        else:
            result.append(p)
    return "/" + "/".join(result) if result else "/"
