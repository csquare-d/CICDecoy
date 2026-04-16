"""Unit tests for the SSH decoy copy-on-write session filesystem."""

import pytest
from cow_filesystem import SessionFilesystem, _normalize
from filesystem import VirtualFilesystem

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

@pytest.fixture
def base_fs():
    """A base VirtualFilesystem with skeleton and sample files."""
    vfs = VirtualFilesystem()
    vfs._build_base_skeleton()
    vfs.create_file("/etc/motd", content="Welcome")
    vfs.create_file("/tmp/base.txt", content="base content")
    vfs.create_directory("/opt/app")
    vfs.create_file("/opt/app/config.yaml", content="key: value")
    return vfs


@pytest.fixture
def cow(base_fs):
    return SessionFilesystem(base_fs)


# ---------------------------------------------------------------------------
# Path normalization
# ---------------------------------------------------------------------------

class TestNormalize:
    def test_root(self):
        assert _normalize("/") == "/"

    def test_trailing_slash(self):
        assert _normalize("/tmp/") == "/tmp"

    def test_double_dots(self):
        assert _normalize("/tmp/foo/..") == "/tmp"

    def test_single_dot(self):
        assert _normalize("/tmp/.") == "/tmp"

    def test_double_slash(self):
        assert _normalize("//tmp") == "/tmp"

    def test_complex(self):
        assert _normalize("/a/b/../c/./d") == "/a/c/d"

    def test_beyond_root(self):
        result = _normalize("/../..")
        assert result == "/"

    def test_empty_becomes_root(self):
        assert _normalize("") == "/"


# ---------------------------------------------------------------------------
# Read-through to base
# ---------------------------------------------------------------------------

class TestReadThrough:
    def test_reads_base_file(self, cow):
        assert cow.read_file("/tmp/base.txt") == "base content"

    def test_reads_base_directory(self, cow):
        assert cow.is_directory("/etc")

    def test_file_exists_in_base(self, cow):
        assert cow.file_exists("/etc/motd")

    def test_nonexistent_file(self, cow):
        assert cow.read_file("/nope") is None

    def test_list_base_directory(self, cow):
        listing = cow.list_directory("/opt/app")
        assert "config.yaml" in listing


# ---------------------------------------------------------------------------
# Overlay writes
# ---------------------------------------------------------------------------

class TestOverlayWrites:
    def test_create_file_in_overlay(self, cow):
        assert cow.create_file("/tmp/new.txt", content="overlay")
        assert cow.read_file("/tmp/new.txt") == "overlay"

    def test_overlay_does_not_affect_base(self, cow, base_fs):
        cow.create_file("/tmp/overlay.txt", content="new")
        assert base_fs.read_file("/tmp/overlay.txt") is None

    def test_overwrite_base_file(self, cow):
        cow.create_file("/etc/motd", content="hacked")
        assert cow.read_file("/etc/motd") == "hacked"

    def test_append_to_base_file(self, cow):
        cow.append_file("/etc/motd", "\nAppended")
        content = cow.read_file("/etc/motd")
        assert "Welcome" in content
        assert "Appended" in content

    def test_append_to_new_file(self, cow):
        cow.append_file("/tmp/app.log", "line1\n")
        cow.append_file("/tmp/app.log", "line2\n")
        assert cow.read_file("/tmp/app.log") == "line1\nline2\n"

    def test_create_directory_in_overlay(self, cow):
        assert cow.create_directory("/tmp/session_dir")
        assert cow.is_directory("/tmp/session_dir")

    def test_create_nested_directory_with_parents(self, cow):
        assert cow.create_directory("/tmp/a/b/c", parents=True)
        assert cow.is_directory("/tmp/a/b/c")

    def test_create_nested_directory_without_parents_creates_parent(self, cow):
        # COW's create_directory(parents=False) still calls _ensure_overlay_dir
        # on the parent path, which creates intermediates. This is a known
        # behavior difference from the base VirtualFilesystem.
        result = cow.create_directory("/tmp/x/y/z", parents=False)
        assert result is True
        assert cow.is_directory("/tmp/x/y/z")


# ---------------------------------------------------------------------------
# Tombstones (deletion)
# ---------------------------------------------------------------------------

class TestTombstones:
    def test_remove_base_file(self, cow):
        assert cow.file_exists("/etc/motd")
        assert cow.remove_file("/etc/motd") is True
        assert cow.file_exists("/etc/motd") is False
        assert cow.read_file("/etc/motd") is None

    def test_remove_overlay_file(self, cow):
        cow.create_file("/tmp/temp.txt", content="x")
        assert cow.remove_file("/tmp/temp.txt") is True
        assert cow.file_exists("/tmp/temp.txt") is False

    def test_remove_recreate(self, cow):
        cow.remove_file("/etc/motd")
        cow.create_file("/etc/motd", content="new motd")
        assert cow.read_file("/etc/motd") == "new motd"

    def test_remove_directory_recursive(self, cow):
        assert cow.remove_directory("/opt/app", recursive=True) is True
        assert cow.file_exists("/opt/app") is False
        assert cow.file_exists("/opt/app/config.yaml") is False

    def test_remove_nonempty_dir_nonrecursive_fails(self, cow):
        assert cow.remove_directory("/opt/app", recursive=False) is False

    def test_cannot_remove_root(self, cow):
        assert cow.remove_directory("/") is False

    def test_tombstoned_file_not_in_listing(self, cow):
        cow.create_file("/tmp/visible.txt", content="v")
        cow.create_file("/tmp/gone.txt", content="g")
        cow.remove_file("/tmp/gone.txt")
        listing = cow.list_directory("/tmp")
        assert "gone.txt" not in listing
        assert "visible.txt" in listing


# ---------------------------------------------------------------------------
# Merged directory views
# ---------------------------------------------------------------------------

class TestMergedView:
    def test_overlay_and_base_files_both_visible(self, cow):
        cow.create_file("/tmp/overlay.txt", content="new")
        listing = cow.list_directory("/tmp")
        assert "base.txt" in listing
        assert "overlay.txt" in listing

    def test_overlay_dir_and_base_dir_merged(self, cow):
        cow.create_file("/opt/app/new.conf", content="x")
        listing = cow.list_directory("/opt/app")
        assert "config.yaml" in listing  # from base
        assert "new.conf" in listing  # from overlay


# ---------------------------------------------------------------------------
# Copy-up (chmod / chown on base files)
# ---------------------------------------------------------------------------

class TestCopyUp:
    def test_chmod_base_file(self, cow, base_fs):
        assert cow.chmod("/etc/motd", "0777") is True
        node = cow.get_node("/etc/motd")
        assert node.permissions == "0777"
        # Base should be unaffected
        assert base_fs.get_node("/etc/motd").permissions != "0777"

    def test_chown_base_file(self, cow, base_fs):
        assert cow.chown("/etc/motd", "attacker", "hackers") is True
        node = cow.get_node("/etc/motd")
        assert node.owner == "attacker"
        assert node.group == "hackers"

    def test_chmod_nonexistent_fails(self, cow):
        assert cow.chmod("/nope", "0777") is False


# ---------------------------------------------------------------------------
# Delta / forensics
# ---------------------------------------------------------------------------

class TestDelta:
    def test_empty_delta(self, cow):
        delta = cow.get_delta()
        assert delta["mutation_count"] == 0

    def test_delta_tracks_created_files(self, cow):
        cow.create_file("/tmp/evil.sh", content="#!/bin/bash")
        delta = cow.get_delta()
        created_paths = [f["path"] for f in delta["files_created"]]
        assert "/tmp/evil.sh" in created_paths

    def test_delta_tracks_modified_files(self, cow):
        cow.append_file("/etc/motd", "\nmodified")
        delta = cow.get_delta()
        modified_paths = [f["path"] for f in delta["files_modified"]]
        assert "/etc/motd" in modified_paths

    def test_delta_tracks_created_dirs(self, cow):
        cow.create_directory("/tmp/staging", parents=True)
        delta = cow.get_delta()
        # The delta may track created dirs or they may appear in mutation_log
        assert delta["mutation_count"] >= 1
        # Check mutation log records the create_dir op
        ops = [m["op"] for m in delta["mutation_log"]]
        assert "create_dir" in ops

    def test_delta_tracks_deletions(self, cow):
        cow.remove_file("/etc/motd")
        delta = cow.get_delta()
        assert "/etc/motd" in delta["paths_deleted"]

    def test_mutation_log(self, cow):
        cow.create_file("/tmp/a.txt", content="a")
        cow.create_file("/tmp/b.txt", content="b")
        delta = cow.get_delta()
        assert len(delta["mutation_log"]) == 2


# ---------------------------------------------------------------------------
# Context snapshot through COW
# ---------------------------------------------------------------------------

class TestCOWSnapshot:
    def test_snapshot_includes_overlay_files(self, cow):
        cow.create_file("/tmp/new.txt", content="x")
        snap = cow.get_context_snapshot("/tmp")
        names = [e["name"] for e in snap["cwd_contents"]]
        assert "new.txt" in names

    def test_profile_data_delegates_to_base(self, cow):
        # Should not raise
        data = cow.get_profile_data()
        assert isinstance(data, dict)
