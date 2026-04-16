"""Unit tests for the SSH decoy virtual filesystem."""

import pytest
from filesystem import FSNode, VirtualFilesystem, _perm_bits

# ---------------------------------------------------------------------------
# FSNode basics
# ---------------------------------------------------------------------------

class TestFSNode:
    def test_file_node_defaults(self):
        n = FSNode(name="test.txt", path="/test.txt")
        assert n.is_dir is False
        assert n.owner == "root"
        assert n.group == "root"
        assert n.permissions == "0644"

    def test_dir_permissions_auto_upgrade(self):
        n = FSNode(name="etc", path="/etc", is_dir=True)
        assert n.permissions == "0755"

    def test_size_from_content(self):
        n = FSNode(name="f", path="/f", content="hello")
        assert n.size == 5

    def test_modified_populated(self):
        n = FSNode(name="f", path="/f")
        assert n.modified != ""


class TestPermBits:
    def test_0755(self):
        assert _perm_bits("0755") == "rwxr-xr-x"

    def test_0644(self):
        assert _perm_bits("0644") == "rw-r--r--"

    def test_0700(self):
        assert _perm_bits("0700") == "rwx------"

    def test_0000(self):
        assert _perm_bits("0000") == "---------"

    def test_0777(self):
        assert _perm_bits("0777") == "rwxrwxrwx"


# ---------------------------------------------------------------------------
# VirtualFilesystem construction
# ---------------------------------------------------------------------------

class TestFilesystemInit:
    def test_root_exists(self):
        fs = VirtualFilesystem()
        assert fs.get_node("/") is not None
        assert fs.is_directory("/")

    def test_base_skeleton_directories(self):
        fs = VirtualFilesystem()
        fs._build_base_skeleton()
        for path in ["/etc", "/tmp", "/var", "/home", "/usr", "/bin", "/root"]:
            assert fs.is_directory(path), f"{path} should exist as directory"

    def test_base_skeleton_files(self):
        fs = VirtualFilesystem()
        fs._build_base_skeleton()
        for path in ["/etc/passwd", "/etc/hostname"]:
            assert fs.is_file(path), f"{path} should exist as file"


# ---------------------------------------------------------------------------
# File CRUD
# ---------------------------------------------------------------------------

class TestFileCRUD:
    @pytest.fixture
    def fs(self):
        vfs = VirtualFilesystem()
        vfs._build_base_skeleton()
        return vfs

    def test_create_file(self, fs):
        assert fs.create_file("/tmp/test.txt", content="hello")
        assert fs.is_file("/tmp/test.txt")
        assert fs.read_file("/tmp/test.txt") == "hello"

    def test_create_file_with_owner(self, fs):
        fs.create_file("/tmp/owned.txt", owner="admin", permissions="0600")
        node = fs.get_node("/tmp/owned.txt")
        assert node.owner == "admin"
        assert node.permissions == "0600"

    def test_create_file_in_nonexistent_dir_fails(self, fs):
        result = fs.create_file("/nonexistent/dir/file.txt", content="x")
        assert result is False

    def test_read_nonexistent_file(self, fs):
        assert fs.read_file("/does/not/exist") is None

    def test_read_directory_returns_none(self, fs):
        assert fs.read_file("/tmp") is None

    def test_append_file(self, fs):
        fs.create_file("/tmp/log.txt", content="line1\n")
        fs.append_file("/tmp/log.txt", "line2\n")
        assert fs.read_file("/tmp/log.txt") == "line1\nline2\n"

    def test_append_creates_if_missing(self, fs):
        fs.append_file("/tmp/new.txt", "content")
        assert fs.read_file("/tmp/new.txt") == "content"

    def test_remove_file(self, fs):
        fs.create_file("/tmp/del.txt", content="x")
        assert fs.remove_file("/tmp/del.txt") is True
        assert fs.file_exists("/tmp/del.txt") is False

    def test_remove_nonexistent_file(self, fs):
        assert fs.remove_file("/tmp/nope.txt") is False

    def test_remove_directory_as_file_fails(self, fs):
        assert fs.remove_file("/tmp") is False


# ---------------------------------------------------------------------------
# Directory operations
# ---------------------------------------------------------------------------

class TestDirectoryOps:
    @pytest.fixture
    def fs(self):
        vfs = VirtualFilesystem()
        vfs._build_base_skeleton()
        return vfs

    def test_create_directory(self, fs):
        assert fs.create_directory("/tmp/mydir")
        assert fs.is_directory("/tmp/mydir")

    def test_create_directory_parents(self, fs):
        assert fs.create_directory("/tmp/a/b/c", parents=True)
        assert fs.is_directory("/tmp/a/b/c")
        assert fs.is_directory("/tmp/a/b")
        assert fs.is_directory("/tmp/a")

    def test_create_directory_no_parents_fails(self, fs):
        result = fs.create_directory("/tmp/x/y/z", parents=False)
        assert result is False

    def test_remove_empty_directory(self, fs):
        fs.create_directory("/tmp/empty")
        assert fs.remove_directory("/tmp/empty") is True
        assert fs.file_exists("/tmp/empty") is False

    def test_remove_nonempty_directory_fails(self, fs):
        fs.create_directory("/tmp/full")
        fs.create_file("/tmp/full/file.txt", content="x")
        assert fs.remove_directory("/tmp/full", recursive=False) is False

    def test_remove_nonempty_directory_recursive(self, fs):
        fs.create_directory("/tmp/full")
        fs.create_file("/tmp/full/file.txt", content="x")
        assert fs.remove_directory("/tmp/full", recursive=True) is True
        assert fs.file_exists("/tmp/full") is False

    def test_cannot_remove_root(self, fs):
        assert fs.remove_directory("/") is False


# ---------------------------------------------------------------------------
# Listing
# ---------------------------------------------------------------------------

class TestListDirectory:
    @pytest.fixture
    def fs(self):
        vfs = VirtualFilesystem()
        vfs._build_base_skeleton()
        return vfs

    def test_list_tmp(self, fs):
        fs.create_file("/tmp/a.txt", content="a")
        fs.create_file("/tmp/b.txt", content="b")
        listing = fs.list_directory("/tmp")
        assert "a.txt" in listing
        assert "b.txt" in listing

    def test_list_hides_hidden_by_default(self, fs):
        fs.create_file("/tmp/.hidden", content="x")
        fs.create_file("/tmp/visible", content="x")
        listing = fs.list_directory("/tmp", show_hidden=False)
        assert ".hidden" not in listing
        assert "visible" in listing

    def test_list_shows_hidden_when_requested(self, fs):
        fs.create_file("/tmp/.hidden", content="x")
        listing = fs.list_directory("/tmp", show_hidden=True)
        assert ".hidden" in listing

    def test_list_nonexistent_directory(self, fs):
        listing = fs.list_directory("/nope")
        assert "cannot access" in listing.lower() or "no such" in listing.lower() or listing == ""

    def test_list_long_format(self, fs):
        fs.create_file("/tmp/test.txt", content="hello")
        listing = fs.list_directory("/tmp", long_format=True)
        # Long format should include permissions and owner
        assert "root" in listing or "rw" in listing


# ---------------------------------------------------------------------------
# chmod / chown
# ---------------------------------------------------------------------------

class TestPermissions:
    @pytest.fixture
    def fs(self):
        vfs = VirtualFilesystem()
        vfs._build_base_skeleton()
        return vfs

    def test_chmod(self, fs):
        fs.create_file("/tmp/f.txt")
        assert fs.chmod("/tmp/f.txt", "0777") is True
        assert fs.get_node("/tmp/f.txt").permissions == "0777"

    def test_chmod_nonexistent(self, fs):
        assert fs.chmod("/tmp/nope", "0777") is False

    def test_chown(self, fs):
        fs.create_file("/tmp/f.txt")
        assert fs.chown("/tmp/f.txt", "admin") is True
        assert fs.get_node("/tmp/f.txt").owner == "admin"

    def test_chown_with_group(self, fs):
        fs.create_file("/tmp/f.txt")
        assert fs.chown("/tmp/f.txt", "admin", "staff") is True
        node = fs.get_node("/tmp/f.txt")
        assert node.owner == "admin"
        assert node.group == "staff"


# ---------------------------------------------------------------------------
# Path resolution edge cases
# ---------------------------------------------------------------------------

class TestPathResolution:
    @pytest.fixture
    def fs(self):
        vfs = VirtualFilesystem()
        vfs._build_base_skeleton()
        return vfs

    def test_trailing_slash(self, fs):
        assert fs.is_directory("/tmp/")

    def test_double_slash(self, fs):
        assert fs.is_directory("//tmp")

    def test_dot_in_path_not_resolved(self, fs):
        # VirtualFilesystem._resolve doesn't handle "." components;
        # it looks for a literal child named "." which doesn't exist.
        assert fs.is_directory("/tmp/./") is False

    def test_file_exists_checks_both(self, fs):
        fs.create_file("/tmp/f.txt", content="x")
        assert fs.file_exists("/tmp/f.txt") is True
        assert fs.file_exists("/tmp") is True  # dirs also "exist"


# ---------------------------------------------------------------------------
# Context snapshot
# ---------------------------------------------------------------------------

class TestContextSnapshot:
    def test_snapshot_returns_cwd(self):
        fs = VirtualFilesystem()
        fs._build_base_skeleton()
        snap = fs.get_context_snapshot("/tmp")
        assert snap["cwd"] == "/tmp"
        assert isinstance(snap["cwd_contents"], list)
