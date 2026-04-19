"""Unit tests for pipe filter commands: wc, sort, uniq, cut.

These tests exercise the _apply_pipe static method directly as well as
full pipe chains through router.route() to verify end-to-end behaviour.
"""


import pytest
from command_router import CommandRouter
from cow_filesystem import SessionFilesystem
from filesystem import VirtualFilesystem
from session import SessionState

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _FakeConfig:
    """Minimal config for CommandRouter."""

    def __init__(self, tier=2, hostname="test-host", **kw):
        self.tier = tier
        self.hostname = hostname
        self.domain = "test.local"
        self.name = "test-decoy"
        self.profile_name = ""
        self.inference_endpoint = "http://localhost:8000"
        self.max_session_tokens = 4096
        self.temperature = 0.3
        self.fast_path_commands = []
        self.filter_patterns = []
        self.custom_responses = {}
        for k, v in kw.items():
            setattr(self, k, v)


@pytest.fixture
def fs():
    vfs = VirtualFilesystem()
    vfs._build_base_skeleton()
    vfs.create_file("/tmp/data.txt", content="banana\napple\napple\ncherry\nbanana\n")
    vfs.create_file("/tmp/nums.txt", content="10\n2\n30\n1\n20\n")
    vfs.create_file(
        "/tmp/colon.txt",
        content="root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000:admin:/home/admin:/bin/bash\n",
    )
    vfs.create_file("/tmp/tabs.txt", content="a\tb\tc\nd\te\tf\n")
    vfs.create_directory("/home/admin")
    return SessionFilesystem(vfs)


@pytest.fixture
def state():
    return SessionState(
        hostname="test-host",
        username="admin",
        uid=1000,
        home="/home/admin",
        cwd="/home/admin",
    )


@pytest.fixture
def router():
    return CommandRouter(_FakeConfig(tier=2))


# ---------------------------------------------------------------------------
# Direct _apply_pipe tests — wc
# ---------------------------------------------------------------------------

class TestPipeWc:
    def test_wc_default_all_columns(self):
        text = "hello world\nfoo bar baz\n"
        result = CommandRouter._apply_pipe("wc", text)
        # 2 newlines → 2 lines, 5 words, byte count of text
        assert "2" in result
        assert "5" in result

    def test_wc_l_flag(self):
        text = "a\nb\nc\n"
        result = CommandRouter._apply_pipe("wc -l", text)
        assert result.strip() == "3"

    def test_wc_w_flag(self):
        text = "one two three\nfour\n"
        result = CommandRouter._apply_pipe("wc -w", text)
        assert result.strip() == "4"

    def test_wc_c_flag(self):
        text = "abc\n"
        result = CommandRouter._apply_pipe("wc -c", text)
        assert result.strip() == "4"  # 3 chars + newline

    def test_wc_combined_lw(self):
        text = "one two\nthree\n"
        result = CommandRouter._apply_pipe("wc -lw", text)
        # Should contain line count and word count but not byte count
        assert "2" in result   # 2 lines
        assert "3" in result   # 3 words

    def test_wc_empty_input(self):
        result = CommandRouter._apply_pipe("wc -l", "")
        assert result.strip() == "0"


# ---------------------------------------------------------------------------
# Direct _apply_pipe tests — sort
# ---------------------------------------------------------------------------

class TestPipeSort:
    def test_sort_alphabetical(self):
        text = "banana\napple\ncherry"
        result = CommandRouter._apply_pipe("sort", text)
        lines = result.splitlines()
        assert lines == ["apple", "banana", "cherry"]

    def test_sort_reverse(self):
        text = "a\nb\nc"
        result = CommandRouter._apply_pipe("sort -r", text)
        lines = result.splitlines()
        assert lines == ["c", "b", "a"]

    def test_sort_numeric(self):
        text = "10\n2\n30\n1\n20"
        result = CommandRouter._apply_pipe("sort -n", text)
        lines = result.splitlines()
        assert lines == ["1", "2", "10", "20", "30"]

    def test_sort_numeric_reverse(self):
        text = "10\n2\n30"
        result = CommandRouter._apply_pipe("sort -rn", text)
        lines = result.splitlines()
        assert lines == ["30", "10", "2"]

    def test_sort_unique(self):
        text = "a\nb\na\nc\nb"
        result = CommandRouter._apply_pipe("sort -u", text)
        lines = result.splitlines()
        assert lines == ["a", "b", "c"]

    def test_sort_unique_reverse(self):
        text = "a\nb\na\nc"
        result = CommandRouter._apply_pipe("sort -ru", text)
        lines = result.splitlines()
        assert lines == ["c", "b", "a"]


# ---------------------------------------------------------------------------
# Direct _apply_pipe tests — uniq
# ---------------------------------------------------------------------------

class TestPipeUniq:
    def test_uniq_basic(self):
        text = "a\na\nb\nb\nb\nc"
        result = CommandRouter._apply_pipe("uniq", text)
        lines = result.splitlines()
        assert lines == ["a", "b", "c"]

    def test_uniq_nonadjacent_kept(self):
        """uniq only removes adjacent duplicates."""
        text = "a\nb\na"
        result = CommandRouter._apply_pipe("uniq", text)
        lines = result.splitlines()
        assert lines == ["a", "b", "a"]

    def test_uniq_count(self):
        text = "a\na\na\nb\nc\nc"
        result = CommandRouter._apply_pipe("uniq -c", text)
        lines = [line.strip() for line in result.splitlines()]
        assert lines[0] == "3 a"
        assert lines[1] == "1 b"
        assert lines[2] == "2 c"

    def test_uniq_duplicates_only(self):
        text = "a\na\nb\nc\nc"
        result = CommandRouter._apply_pipe("uniq -d", text)
        lines = result.splitlines()
        # Only lines that appeared more than once
        assert "a" in lines
        assert "c" in lines
        assert "b" not in lines


# ---------------------------------------------------------------------------
# Direct _apply_pipe tests — cut
# ---------------------------------------------------------------------------

class TestPipeCut:
    def test_cut_single_field_colon(self):
        text = "root:x:0:0\nadmin:x:1000:1000"
        result = CommandRouter._apply_pipe("cut -d: -f1", text)
        lines = result.splitlines()
        assert lines == ["root", "admin"]

    def test_cut_field_with_space_delim(self):
        text = "root:x:0:0\nadmin:x:1000:1000"
        result = CommandRouter._apply_pipe("cut -d : -f 3", text)
        lines = result.splitlines()
        assert lines == ["0", "1000"]

    def test_cut_field_range(self):
        text = "a:b:c:d:e"
        result = CommandRouter._apply_pipe("cut -d: -f2-4", text)
        assert result.strip() == "b:c:d"

    def test_cut_field_list(self):
        text = "a:b:c:d:e"
        result = CommandRouter._apply_pipe("cut -d: -f1,3,5", text)
        assert result.strip() == "a:c:e"

    def test_cut_open_range_start(self):
        """cut -f-2 means fields 1 through 2."""
        text = "a:b:c:d"
        result = CommandRouter._apply_pipe("cut -d: -f-2", text)
        assert result.strip() == "a:b"

    def test_cut_default_tab_delimiter(self):
        text = "a\tb\tc"
        result = CommandRouter._apply_pipe("cut -f2", text)
        assert result.strip() == "b"

    def test_cut_field_beyond_range(self):
        """Requesting a field that doesn't exist → empty."""
        text = "a:b"
        result = CommandRouter._apply_pipe("cut -d: -f5", text)
        assert result.strip() == ""


# ---------------------------------------------------------------------------
# End-to-end pipe chain tests via router.route()
# ---------------------------------------------------------------------------

class TestPipeChainsE2E:
    @pytest.mark.asyncio
    async def test_cat_sort(self, router, state, fs):
        result = await router.route("cat /tmp/data.txt | sort", state, fs, tier=2)
        lines = [line for line in result.split("\n") if line]
        assert lines == sorted(lines)

    @pytest.mark.asyncio
    async def test_cat_sort_uniq(self, router, state, fs):
        result = await router.route(
            "cat /tmp/data.txt | sort | uniq", state, fs, tier=2
        )
        lines = [line for line in result.split("\n") if line]
        assert len(lines) == len(set(lines))  # all unique

    @pytest.mark.asyncio
    async def test_cat_sort_uniq_count(self, router, state, fs):
        result = await router.route(
            "cat /tmp/data.txt | sort | uniq -c", state, fs, tier=2
        )
        # Each line should have a count prefix
        for line in result.split("\n"):
            if line.strip():
                parts = line.strip().split(None, 1)
                assert parts[0].isdigit()

    @pytest.mark.asyncio
    async def test_cat_wc_l(self, router, state, fs):
        result = await router.route(
            "cat /tmp/data.txt | wc -l", state, fs, tier=2
        )
        # data.txt has 5 lines (5 newlines in "banana\napple\napple\ncherry\nbanana\n")
        assert result.strip() == "5"

    @pytest.mark.asyncio
    async def test_cat_grep_wc_l(self, router, state, fs):
        result = await router.route(
            "cat /tmp/data.txt | grep apple | wc -l", state, fs, tier=2
        )
        # With trailing newlines in pipe output (matching real Unix),
        # grep | wc -l now returns the correct count.
        count = int(result.strip())
        assert count == 2  # two "apple" lines in data.txt

    @pytest.mark.asyncio
    async def test_cat_cut_colon(self, router, state, fs):
        result = await router.route(
            "cat /tmp/colon.txt | cut -d: -f1", state, fs, tier=2
        )
        lines = [line for line in result.split("\n") if line]
        assert "root" in lines
        assert "admin" in lines

    @pytest.mark.asyncio
    async def test_cat_sort_numeric(self, router, state, fs):
        result = await router.route(
            "cat /tmp/nums.txt | sort -n", state, fs, tier=2
        )
        lines = [line for line in result.split("\n") if line]
        assert lines == ["1", "2", "10", "20", "30"]

    @pytest.mark.asyncio
    async def test_echo_pipe_wc(self, router, state, fs):
        result = await router.route(
            "echo 'hello world' | wc -w", state, fs, tier=2
        )
        assert result.strip() == "2"

    @pytest.mark.asyncio
    async def test_three_stage_pipe(self, router, state, fs):
        """cat | grep | cut — a realistic attacker pattern."""
        result = await router.route(
            "cat /tmp/colon.txt | grep root | cut -d: -f6",
            state, fs, tier=2,
        )
        lines = [line for line in result.split("\n") if line]
        assert "/root" in lines

    @pytest.mark.asyncio
    async def test_sort_uniq_wc(self, router, state, fs):
        """sort | uniq | wc -l — count distinct values."""
        result = await router.route(
            "cat /tmp/data.txt | sort | uniq | wc -l", state, fs, tier=2
        )
        # 3 unique fruits: apple, banana, cherry
        count = int(result.strip())
        assert count == 3


# ---------------------------------------------------------------------------
# Direct _apply_pipe tests — awk
# ---------------------------------------------------------------------------

class TestPipeAwk:
    def test_awk_print_field(self):
        text = "root x 0 0\nadmin x 1000 1000\n"
        result = CommandRouter._apply_pipe("awk '{print $1}'", text)
        lines = result.splitlines()
        assert lines == ["root", "admin"]

    def test_awk_print_multiple_fields(self):
        text = "alice 25 engineer\nbob 30 designer\n"
        result = CommandRouter._apply_pipe("awk '{print $1, $3}'", text)
        lines = result.splitlines()
        assert lines == ["alice engineer", "bob designer"]

    def test_awk_custom_delimiter(self):
        text = "root:x:0:0:root:/root:/bin/bash\n"
        result = CommandRouter._apply_pipe("awk -F: '{print $1}'", text)
        assert result.strip() == "root"

    def test_awk_custom_delimiter_field6(self):
        text = "root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000:admin:/home/admin:/bin/bash\n"
        result = CommandRouter._apply_pipe("awk -F: '{print $6}'", text)
        lines = result.splitlines()
        assert lines == ["/root", "/home/admin"]

    def test_awk_print_nf(self):
        """$NF prints last field."""
        text = "one two three\nfour five\n"
        result = CommandRouter._apply_pipe("awk '{print $NF}'", text)
        lines = result.splitlines()
        assert lines == ["three", "five"]

    def test_awk_print_nr(self):
        """NR prints line number."""
        text = "alpha\nbeta\ngamma\n"
        result = CommandRouter._apply_pipe("awk '{print NR, $0}'", text)
        lines = result.splitlines()
        assert lines == ["1 alpha", "2 beta", "3 gamma"]

    def test_awk_pattern_filter(self):
        text = "apple 5\nbanana 3\napricot 7\ncherry 2\n"
        result = CommandRouter._apply_pipe("awk '/ap/'", text)
        lines = result.splitlines()
        assert lines == ["apple 5", "apricot 7"]

    def test_awk_pattern_with_action(self):
        text = "root:x:0\nadmin:x:1000\nnobody:x:65534\n"
        result = CommandRouter._apply_pipe("awk -F: '/root/{print $3}'", text)
        assert result.strip() == "0"

    def test_awk_negate_pattern(self):
        text = "good line\nbad line\ngood again\n"
        result = CommandRouter._apply_pipe("awk '!/bad/'", text)
        lines = result.splitlines()
        assert lines == ["good line", "good again"]

    def test_awk_nr_equals(self):
        text = "first\nsecond\nthird\n"
        result = CommandRouter._apply_pipe("awk 'NR==2'", text)
        assert result.strip() == "second"

    def test_awk_nr_greater(self):
        text = "first\nsecond\nthird\nfourth\n"
        result = CommandRouter._apply_pipe("awk 'NR>2'", text)
        lines = result.splitlines()
        assert lines == ["third", "fourth"]

    def test_awk_end_nr(self):
        """END{print NR} counts total lines."""
        text = "a\nb\nc\nd\ne\n"
        result = CommandRouter._apply_pipe("awk 'END{print NR}'", text)
        assert result.strip() == "5"

    def test_awk_begin_ofs(self):
        """BEGIN{OFS=\":\"} sets output field separator."""
        text = "alice 25 engineer\nbob 30 designer\n"
        result = CommandRouter._apply_pipe(
            "awk 'BEGIN{OFS=\":\"}{print $1,$3}'", text
        )
        lines = result.splitlines()
        assert lines == ["alice:engineer", "bob:designer"]

    def test_awk_field_out_of_range(self):
        """Accessing a field beyond available columns returns empty."""
        text = "one two\n"
        result = CommandRouter._apply_pipe("awk '{print $5}'", text)
        assert result.strip() == ""

    def test_awk_empty_input(self):
        result = CommandRouter._apply_pipe("awk '{print $1}'", "")
        assert result.strip() == ""

    def test_awk_whole_line(self):
        text = "hello world\nfoo bar\n"
        result = CommandRouter._apply_pipe("awk '{print $0}'", text)
        lines = result.splitlines()
        assert lines == ["hello world", "foo bar"]


# ---------------------------------------------------------------------------
# E2E awk pipe chain tests
# ---------------------------------------------------------------------------

class TestAwkPipeChainsE2E:
    @pytest.mark.asyncio
    async def test_cat_awk_field(self, router, state, fs):
        """cat /etc/passwd | awk -F: '{print $1}' — classic attacker pattern."""
        result = await router.route(
            "cat /tmp/colon.txt | awk -F: '{print $1}'", state, fs, tier=2
        )
        lines = [line for line in result.splitlines() if line]
        assert "root" in lines
        assert "admin" in lines

    @pytest.mark.asyncio
    async def test_cat_grep_awk(self, router, state, fs):
        """cat | grep | awk — common recon chain."""
        result = await router.route(
            "cat /tmp/colon.txt | grep root | awk -F: '{print $6}'",
            state, fs, tier=2,
        )
        lines = [line for line in result.splitlines() if line]
        assert "/root" in lines

    @pytest.mark.asyncio
    async def test_cat_awk_end_count(self, router, state, fs):
        """awk 'END{print NR}' — count lines."""
        result = await router.route(
            "cat /tmp/data.txt | awk 'END{print NR}'", state, fs, tier=2
        )
        count = int(result.strip())
        assert count == 5  # 5 non-empty lines in data.txt
