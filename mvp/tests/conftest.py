"""
CI/CDecoy — Test Fixtures

Shared fixtures for all test modules. Sets up:
- FastAPI test client (no real NATS/DB required)
- Mock NATS connection
- Mock asyncpg pool
- Sample event factories
"""

import asyncio
import json
import uuid
import sys
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio

# ---------------------------------------------------------------------------
# Ensure sibling packages (dashboard, ssh-decoy, cti) are importable when
# pytest runs from the project root:  python -m pytest tests/ -v
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
for subdir in ["dashboard", "ssh-decoy", "cti"]:
    candidate = PROJECT_ROOT / subdir
    if candidate.is_dir() and str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))


# ── Event factories ─────────────────────────────────

def make_nats_event(
    event_type="command",
    severity="medium",
    command="whoami",
    technique_id="T1082",
    technique_name="System Information Discovery",
    tactic="discovery",
    source_ip="198.51.100.42",
    session_id=None,
    decoy_name="ssh-decoy-01",
    decoy_tier=2,
):
    """Build a realistic NATS event payload matching the decoy_events schema."""
    session_id = session_id or f"sess-{uuid.uuid4().hex[:12]}"
    return {
        "event_id": f"evt-{uuid.uuid4().hex[:12]}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "decoy_name": decoy_name,
        "decoy_tier": decoy_tier,
        "session_id": session_id,
        "event_type": event_type,
        "source_ip": source_ip,
        "source_port": 44120,
        "geo": {"country": "CN", "city": "Beijing"},
        "mitre_techniques": [
            {
                "technique_id": technique_id,
                "technique_name": technique_name,
                "tactic": tactic,
            }
        ],
        "tool_signatures": [],
        "severity": severity,
        "tags": ["test"],
        "raw_data": {"command": command, "output_lines": 5},
    }


def make_session_row(
    session_id=None,
    source_ip="198.51.100.42",
    techniques=None,
    kill_chain=False,
    severity="medium",
    command_count=5,
):
    """Build a dict matching the decoy_sessions table shape."""
    session_id = session_id or f"sess-{uuid.uuid4().hex[:12]}"
    techniques = techniques or [
        {"technique_id": "T1082", "technique_name": "System Information Discovery", "tactic": "discovery"}
    ]
    return {
        "session_id": session_id,
        "decoy_name": "ssh-decoy-01",
        "decoy_tier": 2,
        "source_ip": source_ip,
        "start_time": datetime.now(timezone.utc),
        "end_time": None,
        "duration_seconds": 120.0,
        "auth_username": "admin",
        "auth_method": "password",
        "auth_attempts": 3,
        "command_count": command_count,
        "unique_commands": command_count,
        "commands": json.dumps(["whoami", "id", "uname -a", "cat /etc/passwd", "ls -la"]),
        "mitre_techniques": json.dumps(techniques),
        "tools_detected": json.dumps([]),
        "max_severity": severity,
        "attack_phases": json.dumps(["discovery", "credential-access"]),
        "kill_chain_detected": kill_chain,
        "geo": json.dumps({"country": "CN"}),
        "honeytokens_accessed": json.dumps([]),
        "updated_at": datetime.now(timezone.utc),
    }


# ── Mock asyncpg ────────────────────────────────────

class MockAsyncpgPool:
    """Minimal mock for asyncpg.Pool that supports `async with pool.acquire()`."""

    def __init__(self):
        self.conn = MockAsyncpgConn()

    def acquire(self):
        return _AcquireContext(self.conn)

    async def close(self):
        pass


class MockAsyncpgConn:
    """Mock connection — override fetch/fetchrow/fetchval per test."""

    async def fetch(self, query, *args):
        return []

    async def fetchrow(self, query, *args):
        return {}

    async def fetchval(self, query, *args):
        return "PostgreSQL 16.0 (mock)"

    async def execute(self, query, *args):
        pass


class _AcquireContext:
    def __init__(self, conn):
        self.conn = conn

    async def __aenter__(self):
        return self.conn

    async def __aexit__(self, *args):
        pass


# ── Dashboard app fixture ───────────────────────────

@pytest.fixture
def mock_db_pool():
    return MockAsyncpgPool()


@pytest.fixture
def mock_nats():
    nc = AsyncMock()
    nc.is_connected = True
    nc.subscribe = AsyncMock()
    nc.publish = AsyncMock()
    nc.drain = AsyncMock()
    return nc