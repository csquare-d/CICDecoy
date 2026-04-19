"""
CI/CDecoy — Dashboard API Tests

Tests every REST endpoint in dashboard/main.py using FastAPI's TestClient.
NATS and TimescaleDB are mocked so these run standalone.
"""

import asyncio
import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

# We import after conftest has added the dashboard dir to sys.path
import main as dashboard
import pytest
from conftest import (
    make_nats_event,
)
from httpx import ASGITransport, AsyncClient

# ── Helpers ─────────────────────────────────────────

@pytest.fixture(autouse=True)
def _reset_globals():
    """Reset dashboard module-level state between tests."""
    dashboard.event_buffer.clear()
    dashboard.subscribers.clear()
    dashboard.db_pool = None
    dashboard.nc = None
    # Auth: override the dependency so these pre-auth tests don't need to
    # thread an API key through every request. Auth itself is covered in
    # test_auth.py.
    async def _noop() -> None:
        return None
    dashboard.app.dependency_overrides[dashboard.require_api_key] = _noop
    yield
    dashboard.app.dependency_overrides.pop(dashboard.require_api_key, None)
    dashboard.event_buffer.clear()
    dashboard.subscribers.clear()
    dashboard.db_pool = None
    dashboard.nc = None


@pytest.fixture
def client():
    """
    Raw HTTPX async client against the FastAPI app.
    Bypasses lifespan so we control db_pool/nc directly.
    """
    transport = ASGITransport(app=dashboard.app)
    return AsyncClient(transport=transport, base_url="http://test")


# ── GET / ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_index_returns_html(client):
    resp = await client.get("/")
    # Static SPA files are only present after `npm run build`.
    # In test environments, the catch-all returns a 404 fallback page.
    assert "text/html" in resp.headers["content-type"]
    if resp.status_code == 200:
        assert "CI/CDecoy" in resp.text
    else:
        assert resp.status_code == 404
        assert "Dashboard not built" in resp.text


# ── GET /api/stats — no DB ──────────────────────────

@pytest.mark.asyncio
async def test_stats_no_db(client):
    """Without a DB pool, stats should return 503 with error message."""
    resp = await client.get("/api/stats")
    assert resp.status_code == 503
    data = resp.json()
    assert "error" in data


# ── GET /api/stats — with mocked DB ────────────────

@pytest.mark.asyncio
async def test_stats_with_db(client, mock_db_pool):
    mock_db_pool.conn.fetchrow = AsyncMock(return_value={
        "total_sessions": 42,
        "active": 3,
        "ev24": 187,
        "ips": 15,
        "high24": 7,
        "ht": 2,
        "kc": 1,
    })
    dashboard.db_pool = mock_db_pool
    dashboard.nc = MagicMock(is_connected=True)

    resp = await client.get("/api/stats")
    data = resp.json()
    assert data["total_sessions"] == 42
    assert data["active_sessions"] == 3
    assert data["total_events"] == 187
    assert data["unique_ips"] == 15
    assert data["high_sev_24h"] == 7
    assert data["honeytokens_triggered"] == 2
    assert data["kill_chains"] == 1
    assert data["db_connected"] is True
    assert data["nats_connected"] is True


# ── GET /api/sessions — no DB ──────────────────────

@pytest.mark.asyncio
async def test_sessions_no_db(client):
    resp = await client.get("/api/sessions")
    assert resp.status_code == 503
    data = resp.json()
    assert data["sessions"] == []
    assert "error" in data


# ── GET /api/sessions — with data ──────────────────

@pytest.mark.asyncio
async def test_sessions_with_data(client, mock_db_pool):
    # Row shape must match the SQL SELECT aliases in get_sessions()
    sql_row = {
        "session_id": "sess-test123",
        "decoy_name": "ssh-decoy-01",
        "decoy_tier": 2,
        "source_ip": "10.0.0.5",
        "auth_username": "admin",
        "start_time": datetime.now(timezone.utc),
        "end_time": datetime.now(timezone.utc),
        "duration_seconds": 120,
        "event_count": 12,
        "max_severity": "high",
    }
    # First fetch() returns session rows; second fetch() returns technique rows
    call_count = 0
    async def fetch_side_effect(query, *args):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return [sql_row]
        # Technique sub-query
        return [{"tid": "T1082", "tname": "System Information Discovery", "tactic": "discovery"}]

    mock_db_pool.conn.fetch = AsyncMock(side_effect=fetch_side_effect)
    dashboard.db_pool = mock_db_pool

    resp = await client.get("/api/sessions?limit=10")
    data = resp.json()
    assert len(data["sessions"]) == 1
    sess = data["sessions"][0]
    assert sess["source_ip"] == "10.0.0.5"
    assert sess["max_severity"] == "high"
    assert sess["command_count"] == 12
    assert isinstance(sess["mitre_techniques"], list)


# ── GET /api/mitre — no DB ─────────────────────────

@pytest.mark.asyncio
async def test_mitre_no_db(client):
    resp = await client.get("/api/mitre")
    assert resp.status_code == 503
    data = resp.json()
    assert data["techniques"] == []


# ── GET /api/mitre — with data ─────────────────────

@pytest.mark.asyncio
async def test_mitre_with_data(client, mock_db_pool):
    # Row shape must match the SQL SELECT aliases in get_mitre_summary()
    mock_rows = [
        {"technique_id": "T1082", "technique_name": "System Information Discovery",
         "tactic": "discovery", "total": 45, "actors": 8,
         "last_seen": datetime.now(timezone.utc)},
        {"technique_id": "T1059.004", "technique_name": "Unix Shell",
         "tactic": "execution", "total": 30, "actors": 5,
         "last_seen": datetime.now(timezone.utc)},
    ]
    mock_db_pool.conn.fetch = AsyncMock(return_value=mock_rows)
    mock_db_pool.conn.fetchrow = AsyncMock(return_value={"total": 2})
    dashboard.db_pool = mock_db_pool

    resp = await client.get("/api/mitre")
    data = resp.json()
    assert len(data["techniques"]) == 2
    assert data["total"] == 2
    assert data["techniques"][0]["technique_id"] == "T1082"
    assert data["techniques"][0]["technique_name"] == "System Information Discovery"
    assert data["techniques"][0]["tactic"] == "discovery"
    assert data["techniques"][0]["total"] == 45


# ── GET /api/engage — no DB ────────────────────────

@pytest.mark.asyncio
async def test_engage_no_db(client):
    resp = await client.get("/api/engage")
    assert resp.status_code == 503
    data = resp.json()
    assert data["engage"] == []


# ── GET /api/engage — with data ────────────────────

@pytest.mark.asyncio
async def test_engage_with_data(client, mock_db_pool):
    mock_rows = [
        {
            "tid": "T1082",
            "tname": "System Information Discovery",
            "tactic": "discovery",
            "times_observed": 20,
            "sessions": 10,
            "kill_chains": 2,
            "avg_dur": 180,
            "last_seen": datetime.now(timezone.utc),
        },
    ]
    mock_db_pool.conn.fetch = AsyncMock(return_value=mock_rows)
    dashboard.db_pool = mock_db_pool

    resp = await client.get("/api/engage")
    data = resp.json()
    assert len(data["engage"]) == 1
    e = data["engage"][0]
    assert e["technique_id"] == "T1082"
    assert e["engage_activity"] == "EAC0004 — Pocket Litter"
    assert 0.0 <= e["effectiveness"] <= 1.0
    assert e["times_observed"] == 20


# ── GET /api/engage — effectiveness calculation ────

@pytest.mark.asyncio
async def test_engage_effectiveness_formula(client, mock_db_pool):
    """Effectiveness = min(1.0, (dur/300)*0.5 + (kill_chains/sessions)*0.5)"""
    mock_rows = [
        # 300s, 1 kill chain in 1 session -> (1.0)*0.5 + (1/1)*0.5 = 1.0
        {"tid": "T1", "tname": "A", "tactic": "execution",
         "times_observed": 1, "sessions": 1, "kill_chains": 1,
         "avg_dur": 300, "last_seen": datetime.now(timezone.utc)},
        # 0s, 0 kill chains -> 0.0
        {"tid": "T2", "tname": "B", "tactic": "discovery",
         "times_observed": 1, "sessions": 1, "kill_chains": 0,
         "avg_dur": 0, "last_seen": datetime.now(timezone.utc)},
        # 300s, 0 kill chains -> (1.0)*0.5 + 0 = 0.5
        {"tid": "T3", "tname": "C", "tactic": "collection",
         "times_observed": 1, "sessions": 1, "kill_chains": 0,
         "avg_dur": 300, "last_seen": datetime.now(timezone.utc)},
    ]
    mock_db_pool.conn.fetch = AsyncMock(return_value=mock_rows)
    dashboard.db_pool = mock_db_pool

    resp = await client.get("/api/engage")
    data = resp.json()
    effs = {e["technique_id"]: e["effectiveness"] for e in data["engage"]}
    assert effs["T1"] == 1.0
    assert effs["T2"] == 0.0
    assert effs["T3"] == 0.5


# ── GET /api/engage — tactic-to-activity mapping ───

@pytest.mark.asyncio
async def test_engage_tactic_mapping(client, mock_db_pool):
    tactics = [
        ("discovery", "EAC0004 — Pocket Litter"),
        ("credential-access", "EAC0005 — Lure"),
        ("lateral-movement", "EAC0014 — Network Manipulation"),
        ("execution", "EAC0006 — Behavioral Analytics"),
        ("persistence", "EAC0021 — Monitoring"),
        ("exfiltration", "EAC0003 — Burn Notice"),
        ("unknown-tactic", "EAC0021 — Monitoring"),  # fallback
    ]

    mock_rows = [
        {"tid": f"T{i}", "tname": f"Test-{tactic}", "tactic": tactic,
         "times_observed": 1, "sessions": 1, "kill_chains": 0,
         "avg_dur": 60, "last_seen": datetime.now(timezone.utc)}
        for i, (tactic, _) in enumerate(tactics)
    ]
    mock_db_pool.conn.fetch = AsyncMock(return_value=mock_rows)
    dashboard.db_pool = mock_db_pool

    resp = await client.get("/api/engage")
    data = resp.json()
    for i, (tactic, expected_activity) in enumerate(tactics):
        actual = data["engage"][i]["engage_activity"]
        assert actual == expected_activity, f"Tactic '{tactic}': expected {expected_activity}, got {actual}"


# ── GET /api/top-ips — no DB ───────────────────────

@pytest.mark.asyncio
async def test_top_ips_no_db(client):
    resp = await client.get("/api/top-ips")
    assert resp.status_code == 503
    data = resp.json()
    assert data["ips"] == []


# ── POST /api/test/inject — NATS connected ─────────

@pytest.mark.asyncio
async def test_inject_with_nats(client, mock_nats):
    dashboard.nc = mock_nats

    resp = await client.post("/api/test/inject")
    data = resp.json()
    assert data["status"] == "published_to_nats"
    assert "event_id" in data
    mock_nats.publish.assert_called_once()

    # Verify the published subject
    call_args = mock_nats.publish.call_args
    subject = call_args[0][0]
    assert subject.startswith("cicdecoy.decoy.events.")


# ── POST /api/test/inject — NATS down ──────────────

@pytest.mark.asyncio
async def test_inject_without_nats(client):
    """When NATS is down, inject returns an error (pipeline unavailable)."""
    dashboard.nc = None

    resp = await client.post("/api/test/inject")
    data = resp.json()
    assert data["status"] == "error"
    assert "NATS" in data.get("detail", "")


# ── POST /api/test/inject — event structure ────────

@pytest.mark.asyncio
async def test_inject_event_structure(client, mock_nats):
    """Inject with NATS publishes a well-formed raw event."""
    dashboard.nc = mock_nats

    resp = await client.post("/api/test/inject")
    data = resp.json()
    assert data["status"] == "published_to_nats"

    # Verify the published payload structure (raw event — CTI pipeline adds
    # mitre_techniques and severity during enrichment)
    call_args = mock_nats.publish.call_args
    payload = json.loads(call_args[0][1])

    # Required fields for raw events
    assert "event_id" in payload
    assert "timestamp" in payload
    assert "decoy_name" in payload
    assert "decoy_tier" in payload
    assert "session_id" in payload
    assert "event_type" in payload
    assert "source_ip" in payload
    assert "source_port" in payload
    assert "raw_data" in payload
    assert "command" in payload["raw_data"]

    # Decoy tier must be 2 or 3
    assert payload["decoy_tier"] in (2, 3)

    # Subject should match event type
    subject = call_args[0][0]
    assert subject.startswith("cicdecoy.decoy.events.")


# ── Event buffer ring behavior ──────────────────────

@pytest.mark.asyncio
async def test_event_buffer_ring(client):
    """Buffer (deque) should cap at MAX_BUFFER and drop oldest events."""
    # Test deque maxlen behavior directly — inject requires NATS.
    for i in range(dashboard.MAX_BUFFER + 50):
        dashboard.event_buffer.append({"seq": i, "payload": {}})

    assert len(dashboard.event_buffer) == dashboard.MAX_BUFFER
    # Oldest events should have been evicted; newest remain
    assert dashboard.event_buffer[0]["seq"] == 50


# ── SSE subscriber fan-out ──────────────────────────

@pytest.mark.asyncio
async def test_sse_fanout():
    """Events should be pushed to all SSE subscriber queues."""
    q1 = asyncio.Queue(maxsize=100)
    q2 = asyncio.Queue(maxsize=100)
    dashboard.subscribers.update([q1, q2])

    event = make_nats_event()
    msg = MagicMock()
    msg.data = json.dumps(event).encode()
    msg.subject = "cicdecoy.decoy.events.command"

    await dashboard.nats_handler(msg)

    assert not q1.empty()
    assert not q2.empty()
    ev1 = q1.get_nowait()
    ev2 = q2.get_nowait()
    assert ev1["payload"]["event_id"] == event["event_id"]
    assert ev2["payload"]["event_id"] == event["event_id"]


# ── SSE drops full queues gracefully ────────────────

@pytest.mark.asyncio
async def test_sse_full_queue_dropped():
    """A full subscriber queue should be dropped, not crash the handler."""
    full_q = asyncio.Queue(maxsize=1)
    full_q.put_nowait({"dummy": True})  # fill it
    healthy_q = asyncio.Queue(maxsize=100)
    dashboard.subscribers.update([full_q, healthy_q])

    msg = MagicMock()
    msg.data = json.dumps(make_nats_event()).encode()
    msg.subject = "cicdecoy.decoy.events.command"

    await dashboard.nats_handler(msg)

    # Full queue should be removed from subscribers
    assert full_q not in dashboard.subscribers
    # Healthy queue should still be there and have the event
    assert healthy_q in dashboard.subscribers
    assert not healthy_q.empty()


# ── NATS handler tolerates bad JSON ────────────────

@pytest.mark.asyncio
async def test_nats_handler_bad_json():
    """Non-JSON NATS messages should not crash the handler."""
    msg = MagicMock()
    msg.data = b"this is not json {{"
    msg.subject = "cicdecoy.decoy.events.garbage"

    await dashboard.nats_handler(msg)

    assert len(dashboard.event_buffer) == 1
    assert "raw" in dashboard.event_buffer[0]["payload"]


# ── NATS handler tolerates binary garbage ──────────

@pytest.mark.asyncio
async def test_nats_handler_binary():
    msg = MagicMock()
    msg.data = b"\x00\xff\xfe\x80binary"
    msg.subject = "cicdecoy.decoy.events.binary"

    await dashboard.nats_handler(msg)
    assert len(dashboard.event_buffer) == 1


# ── Inject generates varied data ───────────────────

@pytest.mark.asyncio
async def test_inject_generates_variety(client, mock_nats):
    """Multiple injects should produce varied source IPs and commands."""
    dashboard.nc = mock_nats
    seen_ips = set()
    seen_commands = set()
    seen_decoys = set()

    for _ in range(50):
        await client.post("/api/test/inject")

    # Extract events from the NATS publish calls
    for call in mock_nats.publish.call_args_list:
        p = json.loads(call[0][1])
        seen_ips.add(p["source_ip"])
        seen_commands.add(p["raw_data"].get("command", ""))
        seen_decoys.add(p["decoy_name"])

    # With 50 samples from the random pools, we should see variety
    assert len(seen_ips) > 5, f"Expected IP variety, got {len(seen_ips)}"
    assert len(seen_commands) > 5, f"Expected command variety, got {len(seen_commands)}"
    assert len(seen_decoys) >= 1, "Expected at least 1 decoy name"
