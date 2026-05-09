# Dashboard API Reference

The CI/CDecoy dashboard exposes a REST API for querying session data, threat intelligence, and platform health. It also provides a Server-Sent Events (SSE) endpoint for real-time event streaming.

**Base URL:** `http://<dashboard-host>:8080`

---

## Authentication

All API endpoints (except `/healthz` and `/metrics`) require authentication via API key.

| Method | Format |
|--------|--------|
| Header | `X-API-Key: <key>` |
| Query parameter | `?api_key=<key>` (for SSE clients that cannot set headers) |

The API key is configured via the `DASHBOARD_API_KEY` environment variable. In development mode, an ephemeral key is generated and printed to stdout on startup.

**Rate Limiting:** 100 requests per 60 seconds per key (sliding window). Returns `429 Too Many Requests` when exceeded.

---

## Endpoints

### Health Check

```
GET /healthz
```

Kubernetes liveness probe. No authentication required.

**Response:**
```json
{"status": "ok"}
```

---

### Quick Stats

```
GET /api/stats
```

Aggregated platform statistics.

**Response:**
```json
{
  "total_sessions": 1245,
  "active_sessions": 12,
  "total_events": 45678,
  "unique_ips": 342,
  "high_sev_24h": 23,
  "honeytokens_triggered": 5,
  "kill_chains": 3,
  "db_connected": true,
  "nats_connected": true
}
```

| Field | Description |
|-------|-------------|
| `total_sessions` | All-time distinct sessions |
| `active_sessions` | Sessions with activity in the last hour |
| `total_events` | Events in last 24 hours |
| `unique_ips` | Unique routable source IPs (excludes RFC1918) |
| `high_sev_24h` | High/critical severity events in last 24h |
| `honeytokens_triggered` | All-time honeytoken trigger count |
| `kill_chains` | Sessions with 3+ distinct MITRE tactics |

---

### Sessions List

```
GET /api/sessions?limit=50&offset=0
```

Paginated session list with summary statistics.

| Parameter | Type | Default | Max | Description |
|-----------|------|---------|-----|-------------|
| `limit` | int | 50 | 1000 | Results per page |
| `offset` | int | 0 | — | Pagination offset |

**Response:**
```json
{
  "sessions": [
    {
      "session_id": "sess-a1b2c3d4",
      "decoy_name": "ssh-decoy-01",
      "decoy_tier": 2,
      "source_ip": "203.0.113.42",
      "auth_username": "root",
      "start_time": "2026-04-28T10:30:45Z",
      "end_time": "2026-04-28T10:45:30Z",
      "duration_seconds": 885,
      "command_count": 34,
      "max_severity": "high",
      "mitre_techniques": [
        {"technique_id": "T1033", "technique_name": "System Owner/User Discovery", "tactic": "discovery"}
      ],
      "attack_phases": ["discovery", "lateral-movement", "persistence"],
      "kill_chain_detected": true
    }
  ],
  "offset": 0,
  "limit": 50,
  "total": 1245
}
```

---

### Session Events

```
GET /api/sessions/{session_id}/events?limit=200&offset=0
```

All events for a session, excluding `command.response` events. Chronological order.

| Parameter | Type | Default | Max | Description |
|-----------|------|---------|-----|-------------|
| `limit` | int | 200 | 1000 | Results per page |
| `offset` | int | 0 | — | Pagination offset |

**Response:**
```json
{
  "session_id": "sess-a1b2c3d4",
  "events": [
    {
      "event_id": "evt-001",
      "timestamp": "2026-04-28T10:30:45.123Z",
      "event_type": "command.exec",
      "severity": "medium",
      "source_ip": "203.0.113.42",
      "command": "cat /etc/passwd",
      "raw_data": {"client_ip": "203.0.113.42", "username": "root", "command": "cat /etc/passwd"},
      "mitre_techniques": [
        {"technique_id": "T1087", "technique_name": "Account Discovery", "tactic": "discovery"}
      ],
      "tool_signatures": []
    }
  ],
  "offset": 0,
  "limit": 200,
  "total": 45
}
```

---

### Session Replay

```
GET /api/sessions/{session_id}/replay
```

Complete session with command-response pairing and timing deltas for terminal playback.

**Response:**
```json
{
  "session_id": "sess-a1b2c3d4",
  "summary": {
    "start_time": "2026-04-28T10:30:45Z",
    "end_time": "2026-04-28T10:45:30Z",
    "duration_seconds": 885,
    "command_count": 12,
    "max_severity": "high",
    "decoy_name": "ssh-decoy-01",
    "decoy_tier": 2,
    "source_ip": "203.0.113.42",
    "username": "root",
    "mitre_techniques": [...],
    "attack_phases": ["discovery", "privilege-escalation"],
    "kill_chain_detected": false
  },
  "events": [
    {
      "event_id": "evt-001",
      "timestamp": "2026-04-28T10:30:45.123Z",
      "event_type": "command.exec",
      "command": "whoami",
      "response": "root",
      "delta_ms": null,
      "severity": "medium",
      "mitre_techniques": [...]
    },
    {
      "event_id": "evt-002",
      "timestamp": "2026-04-28T10:30:47.500Z",
      "event_type": "command.exec",
      "command": "cat /etc/passwd",
      "response": "root:x:0:0:...",
      "delta_ms": 2377,
      "severity": "medium",
      "mitre_techniques": [...]
    }
  ]
}
```

`delta_ms` is milliseconds since the previous event (`null` for the first event). Includes `command.response` events (unlike the `/events` endpoint).

---

### Recent Events

```
GET /api/events?limit=100&offset=0&severity=high
```

Recent events across all sessions.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | int | 100 | Results per page (max 1000) |
| `offset` | int | 0 | Pagination offset |
| `severity` | string | — | Filter: `info`, `low`, `medium`, `high`, `critical` |

---

### MITRE Technique Heatmap

```
GET /api/mitre?limit=30&offset=0
```

Top MITRE ATT&CK techniques observed in the last 7 days.

**Response:**
```json
{
  "techniques": [
    {
      "technique_id": "T1033",
      "technique_name": "System Owner/User Discovery",
      "tactic": "discovery",
      "total": 87,
      "actors": 12,
      "last_seen": "2026-04-28T10:45:30Z"
    }
  ],
  "total": 156,
  "offset": 0,
  "limit": 30
}
```

`actors` = unique source IPs. Time range: 7 days.

---

### Engage Effectiveness

```
GET /api/engage?limit=100&offset=0
```

MITRE techniques with mapped Engage activities and effectiveness scores.

**Response:**
```json
{
  "engage": [
    {
      "technique_id": "T1033",
      "technique_name": "System Owner/User Discovery",
      "engage_activity": "EAC0004 — Pocket Litter",
      "times_observed": 87,
      "effectiveness": 0.65,
      "last_seen": "2026-04-28T10:45:30Z"
    }
  ]
}
```

Effectiveness score (0.0-1.0) = weighted combination of average session duration (5-min baseline) and kill chain ratio.

---

### Top IPs

```
GET /api/top-ips?hours=24&limit=15
```

Most active source IPs. Excludes non-routable IPs.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `hours` | int | 24 | Time window (1-8760) |
| `limit` | int | 15 | Number of IPs (max 1000) |

**Response:**
```json
{
  "ips": [
    {"source_ip": "203.0.113.42", "events": 342, "max_severity": "high", "sessions": 8}
  ]
}
```

---

### Kill Chain Timelines

```
GET /api/kill-chains?limit=20&offset=0
```

Sessions with 3+ distinct MITRE tactics, with phase progression detail.

**Response:**
```json
{
  "sessions": [
    {
      "session_id": "sess-a1b2c3d4",
      "source_ip": "203.0.113.42",
      "decoy_name": "ssh-decoy-01",
      "duration_seconds": 885,
      "command_count": 34,
      "phase_count": 4,
      "phases": [
        {"phase": "discovery", "index": 0, "techniques": [{"id": "T1033", "name": "System Owner/User Discovery"}]},
        {"phase": "credential-access", "index": 5, "techniques": [...]},
        {"phase": "lateral-movement", "index": 12, "techniques": [...]}
      ]
    }
  ]
}
```

`index` = event position in session where the phase was first observed.

---

### Duration Histogram

```
GET /api/duration-histogram
```

Distribution of session durations.

**Response:**
```json
{
  "buckets": [
    {"label": "0-10s", "count": 234, "lo": 0, "hi": 10},
    {"label": "10-30s", "count": 567, "lo": 10, "hi": 30},
    {"label": "30s-1m", "count": 789, "lo": 30, "hi": 60},
    {"label": "1-5m", "count": 456, "lo": 60, "hi": 300},
    {"label": "5-15m", "count": 123, "lo": 300, "hi": 900},
    {"label": "15-60m", "count": 45, "lo": 900, "hi": 3600},
    {"label": "60m+", "count": 12, "lo": 3600, "hi": null}
  ],
  "total_sessions": 2226,
  "avg_seconds": 245.3,
  "median_seconds": 156
}
```

---

### Geographic Breakdown

```
GET /api/geo?hours=168
```

Threat activity by country.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `hours` | int | 168 | Time window (1-8760, default 1 week) |

**Response:**
```json
{
  "countries": [
    {
      "country_code": "CN",
      "country_name": "China",
      "sessions": 42,
      "unique_ips": 28,
      "total_commands": 456,
      "avg_duration": 234.5
    }
  ],
  "period_hours": 168
}
```

---

### Server-Sent Events (SSE)

```
GET /api/events/stream?api_key=<key>
```

Live event stream from NATS. Clients receive the last 50 buffered events on connect, then new events in real-time. Keepalive pings every 15 seconds.

**Event Types:**

| Event | Data |
|-------|------|
| `decoy_event` | Full enriched event JSON (see below) |
| `ping` | `"keepalive"` |

**Event Payload:**
```json
{
  "subject": "cicdecoy.enriched.events.command.exec",
  "ts": "2026-04-28T10:30:45.123Z",
  "payload": {
    "event_id": "abc123",
    "event_type": "command.exec",
    "session_id": "sess-1234",
    "source_ip": "203.0.113.42",
    "decoy_name": "ssh-decoy-01",
    "decoy_tier": 2,
    "severity": "medium",
    "raw_data": {"command": "whoami", "response": "root"},
    "mitre_techniques": [{"technique_id": "T1033", "technique_name": "System Owner/User Discovery", "tactic": "discovery"}],
    "tool_signatures": [],
    "geo": {"country": "CN", "city": "Beijing"}
  }
}
```

**Buffer:** 500 events max in memory. New events evict oldest.

---

## Test Endpoints (Development Only)

Disabled when `DASHBOARD_DISABLE_TEST_ENDPOINTS=true`.

```
POST /api/test/inject           # Inject a single random event
POST /api/test/inject-session   # Inject a full multi-phase attack session
```

`inject-session` accepts `?event_count=10` to control session size. Publishes events to NATS with realistic command sequences spanning multiple MITRE tactics.

---

## Error Responses

| Status | Body | Cause |
|--------|------|-------|
| 401 | `{"detail": "Missing or invalid API key"}` | Missing or wrong `X-API-Key` |
| 429 | `{"detail": "Rate limit exceeded — try again later"}` | >100 requests/minute |
| 503 | `{"error": "DB not connected"}` | Database unavailable |

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DASHBOARD_API_KEY` | (auto-generated) | Shared API key |
| `DASHBOARD_REQUIRE_AUTH` | `false` | Enforce auth in dev mode |
| `DASHBOARD_DISABLE_TEST_ENDPOINTS` | `false` | Disable test injection endpoints |
| `DASHBOARD_HSTS` | (unset) | Enable HSTS header |
| `CORS_ORIGINS` | `""` | Comma-separated allowed CORS origins |
| `NATS_URL` | `nats://localhost:4222` | NATS server URL |
| `DB_DSN` | `postgresql://cicdecoy:cicdecoy@localhost:5432/cicdecoy` | Database connection string |
| `NATS_SUBJECTS` | `cicdecoy.enriched.events.>` | NATS subscription pattern |

---

## Prometheus Metrics

Exposed at `GET /metrics` (no auth required; restrict via NetworkPolicy in production).

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `cicdecoy_dashboard_requests_total` | counter | endpoint, method | Total API requests |
| `cicdecoy_dashboard_sse_connections` | gauge | — | Active SSE connections |
| `cicdecoy_dashboard_event_buffer_size` | gauge | — | In-memory event buffer size |
| `cicdecoy_dashboard_db_query_seconds` | histogram | query | Database query latency |
