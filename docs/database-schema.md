# Database Schema Reference

CI/CDecoy uses [TimescaleDB](https://www.timescale.com/) (PostgreSQL extension) for time-series event storage. The schema is initialized by the CTI pipeline on first startup.

**Connection:** `postgresql://cicdecoy:${password}@cicdecoy-timescaledb:5432/cicdecoy?sslmode=require`

---

## Tables

### decoy_events (hypertable)

The primary event store. Every decoy interaction is recorded as a row. Partitioned by timestamp with 1-day chunks.

```sql
CREATE TABLE IF NOT EXISTS decoy_events (
    event_id         TEXT NOT NULL,
    timestamp        TIMESTAMPTZ NOT NULL,
    decoy_name       TEXT NOT NULL,
    decoy_tier       INTEGER NOT NULL,
    session_id       TEXT NOT NULL,
    event_type       TEXT NOT NULL,
    source_ip        INET,
    source_port      INTEGER,
    severity         TEXT DEFAULT 'info',
    mitre_techniques JSONB DEFAULT '[]',
    tool_signatures  JSONB DEFAULT '[]',
    tags             JSONB DEFAULT '[]',
    geo              JSONB DEFAULT '{}',
    raw_data         JSONB DEFAULT '{}',
    PRIMARY KEY (event_id, timestamp)
);

SELECT create_hypertable('decoy_events', 'timestamp',
    chunk_time_interval => INTERVAL '1 day',
    if_not_exists => TRUE
);
```

| Column | Type | Description |
|--------|------|-------------|
| `event_id` | TEXT | Unique event identifier (UUID) |
| `timestamp` | TIMESTAMPTZ | When the event occurred |
| `decoy_name` | TEXT | Name of the decoy that produced this event |
| `decoy_tier` | INTEGER | Fidelity tier (1=beacon, 2=scripted, 3=adaptive) |
| `session_id` | TEXT | Groups events from the same attacker session |
| `event_type` | TEXT | Event classification (see Event Types below) |
| `source_ip` | INET | Attacker's IP address |
| `source_port` | INTEGER | Attacker's source port |
| `severity` | TEXT | `info`, `low`, `medium`, `high`, `critical` |
| `mitre_techniques` | JSONB | Array of `{technique_id, technique_name, tactic}` objects |
| `tool_signatures` | JSONB | Array of detected tool names (e.g., `["nmap", "hydra"]`) |
| `tags` | JSONB | Array of classification tags |
| `geo` | JSONB | GeoIP data: `{country, country_name, city, asn, org, latitude, longitude}` |
| `raw_data` | JSONB | Full event payload (command, response, credentials, etc.) |

**Event Types:**
- `connection.new` — TCP connection established
- `connection.error` — Connection-level error
- `auth.attempt` / `auth.success` / `auth.failure` — Authentication events
- `session.start` / `session.end` / `session.error` — Session lifecycle
- `command.exec` / `command.response` — Command execution and output
- `file.read` / `file.write` / `file.upload` — File operations
- `sftp.*` — SFTP subsystem events
- `scp.*` — SCP transfer events
- `tunnel.attempt` — Port forwarding requests
- `falco.escape` — Injected by Falco correlator when container escape detected
- `honeytoken.triggered` — Honeytoken access detected

### decoy_sessions

Aggregated per-session view, updated on session close by the CTI pipeline.

```sql
CREATE TABLE IF NOT EXISTS decoy_sessions (
    session_id           TEXT PRIMARY KEY,
    decoy_name           TEXT NOT NULL,
    decoy_tier           INTEGER NOT NULL,
    source_ip            INET,
    start_time           TIMESTAMPTZ NOT NULL,
    end_time             TIMESTAMPTZ,
    duration_seconds     DOUBLE PRECISION,
    auth_username        TEXT,
    auth_method          TEXT,
    auth_attempts        INTEGER DEFAULT 0,
    command_count        INTEGER DEFAULT 0,
    unique_commands      INTEGER DEFAULT 0,
    commands             JSONB DEFAULT '[]',
    mitre_techniques     JSONB DEFAULT '[]',
    tools_detected       JSONB DEFAULT '[]',
    max_severity         TEXT DEFAULT 'info',
    attack_phases        JSONB DEFAULT '[]',
    kill_chain_detected  BOOLEAN DEFAULT FALSE,
    geo                  JSONB DEFAULT '{}',
    honeytokens_accessed JSONB DEFAULT '[]',
    created_at           TIMESTAMPTZ DEFAULT NOW(),
    updated_at           TIMESTAMPTZ DEFAULT NOW()
);
```

### ioc_indicators

Extracted indicators of compromise with sighting tracking.

```sql
CREATE TABLE IF NOT EXISTS ioc_indicators (
    indicator_id      TEXT PRIMARY KEY,
    type              TEXT NOT NULL,        -- ip, domain, hash, url, tool, credential
    value             TEXT NOT NULL,
    confidence        INTEGER DEFAULT 50,   -- 0-100
    severity          TEXT DEFAULT 'medium',
    first_seen        TIMESTAMPTZ NOT NULL,
    last_seen         TIMESTAMPTZ NOT NULL,
    sighting_count    INTEGER DEFAULT 1,
    source_decoys     JSONB DEFAULT '[]',
    mitre_techniques  JSONB DEFAULT '[]',
    tools_associated  JSONB DEFAULT '[]',
    geo               JSONB DEFAULT '{}',
    stix_indicator_id TEXT,
    active            BOOLEAN DEFAULT TRUE,
    expires_at        TIMESTAMPTZ,
    created_at        TIMESTAMPTZ DEFAULT NOW(),
    updated_at        TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(type, value)
);
```

### honeytoken_triggers (hypertable)

Records every access to a deployed honeytoken. Partitioned by trigger_time with 7-day chunks.

```sql
CREATE TABLE IF NOT EXISTS honeytoken_triggers (
    trigger_id    TEXT PRIMARY KEY,
    token_name    TEXT NOT NULL,
    token_type    TEXT NOT NULL,
    trigger_time  TIMESTAMPTZ NOT NULL,
    session_id    TEXT,
    source_ip     INET,
    decoy_name    TEXT,
    access_type   TEXT,
    details       JSONB DEFAULT '{}',
    alerted       BOOLEAN DEFAULT FALSE,
    alert_channels JSONB DEFAULT '[]',
    created_at    TIMESTAMPTZ DEFAULT NOW()
);

SELECT create_hypertable('honeytoken_triggers', 'trigger_time',
    chunk_time_interval => INTERVAL '7 days',
    if_not_exists => TRUE
);
```

### decoy_health (hypertable)

Periodic health checks for deployed decoys. Partitioned by check_time with 1-day chunks.

```sql
CREATE TABLE IF NOT EXISTS decoy_health (
    check_time            TIMESTAMPTZ NOT NULL,
    decoy_name            TEXT NOT NULL,
    decoy_tier            INTEGER NOT NULL,
    status                TEXT NOT NULL,
    pod_ip                INET,
    fingerprint_valid     BOOLEAN,
    nmap_os_match         TEXT,
    banner_correct        BOOLEAN,
    timing_realistic      BOOLEAN,
    cpu_usage_millicores  INTEGER,
    memory_usage_bytes    BIGINT,
    active_sessions       INTEGER DEFAULT 0,
    total_connections_24h INTEGER DEFAULT 0,
    PRIMARY KEY (decoy_name, check_time)
);

SELECT create_hypertable('decoy_health', 'check_time',
    chunk_time_interval => INTERVAL '1 day',
    if_not_exists => TRUE
);
```

### engage_outcomes

MITRE Engage session outcomes, written on session close by the engage mapper.

```sql
CREATE TABLE IF NOT EXISTS engage_outcomes (
    session_id             TEXT PRIMARY KEY,
    decoy_name             TEXT NOT NULL,
    timestamp              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    activities             JSONB DEFAULT '[]',
    approaches             JSONB DEFAULT '[]',
    goals                  JSONB DEFAULT '[]',
    engagement_duration    DOUBLE PRECISION,
    commands_captured      INTEGER DEFAULT 0,
    credentials_harvested  INTEGER DEFAULT 0,
    honeytokens_triggered  INTEGER DEFAULT 0,
    ttps_observed          INTEGER DEFAULT 0,
    tools_identified       JSONB DEFAULT '[]',
    lateral_movement       BOOLEAN DEFAULT FALSE,
    deception_maintained   BOOLEAN DEFAULT TRUE,
    intelligence_value     TEXT DEFAULT 'low',
    escape_attempted       BOOLEAN DEFAULT FALSE,
    falco_alert_count      INTEGER DEFAULT 0
);
```

---

## Indexes

```sql
-- Events: fast lookups by session, IP, severity, type, decoy
CREATE INDEX idx_events_session   ON decoy_events (session_id, timestamp DESC);
CREATE INDEX idx_events_source_ip ON decoy_events (source_ip, timestamp DESC);
CREATE INDEX idx_events_severity  ON decoy_events (severity, timestamp DESC)
    WHERE severity IN ('high', 'critical');
CREATE INDEX idx_events_type      ON decoy_events (event_type, timestamp DESC);
CREATE INDEX idx_events_decoy     ON decoy_events (decoy_name, timestamp DESC);

-- JSONB GIN indexes for technique/tool/tag queries
CREATE INDEX idx_events_mitre ON decoy_events USING GIN (mitre_techniques);
CREATE INDEX idx_events_tools ON decoy_events USING GIN (tool_signatures);
CREATE INDEX idx_events_tags  ON decoy_events USING GIN (tags);

-- Sessions
CREATE INDEX idx_sessions_source_ip  ON decoy_sessions (source_ip);
CREATE INDEX idx_sessions_severity   ON decoy_sessions (max_severity)
    WHERE max_severity IN ('high', 'critical');
CREATE INDEX idx_sessions_kill_chain ON decoy_sessions (kill_chain_detected)
    WHERE kill_chain_detected = TRUE;

-- IOCs
CREATE INDEX idx_iocs_active    ON ioc_indicators (type, severity) WHERE active = TRUE;
CREATE INDEX idx_iocs_last_seen ON ioc_indicators (last_seen DESC);
```

---

## Continuous Aggregates

TimescaleDB materialized views for dashboard performance.

### decoy_events_hourly

Hourly rollup of event counts by decoy, type, and severity.

```sql
CREATE MATERIALIZED VIEW IF NOT EXISTS decoy_events_hourly
WITH (timescaledb.continuous) AS
SELECT
    time_bucket('1 hour', timestamp) AS bucket,
    decoy_name,
    event_type,
    severity,
    COUNT(*) AS event_count,
    COUNT(DISTINCT session_id) AS unique_sessions,
    COUNT(DISTINCT source_ip) AS unique_sources
FROM decoy_events
GROUP BY bucket, decoy_name, event_type, severity
WITH NO DATA;
```

### mitre_technique_daily

Daily MITRE technique observation counts.

```sql
CREATE MATERIALIZED VIEW IF NOT EXISTS mitre_technique_daily
WITH (timescaledb.continuous) AS
SELECT
    time_bucket('1 day', timestamp) AS bucket,
    jsonb_array_elements(mitre_techniques)->>'technique_id' AS technique_id,
    COUNT(*) AS observation_count,
    COUNT(DISTINCT source_ip) AS unique_actors,
    COUNT(DISTINCT decoy_name) AS decoys_affected
FROM decoy_events
WHERE jsonb_array_length(mitre_techniques) > 0
GROUP BY bucket, technique_id
WITH NO DATA;
```

---

## Retention

TimescaleDB automatic chunk dropping (configured during schema initialization):

| Table | Retention | Chunk Interval |
|-------|-----------|----------------|
| `decoy_events` | 90 days | 1 day |
| `honeytoken_triggers` | 90 days | 7 days |
| `decoy_health` | 30 days | 1 day |

Retention policies are set via:
```sql
SELECT add_retention_policy('decoy_events', INTERVAL '90 days', if_not_exists => TRUE);
SELECT add_retention_policy('honeytoken_triggers', INTERVAL '90 days', if_not_exists => TRUE);
SELECT add_retention_policy('decoy_health', INTERVAL '30 days', if_not_exists => TRUE);
```

Non-hypertable tables (`decoy_sessions`, `ioc_indicators`, `engage_outcomes`) do not have automatic retention. Clean up manually or via scheduled jobs.

---

## Query Patterns

### Active sessions in the last hour
```sql
SELECT DISTINCT ON (session_id)
    session_id, decoy_name, source_ip, MIN(timestamp) as start
FROM decoy_events
WHERE timestamp > NOW() - INTERVAL '1 hour'
  AND event_type = 'connection.new'
GROUP BY session_id, decoy_name, source_ip;
```

### Top techniques in last 7 days
```sql
SELECT
    t->>'technique_id' AS technique_id,
    t->>'technique_name' AS technique_name,
    COUNT(*) AS count,
    COUNT(DISTINCT source_ip) AS unique_actors
FROM decoy_events,
     jsonb_array_elements(mitre_techniques) t
WHERE timestamp > NOW() - INTERVAL '7 days'
GROUP BY technique_id, technique_name
ORDER BY count DESC
LIMIT 20;
```

### Sessions with kill chain (3+ phases)
```sql
SELECT session_id, source_ip, decoy_name,
       COUNT(DISTINCT t->>'tactic') as phase_count
FROM decoy_events,
     jsonb_array_elements(mitre_techniques) t
WHERE timestamp > NOW() - INTERVAL '7 days'
GROUP BY session_id, source_ip, decoy_name
HAVING COUNT(DISTINCT t->>'tactic') >= 3
ORDER BY phase_count DESC;
```
