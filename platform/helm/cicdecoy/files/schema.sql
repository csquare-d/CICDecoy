-- CI/CDecoy — Database Schema (MVP)
-- Applied automatically by docker-entrypoint-initdb.d

-- Enable TimescaleDB
CREATE EXTENSION IF NOT EXISTS timescaledb;

-- ── Core events table ───────────────────────────────
CREATE TABLE IF NOT EXISTS decoy_events (
    event_id        TEXT NOT NULL,
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    decoy_name      TEXT NOT NULL,
    decoy_tier      INTEGER NOT NULL DEFAULT 0,
    session_id      TEXT NOT NULL DEFAULT '',
    event_type      TEXT NOT NULL DEFAULT 'unknown',
    source_ip       TEXT,
    source_port     INTEGER DEFAULT 0,
    severity        TEXT DEFAULT 'info',
    raw_data        JSONB DEFAULT '{}',

    -- Enrichment fields (populated later by enrichment service)
    geo             JSONB DEFAULT '{}',
    mitre_techniques JSONB DEFAULT '[]',
    threat_feeds    JSONB DEFAULT '[]',
    tool_signatures JSONB DEFAULT '[]',
    tags            JSONB DEFAULT '[]',

    PRIMARY KEY (event_id, timestamp)
);

-- Convert to hypertable
SELECT create_hypertable('decoy_events', 'timestamp',
    chunk_time_interval => INTERVAL '1 day',
    if_not_exists => TRUE
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_events_session
    ON decoy_events (session_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_source_ip
    ON decoy_events (source_ip, timestamp DESC)
    WHERE source_ip IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_events_severity
    ON decoy_events (severity, timestamp DESC)
    WHERE severity IN ('high', 'critical');
CREATE INDEX IF NOT EXISTS idx_events_type
    ON decoy_events (event_type, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_decoy
    ON decoy_events (decoy_name, timestamp DESC);

-- Retention: keep 90 days
SELECT add_retention_policy('decoy_events',
    drop_after => INTERVAL '90 days',
    if_not_exists => TRUE
);

-- ── Falco runtime security alerts ──────────────────
CREATE TABLE IF NOT EXISTS falco_alerts (
    alert_id        TEXT NOT NULL,
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    rule_name       TEXT NOT NULL,
    priority        TEXT NOT NULL DEFAULT 'WARNING',
    pod_name        TEXT,
    namespace       TEXT,
    container_name  TEXT,
    process_name    TEXT,
    command_line    TEXT,
    output          TEXT,
    raw_event       JSONB DEFAULT '{}',

    -- Correlation with decoy sessions
    correlated_session_id TEXT,
    decoy_name      TEXT,

    PRIMARY KEY (alert_id, timestamp)
);

SELECT create_hypertable('falco_alerts', 'timestamp',
    chunk_time_interval => INTERVAL '1 day',
    if_not_exists => TRUE
);

CREATE INDEX IF NOT EXISTS idx_falco_pod
    ON falco_alerts (pod_name, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_falco_priority
    ON falco_alerts (priority, timestamp DESC)
    WHERE priority IN ('CRITICAL', 'HIGH');
CREATE INDEX IF NOT EXISTS idx_falco_session
    ON falco_alerts (correlated_session_id, timestamp DESC)
    WHERE correlated_session_id IS NOT NULL;

SELECT add_retention_policy('falco_alerts',
    drop_after => INTERVAL '90 days',
    if_not_exists => TRUE
);

-- ── Engage outcomes (per session) ──────────────────
CREATE TABLE IF NOT EXISTS engage_outcomes (
    session_id          TEXT PRIMARY KEY,
    decoy_name          TEXT NOT NULL,
    timestamp           TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Engage classifications (JSONB arrays)
    activities          JSONB DEFAULT '[]',
    approaches          JSONB DEFAULT '[]',
    goals               JSONB DEFAULT '[]',

    -- Operational metrics
    engagement_duration DOUBLE PRECISION DEFAULT 0,
    commands_captured   INTEGER DEFAULT 0,
    credentials_harvested INTEGER DEFAULT 0,
    honeytokens_triggered INTEGER DEFAULT 0,
    ttps_observed       INTEGER DEFAULT 0,
    tools_identified    INTEGER DEFAULT 0,
    lateral_movement    BOOLEAN DEFAULT FALSE,
    deception_maintained BOOLEAN DEFAULT TRUE,
    intelligence_value  TEXT DEFAULT 'low',

    -- Falco correlation
    escape_attempted    BOOLEAN DEFAULT FALSE,
    falco_alert_count   INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_engage_value
    ON engage_outcomes (intelligence_value)
    WHERE intelligence_value IN ('high', 'critical');
CREATE INDEX IF NOT EXISTS idx_engage_escape
    ON engage_outcomes (escape_attempted)
    WHERE escape_attempted = TRUE;

-- ── Useful queries ──────────────────────────────────

-- Recent events
-- SELECT * FROM decoy_events ORDER BY timestamp DESC LIMIT 20;

-- Events per session
-- SELECT session_id, COUNT(*), MIN(timestamp), MAX(timestamp)
-- FROM decoy_events GROUP BY session_id ORDER BY MAX(timestamp) DESC;

-- Top source IPs
-- SELECT source_ip, COUNT(*) as events
-- FROM decoy_events WHERE source_ip IS NOT NULL
-- GROUP BY source_ip ORDER BY events DESC LIMIT 10;

-- Falco alerts correlated with sessions
-- SELECT f.timestamp, f.rule_name, f.priority, f.pod_name,
--        f.command_line, f.correlated_session_id
-- FROM falco_alerts f ORDER BY f.timestamp DESC LIMIT 20;

-- Engage effectiveness summary
-- SELECT intelligence_value, COUNT(*) as sessions,
--        AVG(engagement_duration) as avg_duration,
--        SUM(ttps_observed) as total_ttps,
--        AVG(CASE WHEN deception_maintained THEN 1 ELSE 0 END) * 100
--          as deception_success_pct
-- FROM engage_outcomes GROUP BY intelligence_value;

-- Sessions where attacker detected the honeypot
-- SELECT e.session_id, e.decoy_name, e.engagement_duration,
--        e.commands_captured, f.rule_name, f.command_line
-- FROM engage_outcomes e
-- JOIN falco_alerts f ON f.correlated_session_id = e.session_id
-- WHERE e.escape_attempted = TRUE
-- ORDER BY e.timestamp DESC;
