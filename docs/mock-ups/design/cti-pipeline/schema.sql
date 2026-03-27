-- CI/CDecoy — TimescaleDB Schema
-- cti/storage/schema.sql
--
-- Stores all enriched decoy interaction data. Uses TimescaleDB
-- hypertables for efficient time-series queries (e.g., "show me
-- all lateral movement attempts in the last 24 hours").

-- ─────────────────────────────────────────────────────────
--  Core Events Table
-- ─────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS decoy_events (
    event_id        TEXT NOT NULL,
    timestamp       TIMESTAMPTZ NOT NULL,
    decoy_name      TEXT NOT NULL,
    decoy_tier      INTEGER NOT NULL,
    session_id      TEXT NOT NULL,
    event_type      TEXT NOT NULL,       -- connection | auth | command | alert | session

    -- Source information
    source_ip       INET,
    source_port     INTEGER,

    -- Enrichment data (JSONB for flexible querying)
    geo             JSONB DEFAULT '{}',
    mitre_techniques JSONB DEFAULT '[]',
    threat_feeds    JSONB DEFAULT '[]',
    tool_signatures JSONB DEFAULT '[]',

    -- Classification
    severity        TEXT DEFAULT 'info', -- info | low | medium | high | critical
    tags            JSONB DEFAULT '[]',

    -- Raw event payload
    raw_data        JSONB DEFAULT '{}',

    PRIMARY KEY (event_id, timestamp)
);

-- Convert to TimescaleDB hypertable (partitioned by time)
SELECT create_hypertable('decoy_events', 'timestamp',
    chunk_time_interval => INTERVAL '1 day',
    if_not_exists => TRUE
);

-- ─────────────────────────────────────────────────────────
--  Sessions Table (aggregated per-session view)
-- ─────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS decoy_sessions (
    session_id      TEXT PRIMARY KEY,
    decoy_name      TEXT NOT NULL,
    decoy_tier      INTEGER NOT NULL,
    source_ip       INET,

    -- Timing
    start_time      TIMESTAMPTZ NOT NULL,
    end_time        TIMESTAMPTZ,
    duration_seconds DOUBLE PRECISION,

    -- Authentication
    auth_username   TEXT,
    auth_method     TEXT,     -- password | pubkey
    auth_attempts   INTEGER DEFAULT 0,

    -- Activity summary
    command_count   INTEGER DEFAULT 0,
    unique_commands INTEGER DEFAULT 0,
    commands        JSONB DEFAULT '[]',   -- Full command list

    -- Enrichment summary
    mitre_techniques JSONB DEFAULT '[]',  -- Deduplicated across all commands
    tools_detected  JSONB DEFAULT '[]',
    max_severity    TEXT DEFAULT 'info',

    -- Kill chain analysis
    attack_phases   JSONB DEFAULT '[]',   -- ["discovery", "credential", "lateral"]
    kill_chain_detected BOOLEAN DEFAULT FALSE,

    -- Geo
    geo             JSONB DEFAULT '{}',

    -- Honeytokens
    honeytokens_accessed JSONB DEFAULT '[]',

    -- Metadata
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

-- ─────────────────────────────────────────────────────────
--  IOC Table (extracted indicators of compromise)
-- ─────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS ioc_indicators (
    indicator_id    TEXT PRIMARY KEY,
    type            TEXT NOT NULL,        -- ipv4 | ipv6 | domain | hash | url
    value           TEXT NOT NULL,
    confidence      INTEGER DEFAULT 50,   -- 0-100
    severity        TEXT DEFAULT 'medium',

    -- Provenance
    first_seen      TIMESTAMPTZ NOT NULL,
    last_seen       TIMESTAMPTZ NOT NULL,
    sighting_count  INTEGER DEFAULT 1,
    source_decoys   JSONB DEFAULT '[]',   -- Which decoys observed this

    -- Context
    mitre_techniques JSONB DEFAULT '[]',
    tools_associated JSONB DEFAULT '[]',
    geo             JSONB DEFAULT '{}',

    -- STIX reference
    stix_indicator_id TEXT,

    -- Lifecycle
    active          BOOLEAN DEFAULT TRUE,
    expires_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE(type, value)
);

-- ─────────────────────────────────────────────────────────
--  Honeytoken Triggers
-- ─────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS honeytoken_triggers (
    trigger_id      TEXT PRIMARY KEY,
    token_name      TEXT NOT NULL,        -- Reference to HoneyToken CRD name
    token_type      TEXT NOT NULL,        -- aws-credential | kubeconfig | etc.
    trigger_time    TIMESTAMPTZ NOT NULL,

    -- Who triggered it
    session_id      TEXT,
    source_ip       INET,
    decoy_name      TEXT,

    -- What happened
    access_type     TEXT,                 -- file_read | api_call | network_egress
    details         JSONB DEFAULT '{}',

    -- Alert status
    alerted         BOOLEAN DEFAULT FALSE,
    alert_channels  JSONB DEFAULT '[]',

    created_at      TIMESTAMPTZ DEFAULT NOW()
);

SELECT create_hypertable('honeytoken_triggers', 'trigger_time',
    chunk_time_interval => INTERVAL '7 days',
    if_not_exists => TRUE
);

-- ─────────────────────────────────────────────────────────
--  Decoy Health & Metrics
-- ─────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS decoy_health (
    check_time      TIMESTAMPTZ NOT NULL,
    decoy_name      TEXT NOT NULL,
    decoy_tier      INTEGER NOT NULL,
    status          TEXT NOT NULL,        -- healthy | degraded | offline
    pod_ip          INET,

    -- Fingerprint validation results
    fingerprint_valid BOOLEAN,
    nmap_os_match    TEXT,
    banner_correct   BOOLEAN,
    timing_realistic BOOLEAN,

    -- Resource usage
    cpu_usage_millicores INTEGER,
    memory_usage_bytes   BIGINT,

    -- Activity metrics
    active_sessions  INTEGER DEFAULT 0,
    total_connections_24h INTEGER DEFAULT 0,

    PRIMARY KEY (decoy_name, check_time)
);

SELECT create_hypertable('decoy_health', 'check_time',
    chunk_time_interval => INTERVAL '1 day',
    if_not_exists => TRUE
);

-- ─────────────────────────────────────────────────────────
--  Indexes
-- ─────────────────────────────────────────────────────────

-- Events: query by session, source IP, severity, MITRE technique
CREATE INDEX idx_events_session ON decoy_events (session_id, timestamp DESC);
CREATE INDEX idx_events_source_ip ON decoy_events (source_ip, timestamp DESC);
CREATE INDEX idx_events_severity ON decoy_events (severity, timestamp DESC)
    WHERE severity IN ('high', 'critical');
CREATE INDEX idx_events_type ON decoy_events (event_type, timestamp DESC);
CREATE INDEX idx_events_decoy ON decoy_events (decoy_name, timestamp DESC);

-- GIN indexes for JSONB queries
CREATE INDEX idx_events_mitre ON decoy_events USING GIN (mitre_techniques);
CREATE INDEX idx_events_tools ON decoy_events USING GIN (tool_signatures);
CREATE INDEX idx_events_tags ON decoy_events USING GIN (tags);

-- Sessions: query by source IP, severity, attack phase
CREATE INDEX idx_sessions_source_ip ON decoy_sessions (source_ip);
CREATE INDEX idx_sessions_severity ON decoy_sessions (max_severity)
    WHERE max_severity IN ('high', 'critical');
CREATE INDEX idx_sessions_kill_chain ON decoy_sessions (kill_chain_detected)
    WHERE kill_chain_detected = TRUE;

-- IOCs: query by type, value, activity status
CREATE INDEX idx_iocs_active ON ioc_indicators (type, severity)
    WHERE active = TRUE;
CREATE INDEX idx_iocs_last_seen ON ioc_indicators (last_seen DESC);

-- ─────────────────────────────────────────────────────────
--  Continuous Aggregates (materialized views)
-- ─────────────────────────────────────────────────────────

-- Hourly event summary per decoy
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

-- Refresh policy: update every 30 minutes, cover last 2 hours
SELECT add_continuous_aggregate_policy('decoy_events_hourly',
    start_offset => INTERVAL '2 hours',
    end_offset => INTERVAL '30 minutes',
    schedule_interval => INTERVAL '30 minutes',
    if_not_exists => TRUE
);

-- Daily MITRE technique frequency
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

SELECT add_continuous_aggregate_policy('mitre_technique_daily',
    start_offset => INTERVAL '2 days',
    end_offset => INTERVAL '1 hour',
    schedule_interval => INTERVAL '1 hour',
    if_not_exists => TRUE
);

-- ─────────────────────────────────────────────────────────
--  Retention Policies
-- ─────────────────────────────────────────────────────────

-- Keep raw events for 90 days
SELECT add_retention_policy('decoy_events',
    drop_after => INTERVAL '90 days',
    if_not_exists => TRUE
);

-- Keep health checks for 30 days
SELECT add_retention_policy('decoy_health',
    drop_after => INTERVAL '30 days',
    if_not_exists => TRUE
);

-- Keep honeytoken triggers for 1 year (high-value intel)
SELECT add_retention_policy('honeytoken_triggers',
    drop_after => INTERVAL '365 days',
    if_not_exists => TRUE
);

-- ─────────────────────────────────────────────────────────
--  Useful Queries (for dashboard / CTI output)
-- ─────────────────────────────────────────────────────────

-- Top attacking IPs in last 24 hours
-- SELECT source_ip, COUNT(*) as events, MAX(severity) as max_sev,
--        COUNT(DISTINCT session_id) as sessions
-- FROM decoy_events
-- WHERE timestamp > NOW() - INTERVAL '24 hours'
-- GROUP BY source_ip
-- ORDER BY events DESC
-- LIMIT 20;

-- Active kill chains (multi-phase attacks in progress)
-- SELECT session_id, source_ip, decoy_name,
--        attack_phases, command_count, duration_seconds
-- FROM decoy_sessions
-- WHERE kill_chain_detected = TRUE
--   AND end_time IS NULL
-- ORDER BY start_time DESC;

-- MITRE technique heatmap for the last 7 days
-- SELECT technique_id, SUM(observation_count) as total,
--        SUM(unique_actors) as actors
-- FROM mitre_technique_daily
-- WHERE bucket > NOW() - INTERVAL '7 days'
-- GROUP BY technique_id
-- ORDER BY total DESC;
