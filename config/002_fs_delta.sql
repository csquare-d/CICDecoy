-- CI/CDecoy — Migration 002: Session Filesystem Deltas
-- config/migrations/002_fs_delta.sql
--
-- Stores per-session filesystem mutations from the COW layer.
-- The ssh-decoy emits a session.fs_delta event on session teardown
-- containing everything the attacker created, modified, or deleted.

-- ─────────────────────────────────────────────────────────
--  Filesystem Deltas Table
-- ─────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS session_fs_deltas (
    session_id          TEXT NOT NULL,
    timestamp           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    decoy_name          TEXT NOT NULL,
    source_ip           INET,

    -- Summary counts
    mutation_count      INTEGER NOT NULL DEFAULT 0,
    files_created_count INTEGER NOT NULL DEFAULT 0,
    files_modified_count INTEGER NOT NULL DEFAULT 0,
    paths_deleted_count INTEGER NOT NULL DEFAULT 0,
    dirs_created_count  INTEGER NOT NULL DEFAULT 0,

    -- Full delta payload (structured JSONB for querying)
    files_created       JSONB DEFAULT '[]',   -- [{path, content_preview, size, owner}]
    files_modified      JSONB DEFAULT '[]',   -- [{path, content_preview, size, owner}]
    dirs_created        JSONB DEFAULT '[]',   -- ["/path/to/dir", ...]
    paths_deleted       JSONB DEFAULT '[]',   -- ["/path/deleted", ...]
    mutation_log        JSONB DEFAULT '[]',   -- Ordered [{op, path, time}, ...]

    PRIMARY KEY (session_id, timestamp)
);

SELECT create_hypertable('session_fs_deltas', 'timestamp',
    chunk_time_interval => INTERVAL '7 days',
    if_not_exists => TRUE
);

-- ─────────────────────────────────────────────────────────
--  Add mutation count to sessions table
-- ─────────────────────────────────────────────────────────

ALTER TABLE decoy_sessions
    ADD COLUMN IF NOT EXISTS fs_mutations INTEGER DEFAULT 0;

-- ─────────────────────────────────────────────────────────
--  Indexes for common queries
-- ─────────────────────────────────────────────────────────

-- "Show me all sessions that dropped files"
CREATE INDEX IF NOT EXISTS idx_fs_deltas_files_created
    ON session_fs_deltas (files_created_count)
    WHERE files_created_count > 0;

-- "Find sessions that deleted system files"
CREATE INDEX IF NOT EXISTS idx_fs_deltas_deleted
    ON session_fs_deltas (paths_deleted_count)
    WHERE paths_deleted_count > 0;

-- "What did this IP leave behind across all sessions?"
CREATE INDEX IF NOT EXISTS idx_fs_deltas_source_ip
    ON session_fs_deltas (source_ip);

-- JSONB path queries: "Find sessions that created files in /tmp"
CREATE INDEX IF NOT EXISTS idx_fs_deltas_created_gin
    ON session_fs_deltas USING GIN (files_created jsonb_path_ops);

-- ─────────────────────────────────────────────────────────
--  Useful views
-- ─────────────────────────────────────────────────────────

-- Files dropped by attackers in the last 24 hours
CREATE OR REPLACE VIEW recent_dropped_files AS
SELECT
    d.session_id,
    d.source_ip,
    d.decoy_name,
    d.timestamp,
    f->>'path' AS file_path,
    f->>'content_preview' AS content_preview,
    (f->>'size')::integer AS file_size,
    f->>'owner' AS file_owner
FROM session_fs_deltas d,
     jsonb_array_elements(d.files_created) AS f
WHERE d.timestamp > NOW() - INTERVAL '24 hours'
ORDER BY d.timestamp DESC;

-- Sessions ranked by filesystem activity
CREATE OR REPLACE VIEW sessions_by_fs_activity AS
SELECT
    d.session_id,
    d.source_ip,
    d.decoy_name,
    d.timestamp,
    d.mutation_count,
    d.files_created_count,
    d.files_modified_count,
    d.paths_deleted_count,
    s.command_count,
    s.duration_seconds,
    s.auth_username
FROM session_fs_deltas d
LEFT JOIN decoy_sessions s ON d.session_id = s.session_id
ORDER BY d.mutation_count DESC;