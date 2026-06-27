import { useState, useCallback, useEffect } from "react";
import StatCard from "../components/StatCard";
import { fetchHoneytokenEvents } from "../api/client";

/**
 * Honeytokens page.
 *
 * Props:
 *   honeytokens — { honeytokens: [...], total, offset, limit } from /api/honeytokens
 *   stats       — optional stats summary
 */

function timeAgo(iso) {
  if (!iso) return "--";
  const s = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

function formatTimestamp(iso) {
  if (!iso) return "--";
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

const TYPE_COLORS = {
  "aws-key": "#FF9900",
  "ssh-key": "#22C55E",
  "env-var": "#8B5CF6",
  "database-cred": "#3B82F6",
  "api-token": "#F59E0B",
  kubeconfig: "#06B6D4",
  file: "#6B7280",
};

const SEVERITY_COLORS = {
  critical: "var(--red)",
  high: "#FF6B35",
  medium: "var(--orange)",
  low: "var(--text-muted)",
  info: "var(--text-dim)",
};

const s = {
  page: { animation: "fadeIn 0.3s ease" },
  statsRow: { display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12, marginBottom: 16 },
  panel: {
    background: "var(--bg-panel)",
    border: "1px solid var(--border)",
    borderRadius: 6,
    padding: 14,
  },
  panelTitle: {
    fontSize: 10,
    fontWeight: 700,
    letterSpacing: "0.1em",
    color: "var(--text-dim)",
    marginBottom: 12,
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
  },
  panelBody: { maxHeight: 460, overflowY: "auto" },
  headerRow: {
    display: "grid",
    gridTemplateColumns: "160px 90px 1fr 120px 70px 90px 140px",
    gap: 8,
    padding: "6px 0",
    fontSize: 10,
    fontWeight: 700,
    letterSpacing: "0.05em",
    color: "var(--text-dim)",
    borderBottom: "1px solid var(--border)",
    marginBottom: 2,
    textTransform: "uppercase",
  },
  tokenRow: {
    display: "grid",
    gridTemplateColumns: "160px 90px 1fr 120px 70px 90px 140px",
    gap: 8,
    padding: "7px 0",
    fontSize: 11,
    alignItems: "center",
    borderBottom: "1px solid rgba(28,28,30,0.4)",
    cursor: "pointer",
    transition: "background 0.1s",
  },
  tokenName: { fontFamily: "var(--mono)", fontSize: 11, color: "var(--text)", fontWeight: 600 },
  badge: (color) => ({
    display: "inline-block",
    padding: "2px 7px",
    borderRadius: 3,
    fontSize: 9,
    fontWeight: 700,
    letterSpacing: "0.05em",
    background: `${color}22`,
    color,
    textTransform: "uppercase",
  }),
  path: {
    fontFamily: "var(--mono)",
    fontSize: 10,
    color: "var(--text-dim)",
    overflow: "hidden",
    textOverflow: "ellipsis",
    whiteSpace: "nowrap",
  },
  decoy: { fontFamily: "var(--mono)", fontSize: 10, color: "var(--cyan)" },
  triggers: (n) => ({
    fontFamily: "var(--mono)",
    fontSize: 11,
    fontWeight: n > 0 ? 700 : 400,
    color: n > 0 ? "var(--red)" : "var(--text-muted)",
  }),
  lastTriggered: { fontFamily: "var(--mono)", fontSize: 10, color: "var(--text-dim)" },
  ips: { fontFamily: "var(--mono)", fontSize: 10, color: "var(--text-muted)" },
  detailPanel: {
    background: "var(--bg-panel)",
    border: "1px solid var(--border)",
    borderRadius: 6,
    padding: 14,
    marginTop: 12,
  },
  detailHeader: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "flex-start",
    marginBottom: 12,
  },
  detailName: { fontFamily: "var(--mono)", fontSize: 14, fontWeight: 600, color: "var(--text)" },
  detailMeta: { fontFamily: "var(--mono)", fontSize: 10, color: "var(--text-dim)", marginTop: 4 },
  detailStats: {
    display: "grid",
    gridTemplateColumns: "repeat(4, 1fr)",
    gap: 8,
    marginBottom: 14,
    padding: "8px 0",
    borderBottom: "1px solid var(--border)",
  },
  detailStat: {
    textAlign: "center",
  },
  detailStatValue: {
    fontFamily: "var(--mono)",
    fontSize: 16,
    fontWeight: 700,
    color: "var(--text)",
  },
  detailStatLabel: {
    fontFamily: "var(--mono)",
    fontSize: 9,
    color: "var(--text-dim)",
    letterSpacing: "0.05em",
    marginTop: 2,
  },
  closeBtn: {
    background: "none",
    border: "1px solid var(--border)",
    borderRadius: 4,
    color: "var(--text-dim)",
    fontSize: 10,
    padding: "3px 8px",
    cursor: "pointer",
  },
  eventRow: {
    display: "grid",
    gridTemplateColumns: "160px 120px 100px 80px 1fr",
    gap: 8,
    padding: "6px 0",
    fontSize: 11,
    alignItems: "center",
    borderBottom: "1px solid rgba(28,28,30,0.4)",
  },
  eventLabel: { fontFamily: "var(--mono)", fontSize: 10, color: "var(--text-dim)" },
  eventIP: { fontFamily: "var(--mono)", fontSize: 10, color: "var(--orange)" },
  eventVector: { fontFamily: "var(--mono)", fontSize: 10, color: "var(--purple)" },
  eventSeverity: (sev) => ({
    fontFamily: "var(--mono)",
    fontSize: 9,
    fontWeight: 700,
    color: SEVERITY_COLORS[sev] || "var(--text-muted)",
    textTransform: "uppercase",
  }),
  eventCmd: {
    fontFamily: "var(--mono)",
    fontSize: 10,
    color: "var(--text-muted)",
    overflow: "hidden",
    textOverflow: "ellipsis",
    whiteSpace: "nowrap",
  },
  loading: {
    padding: "30px 20px",
    textAlign: "center",
    color: "var(--text-dim)",
    fontSize: 11,
    fontFamily: "var(--mono)",
  },
  empty: { padding: "30px 20px", textAlign: "center", color: "var(--text-muted)", fontSize: 11 },
};

export default function Honeytokens({ honeytokens: honeytokensData, stats: _stats }) {
  const [selectedToken, setSelectedToken] = useState(null);
  const [tokenEvents, setTokenEvents] = useState(null);
  const [eventsLoading, setEventsLoading] = useState(false);
  const [eventsCache, setEventsCache] = useState({});

  const tokens = honeytokensData?.honeytokens || [];

  // Compute stats from token array
  const totalTokens = tokens.length;
  const totalTriggers = tokens.reduce((sum, t) => sum + (t.trigger_count || 0), 0);

  const allIPs = new Set();
  tokens.forEach((t) => {
    (t.source_ips || []).forEach((ip) => allIPs.add(ip));
  });
  const uniqueAttackers = allIPs.size;

  const totalSessions = tokens.reduce((sum, t) => sum + (t.unique_sessions || 0), 0);

  const openTokenDetail = useCallback(
    async (tokenName) => {
      // Toggle off if clicking the same token
      if (tokenName === selectedToken) {
        setSelectedToken(null);
        setTokenEvents(null);
        return;
      }

      setSelectedToken(tokenName);

      // Check cache first
      if (eventsCache[tokenName]) {
        setTokenEvents(eventsCache[tokenName]);
        return;
      }

      setEventsLoading(true);
      setTokenEvents(null);
      try {
        const data = await fetchHoneytokenEvents(tokenName);
        setTokenEvents(data);
        setEventsCache((prev) => ({ ...prev, [tokenName]: data }));
      } catch (err) {
        console.warn("Honeytoken events fetch failed:", err);
        setTokenEvents(null);
      } finally {
        setEventsLoading(false);
      }
    },
    [selectedToken, eventsCache],
  );

  const closeDetail = useCallback(() => {
    setSelectedToken(null);
    setTokenEvents(null);
  }, []);

  // ESC to close detail panel
  useEffect(() => {
    const handler = (e) => {
      if (e.key === "Escape" && selectedToken) closeDetail();
    };
    document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
  }, [selectedToken, closeDetail]);

  if (tokens.length === 0) {
    return (
      <div style={s.page}>
        <div style={s.statsRow}>
          <StatCard label="TOTAL TOKENS" value={0} accent="var(--text-dim)" />
          <StatCard label="TOTAL TRIGGERS" value={0} accent="var(--green)" />
          <StatCard label="UNIQUE ATTACKERS" value={0} accent="var(--green)" />
          <StatCard label="SESSIONS" value={0} accent="var(--green)" />
        </div>
        <div style={s.panel}>
          <div style={s.panelTitle}>HONEYTOKENS</div>
          <div style={s.empty}>
            No honeytokens configured. Add honeytokens to your Decoy CRD&apos;s
            spec.filesystem.honeytokens to start monitoring.
          </div>
        </div>
      </div>
    );
  }

  const selected = selectedToken ? tokens.find((t) => t.token_name === selectedToken) : null;
  const events = tokenEvents?.events || [];

  return (
    <div style={s.page}>
      {/* Stats row */}
      <div style={s.statsRow}>
        <StatCard label="TOTAL TOKENS" value={totalTokens} accent="var(--cyan)" />
        <StatCard
          label="TOTAL TRIGGERS"
          value={totalTriggers}
          accent={totalTriggers > 0 ? "var(--red)" : "var(--green)"}
        />
        <StatCard
          label="UNIQUE ATTACKERS"
          value={uniqueAttackers}
          accent={uniqueAttackers > 0 ? "var(--red)" : "var(--green)"}
        />
        <StatCard
          label="SESSIONS"
          value={totalSessions}
          accent={totalSessions > 0 ? "var(--orange)" : "var(--green)"}
        />
      </div>

      {/* Token table */}
      <div style={s.panel}>
        <div style={s.panelTitle}>
          HONEYTOKENS
          <span style={{ color: "var(--text-muted)" }}>{tokens.length} configured</span>
        </div>

        <div style={s.headerRow}>
          <span>Token Name</span>
          <span>Type</span>
          <span>Path</span>
          <span>Decoy</span>
          <span>Triggers</span>
          <span>Last Triggered</span>
          <span>Source IPs</span>
        </div>

        <div style={s.panelBody}>
          {tokens.map((token) => {
            const typeColor = TYPE_COLORS[token.token_type] || "#6B7280";
            const ips = token.source_ips || [];
            const displayIPs = ips.slice(0, 3).join(", ");
            const moreCount = ips.length > 3 ? ips.length - 3 : 0;

            return (
              <div
                key={token.token_name}
                style={{
                  ...s.tokenRow,
                  background:
                    selectedToken === token.token_name ? "var(--bg-hover)" : "transparent",
                }}
                onClick={() => openTokenDetail(token.token_name)}
                onMouseOver={(e) => {
                  if (selectedToken !== token.token_name)
                    e.currentTarget.style.background = "var(--bg-hover)";
                }}
                onMouseOut={(e) => {
                  if (selectedToken !== token.token_name)
                    e.currentTarget.style.background = "transparent";
                }}
              >
                <span style={s.tokenName}>{token.token_name}</span>
                <span>
                  <span style={s.badge(typeColor)}>{token.token_type}</span>
                </span>
                <span style={s.path} title={token.path}>
                  {token.path}
                </span>
                <span style={s.decoy}>{token.decoy_name || "--"}</span>
                <span style={s.triggers(token.trigger_count || 0)}>{token.trigger_count || 0}</span>
                <span style={s.lastTriggered}>{timeAgo(token.last_triggered)}</span>
                <span style={s.ips}>
                  {ips.length === 0 ? "--" : displayIPs}
                  {moreCount > 0 && (
                    <span style={{ color: "var(--text-dim)" }}> +{moreCount} more</span>
                  )}
                </span>
              </div>
            );
          })}
        </div>
      </div>

      {/* Detail panel */}
      {selected && (
        <div style={s.detailPanel}>
          <div style={s.detailHeader}>
            <div>
              <div style={s.detailName}>{selected.token_name}</div>
              <div style={s.detailMeta}>
                <span style={s.badge(TYPE_COLORS[selected.token_type] || "#6B7280")}>
                  {selected.token_type}
                </span>
                <span style={{ marginLeft: 10 }}>{selected.path}</span>
                {selected.decoy_name && (
                  <span style={{ marginLeft: 10, color: "var(--cyan)" }}>
                    @ {selected.decoy_name}
                  </span>
                )}
              </div>
            </div>
            <button style={s.closeBtn} onClick={closeDetail}>
              CLOSE
            </button>
          </div>

          {/* Token detail stats */}
          <div style={s.detailStats}>
            <div style={s.detailStat}>
              <div style={s.detailStatValue}>{selected.trigger_count || 0}</div>
              <div style={s.detailStatLabel}>TRIGGERS</div>
            </div>
            <div style={s.detailStat}>
              <div style={s.detailStatValue}>{selected.unique_ips || 0}</div>
              <div style={s.detailStatLabel}>UNIQUE IPs</div>
            </div>
            <div style={s.detailStat}>
              <div style={s.detailStatValue}>{selected.unique_sessions || 0}</div>
              <div style={s.detailStatLabel}>SESSIONS</div>
            </div>
            <div style={s.detailStat}>
              <div style={{ ...s.detailStatValue, fontSize: 10 }}>
                {selected.first_triggered ? formatTimestamp(selected.first_triggered) : "--"}
              </div>
              <div style={s.detailStatLabel}>FIRST SEEN</div>
            </div>
          </div>

          <div style={s.panelTitle}>
            TRIGGER EVENTS
            <span style={{ color: "var(--text-muted)" }}>
              {eventsLoading ? "loading..." : `${events.length} events`}
            </span>
          </div>

          {eventsLoading ? (
            <div style={s.loading}>Loading trigger events...</div>
          ) : events.length === 0 ? (
            <div style={s.empty}>No trigger events recorded</div>
          ) : (
            <div style={{ maxHeight: 300, overflowY: "auto" }}>
              <div
                style={{
                  ...s.eventRow,
                  fontSize: 10,
                  fontWeight: 700,
                  color: "var(--text-dim)",
                  textTransform: "uppercase",
                  letterSpacing: "0.05em",
                  borderBottom: "1px solid var(--border)",
                }}
              >
                <span>Timestamp</span>
                <span>Source IP</span>
                <span>Access Vector</span>
                <span>Severity</span>
                <span>Command</span>
              </div>
              {events.map((evt) => (
                <div key={evt.event_id} style={s.eventRow}>
                  <span style={s.eventLabel} title={formatTimestamp(evt.timestamp)}>
                    {timeAgo(evt.timestamp)}
                  </span>
                  <span style={s.eventIP}>{evt.source_ip || "--"}</span>
                  <span style={s.eventVector}>
                    {evt.data?.access_vector || evt.data?.access_type || "--"}
                  </span>
                  <span style={s.eventSeverity(evt.severity)}>{evt.severity || "--"}</span>
                  <span style={s.eventCmd} title={evt.data?.command}>
                    {evt.data?.command || "--"}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
