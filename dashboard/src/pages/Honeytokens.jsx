import { useState } from "react";
import StatCard from "../components/StatCard";

/**
 * Honeytokens page.
 *
 * Props:
 *   honeytokens — array of honeytoken objects from aggregated data
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

const TYPE_COLORS = {
  "aws-key": "#FF9900",
  "ssh-key": "#22C55E",
  "env-var": "#8B5CF6",
  "database-cred": "#3B82F6",
  "api-token": "#F59E0B",
  kubeconfig: "#06B6D4",
  file: "#6B7280",
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
    gridTemplateColumns: "140px 120px 140px 1fr",
    gap: 8,
    padding: "6px 0",
    fontSize: 11,
    alignItems: "center",
    borderBottom: "1px solid rgba(28,28,30,0.4)",
  },
  eventLabel: { fontFamily: "var(--mono)", fontSize: 10, color: "var(--text-dim)" },
  eventIP: { fontFamily: "var(--mono)", fontSize: 10, color: "var(--orange)" },
  eventVector: { fontFamily: "var(--mono)", fontSize: 10, color: "var(--purple)" },
  eventCmd: {
    fontFamily: "var(--mono)",
    fontSize: 10,
    color: "var(--text-muted)",
    overflow: "hidden",
    textOverflow: "ellipsis",
    whiteSpace: "nowrap",
  },
  empty: { padding: "30px 20px", textAlign: "center", color: "var(--text-muted)", fontSize: 11 },
};

export default function Honeytokens({ honeytokens, stats: _stats }) {
  const [selectedToken, setSelectedToken] = useState(null);

  const tokens = honeytokens || [];

  // Compute stats
  const totalTokens = tokens.length;
  const totalTriggers = tokens.reduce((sum, t) => sum + (t.trigger_count || 0), 0);

  const allIPs = new Set();
  tokens.forEach((t) => {
    (t.source_ips || []).forEach((ip) => allIPs.add(ip));
  });
  const uniqueAttackers = allIPs.size;

  const credentialReuse = tokens.reduce((sum, t) => sum + (t.credential_reuse || 0), 0);

  if (tokens.length === 0) {
    return (
      <div style={s.page}>
        <div style={s.statsRow}>
          <StatCard label="TOTAL TOKENS" value={0} accent="var(--text-dim)" />
          <StatCard label="TOTAL TRIGGERS" value={0} accent="var(--green)" />
          <StatCard label="UNIQUE ATTACKERS" value={0} accent="var(--green)" />
          <StatCard label="CREDENTIAL REUSE" value={0} accent="var(--green)" />
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

  const selected = selectedToken ? tokens.find((t) => t.name === selectedToken) : null;

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
          label="CREDENTIAL REUSE"
          value={credentialReuse}
          accent={credentialReuse > 0 ? "var(--red)" : "var(--green)"}
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
            const typeColor = TYPE_COLORS[token.type] || "#6B7280";
            const ips = token.source_ips || [];
            const displayIPs = ips.slice(0, 3).join(", ");
            const moreCount = ips.length > 3 ? ips.length - 3 : 0;

            return (
              <div
                key={token.name}
                style={{
                  ...s.tokenRow,
                  background: selectedToken === token.name ? "var(--bg-hover)" : "transparent",
                }}
                onClick={() => setSelectedToken(selectedToken === token.name ? null : token.name)}
                onMouseOver={(e) => {
                  if (selectedToken !== token.name)
                    e.currentTarget.style.background = "var(--bg-hover)";
                }}
                onMouseOut={(e) => {
                  if (selectedToken !== token.name)
                    e.currentTarget.style.background = "transparent";
                }}
              >
                <span style={s.tokenName}>{token.name}</span>
                <span>
                  <span style={s.badge(typeColor)}>{token.type}</span>
                </span>
                <span style={s.path} title={token.path}>
                  {token.path}
                </span>
                <span style={s.decoy}>{token.decoy || "--"}</span>
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
              <div style={s.detailName}>{selected.name}</div>
              <div style={s.detailMeta}>
                <span style={s.badge(TYPE_COLORS[selected.type] || "#6B7280")}>
                  {selected.type}
                </span>
                <span style={{ marginLeft: 10 }}>{selected.path}</span>
                {selected.decoy && (
                  <span style={{ marginLeft: 10, color: "var(--cyan)" }}>@ {selected.decoy}</span>
                )}
              </div>
            </div>
            <button style={s.closeBtn} onClick={() => setSelectedToken(null)}>
              CLOSE
            </button>
          </div>

          <div style={s.panelTitle}>
            TRIGGER EVENTS
            <span style={{ color: "var(--text-muted)" }}>
              {(selected.events || []).length} events
            </span>
          </div>

          {!selected.events || selected.events.length === 0 ? (
            <div style={s.empty}>No trigger events recorded</div>
          ) : (
            <div style={{ maxHeight: 260, overflowY: "auto" }}>
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
                <span>Command</span>
              </div>
              {selected.events.map((evt, i) => (
                <div key={i} style={s.eventRow}>
                  <span style={s.eventLabel}>{timeAgo(evt.timestamp)}</span>
                  <span style={s.eventIP}>{evt.source_ip || "--"}</span>
                  <span style={s.eventVector}>{evt.access_vector || "--"}</span>
                  <span style={s.eventCmd} title={evt.command}>
                    {evt.command || "--"}
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
