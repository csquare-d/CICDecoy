import { useMemo } from "react";
import StatCard from "../components/StatCard";
import MitreHeatmap from "../components/MitreHeatmap";
import SeverityBadge, { SeverityDot } from "../components/SeverityBadge";
import StatusIndicator from "../components/StatusIndicator";
import TierBadge from "../components/TierBadge";
import { resolveIP, resolveUser, resolveCommand, techIds, fmtTime, parseDict } from "../utils";

/**
 * Overview page.
 *
 * Props:
 *   stats     — from /api/stats (polled)
 *   mitre     — from /api/mitre (polled)
 *   sseEvents — live SSE event buffer (newest first)
 *   eventCount — total SSE events received
 */

const s = {
  page: { animation: "fadeIn 0.3s ease" },
  statsGrid: { display: "grid", gridTemplateColumns: "repeat(6, 1fr)", gap: 12, marginBottom: 16 },
  twoCol: { display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 },
  panel: {
    background: "var(--bg-panel)", border: "1px solid var(--border)",
    borderRadius: 6, padding: 14,
  },
  panelTitle: {
    fontSize: 10, fontWeight: 700, letterSpacing: "0.1em",
    color: "var(--text-dim)", marginBottom: 12,
    display: "flex", justifyContent: "space-between", alignItems: "center",
  },
  liveDot: { color: "var(--red)", animation: "pulse 1.5s ease-in-out infinite" },
  feedList: { display: "flex", flexDirection: "column", gap: 6, maxHeight: 300, overflowY: "auto" },
  feedRow: (severity) => ({
    display: "grid", gridTemplateColumns: "70px 24px 1fr auto",
    gap: 8, alignItems: "center", fontSize: 11, padding: "6px 8px",
    borderRadius: 4, borderLeft: `2px solid ${severity === "critical" ? "var(--red)" : severity === "high" ? "var(--orange)" : "var(--text-muted)"}`,
    backgroundColor: severity === "critical" ? "rgba(255,45,85,0.03)" : "transparent",
  }),
  feedTime: { color: "var(--text-muted)", fontSize: 10 },
  feedDetail: { color: "var(--text-dim)", fontSize: 10, maxWidth: 240, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" },
};

export default function Overview({ stats, mitre, sseEvents = [], eventCount = 0 }) {
  // Build alert feed from SSE events (only show meaningful ones, newest first)
  const alertFeed = useMemo(() => {
    return sseEvents
      .filter((ev) => {
        const p = ev.payload || {};
        const sev = p.severity || "info";
        return sev !== "info";
      })
      .slice(0, 20)
      .map((ev) => {
        const p = ev.payload || {};
        return {
          time: fmtTime(ev.ts || p.timestamp),
          severity: p.severity || "info",
          decoy: p.decoy_name || "--",
          type: p.event_type || "?",
          detail: resolveCommand(p) || resolveIP(p) || "",
        };
      });
  }, [sseEvents]);

  const techniques = mitre?.techniques || [];
  const st = stats || {};

  return (
    <div style={s.page}>
      {/* Stats strip */}
      <div style={s.statsGrid}>
        <StatCard label="SESSIONS (TOTAL)" value={st.total_sessions ?? "--"} accent="var(--green)" />
        <StatCard label="ACTIVE NOW" value={st.active_sessions ?? "--"} accent={st.active_sessions > 0 ? "var(--orange)" : "var(--text-dim)"} />
        <StatCard label="EVENTS / 24H" value={st.total_events ?? "--"} accent="var(--blue)" />
        <StatCard label="UNIQUE IPs / 24H" value={st.unique_ips ?? "--"} accent="var(--purple)" />
        <StatCard label="HIGH/CRIT (24H)" value={st.high_sev_24h ?? "--"} accent={st.high_sev_24h > 0 ? "var(--red)" : "var(--text-dim)"} />
        <StatCard label="KILL CHAINS" value={st.kill_chains ?? "--"} accent={st.kill_chains > 0 ? "var(--red)" : "var(--text-dim)"} />
      </div>

      <div style={s.twoCol}>
        {/* Alert Feed */}
        <div style={s.panel}>
          <div style={s.panelTitle}>
            ALERT FEED
            <span style={s.liveDot}>● LIVE</span>
          </div>
          <div style={s.feedList}>
            {alertFeed.length === 0 && (
              <div style={{ color: "var(--text-muted)", fontSize: 11, textAlign: "center", padding: 20 }}>
                No alerts yet -- waiting for events
              </div>
            )}
            {alertFeed.map((a, i) => (
              <div key={i} style={s.feedRow(a.severity)}>
                <span style={s.feedTime}>{a.time}</span>
                <SeverityDot severity={a.severity} />
                <div>
                  <span style={{ color: "var(--text-dim)" }}>{a.decoy}</span>
                  <span style={{ color: "var(--text-muted)" }}> → </span>
                  <span style={{ color: "var(--text)" }}>{a.type}</span>
                </div>
                <span style={s.feedDetail}>{a.detail}</span>
              </div>
            ))}
          </div>
        </div>

        {/* MITRE Heatmap */}
        <div style={s.panel}>
          <div style={s.panelTitle}>MITRE ATT&CK — 7 DAY TREND</div>
          <MitreHeatmap techniques={techniques} />
        </div>
      </div>
    </div>
  );
}
