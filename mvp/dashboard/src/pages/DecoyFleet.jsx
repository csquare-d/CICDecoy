import { useState } from "react";
import TierBadge from "../components/TierBadge";
import StatusIndicator from "../components/StatusIndicator";

/**
 * DecoyFleet page — fleet management view.
 *
 * For now uses the session data to derive decoy stats.
 * In future this would connect to a fleet management API.
 *
 * Props:
 *   sessions — from /api/sessions (used to derive per-decoy stats)
 *   stats    — from /api/stats
 */

const s = {
  page: { animation: "fadeIn 0.3s ease" },
  panel: {
    background: "var(--bg-panel)", border: "1px solid var(--border)",
    borderRadius: 6, padding: 14,
  },
  header: {
    display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14,
  },
  title: { fontSize: 10, fontWeight: 700, letterSpacing: "0.1em", color: "var(--text-dim)" },
  filters: { display: "flex", gap: 6 },
  filterBtn: (active) => ({
    background: active ? "var(--bg-hover)" : "var(--bg)",
    border: `1px solid ${active ? "var(--border-light)" : "var(--border)"}`,
    color: active ? "var(--text)" : "var(--text-dim)",
    padding: "3px 10px", borderRadius: 3, fontSize: 10,
    cursor: "pointer", fontFamily: "var(--mono)", transition: "all 0.15s",
  }),
  tableHead: {
    display: "grid",
    gridTemplateColumns: "180px 70px 60px 70px 80px 100px 70px 70px 1fr",
    gap: 8, padding: "6px 10px", fontSize: 9, fontWeight: 700,
    letterSpacing: "0.1em", color: "var(--text-muted)",
    borderBottom: "1px solid var(--border)",
  },
  row: (hasAlerts) => ({
    display: "grid",
    gridTemplateColumns: "180px 70px 60px 70px 80px 100px 70px 70px 1fr",
    gap: 8, alignItems: "center", padding: "8px 10px", fontSize: 11,
    borderBottom: "1px solid rgba(13,13,15,0.8)",
    transition: "background 0.1s", cursor: "pointer",
    backgroundColor: hasAlerts ? "rgba(255,45,85,0.02)" : "transparent",
  }),
  name: { color: "var(--text)", fontWeight: 500 },
  sub: { fontSize: 10, color: "var(--text-muted)", marginTop: 2 },
  ip: { color: "var(--text-dim)", fontFamily: "var(--mono)", fontSize: 10 },
};

// Derive decoy fleet data from sessions
function deriveFleet(sessions = []) {
  const decoyMap = {};

  for (const sess of sessions) {
    const name = sess.decoy_name || "unknown";
    if (!decoyMap[name]) {
      decoyMap[name] = {
        name,
        tier: sess.decoy_tier || 2,
        type: "ssh",
        zone: "dmz",
        status: "active",
        ip: sess.source_ip ? "--" : "--",
        sessions: 0,
        alerts: 0,
        highSev: 0,
      };
    }
    decoyMap[name].sessions += 1;
    const sev = sess.max_severity;
    if (sev === "critical" || sev === "high") {
      decoyMap[name].alerts += 1;
      decoyMap[name].highSev += 1;
    }
  }

  return Object.values(decoyMap);
}

export default function DecoyFleet({ sessions, stats }) {
  const [filter, setFilter] = useState("All");
  const sessionList = sessions?.sessions || [];
  const fleet = deriveFleet(sessionList);

  const filtered = filter === "All"
    ? fleet
    : fleet.filter((d) => d.tier === parseInt(filter.replace("T", "")));

  return (
    <div style={s.page}>
      <div style={s.panel}>
        <div style={s.header}>
          <span style={s.title}>DECOY FLEET MANAGEMENT</span>
          <div style={s.filters}>
            {["All", "T1", "T2", "T3"].map((f) => (
              <button key={f} style={s.filterBtn(filter === f)} onClick={() => setFilter(f)}>
                {f}
              </button>
            ))}
          </div>
        </div>

        <div style={s.tableHead}>
          <span>NAME</span><span>TIER</span><span>TYPE</span><span>ZONE</span>
          <span>STATUS</span><span>IP</span><span>SESSIONS</span><span>ALERTS</span><span>UPTIME</span>
        </div>

        {filtered.length === 0 && (
          <div style={{ padding: 30, textAlign: "center", color: "var(--text-muted)", fontSize: 11 }}>
            No decoys found for this filter
          </div>
        )}

        {filtered.map((d, i) => (
          <div
            key={i}
            style={s.row(d.alerts > 2)}
            onMouseOver={(e) => (e.currentTarget.style.backgroundColor = "var(--bg-hover)")}
            onMouseOut={(e) => (e.currentTarget.style.backgroundColor = d.alerts > 2 ? "rgba(255,45,85,0.02)" : "transparent")}
          >
            <span style={s.name}>{d.name}</span>
            <TierBadge tier={d.tier} />
            <span style={{ color: "var(--text-dim)" }}>{d.type}</span>
            <span style={{ color: "var(--text-muted)" }}>{d.zone}</span>
            <StatusIndicator status={d.status} />
            <span style={s.ip}>{d.ip}</span>
            <span style={{ color: "var(--text)" }}>{d.sessions}</span>
            <span style={{
              color: d.alerts > 2 ? "var(--red)" : d.alerts > 0 ? "var(--orange)" : "var(--text-muted)",
              fontWeight: d.alerts > 0 ? 600 : 400,
            }}>
              {d.alerts}
            </span>
            <span style={{ color: "var(--text-muted)" }}>--</span>
          </div>
        ))}
      </div>
    </div>
  );
}
