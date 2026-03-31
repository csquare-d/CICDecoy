import { useNavigate } from "react-router-dom";
import StatCard from "../components/StatCard";
import KillChainTimeline from "../components/KillChainTimeline";
import SeverityBadge from "../components/SeverityBadge";
import { formatDuration } from "../utils";

/**
 * Intelligence page.
 *
 * Props:
 *   killChains — from /api/kill-chains
 *   topIPs     — from /api/top-ips
 *   engage     — from /api/engage
 *   geo        — from /api/geo
 *   histogram  — from /api/duration-histogram
 */

const s = {
  page: { animation: "fadeIn 0.3s ease" },
  statsRow: { display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 12, marginBottom: 16 },
  twoCol: { display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 12 },
  panel: {
    background: "var(--bg-panel)", border: "1px solid var(--border)",
    borderRadius: 6, padding: 14, overflow: "hidden",
  },
  panelTitle: {
    fontSize: 10, fontWeight: 700, letterSpacing: "0.1em",
    color: "var(--text-dim)", marginBottom: 12,
    display: "flex", justifyContent: "space-between", alignItems: "center",
  },
  panelBody: { maxHeight: 360, overflowY: "auto" },
  // Kill chain session
  kcSession: {
    padding: "12px 0", borderBottom: "1px solid var(--border)",
    cursor: "pointer", transition: "background 0.1s",
  },
  kcHeader: { display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 },
  kcMeta: { fontFamily: "var(--mono)", fontSize: 11, color: "var(--text-dim)" },
  kcMetaStrong: { color: "var(--text)", fontWeight: 600 },
  kcStats: {
    display: "flex", gap: 14, fontFamily: "var(--mono)", fontSize: 10,
    color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.5px",
  },
  // Top IP row
  ipRow: {
    display: "grid", gridTemplateColumns: "130px 1fr 50px 60px",
    gap: 8, padding: "6px 0", fontSize: 11, alignItems: "center",
    borderBottom: "1px solid rgba(28,28,30,0.4)",
  },
  ipAddr: { fontFamily: "var(--mono)", fontSize: 11, color: "var(--text)" },
  barBg: { height: 6, background: "var(--bg)", borderRadius: 3, overflow: "hidden" },
  ipBar: (pct) => ({
    height: "100%", borderRadius: 3, width: `${pct}%`,
    background: "linear-gradient(90deg, var(--cyan), var(--blue))",
    transition: "width 0.6s ease",
  }),
  ipCount: { fontFamily: "var(--mono)", fontSize: 10, color: "var(--text-dim)", textAlign: "right" },
  // Engage row
  engRow: {
    display: "grid", gridTemplateColumns: "1fr 160px 60px 140px",
    gap: 8, padding: "6px 0", fontSize: 11, alignItems: "center",
    borderBottom: "1px solid rgba(28,28,30,0.4)",
  },
  engTech: { fontFamily: "var(--mono)", fontSize: 10, color: "var(--purple)" },
  engActivity: { fontFamily: "var(--mono)", fontSize: 10, color: "var(--text-dim)" },
  effBarBg: {
    width: 80, height: 6, background: "var(--bg)",
    borderRadius: 3, overflow: "hidden", display: "inline-block", verticalAlign: "middle",
  },
  effBar: (pct, color) => ({
    height: "100%", borderRadius: 3, width: `${pct}%`, background: color,
    transition: "width 0.6s ease",
  }),
  effVal: (color) => ({ fontFamily: "var(--mono)", fontSize: 10, marginLeft: 6, color }),
  // Geo row
  geoRow: {
    display: "grid", gridTemplateColumns: "30px 90px 1fr 50px 44px 60px",
    gap: 8, padding: "6px 0", fontSize: 11, alignItems: "center",
    borderBottom: "1px solid rgba(28,28,30,0.4)",
  },
  geoCode: { fontFamily: "var(--mono)", fontSize: 11, fontWeight: 700, color: "var(--cyan)" },
  geoName: { fontSize: 10, color: "var(--text-dim)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" },
  geoVal: { fontFamily: "var(--mono)", fontSize: 10, color: "var(--text-muted)", textAlign: "right" },
  // Histogram
  histWrap: { padding: "4px 0" },
  histSummary: {
    display: "flex", gap: 20, paddingBottom: 10, marginBottom: 8,
    borderBottom: "1px solid rgba(28,28,30,0.4)",
  },
  histStat: { fontFamily: "var(--mono)", fontSize: 11, color: "var(--text-dim)" },
  histStatStrong: { color: "var(--text)", fontWeight: 600 },
  histRow: { display: "grid", gridTemplateColumns: "52px 1fr 36px", gap: 10, alignItems: "center", height: 26 },
  histLabel: { fontFamily: "var(--mono)", fontSize: 10, color: "var(--text-dim)", textAlign: "right" },
  histBarBg: { height: 10, background: "var(--bg)", borderRadius: 5, overflow: "hidden" },
  histCount: { fontFamily: "var(--mono)", fontSize: 10, color: "var(--text-dim)", textAlign: "right" },
  empty: { padding: "30px 20px", textAlign: "center", color: "var(--text-muted)", fontSize: 11 },
};

function histBarColor(lo) {
  if (lo >= 300) return "linear-gradient(90deg, var(--green), #5eeb7a)";
  if (lo >= 30) return "linear-gradient(90deg, var(--amber), #e6b84d)";
  return "linear-gradient(90deg, var(--blue), var(--cyan))";
}

export default function Intelligence({ killChains, topIPs, engage, geo, histogram }) {
  const navigate = useNavigate();

  const kcSessions = killChains?.sessions || [];
  const ips = topIPs?.ips || [];
  const engageData = engage?.engage || [];
  const countries = geo?.countries || [];
  const hist = histogram || {};
  const buckets = hist.buckets || [];

  return (
    <div style={s.page}>
      {/* Stats row */}
      <div style={s.statsRow}>
        <StatCard label="KILL CHAINS DETECTED" value={kcSessions.length} accent={kcSessions.length > 0 ? "var(--red)" : "var(--text-dim)"} />
        <StatCard label="UNIQUE ATTACKER IPs" value={ips.length} accent="var(--orange)" />
        <StatCard label="COUNTRIES (7D)" value={countries.length} accent="var(--cyan)" />
      </div>

      <div style={s.twoCol}>
        {/* Kill Chains */}
        <div style={s.panel}>
          <div style={s.panelTitle}>
            KILL CHAINS DETECTED
            <span style={{ color: "var(--text-muted)" }}>{kcSessions.length} sessions</span>
          </div>
          <div style={s.panelBody}>
            {kcSessions.length === 0 && <div style={s.empty}>No kill chain sessions detected yet</div>}
            {kcSessions.map((session) => (
              <div
                key={session.session_id}
                style={s.kcSession}
                onClick={() => navigate(`/sessions?replay=${session.session_id}`)}
                onMouseOver={(e) => (e.currentTarget.style.background = "var(--bg-hover)")}
                onMouseOut={(e) => (e.currentTarget.style.background = "transparent")}
              >
                <div style={s.kcHeader}>
                  <div style={s.kcMeta}>
                    <span style={s.kcMetaStrong}>{session.source_ip}</span>
                    {session.auth_username && <span> / {session.auth_username}</span>}
                    <span> @ {session.decoy_name}</span>
                  </div>
                  <div style={s.kcStats}>
                    <span>{session.command_count} cmds</span>
                    <span>{formatDuration(session.duration_seconds)}</span>
                    <span>{session.phase_count} phases</span>
                  </div>
                </div>
                <KillChainTimeline phases={session.phases || []} />
              </div>
            ))}
          </div>
        </div>

        {/* Top Attacker IPs */}
        <div style={s.panel}>
          <div style={s.panelTitle}>
            TOP ATTACKER IPs — 24H
            <span style={{ color: "var(--text-muted)" }}>{ips.length} IPs</span>
          </div>
          <div style={s.panelBody}>
            {ips.length === 0 && <div style={s.empty}>No IP data yet</div>}
            {(() => {
              const maxEv = Math.max(...ips.map((ip) => ip.events), 1);
              return ips.map((ip, i) => (
                <div key={i} style={s.ipRow}>
                  <span style={{ ...s.ipAddr, color: ip.max_severity === "critical" || ip.max_severity === "high" ? "var(--red)" : "var(--text)" }}>
                    {ip.source_ip}
                  </span>
                  <div style={s.barBg}><div style={s.ipBar((ip.events / maxEv) * 100)} /></div>
                  <span style={s.ipCount}>{ip.events} evt</span>
                  <span style={s.ipCount}>{ip.sessions} sess</span>
                </div>
              ));
            })()}
          </div>
        </div>
      </div>

      <div style={s.twoCol}>
        {/* Engage Effectiveness */}
        <div style={s.panel}>
          <div style={s.panelTitle}>ENGAGE EFFECTIVENESS</div>
          <div style={s.panelBody}>
            {engageData.length === 0 && <div style={s.empty}>No Engage data yet</div>}
            {engageData.slice(0, 15).map((e, i) => {
              const pct = Math.round(e.effectiveness * 100);
              const color = e.effectiveness > 0.7 ? "var(--green)" : e.effectiveness > 0.4 ? "var(--amber)" : "var(--red)";
              return (
                <div key={i} style={s.engRow}>
                  <span style={s.engTech}>{e.technique_id} <span style={{ color: "var(--text-muted)" }}>{e.technique_name}</span></span>
                  <span style={s.engActivity}>{e.engage_activity}</span>
                  <span style={{ fontFamily: "var(--mono)", fontSize: 10, color: "var(--text-dim)" }}>{e.times_observed}</span>
                  <span>
                    <span style={s.effBarBg}><span style={s.effBar(pct, color)} /></span>
                    <span style={s.effVal(color)}>{pct}%</span>
                  </span>
                </div>
              );
            })}
          </div>
        </div>

        {/* Geo + Histogram stacked */}
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          {/* Geo */}
          <div style={s.panel}>
            <div style={s.panelTitle}>
              SOURCE GEOGRAPHY (7D)
              <span style={{ color: "var(--text-muted)" }}>{countries.length} countries</span>
            </div>
            <div style={{ maxHeight: 180, overflowY: "auto" }}>
              {countries.length === 0 && <div style={s.empty}>No geo data yet</div>}
              {(() => {
                const maxSess = Math.max(...countries.map((c) => c.sessions), 1);
                return countries.map((c, i) => (
                  <div key={i} style={s.geoRow}>
                    <span style={s.geoCode}>{c.country_code}</span>
                    <span style={s.geoName}>{c.country_name}</span>
                    <div style={s.barBg}><div style={s.ipBar((c.sessions / maxSess) * 100)} /></div>
                    <span style={s.geoVal}>{c.sessions} sess</span>
                    <span style={s.geoVal}>{c.unique_ips} IPs</span>
                    <span style={s.geoVal}>{formatDuration(c.avg_duration)}</span>
                  </div>
                ));
              })()}
            </div>
          </div>

          {/* Duration Histogram */}
          <div style={s.panel}>
            <div style={s.panelTitle}>
              SESSION DURATION
              <span style={{ color: "var(--text-muted)" }}>{hist.total_sessions || 0} sessions</span>
            </div>
            {buckets.length === 0 ? (
              <div style={s.empty}>No duration data yet</div>
            ) : (
              <div style={s.histWrap}>
                <div style={s.histSummary}>
                  <div style={s.histStat}><span style={s.histStatStrong}>{hist.total_sessions}</span> sessions</div>
                  <div style={s.histStat}>avg <span style={s.histStatStrong}>{formatDuration(hist.avg_seconds)}</span></div>
                  <div style={s.histStat}>median <span style={s.histStatStrong}>{formatDuration(hist.median_seconds)}</span></div>
                </div>
                {(() => {
                  const maxC = Math.max(...buckets.map((b) => b.count), 1);
                  return buckets.map((b, i) => (
                    <div key={i} style={s.histRow}>
                      <div style={s.histLabel}>{b.label}</div>
                      <div style={s.histBarBg}>
                        <div style={{ height: "100%", borderRadius: 5, width: `${(b.count / maxC) * 100}%`, background: histBarColor(b.lo), transition: "width 0.6s ease" }} />
                      </div>
                      <div style={s.histCount}>{b.count}</div>
                    </div>
                  ));
                })()}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
