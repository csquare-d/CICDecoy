import SeverityBadge from "./SeverityBadge";

/**
 * SessionList — renders session rows.
 *
 * In compact mode (when replay is open), shows a narrow sidebar list.
 * In full mode, shows the detailed table.
 *
 * Props:
 *   sessions       — array from /api/sessions
 *   compact        — boolean, true when replay pane is open
 *   activeId       — session_id currently being replayed
 *   onSelect       — (session_id) => void
 */

const s = {
  table: { width: "100%", borderCollapse: "collapse", fontSize: 12 },
  th: {
    fontFamily: "var(--mono)", fontSize: 10, textTransform: "uppercase",
    letterSpacing: "0.8px", color: "var(--text-dim)", textAlign: "left",
    padding: "8px 12px", borderBottom: "1px solid var(--border)",
    background: "var(--bg-panel)", position: "sticky", top: 0, zIndex: 2,
  },
  td: {
    padding: "7px 12px", borderBottom: "1px solid rgba(28,28,30,0.4)",
    verticalAlign: "middle",
  },
  mono: { fontFamily: "var(--mono)", fontSize: 11 },
  techChip: {
    display: "inline-block", fontFamily: "var(--mono)", fontSize: 9,
    padding: "1px 6px", borderRadius: 3, margin: "1px 2px",
    background: "var(--purple-dim)", color: "var(--purple)",
  },
  phaseChip: {
    display: "inline-block", fontFamily: "var(--mono)", fontSize: 9,
    padding: "1px 6px", borderRadius: 3, margin: "1px 2px",
    background: "var(--blue-dim)", color: "var(--blue)",
  },
  kcFlag: {
    display: "inline-block", fontFamily: "var(--mono)", fontSize: 9, fontWeight: 700,
    padding: "1px 6px", borderRadius: 3,
    background: "var(--red-dim)", color: "var(--red)",
  },
  row: {
    cursor: "pointer", transition: "background 0.1s",
  },
  // Compact mode
  compactItem: (active) => ({
    display: "flex", alignItems: "center", gap: 8,
    padding: "7px 12px", cursor: "pointer",
    borderBottom: "1px solid rgba(28,28,30,0.3)",
    fontSize: 11, transition: "background 0.1s",
    borderLeft: active ? "2px solid var(--green)" : "2px solid transparent",
    background: active ? "rgba(48,209,88,0.04)" : "transparent",
  }),
  scIp: { fontFamily: "var(--mono)", color: "var(--text)", fontSize: 11, minWidth: 100 },
  scUser: { fontFamily: "var(--mono)", color: "var(--cyan)", fontSize: 10, minWidth: 50 },
  scCmds: { fontFamily: "var(--mono)", color: "var(--text-dim)", fontSize: 10 },
  empty: { padding: "40px 20px", textAlign: "center", color: "var(--text-dim)", fontSize: 12 },
};

export default function SessionList({ sessions = [], compact = false, activeId = null, onSelect }) {
  if (sessions.length === 0) {
    return <div style={s.empty}>No sessions yet -- inject test events or SSH to port 2222</div>;
  }

  // ── Compact sidebar list ──
  if (compact) {
    return (
      <div>
        {sessions.map((sess) => (
          <div
            key={sess.session_id}
            style={s.compactItem(activeId === sess.session_id)}
            onClick={() => onSelect(sess.session_id)}
            onMouseOver={(e) => { if (activeId !== sess.session_id) e.currentTarget.style.background = "var(--bg-hover)"; }}
            onMouseOut={(e) => { if (activeId !== sess.session_id) e.currentTarget.style.background = "transparent"; }}
          >
            <SeverityBadge severity={sess.max_severity} style={{ fontSize: 8, flexShrink: 0 }} />
            <span style={s.scIp}>{sess.source_ip || "--"}</span>
            <span style={s.scUser}>{sess.auth_username || "--"}</span>
            <span style={s.scCmds}>{sess.command_count || 0} cmds</span>
            {sess.kill_chain_detected && (
              <span style={{ ...s.kcFlag, marginLeft: "auto", fontSize: 8 }}>KC</span>
            )}
          </div>
        ))}
      </div>
    );
  }

  // ── Full table ──
  return (
    <table style={s.table}>
      <thead>
        <tr>
          <th style={s.th}>Source IP</th>
          <th style={s.th}>User</th>
          <th style={s.th}>Decoy</th>
          <th style={s.th}>Cmds</th>
          <th style={s.th}>Severity</th>
          <th style={s.th}>ATT&CK Techniques</th>
        </tr>
      </thead>
      <tbody>
        {sessions.map((sess) => {
          const techs = (sess.mitre_techniques || [])
            .map((t) => <span key={t.technique_id} style={s.techChip}>{t.technique_id || t}</span>);
          const phases = (sess.attack_phases || [])
            .map((p) => <span key={p} style={s.phaseChip}>{p}</span>);

          return (
            <tr
              key={sess.session_id}
              style={s.row}
              onClick={() => onSelect(sess.session_id)}
              onMouseOver={(e) => { for (const td of e.currentTarget.cells || []) td.style.background = "var(--bg-hover)"; }}
              onMouseOut={(e) => { for (const td of e.currentTarget.cells || []) td.style.background = ""; }}
            >
              <td style={{ ...s.td, ...s.mono }}>{sess.source_ip || "--"}</td>
              <td style={{ ...s.td, ...s.mono }}>{sess.auth_username || "--"}</td>
              <td style={{ ...s.td, ...s.mono }}>{sess.decoy_name}</td>
              <td style={{ ...s.td, ...s.mono }}>{sess.command_count || 0}</td>
              <td style={s.td}><SeverityBadge severity={sess.max_severity} /></td>
              <td style={s.td}>
                {techs.length > 0 ? techs : "--"}{" "}
                {phases}
                {sess.kill_chain_detected && <span style={s.kcFlag}>KILL CHAIN</span>}
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}
