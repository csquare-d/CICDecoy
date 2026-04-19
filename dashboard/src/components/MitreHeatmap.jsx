/**
 * MitreHeatmap — bar chart rows of MITRE technique frequency.
 * Props:
 *   techniques — [{ technique_id, technique_name, tactic, total, actors }]
 */

const s = {
  row: {
    display: "flex", alignItems: "center", gap: 10,
    padding: "6px 16px", fontSize: 12,
    borderBottom: "1px solid rgba(28,28,30,0.5)",
    transition: "background 0.1s",
    cursor: "default",
  },
  id: {
    fontFamily: "var(--mono)", fontSize: 10, color: "var(--blue)",
    width: 80, flexShrink: 0,
  },
  name: {
    fontFamily: "var(--mono)", fontSize: 9, color: "var(--text-dim)",
    position: "absolute", left: 6, top: 1, zIndex: 1,
  },
  barBg: {
    flex: 1, height: 16, backgroundColor: "var(--bg-hover)",
    borderRadius: 2, position: "relative", overflow: "hidden",
  },
  bar: (pct) => ({
    position: "absolute", top: 0, left: 0, height: "100%",
    width: `${pct}%`,
    background: "linear-gradient(90deg, #bf5af244, #0a84ff44)",
    borderRadius: 2, transition: "width 0.6s ease",
  }),
  count: {
    fontFamily: "var(--mono)", fontSize: 11, color: "var(--text)",
    width: 36, textAlign: "right", flexShrink: 0,
  },
  actors: {
    fontFamily: "var(--mono)", fontSize: 10, color: "var(--text-muted)",
    width: 40, textAlign: "right", flexShrink: 0,
  },
  empty: {
    padding: "40px 20px", textAlign: "center",
    color: "var(--text-dim)", fontSize: 12,
  },
};

export default function MitreHeatmap({ techniques = [] }) {
  if (techniques.length === 0) {
    return <div style={s.empty}>No MITRE technique data yet</div>;
  }

  const max = Math.max(...techniques.map((t) => t.total));

  return (
    <div>
      {techniques.map((t, i) => {
        const pct = max > 0 ? (t.total / max) * 100 : 0;
        return (
          <div
            key={t.technique_id + "-" + i}
            style={s.row}
            onMouseOver={(e) => (e.currentTarget.style.background = "var(--bg-hover)")}
            onMouseOut={(e) => (e.currentTarget.style.background = "transparent")}
          >
            <span style={s.id}>{t.technique_id}</span>
            <div style={s.barBg}>
              <div style={s.bar(pct)} />
              <span style={s.name}>{t.technique_name}</span>
            </div>
            <span style={s.count}>{t.total}</span>
            <span style={s.actors}>{t.actors} IPs</span>
          </div>
        );
      })}
    </div>
  );
}
