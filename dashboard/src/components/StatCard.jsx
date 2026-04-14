const s = {
  card: {
    background: "var(--bg-panel)", border: "1px solid var(--border)",
    borderRadius: 6, padding: "14px 12px", textAlign: "center",
  },
  value: (accent) => ({
    fontSize: 28, fontWeight: 200, fontFamily: "var(--mono)",
    color: accent || "var(--text)", lineHeight: 1,
  }),
  label: {
    fontSize: 10, fontWeight: 600, letterSpacing: "0.1em",
    color: "var(--text-dim)", marginTop: 4,
  },
  sub: { fontSize: 10, color: "var(--text-muted)", marginTop: 2 },
};

export default function StatCard({ label, value, accent, sub }) {
  return (
    <div style={s.card}>
      <div style={s.value(accent)}>{value ?? "--"}</div>
      <div style={s.label}>{label}</div>
      {sub && <div style={s.sub}>{sub}</div>}
    </div>
  );
}
