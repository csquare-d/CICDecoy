const LABELS = { 1: "BEACON", 2: "SCRIPTED", 3: "ADAPTIVE" };
const COLORS = { 1: "#636366", 2: "#0a84ff", 3: "#bf5af2" };

export default function TierBadge({ tier }) {
  const color = COLORS[tier] || COLORS[1];
  return (
    <span
      style={{
        fontSize: 9, fontWeight: 700, letterSpacing: "0.08em",
        padding: "2px 6px", borderRadius: 3,
        backgroundColor: color + "22", color,
        border: `1px solid ${color}44`,
        fontFamily: "var(--mono)",
      }}
    >
      T{tier} {LABELS[tier] || "UNKNOWN"}
    </span>
  );
}
