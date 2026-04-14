const COLORS = {
  critical: "var(--red)",
  high: "var(--orange)",
  medium: "var(--amber)",
  low: "var(--green)",
  info: "var(--text-muted)",
};

const BG = {
  critical: "var(--red-dim)",
  high: "var(--orange-dim)",
  medium: "var(--amber-dim)",
  low: "var(--green-dim)",
  info: "rgba(110,118,129,0.08)",
};

/** Colored dot only */
export function SeverityDot({ severity, size = 8 }) {
  const color = COLORS[severity] || COLORS.info;
  return (
    <span
      style={{
        display: "inline-block", width: size, height: size, borderRadius: "50%",
        backgroundColor: color, boxShadow: `0 0 6px ${color}80`,
        flexShrink: 0,
      }}
    />
  );
}

/** Labeled badge (CRITICAL, HIGH, etc.) */
export default function SeverityBadge({ severity, style: extra }) {
  const sev = severity || "info";
  return (
    <span
      style={{
        fontFamily: "var(--mono)", fontSize: 9, fontWeight: 600,
        padding: "2px 6px", borderRadius: 3,
        textTransform: "uppercase", letterSpacing: "0.5px",
        whiteSpace: "nowrap",
        background: BG[sev] || BG.info,
        color: COLORS[sev] || COLORS.info,
        ...extra,
      }}
    >
      {sev}
    </span>
  );
}
