const MAP = {
  active:   { color: "var(--green)",  label: "ONLINE" },
  rotating: { color: "var(--amber)",  label: "ROTATING" },
  degraded: { color: "var(--orange)", label: "DEGRADED" },
  offline:  { color: "var(--red)",    label: "OFFLINE" },
};

export default function StatusIndicator({ status }) {
  const { color, label } = MAP[status] || MAP.active;
  return (
    <span
      style={{
        display: "inline-flex", alignItems: "center", gap: 5,
        fontSize: 10, fontWeight: 600, letterSpacing: "0.06em", color,
        fontFamily: "var(--mono)",
      }}
    >
      <span
        style={{
          width: 6, height: 6, borderRadius: "50%", backgroundColor: color,
          animation: status === "active" ? "pulse 2s ease-in-out infinite" : "none",
        }}
      />
      {label}
    </span>
  );
}
