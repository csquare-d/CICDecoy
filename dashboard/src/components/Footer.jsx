const s = {
  footer: {
    padding: "8px 20px", borderTop: "1px solid var(--border)",
    display: "flex", justifyContent: "space-between",
    fontSize: 9, color: "var(--border-light)", letterSpacing: "0.06em",
  },
  dot: (on) => ({
    display: "inline-block", width: 5, height: 5, borderRadius: "50%",
    backgroundColor: on ? "var(--green)" : "var(--text-muted)",
    margin: "0 3px", verticalAlign: "middle",
  }),
};

export default function Footer({ stats }) {
  const db = stats?.db_connected ?? false;
  const nats = stats?.nats_connected ?? false;

  return (
    <footer style={s.footer}>
      <span>
        NATS: <span style={s.dot(nats)} /> {nats ? "streaming" : "disconnected"}
        {" · "}
        DB: <span style={s.dot(db)} /> {db ? "connected" : "offline"}
      </span>
      <span>CI/CDecoy — Cyber Deception Platform</span>
    </footer>
  );
}
