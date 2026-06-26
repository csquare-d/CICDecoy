import { NavLink, useLocation } from "react-router-dom";
import { clearApiKey, injectTestEvent, injectTestSession, UNAUTHORIZED_EVENT } from "../api/client";

const NAV = [
  { to: "/", label: "OVERVIEW", icon: "\u25C8" },
  { to: "/sessions", label: "SESSIONS", icon: "\u25C9" },
  { to: "/intelligence", label: "INTELLIGENCE", icon: "\u25C6" },
  { to: "/honeytokens", label: "HONEYTOKENS", icon: "\u2B23" },
  { to: "/fleet", label: "DECOY FLEET", icon: "\u2B21" },
];

const s = {
  header: {
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    padding: "12px 20px",
    borderBottom: "1px solid var(--border)",
    background: "linear-gradient(90deg, transparent, #2c2c2e, transparent)",
    position: "sticky",
    top: 0,
    zIndex: 100,
    overflow: "hidden",
  },
  topAccent: {
    position: "absolute",
    top: 0,
    left: 0,
    right: 0,
    height: 1,
    background: "linear-gradient(90deg, transparent, #bf5af233, #0a84ff33, transparent)",
  },
  left: { display: "flex", alignItems: "center", gap: 14 },
  logo: { fontSize: 18, fontWeight: 700, letterSpacing: "-0.02em" },
  version: {
    fontSize: 9,
    color: "var(--text-muted)",
    fontWeight: 500,
    letterSpacing: "0.1em",
    padding: "2px 8px",
    border: "1px solid var(--border-light)",
    borderRadius: 3,
  },
  nav: { display: "flex", gap: 2 },
  navBtn: (active) => ({
    background: active ? "var(--bg-hover)" : "transparent",
    border: active ? "1px solid var(--border-light)" : "1px solid transparent",
    color: active ? "var(--text)" : "var(--text-dim)",
    padding: "6px 14px",
    borderRadius: 4,
    fontSize: 10,
    fontWeight: 600,
    letterSpacing: "0.08em",
    cursor: "pointer",
    fontFamily: "var(--mono)",
    textDecoration: "none",
    transition: "all 0.15s ease",
  }),
  right: { display: "flex", gap: 8, alignItems: "center" },
  statusGroup: { display: "flex", gap: 12, alignItems: "center", marginRight: 10 },
  dot: (on) => ({
    width: 6,
    height: 6,
    borderRadius: "50%",
    backgroundColor: on ? "var(--green)" : "var(--text-muted)",
    boxShadow: on ? "0 0 6px var(--green)" : "none",
  }),
  statusLabel: {
    fontSize: 9,
    color: "var(--text-muted)",
    letterSpacing: "0.08em",
    fontWeight: 600,
    marginLeft: 4,
  },
  btn: (color) => ({
    fontFamily: "var(--mono)",
    fontSize: 9,
    fontWeight: 600,
    padding: "4px 10px",
    borderRadius: 3,
    cursor: "pointer",
    letterSpacing: "0.06em",
    textTransform: "uppercase",
    border: `1px solid ${color}44`,
    background: `${color}18`,
    color,
    transition: "all 0.15s",
  }),
};

export default function Header({ stats }) {
  const location = useLocation();
  const db = stats?.db_connected ?? false;
  const nats = stats?.nats_connected ?? false;

  async function handleInject() {
    await injectTestEvent();
  }

  async function handleBurst() {
    for (let i = 0; i < 10; i++) {
      injectTestEvent();
      await new Promise((r) => setTimeout(r, 150));
    }
  }

  async function handleSession() {
    await injectTestSession();
  }

  function handleSignOut() {
    clearApiKey();
    try {
      window.dispatchEvent(new CustomEvent(UNAUTHORIZED_EVENT));
    } catch {
      /* no-op */
    }
  }

  return (
    <header style={s.header}>
      <div style={s.topAccent} />
      <div style={s.left}>
        <div style={s.logo}>
          <span style={{ color: "var(--orange)" }}>CI</span>
          <span style={{ color: "var(--text-dim)" }}>/</span>
          <span style={{ color: "var(--orange)" }}>CDecoy</span>
        </div>
        <span style={s.version}>v0.1.0-alpha</span>
      </div>

      <nav style={s.nav}>
        {NAV.map((item) => {
          const active = location.pathname === item.to;
          return (
            <NavLink key={item.to} to={item.to} style={s.navBtn(active)}>
              <span style={{ marginRight: 6 }}>{item.icon}</span>
              {item.label}
            </NavLink>
          );
        })}
      </nav>

      <div style={s.right}>
        <div style={s.statusGroup}>
          <span style={{ display: "flex", alignItems: "center" }}>
            <span style={s.dot(nats)} />
            <span style={s.statusLabel}>NATS</span>
          </span>
          <span style={{ display: "flex", alignItems: "center" }}>
            <span style={s.dot(db)} />
            <span style={s.statusLabel}>DB</span>
          </span>
        </div>
        <button style={s.btn("var(--green)")} onClick={handleInject}>
          Inject
        </button>
        <button style={s.btn("var(--amber)")} onClick={handleBurst}>
          x10
        </button>
        <button style={s.btn("var(--red)")} onClick={handleSession}>
          Session
        </button>
        <button
          style={s.btn("var(--text-muted)")}
          onClick={handleSignOut}
          title="Clear stored API key"
        >
          Sign out
        </button>
      </div>
    </header>
  );
}
