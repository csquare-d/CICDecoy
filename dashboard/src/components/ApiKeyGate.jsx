import { useEffect, useState } from "react";
import {
  getApiKey,
  setApiKey,
  UNAUTHORIZED_EVENT,
} from "../api/client";

/**
 * ApiKeyGate — renders a modal prompting for the dashboard API key.
 *
 * Controls a single boolean `unlocked`. When unlocked, children render.
 * When locked, a full-screen modal collects the key. The key is stored in
 * localStorage so it persists across reloads.
 *
 * The component also listens for the `cicdecoy:unauthorized` window event,
 * which the API client dispatches on 401 responses — that re-locks the UI.
 */

const s = {
  backdrop: {
    position: "fixed", inset: 0, background: "rgba(0,0,0,0.85)",
    display: "flex", alignItems: "center", justifyContent: "center",
    zIndex: 9999, fontFamily: "var(--mono)",
  },
  card: {
    background: "var(--bg)", border: "1px solid var(--border-light)",
    borderRadius: 6, padding: 32, width: 440, maxWidth: "92vw",
    boxShadow: "0 8px 40px rgba(0,0,0,0.6)",
  },
  title: {
    fontSize: 16, fontWeight: 700, letterSpacing: "-0.01em",
    marginBottom: 6, color: "var(--text)",
  },
  brand: { color: "var(--orange)" },
  sub: {
    fontSize: 11, color: "var(--text-muted)", marginBottom: 20,
    lineHeight: 1.6,
  },
  label: {
    display: "block", fontSize: 10, fontWeight: 600,
    letterSpacing: "0.08em", color: "var(--text-dim)",
    textTransform: "uppercase", marginBottom: 6,
  },
  input: {
    width: "100%", padding: "10px 12px",
    fontFamily: "var(--mono)", fontSize: 13,
    background: "var(--bg-hover)", color: "var(--text)",
    border: "1px solid var(--border-light)", borderRadius: 4,
    boxSizing: "border-box", outline: "none",
  },
  row: { display: "flex", gap: 8, alignItems: "center", marginTop: 16 },
  btn: {
    padding: "8px 18px", fontFamily: "var(--mono)", fontSize: 11,
    fontWeight: 600, letterSpacing: "0.08em", textTransform: "uppercase",
    cursor: "pointer", borderRadius: 4,
    background: "var(--orange)", color: "#111", border: "none",
  },
  btnDisabled: { opacity: 0.4, cursor: "not-allowed" },
  hint: {
    fontSize: 10, color: "var(--text-muted)", marginTop: 12,
    lineHeight: 1.6,
  },
  err: { fontSize: 11, color: "var(--red, #ff453a)", marginTop: 8 },
};

export default function ApiKeyGate({ children }) {
  const [unlocked, setUnlocked] = useState(() => !!getApiKey());
  const [value, setValue] = useState("");
  const [err, setErr] = useState("");

  useEffect(() => {
    function onUnauthorized() {
      setUnlocked(false);
      setValue("");
      setErr("Key rejected. Please re-enter.");
    }
    window.addEventListener(UNAUTHORIZED_EVENT, onUnauthorized);
    return () => window.removeEventListener(UNAUTHORIZED_EVENT, onUnauthorized);
  }, []);

  function submit(e) {
    e.preventDefault();
    const trimmed = value.trim();
    if (!trimmed) {
      setErr("API key is required.");
      return;
    }
    setApiKey(trimmed);
    setErr("");
    setUnlocked(true);
    setValue("");
  }

  if (unlocked) return children;

  return (
    <div style={s.backdrop} role="dialog" aria-modal="true" aria-label="API key required">
      <form style={s.card} onSubmit={submit}>
        <div style={s.title}>
          <span style={s.brand}>CI</span>
          /
          <span style={s.brand}>CDecoy</span>
          {" "}Dashboard
        </div>
        <div style={s.sub}>
          This dashboard requires a shared API key. See
          {" "}<code>DASHBOARD_API_KEY</code>{" "}
          in your environment, or check the backend logs for the ephemeral
          dev key.
        </div>
        <label style={s.label} htmlFor="cicdecoy-api-key">API Key</label>
        <input
          id="cicdecoy-api-key"
          type="password"
          style={s.input}
          value={value}
          onChange={(e) => setValue(e.target.value)}
          autoFocus
          autoComplete="off"
          spellCheck={false}
          placeholder="Paste your API key"
        />
        {err && <div style={s.err}>{err}</div>}
        <div style={s.row}>
          <button
            type="submit"
            style={{ ...s.btn, ...(value.trim() ? {} : s.btnDisabled) }}
            disabled={!value.trim()}
          >
            Unlock
          </button>
        </div>
        <div style={s.hint}>
          Key is stored in this browser only (localStorage). Clear it at any
          time from the dashboard header.
        </div>
      </form>
    </div>
  );
}
