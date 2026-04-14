import { useState, useCallback, useEffect } from "react";
import SessionList from "../components/SessionList";
import TerminalReplay from "../components/TerminalReplay";
import { fetchSessionReplay } from "../api/client";

/**
 * Sessions page.
 *
 * Split layout: session list (left) + terminal replay (right).
 * When no session is selected, the list takes full width.
 *
 * Props:
 *   sessions — { sessions: [] } from /api/sessions (polled)
 *   refresh  — callback to re-fetch session list
 */

const s = {
  page: { animation: "fadeIn 0.3s ease", flex: 1, display: "flex", flexDirection: "column" },
  header: {
    display: "flex", justifyContent: "space-between", alignItems: "center",
    marginBottom: 12,
  },
  title: {
    fontSize: 10, fontWeight: 700, letterSpacing: "0.1em",
    color: "var(--text-dim)",
  },
  count: { fontSize: 10, color: "var(--text-muted)" },
  splitWrap: {
    flex: 1, display: "grid", gap: 12,
    minHeight: 0,
  },
  listPanel: {
    background: "var(--bg-panel)", border: "1px solid var(--border)",
    borderRadius: 6, overflow: "hidden", display: "flex", flexDirection: "column",
  },
  listBody: { flex: 1, overflowY: "auto" },
  replayPanel: {
    minHeight: 500, display: "flex", flexDirection: "column",
  },
  loading: {
    flex: 1, display: "flex", alignItems: "center", justifyContent: "center",
    fontFamily: "var(--mono)", fontSize: 11, color: "var(--text-dim)",
    background: "var(--bg-panel)", border: "1px solid var(--border)",
    borderRadius: 6,
  },
};

export default function Sessions({ sessions: sessionsData, refresh }) {
  const [selectedId, setSelectedId] = useState(null);
  const [replayData, setReplayData] = useState(null);
  const [replayLoading, setReplayLoading] = useState(false);
  const [replayCache, setReplayCache] = useState({});

  const sessionsList = sessionsData?.sessions || [];
  const hasReplay = selectedId != null;

  const openReplay = useCallback(async (sid) => {
    if (sid === selectedId) return;
    setSelectedId(sid);

    // Check cache first
    if (replayCache[sid]) {
      setReplayData(replayCache[sid]);
      return;
    }

    setReplayLoading(true);
    setReplayData(null);
    try {
      const data = await fetchSessionReplay(sid);
      setReplayData(data);
      setReplayCache((prev) => ({ ...prev, [sid]: data }));
    } catch (err) {
      console.warn("Replay fetch failed:", err);
      setReplayData(null);
    } finally {
      setReplayLoading(false);
    }
  }, [selectedId, replayCache]);

  const closeReplay = useCallback(() => {
    setSelectedId(null);
    setReplayData(null);
  }, []);

  // ESC to close
  useEffect(() => {
    const handler = (e) => { if (e.key === "Escape" && selectedId) closeReplay(); };
    document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
  }, [selectedId, closeReplay]);

  return (
    <div style={s.page}>
      <div style={s.header}>
        <span style={s.title}>ACTIVE & RECENT SESSIONS</span>
        <span style={s.count}>{sessionsList.length} total</span>
      </div>

      <div
        style={{
          ...s.splitWrap,
          gridTemplateColumns: hasReplay ? "340px 1fr" : "1fr",
        }}
      >
        {/* Session list */}
        <div style={s.listPanel}>
          <div style={s.listBody}>
            <SessionList
              sessions={sessionsList}
              compact={hasReplay}
              activeId={selectedId}
              onSelect={openReplay}
            />
          </div>
        </div>

        {/* Replay pane */}
        {hasReplay && (
          <div style={s.replayPanel}>
            {replayLoading ? (
              <div style={s.loading}>Loading session replay...</div>
            ) : replayData ? (
              <TerminalReplay data={replayData} onClose={closeReplay} />
            ) : (
              <div style={s.loading}>Failed to load replay</div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
