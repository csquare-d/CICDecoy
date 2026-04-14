import { useEffect, useRef } from "react";
import SeverityBadge from "./SeverityBadge";
import KillChainTimeline from "./KillChainTimeline";
import { formatDuration } from "../utils";

/**
 * TerminalReplay — full session replay pane.
 *
 * Props:
 *   data      — { session_id, summary, events } from /api/sessions/{id}/replay
 *   onClose   — callback to close the replay view
 */

const GAP_THRESHOLD_MS = 5000;

const sty = {
  container: {
    display: "flex", flexDirection: "column", height: "100%",
    background: "var(--bg-panel)", border: "1px solid var(--border)",
    borderRadius: 6, overflow: "hidden", animation: "slideIn 0.25s ease",
  },
  header: {
    padding: "10px 14px", borderBottom: "1px solid var(--border)",
    display: "flex", justifyContent: "space-between", alignItems: "flex-start",
    flexShrink: 0,
  },
  title: { fontSize: 12, fontWeight: 600, color: "var(--text)" },
  titleDim: { fontWeight: 400, color: "var(--text-muted)", marginLeft: 6, fontSize: 11 },
  meta: {
    display: "flex", gap: 14, marginTop: 6, flexWrap: "wrap",
    fontFamily: "var(--mono)", fontSize: 10, color: "var(--text-dim)",
  },
  metaVal: { color: "var(--text)" },
  closeBtn: {
    background: "none", border: "1px solid var(--border-light)",
    color: "var(--text-dim)", padding: "3px 10px", borderRadius: 3,
    fontFamily: "var(--mono)", fontSize: 10, cursor: "pointer",
    transition: "all 0.15s", flexShrink: 0, marginLeft: 10,
  },
  statsStrip: {
    display: "flex", gap: 1, background: "var(--border)",
    borderBottom: "1px solid var(--border)", flexShrink: 0,
  },
  stat: { flex: 1, background: "var(--bg-panel)", padding: "8px 12px", textAlign: "center" },
  statVal: (accent) => ({
    fontFamily: "var(--mono)", fontSize: 16, fontWeight: 600,
    color: accent || "var(--text)", lineHeight: 1,
  }),
  statLabel: {
    fontSize: 9, color: "var(--text-dim)", textTransform: "uppercase",
    letterSpacing: "0.8px", marginTop: 3,
  },
  phases: {
    display: "flex", gap: 4, flexWrap: "wrap", padding: "8px 14px",
    borderBottom: "1px solid var(--border)", background: "var(--bg-panel)", flexShrink: 0,
  },
  terminal: {
    flex: 1, overflowY: "auto", background: "var(--term-bg)",
    padding: "12px 14px", fontFamily: "var(--mono)", fontSize: 11, lineHeight: 1.65,
  },
  divider: { color: "var(--text-muted)", marginBottom: 8, fontSize: 10, opacity: 0.5 },
};

function fmtTime(iso) {
  return new Date(iso).toLocaleTimeString("en-US", {
    hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit",
  });
}

function techStr(arr) {
  if (!arr || arr.length === 0) return "";
  return arr.map((t) => (typeof t === "object" ? t.technique_id : t)).filter(Boolean).join(", ");
}

// ── Terminal line sub-components ─────────────────────

function GapIndicator({ deltaMs }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8, margin: "6px 0", fontSize: 9, color: "var(--text-muted)", opacity: 0.4 }}>
      <div style={{ flex: 1, borderTop: "1px dashed var(--border-light)" }} />
      {(deltaMs / 1000).toFixed(1)}s pause
      <div style={{ flex: 1, borderTop: "1px dashed var(--border-light)" }} />
    </div>
  );
}

function LifecycleEvent({ time, color, label, detail }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 6, padding: "4px 0", margin: "4px 0", fontSize: 10 }}>
      <span style={{ width: 6, height: 6, borderRadius: "50%", backgroundColor: color, flexShrink: 0 }} />
      <span style={{ color: "#2a2f38" }}>[{time}]</span>
      <span style={{ fontFamily: "var(--mono)", textTransform: "uppercase", letterSpacing: "0.5px", color }}>{label}</span>
      {detail && <span style={{ color: "var(--text-dim)", fontFamily: "var(--mono)", fontSize: 10 }}>{detail}</span>}
    </div>
  );
}

function CommandLine({ time, ip, cmd, severity, mitre }) {
  const hasSev = severity === "critical" || severity === "high";
  const mitreIds = techStr(mitre);

  return (
    <div style={{ marginBottom: 1 }}>
      <span style={{ color: "#2a2f38" }}>[{time}] </span>
      <span style={{ color: "var(--red)" }}>{ip}</span>{" "}
      <span style={{ color: "var(--text-muted)" }}>$</span>{" "}
      <span style={{ color: "var(--green)" }}>{cmd}</span>
      {hasSev && (
        <SeverityBadge severity={severity} style={{ marginLeft: 4, fontSize: 8, padding: "1px 4px" }} />
      )}
      {mitreIds && (
        <span style={{ color: "var(--purple)", fontSize: 10, marginLeft: 6, opacity: 0.8 }}>{mitreIds}</span>
      )}
    </div>
  );
}

function ResponseBlock({ text }) {
  if (!text || text === "...") return null;
  return (
    <div style={{ marginBottom: 1 }}>
      <span style={{ color: "#636e7b", whiteSpace: "pre-wrap", wordBreak: "break-all" }}>{text}</span>
    </div>
  );
}

// ── Main component ──────────────────────────────────

export default function TerminalReplay({ data, onClose }) {
  const termRef = useRef(null);
  const summary = data?.summary || {};
  const events = data?.events || [];
  const phases = summary.attack_phases || [];
  const techs = summary.mitre_techniques || [];

  useEffect(() => {
    if (termRef.current) termRef.current.scrollTop = termRef.current.scrollHeight;
  }, [data]);

  const sevAccent =
    summary.max_severity === "critical" || summary.max_severity === "high"
      ? "var(--red)" : summary.max_severity === "medium" ? "var(--amber)" : null;

  const phaseObjs = phases.map((p) => ({
    phase: p,
    techniques: techs.filter((t) => t.tactic === p).map((t) => ({ id: t.technique_id, name: t.technique_name })),
  }));

  return (
    <div style={sty.container}>
      {/* Header */}
      <div style={sty.header}>
        <div style={{ flex: 1 }}>
          <div>
            <span style={sty.title}>{summary.decoy_name || "--"}</span>
            <span style={sty.titleDim}>session {data?.session_id}</span>
          </div>
          <div style={sty.meta}>
            <span>IP: <span style={sty.metaVal}>{summary.source_ip || "--"}</span></span>
            <span>User: <span style={sty.metaVal}>{summary.username || "--"}</span></span>
            <span>Tier: <span style={sty.metaVal}>{summary.decoy_tier || "--"}</span></span>
            <span>Phase: <span style={{ color: "var(--purple)" }}>{phases.length > 0 ? phases[phases.length - 1] : "--"}</span></span>
          </div>
        </div>
        <button style={sty.closeBtn} onClick={onClose}>ESC</button>
      </div>

      {/* Stats strip */}
      <div style={sty.statsStrip}>
        {[
          { val: summary.command_count || 0, label: "Commands" },
          { val: formatDuration(summary.duration_seconds), label: "Duration" },
          { val: summary.max_severity || "info", label: "Severity", accent: sevAccent },
          { val: techs.length, label: "Techniques" },
          { val: phases.length, label: "Phases" },
        ].map((item, i) => (
          <div key={i} style={sty.stat}>
            <div style={sty.statVal(item.accent)}>{item.val}</div>
            <div style={sty.statLabel}>{item.label}</div>
          </div>
        ))}
      </div>

      {/* Kill chain phases */}
      {phaseObjs.length > 0 && (
        <div style={sty.phases}>
          <KillChainTimeline phases={phaseObjs} compact />
        </div>
      )}

      {/* Terminal */}
      <div style={sty.terminal} ref={termRef}>
        <div style={sty.divider}>---- Session Replay ----</div>

        {events.map((ev, i) => {
          const timeStr = fmtTime(ev.timestamp);
          const etype = ev.event_type;
          const elements = [];

          // Timing gap
          if (ev.delta_ms != null && ev.delta_ms > GAP_THRESHOLD_MS && i > 0) {
            elements.push(<GapIndicator key={`gap-${i}`} deltaMs={ev.delta_ms} />);
          }

          // Lifecycle events
          if (etype === "connection.new") {
            elements.push(
              <LifecycleEvent key={`ev-${i}`} time={timeStr} color="var(--blue)" label="connection opened" detail={ev.source_ip} />
            );
            return elements;
          }
          if (etype === "auth.success") {
            const user = ev.raw_data?.username || ev.raw_data?.user || summary.username || "";
            elements.push(
              <LifecycleEvent key={`ev-${i}`} time={timeStr} color="var(--green)" label="authenticated" detail={user} />
            );
            return elements;
          }
          if (etype === "session.end" || etype === "session.close") {
            elements.push(
              <LifecycleEvent key={`ev-${i}`} time={timeStr} color="var(--text-muted)" label="session closed" />
            );
            return elements;
          }

          // Command response
          if (etype === "command.response") {
            const resp = ev.response || ev.raw_data?.response || ev.raw_data?.output || "";
            elements.push(<ResponseBlock key={`ev-${i}`} text={resp} />);
            return elements;
          }

          // Command exec
          if (etype === "command.exec" || etype === "command") {
            const cmd = ev.command || ev.raw_data?.command || ev.raw_data?.input || "";
            const ip = ev.source_ip || summary.source_ip || "";

            elements.push(
              <CommandLine
                key={`cmd-${i}`}
                time={timeStr} ip={ip} cmd={cmd}
                severity={ev.severity} mitre={ev.mitre_techniques}
              />
            );

            // Inline response on same event
            const resp = ev.response || ev.raw_data?.response || "";
            if (resp && resp !== "...") {
              elements.push(<ResponseBlock key={`resp-${i}`} text={resp} />);
            }
            return elements;
          }

          // Generic event
          elements.push(
            <LifecycleEvent key={`ev-${i}`} time={timeStr} color="var(--text-muted)" label={etype} />
          );
          return elements;
        })}
      </div>
    </div>
  );
}
