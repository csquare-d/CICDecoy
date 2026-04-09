/**
 * KillChainTimeline — renders phase progression as colored nodes with arrows.
 *
 * Props:
 *   phases — [{ phase, techniques: [{ id, name }] }]
 *   compact — smaller for inline use
 */

const EARLY = ["reconnaissance", "resource-development", "initial-access", "discovery"];
const MID = ["execution", "credential-access", "defense-evasion", "collection"];
// late = everything else

function phaseColor(phase) {
  if (EARLY.includes(phase)) return { bg: "var(--blue-dim)", fg: "var(--blue)", border: "rgba(10,132,255,0.2)" };
  if (MID.includes(phase)) return { bg: "var(--purple-dim)", fg: "var(--purple)", border: "rgba(191,90,242,0.2)" };
  return { bg: "var(--red-dim)", fg: "var(--red)", border: "rgba(255,45,85,0.2)" };
}

export default function KillChainTimeline({ phases = [], compact = false }) {
  if (phases.length === 0) return null;

  const nodeSize = compact ? { fontSize: 8, padding: "2px 6px" } : { fontSize: 9, padding: "4px 10px" };
  const arrowWidth = compact ? 14 : 20;

  return (
    <div style={{ display: "flex", alignItems: "center", overflowX: "auto", gap: 0 }}>
      {phases.map((p, i) => {
        const c = phaseColor(p.phase);
        const techList = (p.techniques || []).map((t) => t.id + (t.name ? " " + t.name : "")).join(", ") || "phase detected";

        return (
          <div key={i} style={{ display: "flex", alignItems: "center" }}>
            <div
              style={{
                ...nodeSize,
                fontFamily: "var(--mono)", fontWeight: 600,
                textTransform: "uppercase", letterSpacing: "0.5px",
                borderRadius: 3, whiteSpace: "nowrap",
                background: c.bg, color: c.fg,
                border: `1px solid ${c.border}`,
                position: "relative", cursor: "default",
                transition: "filter 0.15s",
              }}
              title={techList}
            >
              {p.phase}
            </div>
            {i < phases.length - 1 && (
              <div
                style={{
                  width: arrowWidth, height: 0,
                  borderTop: "1px solid var(--border-light)",
                  position: "relative", flexShrink: 0, margin: "0 2px",
                }}
              >
                <span
                  style={{
                    position: "absolute", right: -1, top: -4,
                    borderWidth: 4, borderStyle: "solid",
                    borderColor: "transparent", borderLeftWidth: 5,
                    borderLeftColor: "var(--border-light)",
                  }}
                />
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
