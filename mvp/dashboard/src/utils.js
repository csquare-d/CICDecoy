/**
 * Shared utility functions for the CI/CDecoy dashboard.
 */

/** Format seconds into human-readable duration */
export function formatDuration(sec) {
  if (sec == null || sec <= 0) return "--";
  if (sec < 60) return Math.round(sec) + "s";
  if (sec < 3600) return Math.floor(sec / 60) + "m " + Math.round(sec % 60) + "s";
  const h = Math.floor(sec / 3600);
  const m = Math.round((sec % 3600) / 60);
  return h + "h " + m + "m";
}

/** Parse a value that might be dict, JSON string, or null */
export function parseDict(val) {
  if (val == null) return {};
  if (typeof val === "object") return val;
  if (typeof val === "string") {
    try { return JSON.parse(val); } catch { return {}; }
  }
  return {};
}

/** Resolve IP from all possible field locations in an SSE event payload */
export function resolveIP(payload) {
  const d = parseDict(payload.data);
  const rd = parseDict(payload.raw_data);
  return (
    payload.source_ip || payload.src_ip || payload.client_ip ||
    d.client_ip || d.source_ip || d.src_ip || d.ip ||
    rd.client_ip || rd.source_ip || rd.src_ip || rd.ip ||
    ""
  );
}

/** Resolve username from all possible field locations */
export function resolveUser(payload) {
  const d = parseDict(payload.data);
  const rd = parseDict(payload.raw_data);
  return (
    payload.username || payload.user ||
    d.username || d.user ||
    rd.username || rd.user ||
    ""
  );
}

/** Resolve command from all possible field locations */
export function resolveCommand(payload) {
  const d = parseDict(payload.data);
  const rd = parseDict(payload.raw_data);
  return (
    d.command || d.input || d.cmd ||
    rd.command || rd.input || rd.cmd ||
    payload.command || payload.input ||
    ""
  );
}

/** Extract technique IDs from a mitre_techniques array */
export function techIds(arr) {
  if (!arr || arr.length === 0) return [];
  return arr
    .map((t) => (typeof t === "object" ? t.technique_id || "" : String(t)))
    .filter(Boolean);
}

/** Format ISO timestamp to HH:MM:SS */
export function fmtTime(iso) {
  return new Date(iso).toLocaleTimeString("en-US", {
    hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit",
  });
}
