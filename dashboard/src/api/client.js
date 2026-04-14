/**
 * CI/CDecoy Dashboard API Client
 *
 * All backend fetch calls in one place.
 * Responses are returned as-is from the FastAPI JSON.
 */

const BASE = "";

async function get(path) {
  const r = await fetch(BASE + path);
  if (!r.ok) throw new Error(`API ${path} returned ${r.status}`);
  return r.json();
}

async function post(path) {
  const r = await fetch(BASE + path, { method: "POST" });
  return r.json();
}

// ── Stats ──
export const fetchStats = () => get("/api/stats");

// ── Sessions ──
export const fetchSessions = (limit = 40) => get(`/api/sessions?limit=${limit}`);

// ── Session events (drill-down, no command.response) ──
export const fetchSessionEvents = (sid) =>
  get(`/api/sessions/${encodeURIComponent(sid)}/events`);

// ── Session replay (includes command.response + delta timing) ──
export const fetchSessionReplay = (sid) =>
  get(`/api/sessions/${encodeURIComponent(sid)}/replay`);

// ── MITRE ATT&CK heatmap (7d) ──
export const fetchMitre = () => get("/api/mitre");

// ── Engage effectiveness ──
export const fetchEngage = () => get("/api/engage");

// ── Top attacker IPs ──
export const fetchTopIPs = (hours = 24, limit = 15) =>
  get(`/api/top-ips?hours=${hours}&limit=${limit}`);

// ── Kill chain sessions ──
export const fetchKillChains = (limit = 20) =>
  get(`/api/kill-chains?limit=${limit}`);

// ── Duration histogram ──
export const fetchHistogram = () => get("/api/duration-histogram");

// ── Geo breakdown ──
export const fetchGeo = (hours = 168) => get(`/api/geo?hours=${hours}`);

// ── Recent events (DB) ──
export const fetchEvents = (limit = 100, severity = null) => {
  let path = `/api/events?limit=${limit}`;
  if (severity) path += `&severity=${severity}`;
  return get(path);
};

// ── Test injection ──
export const injectTestEvent = () => post("/api/test/inject");
export const injectTestSession = (count = 10) =>
  post(`/api/test/inject-session?event_count=${count}`);
