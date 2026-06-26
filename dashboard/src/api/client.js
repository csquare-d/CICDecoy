/**
 * CI/CDecoy Dashboard API Client
 *
 * All backend fetch calls in one place.
 * Responses are returned as-is from the FastAPI JSON.
 *
 * Auth: a shared API key is stored in localStorage under `STORAGE_KEY`.
 * Every fetch attaches it via the `X-API-Key` header. On 401 responses the
 * stored key is cleared and a UNAUTHORIZED_EVENT is dispatched so the app
 * can re-prompt.
 */

const BASE = "";
export const STORAGE_KEY = "cicdecoy_api_key";
export const UNAUTHORIZED_EVENT = "cicdecoy:unauthorized";

export function getApiKey() {
  try {
    return localStorage.getItem(STORAGE_KEY) || "";
  } catch {
    return "";
  }
}

// NOTE: API key stored in localStorage (plaintext). For production deployments,
// consider using httpOnly cookies or a proper auth flow instead.
export function setApiKey(key) {
  try {
    localStorage.setItem(STORAGE_KEY, key);
  } catch {
    /* storage may be disabled */
  }
}

export function clearApiKey() {
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch {
    /* storage may be disabled */
  }
}

function authHeaders() {
  const key = getApiKey();
  return key ? { "X-API-Key": key } : {};
}

function handleUnauthorized() {
  clearApiKey();
  try {
    window.dispatchEvent(new CustomEvent(UNAUTHORIZED_EVENT));
  } catch {
    /* SSR / test env */
  }
}

async function get(path) {
  const r = await fetch(BASE + path, { headers: authHeaders() });
  if (r.status === 401) {
    handleUnauthorized();
    throw new Error(`API ${path} returned 401`);
  }
  if (!r.ok) throw new Error(`API ${path} returned ${r.status}`);
  return r.json();
}

async function post(path) {
  const r = await fetch(BASE + path, {
    method: "POST",
    headers: authHeaders(),
  });
  if (r.status === 401) {
    handleUnauthorized();
    throw new Error(`API ${path} returned 401`);
  }
  return r.json();
}

/**
 * Append the API key as a query param. Used by EventSource (SSE), which
 * cannot set custom headers in browsers.
 */
export function withAuthQuery(path) {
  const key = getApiKey();
  if (!key) return path;
  const sep = path.includes("?") ? "&" : "?";
  return `${path}${sep}api_key=${encodeURIComponent(key)}`;
}

// ── Stats ──
export const fetchStats = () => get("/api/stats");

// ── Sessions ──
export const fetchSessions = (limit = 40) => get(`/api/sessions?limit=${limit}`);

// ── Session events (drill-down, no command.response) ──
export const fetchSessionEvents = (sid) => get(`/api/sessions/${encodeURIComponent(sid)}/events`);

// ── Session replay (includes command.response + delta timing) ──
export const fetchSessionReplay = (sid) => get(`/api/sessions/${encodeURIComponent(sid)}/replay`);

// ── MITRE ATT&CK heatmap (7d) ──
export const fetchMitre = () => get("/api/mitre");

// ── Engage effectiveness ──
export const fetchEngage = () => get("/api/engage");

// ── Top attacker IPs ──
export const fetchTopIPs = (hours = 24, limit = 15) =>
  get(`/api/top-ips?hours=${hours}&limit=${limit}`);

// ── Kill chain sessions ──
export const fetchKillChains = (limit = 20) => get(`/api/kill-chains?limit=${limit}`);

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

// ── Honeytokens ──
export const fetchHoneytokens = (limit = 50) => get(`/api/honeytokens?limit=${limit}`);
export const fetchHoneytokenEvents = (tokenName) =>
  get(`/api/honeytokens/${encodeURIComponent(tokenName)}/events`);

// ── Test injection ──
export const injectTestEvent = () => post("/api/test/inject");
export const injectTestSession = (count = 10) =>
  post(`/api/test/inject-session?event_count=${count}`);
