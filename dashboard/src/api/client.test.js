import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  fetchStats,
  fetchSessions,
  fetchSessionEvents,
  fetchSessionReplay,
  fetchMitre,
  fetchEngage,
  fetchTopIPs,
  fetchKillChains,
  fetchHistogram,
  fetchGeo,
  fetchEvents,
  injectTestEvent,
  injectTestSession,
} from "./client";

describe("API client", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  function mockFetch(data, ok = true, status = 200) {
    return vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok,
      status,
      json: () => Promise.resolve(data),
    });
  }

  // ── GET endpoints ──

  it("fetchStats calls /api/stats", async () => {
    const spy = mockFetch({ total_sessions: 10 });
    const result = await fetchStats();
    expect(spy).toHaveBeenCalledWith("/api/stats");
    expect(result).toEqual({ total_sessions: 10 });
  });

  it("fetchSessions calls /api/sessions with default limit", async () => {
    const spy = mockFetch({ sessions: [] });
    await fetchSessions();
    expect(spy).toHaveBeenCalledWith("/api/sessions?limit=40");
  });

  it("fetchSessions accepts a custom limit", async () => {
    const spy = mockFetch({ sessions: [] });
    await fetchSessions(10);
    expect(spy).toHaveBeenCalledWith("/api/sessions?limit=10");
  });

  it("fetchSessionEvents calls correct endpoint with encoded ID", async () => {
    const spy = mockFetch({ events: [] });
    await fetchSessionEvents("abc/123");
    expect(spy).toHaveBeenCalledWith("/api/sessions/abc%2F123/events");
  });

  it("fetchSessionReplay calls correct endpoint", async () => {
    const spy = mockFetch({ session_id: "s1", events: [] });
    await fetchSessionReplay("s1");
    expect(spy).toHaveBeenCalledWith("/api/sessions/s1/replay");
  });

  it("fetchMitre calls /api/mitre", async () => {
    const spy = mockFetch({ techniques: [] });
    await fetchMitre();
    expect(spy).toHaveBeenCalledWith("/api/mitre");
  });

  it("fetchEngage calls /api/engage", async () => {
    const spy = mockFetch({ engage: [] });
    await fetchEngage();
    expect(spy).toHaveBeenCalledWith("/api/engage");
  });

  it("fetchTopIPs calls with default params", async () => {
    const spy = mockFetch({ ips: [] });
    await fetchTopIPs();
    expect(spy).toHaveBeenCalledWith("/api/top-ips?hours=24&limit=15");
  });

  it("fetchTopIPs accepts custom hours and limit", async () => {
    const spy = mockFetch({ ips: [] });
    await fetchTopIPs(48, 5);
    expect(spy).toHaveBeenCalledWith("/api/top-ips?hours=48&limit=5");
  });

  it("fetchKillChains calls with default limit", async () => {
    const spy = mockFetch({ sessions: [] });
    await fetchKillChains();
    expect(spy).toHaveBeenCalledWith("/api/kill-chains?limit=20");
  });

  it("fetchHistogram calls /api/duration-histogram", async () => {
    const spy = mockFetch({ buckets: [] });
    await fetchHistogram();
    expect(spy).toHaveBeenCalledWith("/api/duration-histogram");
  });

  it("fetchGeo calls with default hours", async () => {
    const spy = mockFetch({ countries: [] });
    await fetchGeo();
    expect(spy).toHaveBeenCalledWith("/api/geo?hours=168");
  });

  it("fetchGeo accepts custom hours", async () => {
    const spy = mockFetch({ countries: [] });
    await fetchGeo(24);
    expect(spy).toHaveBeenCalledWith("/api/geo?hours=24");
  });

  it("fetchEvents calls with default params", async () => {
    const spy = mockFetch([]);
    await fetchEvents();
    expect(spy).toHaveBeenCalledWith("/api/events?limit=100");
  });

  it("fetchEvents appends severity when provided", async () => {
    const spy = mockFetch([]);
    await fetchEvents(50, "critical");
    expect(spy).toHaveBeenCalledWith("/api/events?limit=50&severity=critical");
  });

  // ── POST endpoints ──

  it("injectTestEvent POSTs to /api/test/inject", async () => {
    const spy = mockFetch({ ok: true });
    await injectTestEvent();
    expect(spy).toHaveBeenCalledWith("/api/test/inject", { method: "POST" });
  });

  it("injectTestSession POSTs with default event count", async () => {
    const spy = mockFetch({ ok: true });
    await injectTestSession();
    expect(spy).toHaveBeenCalledWith("/api/test/inject-session?event_count=10", { method: "POST" });
  });

  it("injectTestSession accepts custom event count", async () => {
    const spy = mockFetch({ ok: true });
    await injectTestSession(25);
    expect(spy).toHaveBeenCalledWith("/api/test/inject-session?event_count=25", { method: "POST" });
  });

  // ── Error handling ──

  it("throws on non-ok response for GET requests", async () => {
    mockFetch(null, false, 500);
    await expect(fetchStats()).rejects.toThrow("API /api/stats returned 500");
  });

  it("throws with the correct status code in error message", async () => {
    mockFetch(null, false, 404);
    await expect(fetchMitre()).rejects.toThrow("404");
  });
});
