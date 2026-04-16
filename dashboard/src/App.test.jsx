import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import App from "./App";

// Mock all API client functions to avoid real network calls
vi.mock("./api/client", () => ({
  fetchStats: vi.fn(() => Promise.resolve({ total_sessions: 0, db_connected: true, nats_connected: true })),
  fetchSessions: vi.fn(() => Promise.resolve({ sessions: [] })),
  fetchMitre: vi.fn(() => Promise.resolve({ techniques: [] })),
  fetchEngage: vi.fn(() => Promise.resolve({ engage: [] })),
  fetchTopIPs: vi.fn(() => Promise.resolve({ ips: [] })),
  fetchKillChains: vi.fn(() => Promise.resolve({ sessions: [] })),
  fetchHistogram: vi.fn(() => Promise.resolve({ buckets: [] })),
  fetchGeo: vi.fn(() => Promise.resolve({ countries: [] })),
  injectTestEvent: vi.fn(() => Promise.resolve({})),
  injectTestSession: vi.fn(() => Promise.resolve({})),
}));

// Mock useSSE to avoid EventSource usage
vi.mock("./hooks/useSSE", () => ({
  default: () => ({ events: [], connected: false, eventCount: 0 }),
}));

function renderApp(route = "/") {
  return render(
    <MemoryRouter initialEntries={[route]}>
      <App />
    </MemoryRouter>
  );
}

describe("App", () => {
  it("renders the Header with nav links", () => {
    renderApp();
    expect(screen.getByText("OVERVIEW")).toBeInTheDocument();
    expect(screen.getByText("SESSIONS")).toBeInTheDocument();
    expect(screen.getByText("INTELLIGENCE")).toBeInTheDocument();
    expect(screen.getByText("DECOY FLEET")).toBeInTheDocument();
  });

  it("renders the Footer", () => {
    renderApp();
    expect(screen.getByText(/CI\/CDecoy/)).toBeInTheDocument();
  });

  it("renders Overview page on root route", () => {
    renderApp("/");
    expect(screen.getByText("ALERT FEED")).toBeInTheDocument();
    expect(screen.getByText(/MITRE ATT&CK/)).toBeInTheDocument();
  });

  it("renders Sessions page on /sessions route", () => {
    renderApp("/sessions");
    expect(screen.getByText("ACTIVE & RECENT SESSIONS")).toBeInTheDocument();
  });

  it("renders Intelligence page on /intelligence route", () => {
    renderApp("/intelligence");
    expect(screen.getByText("ENGAGE EFFECTIVENESS")).toBeInTheDocument();
    expect(screen.getByText(/SOURCE GEOGRAPHY/)).toBeInTheDocument();
  });

  it("renders DecoyFleet page on /fleet route", () => {
    renderApp("/fleet");
    expect(screen.getByText("DECOY FLEET MANAGEMENT")).toBeInTheDocument();
  });
});
