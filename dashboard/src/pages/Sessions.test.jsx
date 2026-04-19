import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import Sessions from "./Sessions";

// Mock fetchSessionReplay to avoid real network calls
vi.mock("../api/client", () => ({
  fetchSessionReplay: vi.fn(() =>
    Promise.resolve({
      session_id: "sess-001",
      summary: { decoy_name: "hp-alpha", source_ip: "1.2.3.4" },
      events: [],
    })
  ),
  getApiKey: vi.fn(() => ""),
  setApiKey: vi.fn(),
  clearApiKey: vi.fn(),
  UNAUTHORIZED_EVENT: "cicdecoy:unauthorized",
}));

const SAMPLE_SESSIONS = {
  sessions: [
    {
      session_id: "sess-001",
      source_ip: "192.168.1.1",
      auth_username: "root",
      decoy_name: "hp-alpha",
      command_count: 5,
      max_severity: "high",
      mitre_techniques: [],
      attack_phases: [],
      kill_chain_detected: false,
    },
    {
      session_id: "sess-002",
      source_ip: "10.0.0.1",
      auth_username: "admin",
      decoy_name: "hp-beta",
      command_count: 2,
      max_severity: "low",
      mitre_techniques: [],
      attack_phases: [],
      kill_chain_detected: false,
    },
  ],
};

describe("Sessions", () => {
  it("renders the page title", () => {
    render(<Sessions sessions={SAMPLE_SESSIONS} refresh={() => {}} />);
    expect(screen.getByText("ACTIVE & RECENT SESSIONS")).toBeInTheDocument();
  });

  it("renders session count", () => {
    render(<Sessions sessions={SAMPLE_SESSIONS} refresh={() => {}} />);
    expect(screen.getByText("2 total")).toBeInTheDocument();
  });

  it("renders session list with session data", () => {
    render(<Sessions sessions={SAMPLE_SESSIONS} refresh={() => {}} />);
    expect(screen.getByText("192.168.1.1")).toBeInTheDocument();
    expect(screen.getByText("10.0.0.1")).toBeInTheDocument();
  });

  it("renders empty state when sessions is null", () => {
    render(<Sessions sessions={null} refresh={() => {}} />);
    expect(screen.getByText(/No sessions yet/)).toBeInTheDocument();
    expect(screen.getByText("0 total")).toBeInTheDocument();
  });

  it("does not show replay pane initially", () => {
    render(<Sessions sessions={SAMPLE_SESSIONS} refresh={() => {}} />);
    expect(screen.queryByText("Loading session replay...")).not.toBeInTheDocument();
    expect(screen.queryByText("ESC")).not.toBeInTheDocument();
  });

  it("shows loading state when a session is clicked", async () => {
    render(<Sessions sessions={SAMPLE_SESSIONS} refresh={() => {}} />);
    // Click first row to trigger replay
    const row = screen.getByText("192.168.1.1").closest("tr");
    fireEvent.click(row);
    // Should show loading state while fetching
    expect(screen.getByText("Loading session replay...")).toBeInTheDocument();
  });
});
