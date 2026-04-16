import { describe, it, expect } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import DecoyFleet from "./DecoyFleet";

const SAMPLE_SESSIONS = {
  sessions: [
    {
      session_id: "s1",
      decoy_name: "honeypot-alpha",
      decoy_tier: 1,
      source_ip: "10.0.0.1",
      max_severity: "critical",
    },
    {
      session_id: "s2",
      decoy_name: "honeypot-alpha",
      decoy_tier: 1,
      source_ip: "10.0.0.2",
      max_severity: "high",
    },
    {
      session_id: "s3",
      decoy_name: "honeypot-beta",
      decoy_tier: 2,
      source_ip: "10.0.0.3",
      max_severity: "low",
    },
    {
      session_id: "s4",
      decoy_name: "honeypot-gamma",
      decoy_tier: 3,
      source_ip: "10.0.0.4",
      max_severity: "medium",
    },
  ],
};

describe("DecoyFleet", () => {
  it("renders the page title", () => {
    render(<DecoyFleet sessions={SAMPLE_SESSIONS} stats={{}} />);
    expect(screen.getByText("DECOY FLEET MANAGEMENT")).toBeInTheDocument();
  });

  it("renders table headers", () => {
    render(<DecoyFleet sessions={SAMPLE_SESSIONS} stats={{}} />);
    expect(screen.getByText("NAME")).toBeInTheDocument();
    expect(screen.getByText("TIER")).toBeInTheDocument();
    expect(screen.getByText("TYPE")).toBeInTheDocument();
    expect(screen.getByText("ZONE")).toBeInTheDocument();
    expect(screen.getByText("STATUS")).toBeInTheDocument();
    expect(screen.getByText("SESSIONS")).toBeInTheDocument();
    expect(screen.getByText("ALERTS")).toBeInTheDocument();
  });

  it("renders filter buttons", () => {
    render(<DecoyFleet sessions={SAMPLE_SESSIONS} stats={{}} />);
    expect(screen.getByText("All")).toBeInTheDocument();
    expect(screen.getByText("T1")).toBeInTheDocument();
    expect(screen.getByText("T2")).toBeInTheDocument();
    expect(screen.getByText("T3")).toBeInTheDocument();
  });

  it("derives decoy entries from session data", () => {
    render(<DecoyFleet sessions={SAMPLE_SESSIONS} stats={{}} />);
    expect(screen.getByText("honeypot-alpha")).toBeInTheDocument();
    expect(screen.getByText("honeypot-beta")).toBeInTheDocument();
    expect(screen.getByText("honeypot-gamma")).toBeInTheDocument();
  });

  it("aggregates session counts per decoy", () => {
    const { container } = render(<DecoyFleet sessions={SAMPLE_SESSIONS} stats={{}} />);
    // honeypot-alpha has 2 sessions, beta has 1, gamma has 1
    // Find the row with honeypot-alpha and check its session count
    const rows = container.querySelectorAll("[style*='grid']");
    // The row for honeypot-alpha should contain "2" for sessions
    const alphaRow = Array.from(rows).find(
      (r) => r.textContent.includes("honeypot-alpha")
    );
    expect(alphaRow).toBeTruthy();
    expect(alphaRow.textContent).toContain("2");
  });

  it("aggregates alert counts for high/critical sessions", () => {
    const { container } = render(<DecoyFleet sessions={SAMPLE_SESSIONS} stats={{}} />);
    // honeypot-alpha: 2 sessions, both high/critical => 2 alerts
    const alphaRow = Array.from(container.querySelectorAll("[style*='grid']")).find(
      (r) => r.textContent.includes("honeypot-alpha")
    );
    expect(alphaRow).toBeTruthy();
    // alert count of 2
    expect(alphaRow.textContent).toContain("2");
  });

  it("filters by tier when T1 is clicked", () => {
    render(<DecoyFleet sessions={SAMPLE_SESSIONS} stats={{}} />);
    fireEvent.click(screen.getByText("T1"));
    // Only honeypot-alpha (tier 1) should remain
    expect(screen.getByText("honeypot-alpha")).toBeInTheDocument();
    expect(screen.queryByText("honeypot-beta")).not.toBeInTheDocument();
    expect(screen.queryByText("honeypot-gamma")).not.toBeInTheDocument();
  });

  it("filters by tier when T2 is clicked", () => {
    render(<DecoyFleet sessions={SAMPLE_SESSIONS} stats={{}} />);
    fireEvent.click(screen.getByText("T2"));
    expect(screen.queryByText("honeypot-alpha")).not.toBeInTheDocument();
    expect(screen.getByText("honeypot-beta")).toBeInTheDocument();
    expect(screen.queryByText("honeypot-gamma")).not.toBeInTheDocument();
  });

  it("filters by tier when T3 is clicked", () => {
    render(<DecoyFleet sessions={SAMPLE_SESSIONS} stats={{}} />);
    fireEvent.click(screen.getByText("T3"));
    expect(screen.queryByText("honeypot-alpha")).not.toBeInTheDocument();
    expect(screen.queryByText("honeypot-beta")).not.toBeInTheDocument();
    expect(screen.getByText("honeypot-gamma")).toBeInTheDocument();
  });

  it("shows all decoys when All filter is clicked after filtering", () => {
    render(<DecoyFleet sessions={SAMPLE_SESSIONS} stats={{}} />);
    fireEvent.click(screen.getByText("T1"));
    expect(screen.queryByText("honeypot-beta")).not.toBeInTheDocument();
    fireEvent.click(screen.getByText("All"));
    expect(screen.getByText("honeypot-alpha")).toBeInTheDocument();
    expect(screen.getByText("honeypot-beta")).toBeInTheDocument();
    expect(screen.getByText("honeypot-gamma")).toBeInTheDocument();
  });

  it("shows empty state when no sessions provided", () => {
    render(<DecoyFleet sessions={null} stats={{}} />);
    expect(screen.getByText("No decoys found for this filter")).toBeInTheDocument();
  });

  it("shows empty state when filtered tier has no decoys", () => {
    const sessions = {
      sessions: [
        { session_id: "s1", decoy_name: "hp", decoy_tier: 1, max_severity: "low" },
      ],
    };
    render(<DecoyFleet sessions={sessions} stats={{}} />);
    fireEvent.click(screen.getByText("T3"));
    expect(screen.getByText("No decoys found for this filter")).toBeInTheDocument();
  });

  it("renders TierBadge for each decoy", () => {
    render(<DecoyFleet sessions={SAMPLE_SESSIONS} stats={{}} />);
    expect(screen.getByText("T1 BEACON")).toBeInTheDocument();
    expect(screen.getByText("T2 SCRIPTED")).toBeInTheDocument();
    expect(screen.getByText("T3 ADAPTIVE")).toBeInTheDocument();
  });

  it("renders StatusIndicator for each decoy", () => {
    render(<DecoyFleet sessions={SAMPLE_SESSIONS} stats={{}} />);
    // All derived decoys have status "active" -> "ONLINE"
    const onlines = screen.getAllByText("ONLINE");
    expect(onlines.length).toBe(3);
  });
});
