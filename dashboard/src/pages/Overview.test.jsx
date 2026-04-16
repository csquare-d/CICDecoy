import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import Overview from "./Overview";

describe("Overview", () => {
  it("renders stat cards with data from stats prop", () => {
    const stats = {
      total_sessions: 42,
      active_sessions: 3,
      total_events: 150,
      unique_ips: 12,
      high_sev_24h: 5,
      kill_chains: 1,
    };
    render(<Overview stats={stats} mitre={null} sseEvents={[]} eventCount={0} />);
    expect(screen.getByText("42")).toBeInTheDocument();
    expect(screen.getByText("3")).toBeInTheDocument();
    expect(screen.getByText("150")).toBeInTheDocument();
    expect(screen.getByText("12")).toBeInTheDocument();
    expect(screen.getByText("5")).toBeInTheDocument();
  });

  it("renders stat card labels", () => {
    render(<Overview stats={{}} />);
    expect(screen.getByText("SESSIONS (TOTAL)")).toBeInTheDocument();
    expect(screen.getByText("ACTIVE NOW")).toBeInTheDocument();
    expect(screen.getByText("EVENTS / 24H")).toBeInTheDocument();
    expect(screen.getByText("UNIQUE IPs / 24H")).toBeInTheDocument();
    expect(screen.getByText("HIGH/CRIT (24H)")).toBeInTheDocument();
    expect(screen.getByText("KILL CHAINS")).toBeInTheDocument();
  });

  it("renders fallback dashes when stats is null", () => {
    render(<Overview stats={null} />);
    // StatCards with null/undefined values show "--"
    const dashes = screen.getAllByText("--");
    expect(dashes.length).toBeGreaterThanOrEqual(6);
  });

  it("renders the ALERT FEED panel", () => {
    render(<Overview stats={{}} />);
    expect(screen.getByText("ALERT FEED")).toBeInTheDocument();
    expect(screen.getByText(/LIVE/)).toBeInTheDocument();
  });

  it("renders the MITRE ATT&CK panel", () => {
    render(<Overview stats={{}} />);
    expect(screen.getByText(/MITRE ATT&CK/)).toBeInTheDocument();
  });

  it("shows empty alert message when no SSE events", () => {
    render(<Overview stats={{}} sseEvents={[]} />);
    expect(screen.getByText(/No alerts yet/)).toBeInTheDocument();
  });

  it("renders alert feed items from SSE events", () => {
    const sseEvents = [
      {
        ts: "2024-06-15T10:00:00Z",
        payload: {
          severity: "critical",
          decoy_name: "hp-alpha",
          event_type: "command.exec",
          timestamp: "2024-06-15T10:00:00Z",
          data: { command: "cat /etc/shadow" },
        },
      },
      {
        ts: "2024-06-15T10:00:01Z",
        payload: {
          severity: "high",
          decoy_name: "hp-beta",
          event_type: "auth.attempt",
          timestamp: "2024-06-15T10:00:01Z",
        },
      },
    ];
    render(<Overview stats={{}} sseEvents={sseEvents} />);
    expect(screen.getByText("hp-alpha")).toBeInTheDocument();
    expect(screen.getByText("hp-beta")).toBeInTheDocument();
    expect(screen.getByText("command.exec")).toBeInTheDocument();
    expect(screen.getByText("auth.attempt")).toBeInTheDocument();
  });

  it("filters out info severity from alert feed", () => {
    const sseEvents = [
      {
        ts: "2024-06-15T10:00:00Z",
        payload: {
          severity: "info",
          decoy_name: "hp-info",
          event_type: "connection.new",
          timestamp: "2024-06-15T10:00:00Z",
        },
      },
    ];
    render(<Overview stats={{}} sseEvents={sseEvents} />);
    expect(screen.queryByText("hp-info")).not.toBeInTheDocument();
    expect(screen.getByText(/No alerts yet/)).toBeInTheDocument();
  });

  it("renders MITRE heatmap with technique data", () => {
    const mitre = {
      techniques: [
        { technique_id: "T1059", technique_name: "Scripting", tactic: "execution", total: 10, actors: 2 },
      ],
    };
    render(<Overview stats={{}} mitre={mitre} />);
    expect(screen.getByText("T1059")).toBeInTheDocument();
    expect(screen.getByText("Scripting")).toBeInTheDocument();
  });

  it("renders MITRE empty state when no techniques", () => {
    render(<Overview stats={{}} mitre={{ techniques: [] }} />);
    expect(screen.getByText(/No MITRE technique data yet/)).toBeInTheDocument();
  });
});
