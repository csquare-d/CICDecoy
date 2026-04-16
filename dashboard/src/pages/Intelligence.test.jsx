import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import Intelligence from "./Intelligence";

function renderIntelligence(props = {}) {
  return render(
    <MemoryRouter>
      <Intelligence {...props} />
    </MemoryRouter>
  );
}

describe("Intelligence", () => {
  it("renders stat cards with zero counts when data is empty", () => {
    renderIntelligence();
    // "KILL CHAINS DETECTED" appears in both the StatCard label and panel title
    expect(screen.getAllByText("KILL CHAINS DETECTED").length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText("UNIQUE ATTACKER IPs")).toBeInTheDocument();
    expect(screen.getByText("COUNTRIES (7D)")).toBeInTheDocument();
  });

  it("renders panel titles", () => {
    renderIntelligence();
    expect(screen.getAllByText(/KILL CHAINS DETECTED/).length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText(/TOP ATTACKER IPs/)).toBeInTheDocument();
    expect(screen.getByText("ENGAGE EFFECTIVENESS")).toBeInTheDocument();
    expect(screen.getByText(/SOURCE GEOGRAPHY/)).toBeInTheDocument();
    expect(screen.getByText("SESSION DURATION")).toBeInTheDocument();
  });

  it("shows empty states when no data is provided", () => {
    renderIntelligence();
    expect(screen.getByText("No kill chain sessions detected yet")).toBeInTheDocument();
    expect(screen.getByText("No IP data yet")).toBeInTheDocument();
    expect(screen.getByText("No Engage data yet")).toBeInTheDocument();
    expect(screen.getByText("No geo data yet")).toBeInTheDocument();
    expect(screen.getByText("No duration data yet")).toBeInTheDocument();
  });

  it("renders kill chain sessions", () => {
    const killChains = {
      sessions: [
        {
          session_id: "kc-001",
          source_ip: "10.0.0.5",
          auth_username: "root",
          decoy_name: "hp-alpha",
          command_count: 20,
          duration_seconds: 300,
          phase_count: 4,
          phases: [
            { phase: "reconnaissance", techniques: [] },
            { phase: "execution", techniques: [] },
          ],
        },
      ],
    };
    renderIntelligence({ killChains });
    expect(screen.getByText("10.0.0.5")).toBeInTheDocument();
    expect(screen.getByText("20 cmds")).toBeInTheDocument();
    expect(screen.getByText("5m 0s")).toBeInTheDocument();
    expect(screen.getByText("4 phases")).toBeInTheDocument();
    // Timeline phases
    expect(screen.getByText("reconnaissance")).toBeInTheDocument();
    expect(screen.getByText("execution")).toBeInTheDocument();
  });

  it("renders top attacker IPs", () => {
    const topIPs = {
      ips: [
        { source_ip: "203.0.113.1", events: 50, sessions: 3, max_severity: "critical" },
        { source_ip: "198.51.100.2", events: 20, sessions: 1, max_severity: "low" },
      ],
    };
    renderIntelligence({ topIPs });
    expect(screen.getByText("203.0.113.1")).toBeInTheDocument();
    expect(screen.getByText("198.51.100.2")).toBeInTheDocument();
    expect(screen.getByText("50 evt")).toBeInTheDocument();
    expect(screen.getByText("3 sess")).toBeInTheDocument();
  });

  it("renders engage effectiveness data", () => {
    const engage = {
      engage: [
        {
          technique_id: "T1059",
          technique_name: "Scripting",
          engage_activity: "Deceive",
          times_observed: 12,
          effectiveness: 0.85,
        },
      ],
    };
    renderIntelligence({ engage });
    expect(screen.getByText(/T1059/)).toBeInTheDocument();
    expect(screen.getByText("Deceive")).toBeInTheDocument();
    expect(screen.getByText("12")).toBeInTheDocument();
    expect(screen.getByText("85%")).toBeInTheDocument();
  });

  it("renders geo data", () => {
    const geo = {
      countries: [
        {
          country_code: "CN",
          country_name: "China",
          sessions: 25,
          unique_ips: 8,
          avg_duration: 120,
        },
      ],
    };
    renderIntelligence({ geo });
    expect(screen.getByText("CN")).toBeInTheDocument();
    expect(screen.getByText("China")).toBeInTheDocument();
    expect(screen.getByText("25 sess")).toBeInTheDocument();
    expect(screen.getByText("8 IPs")).toBeInTheDocument();
    expect(screen.getByText("2m 0s")).toBeInTheDocument();
  });

  it("renders duration histogram", () => {
    const histogram = {
      total_sessions: 100,
      avg_seconds: 90,
      median_seconds: 60,
      buckets: [
        { label: "0-10s", lo: 0, count: 30 },
        { label: "10-30s", lo: 10, count: 45 },
        { label: "5-10m", lo: 300, count: 25 },
      ],
    };
    renderIntelligence({ histogram });
    expect(screen.getByText("100")).toBeInTheDocument();
    expect(screen.getByText("1m 30s")).toBeInTheDocument(); // avg
    expect(screen.getByText("1m 0s")).toBeInTheDocument(); // median
    expect(screen.getByText("0-10s")).toBeInTheDocument();
    expect(screen.getByText("10-30s")).toBeInTheDocument();
    expect(screen.getByText("5-10m")).toBeInTheDocument();
    expect(screen.getByText("30")).toBeInTheDocument();
    expect(screen.getByText("45")).toBeInTheDocument();
    expect(screen.getByText("25")).toBeInTheDocument();
  });

  it("renders stat card values from data", () => {
    renderIntelligence({
      killChains: { sessions: [{ session_id: "1", source_ip: "1.1.1.1", decoy_name: "d", command_count: 1, duration_seconds: 1, phase_count: 1, phases: [] }] },
      topIPs: { ips: [{ source_ip: "1.1.1.1", events: 1, sessions: 1, max_severity: "low" }, { source_ip: "2.2.2.2", events: 1, sessions: 1, max_severity: "low" }] },
      geo: { countries: [{ country_code: "US", country_name: "USA", sessions: 1, unique_ips: 1, avg_duration: 10 }] },
    });
    // "KILL CHAINS DETECTED" appears in both the StatCard and panel title
    expect(screen.getAllByText("KILL CHAINS DETECTED").length).toBe(2);
    expect(screen.getByText("UNIQUE ATTACKER IPs")).toBeInTheDocument();
    expect(screen.getByText("COUNTRIES (7D)")).toBeInTheDocument();
  });
});
