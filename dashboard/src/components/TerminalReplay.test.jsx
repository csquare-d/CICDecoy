import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import TerminalReplay from "./TerminalReplay";

const SAMPLE_DATA = {
  session_id: "sess-abc-123",
  summary: {
    decoy_name: "honeypot-alpha",
    source_ip: "192.168.1.50",
    username: "attacker",
    decoy_tier: 2,
    command_count: 5,
    duration_seconds: 180,
    max_severity: "high",
    attack_phases: ["execution", "credential-access"],
    mitre_techniques: [
      { technique_id: "T1059", technique_name: "Command Interpreter", tactic: "execution" },
      { technique_id: "T1110", technique_name: "Brute Force", tactic: "credential-access" },
    ],
  },
  events: [
    {
      timestamp: "2024-06-15T10:00:00Z",
      event_type: "connection.new",
      source_ip: "192.168.1.50",
    },
    {
      timestamp: "2024-06-15T10:00:02Z",
      event_type: "auth.success",
      raw_data: { username: "attacker" },
    },
    {
      timestamp: "2024-06-15T10:00:10Z",
      event_type: "command.exec",
      command: "whoami",
      source_ip: "192.168.1.50",
      severity: "low",
      response: "root",
    },
    {
      timestamp: "2024-06-15T10:00:15Z",
      event_type: "command.exec",
      command: "cat /etc/shadow",
      source_ip: "192.168.1.50",
      severity: "critical",
      mitre_techniques: [{ technique_id: "T1003" }],
    },
    {
      timestamp: "2024-06-15T10:03:00Z",
      event_type: "session.end",
    },
  ],
};

describe("TerminalReplay", () => {
  it("renders the decoy name and session ID", () => {
    render(<TerminalReplay data={SAMPLE_DATA} onClose={() => {}} />);
    expect(screen.getByText("honeypot-alpha")).toBeInTheDocument();
    expect(screen.getByText(/sess-abc-123/)).toBeInTheDocument();
  });

  it("renders session metadata (IP, User, Tier)", () => {
    render(<TerminalReplay data={SAMPLE_DATA} onClose={() => {}} />);
    // IP appears in metadata and command lines
    expect(screen.getAllByText("192.168.1.50").length).toBeGreaterThanOrEqual(1);
    // "attacker" appears in metadata and possibly auth event
    expect(screen.getAllByText("attacker").length).toBeGreaterThanOrEqual(1);
    // Tier value
    expect(screen.getAllByText("2").length).toBeGreaterThanOrEqual(1);
  });

  it("renders the stats strip with command count", () => {
    render(<TerminalReplay data={SAMPLE_DATA} onClose={() => {}} />);
    expect(screen.getByText("5")).toBeInTheDocument();
    expect(screen.getByText("Commands")).toBeInTheDocument();
  });

  it("renders formatted duration in stats strip", () => {
    render(<TerminalReplay data={SAMPLE_DATA} onClose={() => {}} />);
    expect(screen.getByText("3m 0s")).toBeInTheDocument();
    expect(screen.getByText("Duration")).toBeInTheDocument();
  });

  it("renders severity in stats strip", () => {
    render(<TerminalReplay data={SAMPLE_DATA} onClose={() => {}} />);
    expect(screen.getByText("Severity")).toBeInTheDocument();
    expect(screen.getByText("high")).toBeInTheDocument();
  });

  it("renders technique and phase counts", () => {
    render(<TerminalReplay data={SAMPLE_DATA} onClose={() => {}} />);
    expect(screen.getByText("Techniques")).toBeInTheDocument();
    expect(screen.getByText("Phases")).toBeInTheDocument();
  });

  it("renders the Session Replay divider", () => {
    render(<TerminalReplay data={SAMPLE_DATA} onClose={() => {}} />);
    expect(screen.getByText("---- Session Replay ----")).toBeInTheDocument();
  });

  it("renders connection.new as lifecycle event", () => {
    render(<TerminalReplay data={SAMPLE_DATA} onClose={() => {}} />);
    expect(screen.getByText("connection opened")).toBeInTheDocument();
  });

  it("renders auth.success as lifecycle event", () => {
    render(<TerminalReplay data={SAMPLE_DATA} onClose={() => {}} />);
    expect(screen.getByText("authenticated")).toBeInTheDocument();
  });

  it("renders command.exec events with the command text", () => {
    render(<TerminalReplay data={SAMPLE_DATA} onClose={() => {}} />);
    expect(screen.getByText("whoami")).toBeInTheDocument();
    expect(screen.getByText("cat /etc/shadow")).toBeInTheDocument();
  });

  it("renders inline response for commands", () => {
    render(<TerminalReplay data={SAMPLE_DATA} onClose={() => {}} />);
    expect(screen.getByText("root")).toBeInTheDocument();
  });

  it("renders session.end as lifecycle event", () => {
    render(<TerminalReplay data={SAMPLE_DATA} onClose={() => {}} />);
    expect(screen.getByText("session closed")).toBeInTheDocument();
  });

  it("renders MITRE technique IDs on high-severity commands", () => {
    render(<TerminalReplay data={SAMPLE_DATA} onClose={() => {}} />);
    expect(screen.getByText("T1003")).toBeInTheDocument();
  });

  it("calls onClose when ESC button is clicked", () => {
    const onClose = vi.fn();
    render(<TerminalReplay data={SAMPLE_DATA} onClose={onClose} />);
    fireEvent.click(screen.getByText("ESC"));
    expect(onClose).toHaveBeenCalledOnce();
  });

  it("renders kill chain timeline when phases exist", () => {
    render(<TerminalReplay data={SAMPLE_DATA} onClose={() => {}} />);
    // Phase names appear in both metadata and KillChainTimeline
    expect(screen.getAllByText("execution").length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText("credential-access").length).toBeGreaterThanOrEqual(1);
  });

  it("handles missing data gracefully", () => {
    const minimalData = { session_id: "s1", summary: {}, events: [] };
    render(<TerminalReplay data={minimalData} onClose={() => {}} />);
    expect(screen.getByText("---- Session Replay ----")).toBeInTheDocument();
    // decoy_name falls back to "--"
    expect(screen.getAllByText("--").length).toBeGreaterThanOrEqual(1);
  });

  it("renders gap indicator for large time deltas", () => {
    const dataWithGap = {
      session_id: "s2",
      summary: {},
      events: [
        { timestamp: "2024-06-15T10:00:00Z", event_type: "command.exec", command: "ls" },
        { timestamp: "2024-06-15T10:01:00Z", event_type: "command.exec", command: "pwd", delta_ms: 60000 },
      ],
    };
    render(<TerminalReplay data={dataWithGap} onClose={() => {}} />);
    expect(screen.getByText(/60\.0s pause/)).toBeInTheDocument();
  });

  it("does not render gap indicator for the first event", () => {
    const dataWithGapOnFirst = {
      session_id: "s3",
      summary: {},
      events: [
        { timestamp: "2024-06-15T10:00:00Z", event_type: "command.exec", command: "ls", delta_ms: 10000 },
      ],
    };
    render(<TerminalReplay data={dataWithGapOnFirst} onClose={() => {}} />);
    expect(screen.queryByText(/pause/)).not.toBeInTheDocument();
  });
});
