import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import SessionList from "./SessionList";

const SAMPLE_SESSIONS = [
  {
    session_id: "sess-001",
    source_ip: "192.168.1.100",
    auth_username: "root",
    decoy_name: "honeypot-alpha",
    command_count: 12,
    max_severity: "critical",
    mitre_techniques: [{ technique_id: "T1059" }, { technique_id: "T1078" }],
    attack_phases: ["execution", "persistence"],
    kill_chain_detected: true,
  },
  {
    session_id: "sess-002",
    source_ip: "10.0.0.55",
    auth_username: "admin",
    decoy_name: "honeypot-beta",
    command_count: 3,
    max_severity: "low",
    mitre_techniques: [],
    attack_phases: [],
    kill_chain_detected: false,
  },
];

describe("SessionList", () => {
  // ── Empty state ──
  it("renders empty state message when sessions is empty", () => {
    render(<SessionList sessions={[]} onSelect={() => {}} />);
    expect(screen.getByText(/No sessions yet/)).toBeInTheDocument();
  });

  it("renders empty state when sessions prop is omitted", () => {
    render(<SessionList onSelect={() => {}} />);
    expect(screen.getByText(/No sessions yet/)).toBeInTheDocument();
  });

  // ── Full table mode ──
  it("renders table headers in full mode", () => {
    render(<SessionList sessions={SAMPLE_SESSIONS} onSelect={() => {}} />);
    expect(screen.getByText("Source IP")).toBeInTheDocument();
    expect(screen.getByText("User")).toBeInTheDocument();
    expect(screen.getByText("Decoy")).toBeInTheDocument();
    expect(screen.getByText("Cmds")).toBeInTheDocument();
    expect(screen.getByText("Severity")).toBeInTheDocument();
  });

  it("renders session data in full table mode", () => {
    render(<SessionList sessions={SAMPLE_SESSIONS} onSelect={() => {}} />);
    expect(screen.getByText("192.168.1.100")).toBeInTheDocument();
    expect(screen.getByText("root")).toBeInTheDocument();
    expect(screen.getByText("honeypot-alpha")).toBeInTheDocument();
    expect(screen.getByText("12")).toBeInTheDocument();
    expect(screen.getByText("10.0.0.55")).toBeInTheDocument();
    expect(screen.getByText("admin")).toBeInTheDocument();
  });

  it("renders MITRE technique chips in full mode", () => {
    render(<SessionList sessions={SAMPLE_SESSIONS} onSelect={() => {}} />);
    expect(screen.getByText("T1059")).toBeInTheDocument();
    expect(screen.getByText("T1078")).toBeInTheDocument();
  });

  it("renders attack phase chips in full mode", () => {
    render(<SessionList sessions={SAMPLE_SESSIONS} onSelect={() => {}} />);
    expect(screen.getByText("execution")).toBeInTheDocument();
    expect(screen.getByText("persistence")).toBeInTheDocument();
  });

  it("renders KILL CHAIN flag for detected sessions", () => {
    render(<SessionList sessions={SAMPLE_SESSIONS} onSelect={() => {}} />);
    expect(screen.getByText("KILL CHAIN")).toBeInTheDocument();
  });

  it("calls onSelect with session_id when a row is clicked", () => {
    const onSelect = vi.fn();
    render(<SessionList sessions={SAMPLE_SESSIONS} onSelect={onSelect} />);
    const row = screen.getByText("192.168.1.100").closest("tr");
    fireEvent.click(row);
    expect(onSelect).toHaveBeenCalledWith("sess-001");
  });

  it("renders -- for missing source_ip", () => {
    const sessions = [{ ...SAMPLE_SESSIONS[0], source_ip: null }];
    render(<SessionList sessions={sessions} onSelect={() => {}} />);
    // Should show "--" for missing IP (at least one instance in compact or table)
    expect(screen.getAllByText("--").length).toBeGreaterThanOrEqual(1);
  });

  // ── Compact mode ──
  it("renders compact sidebar items in compact mode", () => {
    render(
      <SessionList
        sessions={SAMPLE_SESSIONS}
        compact={true}
        activeId="sess-001"
        onSelect={() => {}}
      />
    );
    expect(screen.getByText("192.168.1.100")).toBeInTheDocument();
    expect(screen.getByText("root")).toBeInTheDocument();
    expect(screen.getByText("12 cmds")).toBeInTheDocument();
    // Should NOT render table headers in compact mode
    expect(screen.queryByText("Source IP")).not.toBeInTheDocument();
  });

  it("shows KC flag in compact mode for kill chain sessions", () => {
    render(
      <SessionList
        sessions={SAMPLE_SESSIONS}
        compact={true}
        activeId={null}
        onSelect={() => {}}
      />
    );
    expect(screen.getByText("KC")).toBeInTheDocument();
  });

  it("calls onSelect when compact item is clicked", () => {
    const onSelect = vi.fn();
    render(
      <SessionList
        sessions={SAMPLE_SESSIONS}
        compact={true}
        activeId={null}
        onSelect={onSelect}
      />
    );
    fireEvent.click(screen.getByText("192.168.1.100"));
    expect(onSelect).toHaveBeenCalledWith("sess-001");
  });

  it("highlights the active session in compact mode", () => {
    const { container } = render(
      <SessionList
        sessions={SAMPLE_SESSIONS}
        compact={true}
        activeId="sess-001"
        onSelect={() => {}}
      />
    );
    const items = container.querySelectorAll("div > div");
    const activeItem = Array.from(items).find(
      (el) => el.style.borderLeft && el.style.borderLeft.includes("var(--green)")
    );
    expect(activeItem).toBeTruthy();
  });

  it("renders correct command count for each session", () => {
    render(
      <SessionList
        sessions={SAMPLE_SESSIONS}
        compact={true}
        activeId={null}
        onSelect={() => {}}
      />
    );
    expect(screen.getByText("12 cmds")).toBeInTheDocument();
    expect(screen.getByText("3 cmds")).toBeInTheDocument();
  });
});
