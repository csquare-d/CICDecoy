import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import KillChainTimeline from "./KillChainTimeline";

const SAMPLE_PHASES = [
  { phase: "reconnaissance", techniques: [{ id: "T1595", name: "Active Scanning" }] },
  { phase: "execution", techniques: [{ id: "T1059", name: "Command Interpreter" }] },
  { phase: "exfiltration", techniques: [{ id: "T1041", name: "Exfil Over C2" }] },
];

describe("KillChainTimeline", () => {
  it("returns null when phases is empty", () => {
    const { container } = render(<KillChainTimeline phases={[]} />);
    expect(container.innerHTML).toBe("");
  });

  it("returns null when phases prop is omitted", () => {
    const { container } = render(<KillChainTimeline />);
    expect(container.innerHTML).toBe("");
  });

  it("renders all phase names", () => {
    render(<KillChainTimeline phases={SAMPLE_PHASES} />);
    expect(screen.getByText("reconnaissance")).toBeInTheDocument();
    expect(screen.getByText("execution")).toBeInTheDocument();
    expect(screen.getByText("exfiltration")).toBeInTheDocument();
  });

  it("renders correct number of phase nodes", () => {
    const { container } = render(<KillChainTimeline phases={SAMPLE_PHASES} />);
    // Each phase name is rendered as uppercase text
    const nodes = screen.getAllByText(/reconnaissance|execution|exfiltration/i);
    expect(nodes).toHaveLength(3);
  });

  it("renders arrows between phases (n-1 arrows for n phases)", () => {
    const { container } = render(<KillChainTimeline phases={SAMPLE_PHASES} />);
    // Arrows are divs with borderTop style (connector lines)
    const arrows = container.querySelectorAll("[style*='border-top']");
    // Should have 2 arrows for 3 phases
    expect(arrows.length).toBe(2);
  });

  it("sets title attribute with technique info on phase nodes", () => {
    render(<KillChainTimeline phases={SAMPLE_PHASES} />);
    const reconNode = screen.getByText("reconnaissance");
    expect(reconNode).toHaveAttribute("title", "T1595 Active Scanning");
    const execNode = screen.getByText("execution");
    expect(execNode).toHaveAttribute("title", "T1059 Command Interpreter");
  });

  it("shows 'phase detected' as title when techniques is empty", () => {
    const phases = [{ phase: "discovery", techniques: [] }];
    render(<KillChainTimeline phases={phases} />);
    expect(screen.getByText("discovery")).toHaveAttribute("title", "phase detected");
  });

  it("uses smaller padding in compact mode", () => {
    const phases = [{ phase: "execution", techniques: [] }];
    const { rerender } = render(<KillChainTimeline phases={phases} />);
    const normalNode = screen.getByText("execution");
    const normalPadding = normalNode.style.padding;

    rerender(<KillChainTimeline phases={phases} compact />);
    const compactNode = screen.getByText("execution");
    const compactPadding = compactNode.style.padding;

    // Compact padding should be smaller than normal
    expect(compactPadding).not.toBe(normalPadding);
  });

  it("applies blue color scheme for early phases", () => {
    const phases = [{ phase: "reconnaissance", techniques: [] }];
    render(<KillChainTimeline phases={phases} />);
    const node = screen.getByText("reconnaissance");
    expect(node.style.color).toBe("var(--blue)");
    expect(node.style.background).toBe("var(--blue-dim)");
  });

  it("applies purple color scheme for mid phases", () => {
    const phases = [{ phase: "execution", techniques: [] }];
    render(<KillChainTimeline phases={phases} />);
    const node = screen.getByText("execution");
    expect(node.style.color).toBe("var(--purple)");
    expect(node.style.background).toBe("var(--purple-dim)");
  });

  it("applies red color scheme for late phases", () => {
    const phases = [{ phase: "exfiltration", techniques: [] }];
    render(<KillChainTimeline phases={phases} />);
    const node = screen.getByText("exfiltration");
    expect(node.style.color).toBe("var(--red)");
    expect(node.style.background).toBe("var(--red-dim)");
  });

  it("renders a single phase without any arrows", () => {
    const phases = [{ phase: "discovery", techniques: [] }];
    const { container } = render(<KillChainTimeline phases={phases} />);
    const arrows = container.querySelectorAll("[style*='border-top']");
    expect(arrows.length).toBe(0);
  });
});
