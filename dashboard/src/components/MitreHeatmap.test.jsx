import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import MitreHeatmap from "./MitreHeatmap";

const SAMPLE_TECHNIQUES = [
  { technique_id: "T1059", technique_name: "Command and Scripting Interpreter", tactic: "execution", total: 15, actors: 3 },
  { technique_id: "T1078", technique_name: "Valid Accounts", tactic: "persistence", total: 8, actors: 2 },
  { technique_id: "T1021", technique_name: "Remote Services", tactic: "lateral-movement", total: 4, actors: 1 },
];

describe("MitreHeatmap", () => {
  it("renders empty state when no techniques are provided", () => {
    render(<MitreHeatmap techniques={[]} />);
    expect(screen.getByText(/No MITRE technique data yet/)).toBeInTheDocument();
  });

  it("renders empty state when techniques prop is omitted", () => {
    render(<MitreHeatmap />);
    expect(screen.getByText(/No MITRE technique data yet/)).toBeInTheDocument();
  });

  it("renders all technique IDs", () => {
    render(<MitreHeatmap techniques={SAMPLE_TECHNIQUES} />);
    expect(screen.getByText("T1059")).toBeInTheDocument();
    expect(screen.getByText("T1078")).toBeInTheDocument();
    expect(screen.getByText("T1021")).toBeInTheDocument();
  });

  it("renders technique names", () => {
    render(<MitreHeatmap techniques={SAMPLE_TECHNIQUES} />);
    expect(screen.getByText("Command and Scripting Interpreter")).toBeInTheDocument();
    expect(screen.getByText("Valid Accounts")).toBeInTheDocument();
    expect(screen.getByText("Remote Services")).toBeInTheDocument();
  });

  it("renders totals for each technique", () => {
    render(<MitreHeatmap techniques={SAMPLE_TECHNIQUES} />);
    expect(screen.getByText("15")).toBeInTheDocument();
    expect(screen.getByText("8")).toBeInTheDocument();
    expect(screen.getByText("4")).toBeInTheDocument();
  });

  it("renders actor counts with ip suffix", () => {
    render(<MitreHeatmap techniques={SAMPLE_TECHNIQUES} />);
    expect(screen.getByText("3ip")).toBeInTheDocument();
    expect(screen.getByText("2ip")).toBeInTheDocument();
    expect(screen.getByText("1ip")).toBeInTheDocument();
  });

  it("scales bars relative to the maximum total", () => {
    const { container } = render(<MitreHeatmap techniques={SAMPLE_TECHNIQUES} />);
    // The highest total (15) should produce a 100% bar
    // Find bar elements -- they use inline style with width as percentage
    const bars = container.querySelectorAll("[style*='width']");
    const barWidths = Array.from(bars)
      .map((el) => el.style.width)
      .filter((w) => w.endsWith("%"));

    expect(barWidths).toContain("100%");
  });

  it("renders correct number of rows", () => {
    const { container } = render(<MitreHeatmap techniques={SAMPLE_TECHNIQUES} />);
    // Each technique gets one row div (direct children of the wrapper)
    const rows = container.firstChild.children;
    expect(rows).toHaveLength(3);
  });
});
