import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import TierBadge from "./TierBadge";

describe("TierBadge", () => {
  it("renders tier 1 as T1 BEACON", () => {
    render(<TierBadge tier={1} />);
    expect(screen.getByText("T1 BEACON")).toBeInTheDocument();
  });

  it("renders tier 2 as T2 SCRIPTED", () => {
    render(<TierBadge tier={2} />);
    expect(screen.getByText("T2 SCRIPTED")).toBeInTheDocument();
  });

  it("renders tier 3 as T3 ADAPTIVE", () => {
    render(<TierBadge tier={3} />);
    expect(screen.getByText("T3 ADAPTIVE")).toBeInTheDocument();
  });

  it("renders UNKNOWN for unrecognized tier numbers", () => {
    render(<TierBadge tier={9} />);
    expect(screen.getByText("T9 UNKNOWN")).toBeInTheDocument();
  });

  it("applies distinct colors per tier", () => {
    const { rerender } = render(<TierBadge tier={1} />);
    const t1Color = screen.getByText("T1 BEACON").style.color;

    rerender(<TierBadge tier={2} />);
    const t2Color = screen.getByText("T2 SCRIPTED").style.color;

    rerender(<TierBadge tier={3} />);
    const t3Color = screen.getByText("T3 ADAPTIVE").style.color;

    // Each tier should have a unique color
    expect(new Set([t1Color, t2Color, t3Color]).size).toBe(3);
  });

  it("uses monospace font family", () => {
    render(<TierBadge tier={1} />);
    const badge = screen.getByText("T1 BEACON");
    expect(badge.style.fontFamily).toBe("var(--mono)");
  });
});
