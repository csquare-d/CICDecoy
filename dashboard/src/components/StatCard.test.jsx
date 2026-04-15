import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import StatCard from "./StatCard";

describe("StatCard", () => {
  it("renders the label and value", () => {
    render(<StatCard label="ACTIVE DECOYS" value={42} />);
    expect(screen.getByText("42")).toBeInTheDocument();
    expect(screen.getByText("ACTIVE DECOYS")).toBeInTheDocument();
  });

  it("renders a fallback dash when value is null", () => {
    render(<StatCard label="EVENTS" value={null} />);
    expect(screen.getByText("--")).toBeInTheDocument();
  });

  it("renders a fallback dash when value is undefined", () => {
    render(<StatCard label="EVENTS" />);
    expect(screen.getByText("--")).toBeInTheDocument();
  });

  it("renders zero as a valid value (not fallback)", () => {
    render(<StatCard label="ALERTS" value={0} />);
    expect(screen.getByText("0")).toBeInTheDocument();
    expect(screen.queryByText("--")).not.toBeInTheDocument();
  });

  it("renders the sub text when provided", () => {
    render(<StatCard label="SESSIONS" value={5} sub="last 24h" />);
    expect(screen.getByText("last 24h")).toBeInTheDocument();
  });

  it("does not render a sub element when sub is omitted", () => {
    const { container } = render(<StatCard label="SESSIONS" value={5} />);
    // The card div contains only value + label children (no sub div)
    const card = container.firstChild;
    expect(card.children).toHaveLength(2);
  });

  it("applies the accent color to the value", () => {
    render(<StatCard label="CRITICAL" value={3} accent="var(--red)" />);
    const valueEl = screen.getByText("3");
    expect(valueEl.style.color).toBe("var(--red)");
  });

  it("uses default text color when no accent is provided", () => {
    render(<StatCard label="INFO" value={10} />);
    const valueEl = screen.getByText("10");
    expect(valueEl.style.color).toBe("var(--text)");
  });
});
