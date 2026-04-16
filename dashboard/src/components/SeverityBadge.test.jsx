import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import SeverityBadge, { SeverityDot } from "./SeverityBadge";

describe("SeverityBadge", () => {
  it("renders the severity text in uppercase", () => {
    render(<SeverityBadge severity="critical" />);
    expect(screen.getByText("critical")).toBeInTheDocument();
    // The component sets textTransform: uppercase via CSS
    const badge = screen.getByText("critical");
    expect(badge.style.textTransform).toBe("uppercase");
  });

  it.each(["critical", "high", "medium", "low", "info"])(
    "renders without error for severity=%s",
    (severity) => {
      const { container } = render(<SeverityBadge severity={severity} />);
      expect(container.querySelector("span")).toBeInTheDocument();
      expect(screen.getByText(severity)).toBeInTheDocument();
    }
  );

  it("falls back to info when severity is null", () => {
    render(<SeverityBadge severity={null} />);
    expect(screen.getByText("info")).toBeInTheDocument();
  });

  it("falls back to info when severity is undefined", () => {
    render(<SeverityBadge />);
    expect(screen.getByText("info")).toBeInTheDocument();
  });

  it("applies custom style overrides", () => {
    render(<SeverityBadge severity="high" style={{ marginLeft: 8 }} />);
    const badge = screen.getByText("high");
    expect(badge.style.marginLeft).toBe("8px");
  });
});

describe("SeverityDot", () => {
  it("renders as a span element", () => {
    const { container } = render(<SeverityDot severity="critical" />);
    const dot = container.querySelector("span");
    expect(dot).toBeInTheDocument();
  });

  it("uses the default size of 8px", () => {
    const { container } = render(<SeverityDot severity="high" />);
    const dot = container.querySelector("span");
    expect(dot.style.width).toBe("8px");
    expect(dot.style.height).toBe("8px");
  });

  it("respects a custom size prop", () => {
    const { container } = render(<SeverityDot severity="low" size={12} />);
    const dot = container.querySelector("span");
    expect(dot.style.width).toBe("12px");
    expect(dot.style.height).toBe("12px");
  });

  it("renders as a circle (border-radius 50%)", () => {
    const { container } = render(<SeverityDot severity="medium" />);
    const dot = container.querySelector("span");
    expect(dot.style.borderRadius).toBe("50%");
  });
});
