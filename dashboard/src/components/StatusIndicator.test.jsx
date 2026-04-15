import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import StatusIndicator from "./StatusIndicator";

describe("StatusIndicator", () => {
  it("renders ONLINE label for active status", () => {
    render(<StatusIndicator status="active" />);
    expect(screen.getByText("ONLINE")).toBeInTheDocument();
  });

  it("renders ROTATING label for rotating status", () => {
    render(<StatusIndicator status="rotating" />);
    expect(screen.getByText("ROTATING")).toBeInTheDocument();
  });

  it("renders DEGRADED label for degraded status", () => {
    render(<StatusIndicator status="degraded" />);
    expect(screen.getByText("DEGRADED")).toBeInTheDocument();
  });

  it("renders OFFLINE label for offline status", () => {
    render(<StatusIndicator status="offline" />);
    expect(screen.getByText("OFFLINE")).toBeInTheDocument();
  });

  it("defaults to ONLINE when given an unknown status", () => {
    render(<StatusIndicator status="banana" />);
    expect(screen.getByText("ONLINE")).toBeInTheDocument();
  });

  it("renders a status dot element", () => {
    const { container } = render(<StatusIndicator status="active" />);
    // The outer span contains an inner dot span + text
    const spans = container.querySelectorAll("span span");
    expect(spans.length).toBeGreaterThanOrEqual(1);
    // The dot should be circular
    expect(spans[0].style.borderRadius).toBe("50%");
  });

  it("applies pulse animation only for active status", () => {
    const { container: activeContainer } = render(<StatusIndicator status="active" />);
    const activeDot = activeContainer.querySelector("span span");
    expect(activeDot.style.animation).toContain("pulse");

    const { container: offlineContainer } = render(<StatusIndicator status="offline" />);
    const offlineDot = offlineContainer.querySelector("span span");
    expect(offlineDot.style.animation).toBe("none");
  });
});
