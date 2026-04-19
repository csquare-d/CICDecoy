import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import Header from "./Header";

// Mock the API client to avoid real network calls
vi.mock("../api/client", () => ({
  injectTestEvent: vi.fn(() => Promise.resolve({})),
  injectTestSession: vi.fn(() => Promise.resolve({})),
  getApiKey: vi.fn(() => "test-key"),
  setApiKey: vi.fn(),
  clearApiKey: vi.fn(),
  UNAUTHORIZED_EVENT: "cicdecoy:unauthorized",
}));

function renderHeader(props = {}) {
  return render(
    <MemoryRouter initialEntries={["/"]}>
      <Header {...props} />
    </MemoryRouter>
  );
}

describe("Header", () => {
  it("renders the CI/CDecoy brand text", () => {
    renderHeader();
    expect(screen.getByText("CI")).toBeInTheDocument();
    expect(screen.getByText("CDecoy")).toBeInTheDocument();
  });

  it("renders the version badge", () => {
    renderHeader();
    expect(screen.getByText("v0.1.0-alpha")).toBeInTheDocument();
  });

  it("renders all navigation links", () => {
    renderHeader();
    expect(screen.getByText("OVERVIEW")).toBeInTheDocument();
    expect(screen.getByText("SESSIONS")).toBeInTheDocument();
    expect(screen.getByText("INTELLIGENCE")).toBeInTheDocument();
    expect(screen.getByText("DECOY FLEET")).toBeInTheDocument();
  });

  it("renders nav links as anchors pointing to correct routes", () => {
    renderHeader();
    const overview = screen.getByText("OVERVIEW").closest("a");
    const sessions = screen.getByText("SESSIONS").closest("a");
    const intel = screen.getByText("INTELLIGENCE").closest("a");
    const fleet = screen.getByText("DECOY FLEET").closest("a");

    expect(overview).toHaveAttribute("href", "/");
    expect(sessions).toHaveAttribute("href", "/sessions");
    expect(intel).toHaveAttribute("href", "/intelligence");
    expect(fleet).toHaveAttribute("href", "/fleet");
  });

  it("renders NATS and DB status labels", () => {
    renderHeader();
    expect(screen.getByText("NATS")).toBeInTheDocument();
    expect(screen.getByText("DB")).toBeInTheDocument();
  });

  it("renders Inject, x10, and Session action buttons", () => {
    renderHeader();
    expect(screen.getByText("Inject")).toBeInTheDocument();
    expect(screen.getByText("x10")).toBeInTheDocument();
    expect(screen.getByText("Session")).toBeInTheDocument();
  });

  it("calls injectTestEvent when Inject button is clicked", async () => {
    const { injectTestEvent } = await import("../api/client");
    renderHeader();
    fireEvent.click(screen.getByText("Inject"));
    expect(injectTestEvent).toHaveBeenCalled();
  });

  it("calls injectTestSession when Session button is clicked", async () => {
    const { injectTestSession } = await import("../api/client");
    renderHeader();
    fireEvent.click(screen.getByText("Session"));
    expect(injectTestSession).toHaveBeenCalled();
  });

  it("defaults to disconnected status when stats is undefined", () => {
    const { container } = renderHeader();
    // Both NATS and DB dots should use the "off" color (no glow)
    const dots = container.querySelectorAll("span span");
    // Find status dots by their small round size (6px)
    const statusDots = Array.from(dots).filter(
      (el) => el.style.width === "6px" && el.style.borderRadius === "50%"
    );
    expect(statusDots.length).toBe(2);
    statusDots.forEach((dot) => {
      expect(dot.style.boxShadow).toBe("none");
    });
  });

  it("shows connected status dots when both services are up", () => {
    const { container } = renderHeader({
      stats: { db_connected: true, nats_connected: true },
    });
    const statusDots = Array.from(container.querySelectorAll("span span")).filter(
      (el) => el.style.width === "6px" && el.style.borderRadius === "50%"
    );
    expect(statusDots.length).toBe(2);
    statusDots.forEach((dot) => {
      expect(dot.style.boxShadow).not.toBe("none");
    });
  });

  it("handles mixed connection states", () => {
    const { container } = renderHeader({
      stats: { db_connected: false, nats_connected: true },
    });
    const statusDots = Array.from(container.querySelectorAll("span span")).filter(
      (el) => el.style.width === "6px" && el.style.borderRadius === "50%"
    );
    // NATS dot (first) should glow, DB dot (second) should not
    expect(statusDots[0].style.boxShadow).not.toBe("none"); // NATS
    expect(statusDots[1].style.boxShadow).toBe("none"); // DB
  });

  it("highlights the active nav link based on current route", () => {
    render(
      <MemoryRouter initialEntries={["/sessions"]}>
        <Header stats={{}} />
      </MemoryRouter>
    );
    const sessionsLink = screen.getByText("SESSIONS").closest("a");
    const overviewLink = screen.getByText("OVERVIEW").closest("a");
    // Active link should have a visible border, inactive should be transparent
    expect(sessionsLink.style.borderColor || sessionsLink.style.border).not.toBe("");
    expect(overviewLink).toBeInTheDocument();
  });
});
