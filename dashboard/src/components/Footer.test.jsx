import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import Footer from "./Footer";

describe("Footer", () => {
  it("renders the platform name", () => {
    render(<Footer stats={{}} />);
    expect(screen.getByText(/CI\/CDecoy/)).toBeInTheDocument();
  });

  it("shows connected status when both services are up", () => {
    render(<Footer stats={{ db_connected: true, nats_connected: true }} />);
    expect(screen.getByText(/streaming/)).toBeInTheDocument();
    expect(screen.getByText(/connected/)).toBeInTheDocument();
    // Ensure we don't show the down states
    expect(screen.queryByText(/disconnected/)).not.toBeInTheDocument();
    expect(screen.queryByText(/offline/)).not.toBeInTheDocument();
  });

  it("shows disconnected status when both services are down", () => {
    render(<Footer stats={{ db_connected: false, nats_connected: false }} />);
    expect(screen.getByText(/disconnected/)).toBeInTheDocument();
    expect(screen.getByText(/offline/)).toBeInTheDocument();
  });

  it("handles mixed service states", () => {
    render(<Footer stats={{ db_connected: true, nats_connected: false }} />);
    expect(screen.getByText(/disconnected/)).toBeInTheDocument();
    expect(screen.getByText(/connected/)).toBeInTheDocument();
  });

  it("defaults to disconnected when stats is undefined", () => {
    render(<Footer />);
    expect(screen.getByText(/disconnected/)).toBeInTheDocument();
    expect(screen.getByText(/offline/)).toBeInTheDocument();
  });

  it("defaults to disconnected when stats is null", () => {
    render(<Footer stats={null} />);
    expect(screen.getByText(/disconnected/)).toBeInTheDocument();
    expect(screen.getByText(/offline/)).toBeInTheDocument();
  });
});
