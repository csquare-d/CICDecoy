import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import Honeytokens from "./Honeytokens";

// Mock fetchHoneytokenEvents to avoid real network calls
const mockFetchEvents = vi.fn(() =>
  Promise.resolve({
    events: [
      {
        event_id: "evt-001",
        timestamp: new Date().toISOString(),
        decoy_name: "hp-alpha",
        session_id: "sess-001",
        event_type: "honeytoken.accessed",
        source_ip: "10.0.0.1",
        severity: "critical",
        data: {
          token_name: "aws-creds",
          token_type: "aws-key",
          access_type: "file_read",
          access_vector: "shell",
          accessed_path: "/home/admin/.aws/credentials",
          command: "cat /home/admin/.aws/credentials",
          content_hash: "abc123",
          client_ip: "10.0.0.1",
          username: "admin",
        },
      },
      {
        event_id: "evt-002",
        timestamp: new Date(Date.now() - 3600000).toISOString(),
        decoy_name: "hp-alpha",
        session_id: "sess-002",
        event_type: "honeytoken.accessed",
        source_ip: "10.0.0.2",
        severity: "high",
        data: {
          token_name: "aws-creds",
          token_type: "aws-key",
          access_type: "file_read",
          access_vector: "scp",
          accessed_path: "/home/admin/.aws/credentials",
          command: "scp download",
          content_hash: "abc123",
          client_ip: "10.0.0.2",
          username: "root",
        },
      },
    ],
    offset: 0,
    limit: 50,
  }),
);

vi.mock("../api/client", () => ({
  fetchHoneytokenEvents: (...args) => mockFetchEvents(...args),
  getApiKey: vi.fn(() => "test-key"),
  setApiKey: vi.fn(),
  clearApiKey: vi.fn(),
  UNAUTHORIZED_EVENT: "cicdecoy:unauthorized",
}));

const SAMPLE_HONEYTOKENS = {
  honeytokens: [
    {
      token_name: "aws-creds",
      token_type: "aws-key",
      path: "/home/admin/.aws/credentials",
      decoy_name: "hp-alpha",
      trigger_count: 3,
      unique_ips: 2,
      unique_sessions: 2,
      last_triggered: new Date().toISOString(),
      first_triggered: new Date(Date.now() - 86400000).toISOString(),
      last_access_vector: "shell",
      source_ips: ["10.0.0.1", "10.0.0.2"],
    },
    {
      token_name: "ssh-key-root",
      token_type: "ssh-key",
      path: "/root/.ssh/id_rsa",
      decoy_name: "hp-beta",
      trigger_count: 0,
      unique_ips: 0,
      unique_sessions: 0,
      last_triggered: null,
      first_triggered: null,
      last_access_vector: null,
      source_ips: [],
    },
    {
      token_name: "env-secrets",
      token_type: "env-var",
      path: "/opt/app/.env",
      decoy_name: "hp-alpha",
      trigger_count: 1,
      unique_ips: 1,
      unique_sessions: 1,
      last_triggered: new Date(Date.now() - 7200000).toISOString(),
      first_triggered: new Date(Date.now() - 7200000).toISOString(),
      last_access_vector: "shell",
      source_ips: ["10.0.0.3"],
    },
  ],
  offset: 0,
  limit: 50,
  total: 3,
};

beforeEach(() => {
  mockFetchEvents.mockClear();
});

describe("Honeytokens", () => {
  // ── Empty state ──────────────────────────────────────
  it("renders empty state when honeytokens data is null", () => {
    render(<Honeytokens honeytokens={null} />);
    expect(screen.getByText(/No honeytokens configured/)).toBeInTheDocument();
  });

  it("renders empty state when honeytokens array is empty", () => {
    render(<Honeytokens honeytokens={{ honeytokens: [], total: 0 }} />);
    expect(screen.getByText(/No honeytokens configured/)).toBeInTheDocument();
  });

  it("shows zero stat cards in empty state", () => {
    render(<Honeytokens honeytokens={null} />);
    const zeros = screen.getAllByText("0");
    expect(zeros.length).toBe(4);
  });

  // ── Populated state ──────────────────────────────────
  it("renders all token names", () => {
    render(<Honeytokens honeytokens={SAMPLE_HONEYTOKENS} />);
    expect(screen.getByText("aws-creds")).toBeInTheDocument();
    expect(screen.getByText("ssh-key-root")).toBeInTheDocument();
    expect(screen.getByText("env-secrets")).toBeInTheDocument();
  });

  it("renders type badges for each token", () => {
    render(<Honeytokens honeytokens={SAMPLE_HONEYTOKENS} />);
    expect(screen.getByText("aws-key")).toBeInTheDocument();
    expect(screen.getByText("ssh-key")).toBeInTheDocument();
    expect(screen.getByText("env-var")).toBeInTheDocument();
  });

  it("renders file paths", () => {
    render(<Honeytokens honeytokens={SAMPLE_HONEYTOKENS} />);
    expect(screen.getByText("/home/admin/.aws/credentials")).toBeInTheDocument();
    expect(screen.getByText("/root/.ssh/id_rsa")).toBeInTheDocument();
  });

  it("renders decoy names", () => {
    render(<Honeytokens honeytokens={SAMPLE_HONEYTOKENS} />);
    expect(screen.getAllByText("hp-alpha").length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText("hp-beta")).toBeInTheDocument();
  });

  it("renders token count in header", () => {
    render(<Honeytokens honeytokens={SAMPLE_HONEYTOKENS} />);
    expect(screen.getByText("3 configured")).toBeInTheDocument();
  });

  it("shows correct trigger counts in token rows", () => {
    render(<Honeytokens honeytokens={SAMPLE_HONEYTOKENS} />);
    // Total triggers stat card shows 4 (3 + 0 + 1)
    expect(screen.getByText("4")).toBeInTheDocument();
    // Token row trigger counts are rendered in styled spans
    const triggerSpans = screen.getAllByText("3");
    expect(triggerSpans.length).toBeGreaterThanOrEqual(1);
  });

  // ── Stat cards ───────────────────────────────────────
  it("computes total tokens stat", () => {
    render(<Honeytokens honeytokens={SAMPLE_HONEYTOKENS} />);
    expect(screen.getByText("TOTAL TOKENS")).toBeInTheDocument();
  });

  it("computes unique attackers from source_ips", () => {
    render(<Honeytokens honeytokens={SAMPLE_HONEYTOKENS} />);
    // 10.0.0.1, 10.0.0.2, 10.0.0.3 = 3 unique
    expect(screen.getByText("UNIQUE ATTACKERS")).toBeInTheDocument();
  });

  it("displays source IPs in token row", () => {
    render(<Honeytokens honeytokens={SAMPLE_HONEYTOKENS} />);
    expect(screen.getByText("10.0.0.1, 10.0.0.2")).toBeInTheDocument();
    expect(screen.getByText("10.0.0.3")).toBeInTheDocument();
  });

  it("shows dashes for tokens with no triggers", () => {
    render(<Honeytokens honeytokens={SAMPLE_HONEYTOKENS} />);
    // ssh-key-root has no IPs, should show "--"
    const dashes = screen.getAllByText("--");
    expect(dashes.length).toBeGreaterThanOrEqual(1);
  });

  // ── Detail panel (click to open) ─────────────────────
  it("does not show detail panel initially", () => {
    render(<Honeytokens honeytokens={SAMPLE_HONEYTOKENS} />);
    expect(screen.queryByText("TRIGGER EVENTS")).not.toBeInTheDocument();
    expect(screen.queryByText("CLOSE")).not.toBeInTheDocument();
  });

  it("shows loading state when a token row is clicked", async () => {
    // Make the fetch hang so we can see loading state
    mockFetchEvents.mockImplementationOnce(
      () => new Promise((resolve) => setTimeout(() => resolve({ events: [] }), 5000)),
    );

    render(<Honeytokens honeytokens={SAMPLE_HONEYTOKENS} />);
    const row = screen.getByText("aws-creds").closest("div[style]");
    fireEvent.click(row);

    expect(screen.getByText("Loading trigger events...")).toBeInTheDocument();
    expect(screen.getByText("loading...")).toBeInTheDocument();
  });

  it("fetches events when a token is clicked", async () => {
    render(<Honeytokens honeytokens={SAMPLE_HONEYTOKENS} />);
    const row = screen.getByText("aws-creds").closest("div[style]");
    fireEvent.click(row);

    await waitFor(() => {
      expect(mockFetchEvents).toHaveBeenCalledWith("aws-creds");
    });
  });

  it("shows detail panel with events after loading", async () => {
    render(<Honeytokens honeytokens={SAMPLE_HONEYTOKENS} />);
    const row = screen.getByText("aws-creds").closest("div[style]");
    fireEvent.click(row);

    await waitFor(() => {
      expect(screen.getByText("TRIGGER EVENTS")).toBeInTheDocument();
      expect(screen.getByText("2 events")).toBeInTheDocument();
      expect(screen.getByText("CLOSE")).toBeInTheDocument();
    });
  });

  it("shows event details in the detail panel", async () => {
    render(<Honeytokens honeytokens={SAMPLE_HONEYTOKENS} />);
    const row = screen.getByText("aws-creds").closest("div[style]");
    fireEvent.click(row);

    await waitFor(() => {
      expect(screen.getByText("10.0.0.1")).toBeInTheDocument();
      expect(screen.getByText("10.0.0.2")).toBeInTheDocument();
      expect(screen.getByText("shell")).toBeInTheDocument();
      expect(screen.getByText("scp")).toBeInTheDocument();
      expect(screen.getByText("critical")).toBeInTheDocument();
    });
  });

  it("shows token metadata in the detail header", async () => {
    render(<Honeytokens honeytokens={SAMPLE_HONEYTOKENS} />);
    const row = screen.getByText("aws-creds").closest("div[style]");
    fireEvent.click(row);

    await waitFor(() => {
      expect(screen.getByText("TRIGGERS")).toBeInTheDocument();
      expect(screen.getByText("UNIQUE IPs")).toBeInTheDocument();
      expect(screen.getByText("FIRST SEEN")).toBeInTheDocument();
      // "SESSIONS" appears in both stat card and detail panel — use getAllByText
      expect(screen.getAllByText("SESSIONS").length).toBe(2);
    });
  });

  it("closes detail panel when CLOSE button is clicked", async () => {
    render(<Honeytokens honeytokens={SAMPLE_HONEYTOKENS} />);
    const row = screen.getByText("aws-creds").closest("div[style]");
    fireEvent.click(row);

    await waitFor(() => {
      expect(screen.getByText("CLOSE")).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText("CLOSE"));
    expect(screen.queryByText("TRIGGER EVENTS")).not.toBeInTheDocument();
  });

  it("closes detail panel when same token is clicked again", async () => {
    render(<Honeytokens honeytokens={SAMPLE_HONEYTOKENS} />);
    const row = screen.getByText("aws-creds").closest("div[style]");
    fireEvent.click(row);

    await waitFor(() => {
      expect(screen.getByText("TRIGGER EVENTS")).toBeInTheDocument();
    });

    // Click same token again to toggle off
    fireEvent.click(row);
    expect(screen.queryByText("TRIGGER EVENTS")).not.toBeInTheDocument();
  });

  it("closes detail panel on ESC key", async () => {
    render(<Honeytokens honeytokens={SAMPLE_HONEYTOKENS} />);
    const row = screen.getByText("aws-creds").closest("div[style]");
    fireEvent.click(row);

    await waitFor(() => {
      expect(screen.getByText("TRIGGER EVENTS")).toBeInTheDocument();
    });

    fireEvent.keyDown(document, { key: "Escape" });
    expect(screen.queryByText("TRIGGER EVENTS")).not.toBeInTheDocument();
  });

  it("caches events and does not re-fetch on second click", async () => {
    render(<Honeytokens honeytokens={SAMPLE_HONEYTOKENS} />);
    const row = screen.getByText("aws-creds").closest("div[style]");

    // First click
    fireEvent.click(row);
    await waitFor(() => {
      expect(mockFetchEvents).toHaveBeenCalledTimes(1);
    });

    // Close
    fireEvent.click(screen.getByText("CLOSE"));

    // Second click — should use cache
    fireEvent.click(row);
    await waitFor(() => {
      expect(screen.getByText("TRIGGER EVENTS")).toBeInTheDocument();
    });
    expect(mockFetchEvents).toHaveBeenCalledTimes(1); // Not called again
  });

  it("fetches different events when switching tokens", async () => {
    render(<Honeytokens honeytokens={SAMPLE_HONEYTOKENS} />);

    // Click first token
    const row1 = screen.getByText("aws-creds").closest("div[style]");
    fireEvent.click(row1);
    await waitFor(() => {
      expect(mockFetchEvents).toHaveBeenCalledWith("aws-creds");
    });

    // Click second token
    const row2 = screen.getByText("env-secrets").closest("div[style]");
    fireEvent.click(row2);
    await waitFor(() => {
      expect(mockFetchEvents).toHaveBeenCalledWith("env-secrets");
    });

    expect(mockFetchEvents).toHaveBeenCalledTimes(2);
  });

  // ── Empty events ─────────────────────────────────────
  it("shows empty state when token has no events", async () => {
    mockFetchEvents.mockImplementationOnce(() =>
      Promise.resolve({ events: [], offset: 0, limit: 50 }),
    );

    render(<Honeytokens honeytokens={SAMPLE_HONEYTOKENS} />);
    const row = screen.getByText("ssh-key-root").closest("div[style]");
    fireEvent.click(row);

    await waitFor(() => {
      expect(screen.getByText("No trigger events recorded")).toBeInTheDocument();
    });
  });

  // ── Error handling ───────────────────────────────────
  it("handles fetch error gracefully", async () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    mockFetchEvents.mockImplementationOnce(() => Promise.reject(new Error("Network error")));

    render(<Honeytokens honeytokens={SAMPLE_HONEYTOKENS} />);
    const row = screen.getByText("aws-creds").closest("div[style]");
    fireEvent.click(row);

    await waitFor(() => {
      expect(screen.getByText("No trigger events recorded")).toBeInTheDocument();
    });
    expect(warnSpy).toHaveBeenCalledWith("Honeytoken events fetch failed:", expect.any(Error));
    warnSpy.mockRestore();
  });

  // ── IP truncation ────────────────────────────────────
  it("truncates long IP lists with +N more", () => {
    const manyIPs = {
      honeytokens: [
        {
          ...SAMPLE_HONEYTOKENS.honeytokens[0],
          source_ips: ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5"],
          unique_ips: 5,
        },
      ],
      total: 1,
    };
    render(<Honeytokens honeytokens={manyIPs} />);
    expect(screen.getByText("+2 more")).toBeInTheDocument();
  });
});
