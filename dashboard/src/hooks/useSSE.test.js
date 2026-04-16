import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { renderHook, act } from "@testing-library/react";
import useSSE from "./useSSE";

// Mock EventSource
class MockEventSource {
  constructor(url) {
    this.url = url;
    this.listeners = {};
    this.readyState = 0;
    MockEventSource.instances.push(this);
  }

  addEventListener(type, handler) {
    if (!this.listeners[type]) this.listeners[type] = [];
    this.listeners[type].push(handler);
  }

  close() {
    this.readyState = 2;
  }

  // Test helpers
  emit(type, data) {
    (this.listeners[type] || []).forEach((fn) => fn(data));
  }
}
MockEventSource.instances = [];

describe("useSSE", () => {
  let originalEventSource;

  beforeEach(() => {
    MockEventSource.instances = [];
    originalEventSource = globalThis.EventSource;
    globalThis.EventSource = MockEventSource;
    vi.useFakeTimers();
  });

  afterEach(() => {
    globalThis.EventSource = originalEventSource;
    vi.useRealTimers();
  });

  it("connects to the SSE endpoint on mount", () => {
    renderHook(() => useSSE());
    expect(MockEventSource.instances.length).toBe(1);
    expect(MockEventSource.instances[0].url).toBe("/api/events/stream");
  });

  it("starts with empty events and disconnected", () => {
    const { result } = renderHook(() => useSSE());
    expect(result.current.events).toEqual([]);
    expect(result.current.connected).toBe(false);
    expect(result.current.eventCount).toBe(0);
  });

  it("sets connected to true on open event", () => {
    const { result } = renderHook(() => useSSE());
    const sse = MockEventSource.instances[0];

    act(() => {
      sse.emit("open", {});
    });

    expect(result.current.connected).toBe(true);
  });

  it("adds events from decoy_event messages", () => {
    const { result } = renderHook(() => useSSE());
    const sse = MockEventSource.instances[0];

    act(() => {
      sse.emit("decoy_event", { data: JSON.stringify({ id: 1, severity: "high" }) });
    });

    expect(result.current.events).toHaveLength(1);
    expect(result.current.events[0]).toEqual({ id: 1, severity: "high" });
    expect(result.current.eventCount).toBe(1);
  });

  it("prepends new events (newest first)", () => {
    const { result } = renderHook(() => useSSE());
    const sse = MockEventSource.instances[0];

    act(() => {
      sse.emit("decoy_event", { data: JSON.stringify({ id: 1 }) });
    });
    act(() => {
      sse.emit("decoy_event", { data: JSON.stringify({ id: 2 }) });
    });

    expect(result.current.events[0]).toEqual({ id: 2 });
    expect(result.current.events[1]).toEqual({ id: 1 });
    expect(result.current.eventCount).toBe(2);
  });

  it("limits buffer to maxBuffer size", () => {
    const { result } = renderHook(() => useSSE(3));
    const sse = MockEventSource.instances[0];

    act(() => {
      for (let i = 0; i < 5; i++) {
        sse.emit("decoy_event", { data: JSON.stringify({ id: i }) });
      }
    });

    expect(result.current.events).toHaveLength(3);
    // Most recent should be first
    expect(result.current.events[0]).toEqual({ id: 4 });
    expect(result.current.eventCount).toBe(5);
  });

  it("sets connected to false on error and reconnects", () => {
    const { result } = renderHook(() => useSSE());
    const sse = MockEventSource.instances[0];

    act(() => {
      sse.emit("open", {});
    });
    expect(result.current.connected).toBe(true);

    act(() => {
      sse.emit("error", {});
    });
    expect(result.current.connected).toBe(false);

    // Should schedule reconnect
    act(() => {
      vi.advanceTimersByTime(2000);
    });
    // A new EventSource should have been created
    expect(MockEventSource.instances.length).toBe(2);
  });

  it("closes the connection on unmount", () => {
    const { unmount } = renderHook(() => useSSE());
    const sse = MockEventSource.instances[0];
    expect(sse.readyState).not.toBe(2);
    unmount();
    expect(sse.readyState).toBe(2);
  });

  it("handles invalid JSON data gracefully", () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const { result } = renderHook(() => useSSE());
    const sse = MockEventSource.instances[0];

    act(() => {
      sse.emit("decoy_event", { data: "not-json" });
    });

    expect(result.current.events).toHaveLength(0);
    expect(result.current.eventCount).toBe(0);
    warnSpy.mockRestore();
  });

  it("uses exponential backoff on reconnect with max delay", () => {
    renderHook(() => useSSE());
    const sse1 = MockEventSource.instances[0];

    // First error -> 2s delay
    act(() => { sse1.emit("error", {}); });
    expect(MockEventSource.instances.length).toBe(1);
    act(() => { vi.advanceTimersByTime(2000); });
    expect(MockEventSource.instances.length).toBe(2);

    // Second error -> 4s delay
    const sse2 = MockEventSource.instances[1];
    act(() => { sse2.emit("error", {}); });
    act(() => { vi.advanceTimersByTime(3999); });
    expect(MockEventSource.instances.length).toBe(2); // not yet
    act(() => { vi.advanceTimersByTime(1); });
    expect(MockEventSource.instances.length).toBe(3);
  });
});
