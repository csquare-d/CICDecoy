import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { renderHook, act } from "@testing-library/react";
import usePolling from "./usePolling";

describe("usePolling", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("returns loading=true initially", () => {
    const fetchFn = vi.fn(() => new Promise(() => {})); // never resolves
    const { result } = renderHook(() => usePolling(fetchFn, 5000));
    expect(result.current.loading).toBe(true);
    expect(result.current.data).toBeNull();
    expect(result.current.error).toBeNull();
  });

  it("fetches data immediately on mount", async () => {
    const fetchFn = vi.fn(() => Promise.resolve({ count: 42 }));
    const { result } = renderHook(() => usePolling(fetchFn, 5000));

    // Flush the initial fetch (microtask from resolved promise)
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });

    expect(result.current.loading).toBe(false);
    expect(result.current.data).toEqual({ count: 42 });
    expect(result.current.error).toBeNull();
    expect(fetchFn).toHaveBeenCalledTimes(1);
  });

  it("polls at the specified interval", async () => {
    const fetchFn = vi.fn(() => Promise.resolve({ n: 1 }));
    renderHook(() => usePolling(fetchFn, 3000));

    // Initial fetch
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(fetchFn).toHaveBeenCalledTimes(1);

    // Advance past one interval
    await act(async () => {
      await vi.advanceTimersByTimeAsync(3000);
    });
    expect(fetchFn).toHaveBeenCalledTimes(2);

    // Advance past another interval
    await act(async () => {
      await vi.advanceTimersByTimeAsync(3000);
    });
    expect(fetchFn).toHaveBeenCalledTimes(3);
  });

  it("sets error on fetch failure", async () => {
    const err = new Error("Network error");
    const fetchFn = vi.fn(() => Promise.reject(err));
    // Suppress console.warn from the hook
    vi.spyOn(console, "warn").mockImplementation(() => {});

    const { result } = renderHook(() => usePolling(fetchFn, 5000));

    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });

    expect(result.current.loading).toBe(false);
    expect(result.current.error).toBe(err);
    expect(result.current.data).toBeNull();

    console.warn.mockRestore();
  });

  it("does not poll when enabled is false", async () => {
    const fetchFn = vi.fn(() => Promise.resolve({}));
    renderHook(() => usePolling(fetchFn, 5000, false));

    await act(async () => {
      await vi.advanceTimersByTimeAsync(10000);
    });

    expect(fetchFn).not.toHaveBeenCalled();
  });

  it("provides a refresh function that can be called manually", async () => {
    let counter = 0;
    const fetchFn = vi.fn(() => Promise.resolve({ n: ++counter }));
    const { result } = renderHook(() => usePolling(fetchFn, 60000));

    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(result.current.data).toEqual({ n: 1 });

    await act(async () => {
      await result.current.refresh();
    });

    expect(result.current.data).toEqual({ n: 2 });
    expect(fetchFn).toHaveBeenCalledTimes(2);
  });

  it("clears error on successful subsequent fetch", async () => {
    let callCount = 0;
    const fetchFn = vi.fn(() => {
      callCount++;
      if (callCount === 1) return Promise.reject(new Error("fail"));
      return Promise.resolve({ ok: true });
    });
    vi.spyOn(console, "warn").mockImplementation(() => {});

    const { result } = renderHook(() => usePolling(fetchFn, 3000));

    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(result.current.error).toBeTruthy();

    // Next interval
    await act(async () => {
      await vi.advanceTimersByTimeAsync(3000);
    });

    expect(result.current.error).toBeNull();
    expect(result.current.data).toEqual({ ok: true });

    console.warn.mockRestore();
  });

  it("cleans up interval on unmount", async () => {
    const fetchFn = vi.fn(() => Promise.resolve({}));
    const { unmount } = renderHook(() => usePolling(fetchFn, 3000));

    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(fetchFn).toHaveBeenCalledTimes(1);

    unmount();

    await act(async () => {
      await vi.advanceTimersByTimeAsync(9000);
    });
    // Should not have been called again after unmount
    expect(fetchFn).toHaveBeenCalledTimes(1);
  });
});
