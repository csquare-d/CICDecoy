import { useState, useEffect, useCallback, useRef } from "react";

/**
 * usePolling — periodically fetches data from an async function.
 *
 * @param {Function} fetchFn   — async () => data
 * @param {number}   interval  — ms between fetches
 * @param {boolean}  enabled   — whether polling is active (default true)
 *
 * Returns { data, loading, error, refresh }
 */
export default function usePolling(fetchFn, interval = 15000, enabled = true) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const fetchRef = useRef(fetchFn);
  // Always keep ref pointing to latest fetchFn to avoid stale closures
  fetchRef.current = fetchFn;

  const refresh = useCallback(async () => {
    try {
      const result = await fetchRef.current();
      setData(result);
      setError(null);
    } catch (err) {
      setError(err);
      console.warn("Polling error:", err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!enabled) return;

    // Initial fetch
    refresh();

    // Interval
    const id = setInterval(refresh, interval);
    return () => clearInterval(id);
  }, [interval, enabled, refresh]);

  return { data, loading, error, refresh };
}
