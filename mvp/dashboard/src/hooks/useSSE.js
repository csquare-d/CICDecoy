import { useState, useEffect, useRef, useCallback } from "react";

/**
 * useSSE — connects to the SSE live event stream.
 *
 * Returns:
 *   events     — ring buffer of recent events (newest first)
 *   connected  — boolean SSE connection status
 *   eventCount — total events received this session
 */
export default function useSSE(maxBuffer = 200) {
  const [events, setEvents] = useState([]);
  const [connected, setConnected] = useState(false);
  const [eventCount, setEventCount] = useState(0);
  const sseRef = useRef(null);
  const retriesRef = useRef(0);

  const connect = useCallback(() => {
    if (sseRef.current) sseRef.current.close();

    const sse = new EventSource("/api/events/stream");
    sseRef.current = sse;

    sse.addEventListener("decoy_event", (e) => {
      try {
        const ev = JSON.parse(e.data);
        setEvents((prev) => {
          const next = [ev, ...prev];
          return next.length > maxBuffer ? next.slice(0, maxBuffer) : next;
        });
        setEventCount((c) => c + 1);
      } catch (err) {
        console.warn("SSE parse error:", err);
      }
    });

    sse.addEventListener("open", () => {
      setConnected(true);
      retriesRef.current = 0;
    });

    sse.addEventListener("error", () => {
      setConnected(false);
      sse.close();
      retriesRef.current += 1;
      const delay = Math.min(retriesRef.current * 2000, 15000);
      setTimeout(connect, delay);
    });
  }, [maxBuffer]);

  useEffect(() => {
    connect();
    return () => {
      if (sseRef.current) sseRef.current.close();
    };
  }, [connect]);

  return { events, connected, eventCount };
}
