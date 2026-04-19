import { useState, useEffect, useRef, useCallback } from "react";
import {
  withAuthQuery,
  clearApiKey,
  UNAUTHORIZED_EVENT,
} from "../api/client";

/**
 * useSSE — connects to the SSE live event stream.
 *
 * Returns:
 *   events     — ring buffer of recent events (newest first)
 *   connected  — boolean SSE connection status
 *   eventCount — total events received this session
 *
 * The API key is passed as a `?api_key=` query param because browser
 * EventSource objects cannot set custom headers. On repeated connection
 * failures we assume the key is bad, clear it, and trigger re-auth.
 */
export default function useSSE(maxBuffer = 200) {
  const [events, setEvents] = useState([]);
  const [connected, setConnected] = useState(false);
  const [eventCount, setEventCount] = useState(0);
  const sseRef = useRef(null);
  const retriesRef = useRef(0);

  const connect = useCallback(() => {
    if (sseRef.current) sseRef.current.close();

    const sse = new EventSource(withAuthQuery("/api/events/stream"));
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
      // After repeated failures, assume the API key was rejected (EventSource
      // does not expose HTTP status) and force re-auth.
      if (retriesRef.current >= 3) {
        if (sseRef.current) {
          sseRef.current.close();
          sseRef.current = null;
        }
        clearApiKey();
        try {
          window.dispatchEvent(new CustomEvent(UNAUTHORIZED_EVENT));
        } catch {
          /* no-op */
        }
        return;
      }
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
