import { Routes, Route } from "react-router-dom";
import ApiKeyGate from "./components/ApiKeyGate";
import Header from "./components/Header";
import Footer from "./components/Footer";
import Overview from "./pages/Overview";
import Sessions from "./pages/Sessions";
import Intelligence from "./pages/Intelligence";
import DecoyFleet from "./pages/DecoyFleet";
import Honeytokens from "./pages/Honeytokens";
import useSSE from "./hooks/useSSE";
import usePolling from "./hooks/usePolling";
import {
  fetchStats,
  fetchSessions,
  fetchMitre,
  fetchEngage,
  fetchTopIPs,
  fetchKillChains,
  fetchHistogram,
  fetchGeo,
  fetchHoneytokens,
} from "./api/client";

/**
 * App — root layout with header, footer, routed pages.
 *
 * All data fetching is centralized here and passed down as props.
 * This avoids duplicate fetches across pages that share data.
 */
export default function App() {
  // ── SSE live event stream ──
  const { events: sseEvents, connected: sseConnected, eventCount } = useSSE();

  // ── Polled data (each with its own interval) ──
  const { data: stats } = usePolling(fetchStats, 10000);
  const { data: sessions, refresh: refreshSessions } = usePolling(fetchSessions, 15000);
  const { data: mitre } = usePolling(fetchMitre, 30000);
  const { data: engage } = usePolling(fetchEngage, 30000);
  const { data: topIPs } = usePolling(fetchTopIPs, 20000);
  const { data: killChains } = usePolling(fetchKillChains, 30000);
  const { data: histogram } = usePolling(fetchHistogram, 30000);
  const { data: geo } = usePolling(fetchGeo, 60000);
  const { data: honeytokens } = usePolling(fetchHoneytokens, 15000);

  // Augment stats with SSE status
  const statsWithSSE = stats ? { ...stats, sse_connected: sseConnected } : null;

  return (
    <ApiKeyGate>
      <Header stats={statsWithSSE} />

      <main
        style={{ flex: 1, padding: 16, overflow: "auto", display: "flex", flexDirection: "column" }}
      >
        <Routes>
          <Route
            path="/"
            element={
              <Overview stats={stats} mitre={mitre} sseEvents={sseEvents} eventCount={eventCount} />
            }
          />
          <Route
            path="/sessions"
            element={<Sessions sessions={sessions} refresh={refreshSessions} />}
          />
          <Route
            path="/intelligence"
            element={
              <Intelligence
                killChains={killChains}
                topIPs={topIPs}
                engage={engage}
                geo={geo}
                histogram={histogram}
              />
            }
          />
          <Route
            path="/honeytokens"
            element={<Honeytokens honeytokens={honeytokens} stats={stats} />}
          />
          <Route path="/fleet" element={<DecoyFleet sessions={sessions} stats={stats} />} />
        </Routes>
      </main>

      <Footer stats={statsWithSSE} />
    </ApiKeyGate>
  );
}
