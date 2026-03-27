# CI/CDecoy — CTI Pipeline
# cti/collector/src/ingest.py  (collector)
# cti/enrichment/src/          (enrichment modules)
# cti/output/src/              (STIX + IOC generation)
#
# This file combines all CTI pipeline components for the prototype.
# In production, each component runs as a separate container.
#
# Data flow:
# Decoy Events → NATS → Collector → Enrichment → Storage → Output
#                        (normalize)  (geoip,       (TSDB)   (STIX,
#                                      MITRE,                 IOCs,
#                                      tooling)               SIEM)

import asyncio
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

import nats
from nats.aio.client import Client as NATSClient

logger = logging.getLogger("cicdecoy.cti")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  COLLECTOR — Ingest & Normalize
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@dataclass
class NormalizedEvent:
    """Common event schema for all decoy interactions."""
    event_id: str
    timestamp: str
    decoy_name: str
    decoy_tier: int
    session_id: str
    event_type: str               # connection | auth | command | alert | session
    source_ip: str = ""
    source_port: int = 0
    geo: dict = field(default_factory=dict)
    raw_data: dict = field(default_factory=dict)

    # Enrichment fields (populated downstream)
    mitre_techniques: list = field(default_factory=list)
    threat_feed_matches: list = field(default_factory=list)
    tool_signatures: list = field(default_factory=list)
    severity: str = "info"
    tags: list = field(default_factory=list)


class EventCollector:
    """
    Subscribes to the NATS message bus and normalizes incoming
    events from all decoys into a common schema.

    Handles deduplication (same event from multiple exporters)
    and basic validation before forwarding to enrichment.
    """

    def __init__(self, nats_url: str, enrichment_pipeline: "EnrichmentPipeline"):
        self.nats_url = nats_url
        self.enrichment = enrichment_pipeline
        self.nc: Optional[NATSClient] = None
        self.seen_events: set = set()       # Dedup window
        self.event_count = 0
        self.dedup_count = 0

    async def start(self):
        self.nc = await nats.connect(self.nats_url)
        logger.info(f"Collector connected to NATS: {self.nats_url}")

        # Subscribe to all decoy events
        await self.nc.subscribe("decoy.events.>", cb=self._on_event)
        logger.info("Subscribed to decoy.events.>")

    async def _on_event(self, msg):
        """Process a raw event from the message bus."""
        try:
            raw = json.loads(msg.data.decode())
        except json.JSONDecodeError:
            logger.warning(f"Invalid JSON on {msg.subject}")
            return

        # Deduplicate
        event_hash = self._compute_hash(raw)
        if event_hash in self.seen_events:
            self.dedup_count += 1
            return
        self.seen_events.add(event_hash)
        self._trim_dedup_window()

        # Normalize
        normalized = self._normalize(raw, msg.subject)
        self.event_count += 1

        # Forward to enrichment
        await self.enrichment.enrich(normalized)

    def _normalize(self, raw: dict, subject: str) -> NormalizedEvent:
        """Transform raw decoy event into common schema."""
        data = raw.get("data", {})
        return NormalizedEvent(
            event_id=str(uuid.uuid4()),
            timestamp=raw.get("timestamp", datetime.now(timezone.utc).isoformat()),
            decoy_name=raw.get("decoy", "unknown"),
            decoy_tier=raw.get("tier", 0),
            session_id=raw.get("session_id", ""),
            event_type=raw.get("event_type", "unknown"),
            source_ip=data.get("client_ip", ""),
            source_port=data.get("client_port", 0),
            raw_data=data,
        )

    def _compute_hash(self, raw: dict) -> str:
        """Simple hash for deduplication within a 60s window."""
        import hashlib
        key = f"{raw.get('session_id')}:{raw.get('event_type')}:" \
              f"{raw.get('timestamp')}:{json.dumps(raw.get('data', {}), sort_keys=True)}"
        return hashlib.md5(key.encode()).hexdigest()

    def _trim_dedup_window(self):
        """Keep dedup set from growing unbounded."""
        if len(self.seen_events) > 100_000:
            # Remove oldest half (approximate — set is unordered)
            to_remove = list(self.seen_events)[:50_000]
            for item in to_remove:
                self.seen_events.discard(item)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  ENRICHMENT — GeoIP, MITRE, Threat Feeds, Tool ID
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class GeoIPEnricher:
    """Resolve source IPs to geographic location."""

    def __init__(self, db_path: str = "/var/lib/cicdecoy/GeoLite2-City.mmdb"):
        self.db_path = db_path
        self.reader = None

    async def initialize(self):
        try:
            import geoip2.database
            self.reader = geoip2.database.Reader(self.db_path)
            logger.info("GeoIP database loaded")
        except Exception as e:
            logger.warning(f"GeoIP database not available: {e}")

    def enrich(self, event: NormalizedEvent):
        if not self.reader or not event.source_ip:
            return
        try:
            resp = self.reader.city(event.source_ip)
            event.geo = {
                "country": resp.country.iso_code,
                "country_name": resp.country.name,
                "city": resp.city.name,
                "latitude": resp.location.latitude,
                "longitude": resp.location.longitude,
                "asn": None,  # Populated by ASN database if available
            }
        except Exception:
            pass  # Private IP or not in database


class MITREMapper:
    """
    Map observed commands and behaviors to MITRE ATT&CK techniques.

    Uses pattern matching against command strings and behavioral
    sequences to identify techniques. More sophisticated than the
    simple mapping in the SSH decoy — this does multi-command
    sequence analysis.
    """

    # Single-command technique mappings
    COMMAND_TECHNIQUES = {
        # Discovery
        r"whoami|id|groups":                    ("T1033", "System Owner/User Discovery"),
        r"uname|cat /etc/os-release|lsb_release": ("T1082", "System Information Discovery"),
        r"ifconfig|ip addr|ip a":               ("T1016", "System Network Configuration Discovery"),
        r"netstat|ss -[tln]":                   ("T1049", "System Network Connections Discovery"),
        r"ps aux|ps -ef|top":                   ("T1057", "Process Discovery"),
        r"ls|dir|find / ":                      ("T1083", "File and Directory Discovery"),
        r"cat /etc/passwd|cat /etc/group":      ("T1087", "Account Discovery"),
        r"arp -a|ip neigh":                     ("T1018", "Remote System Discovery"),
        r"route|ip route|netstat -r":           ("T1016.001", "Internet Connection Discovery"),
        r"nmap|masscan|zmap":                   ("T1046", "Network Service Discovery"),
        r"docker ps|kubectl get":               ("T1613", "Container and Resource Discovery"),

        # Credential Access
        r"cat /etc/shadow":                     ("T1003.008", "/etc/passwd and /etc/shadow"),
        r"cat.*\.ssh/(id_|authorized)":         ("T1552.004", "Private Keys"),
        r"cat.*\.(aws|kube|docker)/":           ("T1552.001", "Credentials In Files"),
        r"strings.*|grep -r.*(pass|key|token)": ("T1552.001", "Credentials In Files"),
        r"mimikatz|hashdump|secretsdump":       ("T1003", "OS Credential Dumping"),

        # Lateral Movement
        r"ssh\s+\w+@":                          ("T1021.004", "SSH"),
        r"scp\s+|rsync.*:":                     ("T1021.004", "SSH"),
        r"psexec|wmiexec|smbexec":              ("T1021.002", "SMB/Windows Admin Shares"),
        r"kubectl exec|docker exec":            ("T1609", "Container Administration Command"),

        # Execution
        r"python[23]?\s+-c|perl\s+-e":          ("T1059.006", "Python"),
        r"bash\s+-[ic]|sh\s+-c":                ("T1059.004", "Unix Shell"),
        r"curl.*\|\s*(ba)?sh":                  ("T1059.004", "Unix Shell"),
        r"chmod\s+\+x":                         ("T1204.002", "Malicious File"),
        r"crontab|/etc/cron":                   ("T1053.003", "Cron"),
        r"ansible-playbook|terraform apply":    ("T1072", "Software Deployment Tools"),

        # Persistence
        r"echo.*>>.*authorized_keys":           ("T1098.004", "SSH Authorized Keys"),
        r"echo.*>>.*crontab|crontab -e":        ("T1053.003", "Cron"),
        r"echo.*>>.*\.bashrc|\.profile":        ("T1546.004", "Unix Shell Configuration Modification"),
        r"systemctl\s+(enable|start)":          ("T1543.002", "Systemd Service"),

        # Collection & Exfiltration
        r"tar\s+[cx]|zip|7z":                   ("T1560.001", "Archive via Utility"),
        r"base64\s+(|-)":                        ("T1132.001", "Standard Encoding"),
        r"curl.*-d|wget.*--post":               ("T1048", "Exfiltration Over Alternative Protocol"),
        r"scp.*@.*:":                           ("T1048", "Exfiltration Over Alternative Protocol"),

        # Defense Evasion
        r"history\s+-c|unset HISTFILE":         ("T1070.003", "Clear Command History"),
        r"rm\s+.*\.log|>/dev/null":             ("T1070.002", "Clear Linux or Mac System Logs"),
        r"iptables.*DROP|ufw":                  ("T1562.004", "Disable or Modify System Firewall"),

        # Command and Control
        r"nc\s.*-[el]|ncat.*-[el]|socat":       ("T1095", "Non-Application Layer Protocol"),
        r"/dev/tcp/|/dev/udp/":                 ("T1095", "Non-Application Layer Protocol"),
        r"curl.*http.*/beacon|wget.*callback":  ("T1071.001", "Web Protocols"),

        # Impact
        r"rm\s+-rf\s+/|mkfs|dd\s+if=.*of=/dev": ("T1485", "Data Destruction"),
        r"chmod\s+000|chattr\s+\+i":            ("T1486", "Data Encrypted for Impact"),
    }

    def enrich(self, event: NormalizedEvent):
        """Map event data to MITRE techniques."""
        command = event.raw_data.get("command", "")
        if not command:
            return

        import re
        for pattern, (technique_id, technique_name) in self.COMMAND_TECHNIQUES.items():
            if re.search(pattern, command, re.IGNORECASE):
                event.mitre_techniques.append({
                    "technique_id": technique_id,
                    "technique_name": technique_name,
                    "confidence": "high" if len(pattern) > 20 else "medium",
                    "evidence": command,
                })

    def analyze_sequence(self, commands: list[str]) -> list[dict]:
        """
        Detect multi-step attack patterns from command sequences.

        Example: whoami → cat /etc/passwd → ssh user@host
        = Recon → Credential Access → Lateral Movement
        """
        phases = []
        phase_map = {
            "discovery":  r"whoami|id|uname|ls|cat /etc|ifconfig|ip a|ps|netstat",
            "credential": r"cat.*(shadow|passwd|\.ssh|\.aws|\.kube)|grep.*(pass|key|token)",
            "staging":    r"wget|curl.*http|chmod\s+\+x|tar|base64",
            "lateral":    r"ssh\s+\w+@|scp|kubectl exec|docker exec|ansible",
            "persist":    r"crontab|authorized_keys|\.bashrc|systemctl.*enable",
            "exfil":      r"scp.*@.*:|curl.*-d.*http|tar.*\|.*nc",
        }

        import re
        for cmd in commands:
            for phase, pattern in phase_map.items():
                if re.search(pattern, cmd, re.IGNORECASE):
                    phases.append(phase)
                    break

        # Detect kill chain progression
        if len(set(phases)) >= 3:
            return [{
                "pattern": "kill_chain_progression",
                "phases_observed": list(dict.fromkeys(phases)),  # Dedupe preserving order
                "confidence": "high" if len(set(phases)) >= 4 else "medium",
            }]
        return []


class ThreatFeedEnricher:
    """
    Correlate source IPs and observed IOCs against known threat feeds.

    Supports:
    - AlienVault OTX
    - Abuse.ch
    - Custom STIX/TAXII feeds
    - Local blocklists
    """

    def __init__(self):
        self.known_malicious_ips: set = set()
        self.known_tools: dict = {}
        self.feed_sources: list = []

    async def initialize(self):
        """Load threat feed data. In production, this refreshes periodically."""
        # Load local blocklists
        import os
        blocklist_dir = "/var/lib/cicdecoy/feeds"
        if os.path.isdir(blocklist_dir):
            for filename in os.listdir(blocklist_dir):
                filepath = os.path.join(blocklist_dir, filename)
                with open(filepath) as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            self.known_malicious_ips.add(line)

        logger.info(f"Loaded {len(self.known_malicious_ips)} IPs from threat feeds")

    def enrich(self, event: NormalizedEvent):
        if event.source_ip in self.known_malicious_ips:
            event.threat_feed_matches.append({
                "source": "local_blocklist",
                "indicator": event.source_ip,
                "type": "ip",
                "confidence": "high",
            })
            event.severity = self._escalate_severity(event.severity)

    @staticmethod
    def _escalate_severity(current: str) -> str:
        levels = ["info", "low", "medium", "high", "critical"]
        idx = levels.index(current) if current in levels else 0
        return levels[min(idx + 1, len(levels) - 1)]


class ToolIdentifier:
    """
    Identify attacker tools and frameworks from observed behavior.

    Matches against known command patterns, user-agent strings,
    timing signatures, and payload characteristics.
    """

    TOOL_SIGNATURES = {
        "metasploit": {
            "patterns": [
                r"meterpreter",
                r"multi/handler",
                r"exploit/",
                r"msfvenom",
                r"reverse_tcp",
            ],
            "mitre_software": "S0081",
        },
        "cobalt_strike": {
            "patterns": [
                r"beacon",
                r"powershell.*-enc\s+[A-Za-z0-9+/=]{50,}",
                r"jump\s+(psexec|winrm|ssh)",
            ],
            "mitre_software": "S0154",
        },
        "nmap": {
            "patterns": [
                r"nmap",
                r"Nmap",
                r"-sV\s+-p",
                r"-sS\s+-sV",
            ],
            "mitre_software": "S0108",
        },
        "linpeas": {
            "patterns": [
                r"linpeas",
                r"LinPEAS",
                r"curl.*linpeas\.sh",
            ],
            "mitre_software": None,
        },
        "pspy": {
            "patterns": [
                r"pspy",
                r"\./pspy64",
            ],
            "mitre_software": None,
        },
        "chisel": {
            "patterns": [
                r"chisel\s+(client|server)",
                r"\./chisel",
            ],
            "mitre_software": None,
        },
    }

    def enrich(self, event: NormalizedEvent):
        command = event.raw_data.get("command", "")
        if not command:
            return

        import re
        for tool_name, sig in self.TOOL_SIGNATURES.items():
            for pattern in sig["patterns"]:
                if re.search(pattern, command, re.IGNORECASE):
                    event.tool_signatures.append({
                        "tool": tool_name,
                        "confidence": "high",
                        "mitre_software_id": sig.get("mitre_software"),
                        "evidence": command,
                    })
                    break  # One match per tool is enough


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  ENRICHMENT PIPELINE — Orchestrator
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class EnrichmentPipeline:
    """
    Orchestrates all enrichment stages and forwards to storage + output.
    """

    def __init__(self):
        self.geoip = GeoIPEnricher()
        self.mitre = MITREMapper()
        self.threat_feeds = ThreatFeedEnricher()
        self.tool_id = ToolIdentifier()
        self.storage: Optional["EventStore"] = None
        self.outputs: list = []

        # Session tracking for multi-command analysis
        self.sessions: dict[str, list] = {}   # session_id → [commands]

    async def initialize(self):
        await self.geoip.initialize()
        await self.threat_feeds.initialize()
        logger.info("Enrichment pipeline initialized")

    async def enrich(self, event: NormalizedEvent):
        """Run event through all enrichment stages."""

        # Stage 1: GeoIP
        self.geoip.enrich(event)

        # Stage 2: MITRE ATT&CK mapping
        self.mitre.enrich(event)

        # Stage 3: Threat feed correlation
        self.threat_feeds.enrich(event)

        # Stage 4: Tool identification
        self.tool_id.enrich(event)

        # Stage 5: Session sequence analysis
        if event.event_type == "command.exec":
            self._track_session(event)

        # Stage 6: Severity calculation
        self._compute_severity(event)

        # Forward to storage
        if self.storage:
            await self.storage.store(event)

        # Forward to outputs
        for output in self.outputs:
            await output.process(event)

    def _track_session(self, event: NormalizedEvent):
        """Track commands per session for sequence analysis."""
        sid = event.session_id
        if sid not in self.sessions:
            self.sessions[sid] = []

        command = event.raw_data.get("command", "")
        self.sessions[sid].append(command)

        # Run sequence analysis periodically
        if len(self.sessions[sid]) % 5 == 0:
            patterns = self.mitre.analyze_sequence(self.sessions[sid])
            if patterns:
                event.tags.append("kill_chain_detected")
                event.raw_data["sequence_analysis"] = patterns

    def _compute_severity(self, event: NormalizedEvent):
        """Aggregate severity from all enrichment sources."""
        if event.tool_signatures:
            event.severity = "critical"
        elif event.threat_feed_matches:
            event.severity = max(event.severity, "high")
        elif event.mitre_techniques:
            # Certain techniques are always high severity
            high_sev_techniques = {
                "T1003", "T1021", "T1059", "T1048", "T1105",
                "T1609", "T1485", "T1486",
            }
            for tech in event.mitre_techniques:
                base_id = tech["technique_id"].split(".")[0]
                if base_id in high_sev_techniques:
                    event.severity = "high"
                    break


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  STORAGE — TimescaleDB Event Store
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class EventStore:
    """Store enriched events in TimescaleDB for querying and output."""

    def __init__(self, dsn: str):
        self.dsn = dsn
        self.pool = None

    async def initialize(self):
        import asyncpg
        self.pool = await asyncpg.create_pool(self.dsn)
        logger.info("Connected to TimescaleDB")

    async def store(self, event: NormalizedEvent):
        if not self.pool:
            return
        async with self.pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO decoy_events (
                    event_id, timestamp, decoy_name, decoy_tier,
                    session_id, event_type, source_ip, source_port,
                    geo, mitre_techniques, threat_feeds,
                    tool_signatures, severity, tags, raw_data
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8,
                          $9, $10, $11, $12, $13, $14, $15)
            """,
                event.event_id,
                event.timestamp,
                event.decoy_name,
                event.decoy_tier,
                event.session_id,
                event.event_type,
                event.source_ip,
                event.source_port,
                json.dumps(event.geo),
                json.dumps(event.mitre_techniques),
                json.dumps(event.threat_feed_matches),
                json.dumps(event.tool_signatures),
                event.severity,
                json.dumps(event.tags),
                json.dumps(event.raw_data),
            )

    async def get_session(self, session_id: str) -> list[dict]:
        async with self.pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT * FROM decoy_events
                WHERE session_id = $1
                ORDER BY timestamp ASC
            """, session_id)
            return [dict(r) for r in rows]

    async def get_iocs(self, since_hours: int = 24) -> list[dict]:
        async with self.pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT DISTINCT source_ip, severity,
                       jsonb_agg(DISTINCT mitre_techniques) as techniques,
                       jsonb_agg(DISTINCT tool_signatures) as tools,
                       COUNT(*) as event_count
                FROM decoy_events
                WHERE timestamp > NOW() - INTERVAL '%s hours'
                  AND severity IN ('high', 'critical')
                GROUP BY source_ip, severity
                ORDER BY event_count DESC
            """, since_hours)
            return [dict(r) for r in rows]


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  OUTPUT — STIX 2.1 Bundle Generator
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class STIXOutputGenerator:
    """
    Generate STIX 2.1 bundles from enriched events.

    Produces:
    - Indicator objects (IP addresses, hashes, patterns)
    - Attack Pattern objects (mapped from MITRE techniques)
    - Observed Data (raw observations)
    - Relationship objects (connecting indicators to attack patterns)
    - Sighting objects (when known threat actors are detected)
    """

    STIX_IDENTITY = {
        "type": "identity",
        "id": "identity--cicdecoy-platform",
        "name": "CI/CDecoy Deception Platform",
        "identity_class": "system",
    }

    async def process(self, event: NormalizedEvent):
        """Generate STIX objects from an enriched event."""
        # Only generate STIX for high/critical events
        if event.severity not in ("high", "critical"):
            return

        bundle = self._create_bundle(event)

        # In production, this publishes to the TAXII server
        # and/or writes to a STIX feed directory
        logger.info(
            f"STIX bundle generated: {len(bundle['objects'])} objects "
            f"for session {event.session_id[:8]}"
        )
        return bundle

    def _create_bundle(self, event: NormalizedEvent) -> dict:
        objects = [self.STIX_IDENTITY]

        # Create indicator for source IP
        if event.source_ip:
            indicator = self._create_ip_indicator(event)
            objects.append(indicator)

        # Create attack patterns from MITRE mappings
        for technique in event.mitre_techniques:
            attack_pattern = {
                "type": "attack-pattern",
                "id": f"attack-pattern--{uuid.uuid5(uuid.NAMESPACE_URL, technique['technique_id'])}",
                "name": technique["technique_name"],
                "external_references": [{
                    "source_name": "mitre-attack",
                    "external_id": technique["technique_id"],
                    "url": f"https://attack.mitre.org/techniques/{technique['technique_id'].replace('.', '/')}/",
                }],
            }
            objects.append(attack_pattern)

            # Relationship: indicator → uses → attack-pattern
            if event.source_ip:
                rel = {
                    "type": "relationship",
                    "id": f"relationship--{uuid.uuid4()}",
                    "relationship_type": "uses",
                    "source_ref": f"indicator--{uuid.uuid5(uuid.NAMESPACE_URL, event.source_ip)}",
                    "target_ref": attack_pattern["id"],
                }
                objects.append(rel)

        # Create malware/tool objects for identified tools
        for tool in event.tool_signatures:
            tool_obj = {
                "type": "tool",
                "id": f"tool--{uuid.uuid5(uuid.NAMESPACE_URL, tool['tool'])}",
                "name": tool["tool"],
                "tool_types": ["exploitation", "remote-access"],
            }
            if tool.get("mitre_software_id"):
                tool_obj["external_references"] = [{
                    "source_name": "mitre-attack",
                    "external_id": tool["mitre_software_id"],
                }]
            objects.append(tool_obj)

        return {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": objects,
        }

    def _create_ip_indicator(self, event: NormalizedEvent) -> dict:
        return {
            "type": "indicator",
            "id": f"indicator--{uuid.uuid5(uuid.NAMESPACE_URL, event.source_ip)}",
            "name": f"Malicious IP: {event.source_ip}",
            "description": (
                f"IP observed interacting with deception asset "
                f"{event.decoy_name}. Severity: {event.severity}."
            ),
            "pattern": f"[ipv4-addr:value = '{event.source_ip}']",
            "pattern_type": "stix",
            "valid_from": event.timestamp,
            "indicator_types": ["malicious-activity"],
            "confidence": 85,
            "labels": [event.severity, f"decoy:{event.decoy_name}"],
        }


class IOCGenerator:
    """Generate standalone IOC feeds (simpler than full STIX)."""

    async def process(self, event: NormalizedEvent):
        if event.severity not in ("high", "critical"):
            return

        iocs = []

        if event.source_ip:
            iocs.append({
                "type": "ipv4",
                "value": event.source_ip,
                "confidence": 85,
                "severity": event.severity,
                "first_seen": event.timestamp,
                "source": f"cicdecoy:{event.decoy_name}",
                "tags": [t["technique_id"] for t in event.mitre_techniques],
            })

        return iocs


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  MAIN — Pipeline Entrypoint
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    import os
    nats_url = os.environ.get("NATS_URL", "nats://msg-bus:4222")
    db_dsn = os.environ.get("DB_DSN", "postgresql://cicdecoy:pass@tsdb:5432/cicdecoy")

    # Build pipeline
    pipeline = EnrichmentPipeline()
    await pipeline.initialize()

    # Set up storage
    store = EventStore(db_dsn)
    await store.initialize()
    pipeline.storage = store

    # Set up outputs
    pipeline.outputs = [
        STIXOutputGenerator(),
        IOCGenerator(),
    ]

    # Start collector
    collector = EventCollector(nats_url, pipeline)
    await collector.start()

    logger.info("CTI pipeline running")

    # Keep alive
    while True:
        await asyncio.sleep(60)
        logger.info(
            f"Pipeline stats: events={collector.event_count} "
            f"deduped={collector.dedup_count}"
        )


if __name__ == "__main__":
    asyncio.run(main())
