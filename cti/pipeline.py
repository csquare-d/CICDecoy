#!/usr/bin/env python3
"""
CI/CDecoy — CTI Pipeline (MVP)

Event collector and correlator:
1. Subscribes to NATS JetStream for decoy interaction events
2. Subscribes to Falco runtime security alerts
3. Correlates Falco escape attempts with active decoy sessions
4. Normalizes and stores all events in TimescaleDB
5. Republishes enriched events to cicdecoy.enriched.events.>
6. Logs to stdout for debugging
"""

import asyncio
import hashlib
import json
import logging
import os
import random
import re
import signal
import sys
import time
import uuid
from datetime import UTC, datetime
from urllib.parse import urlparse, urlunparse

import asyncpg
import nats
from alerting import AlertForwarder
from engage_mapper import EngageEnricher
from enrichment import enrich_event
from falco_correlator import FalcoCorrelator
from metrics import (
    ACTIVE_SESSIONS,
    ENRICHMENT_LATENCY,
    EVENTS_ERRORS,
    EVENTS_PROCESSED,
    FALCO_ALERTS,
    FALCO_CORRELATED,
    NATS_CONSUMER_LAG,
)
from prometheus_client import start_http_server
from session_analyzer import SessionAnalyzer

logger = logging.getLogger("cicdecoy.collector")

_NATS_SUBJECT_RE = re.compile(r"[^a-zA-Z0-9._-]")
_LABEL_RE = re.compile(r"[^a-zA-Z0-9._-]")


def _sanitize_label(value: str, max_len: int = 64) -> str:
    """Sanitize a value for use as a Prometheus metric label."""
    if not isinstance(value, str):
        value = str(value)
    value = _LABEL_RE.sub("_", value)
    return value[:max_len]


def _sanitize_nats_subject(value: str) -> str:
    """Sanitize a value for use in NATS subject paths.

    Only allows alphanumeric, dots, hyphens, and underscores.
    Strips NATS wildcards (>, *) and other special characters.
    """
    sanitized = _NATS_SUBJECT_RE.sub("_", value)
    # Also strip leading/trailing dots and collapse consecutive dots
    sanitized = re.sub(r"\.{2,}", ".", sanitized).strip(".")
    return sanitized or "unknown"


class Collector:
    """Minimal event collector: NATS → TimescaleDB."""

    def __init__(self, nats_url: str, db_dsn: str):
        self.nats_url = nats_url
        self.db_dsn = db_dsn
        self.nc = None
        self.js = None
        self.pool = None
        # Counters are plain ints — safe under asyncio's cooperative
        # single-threaded event loop (no pre-emptive thread switching).
        self.event_count = 0
        self.error_count = 0
        self._shutting_down = False
        self._in_flight = 0
        self.session_analyzer = SessionAnalyzer()
        self.engage_enricher = EngageEnricher()
        self.alert_forwarder = AlertForwarder()
        self._canary_credentials: set[tuple[str, str]] = set()  # (username, password_sha256)

    def _load_canary_credentials(self):
        """Load canary credentials from CANARY_CREDENTIALS env var.

        Expects a JSON array of {"username": "...", "password": "..."} objects.
        Stores (username, sha256_hash) tuples for matching against auth events
        which report password hashes rather than plaintext.
        """
        raw = os.environ.get("CANARY_CREDENTIALS")
        if not raw:
            logger.info("CANARY_CREDENTIALS not set; credential correlation disabled")
            return
        try:
            creds = json.loads(raw)
            if not isinstance(creds, list):
                logger.error("CANARY_CREDENTIALS must be a JSON array, got %s", type(creds).__name__)
                return
        except json.JSONDecodeError as exc:
            logger.error("Failed to parse CANARY_CREDENTIALS: %s", exc)
            return
        for entry in creds:
            if not isinstance(entry, dict):
                continue
            username = entry.get("username", "")
            password = entry.get("password", "")
            if username and password:
                pw_hash = hashlib.sha256(password.encode()).hexdigest()
                self._canary_credentials.add((username, pw_hash))
        logger.info("Loaded %d canary credentials for cross-decoy correlation", len(self._canary_credentials))

    async def start(self):
        """Connect to NATS and DB, start consuming."""
        # Load canary credentials for cross-decoy correlation
        self._load_canary_credentials()

        # Connect to TimescaleDB
        parsed = urlparse(self.db_dsn)
        if parsed.hostname:
            safe_dsn = urlunparse(
                parsed._replace(
                    netloc=f"{parsed.username or ''}:***@{parsed.hostname}"
                    f"{':' + str(parsed.port) if parsed.port else ''}"
                )
            )
        else:
            safe_dsn = "<unparseable DSN>"
        logger.info("Connecting to TimescaleDB: %s", safe_dsn)
        try:
            self.pool = await asyncpg.create_pool(
                self.db_dsn,
                min_size=2,
                max_size=10,
                command_timeout=30,
            )
            logger.info("TimescaleDB connected")
        except Exception as e:
            logger.error(f"TimescaleDB connection failed: {e}")
            raise

        # Verify schema exists
        await self._verify_schema()

        # Connect to NATS
        logger.info(f"Connecting to NATS: {self.nats_url}")
        nats_token = os.environ.get("NATS_TOKEN", "")
        connect_kwargs = {
            "servers": self.nats_url,
            "reconnect_time_wait": 2,
            "max_reconnect_attempts": -1,  # Retry forever
        }
        if nats_token:
            connect_kwargs["token"] = nats_token
        self.nc = await nats.connect(**connect_kwargs)
        self.js = self.nc.jetstream()
        logger.info("NATS connected")

        # Ensure JetStream streams exist (idempotent — creates if missing,
        # succeeds if already present with matching config).
        await self._ensure_streams()

        # Subscribe using durable consumer
        try:
            sub = await self.js.pull_subscribe(
                "cicdecoy.decoy.events.>",
                durable="cti-collector",
                stream="DECOY_EVENTS",
            )
            logger.info("Subscribed to DECOY_EVENTS stream as cti-collector")
        except Exception as e:
            logger.warning(f"Pull subscribe failed, trying push subscribe: {e}")
            # Fall back to push subscribe via JetStream if possible
            try:
                sub = await self.js.subscribe(
                    "cicdecoy.decoy.events.>",
                    durable="cti-collector-push",
                    stream="DECOY_EVENTS",
                    cb=self._on_message_push,
                )
                logger.info("Subscribed via JetStream push subscribe")
            except Exception as e2:
                # Plain NATS has NO delivery guarantees — events will be
                # lost on restart.  Only allow this if the operator has
                # explicitly opted in via the environment variable.
                if os.environ.get("ALLOW_NONDURABLE_NATS", "").lower() == "true":
                    sub = await self.nc.subscribe(
                        "cicdecoy.decoy.events.>",
                        cb=self._on_message_push,
                    )
                    logger.error(
                        "JetStream unavailable — subscribed via plain NATS "
                        "with NO delivery guarantees. Events WILL be lost on "
                        "restart. Set up JetStream for production use."
                    )
                else:
                    raise RuntimeError(
                        f"JetStream unavailable ({e2}) and "
                        "ALLOW_NONDURABLE_NATS is not set. Refusing to start "
                        "without delivery guarantees. Set "
                        "ALLOW_NONDURABLE_NATS=true to override."
                    ) from e2
            return  # Push subscribe handles its own loop

        # Pull loop
        logger.info("Starting event collection loop")
        consecutive_failures = 0
        while True:
            try:
                messages = await sub.fetch(batch=100, timeout=5)
                for msg in messages:
                    if self._shutting_down:
                        if hasattr(msg, "nak"):
                            await msg.nak()
                        continue
                    self._in_flight += 1
                    try:
                        try:
                            await self._process_message(msg)
                        except (json.JSONDecodeError, UnicodeDecodeError):
                            # Permanently malformed — ACK to discard (retry won't fix it)
                            logger.warning("Permanently malformed message, discarding")
                            if hasattr(msg, "ack"):
                                try:
                                    await msg.ack()
                                except Exception:
                                    pass
                            continue
                        except Exception as e:
                            logger.error("Failed to process message: %s", e, exc_info=True)
                            self.error_count += 1
                            if hasattr(msg, "nak"):
                                try:
                                    await msg.nak()
                                except Exception:
                                    pass
                            continue
                        if hasattr(msg, "ack"):
                            try:
                                await msg.ack()
                            except Exception:
                                pass
                    finally:
                        self._in_flight -= 1
                consecutive_failures = 0
            except nats.errors.TimeoutError:
                # No messages available — this is normal
                consecutive_failures = 0
            except Exception as e:
                logger.error(f"Fetch error: {e}")
                self.error_count += 1
                backoff = min(2**consecutive_failures, 60)
                jitter = random.uniform(0, 1)
                await asyncio.sleep(backoff + jitter)
                consecutive_failures += 1

    async def _on_message_push(self, msg):
        """Callback for push subscribe (JetStream or plain NATS)."""
        try:
            await self._process_message(msg)
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            # Permanently malformed — ACK to discard (retry won't fix it)
            logger.warning("Permanently malformed message, discarding: %s", e)
            if hasattr(msg, "ack"):
                try:
                    await msg.ack()
                except Exception:
                    pass
            return
        except Exception as e:
            logger.error("Failed to process message: %s", e)
            # NAK so JetStream redelivers the message
            if hasattr(msg, "nak"):
                try:
                    await msg.nak()
                except Exception:
                    pass
            return
        # Only acknowledge on successful processing
        if hasattr(msg, "ack"):
            try:
                await msg.ack()
            except Exception:
                logger.debug("Message ack failed (likely plain NATS)")

    async def _process_message(self, msg):
        """Parse, enrich, store, and republish a single event."""
        if len(msg.data) > 10_000_000:  # 10 MB — reject oversized messages
            logger.warning("Rejecting oversized NATS message: %d bytes", len(msg.data))
            self.error_count += 1
            if hasattr(msg, "ack"):
                await msg.ack()  # discard permanently — retrying won't fix size
            return
        try:
            raw = json.loads(msg.data.decode())
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            logger.warning("Invalid JSON/encoding on %s: %s", msg.subject, e)
            self.error_count += 1
            raise  # Let caller (push/pull loop) handle ACK/NAK

        event_id = raw.get("event_id", str(uuid.uuid4()))

        # Parse timestamp — asyncpg needs a UTC-aware datetime object
        ts_raw = raw.get("timestamp")
        if isinstance(ts_raw, str):
            try:
                timestamp = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
            except ValueError:
                timestamp = datetime.now(UTC)
            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=UTC)
        elif isinstance(ts_raw, datetime):
            timestamp = ts_raw
            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=UTC)
        elif isinstance(ts_raw, int | float):
            # Unix timestamp — handle both seconds and milliseconds
            if ts_raw > 1e12:  # milliseconds
                ts_raw = ts_raw / 1000.0
            try:
                timestamp = datetime.fromtimestamp(ts_raw, tz=UTC)
            except (OverflowError, ValueError, OSError):
                logger.warning(f"Invalid numeric timestamp: {ts_raw}")
                timestamp = datetime.now(UTC)
        else:
            timestamp = datetime.now(UTC)

        # Match fields the SSH decoy actually publishes
        source = raw.get("source", {})
        if not isinstance(source, dict):
            source = {}
        decoy_name = raw.get("decoy_name", source.get("decoy", "unknown"))

        # Validate event source matches NATS subject to detect spoofing
        subject_parts = msg.subject.split(".")
        if len(subject_parts) >= 4:
            subject_decoy = subject_parts[3]  # cicdecoy.decoy.events.{decoy_name}...
            if subject_decoy != decoy_name and decoy_name != "unknown":
                logger.warning(
                    f"Event source mismatch: subject says '{subject_decoy}' "
                    f"but payload claims '{decoy_name}' — possible spoofing"
                )
                self.error_count += 1
                if hasattr(msg, "ack"):
                    await msg.ack()  # spoofed events should be discarded
                return  # Reject the event
        raw_tier = raw.get("decoy_tier", source.get("tier", 0))
        try:
            decoy_tier = int(raw_tier) if raw_tier is not None else 0
        except (ValueError, TypeError):
            decoy_tier = 0
        session_id = raw.get("session_id", "")
        event_type = raw.get("event_type", "unknown")
        data = raw.get("data", raw)
        if not isinstance(data, dict):
            data = {"raw": str(data)[:4096]} if data else {}

        source_ip = data.get("client_ip", raw.get("source_ip", ""))
        raw_port = data.get("client_port", raw.get("source_port", 0))
        try:
            source_port = int(raw_port) if raw_port else 0
        except (ValueError, TypeError):
            source_port = 0

        # Also resolve username from where the decoy puts it
        username = data.get("username") or data.get("user") or raw.get("username") or raw.get("user") or ""

        # ── Enrich: classify command into MITRE techniques ──
        _enrich_start = time.time()
        try:
            enrichment = enrich_event(raw)
        except Exception as e:
            logger.error("Enrichment failed for event %s: %s", event_id, e)
            self.error_count += 1
            enrichment = {
                "mitre_techniques": [],
                "tool_signatures": [],
                "severity": "unknown",
                "tags": [],
                "geo": {},
            }
        ENRICHMENT_LATENCY.observe(time.time() - _enrich_start)

        # ── Session-level analysis (non-fatal — event already persisted below) ──
        session_verdict = None
        if session_id:
            # Build a combined payload for the session analyzer
            analysis_input = {
                "event_type": event_type,
                "mitre_techniques": enrichment.get("mitre_techniques", []),
                "tool_signatures": enrichment.get("tool_signatures", []),
                "severity": enrichment.get("severity", "unknown"),
                "tags": enrichment.get("tags", []),
                "data": data if isinstance(data, dict) else {},
            }

            try:
                if event_type == "session.end":
                    # Ingest the final event before closing, so it's included
                    # in the session state
                    await self.session_analyzer.ingest(session_id, analysis_input)
                    session_verdict = await self.session_analyzer.close_session(session_id)
                    if session_verdict:
                        logger.info(
                            f"Session {session_id[:12]} closed: "
                            f"classification={session_verdict.get('classification')} "
                            f"score={session_verdict.get('behavioral_score', 0):.2f} "
                            f"phases={session_verdict.get('phase_count', 0)}"
                        )
                        # Enrich with MITRE Engage outcomes
                        engage_input = {
                            "session_id": session_verdict["session_id"],
                            "decoy_name": decoy_name,
                            "decoy_tier": decoy_tier,
                            "duration_seconds": session_verdict.get("duration_seconds", 0),
                            "command_count": session_verdict.get("command_count", 0),
                            "mitre_techniques": session_verdict.get("techniques_observed", []),
                            "tools_detected": session_verdict.get("tool_signatures", []),
                            "honeytokens_accessed": session_verdict.get("honeytokens_accessed", []),
                            "credentials_captured": [],
                            "alerts": [],
                        }
                        engage_outcome = self.engage_enricher.enrich_session(engage_input)
                        await self._write_session_summary(session_verdict, engage_outcome)
                else:
                    session_verdict = await self.session_analyzer.ingest(session_id, analysis_input)

                    # Persist any LRU-evicted sessions
                    for evicted in await self.session_analyzer.drain_evicted():
                        logger.info(f"LRU-evicted session persisted: {evicted['session_id'][:12]}")
                        await self._write_session_summary(evicted)

                    # Publish any alert triggers
                    for alert in session_verdict.get("alert_triggers", []):
                        try:
                            await self.nc.publish(
                                f"cicdecoy.alert.session.{_sanitize_nats_subject(alert.get('alert_type', 'unknown'))}",
                                json.dumps(alert, default=str).encode(),
                            )
                            logger.warning(
                                f"Session alert: {alert['alert_type']} "
                                f"session={session_id[:12]} "
                                f"severity={alert.get('severity')}"
                            )
                        except Exception as e:
                            logger.warning(f"Session alert publish failed: {e}")
            except Exception as e:
                logger.error(
                    "Session analysis/enrichment failed for session=%s event_type=%s: %s",
                    session_id,
                    event_type,
                    e,
                    exc_info=True,
                )
                self.error_count += 1
                EVENTS_ERRORS.labels(error_type=_sanitize_label("session_analysis")).inc()
                # Continue — event will still be persisted to DB below

            ACTIVE_SESSIONS.set(len(self.session_analyzer._sessions))

        # Insert into TimescaleDB with enrichment data
        try:
            async with self.pool.acquire(timeout=10.0) as conn:
                await conn.execute(
                    """
                    INSERT INTO decoy_events (
                        event_id, timestamp, decoy_name, decoy_tier,
                        session_id, event_type, source_ip, source_port,
                        severity, mitre_techniques, tool_signatures,
                        tags, geo, raw_data
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
                    ON CONFLICT (event_id, timestamp) DO NOTHING
                """,
                    event_id,
                    timestamp,
                    decoy_name,
                    decoy_tier,
                    session_id,
                    event_type,
                    source_ip if source_ip else None,
                    source_port,
                    enrichment["severity"],
                    json.dumps(enrichment["mitre_techniques"]),
                    json.dumps(enrichment["tool_signatures"]),
                    json.dumps(enrichment["tags"]),
                    json.dumps(enrichment.get("geo", {})),
                    json.dumps(data),
                )

            self.event_count += 1
            EVENTS_PROCESSED.labels(event_type=_sanitize_label(event_type)).inc()

            # Log enriched events at DEBUG, periodic summary at INFO
            if enrichment["mitre_techniques"]:
                techs = ", ".join(t["technique_id"] for t in enrichment["mitre_techniques"])
                logger.debug("Enriched event %s: severity=%s techniques=[%s]", event_id, enrichment["severity"], techs)

            if self.event_count % 100 == 0:
                logger.info("Events stored: %d (errors: %d)", self.event_count, self.error_count)

        except Exception as e:
            logger.error(f"DB insert failed: {e}")
            self.error_count += 1
            EVENTS_ERRORS.labels(error_type=_sanitize_label("db_insert")).inc()

        # ── Republish enriched event for dashboard SSE feed ──
        # The dashboard subscribes to cicdecoy.enriched.events.>
        # so it receives pre-enriched events with no inline processing.
        # Skip healthcheck noise (Docker healthcheck hits SSH on 127.0.0.1)
        if source_ip in ("127.0.0.1", "::1"):
            if hasattr(msg, "ack"):
                await msg.ack()  # healthcheck noise — discard
            return

        enriched_event = {
            "event_id": event_id,
            "timestamp": timestamp.isoformat(),
            "decoy_name": decoy_name,
            "decoy_tier": decoy_tier,
            "session_id": session_id,
            "event_type": event_type,
            "source_ip": source_ip,
            "source_port": source_port,
            "username": username,
            "severity": enrichment.get("severity", "info"),
            "mitre_techniques": enrichment.get("mitre_techniques", []),
            "tool_signatures": enrichment.get("tool_signatures", []),
            "tags": enrichment.get("tags", []),
            "geo": enrichment.get("geo", {}),
            "session_analysis": session_verdict if session_verdict else {},
            "data": data if isinstance(data, dict) else {},
            "raw_data": data if isinstance(data, dict) else {},
        }

        try:
            await self.nc.publish(
                f"cicdecoy.enriched.events.{_sanitize_nats_subject(event_type)}",
                json.dumps(enriched_event, default=str).encode(),
            )
        except Exception as e:
            # Non-fatal — dashboard just won't see this event live
            logger.debug("Enriched republish failed: %s", e)

        # ── Forward high-severity alerts to external webhooks ──
        if self.alert_forwarder.enabled:
            try:
                await self.alert_forwarder.maybe_send(enriched_event)
            except Exception as e:
                logger.debug("Alert forwarding failed: %s", e)

        # ── Cross-decoy canary credential correlation ──
        if self._canary_credentials and event_type in ("auth.success", "auth.attempt", "auth.failure"):
            pw_hash = data.get("password_hash") or data.get("password_sha256") or ""
            if username and pw_hash and (username, pw_hash) in self._canary_credentials:
                reuse_event = {
                    "event_id": str(uuid.uuid4()),
                    "timestamp": datetime.now(UTC).isoformat(),
                    "event_type": "honeytoken.credential_reuse",
                    "decoy_name": decoy_name,
                    "decoy_tier": decoy_tier,
                    "session_id": session_id,
                    "source_ip": source_ip,
                    "source_port": source_port,
                    "severity": "critical",
                    "data": {
                        "username": username,
                        "password_hash": pw_hash,
                        "original_event_type": event_type,
                        "original_event_id": event_id,
                    },
                }
                logger.warning(
                    "Canary credential reuse detected: user=%s on decoy=%s from %s",
                    username,
                    decoy_name,
                    source_ip,
                )
                try:
                    subject = f"cicdecoy.honeytoken.credential_reuse.{_sanitize_nats_subject(decoy_name)}"
                    payload = json.dumps(reuse_event, default=str).encode()
                    try:
                        await self.js.publish(subject, payload)
                    except Exception:
                        await self.nc.publish(subject, payload)  # fallback to core NATS
                except Exception as e:
                    logger.debug("Canary credential reuse publish failed: %s", e)

                # Persist credential reuse event to database
                try:
                    reuse_ts = datetime.fromisoformat(reuse_event["timestamp"])
                    async with self.pool.acquire(timeout=10.0) as conn:
                        await conn.execute(
                            """
                            INSERT INTO decoy_events (
                                event_id, timestamp, decoy_name, decoy_tier,
                                session_id, event_type, source_ip, source_port,
                                severity, mitre_techniques, tool_signatures,
                                tags, geo, raw_data
                            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
                            ON CONFLICT (event_id, timestamp) DO NOTHING
                        """,
                            reuse_event["event_id"],
                            reuse_ts,
                            reuse_event.get("decoy_name", ""),
                            0,  # tier not applicable for cross-decoy events
                            reuse_event.get("session_id", ""),
                            reuse_event["event_type"],
                            source_ip if source_ip else None,
                            0,  # source_port not applicable
                            reuse_event.get("severity", "critical"),
                            json.dumps([]),
                            json.dumps([]),
                            json.dumps([]),
                            json.dumps({}),
                            json.dumps(reuse_event.get("data", {})),
                        )
                except Exception as e:
                    logger.warning("Failed to persist credential reuse event: %s", e)

    async def _ensure_streams(self):
        """Create JetStream streams if they don't exist (idempotent)."""
        from nats.js.api import StreamConfig

        # nats.py StreamConfig.max_age is in seconds (float);
        # the library converts to nanoseconds internally.
        streams = [
            # DECOY_EVENTS first — it is the primary pipeline stream and
            # must be created before anything else consumes the JetStream
            # storage budget (default JetStream max_storage is 2 GB).
            StreamConfig(
                name="DECOY_EVENTS", subjects=["cicdecoy.decoy.events.>"], max_age=72 * 3600, max_bytes=268435456
            ),  # 256 MB
            StreamConfig(
                name="ENRICHED_EVENTS", subjects=["cicdecoy.enriched.events.>"], max_age=72 * 3600, max_bytes=268435456
            ),  # 256 MB
            StreamConfig(
                name="ALERTS", subjects=["cicdecoy.alert.>"], max_age=168 * 3600, max_bytes=134217728
            ),  # 128 MB
            StreamConfig(
                name="FALCO_ALERTS", subjects=["cicdecoy.security.falco.>"], max_age=720 * 3600, max_bytes=134217728
            ),  # 128 MB
            StreamConfig(
                name="HONEYTOKEN_EVENTS", subjects=["cicdecoy.honeytoken.>"], max_age=720 * 3600, max_bytes=134217728
            ),  # 128 MB, 30 days
        ]
        for cfg in streams:
            try:
                await self.js.add_stream(cfg)
                logger.info("JetStream stream ensured: %s", cfg.name)
            except Exception as e:
                logger.warning("Failed to create stream %s: %s", cfg.name, e)

    async def _verify_schema(self):
        """Check that the events table exists."""
        async with self.pool.acquire(timeout=10.0) as conn:
            exists = await conn.fetchval("""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables
                    WHERE table_name = 'decoy_events'
                )
            """)
            if not exists:
                logger.error("Table 'decoy_events' does not exist! " "Run schema.sql against the database first.")
                raise RuntimeError("Database schema not initialized")
            logger.info("Database schema verified")

    async def _write_session_summary(self, summary: dict, engage_outcome=None):
        """Write session analysis to engage_outcomes on session close."""
        try:
            async with self.pool.acquire(timeout=10.0) as conn:
                await conn.execute(
                    """
                    INSERT INTO engage_outcomes (
                        session_id, decoy_name, engagement_duration, commands_captured,
                        ttps_observed, intelligence_value, activities, approaches, goals
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                    ON CONFLICT (session_id) DO UPDATE SET
                        decoy_name = EXCLUDED.decoy_name,
                        engagement_duration = EXCLUDED.engagement_duration,
                        commands_captured = EXCLUDED.commands_captured,
                        ttps_observed = EXCLUDED.ttps_observed,
                        intelligence_value = EXCLUDED.intelligence_value,
                        activities = EXCLUDED.activities,
                        approaches = EXCLUDED.approaches,
                        goals = EXCLUDED.goals
                """,
                    summary["session_id"],
                    summary.get("decoy_name", "unknown"),
                    summary.get("duration_seconds", 0),
                    summary.get("command_count", 0),
                    len(summary.get("techniques_observed", [])),
                    engage_outcome.intelligence_value if engage_outcome else summary.get("classification", "unknown"),
                    json.dumps(engage_outcome.activities_exercised) if engage_outcome else json.dumps([]),
                    json.dumps(engage_outcome.approaches_demonstrated) if engage_outcome else json.dumps([]),
                    json.dumps(engage_outcome.goals_achieved) if engage_outcome else json.dumps([]),
                )
        except Exception as e:
            self.error_count += 1
            logger.error(
                "Session summary write failed for %s: %s — full verdict for recovery: %s",
                summary.get("session_id", "unknown"),
                e,
                json.dumps(summary, default=str),
            )

    async def stop(self):
        self._shutting_down = True
        # Wait for in-flight messages to complete (max 10 seconds)
        for _ in range(100):
            if self._in_flight <= 0:
                break
            await asyncio.sleep(0.1)
        try:
            if self.alert_forwarder:
                await self.alert_forwarder.close()
        except Exception as e:
            logger.warning(f"Error closing alert forwarder: {e}")
        try:
            if self.nc:
                await self.nc.drain()
        except Exception as e:
            logger.warning(f"Error draining NATS: {e}")
        try:
            if self.pool:
                await self.pool.close()
        except Exception as e:
            logger.warning(f"Error closing DB pool: {e}")
        logger.info(f"Collector stopped. " f"Total events: {self.event_count}, errors: {self.error_count}")


async def _sweep_idle_sessions(collector):
    """Periodic task to evict idle sessions. Run every 60 seconds."""
    while True:
        await asyncio.sleep(60)
        summaries = await collector.session_analyzer.sweep_idle()
        for summary in summaries:
            logger.info(
                f"Idle session evicted: {summary['session_id'][:12]} "
                f"classification={summary.get('classification')} "
                f"commands={summary.get('command_count')}"
            )
            try:
                await collector._write_session_summary(summary)
            except Exception as e:
                logger.error(
                    "Failed to persist idle-evicted session %s: %s — full verdict for recovery: %s",
                    summary.get("session_id", "unknown"),
                    e,
                    json.dumps(summary, default=str),
                )
        ACTIVE_SESSIONS.set(len(collector.session_analyzer._sessions))


async def _track_consumer_lag(collector):
    """Periodically update NATS consumer lag gauge."""
    while True:
        await asyncio.sleep(30)
        try:
            if collector.js:
                for consumer_name in ("cti-collector", "cti-collector-push"):
                    try:
                        info = await collector.js.consumer_info("DECOY_EVENTS", consumer_name)
                        NATS_CONSUMER_LAG.labels(consumer=consumer_name).set(info.num_pending)
                        break
                    except Exception:
                        continue
        except Exception as e:
            logger.debug(f"Consumer lag check failed: {e}")


async def main():
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        stream=sys.stdout,
    )

    nats_url = os.environ.get("NATS_URL", "nats://localhost:4222")
    db_dsn = os.environ.get("DB_DSN", "postgresql://cicdecoy:cicdecoy@localhost:5432/cicdecoy")

    collector = Collector(nats_url, db_dsn)

    # Start Prometheus metrics server on port 9090
    try:
        metrics_port = int(os.environ.get("METRICS_PORT", "9090"))
    except (ValueError, TypeError):
        logger.warning("Invalid METRICS_PORT env var, using default 9090")
        metrics_port = 9090
    start_http_server(metrics_port)
    logger.info(f"Prometheus metrics server on :{metrics_port}")

    # Graceful shutdown
    shutdown = asyncio.Event()

    loop = asyncio.get_event_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, shutdown.set)

    # Run collector in background
    task = asyncio.create_task(collector.start())

    # Start Falco correlator (subscribes to cicdecoy.security.falco.>)
    falco_task = asyncio.create_task(run_falco_correlator(nats_url, db_dsn))

    # Start idle session sweeper
    sweep_task = asyncio.create_task(_sweep_idle_sessions(collector))

    # Start NATS consumer lag tracker
    lag_task = asyncio.create_task(_track_consumer_lag(collector))

    # Wait for shutdown signal
    await shutdown.wait()

    logger.info("Shutting down...")

    # Cancel non-critical background tasks immediately
    sweep_task.cancel()
    lag_task.cancel()
    try:
        await sweep_task
    except asyncio.CancelledError:
        pass
    try:
        await lag_task
    except asyncio.CancelledError:
        pass

    # Give main tasks a deadline to drain in-flight messages before forcing cancel
    try:
        await asyncio.wait_for(
            asyncio.gather(task, falco_task, return_exceptions=True),
            timeout=30.0,
        )
    except TimeoutError:
        logger.warning("Graceful shutdown timeout, forcing cancellation")
        task.cancel()
        falco_task.cancel()
        await asyncio.gather(task, falco_task, return_exceptions=True)

    await collector.stop()


async def run_falco_correlator(nats_url: str, db_dsn: str):
    """Subscribe to Falco alerts and correlate with decoy sessions."""
    pool = None
    nc = None
    sub = None
    try:
        pool = await asyncpg.create_pool(db_dsn, min_size=1, max_size=3)
        nc = await nats.connect(nats_url, max_reconnect_attempts=10)
        correlator = FalcoCorrelator(pool)

        async def on_falco_alert(msg):
            try:
                data = json.loads(msg.data.decode())
                rule = data.get("rule", "unknown")
                priority = data.get("priority", "unknown")
                FALCO_ALERTS.labels(rule=_sanitize_label(rule), priority=_sanitize_label(priority)).inc()
                prev_correlated = correlator.correlated_count
                await correlator.process_alert(data)
                if correlator.correlated_count > prev_correlated:
                    FALCO_CORRELATED.inc()
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                logger.warning("Malformed Falco alert (bad JSON/encoding): %s", e)
                if hasattr(msg, "ack"):
                    try:
                        await msg.ack()
                    except Exception:
                        pass
                return
            except Exception as e:
                logger.error("Falco alert processing error: %s", e)
                if hasattr(msg, "nak"):
                    try:
                        await msg.nak()
                    except Exception:
                        pass
                return

        # Try JetStream durable subscribe first, fall back to plain NATS
        try:
            js = nc.jetstream()
            sub = await js.subscribe(
                "cicdecoy.security.falco.>",
                durable="falco-correlator",
                stream="FALCO_ALERTS",
                cb=on_falco_alert,
            )
            logger.info("Falco correlator subscribed via JetStream (durable)")
        except Exception:
            sub = await nc.subscribe("cicdecoy.security.falco.>", cb=on_falco_alert)
            logger.info("Falco correlator subscribed via plain NATS (non-durable)")

        # Keep alive
        while True:
            await asyncio.sleep(60)
            stats = correlator.stats
            if stats["total_alerts"] > 0:
                logger.info(
                    f"Falco stats: {stats['total_alerts']} alerts, "
                    f"{stats['correlated']} correlated "
                    f"({stats['correlation_rate']}%)"
                )

    except asyncio.CancelledError:
        logger.info("Falco correlator stopped")
        raise
    except Exception as e:
        logger.warning(f"Falco correlator not running: {e} " "(this is normal if Falco is not deployed)")
    finally:
        if nc is not None and sub is not None:
            try:
                await sub.unsubscribe()
            except Exception:
                logger.debug("Failed to unsubscribe from NATS")
            try:
                await nc.drain()
            except Exception:
                logger.debug("Failed to drain NATS connection")
        if pool is not None:
            try:
                await pool.close()
            except Exception:
                logger.debug("Failed to close connection pool")


if __name__ == "__main__":
    asyncio.run(main())
