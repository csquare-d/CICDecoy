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
import json
import logging
import os
import signal
import sys
import time
import uuid
from datetime import datetime, timezone

import asyncpg
import nats
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


class Collector:
    """Minimal event collector: NATS → TimescaleDB."""

    def __init__(self, nats_url: str, db_dsn: str):
        self.nats_url = nats_url
        self.db_dsn = db_dsn
        self.nc = None
        self.js = None
        self.pool = None
        self.event_count = 0
        self.error_count = 0
        self.session_analyzer = SessionAnalyzer()

    async def start(self):
        """Connect to NATS and DB, start consuming."""
        # Connect to TimescaleDB
        logger.info(f"Connecting to TimescaleDB: {self.db_dsn.split('@')[1] if '@' in self.db_dsn else self.db_dsn}")
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
        self.nc = await nats.connect(
            self.nats_url,
            reconnect_time_wait=2,
            max_reconnect_attempts=-1,  # Retry forever
        )
        self.js = self.nc.jetstream()
        logger.info("NATS connected")

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
            # Fall back to simple subscribe if JetStream isn't configured
            sub = await self.nc.subscribe(
                "cicdecoy.decoy.events.>",
                cb=self._on_message_push,
            )
            logger.info("Subscribed via simple NATS subscribe (no JetStream)")
            return  # Push subscribe handles its own loop

        # Pull loop
        logger.info("Starting event collection loop")
        while True:
            try:
                messages = await sub.fetch(batch=100, timeout=5)
                for msg in messages:
                    await self._process_message(msg)
                    await msg.ack()
            except nats.errors.TimeoutError:
                # No messages available — this is normal
                pass
            except Exception as e:
                logger.error(f"Fetch error: {e}")
                self.error_count += 1
                await asyncio.sleep(1)

    async def _on_message_push(self, msg):
        """Callback for simple (non-JetStream) subscribe."""
        await self._process_message(msg)

    async def _process_message(self, msg):
        """Parse, enrich, store, and republish a single event."""
        try:
            raw = json.loads(msg.data.decode())
        except json.JSONDecodeError:
            logger.warning(f"Invalid JSON on {msg.subject}")
            self.error_count += 1
            return

        event_id = raw.get("event_id", str(uuid.uuid4()))

        # Parse timestamp — asyncpg needs a UTC-aware datetime object
        ts_raw = raw.get("timestamp")
        if isinstance(ts_raw, str):
            try:
                timestamp = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
            except ValueError:
                timestamp = datetime.now(timezone.utc)
            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=timezone.utc)
        elif isinstance(ts_raw, datetime):
            timestamp = ts_raw
            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=timezone.utc)
        else:
            timestamp = datetime.now(timezone.utc)

        # Match fields the SSH decoy actually publishes
        decoy_name = raw.get("decoy_name", raw.get("source", {}).get("decoy", "unknown"))
        decoy_tier = raw.get("decoy_tier", raw.get("source", {}).get("tier", 0))
        session_id = raw.get("session_id", "")
        event_type = raw.get("event_type", "unknown")
        data = raw.get("data", raw)

        source_ip = data.get("client_ip", raw.get("source_ip", ""))
        source_port = data.get("client_port", raw.get("source_port", 0))

        # Also resolve username from where the decoy puts it
        username = (
            data.get("username")
            or data.get("user")
            or raw.get("username")
            or raw.get("user")
            or ""
        )

        # ── Enrich: classify command into MITRE techniques ──
        _enrich_start = time.time()
        enrichment = enrich_event(raw)
        ENRICHMENT_LATENCY.observe(time.time() - _enrich_start)

        # ── Session-level analysis ──
        session_verdict = None
        if session_id:
            # Build a combined payload for the session analyzer
            analysis_input = {
                "event_type": event_type,
                "mitre_techniques": enrichment["mitre_techniques"],
                "tool_signatures": enrichment["tool_signatures"],
                "severity": enrichment["severity"],
                "tags": enrichment.get("tags", []),
                "data": data if isinstance(data, dict) else {},
            }

            if event_type == "session.end":
                session_verdict = self.session_analyzer.close_session(session_id)
                if session_verdict:
                    logger.info(
                        f"Session {session_id[:8]} closed: "
                        f"classification={session_verdict.get('classification')} "
                        f"score={session_verdict.get('behavioral_score', 0):.2f} "
                        f"phases={session_verdict.get('phase_count', 0)}"
                    )
                    await self._write_session_summary(session_verdict)
            else:
                session_verdict = self.session_analyzer.ingest(session_id, analysis_input)

                # Publish any alert triggers
                for alert in session_verdict.get("alert_triggers", []):
                    try:
                        await self.nc.publish(
                            f"cicdecoy.alert.session.{alert.get('alert_type', 'unknown')}",
                            json.dumps(alert, default=str).encode(),
                        )
                        logger.warning(
                            f"Session alert: {alert['alert_type']} "
                            f"session={session_id[:8]} "
                            f"severity={alert.get('severity')}"
                        )
                    except Exception as e:
                        logger.warning(f"Session alert publish failed: {e}")

            ACTIVE_SESSIONS.set(len(self.session_analyzer._sessions))

        # Insert into TimescaleDB with enrichment data
        try:
            async with self.pool.acquire() as conn:
                await conn.execute("""
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
            EVENTS_PROCESSED.labels(event_type=event_type).inc()

            # Log enriched events at DEBUG, periodic summary at INFO
            if enrichment["mitre_techniques"]:
                techs = ", ".join(t["technique_id"] for t in enrichment["mitre_techniques"])
                logger.debug(
                    f"Enriched event {event_id}: "
                    f"severity={enrichment['severity']} techniques=[{techs}]"
                )

            if self.event_count % 100 == 0:
                logger.info(f"Events stored: {self.event_count} (errors: {self.error_count})")

        except Exception as e:
            logger.error(f"DB insert failed: {e}")
            self.error_count += 1
            EVENTS_ERRORS.labels(error_type="db_insert").inc()

        # ── Republish enriched event for dashboard SSE feed ──
        # The dashboard subscribes to cicdecoy.enriched.events.>
        # so it receives pre-enriched events with no inline processing.
        # Skip healthcheck noise (Docker healthcheck hits SSH on 127.0.0.1)
        if source_ip in ("127.0.0.1", "::1"):
            return

        try:
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
                "severity": enrichment["severity"],
                "mitre_techniques": enrichment["mitre_techniques"],
                "tool_signatures": enrichment["tool_signatures"],
                "tags": enrichment["tags"],
                "geo": enrichment.get("geo", {}),
                "session_analysis": session_verdict if session_verdict else {},
                "data": data if isinstance(data, dict) else {},
                "raw_data": data if isinstance(data, dict) else {},
            }

            await self.nc.publish(
                f"cicdecoy.enriched.events.{event_type}",
                json.dumps(enriched_event, default=str).encode(),
            )
        except Exception as e:
            # Non-fatal — dashboard just won't see this event live
            logger.debug(f"Enriched republish failed: {e}")

    async def _verify_schema(self):
        """Check that the events table exists."""
        async with self.pool.acquire() as conn:
            exists = await conn.fetchval("""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables
                    WHERE table_name = 'decoy_events'
                )
            """)
            if not exists:
                logger.error(
                    "Table 'decoy_events' does not exist! "
                    "Run schema.sql against the database first."
                )
                raise RuntimeError("Database schema not initialized")
            logger.info("Database schema verified")

    async def _write_session_summary(self, summary: dict):
        """Write session analysis to engage_outcomes on session close."""
        try:
            async with self.pool.acquire() as conn:
                await conn.execute("""
                    INSERT INTO engage_outcomes (
                        session_id, engagement_duration, commands_captured,
                        ttps_observed, intelligence_value, activities
                    ) VALUES ($1, $2, $3, $4, $5, $6)
                    ON CONFLICT (session_id) DO UPDATE SET
                        engagement_duration = EXCLUDED.engagement_duration,
                        commands_captured = EXCLUDED.commands_captured,
                        ttps_observed = EXCLUDED.ttps_observed,
                        intelligence_value = EXCLUDED.intelligence_value,
                        activities = EXCLUDED.activities
                """,
                    summary["session_id"],
                    summary.get("duration_seconds", 0),
                    summary.get("command_count", 0),
                    len(summary.get("techniques_observed", [])),
                    summary.get("classification", "unknown"),
                    json.dumps({
                        "phases": summary.get("phases_seen", []),
                        "tools": summary.get("tool_signatures", []),
                        "behavioral_score": summary.get("behavioral_score", 0),
                        "kill_chain": summary.get("kill_chain", False),
                    }),
                )
        except Exception as e:
            logger.error(f"Session summary write failed: {e}")

    async def stop(self):
        if self.nc:
            await self.nc.drain()
        if self.pool:
            await self.pool.close()
        logger.info(
            f"Collector stopped. "
            f"Total events: {self.event_count}, errors: {self.error_count}"
        )


async def _sweep_idle_sessions(collector):
    """Periodic task to evict idle sessions. Run every 60 seconds."""
    while True:
        await asyncio.sleep(60)
        summaries = collector.session_analyzer.sweep_idle()
        for summary in summaries:
            logger.info(
                f"Idle session evicted: {summary['session_id'][:8]} "
                f"classification={summary.get('classification')} "
                f"commands={summary.get('command_count')}"
            )
            await collector._write_session_summary(summary)
        ACTIVE_SESSIONS.set(len(collector.session_analyzer._sessions))


async def _track_consumer_lag(collector):
    """Periodically update NATS consumer lag gauge."""
    while True:
        await asyncio.sleep(30)
        try:
            if collector.js:
                info = await collector.js.consumer_info("DECOY_EVENTS", "cti-collector")
                pending = info.num_pending
                NATS_CONSUMER_LAG.labels(consumer="cti-collector").set(pending)
        except Exception as e:
            logger.debug(f"Consumer lag check failed: {e}")


async def main():
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        stream=sys.stdout,
    )

    nats_url = os.environ.get("NATS_URL", "nats://localhost:4222")
    db_dsn = os.environ.get("DB_DSN",
        "postgresql://cicdecoy:cicdecoy@localhost:5432/cicdecoy")

    collector = Collector(nats_url, db_dsn)

    # Start Prometheus metrics server on port 9090
    metrics_port = int(os.environ.get("METRICS_PORT", "9090"))
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
    falco_task = asyncio.create_task(
        run_falco_correlator(nats_url, db_dsn)
    )

    # Start idle session sweeper
    sweep_task = asyncio.create_task(_sweep_idle_sessions(collector))

    # Start NATS consumer lag tracker
    lag_task = asyncio.create_task(_track_consumer_lag(collector))

    # Wait for shutdown signal
    await shutdown.wait()

    logger.info("Shutting down...")
    task.cancel()
    falco_task.cancel()
    sweep_task.cancel()
    lag_task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    try:
        await falco_task
    except asyncio.CancelledError:
        pass
    try:
        await sweep_task
    except asyncio.CancelledError:
        pass
    try:
        await lag_task
    except asyncio.CancelledError:
        pass
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
                FALCO_ALERTS.labels(rule=rule, priority=priority).inc()
                prev_correlated = correlator.correlated_count
                await correlator.process_alert(data)
                if correlator.correlated_count > prev_correlated:
                    FALCO_CORRELATED.inc()
            except Exception as e:
                logger.error(f"Falco alert processing error: {e}")

        sub = await nc.subscribe("cicdecoy.security.falco.>", cb=on_falco_alert)
        logger.info("Falco correlator subscribed to cicdecoy.security.falco.>")

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
        logger.warning(f"Falco correlator not running: {e} "
                       "(this is normal if Falco is not deployed)")
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
