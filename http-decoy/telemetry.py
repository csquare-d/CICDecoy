"""
CI/CDecoy — HTTP Decoy Telemetry

Publishes structured events to NATS, matching the schema expected
by cti/pipeline.py. Falls back to logging when NATS is unavailable.
"""

import json
import logging
import uuid
from datetime import datetime, timezone

import nats

from config import HttpDecoyConfig

logger = logging.getLogger("cicdecoy.http.telemetry")


class EventEmitter:
    """Emit events to NATS JetStream, matching the ssh-decoy event schema."""

    def __init__(self, config: HttpDecoyConfig):
        self.config = config
        self.nc: nats.NATS | None = None
        self.js = None
        self._connected = False

    async def connect(self):
        """Connect to NATS and obtain a JetStream context."""
        try:
            self.nc = await nats.connect(
                self.config.nats_url,
                reconnect_time_wait=2,
                max_reconnect_attempts=10,
            )
            self.js = self.nc.jetstream()
            self._connected = True
            logger.info(f"NATS JetStream connected: {self.config.nats_url}")
        except Exception as e:
            logger.warning(f"NATS connection failed: {e} — events will be logged only")
            self._connected = False

    async def emit(self, event_type: str, session_id: str, source_ip: str,
                   data: dict, severity: str = "info") -> None:
        """
        Publish event to NATS.

        Schema matches what cti/pipeline.py expects:
        {event_id, timestamp, decoy_name, decoy_tier, session_id,
         event_type, source_ip, source_port, data}
        """
        event = {
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": "1.0",
            "decoy_name": self.config.decoy_name,
            "decoy_tier": self.config.decoy_tier,
            "session_id": session_id,
            "event_type": event_type,
            "source_ip": source_ip,
            "source_port": data.get("source_port", 0),
            "severity": severity,
            "data": data,
        }

        subject = f"{self.config.nats_subject}.{self.config.decoy_name}.{event_type}"

        if self._connected and self.nc:
            payload = json.dumps(event).encode()
            try:
                if self.js:
                    # JetStream publish — server acks, dedup, at-least-once delivery
                    await self.js.publish(subject, payload)
                else:
                    # Fallback to core NATS (fire-and-forget, no delivery guarantee)
                    await self.nc.publish(subject, payload)
            except Exception as e:
                logger.warning(f"NATS publish failed: {e}")

        logger.info(f"EVENT {event_type} session={session_id[:8]} {json.dumps(data)}")

    async def close(self):
        """Drain and close the NATS connection."""
        if self.nc and self._connected:
            await self.nc.drain()
            self._connected = False
