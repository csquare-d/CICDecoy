"""
CI/CDecoy — HTTP Session Tracking

Tracks attacker sessions via signed cookies using itsdangerous.
Each session records source IP, user-agent, request count, and
any credentials submitted through login portals.
"""

import asyncio
import time
import uuid
from datetime import UTC, datetime

from fastapi import Request, Response
from itsdangerous import BadSignature, URLSafeSerializer

COOKIE_NAME = "_sess"
COOKIE_MAX_AGE = 86400  # 24 hours
MAX_SESSIONS = 10_000
SESSION_TTL = 86400  # evict sessions idle for > 24 hours


class SessionTracker:
    """Track attacker sessions via signed cookies."""

    def __init__(self, secret: str):
        self._signer = URLSafeSerializer(secret)
        self._sessions: dict[str, dict] = {}
        self._last_activity: dict[str, float] = {}
        self._created_at: dict[str, float] = {}
        self._lock = asyncio.Lock()

    async def get_or_create_session(self, request: Request) -> tuple[str, dict]:
        """Return (session_id, session_data). Creates new if none exists."""
        async with self._lock:
            # Periodically evict stale sessions to prevent memory leak
            self._evict_stale()

            session_id = self._extract_session_id(request)

            if session_id and session_id in self._sessions:
                self._last_activity[session_id] = time.monotonic()
                return session_id, self._sessions[session_id]

            # Create a new session
            session_id = uuid.uuid4().hex[:12]

            # Extract source IP: X-Forwarded-For first, then client.host
            forwarded = request.headers.get("x-forwarded-for")
            if forwarded:
                ip = forwarded.split(",")[0].strip()
                if ip:
                    source_ip = ip
                else:
                    source_ip = request.client.host if request.client else "unknown"
            else:
                source_ip = request.client.host if request.client else "unknown"

            session_data = {
                "session_id": session_id,
                "source_ip": source_ip,
                "user_agent": request.headers.get("user-agent", ""),
                "started": datetime.now(UTC).isoformat(),
                "requests": 0,
                "seen": False,
                "credentials_submitted": [],
            }
            self._sessions[session_id] = session_data
            self._last_activity[session_id] = time.monotonic()
            self._created_at[session_id] = time.monotonic()
            return session_id, session_data

    def set_cookie(self, response: Response, session_id: str) -> Response:
        """Set the session cookie on the response."""
        signed = self._signer.dumps(session_id)
        response.set_cookie(
            key=COOKIE_NAME,
            value=signed,
            max_age=COOKIE_MAX_AGE,
            httponly=True,
            secure=True,
            samesite="lax",
            path="/",
        )
        return response

    async def record_credential(self, session_id: str, username: str, password: str, portal: str):
        """Record a credential submission for the given session."""
        async with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return
            session["credentials_submitted"].append({
                "username": username,
                "password": password,
                "portal": portal,
                "timestamp": datetime.now(UTC).isoformat(),
            })

    async def mark_seen(self, session_id: str) -> bool:
        """Mark session as seen. Returns True if this was the FIRST time (was unseen)."""
        async with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return False
            if session.get("seen"):
                return False
            session["seen"] = True
            return True

    async def record_request(self, session_id: str):
        """Increment the request counter for a session."""
        async with self._lock:
            session = self._sessions.get(session_id)
            if session is not None:
                session["requests"] += 1

    @property
    def active_sessions(self) -> int:
        """Return the number of tracked sessions.

        Note: len() on dict is atomic under CPython's GIL, so no lock needed
        for this read-only property.
        """
        return len(self._sessions)

    def _evict_stale(self):
        """Remove sessions that have been idle longer than SESSION_TTL."""
        from metrics import SESSION_DURATION  # lazy import to avoid module collision in tests

        now = time.monotonic()
        stale = [
            sid for sid, last in self._last_activity.items()
            if now - last > SESSION_TTL
        ]
        for sid in stale:
            created = self._created_at.get(sid)
            if created is not None:
                SESSION_DURATION.observe(now - created)
            self._sessions.pop(sid, None)
            self._last_activity.pop(sid, None)
            self._created_at.pop(sid, None)

        # Hard cap: if still over limit, drop oldest sessions
        if len(self._sessions) > MAX_SESSIONS:
            by_age = sorted(self._last_activity, key=self._last_activity.get)
            to_drop = len(self._sessions) - MAX_SESSIONS
            for sid in by_age[:to_drop]:
                created = self._created_at.get(sid)
                if created is not None:
                    SESSION_DURATION.observe(now - created)
                self._sessions.pop(sid, None)
                self._last_activity.pop(sid, None)
                self._created_at.pop(sid, None)

    def _extract_session_id(self, request: Request) -> str | None:
        """Try to extract and verify a session ID from the request cookie."""
        cookie = request.cookies.get(COOKIE_NAME)
        if not cookie:
            return None
        try:
            session_id = self._signer.loads(cookie)
            if isinstance(session_id, str) and session_id in self._sessions:
                return session_id
        except BadSignature:
            pass
        return None
