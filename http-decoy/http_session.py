"""
CI/CDecoy — HTTP Session Tracking

Tracks attacker sessions via signed cookies using itsdangerous.
Each session records source IP, user-agent, request count, and
any credentials submitted through login portals.
"""

import uuid
from datetime import datetime, timezone

from fastapi import Request, Response
from itsdangerous import BadSignature, URLSafeSerializer

COOKIE_NAME = "_sess"
COOKIE_MAX_AGE = 86400  # 24 hours


class SessionTracker:
    """Track attacker sessions via signed cookies."""

    def __init__(self, secret: str):
        self._signer = URLSafeSerializer(secret)
        self._sessions: dict[str, dict] = {}

    def get_or_create_session(self, request: Request) -> tuple[str, dict]:
        """Return (session_id, session_data). Creates new if none exists."""
        session_id = self._extract_session_id(request)

        if session_id and session_id in self._sessions:
            return session_id, self._sessions[session_id]

        # Create a new session
        session_id = uuid.uuid4().hex[:12]

        # Extract source IP: X-Forwarded-For first, then client.host
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            source_ip = forwarded.split(",")[0].strip()
        else:
            source_ip = request.client.host if request.client else "unknown"

        session_data = {
            "session_id": session_id,
            "source_ip": source_ip,
            "user_agent": request.headers.get("user-agent", ""),
            "started": datetime.now(timezone.utc).isoformat(),
            "requests": 0,
            "credentials_submitted": [],
        }
        self._sessions[session_id] = session_data
        return session_id, session_data

    def set_cookie(self, response: Response, session_id: str) -> Response:
        """Set the session cookie on the response."""
        signed = self._signer.dumps(session_id)
        response.set_cookie(
            key=COOKIE_NAME,
            value=signed,
            max_age=COOKIE_MAX_AGE,
            httponly=True,
            samesite="lax",
            path="/",
        )
        return response

    def record_credential(self, session_id: str, username: str, password: str, portal: str):
        """Record a credential submission for the given session."""
        session = self._sessions.get(session_id)
        if session is None:
            return
        session["credentials_submitted"].append({
            "username": username,
            "password": password,
            "portal": portal,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    def record_request(self, session_id: str):
        """Increment the request counter for a session."""
        session = self._sessions.get(session_id)
        if session is not None:
            session["requests"] += 1

    @property
    def active_sessions(self) -> int:
        """Return the number of tracked sessions."""
        return len(self._sessions)

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
