"""
CI/CDecoy — HTTP Decoy Server

A FastAPI-based web server that mimics real web applications (nginx)
to capture attacker credentials and behavior. Tier 2 decoy.

Usage:
    HTTP_PORT=8080 uvicorn main:app --host 0.0.0.0 --port 8080
"""

import logging
import os
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from http_session import SessionTracker
from telemetry import EventEmitter

from config import HttpDecoyConfig

logger = logging.getLogger("cicdecoy.http")


# ── Configuration ─────────────────────────────────────
config = HttpDecoyConfig.from_env()


# ── Lifespan ──────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Connect to NATS on startup, drain on shutdown."""
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        stream=sys.stdout,
    )

    emitter = EventEmitter(config)
    await emitter.connect()

    sessions = SessionTracker(config.session_secret)

    # Store on app.state for route access
    app.state.config = config
    app.state.sessions = sessions
    app.state.emitter = emitter

    await emitter.emit("decoy.online", "system", "0.0.0.0", {
        "decoy_name": config.decoy_name,
        "tier": config.decoy_tier,
        "port": config.port,
        "portals": config.login_portals,
    })

    logger.info(
        f"CI/CDecoy HTTP server online: name={config.decoy_name} "
        f"tier={config.decoy_tier} port={config.port} "
        f"hostname={config.hostname} portals={config.login_portals}"
    )

    yield

    await emitter.emit("decoy.offline", "system", "0.0.0.0", {
        "decoy_name": config.decoy_name,
    })
    await emitter.close()
    logger.info("HTTP decoy server stopped")


# ── App ───────────────────────────────────────────────
app = FastAPI(
    title=config.hostname,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)


# ── Middleware ────────────────────────────────────────
@app.middleware("http")
async def decoy_middleware(request: Request, call_next):
    """Set Server header, track sessions, log requests."""
    # Get or create session
    sessions: SessionTracker = request.app.state.sessions
    session_id, session_data = sessions.get_or_create_session(request)
    sessions.record_request(session_id)

    # Store session info on request state for routes to access
    request.state.session_id = session_id
    request.state.session_data = session_data

    # Track request via metrics module (if available)
    try:
        from metrics import HTTP_REQUESTS
        HTTP_REQUESTS.labels(
            method=request.method,
            path=request.url.path,
        ).inc()
    except (ImportError, Exception):
        logger.debug("Metrics not available for request tracking")

    # Log the request
    source_ip = session_data["source_ip"]
    logger.info(
        f"{request.method} {request.url.path} "
        f"from={source_ip} session={session_id} "
        f"ua={session_data['user_agent'][:60]}"
    )

    # Emit telemetry for the request
    emitter: EventEmitter = request.app.state.emitter
    await emitter.emit("http.request", session_id, source_ip, {
        "method": request.method,
        "path": request.url.path,
        "user_agent": session_data["user_agent"],
        "headers": dict(request.headers),
    })

    # Process request
    response = await call_next(request)

    # Set Server header to look like nginx
    response.headers["Server"] = config.server_header

    # Set session cookie
    sessions.set_cookie(response, session_id)

    return response


# ── Mount Prometheus metrics ──────────────────────────
try:
    from prometheus_client import make_asgi_app
    metrics_app = make_asgi_app()
    app.mount("/metrics", metrics_app)
except ImportError:
    logger.debug("prometheus_client not available, /metrics endpoint disabled")


# ── Mount route modules ──────────────────────────────
# Each route module is created by a teammate. We use try/except so
# the app starts even if some modules aren't created yet.

try:
    from routes.login import router as login_router
    app.include_router(login_router)
    logger.debug("Mounted routes.login")
except ImportError:
    logger.debug("routes.login not available yet")

try:
    from routes.login_extra import router as login_extra_router
    app.include_router(login_extra_router)
    logger.debug("Mounted routes.login_extra")
except ImportError:
    logger.debug("routes.login_extra not available yet")

try:
    from routes.api import router as api_router
    app.include_router(api_router)
    logger.debug("Mounted routes.api")
except ImportError:
    logger.debug("routes.api not available yet")

try:
    from routes.admin import router as admin_router
    app.include_router(admin_router)
    logger.debug("Mounted routes.admin")
except ImportError:
    logger.debug("routes.admin not available yet")

try:
    from routes.discovery import router as discovery_router
    app.include_router(discovery_router)
    logger.debug("Mounted routes.discovery")
except ImportError:
    logger.debug("routes.discovery not available yet")


# ── Health check ──────────────────────────────────────
@app.get("/healthz")
async def healthz():
    """Kubernetes liveness probe."""
    return {"status": "ok"}


# ── Catch-all: nginx-style 404 ────────────────────────
NGINX_404_HTML = """<!DOCTYPE html>
<html>
<head><title>404 Not Found</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr><center>{server_header}</center>
</body>
</html>
""".strip()


@app.get("/{full_path:path}")
async def catch_all(request: Request, full_path: str):
    """Return a realistic nginx-style 404 page for unmatched routes."""
    html = NGINX_404_HTML.format(server_header=config.server_header)
    return HTMLResponse(content=html, status_code=404)
