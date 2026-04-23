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
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from http_enrichment import HttpRequestClassifier
from http_session import SessionTracker
from metrics import (
    ACTIVE_SESSIONS,
    ATTACK_TECHNIQUES,
    HTTP_REQUESTS,
    INJECTION_ATTEMPTS,
    REQUEST_LATENCY,
    SCANNER_DETECTIONS,
    SENSITIVE_PATH_PROBES,
    normalize_path_group,
)
from telemetry import EventEmitter

from config import HttpDecoyConfig

logger = logging.getLogger("cicdecoy.http")

_REDACTED_HEADERS = frozenset({
    "authorization", "cookie", "set-cookie", "x-api-key",
    "proxy-authorization", "x-csrf-token",
})


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
    classifier = HttpRequestClassifier()

    # Store on app.state for route access
    app.state.config = config
    app.state.sessions = sessions
    app.state.emitter = emitter
    app.state.classifier = classifier

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
MAX_REQUEST_BODY = 1_048_576  # 1 MB


@app.middleware("http")
async def limit_request_size(request: Request, call_next):
    """Reject requests with bodies larger than MAX_REQUEST_BODY."""
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            cl = int(content_length)
        except (ValueError, OverflowError):
            return JSONResponse(status_code=400, content={"detail": "Invalid Content-Length"})
        if cl < 0 or cl > MAX_REQUEST_BODY:
            return JSONResponse(status_code=413, content={"detail": "Request too large"})
    return await call_next(request)


@app.middleware("http")
async def decoy_middleware(request: Request, call_next):
    """Set Server header, track sessions, enrich, log, and emit telemetry."""
    start = time.time()

    # Get or create session
    sessions: SessionTracker = request.app.state.sessions
    session_id, session_data = await sessions.get_or_create_session(request)
    await sessions.record_request(session_id)
    ACTIVE_SESSIONS.set(sessions.active_sessions)

    # Store session info on request state for routes to access
    request.state.session_id = session_id
    request.state.session_data = session_data

    # Extract source info
    source_ip = session_data["source_ip"]
    source_port = request.client.port if request.client else 0

    # Run HTTP enrichment — classify path, UA, injection, method
    classifier: HttpRequestClassifier = request.app.state.classifier
    query_string = str(request.url.query) if request.url.query else ""

    # Read request body for methods that carry payloads so the classifier
    # can detect injection attacks in POST data.  Starlette caches the
    # bytes after the first read, so downstream handlers still work.
    body_text: str | None = None
    if request.method in ("POST", "PUT", "PATCH"):
        body_bytes = await request.body()
        if body_bytes:
            body_text = body_bytes.decode("utf-8", errors="replace")[:2000]

    classification = classifier.classify(
        method=request.method,
        path=request.url.path,
        headers=dict(request.headers),
        query=query_string,
        body=body_text,
    )

    # Update enrichment-related metrics
    if classification.get("tool_signature"):
        SCANNER_DETECTIONS.labels(tool=classification["tool_signature"]).inc()
    if classification.get("technique_id"):
        ATTACK_TECHNIQUES.labels(
            technique_id=classification["technique_id"],
            tactic=classification.get("tactic", "unknown"),
        ).inc()
    for tag in classification.get("tags", []):
        if tag in ("sqli", "xss", "path-traversal", "log4shell", "ssti", "template-injection"):
            INJECTION_ATTEMPTS.labels(type=tag).inc()
        if tag in ("config-exposure", "source-exposure", "git-dump", "database-dump",
                    "admin-panel", "debug-endpoint"):
            SENSITIVE_PATH_PROBES.labels(path_category=tag).inc()

    # Log the request
    logger.info(
        f"{request.method} {request.url.path} "
        f"from={source_ip} session={session_id} "
        f"severity={classification['severity']} "
        f"ua={session_data['user_agent'][:60]}"
    )

    # Emit telemetry for the request (with enrichment + source_port)
    emitter: EventEmitter = request.app.state.emitter
    await emitter.emit("http.request", session_id, source_ip, {
        "method": request.method,
        "path": request.url.path,
        "user_agent": session_data["user_agent"],
        "headers": {k: v for k, v in request.headers.items()
                    if k.lower() not in _REDACTED_HEADERS},
        "source_port": source_port,
        "enrichment": classification,
    }, severity=classification["severity"])

    # Process request
    response = await call_next(request)

    # Track request metrics AFTER response (so we have status_code)
    path_group = normalize_path_group(request.url.path)
    HTTP_REQUESTS.labels(
        method=request.method,
        path_group=path_group,
        status_code=str(response.status_code),
    ).inc()
    REQUEST_LATENCY.labels(method=request.method).observe(time.time() - start)

    # Set Server header to look like nginx
    response.headers["Server"] = config.server_header

    # Set session cookie
    sessions.set_cookie(response, session_id)

    return response


# ── Mount Prometheus metrics ──────────────────────────
# SECURITY: In production, restrict /metrics access via NetworkPolicy
# or a sidecar auth proxy. Prometheus metrics may expose operational details.
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


# ── nginx-style error pages ──────────────────────────
NGINX_404_HTML = """<!DOCTYPE html>
<html>
<head><title>404 Not Found</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr><center>{server_header}</center>
</body>
</html>
""".strip()

NGINX_500_HTML = """<!DOCTYPE html>
<html>
<head><title>500 Internal Server Error</title></head>
<body>
<center><h1>500 Internal Server Error</h1></center>
<hr><center>{server_header}</center>
</body>
</html>
""".strip()


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Return nginx-style 500 page instead of FastAPI's default JSON error."""
    logger.error("Unhandled exception on %s %s: %s", request.method, request.url.path, exc)
    html = NGINX_500_HTML.format(server_header=config.server_header)
    return HTMLResponse(content=html, status_code=500, headers={"Server": config.server_header})


@app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
async def catch_all(request: Request, full_path: str):
    """Return a realistic nginx-style 404 page for unmatched routes."""
    html = NGINX_404_HTML.format(server_header=config.server_header)
    return HTMLResponse(content=html, status_code=404)
