"""Fake REST API endpoints for HTTP honeypot decoy.

Presents a realistic-looking web application backend API that attracts
and logs attacker reconnaissance. Every request is tracked and emitted
as a telemetry event; sensitive probes (debug, env, data export) are
flagged as high severity.
"""

import time
import uuid

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

router = APIRouter(prefix="/api")

# ---------------------------------------------------------------------------
# Module-level start time — used by /health to report uptime
# ---------------------------------------------------------------------------
_START_TIME = time.monotonic()

# Consistent version identity across all endpoints
_VERSION = "2.4.1"
_BUILD = "a3f8c2d"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_source_ip(request: Request) -> str:
    """Extract the most-likely real client IP."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _json(body: dict, status: int = 200) -> JSONResponse:
    """Return a JSONResponse with realistic headers."""
    return JSONResponse(
        content=body,
        status_code=status,
        headers={
            "X-Request-Id": uuid.uuid4().hex,
            "Cache-Control": "no-store",
        },
    )


async def _emit(request: Request, *, severity: str = "medium",
                event_type: str = "http.request", body_preview: str = "") -> None:
    """Emit a telemetry event for this request."""
    session_id, _ = request.app.state.sessions.get_or_create_session(request)
    await request.app.state.emitter.emit(
        event_type=event_type,
        session_id=session_id,
        source_ip=get_source_ip(request),
        data={
            "method": request.method,
            "path": str(request.url.path),
            "query": str(request.url.query),
            "user_agent": request.headers.get("user-agent", ""),
            "body": body_preview,
        },
        severity=severity,
    )


async def _read_body_preview(request: Request, max_len: int = 500) -> str:
    """Read and truncate the request body for logging."""
    try:
        raw = await request.body()
        text = raw.decode("utf-8", errors="replace")
        return text[:max_len]
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Authentication API
# ---------------------------------------------------------------------------

@router.post("/v1/auth/login")
async def auth_login(request: Request):
    body_preview = await _read_body_preview(request)
    await _emit(request, event_type="auth.attempt", severity="high",
                body_preview=body_preview)
    return _json({
        "error": "invalid_credentials",
        "message": "Invalid username or password",
    }, status=401)


@router.post("/v1/auth/token")
async def auth_token(request: Request):
    body_preview = await _read_body_preview(request)
    await _emit(request, event_type="auth.attempt", severity="high",
                body_preview=body_preview)
    return _json({"error": "unauthorized", "message": "Invalid credentials"}, status=401)


@router.get("/v1/auth/me")
async def auth_me(request: Request):
    await _emit(request)
    return _json({
        "error": "token_expired",
        "message": "Please re-authenticate",
    }, status=401)


@router.post("/v1/auth/refresh")
async def auth_refresh(request: Request):
    body_preview = await _read_body_preview(request)
    await _emit(request, body_preview=body_preview)
    return _json({"error": "unauthorized", "message": "Invalid or expired refresh token"}, status=401)


# ---------------------------------------------------------------------------
# Users API — always 403
# ---------------------------------------------------------------------------

@router.get("/v1/users")
async def users_list(request: Request):
    await _emit(request)
    return _json({"error": "forbidden", "message": "Insufficient permissions"}, status=403)


@router.get("/v1/users/{user_id}")
async def users_detail(request: Request, user_id: str):
    await _emit(request)
    return _json({"error": "forbidden", "message": "Insufficient permissions"}, status=403)


@router.post("/v1/users")
async def users_create(request: Request):
    body_preview = await _read_body_preview(request)
    await _emit(request, body_preview=body_preview)
    return _json({"error": "forbidden", "message": "Insufficient permissions"}, status=403)


# ---------------------------------------------------------------------------
# Configuration / Admin API — attacker magnets
# ---------------------------------------------------------------------------

@router.get("/v1/config")
async def api_config(request: Request):
    await _emit(request, severity="high")
    return _json({"error": "forbidden", "message": "Insufficient permissions"}, status=403)


@router.get("/v1/settings")
async def api_settings(request: Request):
    await _emit(request, severity="high")
    return _json({"error": "forbidden", "message": "Insufficient permissions"}, status=403)


@router.get("/v1/admin/config")
async def admin_config(request: Request):
    await _emit(request, severity="high")
    return _json({"error": "forbidden", "message": "Insufficient permissions"}, status=403)


@router.get("/v1/debug")
async def api_debug(request: Request):
    await _emit(request, severity="high")
    return _json({"error": "not_found", "message": "Not found"}, status=404)


@router.get("/v1/env")
async def api_env(request: Request):
    await _emit(request, severity="high")
    return _json({"error": "not_found", "message": "Not found"}, status=404)


# ---------------------------------------------------------------------------
# Health / Info — realistic working endpoints
# ---------------------------------------------------------------------------

@router.get("/v1/health")
async def health(request: Request):
    await _emit(request, severity="low")
    uptime = int(time.monotonic() - _START_TIME)
    return _json({
        "status": "healthy",
        "version": _VERSION,
        "uptime": uptime,
    })


@router.get("/v1/version")
async def version(request: Request):
    await _emit(request, severity="low")
    return _json({
        "version": _VERSION,
        "build": _BUILD,
        "env": "production",
    })


@router.get("/v1/status")
async def status(request: Request):
    await _emit(request, severity="low")
    return _json({
        "status": "operational",
        "services": {
            "database": "connected",
            "cache": "connected",
            "queue": "connected",
        },
    })


# ---------------------------------------------------------------------------
# Search / Data
# ---------------------------------------------------------------------------

@router.get("/v1/search")
async def search(request: Request, q: str = ""):
    await _emit(request, severity="medium")
    return _json({
        "results": [],
        "total": 0,
        "query": q,
    })


@router.get("/v1/data/export")
async def data_export(request: Request):
    await _emit(request, severity="high")
    return _json({"error": "forbidden", "message": "Insufficient permissions"}, status=403)


# ---------------------------------------------------------------------------
# Common vulnerability probes — attacker attractors
# ---------------------------------------------------------------------------

@router.get("/v1/graphql")
async def graphql_get(request: Request):
    await _emit(request, severity="medium")
    return _json({
        "errors": [{"message": "Must provide query string"}],
    })


@router.post("/v1/graphql")
async def graphql_post(request: Request):
    body_preview = await _read_body_preview(request)
    await _emit(request, severity="high", body_preview=body_preview)
    return _json({
        "errors": [{"message": "Unauthorized"}],
    })


_OPENAPI_SPEC = {
    "openapi": "3.0.3",
    "info": {
        "title": "Internal Platform API",
        "version": _VERSION,
        "description": "Internal services API for user management, data, and authentication.",
    },
    "servers": [
        {"url": "/api/v1", "description": "Production"},
    ],
    "paths": {
        "/auth/login": {
            "post": {
                "summary": "Authenticate user",
                "operationId": "authLogin",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "username": {"type": "string"},
                                    "password": {"type": "string"},
                                },
                                "required": ["username", "password"],
                            }
                        }
                    },
                },
                "responses": {
                    "200": {"description": "JWT token pair"},
                    "401": {"description": "Invalid credentials"},
                },
            }
        },
        "/auth/token": {
            "post": {
                "summary": "Obtain access token",
                "operationId": "authToken",
                "responses": {
                    "200": {"description": "Access token"},
                    "401": {"description": "Unauthorized"},
                },
            }
        },
        "/auth/me": {
            "get": {
                "summary": "Current user profile",
                "operationId": "authMe",
                "security": [{"bearerAuth": []}],
                "responses": {
                    "200": {"description": "User profile"},
                    "401": {"description": "Token expired"},
                },
            }
        },
        "/users": {
            "get": {
                "summary": "List users",
                "operationId": "listUsers",
                "security": [{"bearerAuth": []}],
                "parameters": [
                    {"name": "page", "in": "query", "schema": {"type": "integer", "default": 1}},
                    {"name": "limit", "in": "query", "schema": {"type": "integer", "default": 25}},
                ],
                "responses": {
                    "200": {"description": "Paginated user list"},
                    "403": {"description": "Forbidden"},
                },
            },
            "post": {
                "summary": "Create user",
                "operationId": "createUser",
                "security": [{"bearerAuth": []}],
                "responses": {
                    "201": {"description": "User created"},
                    "403": {"description": "Forbidden"},
                },
            },
        },
        "/users/{user_id}": {
            "get": {
                "summary": "Get user by ID",
                "operationId": "getUser",
                "security": [{"bearerAuth": []}],
                "parameters": [
                    {"name": "user_id", "in": "path", "required": True, "schema": {"type": "string"}},
                ],
                "responses": {
                    "200": {"description": "User details"},
                    "403": {"description": "Forbidden"},
                    "404": {"description": "Not found"},
                },
            }
        },
        "/search": {
            "get": {
                "summary": "Search records",
                "operationId": "search",
                "parameters": [
                    {"name": "q", "in": "query", "required": True, "schema": {"type": "string"}},
                ],
                "responses": {
                    "200": {"description": "Search results"},
                },
            }
        },
        "/data/export": {
            "get": {
                "summary": "Export data as CSV",
                "operationId": "exportData",
                "security": [{"bearerAuth": []}],
                "responses": {
                    "200": {"description": "CSV download"},
                    "403": {"description": "Forbidden"},
                },
            }
        },
        "/health": {
            "get": {
                "summary": "Health check",
                "operationId": "healthCheck",
                "responses": {
                    "200": {"description": "Service health status"},
                },
            }
        },
    },
    "components": {
        "securitySchemes": {
            "bearerAuth": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "JWT",
            }
        }
    },
}


@router.get("/v1/swagger.json")
async def swagger_json(request: Request):
    await _emit(request, severity="medium")
    return _json(_OPENAPI_SPEC)


@router.get("/v1/openapi.json")
async def openapi_json(request: Request):
    await _emit(request, severity="medium")
    return _json(_OPENAPI_SPEC)


# ---------------------------------------------------------------------------
# Catch-all for unmatched /api paths
# ---------------------------------------------------------------------------

@router.get("/{path:path}")
@router.post("/{path:path}")
async def api_catchall(request: Request, path: str):
    body_preview = ""
    if request.method == "POST":
        body_preview = await _read_body_preview(request)
    await _emit(request, severity="medium", body_preview=body_preview)
    return _json({
        "error": "not_found",
        "path": f"/api/{path}",
    }, status=404)
