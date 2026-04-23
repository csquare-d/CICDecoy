"""Admin panel routes for HTTP honeypot decoy.

Fake admin panels (generic, phpMyAdmin, Grafana) and common admin
paths that attackers scan for (Tomcat manager, Spring Boot actuator,
.env files, Apache server-status).
"""

import hashlib
from pathlib import Path

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from metrics import CREDENTIALS_CAPTURED
from routes import get_source_ip

router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))


async def _handle_get(request: Request, template: str, portal: str, context: dict | None = None):
    """Common GET handler: track session, emit connection event, render template."""
    session_id, session_data = await request.app.state.sessions.get_or_create_session(request)

    is_new = await request.app.state.sessions.mark_seen(session_id)
    if is_new:
        await request.app.state.emitter.emit(
            event_type="connection.new",
            session_id=session_id,
            source_ip=get_source_ip(request),
            data={"portal": portal, "path": str(request.url.path)},
            severity="medium",
        )

    ctx = {"request": request, "error_message": "", **(context or {})}
    response = templates.TemplateResponse(template, ctx)
    request.app.state.sessions.set_cookie(response, session_id)
    return response


async def _handle_post(
    request: Request,
    username: str,
    password: str,
    portal: str,
    redirect_path: str,
):
    """Common POST handler: record credentials, emit event, redirect back."""
    session_id, session_data = await request.app.state.sessions.get_or_create_session(request)
    await request.app.state.sessions.record_credential(session_id, username, password, portal=portal)
    CREDENTIALS_CAPTURED.labels(portal=portal).inc()

    await request.app.state.emitter.emit(
        event_type="auth.attempt",
        session_id=session_id,
        source_ip=get_source_ip(request),
        data={"username": username, "password_sha256": hashlib.sha256(password.encode()).hexdigest()[:16], "portal": portal, "success": False},
        severity="high",
    )

    response = RedirectResponse(url=f"{redirect_path}?error=1", status_code=303)
    request.app.state.sessions.set_cookie(response, session_id)
    return response


async def _emit_probe(request: Request, path: str, severity: str = "high") -> str:
    """Emit a probe event and return the session_id."""
    session_id, session_data = await request.app.state.sessions.get_or_create_session(request)

    await request.app.state.emitter.emit(
        event_type="recon.probe",
        session_id=session_id,
        source_ip=get_source_ip(request),
        data={"path": path, "method": request.method},
        severity=severity,
    )

    return session_id


# ---------------------------------------------------------------------------
# Generic Admin Panel
# ---------------------------------------------------------------------------

@router.get("/admin/", response_class=HTMLResponse)
@router.get("/admin/login", response_class=HTMLResponse)
@router.get("/administrator/", response_class=HTMLResponse)
async def admin_login_page(request: Request, error: str | None = None):
    ctx = {}
    if error:
        ctx["error_message"] = "Access denied. Invalid credentials."
    else:
        ctx["error_message"] = ""
    return await _handle_get(request, "admin_login.html", "admin", ctx)


@router.post("/admin/", response_class=HTMLResponse)
@router.post("/admin/login", response_class=HTMLResponse)
@router.post("/administrator/", response_class=HTMLResponse)
async def admin_login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    return await _handle_post(request, username, password, "admin", request.url.path)


# ---------------------------------------------------------------------------
# phpMyAdmin
# ---------------------------------------------------------------------------

@router.get("/phpmyadmin/", response_class=HTMLResponse)
@router.get("/pma/", response_class=HTMLResponse)
@router.get("/dbadmin/", response_class=HTMLResponse)
async def phpmyadmin_login_page(request: Request, error: str | None = None):
    ctx = {}
    if error:
        ctx["error_message"] = "Access denied for user"
    else:
        ctx["error_message"] = ""
    return await _handle_get(request, "phpmyadmin_login.html", "phpmyadmin", ctx)


@router.post("/phpmyadmin/", response_class=HTMLResponse)
@router.post("/pma/", response_class=HTMLResponse)
@router.post("/dbadmin/", response_class=HTMLResponse)
async def phpmyadmin_login_submit(
    request: Request,
    pma_username: str = Form(...),
    pma_password: str = Form(...),
    pma_serverchoice: str = Form(""),
):
    session_id, _ = await request.app.state.sessions.get_or_create_session(request)
    await request.app.state.sessions.record_credential(
        session_id, pma_username, pma_password, portal="phpmyadmin",
    )
    CREDENTIALS_CAPTURED.labels(portal="phpmyadmin").inc()

    await request.app.state.emitter.emit(
        event_type="auth.attempt",
        session_id=session_id,
        source_ip=get_source_ip(request),
        data={
            "username": pma_username,
            "password_sha256": hashlib.sha256(pma_password.encode()).hexdigest()[:16],
            "server": pma_serverchoice,
            "portal": "phpmyadmin",
            "success": False,
        },
        severity="high",
    )

    response = RedirectResponse(url=f"{request.url.path}?error=1", status_code=303)
    request.app.state.sessions.set_cookie(response, session_id)
    return response


# ---------------------------------------------------------------------------
# Grafana
# ---------------------------------------------------------------------------

@router.get("/grafana/login", response_class=HTMLResponse)
@router.get("/monitoring/", response_class=HTMLResponse)
async def grafana_login_page(request: Request, error: str | None = None):
    ctx = {}
    if error:
        ctx["error_message"] = "Invalid username or password"
    else:
        ctx["error_message"] = ""
    return await _handle_get(request, "grafana_login.html", "grafana", ctx)


@router.post("/grafana/login", response_class=HTMLResponse)
@router.post("/monitoring/", response_class=HTMLResponse)
async def grafana_login_submit(
    request: Request,
    user: str = Form(...),
    password: str = Form(...),
):
    return await _handle_post(request, user, password, "grafana", request.url.path)


# ---------------------------------------------------------------------------
# Tomcat Manager
# ---------------------------------------------------------------------------

@router.get("/manager/html")
async def tomcat_manager(request: Request):
    await _emit_probe(request, "/manager/html", severity="high")
    return Response(
        content="401 Unauthorized",
        status_code=401,
        headers={"WWW-Authenticate": 'Basic realm="Tomcat Manager Application"'},
    )


# ---------------------------------------------------------------------------
# Spring Boot Actuator
# ---------------------------------------------------------------------------

@router.get("/actuator/health")
async def actuator_health(request: Request):
    await _emit_probe(request, "/actuator/health", severity="high")
    return JSONResponse(content={"status": "UP"})


@router.get("/actuator")
@router.get("/actuator/env")
async def actuator_env(request: Request):
    path = str(request.url.path)
    severity = "critical" if path.endswith("/env") else "high"
    await _emit_probe(request, path, severity=severity)
    return Response(content="401 Unauthorized", status_code=401)


# ---------------------------------------------------------------------------
# .env file probe
# ---------------------------------------------------------------------------

@router.get("/.env")
async def dotenv_probe(request: Request):
    await _emit_probe(request, "/.env", severity="critical")
    return Response(content="403 Forbidden", status_code=403)


# ---------------------------------------------------------------------------
# Apache server-status / server-info
# ---------------------------------------------------------------------------

@router.get("/server-status")
async def server_status_probe(request: Request):
    await _emit_probe(request, "/server-status", severity="high")
    return Response(content="403 Forbidden", status_code=403)


@router.get("/server-info")
async def server_info_probe(request: Request):
    await _emit_probe(request, "/server-info", severity="high")
    return Response(content="403 Forbidden", status_code=403)
