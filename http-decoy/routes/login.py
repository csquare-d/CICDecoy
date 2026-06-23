"""Login portal routes for HTTP honeypot decoy."""

import hashlib
import secrets
from pathlib import Path

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from metrics import CREDENTIALS_CAPTURED

from routes import get_source_ip

router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))
templates.env.autoescape = True  # Defense-in-depth: prevent XSS via template vars


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

    csrf_token = secrets.token_hex(32)
    request.app.state.sessions.store_csrf_token(session_id, csrf_token)
    ctx = {"error_message": "", "csrf_token": csrf_token, **(context or {})}
    response = templates.TemplateResponse(request, template, ctx)
    request.app.state.sessions.set_cookie(response, session_id)
    return response


async def _handle_post(
    request: Request,
    username: str,
    password: str,
    portal: str,
    redirect_path: str,
    csrf_token: str = "",
):
    """Common POST handler: record credentials, emit event, redirect back."""
    # Truncate to prevent DoS via extremely large form submissions
    username = username[:256]
    # Strip control characters and null bytes from captured username
    username = "".join(c for c in username if c.isprintable())
    password = password[:1024]

    session_id, session_data = await request.app.state.sessions.get_or_create_session(request)

    # Validate CSRF token
    if not request.app.state.sessions.validate_csrf_token(session_id, csrf_token):
        response = RedirectResponse(url=f"{redirect_path}?error=csrf", status_code=303)
        request.app.state.sessions.set_cookie(response, session_id)
        return response
    await request.app.state.sessions.record_credential(session_id, username, password, portal=portal)
    CREDENTIALS_CAPTURED.labels(portal=portal).inc()

    await request.app.state.emitter.emit(
        event_type="auth.attempt",
        session_id=session_id,
        source_ip=get_source_ip(request),
        data={"username": username, "password_sha256": hashlib.sha256(password.encode()).hexdigest(), "portal": portal, "success": False},
        severity="high",
    )

    response = RedirectResponse(url=f"{redirect_path}?error=1", status_code=303)
    request.app.state.sessions.set_cookie(response, session_id)
    return response


# ---------------------------------------------------------------------------
# AWS Console Login
# ---------------------------------------------------------------------------

@router.get("/aws/signin", response_class=HTMLResponse)
@router.get("/console/login", response_class=HTMLResponse)
async def aws_login_page(request: Request, error: str | None = None):
    ctx = {}
    if error:
        ctx["error_message"] = "Your authentication information is incorrect. Please try again."
    else:
        ctx["error_message"] = ""
    return await _handle_get(request, "aws_login.html", "aws", ctx)


@router.post("/aws/signin")
@router.post("/console/login")
async def aws_login_submit(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    csrf: str = Form("", alias="_csrf"),
):
    return await _handle_post(request, email, password, "aws", request.url.path, csrf_token=csrf)


# ---------------------------------------------------------------------------
# GitLab Login
# ---------------------------------------------------------------------------

@router.get("/users/sign_in", response_class=HTMLResponse)
@router.get("/gitlab/login", response_class=HTMLResponse)
async def gitlab_login_page(request: Request, error: str | None = None):
    ctx = {}
    if error:
        ctx["error_message"] = "Invalid login or password."
    else:
        ctx["error_message"] = ""
    return await _handle_get(request, "gitlab_login.html", "gitlab", ctx)


@router.post("/users/sign_in")
@router.post("/gitlab/login")
async def gitlab_login_submit(request: Request):
    form = await request.form()
    username = str(form.get("user[login]", ""))[:256]
    password = str(form.get("user[password]", ""))[:1024]
    csrf_token = str(form.get("_csrf", ""))
    return await _handle_post(request, username, password, "gitlab", request.url.path, csrf_token=csrf_token)


# ---------------------------------------------------------------------------
# Jenkins Login
# ---------------------------------------------------------------------------

@router.get("/login", response_class=HTMLResponse)
async def jenkins_login_page(request: Request, error: str | None = None):
    ctx = {}
    if error:
        ctx["error_message"] = "Invalid username or password"
    else:
        ctx["error_message"] = ""
    return await _handle_get(request, "jenkins_login.html", "jenkins", ctx)


@router.post("/j_spring_security_check")
async def jenkins_login_submit(
    request: Request,
    j_username: str = Form(...),
    j_password: str = Form(...),
    csrf: str = Form("", alias="_csrf"),
):
    return await _handle_post(request, j_username, j_password, "jenkins", "/login", csrf_token=csrf)
