"""Extra login portal routes: WordPress, Corporate SSO, and Outlook/O365."""

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
    ctx = {"request": request, "error_message": "", "csrf_token": csrf_token, **(context or {})}
    response = templates.TemplateResponse(template, ctx)
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
# WordPress Login
# ---------------------------------------------------------------------------

@router.get("/wp-login.php", response_class=HTMLResponse)
async def wp_login_page(request: Request, error: str | None = None):
    ctx = {}
    if error:
        ctx["error_message"] = "ERROR: Invalid username. Lost your password?"
    else:
        ctx["error_message"] = ""
    return await _handle_get(request, "wordpress_login.html", "wordpress", ctx)


@router.post("/wp-login.php")
async def wp_login_submit(
    request: Request,
    log: str = Form(...),
    pwd: str = Form(...),
    _csrf: str = Form(""),
):
    return await _handle_post(request, log, pwd, "wordpress", "/wp-login.php", csrf_token=_csrf)


@router.get("/wp-admin", response_class=RedirectResponse)
async def wp_admin_redirect():
    return RedirectResponse(url="/wp-login.php?redirect_to=%2Fwp-admin%2F", status_code=302)


# ---------------------------------------------------------------------------
# Corporate SSO Login
# ---------------------------------------------------------------------------

@router.get("/sso/login", response_class=HTMLResponse)
@router.get("/auth/login", response_class=HTMLResponse)
@router.get("/", response_class=HTMLResponse)
async def corporate_login_page(request: Request, error: str | None = None):
    company = request.app.state.config.company_name
    ctx = {"company_name": company}
    if error:
        ctx["error_message"] = "Invalid email or password. Please try again."
    else:
        ctx["error_message"] = ""
    return await _handle_get(request, "corporate_login.html", "corporate", ctx)


@router.post("/sso/login")
@router.post("/auth/login")
@router.post("/")
async def corporate_login_submit(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    _csrf: str = Form(""),
):
    return await _handle_post(request, email, password, "corporate", request.url.path, csrf_token=_csrf)


# ---------------------------------------------------------------------------
# Outlook / O365 Login
# ---------------------------------------------------------------------------

@router.get("/owa/", response_class=HTMLResponse)
@router.get("/outlook/", response_class=HTMLResponse)
@router.get("/mail/", response_class=HTMLResponse)
async def outlook_login_page(request: Request, error: str | None = None):
    ctx = {}
    if error:
        ctx["error_message"] = "Your account or password is incorrect. If you don\u2019t remember your password, reset it now."
    else:
        ctx["error_message"] = ""
    return await _handle_get(request, "outlook_login.html", "outlook", ctx)


@router.post("/owa/")
@router.post("/outlook/")
@router.post("/mail/")
async def outlook_login_submit(
    request: Request,
    loginfmt: str = Form(...),
    passwd: str = Form(...),
    _csrf: str = Form(""),
):
    return await _handle_post(request, loginfmt, passwd, "outlook", request.url.path, csrf_token=_csrf)
