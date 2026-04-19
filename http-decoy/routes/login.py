"""Login portal routes for HTTP honeypot decoy."""

from pathlib import Path

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from metrics import CREDENTIALS_CAPTURED

router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))


def get_source_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        ip = forwarded.split(",")[0].strip()
        if ip:
            return ip
    return request.client.host if request.client else "unknown"


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
        data={"username": username, "password": password, "portal": portal, "success": False},
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
):
    return await _handle_post(request, email, password, "aws", request.url.path)


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
    username = form.get("user[login]", "")
    password = form.get("user[password]", "")
    return await _handle_post(request, username, password, "gitlab", request.url.path)


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
):
    return await _handle_post(request, j_username, j_password, "jenkins", "/login")
