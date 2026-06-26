"""
CI/CDecoy — Discovery Routes

Serves robots.txt, sitemap.xml, .well-known endpoints, favicon,
and honeypot probe paths that attackers commonly scan for.
"""

from html import escape as html_escape
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse
from honeytoken_registry import HoneytokenRegistry

from routes import get_source_ip as _get_source_ip

router = APIRouter()

STATIC_DIR = Path(__file__).parent.parent / "static"


# ── Helper: nginx-style error response ──────────────────

_NGINX_ERROR_HTML = (
    "<html>\n"
    "<head><title>{status_code} {message}</title></head>\n"
    "<body>\n"
    "<center><h1>{status_code} {message}</h1></center>\n"
    "<hr><center>{server_header}</center>\n"
    "</body>\n"
    "</html>"
)


def _nginx_error(request: Request, status_code: int, message: str) -> HTMLResponse:
    """Return an nginx-style error page."""
    config = getattr(request.app.state, "config", None)
    server_header = html_escape(config.server_header) if config else "nginx/1.24.0"
    html = _NGINX_ERROR_HTML.format(
        status_code=status_code,
        message=message,
        server_header=server_header,
    )
    return HTMLResponse(content=html, status_code=status_code)


def not_found_handler(request: Request) -> HTMLResponse:
    """Return a 404 Not Found page."""
    return _nginx_error(request, 404, "Not Found")


def forbidden_handler(request: Request) -> HTMLResponse:
    """Return a 403 Forbidden page."""
    return _nginx_error(request, 403, "Forbidden")


def bad_gateway_handler(request: Request) -> HTMLResponse:
    """Return a 502 Bad Gateway page."""
    return _nginx_error(request, 502, "Bad Gateway")


# ── robots.txt ───────────────────────────────────────────


def _sanitize_hostname(raw: str) -> str:
    """Strip CR/LF to prevent CRLF injection via hostname."""
    return raw.replace("\r", "").replace("\n", "")


@router.get("/robots.txt", response_class=PlainTextResponse)
async def robots_txt(request: Request):
    hostname = _sanitize_hostname(request.app.state.config.hostname)
    return PlainTextResponse(
        "User-agent: *\n"
        "Disallow: /admin/\n"
        "Disallow: /api/\n"
        "Disallow: /wp-admin/\n"
        "Disallow: /phpmyadmin/\n"
        f"Sitemap: https://{hostname}/sitemap.xml\n"
    )


# ── sitemap.xml ──────────────────────────────────────────


@router.get("/sitemap.xml", response_class=PlainTextResponse)
async def sitemap_xml(request: Request):
    hostname = html_escape(_sanitize_hostname(request.app.state.config.hostname))
    return PlainTextResponse(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        f"  <url><loc>https://{hostname}/</loc></url>\n"
        f"  <url><loc>https://{hostname}/login</loc></url>\n"
        f"  <url><loc>https://{hostname}/about</loc></url>\n"
        f"  <url><loc>https://{hostname}/contact</loc></url>\n"
        "</urlset>\n",
        media_type="application/xml",
    )


# ── .well-known ──────────────────────────────────────────


@router.get("/.well-known/security.txt", response_class=PlainTextResponse)
async def security_txt(request: Request):
    hostname = _sanitize_hostname(request.app.state.config.hostname)
    return PlainTextResponse(
        f"Contact: mailto:security@{hostname}\n"
        f"Expires: 2027-01-01T00:00:00.000Z\n"
        f"Preferred-Languages: en\n"
        f"Canonical: https://{hostname}/.well-known/security.txt\n"
    )


@router.get("/.well-known/openid-configuration", response_class=JSONResponse)
async def openid_configuration(request: Request):
    hostname = _sanitize_hostname(request.app.state.config.hostname)
    base = f"https://{hostname}"
    return JSONResponse(
        {
            "issuer": base,
            "authorization_endpoint": f"{base}/oauth2/authorize",
            "token_endpoint": f"{base}/oauth2/token",
            "userinfo_endpoint": f"{base}/oauth2/userinfo",
            "jwks_uri": f"{base}/.well-known/jwks.json",
            "response_types_supported": ["code", "token", "id_token"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "scopes_supported": ["openid", "profile", "email"],
            "token_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "client_secret_post",
            ],
        }
    )


# ── Favicon ──────────────────────────────────────────────


@router.get("/favicon.ico")
async def favicon():
    ico_path = STATIC_DIR / "favicon.ico"
    return FileResponse(ico_path, media_type="image/x-icon")


# ── Common probe paths (critical / high severity) ───────


async def _emit_probe(request: Request, event_type: str, severity: str, path: str):
    """Emit a telemetry event for a probe attempt."""
    session_id = getattr(request.state, "session_id", "unknown")
    source_ip = _get_source_ip(request)
    await request.app.state.emitter.emit(
        event_type=event_type,
        session_id=session_id,
        source_ip=source_ip,
        data={
            "method": request.method,
            "path": path,
            "user_agent": request.headers.get("user-agent", ""),
        },
        severity=severity,
    )


async def _serve_honeytoken(request: Request, path: str) -> PlainTextResponse | None:
    """If a honeytoken is registered for *path*, serve it and fire an event."""
    registry: HoneytokenRegistry | None = getattr(
        request.app.state,
        "honeytoken_registry",
        None,
    )
    if registry is None or not registry.is_honeytoken(path):
        return None

    session_id = getattr(request.state, "session_id", "unknown")
    source_ip = _get_source_ip(request)
    await registry.on_access(
        path=path,
        session_id=session_id,
        access_vector="http",
        client_ip=source_ip,
        username="anonymous",
    )
    entry = registry._entries[path]
    return PlainTextResponse(content=entry.content)


# --- Git / SVN exposure probes ---


@router.get("/.git/config", response_class=HTMLResponse)
async def git_config(request: Request):
    await _emit_probe(request, "probe.git_exposure", "critical", "/.git/config")
    return forbidden_handler(request)


@router.get("/.git/HEAD", response_class=HTMLResponse)
async def git_head(request: Request):
    await _emit_probe(request, "probe.git_exposure", "critical", "/.git/HEAD")
    return forbidden_handler(request)


@router.get("/.svn/entries", response_class=HTMLResponse)
async def svn_entries(request: Request):
    await _emit_probe(request, "probe.svn_exposure", "high", "/.svn/entries")
    return not_found_handler(request)


# --- Database dump probes ---


@router.get("/backup.sql", response_class=HTMLResponse)
async def backup_sql(request: Request):
    await _emit_probe(request, "probe.db_dump", "critical", "/backup.sql")
    honeytoken_resp = await _serve_honeytoken(request, "/backup.sql")
    if honeytoken_resp is not None:
        return honeytoken_resp
    return forbidden_handler(request)


@router.get("/dump.sql", response_class=HTMLResponse)
async def dump_sql(request: Request):
    await _emit_probe(request, "probe.db_dump", "critical", "/dump.sql")
    honeytoken_resp = await _serve_honeytoken(request, "/dump.sql")
    if honeytoken_resp is not None:
        return honeytoken_resp
    return forbidden_handler(request)


@router.get("/db.sql", response_class=HTMLResponse)
async def db_sql(request: Request):
    await _emit_probe(request, "probe.db_dump", "critical", "/db.sql")
    honeytoken_resp = await _serve_honeytoken(request, "/db.sql")
    if honeytoken_resp is not None:
        return honeytoken_resp
    return forbidden_handler(request)


# --- Config file probes ---


@router.get("/config.php", response_class=HTMLResponse)
async def config_php(request: Request):
    await _emit_probe(request, "probe.config_exposure", "high", "/config.php")
    honeytoken_resp = await _serve_honeytoken(request, "/config.php")
    if honeytoken_resp is not None:
        return honeytoken_resp
    return forbidden_handler(request)


@router.get("/wp-config.php", response_class=HTMLResponse)
async def wp_config_php(request: Request):
    await _emit_probe(request, "probe.config_exposure", "high", "/wp-config.php")
    honeytoken_resp = await _serve_honeytoken(request, "/wp-config.php")
    if honeytoken_resp is not None:
        return honeytoken_resp
    return forbidden_handler(request)


@router.get("/config.yml", response_class=HTMLResponse)
async def config_yml(request: Request):
    await _emit_probe(request, "probe.config_exposure", "high", "/config.yml")
    honeytoken_resp = await _serve_honeytoken(request, "/config.yml")
    if honeytoken_resp is not None:
        return honeytoken_resp
    return forbidden_handler(request)


@router.get("/config.json", response_class=HTMLResponse)
async def config_json(request: Request):
    await _emit_probe(request, "probe.config_exposure", "high", "/config.json")
    honeytoken_resp = await _serve_honeytoken(request, "/config.json")
    if honeytoken_resp is not None:
        return honeytoken_resp
    return forbidden_handler(request)


# --- Miscellaneous probes ---


@router.get("/.DS_Store", response_class=HTMLResponse)
async def ds_store(request: Request):
    await _emit_probe(request, "probe.ds_store", "medium", "/.DS_Store")
    return not_found_handler(request)


@router.get("/crossdomain.xml", response_class=HTMLResponse)
async def crossdomain_xml(request: Request):
    await _emit_probe(request, "probe.crossdomain", "medium", "/crossdomain.xml")
    return not_found_handler(request)


@router.get("/debug/", response_class=HTMLResponse)
@router.get("/debug", response_class=HTMLResponse)
async def debug_probe(request: Request):
    await _emit_probe(request, "probe.debug_endpoint", "high", "/debug/")
    return forbidden_handler(request)


@router.get("/trace/", response_class=HTMLResponse)
@router.get("/trace", response_class=HTMLResponse)
async def trace_probe(request: Request):
    await _emit_probe(request, "probe.debug_endpoint", "high", "/trace/")
    return forbidden_handler(request)
