"""
CI/CDecoy — Dashboard auth tests

Covers the shared-secret API-key gate introduced in Phase B2:
- Every /api/* route (including SSE) requires a valid key.
- /healthz and /metrics remain public (for liveness probes and Prometheus).
- Static assets (index.html, /assets/*) stay public so the React SPA and its
  login modal can load before a key has been entered.
- Constant-time comparison via `secrets.compare_digest`.
"""

import inspect
import secrets

import main as dashboard
import pytest
from httpx import ASGITransport, AsyncClient

# Swap in a known key for testing — resolve_api_key() already ran at import
# time, so we just overwrite the module-level constant.
TEST_KEY = "unit-test-key-0123456789abcdef"
dashboard.API_KEY = TEST_KEY


@pytest.fixture(autouse=True)
def _reset_globals():
    dashboard.event_buffer.clear()
    dashboard.subscribers.clear()
    dashboard.db_pool = None
    dashboard.nc = None
    yield
    dashboard.event_buffer.clear()
    dashboard.subscribers.clear()
    dashboard.db_pool = None
    dashboard.nc = None


@pytest.fixture
def client():
    transport = ASGITransport(app=dashboard.app)
    return AsyncClient(transport=transport, base_url="http://test")


# ───────────────────────────── /api/* gating ─────────────────────────────


@pytest.mark.asyncio
async def test_api_requires_key(client):
    """/api/events with no key returns 401 + WWW-Authenticate: ApiKey."""
    resp = await client.get("/api/events")
    assert resp.status_code == 401
    assert resp.headers.get("www-authenticate", "").lower().startswith("apikey")


@pytest.mark.asyncio
async def test_api_rejects_wrong_key(client):
    resp = await client.get(
        "/api/events",
        headers={"X-API-Key": "definitely-not-the-key"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_api_accepts_header_key(client):
    """Correct X-API-Key header → auth passes (DB is mocked unavailable, so 503)."""
    resp = await client.get("/api/events", headers={"X-API-Key": TEST_KEY})
    assert resp.status_code == 503
    data = resp.json()
    # DB is disabled so the handler returns the "no DB" payload.
    assert "events" in data


@pytest.mark.asyncio
async def test_stats_requires_key(client):
    resp = await client.get("/api/stats")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_sessions_requires_key(client):
    resp = await client.get("/api/sessions")
    assert resp.status_code == 401


# ───────────────────────────── SSE gating ─────────────────────────────


@pytest.mark.asyncio
async def test_sse_rejects_missing_key(client):
    resp = await client.get("/api/events/stream")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_sse_rejects_wrong_key(client):
    resp = await client.get("/api/events/stream?api_key=wrong")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_sse_accepts_query_key():
    """
    SSE must accept the key via query param since EventSource cannot set
    headers. We can't easily drive the long-lived SSE response through
    httpx's ASGI transport (the request-logging middleware buffers the body),
    so we verify the dependency directly with a Starlette Request built from
    the query string the browser would send.
    """
    from starlette.requests import Request

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/api/events/stream",
        "raw_path": b"/api/events/stream",
        "query_string": f"api_key={TEST_KEY}".encode(),
        "headers": [],
    }
    request = Request(scope)

    # No exception raised → key accepted.
    await dashboard.require_api_key(request)


# ───────────────────────────── Public endpoints ─────────────────────────────


@pytest.mark.asyncio
async def test_healthz_is_public(client):
    resp = await client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


@pytest.mark.asyncio
async def test_metrics_is_public(client):
    """Prometheus must be able to scrape /metrics without a key."""
    resp = await client.get("/metrics", follow_redirects=True)
    assert resp.status_code == 200
    # Prometheus text exposition format starts with `#` help/type lines.
    assert resp.text.startswith("#") or "cicdecoy_" in resp.text


@pytest.mark.asyncio
async def test_index_is_public(client):
    """
    Static React SPA entry must not require a key — the app's login modal
    loads *after* the page. In the test env the static build is absent so
    the handler returns its placeholder HTML (404), but crucially without
    hitting the auth dependency.
    """
    resp = await client.get("/")
    # Either 200 (real build present) or 404 (placeholder) is fine — what we
    # assert is that it's NOT 401.
    assert resp.status_code != 401


# ───────────────────────── Constant-time comparison ─────────────────────────


def test_uses_constant_time_comparison():
    """The require_api_key dependency must use secrets.compare_digest."""
    src = inspect.getsource(dashboard.require_api_key)
    assert "compare_digest" in src, (
        "require_api_key must use secrets.compare_digest for constant-time "
        "comparison to prevent timing attacks"
    )
    # And it must actually be imported/used from the `secrets` module.
    assert "secrets.compare_digest" in src or "compare_digest(" in src


def test_compare_digest_rejects_mismatch():
    """Behavioral check — compare_digest returns False for wrong keys."""
    assert secrets.compare_digest("a" * 32, "b" * 32) is False
    assert secrets.compare_digest(TEST_KEY, TEST_KEY) is True


# ───────────────────── Key resolution at startup ─────────────────────


def test_resolve_api_key_honors_env(monkeypatch):
    monkeypatch.setenv("DASHBOARD_API_KEY", "explicit-key-value")
    monkeypatch.delenv("KUBERNETES_SERVICE_HOST", raising=False)
    monkeypatch.delenv("DASHBOARD_REQUIRE_AUTH", raising=False)
    assert dashboard._resolve_api_key() == "explicit-key-value"


def test_resolve_api_key_generates_ephemeral_in_dev(monkeypatch, capsys):
    monkeypatch.delenv("DASHBOARD_API_KEY", raising=False)
    monkeypatch.delenv("KUBERNETES_SERVICE_HOST", raising=False)
    monkeypatch.delenv("DASHBOARD_REQUIRE_AUTH", raising=False)
    key = dashboard._resolve_api_key()
    assert key and len(key) >= 16
    captured = capsys.readouterr()
    assert "ephemeral key" in captured.out


def test_resolve_api_key_refuses_in_production(monkeypatch):
    monkeypatch.delenv("DASHBOARD_API_KEY", raising=False)
    monkeypatch.setenv("DASHBOARD_REQUIRE_AUTH", "true")
    with pytest.raises(SystemExit):
        dashboard._resolve_api_key()


def test_looks_like_production_detection(monkeypatch):
    monkeypatch.delenv("DASHBOARD_REQUIRE_AUTH", raising=False)
    monkeypatch.delenv("KUBERNETES_SERVICE_HOST", raising=False)
    assert dashboard._looks_like_production() is False

    monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
    assert dashboard._looks_like_production() is True
    monkeypatch.delenv("KUBERNETES_SERVICE_HOST")

    monkeypatch.setenv("DASHBOARD_REQUIRE_AUTH", "true")
    assert dashboard._looks_like_production() is True


# ───────────────────────────── Rate limiter ─────────────────────────────


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    """Clear rate limiter state between every test so counters don't leak."""
    dashboard._rate_limiter._requests.clear()
    yield
    dashboard._rate_limiter._requests.clear()


class TestRateLimiterUnit:
    """Direct unit tests for the RateLimiter class."""

    def test_requests_within_limit_succeed(self):
        limiter = dashboard.RateLimiter(max_requests=100, window_seconds=60)
        for i in range(100):
            assert limiter.check("key-a") is True, f"request {i + 1} should pass"

    def test_requests_exceeding_limit_rejected(self):
        limiter = dashboard.RateLimiter(max_requests=5, window_seconds=60)
        for _ in range(5):
            assert limiter.check("key-a") is True
        assert limiter.check("key-a") is False, "6th request should be rejected"

    def test_independent_limits_per_key(self):
        limiter = dashboard.RateLimiter(max_requests=3, window_seconds=60)
        for _ in range(3):
            limiter.check("key-a")
        # key-a is exhausted
        assert limiter.check("key-a") is False
        # key-b should still be fine
        assert limiter.check("key-b") is True

    def test_window_expiry_resets_limit(self, monkeypatch):
        """After the window elapses, previously counted requests are forgotten."""
        fake_time = [1000.0]
        monkeypatch.setattr("time.monotonic", lambda: fake_time[0])

        limiter = dashboard.RateLimiter(max_requests=3, window_seconds=60)
        for _ in range(3):
            assert limiter.check("key-a") is True
        assert limiter.check("key-a") is False

        # Advance time past the 60-second window.
        fake_time[0] += 61.0
        assert limiter.check("key-a") is True, (
            "after window expires the counter should reset"
        )


class TestRateLimiterIntegration:
    """Integration tests exercising rate limiting through the HTTP stack."""

    @pytest.mark.asyncio
    async def test_api_returns_429_when_limit_exceeded(self, client, monkeypatch):
        """Exhaust the global rate limiter, then verify the endpoint returns 429."""
        # Use a tiny limit so we don't need 100 real requests.
        monkeypatch.setattr(dashboard._rate_limiter, "_max", 3)

        for _ in range(3):
            resp = await client.get(
                "/api/events", headers={"X-API-Key": TEST_KEY}
            )
            # 503 is expected (no DB), but NOT 429 yet.
            assert resp.status_code != 429

        resp = await client.get(
            "/api/events", headers={"X-API-Key": TEST_KEY}
        )
        assert resp.status_code == 429
        assert "rate limit" in resp.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_wrong_key_not_rate_limited(self, client):
        """Failed auth (401) should not consume rate-limit tokens."""
        for _ in range(5):
            resp = await client.get(
                "/api/events", headers={"X-API-Key": "wrong-key"}
            )
            assert resp.status_code == 401

        # The valid key should still work (not exhausted by bad attempts).
        resp = await client.get(
            "/api/events", headers={"X-API-Key": TEST_KEY}
        )
        assert resp.status_code != 429
