"""
Local conftest for http-decoy tests.

Ensures `import metrics`, `import session`, etc. resolve to
`http-decoy/` versions for tests in this directory.
"""

import sys
from pathlib import Path

_HTTP_DECOY_DIR = Path(__file__).resolve().parents[2] / "http-decoy"

# Prepend http-decoy/ to sys.path
_http_dir_str = str(_HTTP_DECOY_DIR)
if _http_dir_str in sys.path:
    sys.path.remove(_http_dir_str)
sys.path.insert(0, _http_dir_str)

# Flush colliding modules (metrics, session, config — NOT enrichment,
# which was renamed to http_enrichment.py to avoid the collision).
for _mod_name in ["metrics", "config", "telemetry"]:
    if _mod_name in sys.modules:
        _mod = sys.modules[_mod_name]
        if hasattr(_mod, "__file__") and _mod.__file__ and "http-decoy" not in _mod.__file__:
            del sys.modules[_mod_name]

# Re-export root conftest helpers
_ROOT_CONFTEST = Path(__file__).resolve().parents[1] / "conftest.py"
import importlib.util  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "_cicdecoy_root_conftest", _ROOT_CONFTEST
)
_root = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_root)

MockAsyncpgPool = _root.MockAsyncpgPool
MockAsyncpgConn = _root.MockAsyncpgConn
_AcquireContext = _root._AcquireContext
make_nats_event = _root.make_nats_event
make_session_row = _root.make_session_row


# ── Fixtures ──────────────────────────────────────────

from unittest.mock import AsyncMock, MagicMock, patch  # noqa: E402

import prometheus_client  # noqa: E402
import pytest  # noqa: E402
from httpx import ASGITransport, AsyncClient  # noqa: E402


def _unregister_http_metrics():
    """Clear the default Prometheus registry to allow re-registration.

    This prevents 'Duplicated timeseries in CollectorRegistry' errors
    when the metrics module is re-imported across test fixtures.

    We clear the internal dicts directly because unregister() can fail
    with 'unhashable type: dict' on Info metrics in some versions.
    """
    prometheus_client.REGISTRY._names_to_collectors.clear()
    if hasattr(prometheus_client.REGISTRY, '_collector_to_names'):
        prometheus_client.REGISTRY._collector_to_names.clear()


@pytest.fixture(autouse=True)
def _ensure_http_path():
    """Re-assert http-decoy/ at head of sys.path, flush stale modules."""
    if _http_dir_str in sys.path:
        sys.path.remove(_http_dir_str)
    sys.path.insert(0, _http_dir_str)
    for mod_name in ["metrics", "session", "config", "telemetry"]:
        if mod_name in sys.modules:
            mod = sys.modules[mod_name]
            if hasattr(mod, "__file__") and mod.__file__ and "http-decoy" not in mod.__file__:
                del sys.modules[mod_name]
    yield
    # After test, clean up so other directories aren't contaminated
    if _http_dir_str in sys.path:
        sys.path.remove(_http_dir_str)


@pytest.fixture
def mock_nats():
    nc = AsyncMock()
    nc.is_connected = True
    nc.publish = AsyncMock()
    nc.drain = AsyncMock()
    return nc


@pytest.fixture
def app(mock_nats):
    """Create test app with mocked NATS and all routes mounted."""
    for mod_name in list(sys.modules):
        if mod_name.startswith("routes."):
            del sys.modules[mod_name]
    # Unregister ALL Prometheus collectors and flush cached modules
    # BEFORE re-importing main, to avoid duplicate timeseries errors.
    # This must run unconditionally — other test modules may have
    # registered collectors with the same names.
    _unregister_http_metrics()
    for mod_name in ["metrics", "main", "telemetry"]:
        sys.modules.pop(mod_name, None)

    if _http_dir_str in sys.path:
        sys.path.remove(_http_dir_str)
    sys.path.insert(0, _http_dir_str)

    with patch("nats.connect", new_callable=AsyncMock) as mock_connect:
        mock_connect.return_value = mock_nats
        import main as http_decoy

        # Mount login_extra router
        try:
            from routes.login_extra import router as login_extra_router
            catch_all = None
            remaining = []
            for r in http_decoy.app.routes:
                if hasattr(r, "path") and r.path == "/{full_path:path}":
                    catch_all = r
                else:
                    remaining.append(r)
            http_decoy.app.routes[:] = remaining
            http_decoy.app.include_router(login_extra_router)
            if catch_all is not None:
                http_decoy.app.routes.append(catch_all)
        except ImportError:
            pass

        http_decoy.app.state.emitter = MagicMock()
        http_decoy.app.state.emitter.emit = AsyncMock()
        http_decoy.app.state.emitter._nc = mock_nats
        http_decoy.app.state.emitter._connected = True
        http_decoy.app.state.emitter.close = AsyncMock()

        from http_enrichment import HttpRequestClassifier
        http_decoy.app.state.classifier = HttpRequestClassifier()

        from http_session import SessionTracker
        http_decoy.app.state.sessions = SessionTracker("test-secret-key")

        from config import HttpDecoyConfig
        http_decoy.app.state.config = HttpDecoyConfig(
            session_secret="test-secret-key",
            server_header="nginx/1.24.0",
            hostname="webapp-prod-01",
            company_name="Acme Corp",
        )

        yield http_decoy.app


@pytest.fixture
def client(app):
    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://test")
