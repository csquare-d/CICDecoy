"""
Local conftest for dashboard tests.

The root conftest adds several service directories to sys.path, and some of
them contain a module called `metrics` that collides with
`dashboard/metrics.py`. We re-assert dashboard's path at the head of sys.path
here so `import metrics` resolves to the dashboard one for these tests.

This file also re-exports the helpers/fixtures defined in the top-level
conftest so the existing `test_dashboard_api.py` (which does
`from conftest import MockAsyncpgPool, ...`) keeps working when Python
resolves `conftest` to this local module.
"""

import sys
from pathlib import Path

_DASHBOARD_DIR = Path(__file__).resolve().parents[2] / "dashboard"

# Remove any existing occurrences and prepend to guarantee priority.
for existing in [p for p in sys.path if p == str(_DASHBOARD_DIR)]:
    sys.path.remove(existing)
sys.path.insert(0, str(_DASHBOARD_DIR))

# Drop a cached `metrics` module if a sibling service (inference/, cti/,
# ssh-decoy/) already imported its own version during collection of the root
# conftest.
if "metrics" in sys.modules:
    mod = sys.modules["metrics"]
    if not hasattr(mod, "API_REQUESTS"):
        del sys.modules["metrics"]

# Re-export the top-level test helpers so tests that do
# `from conftest import ...` continue to resolve even when pytest picks
# THIS file as the `conftest` module in sys.modules.
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
