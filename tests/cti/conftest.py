"""
Local conftest for CTI tests.

Ensures `import metrics` resolves to `cti/metrics.py` (not dashboard/ or
inference/ which also have a `metrics` module), and re-exports the shared
test helpers from the root conftest so `from conftest import ...` works
when pytest resolves `conftest` to this local file.
"""

import sys
from pathlib import Path

_CTI_DIR = Path(__file__).resolve().parents[2] / "cti"

# Remove any existing occurrences and prepend to guarantee priority.
for existing in [p for p in sys.path if p == str(_CTI_DIR)]:
    sys.path.remove(existing)
sys.path.insert(0, str(_CTI_DIR))

# Drop a cached `metrics` module if a sibling service already imported its
# own version during collection.
if "metrics" in sys.modules:
    mod = sys.modules["metrics"]
    if not hasattr(mod, "EVENTS_PROCESSED"):
        del sys.modules["metrics"]


# Re-export root conftest helpers so `from conftest import ...` keeps working.
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
