"""
Local conftest for inference tests.

Ensures `import metrics` resolves to `inference/metrics.py` (not dashboard/
or cti/ which also have a `metrics` module), and re-exports shared test
helpers from the root conftest.
"""

import sys
from pathlib import Path

_INFERENCE_DIR = Path(__file__).resolve().parents[2] / "inference"

for existing in [p for p in sys.path if p == str(_INFERENCE_DIR)]:
    sys.path.remove(existing)
sys.path.insert(0, str(_INFERENCE_DIR))

if "metrics" in sys.modules:
    mod = sys.modules["metrics"]
    if not hasattr(mod, "INFERENCE_REQUESTS"):
        del sys.modules["metrics"]

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
