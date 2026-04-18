"""
Local conftest for integration tests.

Ensures ``import enrichment`` and ``import session_analyzer`` resolve to the
cti/ package, mirroring the pattern used by tests/cti/conftest.py.
"""

import sys
from pathlib import Path

_CTI_DIR = Path(__file__).resolve().parents[2] / "cti"

# Remove any existing occurrences and prepend to guarantee priority.
for existing in [p for p in sys.path if p == str(_CTI_DIR)]:
    sys.path.remove(existing)
sys.path.insert(0, str(_CTI_DIR))

# Drop a cached ``metrics`` module if a sibling service already imported its
# own version during collection.
if "metrics" in sys.modules:
    mod = sys.modules["metrics"]
    if not hasattr(mod, "EVENTS_PROCESSED"):
        del sys.modules["metrics"]
