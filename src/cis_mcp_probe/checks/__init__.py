"""Check registry.

Importing this package imports every check module for its side effect of
registering itself. As new sections are added, import them here.
"""

from .base import Check, CheckResult, Level, Status, all_checks, register
from . import section1  # noqa: F401  (imported for check registration side effect)
from . import section2  # noqa: F401  (imported for check registration side effect)
from . import section3  # noqa: F401  (imported for check registration side effect)
from . import section5  # noqa: F401  (imported for check registration side effect)
from . import section7  # noqa: F401  (imported for check registration side effect)

from . import section10  # noqa: F401  (imported for check registration side effect)

# Import order sets the run order, except for the few checks that set `run_last` and
# so sort to the end whatever their module. `all_checks` applies it; each of those
# checks says at its own class why it belongs there.

__all__ = ["Check", "CheckResult", "Level", "Status", "all_checks", "register"]
