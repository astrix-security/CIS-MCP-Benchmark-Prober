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

# Imported LAST, and check 10.2 registers after 10.1. `_run_checks` iterates
# registration order, and 10.2 sends a padded request body: a body large enough to
# trip a rate limiter or a WAF must not precede another check's requests.
from . import section10  # noqa: F401  (imported for check registration side effect)

__all__ = ["Check", "CheckResult", "Level", "Status", "all_checks", "register"]
