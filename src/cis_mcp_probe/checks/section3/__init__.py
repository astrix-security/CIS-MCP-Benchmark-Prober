"""Section 3 checks, one module per check.

Import order is load-bearing, because it is the order the checks run in. Check 3.5
requests a token bound to a different resource, which can rotate the cached refresh
token, so any check importing after it could read a credential 3.5 has already
invalidated. Keep c35 last, and add new modules above it.
"""

from . import na_checks  # noqa: F401  (3.2, 3.3, 3.7, 3.9)
from . import c31  # noqa: F401  (3.1)
from . import c34  # noqa: F401  (3.4)
from . import c38  # noqa: F401  (3.8)
from . import c310  # noqa: F401  (3.10)
from . import c36  # noqa: F401  (3.6)
from . import c35  # noqa: F401  (3.5) — MUST stay last
