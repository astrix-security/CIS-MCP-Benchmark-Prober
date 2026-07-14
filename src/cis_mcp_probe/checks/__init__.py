"""Check registry.

Importing this package imports every check module for its side effect of
registering itself. As Section 1 checks are added, import them here.
"""

from .base import Check, CheckResult, Level, Status, all_checks, register
from . import section1  # noqa: F401  (imported for check registration side effect)

__all__ = ["Check", "CheckResult", "Level", "Status", "all_checks", "register"]
