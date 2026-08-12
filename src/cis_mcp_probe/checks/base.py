"""Check framework: the contract every benchmark check implements.

Each check maps to one recommendation in the CIS MCP Benchmark. It inspects a
``ProbeContext`` and returns a ``CheckResult`` with a verdict, the evidence that
justifies it, and (on failure) remediation guidance. Checks are tagged with a
profile level (L1/L2) so the report can compute a per-level "stamp".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from ..context import ProbeContext


class Level(str, Enum):
    L1 = "L1"
    L2 = "L2"


class Status(str, Enum):
    """The only verdicts a check may return.

    A check is scoped to the part of a recommendation we decided is worth
    probing, which need not be the whole subsection. Within that scope:

    * NOT_APPLICABLE - the entire subsection is operator-side and we defined no
      check of our own for it.
    * REVISION_UNSUPPORTED - the check is valid only for the latest spec and the
      server does not support it.
    * PASS - the server passes the check.
    * FAIL - the server does not pass the check.
    * UNKNOWN - this run cannot decide, a later run may.
    * ERROR - a critical failure on our side means the check cannot be
      determined.

    Do not add verdicts or blur these boundaries.
    """

    PASS = "PASS"
    FAIL = "FAIL"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    REVISION_UNSUPPORTED = "REVISION_UNSUPPORTED"
    UNKNOWN = "UNKNOWN"
    ERROR = "ERROR"


@dataclass
class CheckResult:
    check_id: str
    title: str
    section: str
    level: Level
    status: Status
    evidence: str = ""
    remediation: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def compliant(self) -> bool:
        """PASS and NOT_APPLICABLE both count as 'not blocking the stamp'."""
        return self.status in (Status.PASS, Status.NOT_APPLICABLE)

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "section": self.section,
            "level": self.level.value,
            "status": self.status.value,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "details": self.details,
        }


class Check:
    """Base class for a single benchmark check.

    Subclasses set the class attributes and implement ``run``. Register them with
    the ``@register`` decorator so the runner discovers them.
    """

    id: str = ""
    title: str = ""
    section: str = "1"
    level: Level = Level.L1
    description: str = ""
    rationale: str = ""
    remediation: str = ""

    async def run(self, ctx: ProbeContext) -> CheckResult:  # pragma: no cover
        raise NotImplementedError

    # --- result helpers ---------------------------------------------------
    def _make(self, status: Status, evidence: str, **details: Any) -> CheckResult:
        return CheckResult(
            check_id=self.id,
            title=self.title,
            section=self.section,
            level=self.level,
            status=status,
            evidence=evidence,
            remediation=self.remediation or None,
            details=details,
        )

    def _pass(self, evidence: str, **details: Any) -> CheckResult:
        return self._make(Status.PASS, evidence, **details)

    def _fail(self, evidence: str, **details: Any) -> CheckResult:
        return self._make(Status.FAIL, evidence, **details)

    def _na(self, evidence: str, **details: Any) -> CheckResult:
        return self._make(Status.NOT_APPLICABLE, evidence, **details)

    def _unknown(self, evidence: str, **details: Any) -> CheckResult:
        return self._make(Status.UNKNOWN, evidence, **details)

    def _revision_unsupported(self, evidence: str, **details: Any) -> CheckResult:
        return self._make(Status.REVISION_UNSUPPORTED, evidence, **details)

    def _error(self, evidence: str, **details: Any) -> CheckResult:
        return self._make(Status.ERROR, evidence, **details)


_REGISTRY: list[Check] = []


def register(check_cls: type[Check]) -> type[Check]:
    """Class decorator: instantiate and add a check to the global registry."""
    _REGISTRY.append(check_cls())
    return check_cls


def all_checks() -> list[Check]:
    return list(_REGISTRY)
