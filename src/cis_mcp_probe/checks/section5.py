"""CIS MCP Benchmark Section 5 — Server Configuration.

Section 4 governs the host; Section 5 governs the server, which is the only side a
black-box probe sees. Five of the ten recommendations yield a check:

* 5.1.1 - tool schemas compile under their declared dialect; a violating call is
  surfaced as an execution error. The schema-violating leg needs an operator input.
* 5.1.2 - resource templates declare a URI pattern and a MIME type, and a read of a
  non-existent resource is rejected.
* 5.1.3 - prompts declare well-formed arguments, and an invalid name or a missing
  required argument is rejected. Read from a raw prompts/list: Pydantic coerces a
  non-boolean ``required``, so the SDK path would pass the violation it tests.
* 5.2.3 - the legacy session and stream-resumption surface is gone. Valid only for
  2026-07-28, so it reports NO-REV against every server on an older revision.
* 5.4.1 - a resource read that escapes the approved root is denied.

The other five are operator-side and return NOT_APPLICABLE with the reason.
"""

from __future__ import annotations

from typing import Any

from jsonschema.exceptions import SchemaError
from jsonschema.validators import (
    Draft7Validator,
    Draft201909Validator,
    Draft202012Validator,
)

from ..context import ProbeContext
from .base import Check, CheckResult, Level, register

# The dialects we implement, keyed by the token found in a declared $schema.
# Explicit rather than delegated: validator_for() falls back to the latest draft on
# an unknown value, which would grade a schema under rules it never declared.
_DIALECTS = {
    "": ("2020-12", Draft202012Validator),
    "2020-12": ("2020-12", Draft202012Validator),
    "2019-09": ("2019-09", Draft201909Validator),
    "draft-07": ("draft-07", Draft7Validator),
}


def _declared_dialect(schema: dict) -> str:
    """The _DIALECTS key for this schema's ``$schema``, or the raw value."""
    declared = schema.get("$schema")
    if not isinstance(declared, str) or not declared:
        return ""
    for token in ("2020-12", "2019-09", "draft-07"):
        if token in declared:
            return token
    return declared


def _has_external_ref(node: Any) -> bool:
    """Whether any ``$ref`` anywhere carries a URI scheme.

    check_schema() accepts such a schema without complaint, so this walk is the only
    thing that observes it.
    """
    if isinstance(node, dict):
        ref = node.get("$ref")
        if isinstance(ref, str) and "://" in ref:
            return True
        return any(_has_external_ref(v) for v in node.values())
    if isinstance(node, list):
        return any(_has_external_ref(v) for v in node)
    return False


def compile_schema(schema: dict) -> tuple[str, str, bool]:
    """Compile ``schema`` under the dialect it declares.

    Returns ``(outcome, dialect, has_external_ref)``. ``outcome`` is ``"ok"``,
    ``"unrecognised-dialect"``, or the first line of the SchemaError.
    """
    external = _has_external_ref(schema)
    entry = _DIALECTS.get(_declared_dialect(schema))
    if entry is None:
        return "unrecognised-dialect", _declared_dialect(schema), external
    dialect, validator = entry
    try:
        validator.check_schema(schema)
    except SchemaError as exc:
        return str(exc).splitlines()[0], dialect, external
    return "ok", dialect, external


# Which capability field gates each inventory. There is no resource_templates
# capability: _enumerate gates templates on resources.
_CAPABILITY_FOR = {
    "tools": "tools",
    "prompts": "prompts",
    "resources": "resources",
    "resource_templates": "resources",
}


def _inventory_state(ctx: ProbeContext, primitive: str) -> tuple[int, str]:
    """Which of five states an empty ``primitive`` inventory is in, and why.

    Only state 4 can carry a verdict. Three of the others are claims about this run
    rather than about the server, so they must not share one sentence.
    """
    if ctx.init_result is None:
        return 0, "the session never initialized, so nothing was observed"
    field = _CAPABILITY_FOR[primitive]
    if getattr(ctx.init_result.capabilities, field, None) is None:
        return 1, f"the server declares no {field} capability"
    if any(e.startswith(f"list_{primitive}:") for e in ctx.errors):
        # ctx.errors holds repr(e), so a validation error, a -32601 and a timeout
        # are indistinguishable. Say both rather than picking one.
        return 2, f"the {primitive} document did not parse or the method was refused"
    if not getattr(ctx, primitive):
        return 3, f"the server declares {field} and advertised no {primitive}"
    return 4, ""


@register
class ListChangedRateLimit(Check):
    """5.2.1, Assessment Status: Automated.

    Two blockers, either sufficient. The emission rate over time lives in the
    server's own log, and no external client can provoke a list change, so even a
    held-open subscription stream would have nothing to time.
    """

    id = "5.2.1"
    title = "listChanged notifications are rate-limited to prevent client flooding"
    section = "5"
    level = Level.L2
    remediation = (
        "Configure a minimum interval between two successive list_changed "
        "notifications of the same type, and log the emission rate per server."
    )

    async def run(self, ctx: ProbeContext) -> CheckResult:
        return self._na(
            "Read from the text, not reproduced live. Emission rate over time is "
            "visible only in the server's log, and no external client can provoke a "
            "list change to time two of them. The minimum interval is itself a CIS "
            "Level 2 choice the specification does not define, so there is no "
            "protocol default to test against either."
        )


@register
class SessionIsNotAuthentication(Check):
    """5.2.2, Assessment Status: Manual.

    The wire half needs a handle captured from an authorized session and a tool that
    accepts one as an argument. The recommendation is explicit that the handle is an
    application value rather than a protocol field, so nothing observable names such
    a tool. The rest is inspection of a value we never see.
    """

    id = "5.2.2"
    title = "Sessions are not used as authentication and are bound to user identity"
    section = "5"
    level = Level.L1
    remediation = (
        "Establish authorization independently per request. Where continuity is "
        "needed, issue a handle from a cryptographically secure source, bind it to "
        "the authenticated identity, re-validate it on every use, and expire it."
    )

    async def run(self, ctx: ProbeContext) -> CheckResult:
        return self._na(
            "Read from the text, not reproduced live. The probe needs a handle "
            "captured from an authorized session and a tool that accepts one as an "
            "argument, and neither is discoverable. The adjacent property, an "
            "unauthenticated request reaching a response, is already decided by "
            "check 2.3, so no coverage is lost here."
        )


@register
class StdioLogSeparation(Check):
    """5.3.1, Assessment Status: Automated.

    Scoped to stdio transport. This probe reaches servers by domain over HTTP and
    never launches a server process, so there is no stdout to capture.
    """

    id = "5.3.1"
    title = "Logs are separated from the protocol stream in stdio mode"
    section = "5"
    level = Level.L1
    remediation = (
        "Reserve stdout for JSON-RPC messages only and direct every log, banner and "
        "diagnostic line to stderr or a file sink."
    )

    async def run(self, ctx: ProbeContext) -> CheckResult:
        return self._na(
            "Transport mismatch, not a missing capability: this check applies to the "
            "stdio transport, and this probe speaks HTTP to a remote endpoint and "
            "never launches a server process."
        )


@register
class TaskAuthorization(Check):
    """5.5.1, Assessment Status: Manual.

    Cross-identity access needs a second bearer token. tasks/list was removed in
    2026-07-28, so an existing task cannot be enumerated either, and ttlMs cannot be
    read without creating one.
    """

    id = "5.5.1"
    title = "Authorization, scope and expiry controls are enforced on MCP Tasks"
    section = "5"
    level = Level.L2
    remediation = (
        "Enforce authorization independently at task creation, status polling and "
        "result retrieval, and set a finite non-null ttlMs."
    )

    async def run(self, ctx: ProbeContext) -> CheckResult:
        caps = ctx.init_result.capabilities if ctx.init_result else None
        declared = getattr(caps, "tasks", None) is not None
        observed = "declares" if declared else "declares no"
        return self._na(
            "Read from the text, not reproduced live. Cross-identity retrieval needs "
            "a second identity's bearer token, and tasks/list was removed in this "
            f"revision so an existing task cannot be enumerated. The server {observed} "
            "the Tasks capability.",
            tasks_declared=declared,
        )


@register
class IdempotencyKeys(Check):
    """5.6.1, Assessment Status: Manual.

    Two blockers. Every wire leg executes a side-effecting tool, and the only signal
    that would identify one is an annotation check 3.2.3 asserts must not be relied
    upon. And Idempotency-Key is a convention this recommendation defines rather than
    an MCP field, so a server that never adopted it would fail for not implementing
    a CIS convention.
    """

    id = "5.6.1"
    title = "Idempotency keys are required for side-effecting tool calls"
    section = "5"
    level = Level.L2
    remediation = (
        "Require a client-supplied idempotency key on every side-effecting tool "
        "call, return the stored result for a duplicate key with the same payload, "
        "and reject a reused key carrying a different payload as a conflict."
    )

    async def run(self, ctx: ProbeContext) -> CheckResult:
        return self._na(
            "Read from the text, not reproduced live. Every wire leg requires the "
            "deliberate execution of a side-effecting tool, and no wire observation "
            "identifies a reversible one. Separately, the Idempotency-Key header and "
            "the cached-result indicator are conventions this recommendation defines "
            "and are not MCP specification fields, so a FAIL against a server that "
            "never adopted them would be unearned."
        )
