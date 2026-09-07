"""Section 7 checks (observability and audit), implemented as live probes.

Tracks the Section 7 revision dated 2026-09-01.

Scope reasoning — what a black-box client can and cannot decide:

* 7.1.1 - operator-side. The audit samples the deployment's own audit log and
        requires every entry to carry a timestamp, a correlation identifier, an
        event type and the producing server's identity. None of that is on the
        wire: NOT_APPLICABLE, with two observations recorded as evidence. Whether
        each result names the server is one possible source of the identity field,
        and a logger may equally take it from its own configuration, so it cannot
        earn a verdict here.
* 7.1.2 - decidable. A request whose id is null must be refused. The protocol
        states the rule directly, and the refusal is visible to any client. The
        other half of the recommendation, that the id reaches the audit log, is
        not.
* 7.1.3 - operator-side. The requirement is stated against values recorded in the
        log, read by field name from a schema the deployment pins. MCP carries no
        timestamp on the wire, so there is nothing to compare: NOT_APPLICABLE.
* 7.2.1 - decidable in part. The audit asks for a deliberately mis-scoped token to
        be refused, which is observable. The structured event it should raise, the
        rule that should alert on it, and the routing to an operator are not.
* 7.2.2 - decidable in part. Two properties the monitoring depends on are visible:
        that a notification names its server, and that a progress notification
        echoes the token its originating request set. The baselines and the
        anomaly rules built on top of them are not.

Registration order is load-bearing and runs top to bottom in this file. Check
7.2.1 presents a token minted for another resource, so its class is defined last
and no check after it reads that credential.
"""

from __future__ import annotations

from ..context import ProbeContext
from .base import Check, CheckResult, Level, register

SERVER_INFO_KEY = "io.modelcontextprotocol/serverInfo"


def _reached(ctx: ProbeContext) -> str:
    return f"reached {ctx.domain} over {ctx.transport or 'unknown transport'}"


def _result_identity(ctx: ProbeContext) -> tuple[list[str], list[str]]:
    """Split the results this run collected by whether each named its server.

    Returns (named, unnamed) as method names. A result whose ``_meta`` is absent
    and one whose ``_meta`` is empty are the same answer: it named nothing.
    """
    named, unnamed = [], []
    for method, meta in sorted(ctx.result_meta.items()):
        value = meta.get(SERVER_INFO_KEY) if isinstance(meta, dict) else None
        (named if value else unnamed).append(method)
    return named, unnamed


@register
class LifecycleMetadata(Check):
    """7.1.1, Assessment Status: Automated.

    The audit samples the deployment's own audit log. Two things a client can see
    are recorded as evidence: whether each result names its server, and whether
    the server still advertises the deprecated logging utility.
    """

    id = "7.1.1"
    title = "Lifecycle and invocation metadata is recorded"
    section = "7"
    level = Level.L1
    remediation = (
        "Emit one structured audit entry per lifecycle and invocation operation, "
        "each carrying a timestamp, a correlation identifier, an event type and "
        "the producing server's identity, and ship them to a central store with "
        "integrity controls. Capture at the server rather than through the "
        "deprecated logging utility."
    )

    async def run(self, ctx: ProbeContext) -> CheckResult:
        named, unnamed = _result_identity(ctx)
        caps = ctx.init_result.capabilities if ctx.init_result else None
        advertises_logging = bool(caps and caps.logging is not None)

        if not ctx.result_meta:
            identity = "no result was collected, so none could be inspected"
        elif not unnamed:
            identity = f"every result names its server ({', '.join(named)})"
        elif not named:
            identity = f"no result names its server ({', '.join(unnamed)})"
        else:
            identity = (
                f"some results name their server ({', '.join(named)}) and some do "
                f"not ({', '.join(unnamed)})"
            )

        return self._na(
            "operator-side: the audit samples the deployment's own audit log and "
            "requires every entry to carry a timestamp, a correlation identifier, "
            "an event type and the producing server's identity, none of which is "
            f"on the wire ({_reached(ctx)}). Observed instead: {identity}; the "
            f"server {'advertises' if advertises_logging else 'does not advertise'} "
            "the deprecated logging utility. The negotiated revision is "
            f"{ctx.negotiated_version or 'unknown'}, and reporting server identity "
            "per result is a 2026-07-28 recommendation the protocol marks optional, "
            "so its absence is not a failure",
            transport=ctx.transport,
            negotiated_version=ctx.negotiated_version,
            results_naming_server=named,
            results_not_naming_server=unnamed,
            advertises_deprecated_logging=advertises_logging,
        )


@register
class AuditTimestamps(Check):
    """7.1.3, Assessment Status: Automated.

    Every requirement is stated against values recorded in the log, read by field
    name from a schema the deployment pins. MCP carries no timestamp on the wire.
    """

    id = "7.1.3"
    title = "Audit records carry accurate, monotonic timestamps"
    section = "7"
    level = Level.L1
    remediation = (
        "Give every audit record a timestamp in one parseable format, keep them "
        "non-decreasing within a request stream, and hold the newest record close "
        "to real time."
    )

    async def run(self, ctx: ProbeContext) -> CheckResult:
        return self._na(
            "operator-side: the requirement is stated against the values recorded "
            "in the audit log rather than against any host time service, and the "
            "timestamp field is read by name from the schema the deployment pins. "
            f"MCP carries no timestamp on the wire ({_reached(ctx)}), so there is "
            "nothing to compare",
            transport=ctx.transport,
        )
