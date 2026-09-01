"""The Section 3 recommendations a remote client cannot decide: 3.2, 3.3, 3.7, 3.9.

Each returns NOT_APPLICABLE and follows 2.1's wording: name the operator-side
halves of the audit, then record what this run did reach.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ...context import ProbeContext
from ..base import Check, CheckResult, Level, register

if TYPE_CHECKING:
    from mcp import types

# The four behaviour hints a tool may carry, in the order the recommendation
# lists them.
ANNOTATION_HINTS = (
    "readOnlyHint",
    "destructiveHint",
    "idempotentHint",
    "openWorldHint",
)


def _annotation_counts(tools: list["types.Tool"]) -> dict[str, int]:
    """Count how many tools assert each behaviour hint.

    A tool carries no annotations at all (``annotations`` is None), or carries an
    annotations object where each hint is independently optional. Only a hint
    that is present and non-null counts as asserted.
    """
    counts = {hint: 0 for hint in ANNOTATION_HINTS}
    for tool in tools:
        annotations = getattr(tool, "annotations", None)
        if annotations is None:
            continue
        for hint in ANNOTATION_HINTS:
            if getattr(annotations, hint, None) is not None:
                counts[hint] += 1
    return counts


def _reached(ctx: ProbeContext) -> str:
    return f"reached {ctx.domain} over {ctx.transport or 'unknown transport'}"


@register
class StdioCredentialSourcing(Check):
    """3.2, Assessment Status: Automated — automated against a stdio deployment.

    The audit reads the stdio server's launch configuration and process
    environment. Neither exists for a server reached over the network, and a
    server we reached by domain is not on the stdio transport.
    """

    id = "3.2"
    title = "stdio credentials are sourced from the environment or a credential store"
    section = "3"
    level = Level.L1
    remediation = (
        "Inject stdio server credentials from the environment or an OS secret "
        "store at launch, never as a command-line argument and never through an "
        "interactive browser authorization flow on the stdio connection."
    )

    async def run(self, ctx: ProbeContext) -> CheckResult:
        return self._na(
            "governs the stdio transport, which this run does not use: the "
            "launch configuration and process environment the audit inspects "
            "are operator-side and absent for a networked server "
            f"({_reached(ctx)})",
            transport=ctx.transport,
        )


@register
class PerToolAuthorization(Check):
    """3.3, Assessment Status: Manual.

    The audit needs a second, least-privileged identity, a positive control that
    really invokes a privileged tool, and the server's authorization decision
    log. We can mint no second identity, must not invoke a privileged tool for
    its side effect, and cannot read the log.
    """

    id = "3.3"
    title = "Per-tool authorization policies are enforced"
    section = "3"
    level = Level.L2
    remediation = (
        "Enforce deny-by-default per-tool authorization at the server's tool "
        "dispatcher or the gateway, keyed to the identity in the authenticated "
        "token and an operator-controlled tool risk classification, and log "
        "every allow and deny decision with tool, identity, matched rule, "
        "timestamp, and a correlation identifier."
    )

    async def run(self, ctx: ProbeContext) -> CheckResult:
        return self._na(
            "operator-side: the audit compares a least-privileged identity "
            "against an authorized one, which needs a second credential we "
            "cannot mint; its positive control invokes a privileged tool for "
            "real, which we will not do; and the allow and deny records live in "
            "the server's authorization decision log, which is not readable "
            f"from a remote client ({_reached(ctx)}, {len(ctx.tools)} tools "
            "listed)",
            transport=ctx.transport,
            tools_listed=len(ctx.tools),
        )


@register
class AnnotationsNotTrusted(Check):
    """3.7, Assessment Status: Manual.

    The requirement binds whoever consumes the annotations — the client, host or
    gateway policy — not the server that publishes them. A server advertising a
    hint is conformant; trusting that hint for a gating decision is the defect,
    and that decision is made outside the audited server. The annotations we did
    observe are reported as evidence.
    """

    id = "3.7"
    title = "Server-provided tool annotations are not relied upon for gating decisions"
    section = "3"
    level = Level.L1
    remediation = (
        "Key authorization and human-in-the-loop gating on an "
        "operator-controlled tool risk classification looked up by tool name, "
        "and remove any rule that branches on readOnlyHint, destructiveHint, "
        "idempotentHint or openWorldHint."
    )

    async def run(self, ctx: ProbeContext) -> CheckResult:
        counts = _annotation_counts(ctx.tools)
        inventory = ", ".join(f"{hint}={counts[hint]}" for hint in ANNOTATION_HINTS)
        return self._na(
            "binds the consuming client, host or gateway policy rather than the "
            "audited server: the gating configuration and the tool risk "
            "classification it must key on are both operator-side, and the "
            "audit's fixture is a tool the operator classifies destructive that "
            "advertises readOnlyHint. Annotation inventory over "
            f"{len(ctx.tools)} tools listed: {inventory} ({_reached(ctx)})",
            transport=ctx.transport,
            tools_listed=len(ctx.tools),
            **counts,
        )


@register
class SharedServiceIdentities(Check):
    """3.9, Assessment Status: Manual.

    The authoritative evidence is the identity mapping inventory, and the
    supplementary scan reads configuration files on the deployment host. Which
    downstream identity a tool uses leaves no signature on the MCP wire.
    """

    id = "3.9"
    title = "Downstream service identities are not shared across tools or servers"
    section = "3"
    level = Level.L2
    remediation = (
        "Give each server and each tool its own downstream service or workload "
        "identity with least privilege, record the mapping in an identity "
        "inventory, and cover any remaining shared identity with a documented, "
        "time-bound exception that names an owner and compensating controls."
    )

    async def run(self, ctx: ProbeContext) -> CheckResult:
        return self._na(
            "operator-side: the identity mapping inventory and the per-server "
            "credential configuration the supplementary scan reads are both on "
            "the deployment host, and which downstream identity a tool uses "
            f"leaves no signature on the MCP wire ({_reached(ctx)}, "
            f"{len(ctx.tools)} tools listed)",
            transport=ctx.transport,
            tools_listed=len(ctx.tools),
        )
