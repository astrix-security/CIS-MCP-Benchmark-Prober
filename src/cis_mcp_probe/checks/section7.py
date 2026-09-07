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
from ..rawreq import raw_jsonrpc
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


def _null_id_outcome(status: int, payload: dict | None) -> tuple[str, str]:
    """Decide leg 7.1.2a from the response to a request carrying a null id.

    The protocol states the rule directly: a request id must be a string or an
    integer and must not be null. So a result is a failure and a refusal is not.

    A refusal counts whatever status and code carry it, because a refusal is
    positive evidence. Only the shape of the refusal is graded, and the observed
    values are named so a reviewer can judge them. What cannot count is a bare
    status with no JSON-RPC error object: a gateway in front of the server
    produces exactly that, so it says nothing about the server itself.
    """
    if status in (401, 403):
        return (
            "unknown",
            f"the request drew HTTP {status}, so it did not reach id validation and "
            "the rule was never exercised",
        )
    error = payload.get("error") if isinstance(payload, dict) else None
    if not isinstance(error, dict):
        if isinstance(payload, dict) and payload.get("result") is not None:
            return (
                "fail",
                "the server accepted a null JSON-RPC request id and answered with "
                "a result",
            )
        if 200 <= status < 300:
            # A 2xx with no body is how Streamable HTTP acknowledges a notification.
            # A message carrying id: null is not one, so the server took it for
            # something it is not instead of refusing it. That is still an
            # acceptance, and the evidence has to say which acceptance it was.
            return (
                "fail",
                f"the server accepted a null JSON-RPC request id: HTTP {status} with "
                "no response body, which is how an accepted notification is "
                "acknowledged, rather than the refusal the rule requires",
            )
        return (
            "error",
            f"HTTP {status} carried no JSON-RPC error object, so the refusal cannot "
            "be attributed to the server rather than to something in front of it",
        )
    code = error.get("code")
    if status == 400 and code == -32600:
        return (
            "pass",
            "the null request id was rejected with HTTP 400 and JSON-RPC -32600",
        )
    return (
        "pass",
        f"the null request id was rejected, with HTTP {status} and JSON-RPC {code} "
        "rather than the 400 and -32600 the benchmark names",
    )


@register
class NullRequestIdRejected(Check):
    """7.1.2, Assessment Status: Automated.

    One request, otherwise conformant, carrying a null id. Sent authenticated so
    it reaches id validation rather than stopping at a 401.
    """

    id = "7.1.2"
    title = "Non-null JSON-RPC request IDs are enforced and included in audit logs"
    section = "7"
    level = Level.L1
    remediation = (
        "Reject a request whose id is null, and one whose id collides with another "
        "request still awaiting a response, with JSON-RPC error -32600 and HTTP "
        "400. Record the request id on every audit-log entry so a logged event can "
        "be tied back to the request that produced it."
    )

    async def run(self, ctx: ProbeContext) -> CheckResult:
        if not ctx.endpoint_url:
            return self._error("no endpoint was reached, so no request could be sent")

        payload = {
            "jsonrpc": "2.0",
            "id": None,
            "method": "tools/list",
            "params": {},
        }
        try:
            status, body, _text = await raw_jsonrpc(
                ctx.endpoint_url,
                payload,
                token=ctx.access_token,
                session_id=ctx.session_id,
                protocol_header=ctx.negotiated_version,
            )
        except Exception as e:  # noqa: BLE001
            return self._error(f"the null-id request could not be sent: {e!r}")

        outcome, note = _null_id_outcome(status, body)
        evidence = (
            f"7.1.2a: {note}. Not covered: 7.1.2b, that an id colliding with an "
            "outstanding request is refused, which discrete HTTP requests cannot "
            "hold open to test; and 7.1.2c, that the request id reaches the audit "
            "log, which is on the deployment host"
        )
        details: dict[str, object] = {
            "legs": {"7.1.2a": outcome},
            "http_status": status,
            "jsonrpc_error": (body or {}).get("error")
            if isinstance(body, dict)
            else None,
        }
        if outcome == "fail":
            return self._fail(evidence, **details)
        if outcome == "error":
            return self._error(evidence, **details)
        if outcome == "unknown":
            return self._unknown(evidence, **details)
        return self._pass(evidence, **details)


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
