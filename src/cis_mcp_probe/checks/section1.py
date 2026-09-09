"""Section 1 checks (protocol version and capability governance), as live probes.

Tracks the Section 1 revision captured 2026-09-08.

Scope reasoning — what a black-box client can and cannot decide:

* 1.1 - decidable in five legs. 1.1a enumerates the revisions the server serves and
        compares them against the recommendation's own 2025-06-18 floor, which stands
        in for the operator allowlist we do not hold. Legs 1.1b to 1.1e each send one
        malformed version assertion and require the specified error code at HTTP 400.
        The log-inspection leg reads a deployment audit log and is dropped.
* 1.2 - decidable against a baseline we record ourselves per server URL, not against
        the registry-approved configuration the audit names. The comparison covers
        every nested capability leaf and its value, so a setting that changes without
        any name changing is drift. Tool, resource and prompt name drift is reported
        but gates no verdict: the audit tests the capability configuration object, and
        a tool name is not part of it.
* 1.3 - decidable where a tool can be invoked. The staged capability is a tool
        advertised now and absent from the recorded baseline, which is this probe's
        stand-in for "advertised beyond the approved baseline". The audit's log leg is
        dropped. Arguments cannot be synthesised from a schema safely, so they come
        from the operator's ``tool_arguments`` entry where one exists and are otherwise
        empty. A tool whose arguments are required then answers with a validation
        error that reads exactly like a gate denial, which is why an unmatched
        rejection is UNKNOWN rather than PASS and why the control probe failing is
        ERROR rather than a verdict.
* 1.4 - decidable as identity drift. The verdict comes from the audit's registry
        comparison, reduced to the identity we recorded ourselves, because an observed
        identity absent from the approved list is the recommendation's own FAIL
        condition. Whether that identity is well formed is reported as evidence and
        gates nothing: the audit routes its only malformed branch to REVIEW, and a
        malformed value is never named as a FAIL. The registry export and the
        "registered but not observed" leg are dropped.

Legs 1.1d and 1.1e assert the header-versus-``_meta`` agreement that only 2026-07-28
defines, so they report REVISION_UNSUPPORTED on an earlier revision. A leg reporting
that is excluded from the check's aggregation rather than lowering it, and the count
appears in the evidence.
"""

from __future__ import annotations

import re
from typing import Any

from .. import baseline, inputs
from ..client import RC_VERSION
from ..context import ProbeContext
from ..rawreq import is_rejection, jsonrpc_error_code, raw_jsonrpc
from .base import Check, CheckResult, Level, register

# Error codes the 2026-07-28 schema defines for version and header enforcement.
UNSUPPORTED_PROTOCOL_VERSION = -32022
HEADER_MISMATCH = -32020
INVALID_PARAMS = -32602

# The recommendation's own floor: "do not serve revisions earlier than 2025-06-18".
FLOOR_REVISION = "2025-06-18"

# The published MCP revisions earlier than the floor. These are the only ones the
# sweep offers: the floor test asks whether any sub-floor revision is served, and
# probing the revisions at or above the floor cannot change that answer. Keeping the
# sweep to two requests also keeps the whole check within nine requests per run, which
# matters -- a five-revision sweep provoked connection refusals from one live server.
SUB_FLOOR_REVISIONS = ("2024-11-05", "2025-03-26")

STALE_VERSION = "2025-03-26"  # a supported-but-old header, for the disagreement probe
BOGUS_VERSION = "2024-01-01"  # never a published revision

PROTOCOL_VERSION_KEY = "io.modelcontextprotocol/protocolVersion"

_AUDIT_META = {
    "io.modelcontextprotocol/clientInfo": {
        "name": "cis-benchmark-audit",
        "version": "1.0",
    },
    "io.modelcontextprotocol/clientCapabilities": {},
}

_REVISION_SHAPE = re.compile(r"\d{4}-\d{2}-\d{2}")

DROPPED_1_1F = (
    " 1.1f: not probed, the asserted version is recorded in a deployment audit log "
    "this probe does not read"
)
DROPPED_1_3B = (
    " 1.3b: not probed, the capability diff and approval state are recorded in a "
    "deployment audit log this probe does not read"
)
DROPPED_1_4B_REVIEW = (
    " registry export not read: the comparison is against the identity this probe "
    "recorded itself, so it decides drift rather than conformance to an approved "
    "inventory, and a registered identity we never observed is not reported"
)


def _resolve(check: Check, legs: list[tuple[str, str, str]], suffix: str = "", **details: Any) -> CheckResult:
    """Combine leg outcomes into one verdict, worst first.

    ``fail > error > unknown > pass``, the order Section 3 established. A
    ``revision_unsupported`` leg is excluded from that ordering rather than lowering
    the check: legs 1.1d and 1.1e do not apply below 2026-07-28, and letting them
    decide would report a whole check as inapplicable because two of its five legs
    are. Where every leg is ``revision_unsupported`` there is nothing left to decide
    and the check reports it.
    """
    evidence = "; ".join(f"{leg}: {note}" for leg, _outcome, note in legs) + suffix
    details["legs"] = {leg: outcome for leg, outcome, _note in legs}
    decided = [outcome for _leg, outcome, _note in legs if outcome != "revision_unsupported"]
    if not decided:
        return check._revision_unsupported(evidence, **details)
    if "fail" in decided:
        return check._fail(evidence, **details)
    if "error" in decided:
        return check._error(evidence, **details)
    if "unknown" in decided:
        return check._unknown(evidence, **details)
    return check._pass(evidence, **details)


def _tools_list(version: str | None = None) -> dict[str, Any]:
    """A tools/list request, asserting ``version`` in ``_meta`` when one is given.

    Every probe carries the auditor's ``clientInfo``, so an operator reading their own
    logs can tell this probe's traffic from a real client's. With ``version`` omitted
    the envelope is complete except for the version field, which is leg 1.1d's shape.
    """
    meta = dict(_AUDIT_META)
    if version is not None:
        meta[PROTOCOL_VERSION_KEY] = version
    return {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {"_meta": meta}}


def _version_leg(
    status: int,
    data: dict[str, Any] | None,
    text: str,
    *,
    expected: int,
    expected_name: str,
    overrides: dict[int, tuple[str, str]],
) -> tuple[str, str]:
    """Map one version-enforcement probe to ``(outcome, note)``.

    The shared branches, identical in all four of the audit's probes: the expected
    code at HTTP 400 passes, the expected code at another status fails because the
    specification requires 400, and an accepted request fails. ``overrides`` carries
    the codes one leg treats differently from another, which is where the audit's
    probes genuinely disagree.

    An empty or non-JSON body is ERROR, never FAIL. A bare rejection may have come
    from a gateway that never reached the origin, so it says nothing about the server.
    """
    if text.startswith("__transport_failure__"):
        return "error", f"the probe could not be sent: {text.split(' ', 1)[1]}"
    if not text.strip():
        return "error", "no response from the endpoint"
    if data is None:
        return (
            "error",
            (
                f"response body is not JSON (HTTP {status}), so no verdict is "
                f"attributable; confirm the probe reaches the origin server"
            ),
        )
    code = jsonrpc_error_code(data)
    if code == expected:
        if status == 400:
            supported = ((data.get("error") or {}).get("data") or {}).get("supported")
            names = f", server supports {supported}" if supported else ""
            return "pass", f"rejected with HTTP 400 and {expected_name}{names}"
        return (
            "fail",
            (
                f"{expected_name} returned with HTTP {status}, the specification "
                f"requires 400"
            ),
        )
    if code in overrides:
        outcome, note = overrides[code]
        return outcome, note.format(status=status)
    if code is not None:
        return (
            "pass",
            (
                f"rejected with error code {code} at HTTP {status}; confirm the "
                f"rejection is version enforcement"
            ),
        )
    if is_rejection(status, data):
        return (
            "error",
            (
                f"rejected at HTTP {status} with no protocol error, so the rejection "
                f"is not attributable to the server's version enforcement"
            ),
        )
    return "fail", "the request was accepted"


def _leg_1_1b(status: int, data: dict[str, Any] | None, text: str) -> tuple[str, str]:
    """An unapproved version must draw UnsupportedProtocolVersion at HTTP 400."""
    return _version_leg(
        status,
        data,
        text,
        expected=UNSUPPORTED_PROTOCOL_VERSION,
        expected_name="UnsupportedProtocolVersion",
        overrides={},
    )


def _leg_1_1c(status: int, data: dict[str, Any] | None, text: str) -> tuple[str, str]:
    """A request with no version header must draw HeaderMismatch at HTTP 400.

    An UnsupportedProtocolVersion rejection here is a reference-SDK divergence
    reported upstream. The request was still rejected, so no downgrade path opened
    and the leg passes with the divergence named.
    """
    return _version_leg(
        status,
        data,
        text,
        expected=HEADER_MISMATCH,
        expected_name="HeaderMismatch",
        overrides={
            UNSUPPORTED_PROTOCOL_VERSION: (
                "pass",
                (
                    "rejected as an unsupported version at HTTP {status} rather than "
                    "HeaderMismatch, a known reference-SDK divergence; the request was "
                    "still rejected, so no silent downgrade path opened"
                ),
            )
        },
    )


def _leg_1_1d(status: int, data: dict[str, Any] | None, text: str) -> tuple[str, str]:
    """A body missing the version field must draw Invalid params at HTTP 400."""
    return _version_leg(
        status,
        data,
        text,
        expected=INVALID_PARAMS,
        expected_name="Invalid params",
        overrides={
            HEADER_MISMATCH: (
                "pass",
                (
                    "rejected as a header mismatch at HTTP {status}, defensible where "
                    "the header is compared before required-field validation"
                ),
            ),
            UNSUPPORTED_PROTOCOL_VERSION: (
                "pass",
                (
                    "rejected as an unsupported version at HTTP {status}; the "
                    "specification defines a missing required field as a malformed "
                    "request"
                ),
            ),
        },
    )


def _leg_1_1e(status: int, data: dict[str, Any] | None, text: str) -> tuple[str, str]:
    """Disagreeing header and body versions must draw HeaderMismatch at HTTP 400.

    The one leg where UnsupportedProtocolVersion fails rather than passing with a
    caveat, and the audit says why: the body carries a supported version, so no
    version-support rejection applies.
    """
    return _version_leg(
        status,
        data,
        text,
        expected=HEADER_MISMATCH,
        expected_name="HeaderMismatch",
        overrides={
            UNSUPPORTED_PROTOCOL_VERSION: (
                "fail",
                (
                    "rejected as an unsupported version at HTTP {status}; the body "
                    "carries a supported version, so no version-support rejection "
                    "applies and the specification requires HeaderMismatch"
                ),
            )
        },
    )


def _floor_verdict(served: list[str]) -> tuple[str, str]:
    """Compare a served revision set against the 2025-06-18 floor.

    A revision string that is not a date is treated as below the floor and named. One
    we cannot place is not evidence of compliance, and reading it as compliant would
    pass a server on a value we did not understand.
    """
    if not served:
        return (
            "error",
            (
                "no served revision set could be enumerated, so no verdict is "
                "attributable"
            ),
        )
    below = sorted(
        v for v in served if not _REVISION_SHAPE.fullmatch(v) or v < FLOOR_REVISION
    )
    if below:
        return (
            "fail",
            (
                f"serves {', '.join(below)}, earlier than the {FLOOR_REVISION} floor "
                f"this Recommendation sets (served set: {', '.join(sorted(served))}); "
                f"the operator allowlist itself was not read"
            ),
        )
    return (
        "pass",
        (
            f"every served revision is at or after the {FLOOR_REVISION} floor "
            f"(served set: {', '.join(sorted(served))}); the operator allowlist itself "
            f"was not read, so a revision approved by neither is not detected"
        ),
    )


def _prefer_read_only(
    tools: list[Any], candidates: set[str], supplied: dict[str, dict] | None = None
) -> str | None:
    """Pick a tool from ``candidates``, in a fixed order of preference.

    A tool the operator supplied arguments for comes first, because a tool whose
    arguments are required cannot be invoked without them and its error is
    indistinguishable from a gate denial. Then a tool annotated ``readOnlyHint``.
    Then the first name in sorted order, so a run is repeatable.

    The hint orders the candidates and is not a safeguard: it is a self-asserted
    server claim, and check 3.2.3 exists to say it must not gate a decision.
    """
    if not candidates:
        return None
    with_arguments = candidates & set(supplied or {})
    if with_arguments:
        candidates = with_arguments
    hinted = [
        t.name
        for t in tools
        if t.name in candidates
        and getattr(getattr(t, "annotations", None), "readOnlyHint", None) is True
    ]
    return min(hinted) if hinted else min(candidates)


async def _server_discover(ctx: ProbeContext) -> tuple[int, dict[str, Any] | None, str]:
    """Call ``server/discover`` under 2026-07-28, as the audit's first probe does."""
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "server/discover",
        "params": {"_meta": {PROTOCOL_VERSION_KEY: RC_VERSION, **_AUDIT_META}},
    }
    return await raw_jsonrpc(
        ctx.endpoint_url or "",
        payload,
        token=ctx.access_token,
        session_id=ctx.session_id,
        protocol_header=RC_VERSION,
        extra_headers={"Mcp-Method": "server/discover"},
    )


@register
class ProtocolVersionPinning(Check):
    """1.1, Assessment Status: Automated.

    Five legs. The audit's log-inspection leg is not probed.
    """

    id = "1.1"
    title = "Served protocol revisions are pinned and malformed assertions are rejected"
    section = "1"
    level = Level.L1
    remediation = (
        "Serve only operator-approved protocol revisions and none earlier than "
        f"{FLOOR_REVISION}. Reject a request whose asserted version is unapproved "
        "with -32022, one whose header and body disagree with -32020, and one "
        "missing either value as malformed, each at HTTP 400."
    )

    async def run(self, ctx: ProbeContext) -> CheckResult:
        if ctx.session is None or not ctx.endpoint_url:
            return self._error("no live session to test against")

        legs = [await self._leg_a(ctx)]
        legs.extend(await self._wire_legs(ctx))
        return _resolve(
            self,
            legs,
            suffix=DROPPED_1_1F,
            mechanism=self._mechanism(ctx),
            floor=FLOOR_REVISION,
        )

    def _mechanism(self, ctx: ProbeContext) -> str:
        if ctx.rc_supported:
            return f"_meta {PROTOCOL_VERSION_KEY} ({RC_VERSION})"
        return f"MCP-Protocol-Version header ({ctx.negotiated_version})"

    async def _leg_a(self, ctx: ProbeContext) -> tuple[str, str, str]:
        """Enumerate the served revision set, then compare it against the floor.

        ``server/discover`` is the audit's own source and is read first. It exists
        only from 2026-07-28, and a server that will not negotiate that revision
        rejects the call at its version gate before reading the method, so the served
        set is then enumerated by offering each published revision on its own
        ``initialize`` and comparing the echoed version against the requested one.
        Both routes measure the revisions the endpoint serves, which is what the
        Recommendation requires over the ones it accepts per request.
        """
        discover_note = ""
        if ctx.rc_supported:
            status, data, _text = await _server_discover(ctx)
            result = (data or {}).get("result")
            if isinstance(result, dict):
                advertised = result.get("supportedVersions")
                if (
                    isinstance(advertised, list)
                    and advertised
                    and all(isinstance(v, str) for v in advertised)
                ):
                    outcome, note = _floor_verdict(advertised)
                    return "1.1a", outcome, f"{note}, read from server/discover"
                return (
                    "1.1a",
                    "error",
                    (
                        f"server/discover returned no well-formed supportedVersions "
                        f"array (HTTP {status}), so the served set cannot be enumerated"
                    ),
                )
            discover_note = (
                f", after server/discover was attempted and rejected (HTTP {status}, "
                f"code {jsonrpc_error_code(data)})"
            )

        sub_floor, unreached = await self._sweep(ctx)
        if sub_floor:
            return (
                "1.1a",
                "fail",
                (
                    f"serves {', '.join(sub_floor)}, earlier than the "
                    f"{FLOOR_REVISION} floor this Recommendation sets, so an "
                    f"unapproved revision is reachable by negotiation; the operator "
                    f"allowlist itself was not read{discover_note}"
                ),
            )
        if unreached:
            # An unreached revision could be the served sub-floor one, so a compliant
            # reading is not attributable. A FAIL above needs no such caution, because
            # a sub-floor revision was positively observed.
            return (
                "1.1a",
                "unknown",
                (
                    f"no revision earlier than the {FLOOR_REVISION} floor was found "
                    f"to be served, but {', '.join(unreached)} could not be probed, "
                    f"so a compliant reading is not attributable{discover_note}"
                ),
            )
        return (
            "1.1a",
            "pass",
            (
                f"no revision earlier than the {FLOOR_REVISION} floor is served; the "
                f"endpoint negotiated {ctx.negotiated_version}. The operator "
                f"allowlist itself was not read, so a revision at or after the floor "
                f"and outside a narrower allowlist is not detected{discover_note}"
            ),
        )

    async def _sweep(self, ctx: ProbeContext) -> tuple[list[str], list[str]]:
        """Offer each sub-floor revision, returning those served and those unreached.

        The specification requires a server to answer with the requested revision
        when it supports it, and with another revision it does support when it does
        not. So an echo equal to the request is positive evidence the endpoint serves
        that revision, which is the same test ``client.py`` applies for the release
        candidate.

        A revision whose probe never completed is returned separately rather than
        dropped. Silently omitting it would let a run where the offending revision
        never answered read as compliant.
        """
        served: list[str] = []
        unreached: list[str] = []
        for revision in SUB_FLOOR_REVISIONS:
            payload = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": revision,
                    "capabilities": {},
                    "clientInfo": _AUDIT_META["io.modelcontextprotocol/clientInfo"],
                },
            }
            try:
                _status, data, _text = await raw_jsonrpc(
                    ctx.endpoint_url or "", payload, token=ctx.access_token
                )
            except Exception as exc:  # noqa: BLE001 — one revision failing is not fatal
                ctx.errors.append(f"1.1a sweep {revision}: {exc!r}")
                unreached.append(revision)
                continue
            result = (data or {}).get("result")
            if isinstance(result, dict) and result.get("protocolVersion") == revision:
                served.append(revision)
        return served, unreached

    async def _wire_legs(self, ctx: ProbeContext) -> list[tuple[str, str, str]]:
        """The four malformed-assertion probes, adapted to the negotiated revision."""
        endpoint, token, sid = ctx.endpoint_url or "", ctx.access_token, ctx.session_id

        async def send(payload, **kwargs):
            """Send one probe, reporting a transport failure rather than raising.

            A dropped connection on one probe must not take the whole check out as a
            raised exception: the other legs still have something to say, and the
            evidence should name which probe could not be sent.
            """
            try:
                return await raw_jsonrpc(
                    endpoint, payload, token=token, session_id=sid, **kwargs
                )
            except Exception as exc:  # noqa: BLE001 — reported as an unreachable probe
                ctx.errors.append(f"1.1 probe: {exc!r}")
                return 0, None, f"__transport_failure__ {exc!r}"

        if ctx.rc_supported:
            b = await send(_tools_list(BOGUS_VERSION), protocol_header=BOGUS_VERSION)
            c = await send(_tools_list(RC_VERSION), omit_protocol_header=True)
            d = await send(_tools_list(), protocol_header=RC_VERSION)
            e = await send(_tools_list(RC_VERSION), protocol_header=STALE_VERSION)
            legs = [
                ("1.1b", *_leg_1_1b(*b)),
                ("1.1c", *_leg_1_1c(*c)),
                ("1.1d", *_leg_1_1d(*d)),
                ("1.1e", *_leg_1_1e(*e)),
            ]
            return [(leg, outcome, note) for leg, outcome, note in legs]

        # Before 2026-07-28 the version travels in the header alone, so the body
        # carries no version to omit and none to disagree with the header. Legs 1.1d
        # and 1.1e have no request to send and report that, rather than passing on a
        # probe that tested nothing. The two that do run still carry the auditor's
        # clientInfo in _meta, so an operator reading their own logs can tell this
        # probe's traffic from a real client's.
        b = await send(_tools_list(), protocol_header=BOGUS_VERSION)
        c = await send(_tools_list(), omit_protocol_header=True)
        b_outcome, b_note = _leg_1_1b(*b)
        c_outcome, c_note = _leg_1_1c(*c)
        unsupported = (
            f"needs the header and _meta version pair that only {RC_VERSION} "
            f"defines; this server negotiated {ctx.negotiated_version}"
        )
        return [
            ("1.1b", b_outcome, f"{b_note}, asserted in the header"),
            (
                "1.1c",
                c_outcome,
                (
                    f"{c_note}, header omitted; before {RC_VERSION} there is no "
                    f"_meta version for the header to be compared against, so a "
                    f"server has only the omission to reject"
                ),
            ),
            ("1.1d", "revision_unsupported", unsupported),
            ("1.1e", "revision_unsupported", unsupported),
        ]


@register
class CapabilityBaseline(Check):
    """1.2, Assessment Status: Manual.

    The comparison is scripted; approving a baseline is the operator's judgement, so
    the audit calls the Recommendation manual. This probe compares against a baseline
    it recorded itself rather than an approved one.
    """

    id = "1.2"
    title = "Advertised capability configuration matches the recorded baseline"
    section = "1"
    level = Level.L1
    remediation = (
        "Approve any new or changed capability setting into the baseline held in the "
        "enterprise MCP registry, or disable it on the server. An advertised "
        "configuration that exceeds or differs from the approved one is unauthorized "
        "drift."
    )

    REDUCTION = (
        " compared against the baseline this probe recorded for the endpoint, not "
        "against a registry-approved configuration under change control"
    )

    async def run(self, ctx: ProbeContext) -> CheckResult:
        if ctx.init_result is None or not ctx.endpoint_url:
            return self._error("no session; cannot read advertised capabilities")

        current = baseline.snapshot(ctx)
        leaves = current["capability_leaves"]

        if ctx.update_baseline:
            path = baseline.save(ctx.endpoint_url, current)
            return self._unknown(
                f"baseline captured this run ({len(leaves)} capability leaf/leaves, "
                f"{len(current['tools'])} tool(s)), so there was nothing to compare "
                f"against. Re-run without --update-baseline to decide drift",
                saved_to=str(path),
            )

        recorded = baseline.load(ctx.endpoint_url)
        if recorded is None:
            return self._unknown(
                "no baseline recorded yet for this endpoint; run once with "
                "--update-baseline to establish one"
            )

        legs = [self._leg_a(recorded, current, leaves), self._leg_b(recorded, current)]
        return _resolve(
            self,
            legs,
            suffix=self.REDUCTION,
            capability_leaves_advertised=len(leaves),
            capability_substrate=current["capability_substrate"],
        )

    def _leg_a(self, recorded, current, leaves) -> tuple[str, str, str]:
        """The nested capability comparison, which is where 1.2's verdict comes from.

        Four causes of UNKNOWN and they are not interchangeable, so each names itself:
        three are cleared by re-recording the baseline and total withdrawal is not.
        """
        changes, undecidable = baseline.compare_leaves(recorded, current)
        if undecidable == "record":
            return (
                "1.2a",
                "unknown",
                (
                    "the recorded baseline predates capability-leaf capture, so a "
                    "comparison would decide nothing; re-run with --update-baseline"
                ),
            )
        if undecidable == "substrate":
            return (
                "1.2a",
                "unknown",
                (
                    f"the baseline records the capability object read from "
                    f"{recorded.get('capability_substrate')!r} and this run read "
                    f"{current['capability_substrate']!r}; two substrates are two "
                    f"objects, so the difference is not drift. Re-run with "
                    f"--update-baseline"
                ),
            )
        if undecidable == "current":
            return "1.2a", "unknown", "this run observed no capability object"

        parts = [
            f"{label}: {', '.join(baseline.render_leaf(i) for i in items)}"
            for label, items in (
                ("unapproved", changes["added"]),
                ("changed", changes["changed"]),
                ("withdrawn", changes["withdrawn"]),
            )
            if items
        ]
        detail = "; ".join(parts)
        if changes["added"] or changes["changed"]:
            return (
                "1.2a",
                "fail",
                (
                    f"the advertised capability configuration exceeds or differs from "
                    f"the recorded baseline -> {detail}"
                ),
            )
        if changes["withdrawn"] and not leaves:
            return (
                "1.2a",
                "unknown",
                (
                    f"every recorded capability leaf is gone and none is advertised, "
                    f"which is more likely a read that returned nothing than a "
                    f"reconfiguration -> {detail}"
                ),
            )
        if changes["withdrawn"]:
            return (
                "1.2a",
                "pass",
                (
                    f"the advertised configuration adds and changes nothing, and some "
                    f"recorded settings are no longer advertised -> {detail}"
                ),
            )
        return "1.2a", "pass", "the advertised capability configuration matches the baseline"

    def _leg_b(self, recorded, current) -> tuple[str, str, str]:
        """Tool, resource and prompt name drift, reported and gating nothing.

        This Recommendation's audit compares the capability configuration object, and
        a tool name is not part of it, so a newly advertised name is reported here
        rather than failing the check. Check 1.3 invokes such a tool and decides
        whether it was gated.
        """
        added = baseline.diff(recorded, current)
        names = {k: v for k, v in added.items() if k != "capability_keys"}
        if not names:
            return "1.2b", "pass", "no new tool, resource or prompt name"
        detail = "; ".join(f"{cat}: {', '.join(items)}" for cat, items in names.items())
        return (
            "1.2b",
            "pass",
            (
                f"new name(s) advertised since the baseline, reported and not gating "
                f"this verdict -> {detail}"
            ),
        )


@register
class StagedCapabilityGating(Check):
    """1.3, Assessment Status: Manual.

    The audit's log leg is not probed. Both tool calls carry empty arguments.
    """

    id = "1.3"
    title = "A capability advertised beyond the baseline is denied until re-approved"
    section = "1"
    level = Level.L2
    remediation = (
        "Hold a capability advertised beyond the approved baseline in a staging "
        "state, deny invocation until an explicit re-approval is recorded, and make "
        "the denial name the pending or unauthorized state."
    )

    DENY_PATTERN = re.compile(
        r"pending|not approved|unapproved|unauthori[sz]ed|awaiting approval|forbidden|denied",
        re.IGNORECASE,
    )

    async def run(self, ctx: ProbeContext) -> CheckResult:
        if ctx.session is None or not ctx.endpoint_url:
            return self._error("no live session")

        recorded = baseline.load(ctx.endpoint_url)
        if recorded is None or ctx.update_baseline:
            return self._unknown(
                "no baseline to identify a capability advertised beyond it; run once "
                "with --update-baseline, then again to decide"
            )

        advertised = {t.name for t in ctx.tools}
        baselined = set(recorded.get("tools") or [])
        staged_names = advertised - baselined
        control_names = advertised & baselined

        # Order matters: a server advertising no tools satisfies both emptiness tests,
        # and "nothing was advertised beyond the baseline" is the true reading.
        if not staged_names:
            return self._unknown(
                f"no tool is advertised beyond the recorded baseline "
                f"({len(advertised)} advertised, all recorded), so no staged "
                f"capability exists to be gated" + DROPPED_1_3B
            )
        if not control_names:
            return self._unknown(
                "no recorded tool is still advertised, so no control probe is "
                "available and a denial would not be attributable to a staging "
                "gate; re-run with --update-baseline" + DROPPED_1_3B
            )

        supplied = inputs.tool_arguments(ctx.domain)
        staged = _prefer_read_only(ctx.tools, staged_names, supplied)
        control = _prefer_read_only(ctx.tools, control_names, supplied)

        control_ok, control_note = await self._control(ctx, control, supplied)
        if not control_ok:
            hint = (
                ""
                if control in supplied
                else (
                    f". Supply arguments for {control!r} under tool_arguments in "
                    f"probe-inputs.json to make this leg decidable"
                )
            )
            return self._error(
                f"1.3a: {control_note}, so a failure on {staged!r} would not be "
                f"attributable to a staging gate{hint}" + DROPPED_1_3B,
                control_tool=control,
                staged_tool=staged,
                arguments_supplied=sorted(supplied),
            )

        legs = [await self._leg_a(ctx, staged, control, supplied)]
        return _resolve(
            self,
            legs,
            suffix=DROPPED_1_3B,
            arguments_supplied=sorted(supplied),
            control_tool=control,
            staged_tool=staged,
        )

    async def _control(
        self, ctx: ProbeContext, control: str, supplied: dict[str, dict]
    ) -> tuple[bool, str]:
        """Call a baselined tool and require it to execute cleanly.

        Without this the check cannot tell a staging gate from a tool that simply
        does not work with the arguments we can supply.
        """
        status, data, _text = await self._call(ctx, control, supplied.get(control))
        if data is None:
            return False, f"the control probe on {control!r} returned no JSON (HTTP {status})"
        if jsonrpc_error_code(data) is not None:
            return False, (
                f"the control probe on {control!r} was rejected with code "
                f"{jsonrpc_error_code(data)}"
            )
        result = data.get("result")
        if not isinstance(result, dict):
            return False, f"the control probe on {control!r} returned neither result nor error"
        if result.get("isError") is True:
            return False, (
                f"the control probe on {control!r} did not execute cleanly, most "
                f"likely because it needs arguments this probe cannot supply"
            )
        return True, f"the control probe on {control!r} executed cleanly"

    async def _leg_a(
        self, ctx: ProbeContext, staged: str, control: str, supplied: dict[str, dict]
    ) -> tuple[str, str, str]:
        """Invoke the staged tool and read whether a gate intercepted it.

        A denial arrives on one of two carriers and either is accepted: a JSON-RPC
        error from a gateway or middleware, or a result carrying ``isError`` from a
        gate inside the server's own tool handling, since a tool handler cannot emit
        a protocol error. Both arrive at HTTP 200.
        """
        status, data, _text = await self._call(ctx, staged, supplied.get(staged))
        if data is None:
            return "1.3a", "error", f"the staged probe on {staged!r} returned no JSON (HTTP {status})"

        code = jsonrpc_error_code(data)
        if code == -32601:
            return (
                "1.3a",
                "unknown",
                (
                    f"{staged!r} did not resolve as a method, so nothing was tested "
                    f"about a staging gate"
                ),
            )
        if code == INVALID_PARAMS:
            return (
                "1.3a",
                "fail",
                (
                    f"{staged!r} resolved and was validated for arguments, so no gate "
                    f"intercepted it before the server began handling it "
                    f"(control: {control!r} executed cleanly)"
                ),
            )
        if code is not None:
            message = str((data.get("error") or {}).get("message") or "")
            return self._denial("1.3a", staged, control, message, "a protocol error", code)

        result = data.get("result")
        if isinstance(result, dict) and result.get("isError") is True:
            return self._denial(
                "1.3a", staged, control, self._text_of(result), "an in-band tool error", None
            )
        if isinstance(result, dict):
            return (
                "1.3a",
                "fail",
                (
                    f"{staged!r} executed, so no approval gate is enforced on a "
                    f"capability advertised beyond the baseline"
                ),
            )
        return "1.3a", "error", f"the staged probe on {staged!r} carried neither result nor error"

    def _denial(self, leg, staged, control, message, carrier, code) -> tuple[str, str, str]:
        """A rejection passes only when its wording names the gate.

        Both calls carry empty arguments, so an argument-validation failure reads
        identically to a gate denial on either carrier. Requiring the wording is
        what keeps that from being read as compliance.
        """
        at = f" (code {code})" if code is not None else ""
        if self.DENY_PATTERN.search(message):
            return (
                leg,
                "pass",
                (
                    f"{staged!r} was denied on {carrier}{at} naming a pending or "
                    f"unauthorized state, while the control {control!r} executed "
                    f"cleanly: {message[:160]!r}"
                ),
            )
        return (
            leg,
            "unknown",
            (
                f"{staged!r} was rejected on {carrier}{at} but the message names no "
                f"pending or unauthorized state, and this probe calls with empty "
                f"arguments, so an argument-validation failure reads identically: "
                f"{message[:160]!r}"
            ),
        )

    async def _call(self, ctx: ProbeContext, tool: str, arguments: dict | None = None):
        """Invoke ``tool`` with the operator's arguments, or with none.

        With no arguments supplied, a tool whose arguments are required answers with
        a validation error that reads exactly like a gate denial. That is why an
        unmatched rejection is UNKNOWN and why the control failing is ERROR.
        """
        return await raw_jsonrpc(
            ctx.endpoint_url or "",
            {
                "jsonrpc": "2.0",
                "id": 9,
                "method": "tools/call",
                "params": {"name": tool, "arguments": arguments or {}},
            },
            token=ctx.access_token,
            session_id=ctx.session_id,
        )

    @staticmethod
    def _text_of(result: dict[str, Any]) -> str:
        content = result.get("content")
        if not isinstance(content, list):
            return ""
        return " ".join(
            str(part.get("text", ""))
            for part in content
            if isinstance(part, dict) and part.get("type") == "text"
        )


@register
class ServerIdentityDrift(Check):
    """1.4, Assessment Status: Automated.

    The audit's identity-recording leg reads a deployment capture window and is not
    probed. The verdict comes from its registry comparison, reduced to the identity
    this probe recorded itself.

    The identity comes from the ``initialize`` result, where the schema requires it.
    From 2026-07-28 a server asserts it per response in ``_meta`` instead, and reading
    it from there is deferred rather than done here: the baseline holds one record per
    endpoint and three checks write it, so a check that sourced the identity
    differently from the others would have its value overwritten by whichever wrote
    last, and the next run would read the difference as drift and fail a server that
    changed nothing. Wiring the per-response ``_meta`` identity onto the context as one
    shared observation is the fix, alongside the same change for the capability object.
    """

    id = "1.4"
    title = "Server identity matches the recorded identity (no unregistered identity)"
    section = "1"
    level = Level.L1
    remediation = (
        "Register the server's asserted name and version in the enterprise MCP "
        "registry and re-approve the entry on every version change. An identity "
        "observed but not registered is unauthorized asset expansion."
    )

    async def run(self, ctx: ProbeContext) -> CheckResult:
        if ctx.init_result is None or not ctx.endpoint_url:
            return self._error("no session; server identity unavailable")

        current = baseline.snapshot(ctx)
        server_info = getattr(ctx.init_result, "serverInfo", None)
        observed = current["server_identity"]

        if ctx.update_baseline:
            baseline.save(ctx.endpoint_url, current)
            return self._unknown(
                f"identity recorded this run ({observed[0] if observed else 'none asserted'}), "
                f"so there was nothing to compare against. Re-run without "
                f"--update-baseline to decide drift"
            )

        recorded = baseline.load(ctx.endpoint_url)
        legs = [
            self._leg_a(server_info, observed),
            self._leg_b(recorded or {}, current, observed),
        ]
        return _resolve(self, legs, suffix=DROPPED_1_4B_REVIEW)

    def _leg_a(self, server_info: Any, observed: list[str] | None) -> tuple[str, str, str]:
        """Whether the asserted identity is well formed, reported and gating nothing.

        The audit names no malformed-identity FAIL: its one malformed branch is the
        registry-delimiter check and its outcome is REVIEW. And the schema makes the
        per-response identity optional from 2026-07-28, so an omission conforms. So
        this observation is evidence, and the verdict comes from leg 1.4b.
        """
        if server_info is None:
            return "1.4a", "pass", "the server asserts no identity, which the schema permits"
        pair = observed[0] if observed else None
        if pair is None:
            return (
                "1.4a",
                "pass",
                (
                    "the server asserts an identity carrying no usable name, recorded as "
                    "a metadata-validation finding and not as a verdict"
                ),
            )
        name, _, version = pair.partition("|")
        notes = []
        if not version:
            notes.append("no version asserted")
        if "|" in name or "|" in version:
            notes.append("contains the registry delimiter, so it cannot be represented as name|version")
        if notes:
            return "1.4a", "pass", f"identity {pair!r}: {', '.join(notes)}"
        return "1.4a", "pass", f"identity {pair!r} is well formed"

    def _leg_b(self, recorded, current, observed) -> tuple[str, str, str]:
        """The registry comparison, reduced to the identity we recorded.

        An observed identity absent from the approved list is what this
        Recommendation calls unauthorized asset expansion, and it is the FAIL
        condition the audit names. Only the server side is compared: this probe is
        the client, so comparing client identity would measure this tool.
        """
        added, missing_in = baseline.compare_category(recorded, current, "server_identity")
        if missing_in == "record":
            return (
                "1.4b",
                "unknown",
                (
                    "no server identity recorded yet for this endpoint; run once with "
                    "--update-baseline to establish one"
                ),
            )
        if missing_in == "current":
            return "1.4b", "unknown", "this run observed no server identity to compare"
        if added:
            return (
                "1.4b",
                "fail",
                (
                    f"the server asserts {', '.join(added)}, which is absent from the "
                    f"recorded identity {', '.join(recorded.get('server_identity') or [])}. "
                    f"An identity observed and not approved is unauthorized asset "
                    f"expansion; re-approve it with --update-baseline if the change is "
                    f"intended"
                ),
            )
        return (
            "1.4b",
            "pass",
            f"the asserted identity {', '.join(observed or [])} matches the recorded one",
        )
