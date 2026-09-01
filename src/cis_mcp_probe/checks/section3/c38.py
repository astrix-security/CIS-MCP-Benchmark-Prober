"""Check 3.8: scope minimization.

Six legs, in order:

* ``3.8a`` — the scopes we were granted are readable at all.
* ``3.8b`` — no granted scope is a wildcard.
* ``3.8c`` — the granted set has not grown since the baseline we recorded.
* ``3.8d`` — the advertised ``scopes_supported`` carries no wildcard and no
  admin-tier scope.
* ``3.8e`` — a tool the operator names as outside our grant is refused rather
  than executed.
* ``3.8f`` — at least one of the three scope-discovery sources carries a value,
  and a source this run never read leaves the leg undecided rather than failed.

The two decisions that are easy to get backwards live in module-level functions
so they can be exercised without a server: leg 3.8c must not read an
undecidable baseline category as drift, and leg 3.8f must consult all three
scope-discovery sources before concluding a client has no way to learn what to
request.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from ... import baseline, inputs
from ...context import ProbeContext
from ...tokens import has_admin_tier, has_wildcard, jwt_claims, observed_scopes
from ..base import Check, CheckResult, Level, Status, register
from .observations import guard_refused, unread

# Substrings that make a tool refusal attributable to authorization rather than
# to the call itself. An ``insufficient_scope`` error names the scope it
# required, so it needs no positive control to interpret.
AUTHORIZATION_MARKERS = (
    "insufficient_scope",
    "insufficient scope",
    "scope",
    "unauthorized",
    "forbidden",
    "access denied",
    "permission",
    "401",
    "403",
)

# What this check cannot see, stated in the verdict rather than only here.
REDUCTION = (
    " Reduced scope: this reads the wire and the baseline we recorded ourselves. "
    "The operator's documented justification for a scope is not readable from a "
    "client, so a documented exception for a flagged scope would change 3.8b and "
    "3.8d."
)


def _string_list(value: Any) -> list[str]:
    """Return a server-supplied JSON value as a list of strings.

    Anything that is not a list of strings carries no scope, so it yields [].
    """
    if isinstance(value, list):
        return [s for s in value if isinstance(s, str)]
    return []


def _scopes_supported(documents: Iterable[dict | None]) -> list[str]:
    """Collect ``scopes_supported`` across documents, deduplicated, first seen first."""
    found: list[str] = []
    for document in documents:
        for scope in _string_list((document or {}).get("scopes_supported")):
            if scope not in found:
                found.append(scope)
    return found


def _unread_servers(ctx: ProbeContext) -> list[str]:
    """The advertised authorization servers whose metadata this run never read.

    ``as_metadata_by_issuer`` is keyed by the advertised entry and holds
    successes only, so an entry missing from it was advertised but never
    observed: a fetch that timed out or failed, a URL the host guard refused, or
    an entry past the resolution cap. The document is server-controlled, so
    every element is type-checked.
    """
    advertised = (ctx.protected_resource_metadata or {}).get("authorization_servers")
    if not isinstance(advertised, list):
        return []
    return [
        entry
        for entry in advertised
        if isinstance(entry, str)
        and entry.strip()
        and entry not in ctx.as_metadata_by_issuer
    ]


def baseline_outcome(
    record: dict[str, Any] | None,
    current: dict[str, Any],
    update_baseline: bool,
    baseline_written: bool = True,
) -> tuple[str, str]:
    """Decide leg 3.8c: has the granted scope set grown since we recorded it?

    ``unknown`` covers every case where nothing was compared: a capture run, no
    record yet, and a record that has no value for the scope category. A record
    written before this category was captured is not evidence that anything
    grew — reading its absence as drift would report every granted scope as
    newly added.

    ``baseline_written`` is read only on a capture run, and says whether a
    record was actually stored: a capture the run declined to write is still
    undecided, but reporting it as captured would claim a snapshot that no file
    holds.
    """
    if update_baseline:
        if not baseline_written:
            return (
                "unknown",
                "this run asked to capture a baseline, but no MCP session was "
                "established, so no baseline was written and nothing was compared",
            )
        return "unknown", "baseline captured this run, so nothing was compared"
    if record is None:
        return "unknown", "no baseline recorded yet for this endpoint"
    added, missing_in = baseline.compare_category(record, current, "scopes")
    if missing_in == "record":
        return (
            "unknown",
            "the baseline record carries no scope set, so scope growth is not "
            "decidable against it",
        )
    if missing_in == "current":
        return (
            "unknown",
            "this run read no granted scope, so there is nothing to compare "
            "against the recorded set -- a run that compared nothing cannot "
            "report that nothing grew",
        )
    if added:
        return "fail", "scopes added since the recorded baseline: " + ", ".join(added)
    return "pass", "granted scopes are within the recorded baseline"


def discovery_outcome(
    challenge_scope: str | None,
    resource_scopes: list[str],
    as_scopes: list[str],
    unread_servers: Iterable[str] = (),
    guard_refused: Iterable[str] = (),
    unanswered_resource_paths: Iterable[str] = (),
) -> tuple[str, str]:
    """Decide leg 3.8f: can a client discover the scopes it has to request?

    Three sources, in the order a client reads them: the challenge ``scope``
    parameter, the protected-resource ``scopes_supported``, then the
    authorization server's own ``scopes_supported``. A client that gets no
    answer from the first two still learns what to request from the third, so
    only the absence of all three means no discovery path exists.

    Failing needs all three absent *and* observed, and either of the two
    documents can be the one this run never read. ``unanswered_resource_paths``
    names the protected-resource discovery attempts that left no answer, and
    ``unread_servers`` names advertised authorization servers whose metadata was
    never read; with either outstanding the leg is undecided, because "we could
    not read it" is not "it advertises nothing". ``guard_refused`` names the URLs
    the host guard refused, which is why some of them were never read.

    A challenge that disagrees with the advertised set is still a discovery
    path; the disagreement is reported, not failed.
    """
    present = []
    if challenge_scope:
        present.append(f"challenge scope {challenge_scope!r}")
    if resource_scopes:
        present.append(
            "protected-resource scopes_supported " + ", ".join(resource_scopes)
        )
    if as_scopes:
        present.append("authorization-server scopes_supported " + ", ".join(as_scopes))

    if not present:
        unanswered = list(unanswered_resource_paths)
        unread = list(unread_servers)
        reasons = []
        if unanswered:
            reasons.append(
                "no protected-resource metadata was read, so its scopes_supported "
                "was never seen: " + "; ".join(unanswered)
            )
        if unread:
            reasons.append(
                "the metadata of advertised authorization server(s) was never "
                "read, so their scopes_supported was never seen: " + ", ".join(unread)
            )
        if reasons:
            note = "no scope-discovery source was observed, but " + " and ".join(
                reasons
            )
            refused = list(guard_refused)
            if refused:
                note += ". The host guard refused " + ", ".join(refused)
            return "unknown", note
        return (
            "fail",
            "no scope-discovery source: the challenge carried no scope parameter, "
            "and neither the protected-resource nor the authorization-server "
            "metadata advertises scopes_supported",
        )

    note = "scopes discoverable from " + "; ".join(present)
    advertised = set(resource_scopes) | set(as_scopes)
    if challenge_scope and advertised and set(challenge_scope.split()) != advertised:
        note += (
            f" — the challenge names {challenge_scope!r} while the advertised set "
            f"is {', '.join(sorted(advertised))}"
        )
    return "pass", note


def _result_text(result: Any) -> str:
    """Flatten a tool result's content blocks into one string for classification."""
    blocks = getattr(result, "content", None) or []
    parts = [getattr(block, "text", "") for block in blocks]
    return " ".join(p for p in parts if p) or repr(result)


def _classify_refusal(tool: str, text: str) -> tuple[str, str]:
    """Read a refusal of the operator-named tool.

    A refusal that names an authorization failure is attributable to scope
    enforcement. A refusal for any other reason — a rejected argument, an
    unknown tool name — says nothing about scope, so the leg stays undecided.
    """
    excerpt = text[:200]
    if any(marker in text.lower() for marker in AUTHORIZATION_MARKERS):
        return "pass", f"{tool!r} was refused on authorization grounds: {excerpt}"
    return (
        "unknown",
        f"{tool!r} was refused for a reason that names no authorization failure: "
        f"{excerpt}",
    )


@register
class ScopeMinimization(Check):
    """3.8, Assessment Status: Automated.

    Reads the granted scopes and the advertised surface, compares the granted
    set against our own recorded baseline, and calls the tool the operator names
    as outside our grant.
    """

    id = "3.8"
    title = "Granted OAuth scopes are minimized to what the client needs"
    section = "3"
    level = Level.L2
    remediation = (
        "Grant each client only the scopes its tools require, and remove "
        "wildcard and admin-tier scopes from both the issued token and the "
        "advertised scopes_supported. Enforce the granted scope at the tool "
        "dispatcher so an out-of-scope call is refused with insufficient_scope "
        "before it executes, and advertise the scopes a client must request in "
        "the protected-resource metadata or the challenge."
    )

    async def run(self, ctx: ProbeContext) -> CheckResult:
        if not ctx.endpoint_url:
            return self._error("no live session to test against")

        claims = jwt_claims(ctx.access_token or "")
        granted = observed_scopes(ctx.token_scope, claims)
        resource_scopes = _scopes_supported([ctx.protected_resource_metadata])
        as_scopes = _scopes_supported(ctx.as_metadata_by_issuer.values())

        # A 401 challenge is itself proof the server does OAuth, so a run whose
        # discovery all failed and that obtained no token is undecided, not
        # vacuous. Checks 3.4 and 3.5 draw the same line.
        if not (
            ctx.auth_required
            or ctx.access_token
            or ctx.prm_documents
            or ctx.as_metadata_by_issuer
            or ctx.challenge_scope
        ):
            return self._na(
                "the server offers no OAuth at all: no unauthenticated request "
                "drew a 401 challenge, no token was issued, no "
                "protected-resource metadata was served, and no challenge named "
                "a scope, so there is no granted or advertised scope to minimize. "
                "The benchmark specifies ERROR for a discovery chain that "
                "resolves to nothing; ERROR is reserved here for a failure on "
                "our own side, and a server that never offered OAuth is not that",
                legs={},
                challenge_scope=ctx.challenge_scope,
            )

        results: list[tuple[str, str, str]] = []

        # 3.8a — an opaque token whose response omitted "scope" carries nothing
        # readable, which is undecided rather than a grant of zero scopes. A
        # response that states an empty scope set is the other case: that was
        # observed, so it decides, and leg 3.8c reads the same signal.
        if granted is None:
            results.append(
                (
                    "3.8a",
                    "unknown",
                    "no granted scope is readable: neither the token response nor "
                    "the token body stated one",
                )
            )
        elif granted:
            results.append(
                ("3.8a", "pass", "granted scopes read: " + " ".join(granted))
            )
        else:
            results.append(
                (
                    "3.8a",
                    "pass",
                    "the granted scope set was stated and is empty, so no scope is "
                    "granted at all",
                )
            )

        # 3.8b
        granted_wildcards = has_wildcard(granted or [])
        if granted is None:
            results.append(("3.8b", "unknown", "no granted scope to inspect"))
        elif not granted:
            results.append(
                (
                    "3.8b",
                    "pass",
                    "the granted scope set is empty, so no granted scope is a wildcard",
                )
            )
        elif granted_wildcards:
            results.append(
                (
                    "3.8b",
                    "fail",
                    "wildcard scope granted: "
                    + ", ".join(granted_wildcards)
                    + ". A documented operator exception for this grant would "
                    "change this outcome",
                )
            )
        else:
            results.append(
                ("3.8b", "pass", "no granted scope is a wildcard: " + " ".join(granted))
            )

        # 3.8c — capture only what an established session backs, the same
        # condition check 1.2 puts on its own save. Without a session the
        # snapshot carries no capabilities and no tools, and storing it would
        # overwrite a good record with an empty one, which check 1.2 would then
        # read as capability drift on every later run.
        current = baseline.snapshot(ctx)
        baseline_written = ctx.update_baseline and ctx.init_result is not None
        if baseline_written:
            baseline.save(ctx.endpoint_url, current)
        record = None if ctx.update_baseline else baseline.load(ctx.endpoint_url)
        outcome, note = baseline_outcome(
            record, current, ctx.update_baseline, baseline_written
        )
        results.append(("3.8c", outcome, note))

        # 3.8d — the advertised surface is the protected-resource document's own
        # scopes_supported, the single field, not every document that answered.
        advertised_wildcards = has_wildcard(resource_scopes)
        flagged = advertised_wildcards + [
            s for s in has_admin_tier(resource_scopes) if s not in advertised_wildcards
        ]
        if not resource_scopes:
            results.append(
                (
                    "3.8d",
                    "unknown",
                    "the protected-resource metadata advertises no "
                    "scopes_supported to inspect",
                )
            )
        elif flagged:
            results.append(
                (
                    "3.8d",
                    "fail",
                    "the advertised surface carries a wildcard or admin-tier "
                    "scope: " + ", ".join(flagged),
                )
            )
        else:
            results.append(
                (
                    "3.8d",
                    "pass",
                    "advertised scopes_supported carries no wildcard and no "
                    "admin-tier scope: " + ", ".join(resource_scopes),
                )
            )

        # 3.8e
        entry = inputs.load(ctx.domain)
        outcome, note = await self._call_named_tool(
            ctx, entry.get("scope_probe_tool"), entry.get("scope_probe_arguments") or {}
        )
        results.append(("3.8e", outcome, note))

        # 3.8f — either document can be the one this run never read, so the
        # protected-resource attempts are consulted too. A document that answered
        # and carries no scopes_supported is an observed absence; a path that
        # never answered is not.
        outcome, note = discovery_outcome(
            ctx.challenge_scope,
            resource_scopes,
            as_scopes,
            _unread_servers(ctx),
            guard_refused(ctx, "as:"),
            unread(ctx, "prm:"),
        )
        results.append(("3.8f", outcome, note))

        details = {
            "legs": {leg: outcome for leg, outcome, _ in results},
            "challenge_scope": ctx.challenge_scope,
            "granted_scopes": granted,
            "advertised_scopes": resource_scopes,
            "authorization_server_scopes": as_scopes,
        }
        evidence = "; ".join(f"{leg}: {note}" for leg, _, note in results) + REDUCTION
        outcomes = {outcome for _, outcome, _ in results}

        if "fail" in outcomes:
            return self._fail(evidence, **details)
        if "error" in outcomes:
            return self._error(evidence, **details)
        if "unknown" in outcomes:
            return self._unknown(evidence, **details)
        return self._pass(evidence, **details)

    async def _call_named_tool(
        self, ctx: ProbeContext, tool: Any, arguments: Any
    ) -> tuple[str, str]:
        """Leg 3.8e: call the tool the operator named as outside our grant.

        The name and the arguments both come from the operator; nothing is
        fabricated here, and no other tool is called. Execution means the
        granted scope was not enforced before the call ran.
        """
        if not isinstance(tool, str) or not tool:
            return (
                "unknown",
                f"no scope_probe_tool is named for {ctx.domain}, so no "
                "out-of-scope call was made",
            )
        if not isinstance(arguments, dict):
            return (
                "unknown",
                f"scope_probe_arguments for {ctx.domain} is not an object, so "
                f"{tool!r} was not called",
            )
        if ctx.session is None:
            return "error", f"no live session to call {tool!r} with"
        try:
            result = await ctx.session.call_tool(tool, arguments)
        except Exception as exc:  # noqa: BLE001 — a refusal arrives as an exception
            return _classify_refusal(tool, repr(exc))
        if getattr(result, "isError", False):
            return _classify_refusal(tool, _result_text(result))
        return (
            "fail",
            f"{tool!r} executed, so the granted scope was not enforced before "
            "execution. The operator names this tool as outside our grant",
        )


if __name__ == "__main__":
    current = {"scopes": ["read", "write"]}

    # 3.8c: a record that cannot decide the scope category never reports drift.
    # A record from before the category was captured, and one that stored None,
    # are both undecidable — reading either as drift would name every granted
    # scope as newly added.
    for stored in ({"tools": ["a"]}, {"scopes": None}):
        outcome, note = baseline_outcome(stored, current, False)
        assert outcome == "unknown", (stored, outcome, note)
    # test-type: regression | source: live run 2026-08-31 against mcp.stripe.com --
    # an unauthenticated pass read no granted scope and reported leg 3.8c "pass"
    # against a stored record holding ['mcp'].
    #
    # A run that read no scope compared nothing, so it cannot report that nothing
    # grew. This is the case that passed vacuously: an unauthenticated run against
    # a record holding a real scope set reported "within the recorded baseline".
    for blind in ({"scopes": None}, {}):
        outcome, note = baseline_outcome({"scopes": ["mcp"]}, blind, False)
        assert outcome == "unknown", (blind, outcome, note)
        assert "this run read no granted scope" in note, note
    # An observed-and-empty scope set is an observation, so it still decides.
    assert baseline_outcome({"scopes": ["read"]}, {"scopes": []}, False)[0] == "pass"
    # A record that can decide reports a real addition, and only the addition.
    outcome, note = baseline_outcome({"scopes": ["read"]}, current, False)
    assert outcome == "fail" and "write" in note and "read" not in note, (outcome, note)
    assert baseline_outcome({"scopes": ["read", "write"]}, current, False)[0] == "pass"
    # A capture run compares nothing, and neither does a first-ever run.
    assert baseline_outcome({"scopes": ["read"]}, current, True)[0] == "unknown"
    assert baseline_outcome(None, current, False)[0] == "unknown"

    # 3.8c's other half: a capture run must store nothing when no MCP session was
    # established, because the snapshot then carries no capabilities and no tools.
    # Storage is redirected to a temporary directory so no real record is touched.
    import asyncio
    import json
    import tempfile
    from pathlib import Path

    from mcp import types

    from ...context import HttpObservation

    tmp = Path(tempfile.mkdtemp())
    baseline.DATA_DIR = tmp / "baselines"
    inputs.PATH = tmp / "probe-inputs.json"  # absent, so 3.8e stays undecided

    endpoint = "https://mcp.example.com/mcp"
    recorded = {
        "endpoint": endpoint,
        "capability_keys": ["tools"],
        "tools": ["create_issue", "search_issues"],
        "resources": [],
        "prompts": [],
        "scopes": ["read"],
        "authorization_servers": None,
    }
    record_path = baseline.save(endpoint, recorded)

    captured_prm = "https://mcp.example.com/.well-known/oauth-protected-resource"

    def capture_run(**ctx_fields) -> CheckResult:
        """Run the check as `--update-baseline` would, and pin leg 3.8c's outcome."""
        ctx = ProbeContext(
            domain="mcp.example.com",
            base_url="https://mcp.example.com",
            endpoint_url=endpoint,
            update_baseline=True,
            # Survives a failed session, so the no-OAuth-at-all gate stays shut.
            # The fetch that produced the document is recorded alongside it, the
            # way discovery records every attempt before it parses the body.
            prm_documents={captured_prm: {}},
            http={
                f"prm:{captured_prm}": HttpObservation(
                    url=captured_prm, method="GET", status=200
                )
            },
            **ctx_fields,
        )
        result = asyncio.run(ScopeMinimization().run(ctx))
        assert result.details["legs"]["3.8c"] == "unknown", result.details
        return result

    # A detected endpoint with no session: the record on disk is left alone, and
    # the leg says so rather than reporting a capture that did not happen.
    result = capture_run(init_result=None)
    assert json.loads(record_path.read_text()) == recorded, record_path.read_text()
    assert "no baseline was written" in result.evidence, result.evidence
    assert "baseline captured this run" not in result.evidence, result.evidence

    # A session that did establish: the capture is written, tools and all.
    result = capture_run(
        init_result=types.InitializeResult(
            protocolVersion="2025-06-18",
            capabilities=types.ServerCapabilities(tools=types.ToolsCapability()),
            serverInfo=types.Implementation(name="example", version="1.0"),
        ),
        tools=[types.Tool(name="fresh_tool", inputSchema={})],
    )
    assert json.loads(record_path.read_text())["tools"] == [
        "fresh_tool"
    ], record_path.read_text()
    assert "baseline captured this run" in result.evidence, result.evidence

    # 3.8f: three sources. Any one of them is a discovery path.
    assert discovery_outcome("mcp", [], [])[0] == "pass"
    assert discovery_outcome(None, ["read"], [])[0] == "pass"
    assert discovery_outcome(None, [], ["mcp"])[0] == "pass"
    # Only the absence of all three is a failure, and only when all three were
    # observed: nothing advertised leaves nothing unread.
    outcome, note = discovery_outcome(None, [], [])
    assert outcome == "fail", (outcome, note)
    assert discovery_outcome(None, [], [], [], [])[0] == "fail"
    # The protected-resource document is the other source that can go unread. A
    # path that never answered leaves its scopes_supported unobserved, so the
    # leg is undecided rather than failed.
    outcome, note = discovery_outcome(
        None, [], [], [], [], ["https://api.example.com/.well-known/prm (502)"]
    )
    assert outcome == "unknown" and "502" in note, (outcome, note)
    # A path that cleanly answered 404 leaves nothing unanswered, so the absence
    # of all three sources was observed and the leg fails.
    assert discovery_outcome(None, [], [], [], [], [])[0] == "fail"
    # An advertised authorization server whose metadata was never read is
    # undecided instead, and the refusal that explains it is named.
    as_url = "https://as2.example.com/.well-known/oauth-authorization-server"
    outcome, note = discovery_outcome(
        None, [], [], ["https://as2.example.com"], [as_url]
    )
    assert outcome == "unknown", (outcome, note)
    assert "https://as2.example.com" in note and "host guard" in note, note

    # The inputs those two arguments are built from: one advertised server
    # answered with scopes, the other was refused before it was fetched.
    partial = ProbeContext(
        domain="mcp.example.com",
        base_url="https://mcp.example.com",
        protected_resource_metadata={
            "authorization_servers": [
                "https://as1.example.com",
                "https://as2.example.com",
                7,
            ]
        },
        as_metadata_by_issuer={
            "https://as1.example.com": {"scopes_supported": ["mcp"]}
        },
        http={
            f"as:https://as2.example.com:{as_url}": HttpObservation(
                url=as_url, method="GET", error="guard-refused"
            )
        },
    )
    assert _unread_servers(partial) == ["https://as2.example.com"], _unread_servers(
        partial
    )
    assert guard_refused(partial, "as:") == [as_url]
    # The server that did answer carries scopes, so a discovery path exists.
    outcome, note = discovery_outcome(
        None,
        [],
        _scopes_supported(partial.as_metadata_by_issuer.values()),
        _unread_servers(partial),
        guard_refused(partial, "as:"),
    )
    assert outcome == "pass" and "mcp" in note, (outcome, note)

    # The same two inputs read through the check, on a server that answered an
    # unauthenticated request with a 401 challenge and served nothing else.
    prm_url = "https://api.example.com/.well-known/oauth-protected-resource"

    def challenged_run(prm_status: int) -> CheckResult:
        """Run the check where the only OAuth evidence is the 401 challenge."""
        ctx = ProbeContext(
            domain="api.example.com",
            base_url="https://api.example.com",
            endpoint_url="https://api.example.com/mcp",
            auth_required=True,
            http={
                f"prm:{prm_url}": HttpObservation(
                    url=prm_url, method="GET", status=prm_status
                )
            },
        )
        return asyncio.run(ScopeMinimization().run(ctx))

    # A 401 challenge is proof the server does OAuth, so the recommendation
    # applies to it even with every discovery document missing, and a
    # protected-resource path that never answered leaves 3.8f undecided.
    result = challenged_run(502)
    assert result.status is Status.UNKNOWN, (result.status, result.evidence)
    assert result.details["legs"]["3.8f"] == "unknown", result.details
    assert "502" in result.evidence, result.evidence
    # The same server where that path cleanly answered 404: nothing was left
    # unread, so no scope-discovery source exists and 3.8f fails on an
    # observed absence.
    result = challenged_run(404)
    assert result.status is Status.FAIL, (result.status, result.evidence)
    assert result.details["legs"]["3.8f"] == "fail", result.details

    # A server with no OAuth signal at all: no challenge, no token, no document
    # and no advertised scope. The recommendation really is vacuous there.
    bare = ProbeContext(
        domain="api.example.com",
        base_url="https://api.example.com",
        endpoint_url="https://api.example.com/mcp",
    )
    result = asyncio.run(ScopeMinimization().run(bare))
    assert result.status is Status.NOT_APPLICABLE, (result.status, result.evidence)

    # A challenge scope disagreeing with the advertised set still passes, and
    # the disagreement is reported.
    outcome, note = discovery_outcome("admin", ["read"], [])
    assert outcome == "pass" and "admin" in note and "read" in note, (outcome, note)

    # The advertised surface: a wildcard is a trailing "*" segment, and a
    # namespaced scope is not one.
    assert _scopes_supported([{"scopes_supported": ["read", 7, None]}]) == ["read"]
    assert _scopes_supported([None, {}, {"scopes_supported": "read"}]) == []
    assert _scopes_supported(
        [{"scopes_supported": ["read"]}, {"scopes_supported": ["read", "write"]}]
    ) == ["read", "write"]

    # A refusal is a pass only when it says something about authorization.
    refused, _ = _classify_refusal("t", "insufficient_scope: requires issues:write")
    assert refused == "pass", refused
    assert _classify_refusal("t", "missing required argument 'id'")[0] == "unknown"

    # A server that challenged us, on a run where discovery never attempted a
    # single path, has told us nothing about its scopes. That is undecided, not a
    # failure -- distinct from every path answering a clean 404, which is an
    # observation that the server serves no document.
    _never = ProbeContext(domain="d", base_url="https://d")
    _never.endpoint_url = "https://d/mcp"
    _never.auth_required = True
    assert unread(_never, "prm:") == [
        "no protected-resource metadata discovery was attempted at all"
    ]
    assert asyncio.run(ScopeMinimization().run(_never)).status is Status.UNKNOWN
    _served_none = ProbeContext(domain="d", base_url="https://d")
    _served_none.endpoint_url = "https://d/mcp"
    _served_none.auth_required = True
    _served_none.http["prm:https://d/.well-known/oauth-protected-resource"] = (
        HttpObservation(
            url="https://d/.well-known/oauth-protected-resource",
            method="GET",
            status=404,
        )
    )
    assert unread(_served_none, "prm:") == []
    assert asyncio.run(ScopeMinimization().run(_served_none)).status is Status.FAIL
    print("c38: all self-checks passed")
