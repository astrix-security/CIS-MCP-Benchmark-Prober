"""Section 3 checks (authentication and authorization), implemented as live probes.

Tracks the Section 3 revision dated 2026-08-12.

Scope reasoning — what a black-box client can and cannot decide:

* 3.1.2 - decidable. An unauthenticated request must draw a 401 challenge naming
        resource_metadata, and the issued lifetime is read from ``expires_in`` or
        ``exp - iat`` against a 1-hour baseline, never from a clock: a token read
        late in its life would otherwise look shorter than the server issued.
* 3.1.1 - operator-side only. The audit reads a stdio server's launch configuration
        and process environment, and a server reached by domain is not on stdio:
        reported NOT_APPLICABLE.
* 3.2.1 - operator-side only. The audit needs a second least-privileged credential,
        a positive control that really invokes a privileged tool, and the server's
        authorization decision log: NOT_APPLICABLE.
* 3.2.2 - decidable where the token is readable. An opaque token records UNKNOWN
        rather than FAIL, because ``aud`` lives only in a JWT body and reading its
        absence as a missing audience would fail every opaque-token issuer.
* 3.3.1 - decidable in part. Presents the live token to a downstream identity
        endpoint on the endpoint's own registrable domain, and asks the
        authorization server for a token bound to another resource. Candidate
        hosts are derived from the endpoint's name rather than discovered, so a
        genuine downstream API hosted elsewhere is never reached.
* 3.3.5 - decidable before authentication only. Its precondition needs two client
        registrations and the client id each authorize redirect carries onward, so
        a server that authorizes on its own host is settled from metadata alone
        and no client is registered. A safeguard that fires only after the user
        authenticates is not reachable from here.
* 3.2.3 - binds whoever consumes a tool annotation, not the server that publishes
        one. The gating configuration and the risk classification it keys on are
        both operator-side: NOT_APPLICABLE, with the annotations observed recorded
        as evidence.
* 3.3.4 - decidable except the operator's documented justification for a scope. Leg
        3.3.4f consults three discovery sources, because a server may advertise
        scopes on the authorization server alone and a two-source reading would
        fail a working server. The step-up elevation the recommendation describes is
        outside its own audit, which decides on the scopes a token carries, so no
        leg tests whether a client accumulates scopes across challenges.
* 3.3.3 - operator-side only. The evidence is an identity mapping inventory on the
        deployment host, and which downstream identity a tool uses leaves no
        signature on the MCP wire: NOT_APPLICABLE.
* 3.3.2 - decidable. Compares the document a client selects against the one the
        challenge names, which is the pair a conforming client reads. Comparing
        every answering path would fail a server that serves one document per
        resource, which is what RFC 9728 path-insertion is for.

Registration order is load-bearing and runs top to bottom in this file. Check 3.3.1
requests a token bound to a different resource, which can rotate the cached refresh
token, so its class is defined last and no check after it reads that credential.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx
from mcp.client.auth.oauth2 import PKCEParameters
from mcp.client.auth.utils import extract_resource_metadata_from_www_auth
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from mcp.shared.auth_utils import resource_url_from_server_url
from pydantic import ValidationError

from .. import baseline, inputs, tokens
from ..client import AS_LIST_CAP, DISCOVERY_TIMEOUT
from ..context import ProbeContext
from ..netguard import (
    derive_apex_host,
    derive_api_host,
    host_of,
    is_credential_safe_target,
    is_safe_fetch_host,
    parts_of,
    registrable_domain,
    resource_covers,
    scheme_of,
)
from ..observations import (
    attempted,
    attempted_for,
    guard_refused,
    unanswered,
    unread,
)
from ..rawreq import (
    is_rejection,
    raw_get,
    raw_jsonrpc,
    raw_post_form,
    raw_post_json,
)
from ..storage import FileTokenStorage
from ..tokens import has_admin_tier, has_wildcard, jwt_claims, observed_scopes
from .base import Check, CheckResult, Level, register

if TYPE_CHECKING:
    from mcp import types


# --- na_checks --------------------------------------------------------

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
    """3.1.1, Assessment Status: Automated — automated against a stdio deployment.

    The audit reads the stdio server's launch configuration and process
    environment. Neither exists for a server reached over the network, and a
    server we reached by domain is not on the stdio transport.
    """

    id = "3.1.1"
    title = "stdio server credentials are sourced from the environment or OS credential store"
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
    """3.2.1, Assessment Status: Manual.

    The audit needs a second, least-privileged identity, a positive control that
    really invokes a privileged tool, and the server's authorization decision
    log. We can mint no second identity, must not invoke a privileged tool for
    its side effect, and cannot read the log.
    """

    id = "3.2.1"
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
    """3.2.3, Assessment Status: Manual.

    The requirement binds whoever consumes the annotations — the client, host or
    gateway policy — not the server that publishes them. A server advertising a
    hint is conformant; trusting that hint for a gating decision is the defect,
    and that decision is made outside the audited server. The annotations we did
    observe are reported as evidence.
    """

    id = "3.2.3"
    title = "Server-provided tool annotations are not relied upon for authorization or HITL gating decisions"
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
    """3.3.3, Assessment Status: Manual.

    The authoritative evidence is the identity mapping inventory, and the
    supplementary scan reads configuration files on the deployment host. Which
    downstream identity a tool uses leaves no signature on the MCP wire.
    """

    id = "3.3.3"
    title = "Shared downstream service account identities are prohibited across multiple MCP tools or servers"
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


# --- c31 --------------------------------------------------------------

LIFETIME_BASELINE_SECONDS = 3600


def _challenge(ctx: ProbeContext) -> httpx.Response | None:
    """Rebuild the unauthenticated initialize response as an httpx.Response.

    That round-trip is recorded once, before any check runs, as an
    HttpObservation keyed by the endpoint URL. The WWW-Authenticate parser
    this check reuses takes a Response object, so the observation is replayed
    into one rather than re-sent over the wire.
    """
    if not ctx.endpoint_url:
        return None
    obs = ctx.http.get(f"initialize:{ctx.endpoint_url}")
    if obs is None or obs.status is None:
        return None
    return httpx.Response(status_code=obs.status, headers=obs.headers)


@register
class RemoteAuthentication(Check):
    """3.1.2, Assessment Status: Manual."""

    id = "3.1.2"
    title = "OIDC/OAuth 2.1 or short-lived API tokens are used for remote servers"
    section = "3"
    level = Level.L1
    remediation = (
        "Require a valid OAuth access token on every request, refuse an "
        "unauthenticated request with a 401 challenge naming resource_metadata, "
        f"and issue access tokens with a lifetime at or under "
        f"{LIFETIME_BASELINE_SECONDS} seconds."
    )

    async def run(self, ctx: ProbeContext) -> CheckResult:
        if not ctx.endpoint_url:
            return self._error("no live session to test against")

        legs = [
            ("3.1.2a", *self._leg_refusal_and_challenge(ctx)),
            ("3.1.2b", *self._leg_lifetime(ctx)),
            ("3.1.2c", *self._leg_iss_flag(ctx)),
            ("3.1.2d", *self._leg_registration_requirements(ctx)),
        ]
        details = {"legs": {leg_id: outcome for leg_id, outcome, _ in legs}}
        evidence = "; ".join(f"{leg_id}: {note}" for leg_id, _, note in legs)
        evidence += (
            ". Refusal is tautological: endpoint detection accepts a candidate "
            "only on a 200 or a 401, so a reachable server's recorded status is "
            'always one of those and "refused" is identical to whether '
            "authentication was required at all -- a 403 that passes with a "
            "caveat cannot occur here. The authorization-server iss flag and its "
            "registration requirements are evidence only and never move this "
            "verdict."
        )

        outcomes = [outcome for _, outcome, _ in legs]
        if "fail" in outcomes:
            return self._fail(evidence, **details)
        if "error" in outcomes:
            return self._error(evidence, **details)
        if "unknown" in outcomes:
            return self._unknown(evidence, **details)
        return self._pass(evidence, **details)

    def _leg_refusal_and_challenge(self, ctx: ProbeContext) -> tuple[str, str]:
        """Whether the server refused us, and whether its challenge named
        resource_metadata -- a challenge with no resource_metadata gives a
        client nowhere to look for how to authenticate."""
        if not ctx.auth_required:
            return (
                "fail",
                "an unauthenticated request reached a response instead of a "
                "401 challenge",
            )
        challenge = _challenge(ctx)
        resource_metadata = (
            extract_resource_metadata_from_www_auth(challenge) if challenge else None
        )
        if resource_metadata:
            return (
                "pass",
                "refused with a 401 challenge naming resource_metadata="
                f"{resource_metadata!r}",
            )
        return (
            "fail",
            "refused with a 401 challenge that did not name resource_metadata",
        )

    def _leg_lifetime(self, ctx: ProbeContext) -> tuple[str, str]:
        """The issued token's lifetime against the baseline, never computed
        from wall-clock now."""
        claims = tokens.jwt_claims(ctx.access_token) if ctx.access_token else None
        lifetime = tokens.issued_lifetime(ctx.token_expires_in, claims)
        if lifetime is None:
            return (
                "unknown",
                "issued lifetime could not be determined (opaque token, no "
                "expires_in on record)",
            )
        if lifetime > LIFETIME_BASELINE_SECONDS:
            return (
                "fail",
                f"issued lifetime {lifetime}s exceeds the "
                f"{LIFETIME_BASELINE_SECONDS}s baseline",
            )
        return (
            "pass",
            f"issued lifetime {lifetime}s is at or under the "
            f"{LIFETIME_BASELINE_SECONDS}s baseline",
        )

    def _leg_iss_flag(self, ctx: ProbeContext) -> tuple[str, str]:
        """The authorization server's advertised iss-parameter support,
        reported and never evaluated."""
        meta = ctx.auth_server_metadata
        if not isinstance(meta, dict):
            return "pass", "no authorization-server metadata was resolved"
        supported = meta.get("authorization_response_iss_parameter_supported")
        return (
            "pass",
            f"authorization-server iss-parameter support advertised as {supported!r}",
        )

    def _leg_registration_requirements(self, ctx: ProbeContext) -> tuple[str, str]:
        """The authorization server's advertised registration endpoint and
        token-endpoint auth methods, reported and never evaluated."""
        meta = ctx.auth_server_metadata
        if not isinstance(meta, dict):
            return "pass", "no authorization-server metadata was resolved"
        endpoint = meta.get("registration_endpoint")
        methods = meta.get("token_endpoint_auth_methods_supported")
        return (
            "pass",
            f"registration_endpoint={endpoint!r}, "
            f"token_endpoint_auth_methods_supported={methods!r}",
        )


# --- c34 --------------------------------------------------------------


def _canonical_uri(ctx: ProbeContext) -> str:
    """The resource URI our token request targeted.

    Derived from the endpoint, unless the protected-resource document advertises a
    value that is an accepting parent of it under RFC 8707. That value is
    server-controlled, so it goes through the guarded matcher, and a string the
    matcher cannot parse is not substituted.
    """
    canonical = resource_url_from_server_url(ctx.endpoint_url or "")
    prm = ctx.protected_resource_metadata
    advertised = prm.get("resource") if isinstance(prm, dict) else None
    if isinstance(advertised, str) and resource_covers(advertised, canonical):
        return advertised
    return canonical


def _strip_trailing_slash(uri: str) -> str:
    """``uri`` without one trailing slash.

    The endpoint candidate list includes ``/``, so a root-detected endpoint has a
    canonical URI ending in a slash while an authorization server commonly mints
    the same name without one. The two are the same resource under the SDK's
    matching rule, so the audience comparison normalizes both sides.
    """
    return uri[:-1] if uri.endswith("/") else uri


@register
class NoTokenPassthrough(Check):
    """3.2.2, Assessment Status: Manual."""

    id = "3.2.2"
    title = "Token passthrough to downstream APIs is forbidden"
    section = "3"
    level = Level.L1
    remediation = (
        "Mint access tokens whose aud claim names only the resource server the "
        "client requested, and reject any use of the token against a "
        "different resource."
    )

    async def run(self, ctx: ProbeContext) -> CheckResult:
        if not ctx.endpoint_url:
            return self._error("no live session to test against")

        if not ctx.access_token:
            # Two different situations, and collapsing them misreports one. A
            # server that challenges us or publishes protected-resource metadata
            # does issue tokens, so this requirement applies to it and we simply
            # failed to read one -- undecided. Only a server offering no OAuth at
            # all has no audience to confine.
            if ctx.offers_oauth:
                return self._unknown(
                    "the server requires authentication but no access token was "
                    "obtained, so no issued token's aud claim could be read",
                    legs={"3.2.2a": "unknown"},
                )
            return self._na(
                "the server offers no OAuth at all, so no issued token exists "
                "whose audience could be confined"
            )

        claims = tokens.jwt_claims(ctx.access_token)
        if claims is None:
            return self._unknown(
                "the access token is opaque, so its aud claim is not readable",
                legs={"3.2.2a": "unknown"},
            )

        auds = tokens.audiences(claims)
        if not auds:
            return self._unknown(
                "the token carries no aud claim, so audience confinement is "
                "not observable",
                legs={"3.2.2a": "unknown"},
            )

        canonical = _canonical_uri(ctx)
        wanted = _strip_trailing_slash(canonical)
        extra = [a for a in auds if _strip_trailing_slash(a) != wanted]
        if extra:
            return self._fail(
                f"aud names {extra} beyond the canonical resource "
                f"{canonical!r}; we cannot confirm from the token alone "
                "whether each extra entry is a genuine downstream API or "
                "passthrough",
                legs={"3.2.2a": "fail"},
                extra_audiences=extra,
            )
        return self._pass(
            f"aud names only the canonical resource {canonical!r}",
            legs={"3.2.2a": "pass"},
        )


# --- c38 --------------------------------------------------------------

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
SCOPE_REDUCTION = (
    " Reduced scope: this reads the wire and the baseline we recorded ourselves. "
    "The operator's documented justification for a scope is not readable from a "
    "client, so a documented exception for a flagged scope would change 3.3.4b and "
    "3.3.4d."
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
    return [
        entry
        for entry in ctx.advertised_authorization_servers
        if entry not in ctx.as_metadata_by_issuer
    ]


def baseline_outcome(
    record: dict[str, Any] | None,
    current: dict[str, Any],
    update_baseline: bool,
    baseline_written: bool = True,
) -> tuple[str, str]:
    """Decide leg 3.3.4c: has the granted scope set grown since we recorded it?

    ``unknown`` covers every case where nothing was compared, so an absent record
    is never read as drift. ``baseline_written`` distinguishes a capture that was
    stored from one the run declined to write.
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
    """Decide leg 3.3.4f: can a client discover the scopes it has to request?

    Three sources: the challenge ``scope``, the protected-resource
    ``scopes_supported``, then the authorization server's own. Any one is a
    discovery path. Failing needs all three absent *and* observed, so an
    unread document leaves the leg undecided rather than failed.
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
    """3.3.4, Assessment Status: Manual.

    Reads the granted scopes and the advertised surface, compares the granted
    set against our own recorded baseline, and calls the tool the operator names
    as outside our grant.
    """

    id = "3.3.4"
    title = "OAuth scopes are minimized and elevated progressively"
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
        # vacuous. Checks 3.2.2 and 3.3.1 draw the same line.
        if not ctx.offers_oauth:
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

        # 3.3.4a — an opaque token whose response omitted "scope" carries nothing
        # readable, which is undecided rather than a grant of zero scopes. A
        # response that states an empty scope set is the other case: that was
        # observed, so it decides, and leg 3.3.4c reads the same signal.
        if granted is None:
            results.append(
                (
                    "3.3.4a",
                    "unknown",
                    "no granted scope is readable: neither the token response nor "
                    "the token body stated one",
                )
            )
        elif granted:
            results.append(
                ("3.3.4a", "pass", "granted scopes read: " + " ".join(granted))
            )
        else:
            results.append(
                (
                    "3.3.4a",
                    "pass",
                    "the granted scope set was stated and is empty, so no scope is "
                    "granted at all",
                )
            )

        # 3.3.4b
        granted_wildcards = has_wildcard(granted or [])
        if granted is None:
            results.append(("3.3.4b", "unknown", "no granted scope to inspect"))
        elif not granted:
            results.append(
                (
                    "3.3.4b",
                    "pass",
                    "the granted scope set is empty, so no granted scope is a wildcard",
                )
            )
        elif granted_wildcards:
            results.append(
                (
                    "3.3.4b",
                    "fail",
                    "wildcard scope granted: "
                    + ", ".join(granted_wildcards)
                    + ". A documented operator exception for this grant would "
                    "change this outcome",
                )
            )
        else:
            results.append(
                (
                    "3.3.4b",
                    "pass",
                    "no granted scope is a wildcard: " + " ".join(granted),
                )
            )

        # 3.3.4c — capture only what an established session backs, the same
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
        results.append(("3.3.4c", outcome, note))

        # 3.3.4d — the advertised surface is the protected-resource document's own
        # scopes_supported, the single field, not every document that answered.
        advertised_wildcards = has_wildcard(resource_scopes)
        flagged = advertised_wildcards + [
            s for s in has_admin_tier(resource_scopes) if s not in advertised_wildcards
        ]
        if not resource_scopes:
            results.append(
                (
                    "3.3.4d",
                    "unknown",
                    "the protected-resource metadata advertises no "
                    "scopes_supported to inspect",
                )
            )
        elif flagged:
            results.append(
                (
                    "3.3.4d",
                    "fail",
                    "the advertised surface carries a wildcard or admin-tier "
                    "scope: " + ", ".join(flagged),
                )
            )
        else:
            results.append(
                (
                    "3.3.4d",
                    "pass",
                    "advertised scopes_supported carries no wildcard and no "
                    "admin-tier scope: " + ", ".join(resource_scopes),
                )
            )

        # 3.3.4e
        entry = inputs.load(ctx.domain)
        outcome, note = await self._call_named_tool(
            ctx, entry.get("scope_probe_tool"), entry.get("scope_probe_arguments") or {}
        )
        results.append(("3.3.4e", outcome, note))

        # 3.3.4f — either document can be the one this run never read, so the
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
        results.append(("3.3.4f", outcome, note))

        details = {
            "legs": {leg: outcome for leg, outcome, _ in results},
            "challenge_scope": ctx.challenge_scope,
            "granted_scopes": granted,
            "advertised_scopes": resource_scopes,
            "authorization_server_scopes": as_scopes,
        }
        evidence = (
            "; ".join(f"{leg}: {note}" for leg, _, note in results) + SCOPE_REDUCTION
        )
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
        """Leg 3.3.4e: call the tool the operator named as outside our grant.

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


# --- c310 -------------------------------------------------------------

RESOURCE_RULE = (
    "the probe applies the SDK's parent-prefix rule (same origin, canonical path "
    "at or below the advertised path) rather than the audit's exact string match"
)


def _is_tls(url: str) -> bool:
    """True when ``url`` is served over https.

    A URL that cannot be parsed is not https. One of the discovery paths is built
    from a header the server sent, so this must answer rather than raise.
    """
    return scheme_of(url) == "https"


def _documents_agree(one: dict, other: dict) -> bool:
    """True when two documents are byte-equal after a canonical key sort."""
    return json.dumps(one, sort_keys=True) == json.dumps(other, sort_keys=True)


@register
class DiscoveryChainIntegrity(Check):
    """3.3.2, Assessment Status: Automated."""

    id = "3.3.2"
    title = "OAuth discovery metadata is served over TLS and validated against the approved authorization server list"
    section = "3"
    level = Level.L2
    remediation = (
        "Serve one protected-resource metadata document over TLS at every "
        "discovery path the client may try, with a resource value equal to the "
        "server's canonical URI and a non-empty authorization_servers list; make "
        "each advertised authorization server publish metadata whose issuer "
        "string-equals the advertised entry; and change-control the advertised "
        "list so a new authorization server cannot appear unreviewed."
    )

    async def run(self, ctx: ProbeContext) -> CheckResult:
        endpoint = ctx.endpoint_url
        if not endpoint:
            return self._error("no live session to test against")

        # 3.3.2a, the precondition. Check 2.2 owns the endpoint's TLS verdict.
        if not _is_tls(endpoint):
            return self._unknown(
                f"3.3.2a: the MCP endpoint {endpoint} is not served over TLS, so "
                "the discovery chain below it cannot be assessed. Check 2.2 owns "
                "the transport-security verdict and reports it there",
                legs={"3.3.2a": "unknown"},
            )

        if not ctx.prm_documents:
            # Every path answering a clean 404 is the server stating it publishes
            # none. Anything else means we never got that statement, so neither
            # outcome was observed and nothing here is vacuous.
            attempts = attempted(ctx, "prm:")
            refused = guard_refused(ctx, "prm:") + guard_refused(ctx, "as:")
            why = unread(ctx, "prm:")
            if why:
                return self._unknown(
                    "no protected-resource metadata was read, and no discovery "
                    "path answered that the server publishes none: "
                    + "; ".join(why)
                    + ". Whether a discovery chain exists here is undecided, so "
                    "this run neither grades the chain nor rules the "
                    "recommendation out",
                    legs={"3.3.2a": "pass"},
                    discovery_attempts=attempts,
                    guard_refused_urls=refused,
                )
            # Every path answered a clean 404, so the absence was observed rather
            # than assumed. What that absence means depends on whether the server
            # does OAuth at all. Checks 3.3.1 and 3.3.4 draw the same line.
            if ctx.offers_oauth:
                return self._fail(
                    "the server requires OAuth and every discovery path answered "
                    "404, so it publishes no protected-resource metadata at all. A "
                    "client has no way to discover the authorization server, which "
                    "is what this recommendation exists to guarantee. The absence "
                    "was observed on every path rather than assumed",
                    legs={"3.3.2a": "pass"},
                    discovery_attempts=attempts,
                    guard_refused_urls=refused,
                )
            return self._na(
                "every discovery path answered 404 and the server offers no OAuth "
                "at all, so it published no protected-resource metadata, there is "
                "no discovery chain to assess and the recommendation is vacuous "
                "for this target. The audit reports ERROR for a chain that "
                "resolves to nothing; this probe reports NOT_APPLICABLE, because "
                "ERROR is reserved for a failure on our side and a server that "
                "never offered OAuth is not one",
                legs={"3.3.2a": "pass"},
                discovery_attempts=attempts,
                guard_refused_urls=refused,
            )

        document = ctx.protected_resource_metadata or {}
        advertised = ctx.advertised_authorization_servers
        refused = guard_refused(ctx, "prm:") + guard_refused(ctx, "as:")

        legs = [
            (
                "3.3.2a",
                "pass",
                f"the MCP endpoint {endpoint} is served over TLS",
            ),
            self._paths_agree(ctx),
            self._document_over_tls(ctx),
            self._resource_matches(document, endpoint),
            self._servers_advertised(document, advertised),
            self._within_baseline(ctx),
            self._issuers_match(ctx, advertised),
        ]

        past_cap = max(0, len(advertised) - AS_LIST_CAP)
        evidence = "; ".join(f"{leg}: {note}" for leg, _, note in legs)
        evidence += (
            f". Discovery is bounded: at most {AS_LIST_CAP} advertised "
            f"authorization server(s) are resolved ({len(advertised)} advertised, "
            f"{past_cap} past the cap left unresolved) and every discovery fetch "
            f"uses a fixed {DISCOVERY_TIMEOUT:.0f}s timeout, so a longer "
            "advertised list is assessed only as far as the cap"
        )

        details = {
            "legs": {leg: outcome for leg, outcome, _ in legs},
            "discovery_paths_answered": sorted(ctx.prm_documents),
            "authorization_servers_advertised": len(advertised),
            "authorization_servers_resolved": len(ctx.as_metadata_by_issuer),
            "authorization_servers_cap": AS_LIST_CAP,
            "authorization_servers_past_cap": past_cap,
            "discovery_timeout_seconds": DISCOVERY_TIMEOUT,
            "guard_refused_urls": refused,
        }

        outcomes = [outcome for _, outcome, _ in legs]
        if "fail" in outcomes:
            return self._fail(evidence, **details)
        if "error" in outcomes:
            return self._error(evidence, **details)
        if "unknown" in outcomes:
            return self._unknown(evidence, **details)
        return self._pass(evidence, **details)

    # --- legs -------------------------------------------------------------
    def _paths_agree(self, ctx: ProbeContext) -> tuple[str, str, str]:
        """3.3.2b — the document a client selects agrees with the one the challenge names.

        Every answering path is deliberately not compared against every other:
        RFC 9728 path-insertion lets a server serve one document per resource, and
        a client answered from the inserted path never reads the root.
        """
        selected = ctx.protected_resource_metadata or {}
        challenge_url = ctx.challenge_resource_metadata
        advertised = ctx.prm_documents.get(challenge_url or "")

        if advertised is None:
            reason = (
                "the challenge named no metadata URL"
                if not challenge_url
                else f"the challenge named {challenge_url}, which served no document"
            )
            return (
                "3.3.2b",
                "pass",
                f"only one discovery document was consulted, because {reason}, so "
                "there is no second document to disagree with it. The "
                f"{len(ctx.prm_documents)} path(s) that answered are recorded, and "
                "paths a client would not read are not compared against each other",
            )
        if _documents_agree(selected, advertised):
            return (
                "3.3.2b",
                "pass",
                f"the document the challenge names ({challenge_url}) is byte-equal "
                "to the one a client selects, after a canonical key sort",
            )
        return (
            "3.3.2b",
            "fail",
            f"the document the challenge names ({challenge_url}) differs from the "
            "one a client selects, after a canonical key sort",
        )

    def _document_over_tls(self, ctx: ProbeContext) -> tuple[str, str, str]:
        """3.3.2c — the metadata document is served only over TLS."""
        plain = sorted(url for url in ctx.prm_documents if not _is_tls(url))
        if plain:
            return (
                "3.3.2c",
                "fail",
                "protected-resource metadata was served over a non-TLS URL: "
                + ", ".join(plain),
            )
        refused = guard_refused(ctx, "prm:")
        if refused:
            return (
                "3.3.2c",
                "unknown",
                "the host guard refused a discovery URL the server supplied, so "
                "it was never fetched and its scheme was never observed: "
                + ", ".join(refused),
            )
        return (
            "3.3.2c",
            "pass",
            f"every one of the {len(ctx.prm_documents)} discovery path(s) that "
            "answered was https",
        )

    def _resource_matches(self, document: dict, endpoint: str) -> tuple[str, str, str]:
        """3.3.2d — the advertised resource covers the canonical URI."""
        canonical = resource_url_from_server_url(endpoint)
        advertised = document.get("resource")
        if not isinstance(advertised, str) or not advertised.strip():
            return (
                "3.3.2d",
                "unknown",
                f"the protected-resource document carries no resource string, so "
                f"there was nothing to compare against the canonical URI "
                f"{canonical}; {RESOURCE_RULE}",
            )
        covers = resource_covers(advertised, canonical)
        if covers is None:
            # RFC 9728 requires this member to be a URI, and no conforming client
            # can parse this one. That is a violation we observed in the document
            # the server served, which is why it fails rather than staying
            # undecided: the value is present, readable, and wrong.
            return (
                "3.3.2d",
                "fail",
                f"the advertised resource {advertised!r} is not a parsable URI, so "
                f"it could not be compared with the canonical URI {canonical}; "
                f"{RESOURCE_RULE}",
            )
        if covers:
            relation = (
                "equals" if advertised == canonical else "is a hierarchical parent of"
            )
            return (
                "3.3.2d",
                "pass",
                f"the advertised resource {advertised} {relation} the canonical "
                f"URI {canonical}; {RESOURCE_RULE}",
            )
        return (
            "3.3.2d",
            "fail",
            f"the advertised resource {advertised} does not cover the canonical "
            f"URI {canonical}; {RESOURCE_RULE}",
        )

    def _servers_advertised(
        self, document: dict, advertised: list[str]
    ) -> tuple[str, str, str]:
        """3.3.2e — authorization_servers is present and non-empty."""
        if advertised:
            return (
                "3.3.2e",
                "pass",
                f"{len(advertised)} authorization server(s) advertised: "
                + ", ".join(advertised),
            )
        return (
            "3.3.2e",
            "fail",
            "the protected-resource document advertises no usable "
            "authorization_servers entry, which is protocol-invalid: a document "
            f"was served, so the requirement applies (value: "
            f"{document.get('authorization_servers')!r})",
        )

    def _within_baseline(self, ctx: ProbeContext) -> tuple[str, str, str]:
        """3.3.2f — the advertised list is within the recorded baseline."""
        if ctx.update_baseline:
            return (
                "3.3.2f",
                "unknown",
                "this run captures the baseline instead of comparing against it, "
                "so it decides nothing about the advertised list",
            )
        record = baseline.load(ctx.endpoint_url or "")
        if record is None:
            return (
                "3.3.2f",
                "unknown",
                "no baseline recorded for this endpoint yet; run once with "
                "--update-baseline to establish one",
            )
        added, missing_in = baseline.compare_category(
            record, baseline.snapshot(ctx), "authorization_servers"
        )
        if missing_in == "record":
            return (
                "3.3.2f",
                "unknown",
                "the baseline record carries no authorization_servers category, "
                "so this run cannot tell an addition from a first observation",
            )
        if missing_in == "current":
            return (
                "3.3.2f",
                "unknown",
                "this run observed no advertised authorization_servers list, so "
                "there is nothing to compare against the recorded one",
            )
        if added:
            return (
                "3.3.2f",
                "fail",
                "authorization server(s) advertised but not in the recorded "
                "baseline: " + ", ".join(added),
            )
        return (
            "3.3.2f",
            "pass",
            "every advertised authorization server is in the recorded baseline",
        )

    def _issuers_match(
        self, ctx: ProbeContext, advertised: list[str]
    ) -> tuple[str, str, str]:
        """3.3.2g — each advertised authorization server publishes a matching issuer."""
        if not advertised:
            return (
                "3.3.2g",
                "unknown",
                "no authorization server was advertised, so no issuer could be "
                "resolved",
            )

        matched: list[str] = []
        mismatched: list[str] = []
        unresolved: list[str] = []
        for entry in advertised[:AS_LIST_CAP]:
            metadata = ctx.as_metadata_by_issuer.get(entry)
            if metadata is None:
                unresolved.append(entry)
            elif metadata.get("issuer") == entry:
                matched.append(entry)
            else:
                mismatched.append(f"{entry} publishes {metadata.get('issuer')!r}")

        if mismatched:
            return (
                "3.3.2g",
                "fail",
                "advertised authorization server(s) publish a different issuer: "
                + "; ".join(mismatched),
            )
        if unresolved:
            # Each issuer's own attempts, told apart from an issuer that extends
            # it, so both the refusal and the count below speak for one entry.
            attempts = {
                entry: attempted_for(ctx, "as:", entry, advertised)
                for entry in unresolved
            }
            refused = set(guard_refused(ctx, "as:"))
            blocked = [
                entry for entry in unresolved if refused.intersection(attempts[entry])
            ]
            if blocked:
                return (
                    "3.3.2g",
                    "unknown",
                    "the host guard refused an authorization-server metadata URL, "
                    "so nothing was fetched and no issuer was observed for "
                    + ", ".join(blocked),
                )
            # The number of forms tried is a property of the issuer string --
            # an issuer carrying a path yields one more form than a root one --
            # so it is counted from the attempts actually recorded.
            tried = [
                f"{entry} ({len(attempts[entry])} discovery form(s) tried)"
                for entry in unresolved
            ]
            return (
                "3.3.2g",
                "error",
                "no discovery form served authorization-server metadata carrying "
                "an issuer, so no issuer was reached for " + "; ".join(tried),
            )
        return (
            "3.3.2g",
            "pass",
            f"each of the {len(matched)} advertised authorization server(s) "
            "publishes an issuer that string-equals the advertised entry, taking "
            "the first discovery form that yields an issuer",
        )


# --- c36 --------------------------------------------------------------

SCRATCH_REDIRECT_URI = "http://127.0.0.1:33418/callback"

# The redirect_uri leg varies this one parameter and nothing else. The host is
# under .invalid, which can never resolve, so a server that honours it hands the
# authorization code to no one.
VARIED_REDIRECT_URI = "https://cis-probe-attacker.invalid/callback"

# Values chosen to be recognisable in a server's own logs as probe traffic. The
# authorize requests carry one state throughout, so the redirect_uri leg varies
# that parameter and nothing else; the callback leg carries a different one, so
# the state it replays is one no authorize request ever sent either.
PROBE_STATE = "cis-probe-authorize-state"
FABRICATED_CODE = "cis-probe-fabricated-code"
UNISSUED_STATE = "cis-probe-unissued-state"
CONTROL_PATH = "/cis-probe-no-such-path"
CALLBACK_PATH = "/callback"

# What this check cannot see, stated in the verdict rather than only here.
PROXY_REDUCTION = (
    " Reduced scope: no interactive login is performed, so only the part of each "
    "safeguard that fires before authentication is observed -- a redirect_uri or "
    "a client id that is validated only after the user authenticates is not "
    "reachable from here. 3.3.5b sends a fabricated code, so the invalid code "
    "alone may explain a refusal that the missing state would also have earned."
)


def _is_code_leak(location: str) -> bool:
    """True when a redirect target carries an authorization code.

    The location comes from the server under test, so it may not be parseable at
    all. A URL nothing can be read out of shows no code, which is what this
    answers: no leak is visible.
    """
    parts = parts_of(location) if location else None
    if parts is None:
        return False
    return any("code" in parse_qs(blob) for blob in (parts.query, parts.fragment))


def _has_oauth_error(body: str) -> bool:
    """True when a body names an OAuth error, as a JSON field or a parameter."""
    try:
        parsed = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        parsed = None
    if isinstance(parsed, dict) and parsed.get("error"):
        return True
    return "error=" in body


def _classify_callback(
    status: int | None, body: str, location: str, control_status: int | None
) -> str:
    """Read the callback's answer to a fabricated code against the control.

    The control is a nonsense path on the same origin, and it is a parameter
    because the same status means opposite things depending on it: a catch-all 200
    for any unknown path never reached a handler at all.
    """
    if _is_code_leak(location):
        # An authorization code in the redirect is evidence on its own, so it
        # stands whatever the control answered.
        return "fail"
    if status is None:
        return "error"
    if control_status is None or control_status >= 500:
        # The control never answered for itself, so what this origin serves for an
        # unknown path was not observed and there is nothing to compare against:
        # a 200 on the callback is as consistent with a catch-all as with a
        # handler. Reading it as either would invent a finding.
        return "error"
    if status == control_status:
        # The control path has no handler either, so nothing here is a callback.
        return "error"
    if 300 <= status < 400:
        return "pass"
    if 400 <= status < 500:
        if _has_oauth_error(body) or _has_oauth_error(location):
            return "pass"
        # A bare 4xx says nothing about the server: a gateway serves those too.
        return "error"
    if status >= 500:
        # A server error is not a handler accepting the code: it is evidence
        # the handler was never reached.
        return "error"
    return "fail"


def _downstream_client_id(location: str) -> str | None:
    """The ``client_id`` an authorize redirect carries onward, if it carries one.

    A location that cannot be parsed carries no client id, the same answer as one
    that carries no such parameter.
    """
    parts = parts_of(location) if location else None
    if parts is None:
        return None
    values = parse_qs(parts.query).get("client_id") or []
    return values[0] if values else None


def _authorize_url(
    authorization_endpoint: str,
    *,
    client_id: str,
    redirect_uri: str,
    state: str,
    code_challenge: str,
    resource: str,
) -> str:
    """Build one authorization request URL against the advertised endpoint."""
    query = urlencode(
        {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "resource": resource,
        }
    )
    parts = parts_of(authorization_endpoint)
    separator = "&" if parts and parts.query else "?"
    return f"{authorization_endpoint}{separator}{query}"


def _registration_body() -> dict[str, Any]:
    """The dynamic client registration request for a scratch client.

    A JSON body, with the plural members as real arrays. RFC 7591 section 3.1.2
    requires ``application/json`` at the registration endpoint, and a conforming
    authorization server answers 400 or 415 to a form-encoded one.
    """
    return {
        "client_name": "cis-mcp-probe (3.3.5 scratch client)",
        "redirect_uris": [SCRATCH_REDIRECT_URI],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
    }


def _applicability_gate_reason(
    ctx: ProbeContext, endpoint: str, authorize: object, register_at: object
) -> tuple[str, str] | None:
    """What 3.3.5 may conclude without probing, or None when it must probe.

    Returns the outcome and why: ``"na"`` when the recommendation is vacuous for
    this target, ``"unknown"`` when the metadata that would decide it was never
    read. Decided from the discovery record alone, before any client is
    registered.
    """
    if not isinstance(ctx.auth_server_metadata, dict):
        # An attempt that failed or was refused leaves what it holds unread, and a
        # run that fetched nothing learned nothing: undecided either way. Only
        # discovery answering for itself leaves the recommendation nothing to bite
        # on.
        why = unanswered(ctx, "as:", "prm:") or unread(ctx, "prm:")
        if why:
            return (
                "unknown",
                "no authorization-server metadata was read, and discovery did not "
                "settle whether one is advertised: "
                + "; ".join(why)
                + ". Whether this server fronts a separate authorization server "
                "on one static client id is undecided, so this run neither grades "
                "the safeguards nor rules the recommendation out",
            )
        return (
            "na",
            "no authorization-server metadata was read, and no discovery attempt "
            "failed or was refused: every path either served a document or "
            "answered a clean 404, so the absence of authorization-server metadata "
            "for this endpoint was observed rather than assumed. There is no "
            "separate authorization server for this one to front on a shared "
            "client id and the recommendation is vacuous for it",
        )
    if not isinstance(authorize, str) or not authorize.strip():
        return (
            "na",
            "the authorization server advertises no authorization_endpoint, so no "
            "authorize request could be built and the static-client-id condition "
            "was not established",
        )
    if parts_of(authorize) is None:
        return (
            "unknown",
            f"the advertised authorization_endpoint {authorize!r} cannot be parsed "
            "as a URL, so no authorize request could be built against it and the "
            "static-client-id condition was not established",
        )
    if not isinstance(register_at, str) or not register_at.strip():
        return (
            "na",
            "the authorization server advertises no registration_endpoint, so the "
            "two client registrations the static-client-id condition is read from "
            "could not be made and the condition was not established",
        )
    authorize_host = host_of(authorize)
    endpoint_host = host_of(endpoint)
    if authorize_host and authorize_host == endpoint_host:
        return (
            "na",
            f"the authorization endpoint is on the MCP server's own host "
            f"({authorize_host}), so the server authorizes for itself rather than "
            "fronting a separate authorization server on a shared client id. The "
            "static-client-id condition was not established and no client was "
            "registered",
        )
    return None


async def _cache(storage: FileTokenStorage, document: dict) -> None:
    """Keep a client this run created, under the scratch key."""
    record = dict(document)
    record.setdefault("redirect_uris", [SCRATCH_REDIRECT_URI])
    try:
        info = OAuthClientInformationFull.model_validate(record)
    except Exception:  # noqa: BLE001 -- details still records the client id
        return
    await storage.set_client_info(info)


@register
class ConfusedDeputySafeguards(Check):
    """3.3.5, Assessment Status: Manual.

    Applies to a server fronting a separate authorization server on one static
    client id. On such a server it varies the ``redirect_uri``, replays a
    fabricated code at the callback against a control path, and starts a flow on
    a client id the authorization server has never seen.
    """

    id = "3.3.5"
    title = "Confused-deputy safeguards are applied for static OAuth client IDs"
    section = "3"
    level = Level.L2
    remediation = (
        "Accept only a redirect_uri that string-matches one registered to the "
        "client_id in the request, and refuse the request without redirecting "
        "when it does not match. Bind every callback to state the server itself "
        "issued and reject a code arriving with a state it never issued. Obtain "
        "the user's consent for each client_id the first time it is seen, rather "
        "than passing a newly registered client straight through to the upstream "
        "authorization server on the shared client id."
    )

    async def run(self, ctx: ProbeContext) -> CheckResult:
        endpoint = ctx.endpoint_url
        if not endpoint:
            return self._error("no live session to test against")

        metadata = (
            ctx.auth_server_metadata
            if isinstance(ctx.auth_server_metadata, dict)
            else {}
        )
        authorize = metadata.get("authorization_endpoint")
        register_at = metadata.get("registration_endpoint")

        # 3.3.5-pre, first half: settled from the discovery record, before any
        # registration. A target the recommendation is vacuous for and a target
        # whose metadata was never read are different answers.
        gate = _applicability_gate_reason(ctx, endpoint, authorize, register_at)
        if gate:
            outcome, reason = gate
            verdict = self._unknown if outcome == "unknown" else self._na
            return verdict(
                f"3.3.5-pre: {reason}." + PROXY_REDUCTION,
                legs={"3.3.5-pre": "unknown"},
                registrations=[],
            )

        pkce = PKCEParameters.generate()
        state = PROBE_STATE
        resource = resource_url_from_server_url(endpoint)
        scratch = FileTokenStorage(f"cis-probe-scratch:{ctx.domain}")
        registrations: list[str] = []

        def authorize_url(client_id: str, redirect_uri: str) -> str:
            return _authorize_url(
                str(authorize),
                client_id=client_id,
                redirect_uri=redirect_uri,
                state=state,
                code_challenge=pkce.code_challenge,
                resource=resource,
            )

        # 3.3.5-pre, second half: two registrations, and the client id each
        # authorize redirect carries onward.
        first_id, first_note = await self._register(str(register_at), scratch)
        if first_id is None:
            return self._na(
                f"3.3.5-pre: {first_note}, so the static-client-id condition was not "
                "established." + PROXY_REDUCTION,
                legs={"3.3.5-pre": "unknown"},
                registrations=registrations,
            )
        registrations.append(first_id)
        first = await raw_get(authorize_url(first_id, SCRATCH_REDIRECT_URI))

        second_id, second_note = await self._register(str(register_at), scratch)
        if second_id is None:
            return self._na(
                f"3.3.5-pre: {second_note}, so the static-client-id condition was not "
                "established." + PROXY_REDUCTION,
                legs={"3.3.5-pre": "unknown"},
                registrations=registrations,
            )
        registrations.append(second_id)
        second = await raw_get(authorize_url(second_id, SCRATCH_REDIRECT_URI))

        first_downstream = _downstream_client_id(first[1].get("location", ""))
        second_downstream = _downstream_client_id(second[1].get("location", ""))
        if not first_downstream or first_downstream != second_downstream:
            return self._na(
                f"3.3.5-pre: registered {first_id} and {second_id}, and their "
                f"authorize responses (HTTP {first[0]}, {second[0]}) carry the "
                f"onward client ids {first_downstream!r} and {second_downstream!r}. "
                "They are not one shared static value, so this server does not "
                "front a separate authorization server on a static client id and "
                "the recommendation is vacuous for it." + PROXY_REDUCTION,
                legs={"3.3.5-pre": "unknown"},
                registrations=registrations,
                downstream_client_ids=[first_downstream, second_downstream],
            )

        legs = [
            (
                "3.3.5-pre",
                "pass",
                f"registered {first_id} and {second_id}, and both authorize "
                f"responses redirect onward on the same client id "
                f"{first_downstream}, so this server fronts a separate "
                "authorization server on one static client id and the "
                "recommendation applies",
            ),
            await self._leg_redirect_uri(
                first, authorize_url(first_id, VARIED_REDIRECT_URI)
            ),
            await self._leg_callback(endpoint),
            await self._leg_consent(
                str(register_at), str(authorize), scratch, registrations, authorize_url
            ),
        ]

        evidence = (
            "; ".join(f"{leg}: {note}" for leg, _, note in legs) + PROXY_REDUCTION
        )
        details = {
            "legs": {leg: outcome for leg, outcome, _ in legs},
            "registrations": registrations,
            "downstream_client_ids": [first_downstream, second_downstream],
        }

        outcomes = [outcome for _, outcome, _ in legs]
        if "fail" in outcomes:
            return self._fail(evidence, **details)
        if "error" in outcomes:
            return self._error(evidence, **details)
        if "unknown" in outcomes:
            return self._unknown(evidence, **details)
        return self._pass(evidence, **details)

    # --- registration -----------------------------------------------------
    async def _register(
        self, registration_endpoint: str, scratch: FileTokenStorage
    ) -> tuple[str | None, str]:
        """Register one client, returning its client id or why there is none."""
        status, _, body, error = await raw_post_json(
            registration_endpoint, _registration_body()
        )
        if error:
            return None, f"registration at {registration_endpoint} failed: {error}"
        if status not in (200, 201):
            return (
                None,
                f"registration at {registration_endpoint} answered HTTP {status}: "
                f"{body[:200]}",
            )
        try:
            document = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            return (
                None,
                f"registration at {registration_endpoint} answered HTTP {status} "
                "with a body that is not JSON",
            )
        client_id = document.get("client_id") if isinstance(document, dict) else None
        if not isinstance(client_id, str) or not client_id:
            return None, "the registration response carried no client_id"
        await _cache(scratch, document)
        return client_id, f"registered client_id {client_id}"

    # --- legs -------------------------------------------------------------
    async def _leg_redirect_uri(
        self,
        registered: tuple[int | None, dict[str, str], str, str | None],
        varied_url: str,
    ) -> tuple[str, str, str]:
        """3.3.5a — vary only redirect_uri and require the varied value refused."""
        status, headers, body, error = await raw_get(varied_url)
        location = headers.get("location", "")
        registered_status = registered[0]

        if _is_code_leak(location):
            return (
                "3.3.5a",
                "fail",
                f"the authorize request carrying redirect_uri="
                f"{VARIED_REDIRECT_URI} answered HTTP {status} and redirected to "
                "a location carrying an authorization code, so the code leaks to "
                "a redirect target that was never registered",
            )
        if error or status is None:
            return (
                "3.3.5a",
                "error",
                f"the authorize request varying redirect_uri did not complete "
                f"({error}), so the registered value was never compared against a "
                "varied one",
            )
        if registered_status is None or 400 <= registered_status < 500:
            return (
                "3.3.5a",
                "error",
                f"the authorize request carrying the registered redirect_uri was "
                f"itself refused (HTTP {registered_status}), so a refusal of the "
                "varied one is not attributable to redirect_uri validation",
            )
        if 400 <= status < 500:
            return (
                "3.3.5a",
                "pass",
                f"the registered redirect_uri was accepted (HTTP "
                f"{registered_status}) and varying it alone to "
                f"{VARIED_REDIRECT_URI} was refused with HTTP {status}: "
                f"{body[:200]}",
            )
        if 300 <= status < 400:
            if host_of(location) == host_of(VARIED_REDIRECT_URI):
                return (
                    "3.3.5a",
                    "fail",
                    f"the authorize request carrying redirect_uri="
                    f"{VARIED_REDIRECT_URI} answered HTTP {status} and redirected "
                    f"to {location}, so the unregistered redirect target was "
                    "honoured rather than refused",
                )
            if _has_oauth_error(location):
                return (
                    "3.3.5a",
                    "pass",
                    f"the registered redirect_uri was accepted (HTTP "
                    f"{registered_status}) and varying it alone to "
                    f"{VARIED_REDIRECT_URI} was answered with HTTP {status} "
                    f"redirecting to an error at {location}",
                )
            # The flow carried on for a value that was never registered. Whether
            # it is validated later, after the user authenticates, is not
            # reachable without completing the login.
            return (
                "3.3.5a",
                "unknown",
                f"the authorize request carrying redirect_uri="
                f"{VARIED_REDIRECT_URI} answered HTTP {status} redirecting to "
                f"{location}, which names no error and is not the varied target, "
                "so the flow carried on for a redirect_uri that was never "
                "registered without refusing it up front",
            )
        return (
            "3.3.5a",
            "unknown",
            f"the authorize request carrying redirect_uri={VARIED_REDIRECT_URI} "
            f"answered HTTP {status} with no redirect, which says nothing about "
            "whether the value was validated: an authorization server that "
            "validates it only after the user authenticates answers the same way",
        )

    async def _leg_callback(self, endpoint: str) -> tuple[str, str, str]:
        """3.3.5b — a fabricated code with an unissued state, against a control."""
        parts = urlsplit(endpoint)
        origin = f"{parts.scheme}://{parts.netloc}"
        query = urlencode({"code": FABRICATED_CODE, "state": UNISSUED_STATE})
        callback_url = f"{origin}{CALLBACK_PATH}?{query}"
        control_url = f"{origin}{CONTROL_PATH}"

        status, headers, body, error = await raw_get(callback_url)
        control_status, _, _, control_error = await raw_get(control_url)
        location = headers.get("location", "")

        outcome = _classify_callback(status, body, location, control_status)
        note = (
            f"{callback_url} answered HTTP {status}{f' ({error})' if error else ''} "
            f"and the control path {CONTROL_PATH} answered HTTP {control_status}"
            f"{f' ({control_error})' if control_error else ''}"
        )
        if location:
            note += f", redirecting to {location}"
        if outcome == "pass":
            note += (
                ". The fabricated code was refused, and the control answered "
                "differently, so the refusal came from a handler rather than from a "
                "response this origin serves for any path"
            )
        elif outcome == "fail":
            note += ". The callback processed a code it had issued no state for"
        else:
            note += (
                ". That is not attributable to a callback handler, so this leg "
                "decided nothing"
            )
        return "3.3.5b", outcome, note

    async def _leg_consent(
        self,
        registration_endpoint: str,
        authorization_endpoint: str,
        scratch: FileTokenStorage,
        registrations: list[str],
        authorize_url: Callable[[str, str], str],
    ) -> tuple[str, str, str]:
        """3.3.5c — a never-before-seen client id must meet a consent step."""
        client_id, note = await self._register(registration_endpoint, scratch)
        if client_id is None:
            return (
                "3.3.5c",
                "error",
                f"{note}, so no authorize flow was started on a client id the "
                "authorization server has never seen",
            )
        registrations.append(client_id)

        status, headers, _, error = await raw_get(
            authorize_url(client_id, SCRATCH_REDIRECT_URI)
        )
        if error or status is None:
            return (
                "3.3.5c",
                "error",
                f"the authorize request on the freshly registered {client_id} did "
                f"not complete ({error}), so no consent step was observed",
            )
        location = headers.get("location", "")
        if 300 <= status < 400:
            target = host_of(location)
            if target and target != host_of(authorization_endpoint):
                return (
                    "3.3.5c",
                    "fail",
                    f"the first response for the freshly registered {client_id} is "
                    f"HTTP {status} redirecting straight to {target}, the upstream "
                    "authorization server, so a client id the server had never "
                    "seen was handed onward on the shared static client id with no "
                    "consent step of its own",
                )
            return (
                "3.3.5c",
                "pass",
                f"the first response for the freshly registered {client_id} is "
                f"HTTP {status} redirecting to {location}, which stays on the "
                "authorization server's own host rather than handing the new "
                "client straight onward",
            )
        if 200 <= status < 300:
            return (
                "3.3.5c",
                "pass",
                f"the first response for the freshly registered {client_id} is "
                f"HTTP {status}, a page served by the authorization server itself "
                "rather than an immediate hand-off to the upstream one",
            )
        return (
            "3.3.5c",
            "error",
            f"the authorize request on the freshly registered {client_id} was "
            f"refused with HTTP {status}, so the consent step was never reached",
        )


# --- c35 --------------------------------------------------------------

CANDIDATE_PATHS: tuple[str, ...] = ("/", "/me", "/user", "/viewer", "/v1/account")

# The resource value 3.3.1b asks for a token against. RFC 2606 reserves
# ".invalid", so no server can legitimately serve it, and nothing is ever
# fetched from this URL: it travels only as the "resource" field of a token
# request.
WRONG_AUDIENCE_RESOURCE = "https://cis-probe.invalid/wrong-audience"

# What this check cannot see, stated in the verdict rather than only here.
AUDIENCE_REDUCTION = (
    " Reduced scope: 3.3.1c's candidates are guesses -- a host derived from the "
    "endpoint's own name, or one the operator named -- not a downstream API "
    "discovered from the server, and the credential-release gate refuses every "
    "candidate off the endpoint's registrable domain, so a genuine downstream "
    "API hosted elsewhere is never reached. 3.3.1b cannot confirm that an opaque "
    "minted token carries the resource it asked for rather than the "
    "authorization server having ignored the parameter."
)


def classify_downstream(with_token: int | None, without_token: int | None) -> str:
    """Read one downstream candidate probed twice, with the token and without it.

    401 with the token refuses the credential. 200 or 403 accepts it -- a 403
    authenticated then denied authorization -- but only where the status without
    the token differs, since an endpoint answering the same either way says
    nothing. Anything else is not a comparison.
    """
    if with_token == 401:
        return "pass"
    if with_token in (200, 403) and without_token is not None:
        return "fail" if without_token != with_token else "unknown"
    return "unknown"


def _collapse(outcomes: list[str]) -> str:
    """One leg outcome from the per-candidate results.

    Fail wins: one endpoint that accepted the credential is the finding. An empty
    list decides nothing, and is the ordinary case when no candidate survived the
    gate.
    """
    if "fail" in outcomes:
        return "fail"
    if "pass" in outcomes:
        return "pass"
    return "unknown"


def _credential_gate_reason(url: str, endpoint_host: str) -> str:
    """Why the credential-release gate refused ``url``, for the record only.

    ``is_credential_safe_target`` makes the decision; this re-reads its
    conditions to name one in a message and never decides anything itself.
    """
    if scheme_of(url) is None:
        return "not a parseable URL, so its host could never be checked"
    if scheme_of(url) != "https":
        return "not https, so a bearer token would travel in plaintext"
    if not is_safe_fetch_host(url):
        return "an internal or non-routable address, or an encoding of one"
    return (
        f"not on {endpoint_host}'s own registrable domain, or under a suffix "
        "where unrelated parties publish their own content"
    )


def _screen(urls: list[str], endpoint_host: str) -> tuple[list[str], dict[str, str]]:
    """Split candidates into those that may receive the token and those that may not.

    Returns ``(probeable, refused)``, where ``refused`` maps each rejected URL to
    the reason it was rejected. An operator-named URL goes through exactly the
    same gate as a derived one.
    """
    probeable: list[str] = []
    refused: dict[str, str] = {}
    for url in urls:
        if is_credential_safe_target(url, endpoint_host):
            if url not in probeable:
                probeable.append(url)
        else:
            refused[url] = _credential_gate_reason(url, endpoint_host)
    return probeable, refused


def _candidate_urls(ctx: ProbeContext, endpoint_host: str) -> list[str]:
    """Every URL that might hold a downstream identity endpoint, before the gate.

    The endpoint host with its leftmost label replaced by ``api``, and with that
    label dropped, each crossed with ``CANDIDATE_PATHS``. Neither derivation works
    below three labels, so a two-label host rests entirely on the operator entry.
    """
    urls: list[str] = []
    for host in (derive_api_host(endpoint_host), derive_apex_host(endpoint_host)):
        if host:
            urls.extend(f"https://{host}{path}" for path in CANDIDATE_PATHS)
    named = inputs.load(ctx.domain).get("downstream_endpoints")
    if isinstance(named, list):
        urls.extend(url for url in named if isinstance(url, str) and url)
    return urls


def _advertising_issuer(ctx: ProbeContext) -> str | None:
    """The advertised authorization server whose metadata ``ctx`` carries.

    ``as_metadata_by_issuer`` is keyed by the entry the protected-resource
    document advertised, which is the name a token endpoint out of that document
    has to belong to.
    """
    for entry, doc in ctx.as_metadata_by_issuer.items():
        if doc == ctx.auth_server_metadata:
            return entry
    return None


def _token_endpoint_refusal(token_endpoint: str, issuer: str | None) -> str | None:
    """Why ``token_endpoint`` may not receive the cached refresh token, or None.

    Pinned to https and to the registrable domain of the issuer that advertised
    it, rather than the MCP endpoint's, because an authorization server
    legitimately lives on a domain of its own.
    """
    if scheme_of(token_endpoint) is None:
        return "not a parseable URL, so its host could never be checked"
    if scheme_of(token_endpoint) != "https":
        return "not https, so the refresh token would travel in plaintext"
    if not issuer:
        return (
            "no advertised authorization server matches the metadata that named "
            "it, so there is no issuer to pin the endpoint to"
        )
    owned = registrable_domain(host_of(issuer) or "")
    host = registrable_domain(host_of(token_endpoint) or "")
    if owned is None or host != owned:
        return (
            f"not on the registrable domain of the issuer {issuer} that advertised it"
        )
    return None


def _minted_token(body: str) -> str | None:
    """The ``access_token`` from a token response body, or None when absent."""
    try:
        parsed = json.loads(body)
    except ValueError:
        return None
    token = parsed.get("access_token") if isinstance(parsed, dict) else None
    return token if isinstance(token, str) and token else None


def _rotated_refresh(body: str, spent: str) -> str | None:
    """The refresh token a token response returns, when it replaced the one we spent.

    None when the server returned none, echoed the one we sent, or answered with a
    body that cannot be read: in each of those cases nothing rotated, so the token
    already on disk still stands.
    """
    try:
        parsed = json.loads(body)
    except ValueError:
        return None
    token = parsed.get("refresh_token") if isinstance(parsed, dict) else None
    if isinstance(token, str) and token and token != spent:
        return token
    return None


async def _restore_refresh_chain(
    store: FileTokenStorage,
    token_endpoint: str,
    form: dict[str, str],
    refresh: str,
    resource: str,
) -> str:
    """Spend ``refresh`` on the audited resource and cache the response.

    3.3.1b's request rotates the cached refresh token, and the pair it returns is
    bound to a resource the audited server does not serve, so neither caching that
    pair nor caching nothing is right. Returns the sentence the leg appends to its
    evidence; a failure here is not a verdict.
    """
    status, _, text, error = await raw_post_form(
        token_endpoint, dict(form, refresh_token=refresh, resource=resource)
    )
    if error:
        return (
            f"the refresh chain was not restored ({error}), so the cached refresh "
            "token stays spent and the next run needs a fresh login"
        )
    try:
        renewed = OAuthToken.model_validate(json.loads(text))
    except (ValidationError, ValueError):
        return (
            f"the refresh chain was not restored: HTTP {status} carried no usable "
            "token response, so the cached refresh token stays spent and the next "
            "run needs a fresh login"
        )
    await store.set_tokens(renewed)
    return (
        f"the refresh chain was restored for {resource}, so the cached credential "
        "survives this leg"
    )


async def _tools_list(endpoint: str, token: str) -> tuple[int | None, dict | None]:
    """POST ``tools/list`` with ``token``, or (None, None) if it did not complete.

    ``tools/list`` needs no session id, so the same request shape is usable as
    its own control.
    """
    payload: dict[str, Any] = {
        "jsonrpc": "2.0",
        "id": 35,
        "method": "tools/list",
        "params": {},
    }
    try:
        status, data, _ = await raw_jsonrpc(endpoint, payload, token=token)
    except Exception:  # noqa: BLE001 -- a transport failure is not a verdict
        return None, None
    return status, data


@register
class AudienceBinding(Check):
    """3.3.1, Assessment Status: Automated.

    Reads the token's audience, presents the token to a downstream identity
    endpoint on the endpoint's own registrable domain, and asks the
    authorization server for a token bound to a different resource.
    """

    id = "3.3.1"
    title = (
        "OAuth tokens are audience-bound to the MCP server using Resource Indicators"
    )
    section = "3"
    level = Level.L1
    remediation = (
        "Mint access tokens whose audience names only the resource server the "
        "client requested, validate that audience on every request before "
        "acting on the token, refuse a token minted for another resource, and "
        "refuse a token request naming a resource the authorization server does "
        "not serve with invalid_target."
    )

    async def run(self, ctx: ProbeContext) -> CheckResult:
        endpoint = ctx.endpoint_url
        if not endpoint:
            return self._error("no live session to test against")

        if not ctx.access_token:
            if ctx.offers_oauth:
                return self._unknown(
                    "the server requires OAuth but no access token was obtained, "
                    "so there is no credential to read an audience from, present "
                    "to a downstream endpoint, or re-mint for another resource"
                    + AUDIENCE_REDUCTION,
                    legs={
                        "3.3.1a": "unknown",
                        "3.3.1c": "unknown",
                        "3.3.1b": "unknown",
                    },
                    hosts_probed=[],
                )
            return self._na(
                "the server offers no OAuth at all: no token was issued and no "
                "protected-resource metadata was served, so there is no audience "
                "to bind and the recommendation is vacuous for this target. The "
                "benchmark specifies ERROR for a chain that resolves to nothing; "
                "ERROR is reserved here for a failure on our own side, and a "
                "server that never offered OAuth is not that",
                legs={},
                hosts_probed=[],
            )

        endpoint_host = host_of(endpoint) or ""
        legs = [("3.3.1a", *self._leg_audience(ctx))]

        candidates, refused = _screen(
            _candidate_urls(ctx, endpoint_host), endpoint_host
        )
        outcome, note, probes = await self._leg_downstream(ctx, candidates, refused)
        legs.append(("3.3.1c", outcome, note))

        # 3.3.1b runs last: the refresh grant can rotate the cached refresh token.
        legs.append(("3.3.1b", *await self._leg_wrong_resource(ctx)))

        details: dict[str, Any] = {
            "legs": {leg: outcome for leg, outcome, _ in legs},
            "candidates_refused": refused,
            "wrong_resource": WRONG_AUDIENCE_RESOURCE,
            **probes,
        }
        evidence = (
            "; ".join(f"{leg}: {note}" for leg, _, note in legs) + AUDIENCE_REDUCTION
        )
        outcomes = [outcome for _, outcome, _ in legs]

        if "fail" in outcomes:
            return self._fail(evidence, **details)
        if "error" in outcomes:
            return self._error(evidence, **details)
        if "unknown" in outcomes:
            return self._unknown(evidence, **details)
        return self._pass(evidence, **details)

    # --- legs -------------------------------------------------------------
    def _leg_audience(self, ctx: ProbeContext) -> tuple[str, str]:
        """3.3.1a -- the token's aud claim names the canonical resource URI.

        An opaque token records unknown, never fail: aud lives only in a JWT
        body, so reading its absence as a missing audience would fail every
        server that issues an opaque token.
        """
        canonical = _canonical_uri(ctx)
        claims = tokens.jwt_claims(ctx.access_token or "")
        if claims is None:
            return (
                "unknown",
                "the access token is opaque, so its aud claim is not readable "
                f"and its binding to {canonical} is not observable",
            )
        auds = tokens.audiences(claims)
        if not auds:
            return (
                "unknown",
                "the token carries no aud claim, so its binding to "
                f"{canonical} is not observable",
            )
        if _strip_trailing_slash(canonical) in [_strip_trailing_slash(a) for a in auds]:
            return ("pass", f"aud names the canonical resource {canonical}")
        return (
            "fail",
            f"aud names {auds} and none of those entries is the canonical "
            f"resource {canonical}",
        )

    async def _leg_downstream(
        self,
        ctx: ProbeContext,
        candidates: list[str],
        refused: dict[str, str],
    ) -> tuple[str, str, dict[str, Any]]:
        """3.3.1c -- present the token to each candidate, and probe each without it.

        Returns ``(outcome, note, details_fragment)``. Every candidate is fetched
        twice, because a guessed path may be public and a bare 200 with the token
        would then prove nothing. Redirects are returned unfollowed by ``raw_get``,
        so a redirect off a guessed host cannot carry the credential onward.
        """
        outcomes: dict[str, str] = {}
        hosts: list[str] = []
        for url in candidates:
            with_status, _, _, _ = await raw_get(url, token=ctx.access_token)
            without_status, _, _, _ = await raw_get(url)
            outcomes[url] = classify_downstream(with_status, without_status)
            host = host_of(url) or url
            if host not in hosts:
                hosts.append(host)

        fragment = {"hosts_probed": hosts, "downstream_outcomes": outcomes}
        outcome = _collapse(list(outcomes.values()))

        if not candidates:
            return (
                outcome,
                f"no candidate downstream endpoint was probed: {len(refused)} "
                "candidate(s) were refused by the credential-release gate and "
                "no other candidate was available, so the token was presented "
                "to nothing",
                fragment,
            )
        accepted = [url for url, o in outcomes.items() if o == "fail"]
        if accepted:
            return (
                outcome,
                "our token was accepted by a downstream endpoint that is not "
                "the audited resource: " + ", ".join(accepted),
                fragment,
            )
        rejected = [url for url, o in outcomes.items() if o == "pass"]
        if rejected:
            return (
                outcome,
                "our token was presented to and refused with 401 by "
                + ", ".join(rejected),
                fragment,
            )
        return (
            outcome,
            f"{len(candidates)} candidate(s) on {', '.join(hosts)} were probed "
            "with the token and without it, and none produced a usable "
            "comparison: each was unreachable, or answered the same either way",
            fragment,
        )

    async def _leg_wrong_resource(self, ctx: ProbeContext) -> tuple[str, str]:
        """3.3.1b -- a token minted for another resource must be refused.

        Uses the refresh grant, which can rotate the cached refresh token, so this
        is the run's last credential operation. The wrong-audience pair is never
        cached; ``_restore_refresh_chain`` re-establishes the chain instead.
        """
        metadata = ctx.auth_server_metadata
        token_endpoint = (
            metadata.get("token_endpoint") if isinstance(metadata, dict) else None
        )
        if not isinstance(token_endpoint, str) or not token_endpoint:
            return (
                "unknown",
                "the authorization server metadata names no token_endpoint, so "
                "no token could be requested for another resource",
            )

        refusal = _token_endpoint_refusal(token_endpoint, _advertising_issuer(ctx))
        if refusal:
            return (
                "unknown",
                f"no token was requested for another resource: the token endpoint "
                f"{token_endpoint} may not receive our refresh token, being "
                f"{refusal}",
            )

        store = FileTokenStorage(ctx.endpoint_url or "")
        stored = await store.get_tokens()
        client = await store.get_client_info()
        refresh = getattr(stored, "refresh_token", None)
        client_id = getattr(client, "client_id", None)
        if not refresh or not client_id:
            return (
                "unknown",
                "no cached refresh token and client id for this endpoint, so no "
                "token could be minted for another resource",
            )

        form = {
            "grant_type": "refresh_token",
            "refresh_token": refresh,
            "client_id": client_id,
            "resource": WRONG_AUDIENCE_RESOURCE,
        }
        secret = getattr(client, "client_secret", None)
        if secret:
            form["client_secret"] = secret

        status, _, text, error = await raw_post_form(token_endpoint, form)
        if error:
            return (
                "unknown",
                f"the token request to {token_endpoint} did not complete "
                f"({error}), so no token was minted for "
                f"{WRONG_AUDIENCE_RESOURCE}",
            )

        minted = _minted_token(text)
        if minted is None:
            refusal = "invalid_target" if "invalid_target" in text else f"HTTP {status}"
            return (
                "unknown",
                "the authorization server refused to mint a token for "
                f"{WRONG_AUDIENCE_RESOURCE} ({refusal}), which is the conforming "
                "refusal and leaves the audited server's own audience validation "
                "untested",
            )

        # The request above spent the cached refresh token, and a server that
        # rotates has just replaced it. Re-establish the chain for the audited
        # resource before anything else, or the next run has no way to refresh.
        rotated = _rotated_refresh(text, refresh)
        if rotated:
            restored = await _restore_refresh_chain(
                store,
                token_endpoint,
                form,
                rotated,
                resource_url_from_server_url(ctx.endpoint_url or ""),
            )
        else:
            restored = (
                "the authorization server returned no new refresh token, so the "
                "cached one still stands"
            )

        outcome, note = await self._compare_minted(ctx, minted)
        return outcome, f"{note}. {restored}"

    async def _compare_minted(self, ctx: ProbeContext, minted: str) -> tuple[str, str]:
        """Present the differently-bound token to the audited endpoint, with a control.

        Split out so the refresh-chain sentence is appended once rather than at
        every return below.
        """
        if minted == ctx.access_token:
            return (
                "unknown",
                "the authorization server returned the token we already hold "
                f"rather than one bound to {WRONG_AUDIENCE_RESOURCE}, so nothing "
                "about audience validation was tested",
            )

        endpoint = ctx.endpoint_url or ""
        wrong_status, wrong_data = await _tools_list(endpoint, minted)
        control_status, control_data = await _tools_list(
            endpoint, ctx.access_token or ""
        )
        if wrong_status is None or control_status is None:
            return (
                "unknown",
                "the endpoint did not answer one of the two tools/list requests, "
                "so the differently-bound token was not compared against our own",
            )
        if is_rejection(control_status, control_data):
            return (
                "unknown",
                f"the endpoint refused this request shape with our own token too "
                f"(HTTP {control_status}), so any refusal of the differently-bound "
                "token is not attributable to audience validation",
            )
        if is_rejection(wrong_status, wrong_data):
            return (
                "pass",
                "the endpoint refused a token the authorization server minted for "
                f"{WRONG_AUDIENCE_RESOURCE} (HTTP {wrong_status}) while accepting "
                "our own, so the audience was validated",
            )
        return (
            "fail",
            "the endpoint accepted a token the authorization server minted for "
            f"{WRONG_AUDIENCE_RESOURCE} (HTTP {wrong_status}), so the audience "
            "was not validated",
        )
