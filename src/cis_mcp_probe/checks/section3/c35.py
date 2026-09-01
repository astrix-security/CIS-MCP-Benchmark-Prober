"""Check 3.5: the issued access token is bound to the resource that requested it.

Three legs:

* ``3.5a`` -- the token's ``aud`` claim names the canonical resource URI.
* ``3.5c`` -- a downstream identity endpoint on the audited endpoint's own
  registrable domain refuses the token.
* ``3.5b`` -- a token the authorization server mints for a different
  ``resource`` value is refused by the audited server.

3.5b runs last: the refresh grant can rotate the cached refresh token, so it is
kept as the final credential operation of the run.

3.5c is the one leg that presents a live bearer token to a host other than the
MCP endpoint. Every candidate URL -- derived here or named by the operator --
passes ``is_credential_safe_target`` before the token touches it, so a
credential never travels over plaintext, never leaves the endpoint's own
registrable domain, and never reaches an internal or non-routable address.

3.5b sends the cached refresh token to a token endpoint the audited server's
discovery chain names, so that endpoint is pinned first: https, and on the
registrable domain of the issuer that advertised it. An authorization server
runs on a domain of its own, so the pin is to the issuer rather than to the MCP
endpoint.
"""

from __future__ import annotations

import json
from typing import Any

from mcp.shared.auth import OAuthToken
from mcp.shared.auth_utils import resource_url_from_server_url
from pydantic import ValidationError

from ... import inputs, tokens
from ...context import ProbeContext
from ...netguard import (
    derive_api_host,
    derive_apex_host,
    host_of,
    is_credential_safe_target,
    is_safe_fetch_host,
    registrable_domain,
    scheme_of,
)
from ...rawreq import is_rejection, raw_get, raw_jsonrpc, raw_post_form
from ...storage import FileTokenStorage
from ..base import Check, CheckResult, Level, register
from .c34 import _canonical_uri, _strip_trailing_slash

# Generic identity paths a resource API is likely to serve. The list is fixed, so
# the request count is bounded at hosts x paths x 2.
CANDIDATE_PATHS: tuple[str, ...] = ("/", "/me", "/user", "/viewer", "/v1/account")

# The resource value 3.5b asks for a token against. RFC 2606 reserves
# ".invalid", so no server can legitimately serve it, and nothing is ever
# fetched from this URL: it travels only as the "resource" field of a token
# request.
WRONG_AUDIENCE_RESOURCE = "https://cis-probe.invalid/wrong-audience"

# What this check cannot see, stated in the verdict rather than only here.
REDUCTION = (
    " Reduced scope: 3.5c's candidates are guesses -- a host derived from the "
    "endpoint's own name, or one the operator named -- not a downstream API "
    "discovered from the server, and the credential-release gate refuses every "
    "candidate off the endpoint's registrable domain, so a genuine downstream "
    "API hosted elsewhere is never reached. 3.5b cannot confirm that an opaque "
    "minted token carries the resource it asked for rather than the "
    "authorization server having ignored the parameter."
)


def classify_downstream(with_token: int | None, without_token: int | None) -> str:
    """Read one downstream candidate probed twice, with the token and without it.

    Keys on the with-token status, which is the decisive one. 401 is a refusal of
    the credential itself. 200 or 403 is acceptance -- a 403 means the credential
    authenticated and was then denied authorization, so the other resource
    validated it -- but only where the status without the token differs, because
    an endpoint answering the same either way says nothing about the credential.
    Everything else, including a transport failure on one side only, is not a
    comparison.
    """
    if with_token == 401:
        return "pass"
    if with_token in (200, 403) and without_token is not None:
        return "fail" if without_token != with_token else "unknown"
    return "unknown"


def _collapse(outcomes: list[str]) -> str:
    """One leg outcome from the per-candidate results.

    Fail wins: one downstream endpoint that accepted the credential is the
    finding, whatever the others did. An empty list means no candidate was
    probed at all, which decides nothing -- and that is the ordinary case, since
    the derived hosts are unavailable below three labels and the operator input
    file is absent unless somebody wrote one.
    """
    if "fail" in outcomes:
        return "fail"
    if "pass" in outcomes:
        return "pass"
    return "unknown"


def _gate_reason(url: str, endpoint_host: str) -> str:
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
            refused[url] = _gate_reason(url, endpoint_host)
    return probeable, refused


def _candidate_urls(ctx: ProbeContext, endpoint_host: str) -> list[str]:
    """Every URL that might hold a downstream identity endpoint, before the gate.

    Derived: the endpoint host with its leftmost label replaced by ``api``, and
    the host with that label dropped, each crossed with ``CANDIDATE_PATHS``. Both
    derivations are unavailable below three labels, so a two-label host yields
    nothing derived and the leg rests entirely on the operator entry. Operator
    entries are full URLs and are taken as given.
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

    The audited server chooses which authorization server metadata we read, so a
    token endpoint out of that document is pinned before a credential is sent to
    it: https, and on the registrable domain of the issuer that advertised it.
    The comparison is against the issuer rather than the MCP endpoint because an
    authorization server legitimately lives on a domain of its own.
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

    3.5b's own request rotates the refresh token on a server that rotates, and the
    pair it returns is bound to a resource the audited server does not serve.
    Caching that pair would put a wrong-audience credential on disk, which is the
    one outcome this check exists to detect. Caching nothing leaves a spent refresh
    token on disk, so the next run cannot refresh and needs an interactive login.
    So the chain is re-established explicitly: one more refresh naming the audited
    resource, and that response is what gets cached.

    Returns the sentence the leg appends to its evidence. A failure here is not a
    verdict: it leaves the cache exactly as bad as caching nothing did.
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
    """3.5, Assessment Status: Automated.

    Reads the token's audience, presents the token to a downstream identity
    endpoint on the endpoint's own registrable domain, and asks the
    authorization server for a token bound to a different resource.
    """

    id = "3.5"
    title = "The issued access token is bound to the audience that requested it"
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
            if ctx.auth_required or ctx.prm_documents:
                return self._unknown(
                    "the server requires OAuth but no access token was obtained, "
                    "so there is no credential to read an audience from, present "
                    "to a downstream endpoint, or re-mint for another resource"
                    + REDUCTION,
                    legs={"3.5a": "unknown", "3.5c": "unknown", "3.5b": "unknown"},
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
        legs = [("3.5a", *self._leg_audience(ctx))]

        candidates, refused = _screen(
            _candidate_urls(ctx, endpoint_host), endpoint_host
        )
        outcome, note, probes = await self._leg_downstream(ctx, candidates, refused)
        legs.append(("3.5c", outcome, note))

        # 3.5b runs last: the refresh grant can rotate the cached refresh token.
        legs.append(("3.5b", *await self._leg_wrong_resource(ctx)))

        details: dict[str, Any] = {
            "legs": {leg: outcome for leg, outcome, _ in legs},
            "candidates_refused": refused,
            "wrong_resource": WRONG_AUDIENCE_RESOURCE,
            **probes,
        }
        evidence = "; ".join(f"{leg}: {note}" for leg, _, note in legs) + REDUCTION
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
        """3.5a -- the token's aud claim names the canonical resource URI.

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
        """3.5c -- present the token to each candidate, and probe each without it.

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
        """3.5b -- a token minted for another resource must be refused.

        Uses the refresh grant, which can rotate the cached refresh token, so
        this is the last credential operation the run performs. The wrong-audience
        pair the request returns is never cached. When the server rotated, the
        chain is re-established with one further refresh naming the audited
        resource, so the next run still has a credential to refresh -- see
        ``_restore_refresh_chain``.
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


if __name__ == "__main__":
    # A 403 WITH the token is acceptance: the credential
    # authenticated and was then denied authorization.
    assert classify_downstream(401, 401) == "pass"
    assert classify_downstream(401, 200) == "pass"
    assert classify_downstream(200, 401) == "fail"
    assert classify_downstream(403, 401) == "fail"
    assert classify_downstream(403, 200) == "fail"
    assert classify_downstream(200, 404) == "fail"
    # the token changed nothing, so nothing is proven
    assert classify_downstream(200, 200) == "unknown"
    assert classify_downstream(403, 403) == "unknown"
    assert classify_downstream(404, 404) == "unknown"
    assert classify_downstream(500, 500) == "unknown"
    # a one-sided transport failure is not a comparison
    assert classify_downstream(None, 401) == "unknown"
    assert classify_downstream(401, None) == "pass"  # the token was still refused
    assert len(CANDIDATE_PATHS) == 5
    # collapse rule: fail wins over pass
    assert _collapse(["pass", "unknown", "fail"]) == "fail"
    assert _collapse(["unknown", "pass"]) == "pass"
    assert _collapse(["unknown", "unknown"]) == "unknown"
    # no candidate survived the gate, which is the reachable default
    assert _collapse([]) == "unknown"

    # 3.5b's pin on the token endpoint. The issuer's own domain is allowed, since
    # an authorization server does not live on the audited server's domain.
    _issuer = "https://auth.vendor.example"
    assert _token_endpoint_refusal("https://auth.vendor.example/token", _issuer) is None
    assert (
        _token_endpoint_refusal("https://login.vendor.example/token", _issuer) is None
    )
    assert _token_endpoint_refusal("http://auth.vendor.example/token", _issuer)
    assert _token_endpoint_refusal("https://evil.example.com/token", _issuer)
    assert _token_endpoint_refusal("https://auth.vendor.example/token", None)
    # An unbalanced bracket makes the authority unparseable. Refused, not raised.
    assert _token_endpoint_refusal("https://exa[mple.com/token", _issuer)
    # A tenant on a hosting domain owns only its own name, so a neighbour tenant
    # is a third party.
    assert (
        _token_endpoint_refusal(
            "https://other-tenant.onrender.com/token", "https://one.onrender.com"
        )
        is not None
    )

    # 3.5b's rotation reader. Only a token that differs from the one we spent is a
    # rotation: an echoed value, an absent field and an unreadable body all mean
    # the server rotated nothing, so the token already on disk still stands and no
    # second refresh is spent trying to replace it.
    assert _rotated_refresh('{"refresh_token": "new"}', "old") == "new"
    assert _rotated_refresh('{"refresh_token": "same"}', "same") is None
    assert _rotated_refresh('{"access_token": "a"}', "old") is None
    assert _rotated_refresh('{"refresh_token": ""}', "old") is None
    assert _rotated_refresh('{"refresh_token": 7}', "old") is None
    assert _rotated_refresh("not json", "old") is None
    assert _rotated_refresh("[]", "old") is None

    # 3.5a tolerates one trailing slash, on either side.
    assert _strip_trailing_slash("https://host/") == _strip_trailing_slash(
        "https://host"
    )

    # An unbalanced bracket makes the authority unparseable. _gate_reason must
    # explain the refusal, not raise while trying to.
    # An unparseable URL and a plaintext URL are different refusals, and the
    # message an operator reads must say which one happened.
    assert "parseable" in _token_endpoint_refusal("https://exa[mple.com/t", _issuer)
    assert "plaintext" in _token_endpoint_refusal(
        "http://auth.vendor.example/t", _issuer
    )
    assert "parseable" in _gate_reason("https://exa[mple.com/x", "endpoint.example")
    assert "plaintext" in _gate_reason(
        "http://api.endpoint.example/x", "endpoint.example"
    )

    # The credential-release gate, end to end through the check. A bearer token
    # leaving the endpoint's own registrable domain is the worst thing this
    # module could do, so the assertion is on what 3.5c actually probed.
    import asyncio
    import json as _json
    import tempfile
    from pathlib import Path

    from ... import inputs as _inputs, storage as _storage

    _tmp = Path(tempfile.mkdtemp())
    _inputs.PATH = _tmp / "probe-inputs.json"
    _storage.DATA_DIR = _tmp / "tokens"
    # A two-label endpoint host derives no candidate of its own, so the four
    # below are the whole candidate list: a third party, a plaintext URL, a
    # private address, and one host on the endpoint's own domain.
    _inputs.PATH.write_text(
        _json.dumps(
            {
                "probe.test": {
                    "downstream_endpoints": [
                        "https://evil.example.com/me",
                        "http://api.cis-probe.invalid/me",
                        "https://10.0.0.1/me",
                        "https://api.cis-probe.invalid/me",
                    ]
                }
            }
        )
    )
    _ctx = ProbeContext(
        domain="probe.test",
        base_url="https://cis-probe.invalid",
        endpoint_url="https://cis-probe.invalid/mcp",
        access_token="opaque-token-not-a-jwt",
        auth_required=True,
    )
    _result = asyncio.run(AudienceBinding().run(_ctx))
    assert _result.details["hosts_probed"] == ["api.cis-probe.invalid"], _result.details
    assert set(_result.details["candidates_refused"]) == {
        "https://evil.example.com/me",
        "http://api.cis-probe.invalid/me",
        "https://10.0.0.1/me",
    }, _result.details
    # An opaque token and no authorization-server metadata leave 3.5a and 3.5b
    # undecided, and the one reachable candidate does not resolve.
    assert _result.details["legs"] == {
        "3.5a": "unknown",
        "3.5c": "unknown",
        "3.5b": "unknown",
    }, _result.details

    print("c35: all self-checks passed")
