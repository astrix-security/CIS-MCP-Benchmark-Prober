"""Section 10 checks (caching and resource limits), implemented as live probes.

Both recommendations are Level 1, and the benchmark marks both **Manual**.

Scope reasoning — what a black-box client can and cannot decide:

* 10.1 - three legs, two of them graded.

  - 10.1a reads the cache headers of one static resource. The path is the
    operator's to name and cannot be derived: MCP defines no HTTP static asset,
    ``resources/list`` returns protocol-layer URIs rather than files at a path, and
    every conventional static path tried on a live MCP host answered 404. So no
    path is guessed -- one that did answer would belong to the vendor's web
    application rather than the audited server -- and the leg records ``unknown``
    naming the missing input. It fires on a deployment that co-hosts static assets
    behind the same hostname, which is a real enterprise shape.
  - 10.1b reads the ``Cache-Control`` on the endpoint's own response to a
    ``tools/list`` POST, graded as dynamic content, and needs no operator input.
    Two substitutions, both named in the evidence: the audit probes a GET path
    where this reads a POST response, and a shared cache does not store a POST
    response by default, so the confidentiality exposure is thinner than the
    audit's GET case. Neither applies where an operator names a
    ``per_user_resource_path``, which is then graded instead.
  - 10.1c reports the protocol-layer cacheable-result fields and is never graded,
    for two independent reasons: the benchmark calls that block an optional aid
    rather than a required one, and grading it needs an operator-named per-user
    resource whose per-user nature a remote client cannot judge.

  Whether a resource is per-user is not inferred from authentication. The
  recommendation denies that in terms: a ``public`` result may be shared across
  callers even from an authenticated endpoint.

* 10.2 - one graded leg. A control ``tools/list`` then the same request padded
  past the probe size. A 413 earns ``pass`` on any server whatever its
  configuration, because it proves a limit is enforced at or below the size sent.
  ``fail`` needs the limit the operator configured, because a 2xx proves only that
  no limit sits at or below that size, which is not the same claim as no limit at
  all. Five further obligations are dropped: response-payload bounds, per-message
  stream bounds, token budgets, per-principal quota behaviour, and enforcement at
  both the reverse proxy and the application middleware. The audit assigns all
  five to configuration review and a load test, and they are named in the evidence
  so a ``pass`` does not read as compliance with the recommendation.
"""

from __future__ import annotations

import json
import re
from urllib.parse import urljoin

from .. import inputs
from ..context import ProbeContext
from ..netguard import host_of, is_credential_safe_target, registrable_domain
from ..rawreq import raw_endpoint_request, raw_get, raw_jsonrpc_headers
from .base import Check, CheckResult, Level, Status, register

_AUDIT_META = {
    "io.modelcontextprotocol/clientInfo": {
        "name": "cis-benchmark-audit",
        "version": "1.0",
    },
    "io.modelcontextprotocol/clientCapabilities": {},
}
RC_VERSION = "2026-07-28"

# A validator, in the audit's terms: `grep -Ei '^(etag|last-modified):'`.
_VALIDATOR_HEADERS = ("etag", "last-modified")

# The two directives that bar shared caching. The audit reads them as a pair in
# both of its HTTP scripts, where their presence is FAIL for a static resource and
# PASS for a dynamic one.
_NON_SHAREABLE = frozenset({"no-store", "private"})

# `grep -Eqx 'max-age=[0-9]+'`. Anchored at both ends, so `s-maxage=60` and
# `max-age=60x` are not matches.
_MAX_AGE = re.compile(r"^max-age=[0-9]+$")

# The protocol-layer cacheable-result fields, required on every cacheable result type
# from 2026-07-28. Leg 10.1c reports which are present and grades none of them.
_CACHEABLE_FIELDS = ("resultType", "ttlMs", "cacheScope")

# Leg 10.1c's outcome. No branch of ``_verdict`` reads it, so check 10.1's verdict
# cannot move on an evidence-only leg. That is verdict-neutrality by construction
# rather than by care, and it keeps the leg out of the aggregation while still
# appearing in ``details["legs"]``.
OBSERVED = "observed"

# Leg 10.2b's outcome. Nothing is sent for it and nothing is read: it holds the five
# obligations the audit assigns to configuration review and a load test. It appears in
# ``details["legs"]`` anyway, so a reader sees that the leg exists and was not probed
# rather than inferring its absence from a list that names only what ran. Like
# ``OBSERVED``, no branch of ``_verdict`` reads it.
DROPPED = "dropped"

# Named in check 10.1's evidence on every run. A reader has to be able to see what
# the verdict rests on without holding the benchmark text.
CACHE_REDUCTION = (
    ". Reductions: leg 10.1b reads a POST response where the audit probes a GET "
    "path, and a shared cache does not store a POST response by default, so the "
    "confidentiality exposure is thinner than the audit's GET case -- neither "
    "substitution applies where an operator names a per_user_resource_path. Leg "
    "10.1c is an observation and no verdict rests on it, because the benchmark "
    "calls the protocol-layer block an optional aid rather than a required one"
)

# Named in check 10.2's evidence on every run, so a pass cannot read as compliance
# with the recommendation. Leg 10.2b holds all five and is not probed.
BODY_LIMIT_REDUCTION = (
    ". 10.2b: a pass above covers one of the recommendation's six obligations, and "
    "the other five are not probed because the audit assigns them to configuration "
    "review and a load test -- a bound on a non-streaming response payload, a bound "
    "on each message of a streamed response, per-request and per-workload token "
    "budgets, per-principal quota exhaustion returning a clear error rather than "
    "silently queuing, and the body-size limit holding at both the reverse proxy "
    "and the MCP application middleware"
)


def _rc_meta(version: str = RC_VERSION) -> dict:
    return {
        "io.modelcontextprotocol/protocolVersion": version,
        **_AUDIT_META,
    }


def _directives(headers: dict[str, str]) -> tuple[str | None, list[str]]:
    """Return the raw ``Cache-Control`` value and its directives as whole tokens.

    Both of 10.1's HTTP scripts tokenise the same way: split on commas, trim each
    field, lowercase it. Each directive is then matched with ``grep -Eqx``, an
    anchored whole-line match, so a caller must compare whole tokens and never
    substrings -- ``no-store`` does not match inside ``no-store-remote``.

    An absent header returns None, which a caller distinguishes from an empty one.
    """
    raw = headers.get("cache-control")
    if raw is None:
        return None, []
    return raw, [token for token in (t.strip().lower() for t in raw.split(",")) if token]


def _has_max_age(tokens: list[str]) -> bool:
    """True if any directive is ``max-age=<digits>``, anchored as the audit anchors it."""
    return any(_MAX_AGE.match(token) for token in tokens)


def _status_gate(
    status: object, error: str | None, label: str
) -> tuple[str, str] | None:
    """Return an outcome when cache policy cannot be attributed, else None.

    Three conditions, and the first two are the audit's own branch in both of its
    HTTP scripts: a request that never answered or a non-numeric status, and a status
    at or above 400. Both are ERROR. That is what keeps a 401 challenge, a 403, a 429
    and a 502 -- none of which carries a ``Cache-Control`` or any content -- from
    reading as a FAIL on a missing directive, and it is what makes grading the
    endpoint's own response safe on a run that never authenticated.

    The third is a redirect, which is UNKNOWN. ``raw_get`` does not follow one, so a
    301 or a 302 arrives as the status and is below 400: without this branch a static
    path redirected to a CDN would read as "lacks a validator" and a per-user path
    redirected to a login page as "lacks a no-store directive". A redirect response is
    not the resource, so its headers show nothing about the resource's cache policy.
    Leg 10.2a treats a 3xx the same way.

    304 is excluded and graded. A conditional-request answer comes from the resource
    itself and carries its validator and its policy.
    """
    if isinstance(status, bool) or not isinstance(status, int):
        detail = error or f"status {status!r}"
        return "error", (
            f"{label} did not answer with a numeric status ({detail}), so no "
            "attribution is possible"
        )
    if 300 <= status < 400 and status != 304:
        return "unknown", (
            f"{label} answered {status}, a redirect rather than the resource, so its "
            "headers say nothing about the resource's cache policy. The redirect was "
            "not followed"
        )
    if status >= 400:
        return "error", (
            f"{label} returned {status}, so cache policy cannot be attributed to "
            "the resource"
        )
    return None


def _static_verdict(
    status: object, headers: dict[str, str], error: str | None, label: str
) -> tuple[str, str]:
    """Grade a static resource's cache headers, in the audit's own branch order.

    The contradictory-directive branch is checked BEFORE the validator branch,
    matching the script: a resource carrying ``max-age`` alongside ``no-store`` is
    FAIL even though it also carries a validator.
    """
    gate = _status_gate(status, error, label)
    if gate is not None:
        return gate

    raw, tokens = _directives(headers)
    seen = raw if raw is not None else "no Cache-Control header"
    validator = next((name for name in _VALIDATOR_HEADERS if name in headers), None)

    contradictory = sorted(_NON_SHAREABLE.intersection(tokens))
    if contradictory:
        return "fail", (
            f"{label} carries a contradictory non-shareable directive alongside "
            f"caching ({status}, {' and '.join(contradictory)} present, "
            f"Cache-Control: {seen})"
        )
    if validator is not None and _has_max_age(tokens):
        return "pass", (
            f"{label} carries a validator ({validator}) and a Cache-Control "
            f"max-age ({status}, Cache-Control: {seen})"
        )
    return "fail", (
        f"{label} lacks a validator or a Cache-Control max-age ({status}, "
        f"validator: {validator or 'none'}, Cache-Control: {seen})"
    )


def _dynamic_verdict(
    status: object, headers: dict[str, str], error: str | None, label: str
) -> tuple[str, str]:
    """Grade dynamic content's cache headers: no-store or private, or FAIL.

    ``no-cache`` alone does not pass. The audit is explicit about it, matching
    ``no-store`` and ``private`` as directives and nothing else.
    """
    gate = _status_gate(status, error, label)
    if gate is not None:
        return gate

    raw, tokens = _directives(headers)
    seen = raw if raw is not None else "no Cache-Control header"

    present = sorted(_NON_SHAREABLE.intersection(tokens))
    if present:
        return "pass", (
            f"{label} is not shared-cacheable ({status}, "
            f"{' and '.join(present)} present, Cache-Control: {seen})"
        )
    return "fail", (
        f"{label} lacks a no-store or private directive ({status}, Cache-Control: "
        f"{seen}); no-cache alone does not pass, because the audit matches no-store "
        "or private as directives"
    )


def _blocked(ctx: ProbeContext) -> tuple[str, str] | None:
    """Return the outcome every request-making leg shares, or None to proceed.

    No endpoint is ERROR, because nothing was reached -- the guard checks 2.3 and
    2.5 both open with. A server that requires authentication and yielded no token
    is UNKNOWN, because no response can be attributed.

    ``ctx.authenticated`` is deliberately not read. ``client.py`` assigns it from
    ``auth_required``, so a reset session can leave it true with no token, and a
    token-less request would then have its 401 challenge read as the answer. A
    server that requires no authentication proceeds token-less, which is the common
    case: a public server and a local fixture both yield no token, and a bare
    "token present" gate would report ``unknown`` on both.
    """
    if not ctx.endpoint_url:
        return "error", "no endpoint to test against"
    if ctx.auth_required and not ctx.access_token:
        return "unknown", (
            "the server requires authentication and no access token was obtained, "
            "so no response can be attributed to it"
        )
    return None


def _resolve_operator_url(ctx: ProbeContext, path: str) -> tuple[str | None, str | None]:
    """Resolve an operator-named path against the endpoint's own registrable domain.

    Returns ``(url, mismatch_note)``, exactly one of which is set.

    The host guard is SSRF-shaped and admits any public host, so a path pointing
    elsewhere would produce a verdict the report attributes to the wrong server.
    A bare path is joined to ``ctx.base_url``, never to ``ctx.endpoint_url``, which
    may carry a ``/mcp`` suffix that the join would land inside.
    """
    absolute = path.startswith(("http://", "https://"))
    url = path if absolute else urljoin(ctx.base_url, path)

    target_host = host_of(url)
    if target_host is None:
        return None, f"{path!r} does not resolve to a URL with a host"

    endpoint_host = host_of(ctx.endpoint_url or "") or ""
    ours = registrable_domain(endpoint_host)
    theirs = registrable_domain(target_host)
    if ours is None or theirs is None or ours != theirs:
        return None, (
            f"{url} resolves to {target_host}, outside the endpoint's registrable "
            f"domain {ours or endpoint_host or 'unknown'}, so no request was made: "
            "a verdict there would be attributed to the wrong server"
        )
    return url, None


def _verdict(outcomes: set[str]) -> Status:
    """Aggregate leg outcomes as Section 3 does: fail > error > unknown > pass.

    There is no ``revision_unsupported`` branch, and none belongs here. Every
    Section 10 leg either reads an HTTP header or status, or reports a field's
    absence as an observation, so no leg can produce that outcome.
    """
    if "fail" in outcomes:
        return Status.FAIL
    if "error" in outcomes:
        return Status.ERROR
    if "unknown" in outcomes:
        return Status.UNKNOWN
    return Status.PASS


async def _endpoint_response(
    ctx: ProbeContext,
) -> tuple[object, dict | None, dict[str, str], str | None]:
    """POST one ``tools/list`` and return (status, data, headers, error).

    Leg 10.1b grades these headers as dynamic content and leg 10.1c reads the
    result's cacheable fields, so one request serves both. Leg 10.2a sends it as its
    control, which is why the revision headers here must match the ones that leg puts
    on its padded body: any header one sends and the other does not is a difference
    unrelated to size.

    ``raw_jsonrpc_headers`` does not catch its own transport failures, so they are
    caught here: no failure leaves ``run()``.
    """
    payload = {
        "jsonrpc": "2.0",
        "id": 101,
        "method": "tools/list",
        "params": {"_meta": _rc_meta()} if ctx.rc_supported else {},
    }
    extra = {"Mcp-Method": "tools/list"} if ctx.rc_supported else None
    try:
        status, data, _text, headers = await raw_jsonrpc_headers(
            ctx.endpoint_url or "",
            payload,
            token=ctx.access_token,
            session_id=ctx.session_id,
            protocol_header=RC_VERSION if ctx.rc_supported else None,
            extra_headers=extra,
        )
    except Exception as exc:  # noqa: BLE001 - a leg gets a string, never a raise
        return None, None, {}, repr(exc)
    return status, data, headers, None


async def _leg_static(
    ctx: ProbeContext, entry: dict, blocked: tuple[str, str] | None
) -> tuple[str, str]:
    """Leg 10.1a: the operator's static resource carries a validator and a max-age."""
    if blocked is not None:
        return blocked

    path = inputs.resource_path(entry, "static_resource_path")
    if path is None:
        return "unknown", (
            "no static_resource_path was named, so no static resource was fetched. "
            "There is no discovery route for one: MCP defines no HTTP static asset "
            "and resources/list returns protocol-layer URIs rather than files at a "
            "path. No path is guessed, because one that answered would belong to "
            "the vendor's web application rather than the audited server"
        )

    url, mismatch = _resolve_operator_url(ctx, path)
    if url is None:
        return "unknown", mismatch or "the operator path could not be resolved"

    status, headers, _text, error = await raw_get(url)
    if error == "guard-refused":
        return "unknown", (
            f"the host guard refused {url}, so no request was made; a refusal by "
            "our own guard is not a finding about the server"
        )
    return _static_verdict(status, headers, error, f"static resource {url}")


async def _leg_dynamic(
    ctx: ProbeContext,
    entry: dict,
    blocked: tuple[str, str] | None,
    status: object,
    headers: dict[str, str],
    error: str | None,
) -> tuple[str, str]:
    """Leg 10.1b: dynamic content is not shared-cacheable.

    The endpoint's own response is the default substrate and needs no operator
    input. Where the operator names a ``per_user_resource_path``, that is the
    audit's own substrate and is graded instead, with no substitution to declare.
    """
    if blocked is not None:
        return blocked

    path = inputs.resource_path(entry, "per_user_resource_path")
    if path is None:
        outcome, note = _dynamic_verdict(
            status, headers, error, "the endpoint's own tools/list response"
        )
        return outcome, note + (
            " [substrate: the endpoint's own response, graded as dynamic content, "
            "with no operator path named]"
        )

    url, mismatch = _resolve_operator_url(ctx, path)
    if url is None:
        return "unknown", mismatch or "the operator path could not be resolved"

    # The token goes with the request. A per-user resource is identity-scoped by
    # definition, so a token-less GET draws a 401 or a redirect to a login page on any
    # server that requires authentication -- making this leg undecidable in exactly
    # the deployment the override exists to serve.
    #
    # ``is_credential_safe_target`` makes the decision, as it does for check 3.3.1's
    # downstream leg. It is stricter than the registrable-domain check above: it also
    # requires https, so a plaintext operator path receives no credential.
    endpoint_host = host_of(ctx.endpoint_url or "") or ""
    credentialed = bool(ctx.access_token) and is_credential_safe_target(
        url, endpoint_host
    )
    own_status, own_headers, _text, own_error = await raw_get(
        url, token=ctx.access_token if credentialed else None
    )
    if own_error == "guard-refused":
        return "unknown", (
            f"the host guard refused {url}, so no request was made; a refusal by "
            "our own guard is not a finding about the server"
        )
    outcome, note = _dynamic_verdict(
        own_status, own_headers, own_error, f"per-user resource {url}"
    )
    sent = "with the bearer token" if credentialed else "with no credential"
    return outcome, note + (
        f" [substrate: the operator-named path {path}, fetched {sent}]"
    )


def _leg_cacheable_fields(
    data: dict | None, blocked: tuple[str, str] | None, rc_supported: bool
) -> tuple[str, str]:
    """Leg 10.1c: report the cacheable-result fields, never grade them.

    Never a verdict, for two independent reasons. The benchmark calls the
    protocol-layer block an optional aid rather than a required one. And grading it
    needs an operator-named per-user resource whose cache scope is the judgement leg
    10.1b already covers -- whether a resource is per-user is not something a remote
    client can decide, and it is not inferred from authentication, because a
    ``public`` result may be shared across callers even from an authenticated
    endpoint.

    No request of its own: it reads the ``tools/list`` response leg 10.1b already
    fetched.
    """
    if blocked is not None:
        return OBSERVED, f"the cacheable-result fields were not read: {blocked[1]}"

    result = (data or {}).get("result")
    if not isinstance(result, dict):
        return OBSERVED, (
            "the tools/list response carried no result object, so the "
            "cacheable-result fields could not be read"
        )

    present = [name for name in _CACHEABLE_FIELDS if name in result]
    absent = [name for name in _CACHEABLE_FIELDS if name not in result]
    values = ", ".join(f"{name}={result[name]!r}" for name in present) or "none present"
    if not absent:
        return OBSERVED, f"the tools/list result carries all three fields ({values})"
    if rc_supported:
        return OBSERVED, (
            f"the tools/list result is missing {', '.join(absent)}. The server "
            "negotiated 2026-07-28, where all three are required on every cacheable "
            f"result type, so their absence is a schema deviation ({values})"
        )
    return OBSERVED, (
        f"the tools/list result is missing {', '.join(absent)}, which the negotiated "
        f"revision does not yet define ({values})"
    )


async def _leg_body_limit(
    ctx: ProbeContext, entry: dict, blocked: tuple[str, str] | None
) -> tuple[str, str]:
    """Leg 10.2a: an oversized request body is rejected while a control is accepted.

    The order of the four steps is fixed and no step may move.

    1. Resolve the probe size. A stated but unusable value sends nothing at all.
    2. Send a control ``tools/list`` carrying the envelope, headers and credential
       the negotiated revision requires. The audit is explicit that a conforming
       server accepts the control, so a bare request would leave this permanently
       undecided.
    3. Read the control's outcome. Anything but 2xx stops here: a 413 proves nothing
       where the normal request was not accepted, because the rejection may not be
       about size.
    4. Only then send the padded body, with redirects disabled.
    """
    if blocked is not None:
        return blocked

    probe_bytes, stated_limit, rejection = inputs.probe_body_size(entry)
    if probe_bytes is None:
        return "unknown", f"{rejection}, so no request was sent"

    source = "the operator's stated limit" if stated_limit else "the tool's default"
    sizes = f"{probe_bytes} bytes, from {source}"

    control_status, _data, _headers, control_error = await _endpoint_response(ctx)
    if control_error is not None or not isinstance(control_status, int):
        return "error", (
            f"the control tools/list did not answer "
            f"({control_error or control_status!r}), so no attribution is possible "
            "and the padded body was not sent"
        )
    if not 200 <= control_status < 300:
        return "unknown", (
            f"the control tools/list returned {control_status} rather than a 2xx, so "
            "the padded body was not sent: a rejection of an oversized body proves "
            "nothing where the normal request was not accepted. Fix the request "
            f"envelope or the server, then re-run ({sizes} would have been sent)"
        )

    # The padding sits inside a JSON string value, so the body still parses. Appended
    # as junk after the JSON it would draw a parse error and a status that says
    # nothing about size, losing both the fail branch and the 2xx branch.
    params: dict = {"pad": "X" * (probe_bytes + 1)}
    if ctx.rc_supported:
        params["_meta"] = _rc_meta()
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 102, "method": "tools/list", "params": params}
    ).encode()

    # The padded request carries the control's headers, because the audit's design is
    # ONE request, padded. Any header the control sends and this one does not is a
    # difference unrelated to size: without Accept, a conforming streamable-HTTP
    # server answers 406, and the leg would read its own malformed request as the
    # server's way of signalling oversize. Measured against a live server before this
    # was fixed: 406 on the padded body against a 200 control.
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if ctx.session_id:
        headers["Mcp-Session-Id"] = ctx.session_id
    if ctx.rc_supported:
        headers["MCP-Protocol-Version"] = RC_VERSION
        headers["Mcp-Method"] = "tools/list"

    over_status, _over_headers, _text, over_error = await raw_endpoint_request(
        "POST",
        ctx.endpoint_url or "",
        extra_headers=headers,
        token=ctx.access_token,
        content=body,
        timeout=30.0,
    )
    sent = f"sent {len(body)} bytes against a probe size of {sizes}"

    if over_error is not None or not isinstance(over_status, int):
        # The audit's own REVIEW for this branch: a closed connection or a write
        # timeout mid-upload is one of the ways a server signals oversize, so it is
        # not attributed either way.
        return "unknown", (
            f"the connection closed or timed out on the oversized body "
            f"({over_error or over_status!r}); {sent}. Confirm whether that is size "
            "enforcement or an unrelated fault"
        )
    if over_status == 413:
        return "pass", (
            f"the oversized body was rejected with 413 while the control was "
            f"accepted with {control_status}; {sent}. A limit is enforced at or "
            "below that size whatever the configured value is"
        )
    if 300 <= over_status < 400:
        return "unknown", (
            f"the oversized body drew a {over_status} redirect; {sent}. Redirects "
            "are disabled here, because following one would re-send the whole body "
            "to a location the server chose, past the host guard"
        )
    if 200 <= over_status < 300:
        if stated_limit is not None:
            return "fail", (
                f"the oversized body was accepted with {over_status} at the HTTP "
                f"layer, so no request-body size limit is enforced at the "
                f"{stated_limit}-byte limit the operator stated (control "
                f"{control_status}); {sent}"
            )
        return "unknown", (
            f"the oversized body was accepted with {over_status} (control "
            f"{control_status}); {sent}. No limit sits at or below that size, which "
            "is not the same claim as no limit at all, so this is not reported as "
            "non-compliance. Set max_request_bytes to the configured limit to decide "
            "it"
        )
    return "unknown", (
        f"the oversized body returned {over_status} (control {control_status}); "
        f"{sent}. Confirm how the server signals oversize"
    )


@register
class CachePolicy(Check):
    id = "10.1"
    title = (
        "Static resources are cached with freshness limits and per-user data is "
        "never shared-cached"
    )
    section = "10"
    level = Level.L1
    remediation = (
        "Enable ETag or Last-Modified generation for genuinely static content and "
        "set a Cache-Control max-age appropriate to how static each resource is, "
        "with invalidation on update. Mark every dynamic, identity-sensitive and "
        "authorization-related response Cache-Control: no-store. At the protocol "
        "layer, set cacheScope private on any per-user or identity-sensitive "
        "result, reserve public for genuinely non-identity-specific data, and set "
        "ttlMs to a freshness bound appropriate to the data."
    )

    async def run(self, ctx: ProbeContext) -> CheckResult:
        entry = inputs.load(ctx.domain)
        blocked = _blocked(ctx)

        # One endpoint request, whether or not the operator named a path: leg 10.1c
        # reads its result fields even when leg 10.1b grades an operator path.
        status: object = None
        data: dict | None = None
        headers: dict[str, str] = {}
        error: str | None = None
        if blocked is None:
            status, data, headers, error = await _endpoint_response(ctx)

        results = []
        outcome, note = await _leg_static(ctx, entry, blocked)
        results.append(("10.1a", outcome, note))
        outcome, note = await _leg_dynamic(ctx, entry, blocked, status, headers, error)
        results.append(("10.1b", outcome, note))
        outcome, note = _leg_cacheable_fields(data, blocked, ctx.rc_supported)
        results.append(("10.1c", outcome, note))

        details = {
            "legs": {leg: outcome for leg, outcome, _ in results},
            "endpoint_status": status,
            "endpoint_cache_control": headers.get("cache-control"),
        }
        evidence = (
            "; ".join(f"{leg}: {note}" for leg, _, note in results) + CACHE_REDUCTION
        )
        outcomes = {outcome for _, outcome, _ in results}
        return self._make(_verdict(outcomes), evidence, **details)


@register
class RequestBodyLimit(Check):
    id = "10.2"
    title = (
        "Request and response body size limits, token budgets, and per-principal "
        "quotas are enforced"
    )
    section = "10"
    level = Level.L1
    remediation = (
        "Configure a maximum request-body size at the reverse proxy and "
        "independently in MCP application middleware, so a proxy misconfiguration "
        "does not remove the only enforcement point. Set a maximum non-streaming "
        "response-payload size and a per-message bound for streamed responses, "
        "configure per-request and per-workload token-budget caps for "
        "model-proxying calls, and set per-principal and per-tenant rate quotas "
        "distinct from the global limits."
    )

    async def run(self, ctx: ProbeContext) -> CheckResult:
        entry = inputs.load(ctx.domain)
        blocked = _blocked(ctx)

        outcome, note = await _leg_body_limit(ctx, entry, blocked)
        results = [("10.2a", outcome, note)]

        details = {"legs": {leg: outcome for leg, outcome, _ in results}}
        # The dropped leg is listed rather than left out, so a reader sees it exists
        # and was not probed. Its five obligations are spelled out in the evidence.
        details["legs"]["10.2b"] = DROPPED
        evidence = (
            "; ".join(f"{leg}: {note}" for leg, _, note in results)
            + BODY_LIMIT_REDUCTION
        )
        outcomes = {outcome for _, outcome, _ in results}
        return self._make(_verdict(outcomes), evidence, **details)
