"""Check 3.6 — confused-deputy safeguards on an OAuth proxy.

Four legs, recorded under ``details["legs"]``:

* ``3.6-pre`` — whether the recommendation applies at all. It applies to a
  server that fronts a separate authorization server on one static client id
  shared by every client it registers. Establishing that condition means
  registering twice and comparing the client id each authorize redirect carries
  onward. A server whose authorization endpoint is its own is not fronting
  anything, so the condition is settled from metadata alone and no registration
  is made.
* ``3.6a`` — an authorize request varying only ``redirect_uri`` is refused while
  the registered value is accepted.
* ``3.6b`` — the callback refuses a fabricated code carrying a state that was
  never issued. A nonsense path on the same origin is fetched as a control, so a
  response the server serves for everything cannot be read as a refusal.
* ``3.6c`` — a client id the authorization server has never seen is not handed
  onward to the upstream authorization server without a consent step.

Legs 3.6-pre and 3.6c create real clients at the authorization server, so both
run only once the metadata gate has passed. The clients they create are cached
under a scratch key of their own and never under the key holding the working
token: a client registration written over that key invalidates the cached token
and forces a fresh browser login.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit

from mcp.client.auth.oauth2 import PKCEParameters
from mcp.shared.auth import OAuthClientInformationFull
from mcp.shared.auth_utils import resource_url_from_server_url

from ...context import ProbeContext
from ...netguard import host_of, parts_of
from ...rawreq import raw_get, raw_post_json
from ...storage import FileTokenStorage
from ..base import Check, CheckResult, Level, register
from .observations import unanswered, unread

# Where a registered client would be sent back to. Nothing listens on it: no
# flow started here is ever completed, so no code is ever redeemed.
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
REDUCTION = (
    " Reduced scope: no interactive login is performed, so only the part of each "
    "safeguard that fires before authentication is observed -- a redirect_uri or "
    "a client id that is validated only after the user authenticates is not "
    "reachable from here. 3.6b sends a fabricated code, so the invalid code "
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

    The control is a nonsense path on the same origin. It is a parameter rather
    than a comparison made afterwards, because the same status means opposite
    things depending on it: a server that answers a catch-all 200 for any unknown
    path never reached a callback handler at all, and reading that as a handler
    accepting the fabricated code would invent a finding.
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

    A JSON body, with the plural members as real arrays. RFC 7591 section 3.1
    requires ``application/json`` at the registration endpoint, and a conforming
    authorization server answers 400 or 415 to a form-encoded one.
    """
    return {
        "client_name": "cis-mcp-probe (3.6 scratch client)",
        "redirect_uris": [SCRATCH_REDIRECT_URI],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
    }


def _gate_reason(
    ctx: ProbeContext, endpoint: str, authorize: object, register_at: object
) -> tuple[str, str] | None:
    """What 3.6 may conclude without probing, or None when it must probe.

    Returns the outcome and why: ``"na"`` when the recommendation is vacuous for
    this target, ``"unknown"`` when the metadata that would decide it was never
    read. Decided from the discovery record alone, before any client is
    registered.
    """
    if not isinstance(ctx.auth_server_metadata, dict):
        # No document, and several reasons for that. An attempt that failed or was
        # refused under either prefix leaves what it holds unread; and a run that
        # never fetched protected-resource metadata at all learned nothing about
        # what this endpoint advertises. Either way the answer is undecided rather
        # than vacuous. Only when discovery answered for itself -- a document that
        # named no authorization server, or a clean 404 -- is there nothing here
        # for the recommendation to bite on.
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
    """3.6, Assessment Status: Automated.

    Applies to a server fronting a separate authorization server on one static
    client id. On such a server it varies the ``redirect_uri``, replays a
    fabricated code at the callback against a control path, and starts a flow on
    a client id the authorization server has never seen.
    """

    id = "3.6"
    title = (
        "An OAuth proxy validates redirect_uri, callback state and consent for "
        "every client it registers"
    )
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

        # 3.6-pre, first half: settled from the discovery record, before any
        # registration. A target the recommendation is vacuous for and a target
        # whose metadata was never read are different answers.
        gate = _gate_reason(ctx, endpoint, authorize, register_at)
        if gate:
            outcome, reason = gate
            verdict = self._unknown if outcome == "unknown" else self._na
            return verdict(
                f"3.6-pre: {reason}." + REDUCTION,
                legs={"3.6-pre": "unknown"},
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

        # 3.6-pre, second half: two registrations, and the client id each
        # authorize redirect carries onward.
        first_id, first_note = await self._register(str(register_at), scratch)
        if first_id is None:
            return self._na(
                f"3.6-pre: {first_note}, so the static-client-id condition was not "
                "established." + REDUCTION,
                legs={"3.6-pre": "unknown"},
                registrations=registrations,
            )
        registrations.append(first_id)
        first = await raw_get(authorize_url(first_id, SCRATCH_REDIRECT_URI))

        second_id, second_note = await self._register(str(register_at), scratch)
        if second_id is None:
            return self._na(
                f"3.6-pre: {second_note}, so the static-client-id condition was not "
                "established." + REDUCTION,
                legs={"3.6-pre": "unknown"},
                registrations=registrations,
            )
        registrations.append(second_id)
        second = await raw_get(authorize_url(second_id, SCRATCH_REDIRECT_URI))

        first_downstream = _downstream_client_id(first[1].get("location", ""))
        second_downstream = _downstream_client_id(second[1].get("location", ""))
        if not first_downstream or first_downstream != second_downstream:
            return self._na(
                f"3.6-pre: registered {first_id} and {second_id}, and their "
                f"authorize responses (HTTP {first[0]}, {second[0]}) carry the "
                f"onward client ids {first_downstream!r} and {second_downstream!r}. "
                "They are not one shared static value, so this server does not "
                "front a separate authorization server on a static client id and "
                "the recommendation is vacuous for it." + REDUCTION,
                legs={"3.6-pre": "unknown"},
                registrations=registrations,
                downstream_client_ids=[first_downstream, second_downstream],
            )

        legs = [
            (
                "3.6-pre",
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

        evidence = "; ".join(f"{leg}: {note}" for leg, _, note in legs) + REDUCTION
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
        """3.6a — vary only redirect_uri and require the varied value refused."""
        status, headers, body, error = await raw_get(varied_url)
        location = headers.get("location", "")
        registered_status = registered[0]

        if _is_code_leak(location):
            return (
                "3.6a",
                "fail",
                f"the authorize request carrying redirect_uri="
                f"{VARIED_REDIRECT_URI} answered HTTP {status} and redirected to "
                "a location carrying an authorization code, so the code leaks to "
                "a redirect target that was never registered",
            )
        if error or status is None:
            return (
                "3.6a",
                "error",
                f"the authorize request varying redirect_uri did not complete "
                f"({error}), so the registered value was never compared against a "
                "varied one",
            )
        if registered_status is None or 400 <= registered_status < 500:
            return (
                "3.6a",
                "error",
                f"the authorize request carrying the registered redirect_uri was "
                f"itself refused (HTTP {registered_status}), so a refusal of the "
                "varied one is not attributable to redirect_uri validation",
            )
        if 400 <= status < 500:
            return (
                "3.6a",
                "pass",
                f"the registered redirect_uri was accepted (HTTP "
                f"{registered_status}) and varying it alone to "
                f"{VARIED_REDIRECT_URI} was refused with HTTP {status}: "
                f"{body[:200]}",
            )
        if 300 <= status < 400:
            if host_of(location) == host_of(VARIED_REDIRECT_URI):
                return (
                    "3.6a",
                    "fail",
                    f"the authorize request carrying redirect_uri="
                    f"{VARIED_REDIRECT_URI} answered HTTP {status} and redirected "
                    f"to {location}, so the unregistered redirect target was "
                    "honoured rather than refused",
                )
            if _has_oauth_error(location):
                return (
                    "3.6a",
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
                "3.6a",
                "unknown",
                f"the authorize request carrying redirect_uri="
                f"{VARIED_REDIRECT_URI} answered HTTP {status} redirecting to "
                f"{location}, which names no error and is not the varied target, "
                "so the flow carried on for a redirect_uri that was never "
                "registered without refusing it up front",
            )
        return (
            "3.6a",
            "unknown",
            f"the authorize request carrying redirect_uri={VARIED_REDIRECT_URI} "
            f"answered HTTP {status} with no redirect, which says nothing about "
            "whether the value was validated: an authorization server that "
            "validates it only after the user authenticates answers the same way",
        )

    async def _leg_callback(self, endpoint: str) -> tuple[str, str, str]:
        """3.6b — a fabricated code with an unissued state, against a control."""
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
        return "3.6b", outcome, note

    async def _leg_consent(
        self,
        registration_endpoint: str,
        authorization_endpoint: str,
        scratch: FileTokenStorage,
        registrations: list[str],
        authorize_url: Callable[[str, str], str],
    ) -> tuple[str, str, str]:
        """3.6c — a never-before-seen client id must meet a consent step."""
        client_id, note = await self._register(registration_endpoint, scratch)
        if client_id is None:
            return (
                "3.6c",
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
                "3.6c",
                "error",
                f"the authorize request on the freshly registered {client_id} did "
                f"not complete ({error}), so no consent step was observed",
            )
        location = headers.get("location", "")
        if 300 <= status < 400:
            target = host_of(location)
            if target and target != host_of(authorization_endpoint):
                return (
                    "3.6c",
                    "fail",
                    f"the first response for the freshly registered {client_id} is "
                    f"HTTP {status} redirecting straight to {target}, the upstream "
                    "authorization server, so a client id the server had never "
                    "seen was handed onward on the shared static client id with no "
                    "consent step of its own",
                )
            return (
                "3.6c",
                "pass",
                f"the first response for the freshly registered {client_id} is "
                f"HTTP {status} redirecting to {location}, which stays on the "
                "authorization server's own host rather than handing the new "
                "client straight onward",
            )
        if 200 <= status < 300:
            return (
                "3.6c",
                "pass",
                f"the first response for the freshly registered {client_id} is "
                f"HTTP {status}, a page served by the authorization server itself "
                "rather than an immediate hand-off to the upstream one",
            )
        return (
            "3.6c",
            "error",
            f"the authorize request on the freshly registered {client_id} was "
            f"refused with HTTP {status}, so the consent step was never reached",
        )


if __name__ == "__main__":
    from mcp.client.auth.oauth2 import PKCEParameters

    # test-type: ground-truth-vendor | source: RFC 7636 section 4.2, via
    # mcp.client.auth.oauth2.PKCEParameters | captured-from: mcp 1.28.1
    # last-revalidated: 2026-09-01
    # Pinned through the SDK we depend on rather than a reimplementation.
    p = PKCEParameters.generate()
    assert 43 <= len(p.code_verifier) <= 128
    assert "=" not in p.code_challenge
    assert PKCEParameters.generate().code_verifier != p.code_verifier
    # Signature is (status, body, location, control_status).
    #
    # A control that answers the same as the callback means there is no handler at
    # all, so the mechanism was never reached whatever the status was.
    assert _classify_callback(400, "", "", 400) == "error"
    assert _classify_callback(200, "", "", 200) == "error"
    # A bare 4xx with no error body is unattributable, so it is an error, not a pass.
    assert _classify_callback(400, "", "", 404) == "error"
    assert _classify_callback(400, '{"error":"invalid_grant"}', "", 404) == "pass"
    assert _classify_callback(302, "", "https://as.example/cb?error=x", 404) == "pass"
    assert _classify_callback(200, "", "", 404) == "fail"
    # A leaked code outranks the control: it is a finding even where the control
    # matches, because the code in the redirect is positive evidence on its own.
    assert (
        _classify_callback(302, "", "https://attacker.example/cb?code=a", 302) == "fail"
    )
    # A server error says nothing about whether a handler exists.
    assert _classify_callback(500, "", "", 404) == "error"
    assert _classify_callback(502, "", "", 404) == "error"
    # A leaked code still outranks everything, including a 5xx.
    assert (
        _classify_callback(502, "", "https://attacker.example/cb?code=a", 404) == "fail"
    )
    # A control that never answered for itself, or answered 5xx, is no baseline:
    # what this origin serves for an unknown path was not observed, so a 200 on
    # the callback is not attributable to a handler.
    assert _classify_callback(200, "", "", None) == "error"
    assert _classify_callback(200, "", "", 503) == "error"
    # An answering control still grades the same way it always did.
    assert _classify_callback(200, "", "", 404) == "fail"
    # A leaked code outranks a missing baseline too.
    assert (
        _classify_callback(302, "", "https://attacker.example/cb?code=a", None)
        == "fail"
    )
    # A 302 whose Location carries an authorization code is a leak, not a rejection.
    assert _is_code_leak("https://attacker.example.com/cb?code=abc&state=x")
    assert not _is_code_leak("https://attacker.example.com/cb?error=invalid_request")
    assert not _is_code_leak("")
    # A location the server chose may not be parseable at all. Neither reader may
    # raise on one: an unbalanced bracket in the authority makes urlsplit raise.
    UNPARSEABLE = "https://exa[mple.com/cb?code=a"
    assert not _is_code_leak(UNPARSEABLE)
    assert _downstream_client_id(UNPARSEABLE) is None
    assert (
        _downstream_client_id("https://as.example/authorize?client_id=shared")
        == "shared"
    )
    assert _downstream_client_id("https://as.example/authorize") is None

    # The applicability gate, over hand-built contexts and no network. Two legs of
    # this check register real clients at a real authorization server, so every
    # case below must return before any registration is made.
    import asyncio
    import tempfile
    from pathlib import Path

    from ... import storage as _storage
    from ...context import HttpObservation
    from ..base import Status

    _tmp = Path(tempfile.mkdtemp())
    _storage.DATA_DIR = _tmp / "tokens"
    _storage.DATA_DIR.mkdir(parents=True)

    ENDPOINT = "https://mcp.example.com/mcp"
    AS_FORM = "https://as.example.com/.well-known/oauth-authorization-server"
    PRM_URL = "https://mcp.example.com/.well-known/oauth-protected-resource"

    def _context(**kwargs) -> ProbeContext:
        return ProbeContext(
            domain="probe.test",
            base_url="https://mcp.example.com",
            endpoint_url=ENDPOINT,
            auth_required=True,
            **kwargs,
        )

    def _verdict(ctx: ProbeContext) -> CheckResult:
        return asyncio.run(ConfusedDeputySafeguards().run(ctx))

    ISSUER = "https://as.example.com"
    # A protected-resource document that answered and was parsed. An as: attempt is
    # only ever made against an issuer such a document advertised, so a fixture
    # carrying one without it describes a run that cannot happen.
    PRM_READ = {f"prm:{PRM_URL}": HttpObservation(PRM_URL, "GET", 200)}
    PRM_ADVERTISING = {
        PRM_URL: {"resource": ENDPOINT, "authorization_servers": [ISSUER]}
    }

    # No metadata, and an attempt that failed or was refused: the document is
    # unread, which is not the same as a server that advertises none.
    for http, documents, why in (
        (
            PRM_READ | {f"as:{ISSUER}:{AS_FORM}": HttpObservation(AS_FORM, "GET", 502)},
            PRM_ADVERTISING,
            "502",
        ),
        (
            PRM_READ
            | {
                f"as:{ISSUER}:{AS_FORM}": HttpObservation(
                    AS_FORM, "GET", None, error="guard-refused"
                )
            },
            PRM_ADVERTISING,
            "guard-refused",
        ),
        (
            {f"prm:{PRM_URL}": HttpObservation(PRM_URL, "GET", None, error="timeout")},
            {},
            "timeout",
        ),
    ):
        undecided = _verdict(_context(http=http, prm_documents=documents))
        assert undecided.status is Status.UNKNOWN, (why, undecided.status)
        assert why in undecided.evidence, undecided.evidence
        assert undecided.details["registrations"] == [], undecided.details

    # A protected-resource document that was read and advertises no authorization
    # server is an observation: there is none for this server to front, and the
    # recommendation is vacuous. The document that answered is not an attempt that
    # left anything unobserved, so the verdict must not name it as one.
    read_it = _verdict(
        _context(http=PRM_READ, prm_documents={PRM_URL: {"resource": ENDPOINT}})
    )
    assert read_it.status is Status.NOT_APPLICABLE, read_it.status
    assert PRM_URL not in read_it.evidence, read_it.evidence
    assert read_it.details["registrations"] == [], read_it.details

    # Nothing fetched at all decides nothing. The absence of a document is then a
    # fact about this run rather than about the server, so it cannot rule the
    # recommendation out.
    absent = _verdict(_context())
    assert absent.status is Status.UNKNOWN, absent.status
    assert (
        "no protected-resource metadata discovery was attempted at all"
        in absent.evidence
    ), absent.evidence
    assert absent.details["registrations"] == [], absent.details

    # Every path answering a clean 404 is the server saying it serves no such
    # document -- on the protected-resource paths, or on the metadata paths of an
    # issuer a document that did answer advertised.
    for http, documents in (
        ({f"prm:{PRM_URL}": HttpObservation(PRM_URL, "GET", 404)}, {}),
        (
            PRM_READ | {f"as:{ISSUER}:{AS_FORM}": HttpObservation(AS_FORM, "GET", 404)},
            PRM_ADVERTISING,
        ),
    ):
        answered = _verdict(_context(http=http, prm_documents=documents))
        assert answered.status is Status.NOT_APPLICABLE, answered.status

    # A first-party server authorizes for itself, so it fronts nothing. This case
    # must cost no registration: one written over the live key forces a fresh
    # browser login for the operator.
    FIRST_PARTY = {
        "authorization_endpoint": "https://mcp.example.com/oauth/authorize",
        "registration_endpoint": "https://mcp.example.com/oauth/register",
    }
    own_host = _verdict(_context(auth_server_metadata=FIRST_PARTY))
    assert own_host.status is Status.NOT_APPLICABLE, own_host.status
    assert own_host.details["registrations"] == [], own_host.details
    assert "mcp.example.com" in own_host.evidence
    written = sorted(p.name for p in (_tmp / "tokens").glob("*"))
    assert written == [], written

    # An authorization_endpoint that cannot be parsed cannot have an authorize
    # request built against it, so the gate says so instead of raising later.
    broken = _verdict(
        _context(
            auth_server_metadata={
                "authorization_endpoint": "https://exa[mple.com/authorize",
                "registration_endpoint": "https://as.example.com/register",
            }
        )
    )
    assert broken.status is Status.UNKNOWN, broken.status
    assert broken.details["registrations"] == [], broken.details
    assert sorted(p.name for p in (_tmp / "tokens").glob("*")) == []

    # A document that names both endpoints on a separate host is past the gate.
    assert (
        _gate_reason(
            _context(
                auth_server_metadata={
                    "authorization_endpoint": "https://as.example.com/authorize",
                    "registration_endpoint": "https://as.example.com/register",
                }
            ),
            ENDPOINT,
            "https://as.example.com/authorize",
            "https://as.example.com/register",
        )
        is None
    )
    # Every case above returned before any registration, so nothing was written to
    # the redirected storage. Listed rather than asserted alone, because a client
    # written here would be a real credential created at a real server.
    print(
        f"c36: token storage holds {sorted(p.name for p in _storage.DATA_DIR.glob('*'))}"
    )
    print("c36: all self-checks passed")
