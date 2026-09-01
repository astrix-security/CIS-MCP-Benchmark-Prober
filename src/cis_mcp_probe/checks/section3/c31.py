"""Check 3.1: remote authentication is required and the issued token is short-lived.

Confirms an unauthenticated request is refused with a 401 challenge naming
resource_metadata, then reads the issued token's lifetime against a 1-hour
baseline. The authorization server's iss-parameter support and registration
requirements are recorded as evidence only; neither ever changes the verdict.
"""

from __future__ import annotations

import httpx
from mcp.client.auth.utils import extract_resource_metadata_from_www_auth

from ... import tokens
from ...context import ProbeContext
from ..base import Check, CheckResult, Level, register

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
    id = "3.1"
    title = "Remote MCP servers require authentication and issue short-lived tokens"
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
            ("3.1a", *self._leg_refusal_and_challenge(ctx)),
            ("3.1b", *self._leg_lifetime(ctx)),
            ("3.1c", *self._leg_iss_flag(ctx)),
            ("3.1d", *self._leg_registration_requirements(ctx)),
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
            f"authorization-server iss-parameter support advertised as "
            f"{supported!r}",
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


if __name__ == "__main__":
    import asyncio

    def _status(**fields) -> str:
        ctx = ProbeContext(domain="probe.test", base_url="https://mcp.example.com")
        for name, value in fields.items():
            setattr(ctx, name, value)
        return asyncio.run(RemoteAuthentication().run(ctx)).status.value

    # A server that was never reached tells us nothing. Reporting a refusal
    # failure there would state something the probe did not observe, and FAIL
    # also lands in the pass-rate denominator while ERROR does not.
    assert _status() == "ERROR"
    # A server that WAS reached and answered an unauthenticated request is a
    # genuine failure of this recommendation, and must stay one.
    assert _status(endpoint_url="https://mcp.example.com/mcp") == "FAIL"
    # A lifetime over the baseline fails; one at or under it does not. Neither
    # reads a clock: both come from the value the token response carried.
    assert (
        _status(
            endpoint_url="https://mcp.example.com/mcp",
            auth_required=True,
            token_expires_in=LIFETIME_BASELINE_SECONDS + 1,
        )
        == "FAIL"
    )
    print("c31: all self-checks passed")
