"""Check 3.4: the issued token cannot be passed through to another resource.

Confirms the token's aud claim, when readable, holds nothing beyond the
canonical resource URI. An extra entry is a fully observed property of the
token itself, so it fails with the entries named -- but we cannot confirm from
the token alone that the extra entry is a downstream API rather than
passthrough, and that caveat is stated alongside the failure. An opaque token
cannot be read at all and records unknown, never fail: a permanent non-verdict
on an unobservable token would only hide the case where we simply cannot tell.
"""

from __future__ import annotations

from mcp.shared.auth_utils import resource_url_from_server_url

from ... import tokens
from ...context import ProbeContext
from ...netguard import resource_covers
from ..base import Check, CheckResult, Level, register


def _canonical_uri(ctx: ProbeContext) -> str:
    """The resource URI our token request targeted.

    resource_url_from_server_url(ctx.endpoint_url), unless the protected-resource
    document advertises a resource value that is an accepting parent of it under
    RFC 8707 hierarchical matching -- never the server's raw advertised value on
    its own.

    The advertised value comes from a document the audited server controls, so it
    goes through the guarded matcher. When that cannot answer -- the advertised
    string is not a URL the matching rule can parse -- the value is not
    substituted, and the URI derived from the endpoint stands.
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
    id = "3.4"
    title = "The issued token's audience is confined to the audited resource"
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
            if ctx.auth_required or ctx.prm_documents:
                return self._unknown(
                    "the server requires authentication but no access token was "
                    "obtained, so no issued token's aud claim could be read",
                    legs={"3.4a": "unknown"},
                )
            return self._na(
                "the server offers no OAuth at all, so no issued token exists "
                "whose audience could be confined"
            )

        claims = tokens.jwt_claims(ctx.access_token)
        if claims is None:
            return self._unknown(
                "the access token is opaque, so its aud claim is not readable",
                legs={"3.4a": "unknown"},
            )

        auds = tokens.audiences(claims)
        if not auds:
            return self._unknown(
                "the token carries no aud claim, so audience confinement is "
                "not observable",
                legs={"3.4a": "unknown"},
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
                legs={"3.4a": "fail"},
                extra_audiences=extra,
            )
        return self._pass(
            f"aud names only the canonical resource {canonical!r}",
            legs={"3.4a": "pass"},
        )


if __name__ == "__main__":
    import asyncio
    import base64
    import json

    def _jwt(aud) -> str:
        body = base64.urlsafe_b64encode(json.dumps({"aud": aud}).encode()).decode()
        return f"header.{body.rstrip('=')}.signature"

    def _ctx(endpoint: str | None, aud=None, advertised: str | None = None):
        return ProbeContext(
            domain="probe.test",
            base_url="https://mcp.example.com",
            endpoint_url=endpoint,
            access_token=_jwt(aud) if aud else None,
            protected_resource_metadata=(
                {"resource": advertised} if advertised is not None else None
            ),
        )

    def _status(endpoint: str | None, aud, advertised: str | None = None) -> str:
        return asyncio.run(
            NoTokenPassthrough().run(_ctx(endpoint, aud, advertised))
        ).status.value

    # A root-detected endpoint carries a trailing slash into the canonical URI,
    # and the same name without one is the same resource.
    assert (
        _canonical_uri(_ctx("https://mcp.example.com/")) == "https://mcp.example.com/"
    )

    # The advertised resource, all three ways it can relate to the canonical URI.
    # A parent is substituted, a value that does not cover the canonical URI is
    # not, and one the matching rule cannot parse is not either -- the last is a
    # string the audited server chose, and it must yield a verdict, not a raise.
    assert (
        _canonical_uri(
            _ctx("https://mcp.example.com/mcp", advertised="https://mcp.example.com")
        )
        == "https://mcp.example.com"
    )
    assert (
        _canonical_uri(
            _ctx("https://mcp.example.com/mcp", advertised="https://other.example.com")
        )
        == "https://mcp.example.com/mcp"
    )
    assert (
        _canonical_uri(
            _ctx("https://mcp.example.com/mcp", advertised="https://exa[mple.com")
        )
        == "https://mcp.example.com/mcp"
    )
    assert (
        _status(
            "https://mcp.example.com/mcp",
            "https://mcp.example.com/mcp",
            advertised="https://exa[mple.com",
        )
        == "PASS"
    )

    assert (
        _strip_trailing_slash("https://mcp.example.com/") == "https://mcp.example.com"
    )
    assert _strip_trailing_slash("https://mcp.example.com") == "https://mcp.example.com"
    assert _status("https://mcp.example.com/", "https://mcp.example.com") == "PASS"
    assert _status("https://mcp.example.com", "https://mcp.example.com/") == "PASS"
    assert (
        _status("https://mcp.example.com/mcp", "https://mcp.example.com/mcp") == "PASS"
    )
    # A different host is still an extra audience.
    assert _status("https://mcp.example.com/", "https://other.example.com") == "FAIL"
    assert (
        _status(
            "https://mcp.example.com/",
            ["https://mcp.example.com", "https://other.example.com"],
        )
        == "FAIL"
    )
    # No endpoint was reached, so nothing is known about this server's audiences.
    assert _status(None, "https://mcp.example.com") == "ERROR"
    print("c34: all self-checks passed")
