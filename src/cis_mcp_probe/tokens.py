"""Read lifetime, scope and audience out of an OAuth access token.

Authorization checks need three things about the token a server issued us: how
long it lives, what it was granted, and who it is addressed to. Where the token
is a JWT those live in its payload (``exp``, ``iat``, ``scope``, ``scp``,
``aud``); where it is opaque, nothing is readable at all. Every function here
returns ``None`` or an empty list for "not observable" rather than guessing, so
a caller can tell an unreadable token from a token that really carries nothing.

The lifetime reported is the lifetime the token was *issued* with, computed
without reading a clock: ``expires_in`` from the token response, or ``exp - iat``
from the payload. ``exp`` minus the current time would measure how much life is
left, so a token read from cache an hour after it was issued would report an
hour less than the server actually granted.
"""

from __future__ import annotations

import base64
import json
from typing import Any


def jwt_claims(token: str) -> dict[str, Any] | None:
    """Decode a JWT payload, or return None when the token isn't a JWT.

    The payload is the second of three dot-separated segments, base64url with
    its padding stripped. A token that is opaque, malformed, or whose payload
    decodes to something other than a JSON object yields None.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return None
    padded = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        claims = json.loads(base64.urlsafe_b64decode(padded))
    except ValueError:
        # Covers binascii.Error, JSONDecodeError and UnicodeDecodeError.
        return None
    return claims if isinstance(claims, dict) else None


def issued_lifetime(
    expires_in: int | None, claims: dict[str, Any] | None
) -> int | None:
    """Return the lifetime in seconds the token was issued with, or None.

    Prefers ``expires_in`` from the token response, falls back to ``exp - iat``
    from the payload. No clock is read.
    """
    if expires_in is not None:
        return expires_in
    exp = (claims or {}).get("exp")
    iat = (claims or {}).get("iat")
    if isinstance(exp, (int, float)) and isinstance(iat, (int, float)):
        return int(exp - iat)
    return None


def _scope_list(value: Any) -> list[str]:
    """Normalise a scope value that may be a space-delimited string or a list."""
    if isinstance(value, str):
        return value.split()
    if isinstance(value, list):
        return [s for s in value if isinstance(s, str)]
    return []


def observed_scopes(
    scope: str | None, claims: dict[str, Any] | None
) -> list[str] | None:
    """Return the granted scopes, or None when no source stated any.

    Three sources in order: the ``scope`` field of the token response, the
    ``scope`` claim, then the ``scp`` claim. Issuers write ``scp`` as either a
    list or a space-delimited string, so both are accepted.

    None and [] are different answers, and every caller depends on the
    difference. None means no source stated a scope, so nothing was observed. []
    means a source stated one and it is empty. Reading the first as the second
    claims a grant of zero scopes that was never seen, and a later comparison
    against that record then finds no growth on a run that observed nothing.

    The token response wins even when it is empty, because a server that states
    an empty grant has stated the grant. A claim whose value is neither a string
    nor a list states nothing readable, so the next source is tried.
    """
    if scope is not None:
        return scope.split()
    for key in ("scope", "scp"):
        value = (claims or {}).get(key)
        if isinstance(value, (str, list)):
            return _scope_list(value)
    return None


def audiences(claims: dict[str, Any] | None) -> list[str]:
    """Return the ``aud`` claim as a list, or [] when absent.

    ``aud`` is legitimately either a single string or a list of strings.
    """
    aud = (claims or {}).get("aud")
    if isinstance(aud, str):
        return [aud]
    if isinstance(aud, list):
        return [a for a in aud if isinstance(a, str)]
    return []


def has_wildcard(scopes: list[str]) -> list[str]:
    """Return the scopes whose last colon-segment is ``*``.

    A scope with no colon is its own last segment, so a bare ``*`` matches.
    This is not glob matching: ``issues:read`` and ``read:write`` are ordinary
    namespaced scopes, and only a literal ``*`` segment counts.
    """
    return [s for s in scopes if s.split(":")[-1] == "*"]


def has_admin_tier(scopes: list[str]) -> list[str]:
    """Return the scopes whose first colon-segment is ``admin``."""
    return [s for s in scopes if s.split(":")[0] == "admin"]


if __name__ == "__main__":
    import base64, json as _json

    def _mk(payload: dict) -> str:
        seg = (
            base64.urlsafe_b64encode(_json.dumps(payload).encode()).decode().rstrip("=")
        )
        return f"hdr.{seg}.sig"

    # jwt_claims: every payload length mod 4 must decode, including the padded cases.
    for payload in (
        {"a": 1},
        {"aud": "x"},
        {"exp": 1, "iat": 0},
        {"scope": "read write"},
    ):
        assert jwt_claims(_mk(payload)) == payload, payload
    assert jwt_claims("notajwt") is None
    assert jwt_claims("a.b") is None
    assert jwt_claims("a.!!!.c") is None
    # a payload that decodes but is not an object must be rejected, not returned
    assert (
        jwt_claims(f"hdr.{base64.urlsafe_b64encode(b'[1,2]').decode().rstrip('=')}.sig")
        is None
    )
    assert (
        jwt_claims(f"hdr.{base64.urlsafe_b64encode(b'42').decode().rstrip('=')}.sig")
        is None
    )
    # The lifetime ladder. 3600s is the benchmark's stated baseline for a short-lived token.
    assert issued_lifetime(86400, None) == 86400
    assert issued_lifetime(None, {"exp": 1000, "iat": 400}) == 600
    assert issued_lifetime(None, {"exp": 1000}) is None
    assert issued_lifetime(None, None) is None
    # A bare-string aud normalises to a list.
    assert audiences({"aud": "https://h/mcp"}) == ["https://h/mcp"]
    assert audiences({"aud": ["a", "b"]}) == ["a", "b"]
    assert audiences(None) == []
    # Wildcard and admin-tier detection. A compliant token trips neither.
    assert has_wildcard(["read", "admin:*"]) == ["admin:*"]
    assert has_wildcard(["*"]) == ["*"]
    assert has_wildcard(["read", "write"]) == []
    # a namespaced scope is NOT a wildcard. A glob reading of "*:*" matches all of these,
    # which would fail 3.8 against every server using namespaced scopes.
    assert has_wildcard(["read:write", "issues:read", "rak_charge:read"]) == []
    assert has_wildcard(["a:b:*"]) == ["a:b:*"]
    assert has_admin_tier(["read", "admin:write"]) == ["admin:write"]
    assert has_admin_tier(["read", "write"]) == []
    # scope precedence: the token response wins over claims.
    assert observed_scopes("a b", {"scope": "c"}) == ["a", "b"]
    # the middle rung: the scope CLAIM. An implementation skipping it passes without this.
    assert observed_scopes(None, {"scope": "c d"}) == ["c", "d"]
    assert observed_scopes(None, {"scp": ["c", "d"]}) == ["c", "d"]
    # scp is space-delimited in some issuers, a list in others
    assert observed_scopes(None, {"scp": "c d"}) == ["c", "d"]
    # A source that stated nothing is None; a source that stated an empty set is [].
    assert observed_scopes(None, None) is None
    assert observed_scopes(None, {}) is None
    assert observed_scopes("", None) == []
    assert observed_scopes(None, {"scope": ""}) == []
    assert observed_scopes(None, {"scp": []}) == []
    assert observed_scopes("a b", None) == ["a", "b"]
    # A claim that is neither a string nor a list states nothing readable, so the
    # next source is tried and an absent one leaves the set unobserved.
    assert observed_scopes(None, {"scope": 12345}) is None
    assert observed_scopes(None, {"scope": 12345, "scp": "c d"}) == ["c", "d"]
    # The token response wins even when empty: a server that states an empty grant
    # has stated the grant, so a claim does not override it.
    assert observed_scopes("", {"scope": "c d"}) == []
    print("tokens: all self-checks passed")
