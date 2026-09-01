"""Read lifetime, scope and audience out of an OAuth access token.

Every function returns ``None`` or an empty list for "not observable" rather than
guessing, so a caller can tell an unreadable token from one that really carries
nothing. An opaque token is readable nowhere.

The lifetime reported is the lifetime the token was *issued* with, and no function
here reads a clock. ``exp`` minus the current time would measure the life left, so
a token read from cache an hour on would report an hour less than the server
granted.
"""

from __future__ import annotations

import base64
import json
from typing import Any


def jwt_claims(token: str) -> dict[str, Any] | None:
    """Decode a JWT payload, or return None when the token isn't a JWT."""
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
    """Return the lifetime in seconds the token was issued with, or None."""
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

    Issuers write ``scp`` as either a list or a space-delimited string, so both
    are accepted.

    None and [] are different answers. Reading None as [] claims a grant of zero
    scopes that was never seen, and a later baseline comparison then finds no
    growth on a run that observed nothing. The token response wins even when
    empty, because a server that states an empty grant has stated the grant.
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
