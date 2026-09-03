"""Send a raw JSON-RPC request to an MCP endpoint over HTTP.

The SDK's ``ClientSession`` is great for well-formed traffic, but several checks
need to send deliberately malformed or hand-crafted requests (a bogus protocol
version, a direct tool call, an initialize offering a specific revision). This
helper does that, reusing the session's bearer token and session id, and copes
with servers that answer a POST with a Server-Sent-Events stream instead of a
plain JSON body.

It also holds ``raw_get`` and ``raw_post_form``, the two helpers for reaching a
URL outside the MCP endpoint's own origin. Those check the host guard before
connecting and never follow a redirect; the JSON-RPC helpers above do follow
redirects, because they post to the endpoint the probe was pointed at rather
than to a URL the server chose.
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from .netguard import is_safe_fetch_host, parts_of, verify_context


def _extract_json(resp: httpx.Response) -> dict[str, Any] | None:
    """Return the JSON-RPC object from a response body, JSON or SSE-framed."""
    ctype = resp.headers.get("content-type", "")
    if "text/event-stream" in ctype:
        for line in resp.text.splitlines():
            line = line.strip()
            if line.startswith("data:"):
                fragment = line[len("data:") :].strip()
                try:
                    return json.loads(fragment)
                except json.JSONDecodeError:
                    continue
        return None
    try:
        return resp.json()
    except (json.JSONDecodeError, ValueError):
        return None


async def raw_jsonrpc(
    endpoint: str,
    payload: dict[str, Any],
    *,
    token: str | None = None,
    session_id: str | None = None,
    protocol_header: str | None = None,
    omit_protocol_header: bool = False,
    extra_headers: dict[str, str] | None = None,
    timeout: float = 30.0,
) -> tuple[int, dict[str, Any] | None, str]:
    """POST a JSON-RPC payload and return (status_code, parsed_json, raw_text).

    ``protocol_header`` sets the MCP-Protocol-Version header to a specific value;
    ``omit_protocol_header`` documents the intent to leave it off entirely (the
    default already omits it). Both are used by the version-pinning check.
    """
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if session_id:
        headers["Mcp-Session-Id"] = session_id
    if protocol_header is not None and not omit_protocol_header:
        headers["MCP-Protocol-Version"] = protocol_header
    if extra_headers:
        headers.update(extra_headers)

    async with httpx.AsyncClient(
        follow_redirects=True, timeout=timeout, verify=verify_context()
    ) as client:
        resp = await client.post(endpoint, json=payload, headers=headers)
    return resp.status_code, _extract_json(resp), resp.text


async def raw_jsonrpc_headers(
    endpoint: str,
    payload: dict[str, Any],
    *,
    token: str | None = None,
    session_id: str | None = None,
    protocol_header: str | None = None,
    extra_headers: dict[str, str] | None = None,
    timeout: float = 30.0,
) -> tuple[int, dict[str, Any] | None, str, dict[str, str]]:
    """As ``raw_jsonrpc``, but also return the response headers.

    Check 2.3 has to assert on ``Content-Type``: the benchmark requires the
    authenticated response to be an SSE stream, which is only visible in the
    headers.
    """
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if session_id:
        headers["Mcp-Session-Id"] = session_id
    if protocol_header is not None:
        headers["MCP-Protocol-Version"] = protocol_header
    if extra_headers:
        headers.update(extra_headers)

    async with httpx.AsyncClient(
        follow_redirects=True, timeout=timeout, verify=verify_context()
    ) as client:
        resp = await client.post(endpoint, json=payload, headers=headers)
    return (
        resp.status_code,
        _extract_json(resp),
        resp.text,
        {k.lower(): v for k, v in resp.headers.items()},
    )


async def _guarded_fetch(
    method: str,
    url: str,
    *,
    token: str | None,
    timeout: float,
    data: dict[str, str] | None = None,
    json_body: dict[str, Any] | None = None,
) -> tuple[int | None, dict[str, str], str, str | None]:
    """Fetch ``url`` if its host passes the guard, without following redirects.

    Returns ``(status, lowercased_headers, text, error)``. ``status`` is None
    exactly when ``error`` is set: ``"guard-refused"`` when the host was
    rejected or the URL carried userinfo, and no request was made in either
    case, otherwise the repr of the transport exception.

    Pass ``data`` for a form body or ``json_body`` for a JSON one, never both.

    Redirects are returned as they arrive. Check 3.3.1 presents a live bearer
    token to a host derived from the endpoint's domain, so a followed redirect
    would carry that token to a location the guard never saw.
    """
    if not is_safe_fetch_host(url):
        return None, {}, "", "guard-refused"

    parts = parts_of(url)
    if parts is None or parts.username or parts.password:
        # httpx builds a Basic-auth header from URL userinfo and that header
        # replaces any Authorization header set below, silently dropping the
        # bearer token a check meant to send. The host guard runs first, so an
        # unparseable URL is already refused there rather than raising here.
        return None, {}, "", "guard-refused"

    headers = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        async with httpx.AsyncClient(
            follow_redirects=False, timeout=timeout, verify=verify_context()
        ) as client:
            resp = await client.request(
                method, url, headers=headers, data=data, json=json_body
            )
    except Exception as exc:  # a caller gets an error string, never a raise
        return None, {}, "", repr(exc)

    return (
        resp.status_code,
        {k.lower(): v for k, v in resp.headers.items()},
        resp.text,
        None,
    )


async def raw_get(
    url: str,
    *,
    token: str | None = None,
    timeout: float = 8.0,
) -> tuple[int | None, dict[str, str], str, str | None]:
    """GET a URL through the host guard, returning any redirect unresolved."""
    return await _guarded_fetch("GET", url, token=token, timeout=timeout)


async def raw_post_form(
    url: str,
    data: dict[str, str],
    *,
    token: str | None = None,
    timeout: float = 8.0,
) -> tuple[int | None, dict[str, str], str, str | None]:
    """POST form-encoded ``data`` through the host guard, as ``raw_get`` does.

    For a token request, where RFC 6749 section 4.1.3 requires
    ``application/x-www-form-urlencoded``. A dynamic client registration is not
    one of these: RFC 7591 section 3.1 requires JSON there, so it uses
    ``raw_post_json``.
    """
    return await _guarded_fetch("POST", url, token=token, timeout=timeout, data=data)


async def raw_post_json(
    url: str,
    payload: dict[str, Any],
    *,
    token: str | None = None,
    timeout: float = 8.0,
) -> tuple[int | None, dict[str, str], str, str | None]:
    """POST ``payload`` as JSON through the host guard, as ``raw_get`` does.

    For a dynamic client registration, where RFC 7591 section 3.1 requires the
    request parameters in the entity body as ``application/json``. A conforming
    authorization server answers 400 or 415 to a form body.
    """
    return await _guarded_fetch(
        "POST", url, token=token, timeout=timeout, json_body=payload
    )


def jsonrpc_error_code(data: dict[str, Any] | None) -> int | None:
    """Return the JSON-RPC ``error.code`` if the response carries one."""
    if data and isinstance(data.get("error"), dict):
        code = data["error"].get("code")
        return code if isinstance(code, int) else None
    return None


def is_rejection(status: int, data: dict[str, Any] | None) -> bool:
    """True if the server refused the request (HTTP >=400 or a JSON-RPC error)."""
    if status >= 400:
        return True
    if data and isinstance(data.get("error"), dict):
        return True
    return False


def is_success(status: int, data: dict[str, Any] | None) -> bool:
    """True if the server accepted and answered the request."""
    return status == 200 and bool(data) and data.get("result") is not None
