"""Send a raw JSON-RPC request to an MCP endpoint over HTTP.

The SDK's ``ClientSession`` is great for well-formed traffic, but several checks
need to send deliberately malformed or hand-crafted requests (a bogus protocol
version, a direct tool call, an initialize offering a specific revision). This
helper does that, reusing the session's bearer token and session id, and copes
with servers that answer a POST with a Server-Sent-Events stream instead of a
plain JSON body.
"""

from __future__ import annotations

import json
from typing import Any

import httpx


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

    async with httpx.AsyncClient(follow_redirects=True, timeout=timeout) as client:
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

    async with httpx.AsyncClient(follow_redirects=True, timeout=timeout) as client:
        resp = await client.post(endpoint, json=payload, headers=headers)
    return (
        resp.status_code,
        _extract_json(resp),
        resp.text,
        {k.lower(): v for k, v in resp.headers.items()},
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
