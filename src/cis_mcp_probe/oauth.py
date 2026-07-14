"""Interactive OAuth 2.1 helpers for the probe.

The MCP ``OAuthClientProvider`` drives the authorization-code + PKCE flow but
delegates two human-facing steps back to us:

* ``redirect_handler(auth_url)`` — get the user in front of the provider's
  consent screen. We open their browser and also print the URL as a fallback.
* ``callback_handler()`` — receive the ``?code=...&state=...`` redirect. We run
  a throwaway HTTP server bound to a loopback port and wait for the browser to
  hit it, then hand the code back to the SDK.

The loopback port is chosen up front so the caller can register a matching
``redirect_uri`` before the flow starts.
"""

from __future__ import annotations

import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import anyio

_SUCCESS_PAGE = b"""<!doctype html><html><head><meta charset="utf-8">
<title>CIS MCP Probe</title></head>
<body style="font-family:system-ui;max-width:32rem;margin:4rem auto;text-align:center">
<h2>Authentication complete</h2>
<p>You can close this tab and return to the terminal.</p>
</body></html>"""

_ERROR_PAGE = b"""<!doctype html><html><head><meta charset="utf-8">
<title>CIS MCP Probe</title></head>
<body style="font-family:system-ui;max-width:32rem;margin:4rem auto;text-align:center">
<h2>Authentication failed</h2>
<p>The authorization server returned an error. Check the terminal for details.</p>
</body></html>"""


class _CallbackHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 (http.server API)
        query = parse_qs(urlparse(self.path).query)
        code = query.get("code", [None])[0]
        error = query.get("error", [None])[0]
        state = query.get("state", [None])[0]

        if code or error:
            self.server.callback_result = {  # type: ignore[attr-defined]
                "code": code,
                "state": state,
                "error": error,
                "error_description": query.get("error_description", [None])[0],
            }
            body = _SUCCESS_PAGE if code else _ERROR_PAGE
            self.send_response(200)
        else:
            # e.g. /favicon.ico — ignore, keep waiting for the real redirect.
            body = b"waiting for authorization redirect..."
            self.send_response(404)

        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:  # silence stderr access log
        pass


class LoopbackCallbackServer:
    """A one-shot loopback HTTP server that captures the OAuth redirect."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        # port=0 lets the OS pick a free port; we then bake it into redirect_uri.
        self._server = HTTPServer((host, port), _CallbackHandler)
        self._server.callback_result = None  # type: ignore[attr-defined]
        self._server.timeout = 1.0
        self.host, self.port = self._server.server_address[0], self._server.server_address[1]

    @property
    def redirect_uri(self) -> str:
        return f"http://{self.host}:{self.port}/callback"

    async def redirect_handler(self, authorization_url: str) -> None:
        print(f"\n  Opening browser for authentication:\n    {authorization_url}\n")
        try:
            webbrowser.open(authorization_url)
        except Exception:  # noqa: BLE001 — headless boxes: URL is printed above
            print("  (could not auto-open a browser — paste the URL above)")

    async def callback_handler(self) -> tuple[str, str | None]:
        """Block (off the event loop) until the redirect arrives; return (code, state)."""
        result = await anyio.to_thread.run_sync(self._wait_for_callback)
        if result.get("error"):
            desc = result.get("error_description") or ""
            raise RuntimeError(f"OAuth error: {result['error']} {desc}".strip())
        return result["code"], result.get("state")

    def _wait_for_callback(self, timeout_s: float = 300.0) -> dict:
        deadline = timeout_s
        while self._server.callback_result is None and deadline > 0:
            self._server.handle_request()  # honors self._server.timeout (1s)
            deadline -= self._server.timeout
        if self._server.callback_result is None:
            raise TimeoutError("Timed out waiting for the OAuth redirect.")
        return self._server.callback_result

    def close(self) -> None:
        self._server.server_close()
