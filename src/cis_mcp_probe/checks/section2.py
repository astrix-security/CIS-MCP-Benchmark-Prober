"""Section 2 checks (transport security), implemented as live probes.

Scope reasoning — what a black-box client can and cannot decide:

* 2.1 - operator-side only (``systemctl``/``ss`` inventory plus a documented
        justification in the enterprise registry). A client reaching the server
        by domain is by definition talking to a network transport, so there is
        nothing to decide remotely: reported NOT_APPLICABLE.
* 2.2 - fully decidable. Plaintext HTTP, weak-TLS refusal and certificate
        validity are all observable from outside.
* 2.3 - the authentication half is decidable (unauthenticated request must be
        refused, authenticated must be accepted). Confirming that *each* proxy
        hop forwarded the credential needs per-proxy access logs, which is
        operator-side; the evidence says so explicitly.
* 2.4 - decidable on the wire, but the routing headers and the -32020
        HeaderMismatch error only exist in 2026-07-28. Against a server that
        won't negotiate that revision the checks report UNKNOWN.
* 2.5 - fully decidable, and not gated on 2026-07-28.

Profile levels are not stated in the Section 2 source text; the values here are
provisional (2.1 as L2, the rest L1) and should be reconciled with the benchmark.
"""

from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import urlparse

from ..context import ProbeContext
from ..rawreq import is_rejection, raw_jsonrpc
from .base import Check, CheckResult, Level, register

_AUDIT_META = {
    "io.modelcontextprotocol/clientInfo": {
        "name": "cis-benchmark-audit",
        "version": "1.0",
    },
    "io.modelcontextprotocol/clientCapabilities": {},
}
RC_VERSION = "2026-07-28"

# Origin we assert must be refused. Deliberately unrelated to any real deployment.
HOSTILE_ORIGIN = "http://evil.example.com"


def _rc_meta(version: str = RC_VERSION) -> dict:
    return {
        "io.modelcontextprotocol/protocolVersion": version,
        **_AUDIT_META,
    }


def _looks_sse(text: str) -> bool:
    """True if the body is Server-Sent-Events framed rather than a plain object."""
    return any(line.startswith("data:") for line in text.splitlines())


@register
class StdioPreferredForLocal(Check):
    id = "2.1"
    title = "stdio is preferred for local, single-user servers"
    section = "2"
    level = Level.L2
    remediation = (
        "Inventory each server's transport and record a documented operational "
        "justification for every server exposed over Streamable HTTP where stdio "
        "would suffice."
    )

    async def run(self, ctx: ProbeContext) -> CheckResult:
        # The audit is a host-side unit/socket inventory plus a registry lookup.
        # Nothing about it is observable from a remote client, and a server we
        # reached by domain is a network transport by construction.
        return self._na(
            "operator-side: transport inventory and the documented justification "
            "in the enterprise registry are not observable from a remote client "
            f"(reached {ctx.domain} over {ctx.transport or 'unknown transport'})",
            transport=ctx.transport,
        )


@register
class TlsRequiredNoPlaintext(Check):
    id = "2.2"
    title = "TLS is required for HTTP and plaintext is disallowed"
    section = "2"
    level = Level.L1
    remediation = (
        "Redirect or refuse plaintext HTTP, disable TLS 1.0/1.1 so only TLS 1.2+ "
        "is negotiable, and keep the server certificate valid."
    )

    async def run(self, ctx: ProbeContext) -> CheckResult:
        plaintext = ctx.http.get("plaintext")
        tls = ctx.http.get("tls")
        if plaintext is None or tls is None:
            return self._error("transport observations missing; cannot judge TLS posture")

        failures: list[str] = []
        notes: list[str] = []
        details: dict[str, object] = {}

        # --- plaintext HTTP must not be served -----------------------------
        if plaintext.error is not None:
            notes.append("plaintext port refused")
            details["plaintext"] = "refused"
        elif plaintext.status == 200:
            failures.append("plaintext HTTP served (200)")
            details["plaintext"] = 200
        elif plaintext.status in (301, 302, 307, 308):
            notes.append(f"HTTP redirects to HTTPS ({plaintext.status})")
            details["plaintext"] = plaintext.status
        else:
            notes.append(f"plaintext HTTP returned {plaintext.status} (review)")
            details["plaintext"] = plaintext.status

        # --- weak TLS revisions must be refused ----------------------------
        weak_accepted: list[str] = []
        for name in ("TLSv1", "TLSv1_1"):
            obs = ctx.http.get(f"tls:{name}")
            if obs is None:
                continue
            if obs.status == 0:  # handshake completed -> server accepted it
                weak_accepted.append(obs.tls_version or name)
        details["weak_tls_accepted"] = weak_accepted
        if weak_accepted:
            failures.append(f"weak TLS negotiated: {', '.join(weak_accepted)}")
        else:
            notes.append("TLS 1.0/1.1 refused")

        # --- the negotiated revision must be TLS 1.2+ ----------------------
        details["tls_version"] = tls.tls_version
        if tls.error is not None:
            failures.append(f"TLS handshake/validation failed: {tls.error}")
        elif tls.tls_version and tls.tls_version in ("TLSv1", "TLSv1.1"):
            failures.append(f"server negotiated {tls.tls_version} (below TLS 1.2)")
        elif tls.tls_version:
            notes.append(f"negotiated {tls.tls_version}")

        # --- certificate must be currently valid ---------------------------
        expiry_note, expired = self._cert_state(tls.tls_cert)
        details["cert_not_after"] = (tls.tls_cert or {}).get("notAfter")
        if expired:
            failures.append(expiry_note)
        elif expiry_note:
            notes.append(expiry_note)

        evidence = "; ".join(failures + notes)
        if failures:
            return self._fail(evidence, **details)
        return self._pass(evidence, **details)

    def _cert_state(self, cert: dict | None) -> tuple[str, bool]:
        """Return (note, expired). A successful default-context handshake already
        implies the chain validated, so this only adds explicit expiry detail."""
        if not cert:
            return ("", False)
        not_after = cert.get("notAfter")
        if not not_after:
            return ("", False)
        try:
            expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc
            )
        except ValueError:
            return (f"certificate notAfter unparsed ({not_after})", False)
        now = datetime.now(timezone.utc)
        if expires <= now:
            return (f"certificate expired ({not_after})", True)
        days = (expires - now).days
        return (f"certificate valid for {days}d", False)


@register
class AuthPropagatesThroughProxies(Check):
    id = "2.3"
    title = "Authentication is enforced and propagates through proxies on Streamable HTTP"
    section = "2"
    level = Level.L1
    remediation = (
        "Require authentication before establishing a request-scoped response "
        "stream, and ensure every proxy hop forwards the Authorization header to "
        "the upstream MCP server."
    )

    async def run(self, ctx: ProbeContext) -> CheckResult:
        if not ctx.endpoint_url:
            return self._error("no endpoint to test against")
        if not ctx.auth_required:
            return self._na(
                "server does not require authentication; there is no credential "
                "to enforce or propagate"
            )
        if not ctx.access_token:
            return self._unknown(
                "server requires auth but no access token was obtained; cannot "
                "compare the authenticated leg"
            )

        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {"_meta": _rc_meta()} if ctx.rc_supported else {},
        }
        extra = (
            {"Mcp-Method": "tools/list"} if ctx.rc_supported else None
        )

        # Unauthenticated: must be refused before any response stream starts.
        no_status, no_data, _no_text = await raw_jsonrpc(
            ctx.endpoint_url, payload, token=None, extra_headers=extra
        )
        # Authenticated: same request, credential attached. tools/list is used
        # deliberately — it exercises the same request path without the side
        # effects of invoking an arbitrary tool on a live production server.
        ok_status, ok_data, ok_text = await raw_jsonrpc(
            ctx.endpoint_url,
            payload,
            token=ctx.access_token,
            session_id=ctx.session_id,
            extra_headers=extra,
        )

        unauth_refused = no_status in (401, 403) or is_rejection(no_status, no_data)
        auth_accepted = 200 <= ok_status < 300
        streamed = _looks_sse(ok_text)

        details = {
            "unauthenticated_status": no_status,
            "authenticated_status": ok_status,
            "unauthenticated_refused": unauth_refused,
            "authenticated_accepted": auth_accepted,
            "response_streamed_sse": streamed,
            "per_hop_verification": "operator-side",
        }
        framing = "SSE-framed" if streamed else "plain JSON"
        evidence = (
            f"unauthenticated -> HTTP {no_status} "
            f"({'refused' if unauth_refused else 'ACCEPTED'}); "
            f"authenticated -> HTTP {ok_status} "
            f"({'accepted' if auth_accepted else 'refused'}, {framing}); "
            "per-proxy-hop forwarding needs proxy access logs (operator-side)"
        )

        if unauth_refused and auth_accepted:
            return self._pass(evidence, **details)
        if not unauth_refused:
            return self._fail(evidence, **details)
        return self._unknown(evidence, **details)


@register
class RoutingHeadersRequired(Check):
    id = "2.4"
    title = "Required routing headers are present and header/body mismatch is rejected"
    section = "2"
    level = Level.L1
    remediation = (
        "Require the Mcp-Method and Mcp-Name routing headers on every Streamable "
        "HTTP request and reject any request whose headers contradict the "
        "JSON-RPC body with HTTP 400 / JSON-RPC -32020 HeaderMismatch."
    )

    HEADER_MISMATCH_CODE = -32020

    async def run(self, ctx: ProbeContext) -> CheckResult:
        if not ctx.endpoint_url:
            return self._error("no endpoint to test against")
        if not ctx.rc_supported:
            return self._unknown(
                f"routing headers and -32020 HeaderMismatch are {RC_VERSION} "
                f"features; server negotiates "
                f"{ctx.rc_negotiated_version or ctx.negotiated_version or 'unknown'}"
            )

        # (a) A request missing the required Mcp-Method routing header.
        missing_status, missing_data, _ = await raw_jsonrpc(
            ctx.endpoint_url,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list",
                "params": {"_meta": _rc_meta()},
            },
            token=ctx.access_token,
            session_id=ctx.session_id,
            protocol_header=RC_VERSION,
        )

        # (b) Routing header names one tool, the body names another.
        mismatch_status, mismatch_data, _ = await raw_jsonrpc(
            ctx.endpoint_url,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "body_tool",
                    "arguments": {},
                    "_meta": _rc_meta(),
                },
            },
            token=ctx.access_token,
            session_id=ctx.session_id,
            protocol_header=RC_VERSION,
            extra_headers={"Mcp-Method": "tools/call", "Mcp-Name": "header_tool"},
        )

        missing_rejected = missing_status == 400
        mismatch_code = None
        if mismatch_data and isinstance(mismatch_data.get("error"), dict):
            mismatch_code = mismatch_data["error"].get("code")
        mismatch_rejected = (
            mismatch_status == 400 and mismatch_code == self.HEADER_MISMATCH_CODE
        )

        details = {
            "missing_header_status": missing_status,
            "missing_header_rejected": missing_rejected,
            "mismatch_status": mismatch_status,
            "mismatch_error_code": mismatch_code,
            "mismatch_rejected": mismatch_rejected,
        }
        evidence = (
            f"missing Mcp-Method -> HTTP {missing_status} "
            f"({'rejected' if missing_rejected else 'not rejected with 400'}); "
            f"header/body mismatch -> HTTP {mismatch_status}, "
            f"JSON-RPC code {mismatch_code} "
            f"({'HeaderMismatch' if mismatch_rejected else 'not -32020'})"
        )
        if missing_rejected and mismatch_rejected:
            return self._pass(evidence, **details)
        return self._fail(evidence, **details)


@register
class OriginValidated(Check):
    id = "2.5"
    title = "Origin header is validated on all Streamable HTTP requests"
    section = "2"
    level = Level.L1
    remediation = (
        "Validate the Origin header on every request against an operator-"
        "configured allowlist and return HTTP 403 for any Origin not on it; "
        "enforce on the request itself, not only on CORS preflight."
    )

    async def run(self, ctx: ProbeContext) -> CheckResult:
        if not ctx.endpoint_url:
            return self._error("no endpoint to test against")

        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {"_meta": _rc_meta()} if ctx.rc_supported else {},
        }

        def headers_for(origin: str) -> dict[str, str]:
            h = {"Origin": origin}
            if ctx.rc_supported:
                h["Mcp-Method"] = "tools/list"
            return h

        # The token is attached deliberately: on an auth-required server an
        # unauthenticated probe returns 401 for every Origin, which would mask
        # whether Origin is validated at all. No preceding OPTIONS is sent, so
        # this tests enforcement on the request itself rather than a preflight.
        evil_status, evil_data, _ = await raw_jsonrpc(
            ctx.endpoint_url,
            payload,
            token=ctx.access_token,
            session_id=ctx.session_id,
            extra_headers=headers_for(HOSTILE_ORIGIN),
        )

        # The real allowlist is operator-configured and not externally
        # discoverable; the server's own origin is the best available stand-in.
        parsed = urlparse(ctx.endpoint_url)
        own_origin = f"{parsed.scheme}://{parsed.netloc}"
        good_status, _good_data, _ = await raw_jsonrpc(
            ctx.endpoint_url,
            payload,
            token=ctx.access_token,
            session_id=ctx.session_id,
            extra_headers=headers_for(own_origin),
        )

        hostile_forbidden = evil_status == 403
        hostile_refused = is_rejection(evil_status, evil_data)
        good_accepted = 200 <= good_status < 400

        details = {
            "hostile_origin": HOSTILE_ORIGIN,
            "hostile_status": evil_status,
            "allowed_origin_probed": own_origin,
            "allowed_origin_status": good_status,
            "hostile_forbidden": hostile_forbidden,
        }
        evidence = (
            f"hostile Origin {HOSTILE_ORIGIN} -> HTTP {evil_status}; "
            f"own-origin {own_origin} -> HTTP {good_status} "
            f"(stand-in for the operator allowlist, which is not externally "
            f"discoverable)"
        )

        if hostile_forbidden and good_accepted:
            return self._pass(evidence, **details)
        if hostile_forbidden:
            return self._unknown(
                evidence + "; hostile Origin correctly forbidden but the "
                "stand-in allowed Origin was also refused, so the positive leg "
                "is undecided",
                **details,
            )
        if hostile_refused:
            return self._fail(
                evidence + f"; refused with {evil_status} rather than 403 — "
                f"confirm this is Origin validation and not an unrelated refusal",
                **details,
            )
        return self._fail(
            evidence + "; hostile Origin was accepted (no DNS-rebinding "
            "protection on the request itself)",
            **details,
        )
