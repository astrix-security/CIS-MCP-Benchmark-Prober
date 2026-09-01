"""Section 2 checks (transport security), implemented as live probes.

Tracks the Section 2 revision dated 2026-08-12.

Scope reasoning — what a black-box client can and cannot decide:

* 2.1 - operator-side only (``systemctl``/``ss`` unit inventory, then a manual
        determination of the configured transport). A client reaching the server
        by domain is by definition talking to a network transport, so there is
        nothing to decide remotely: reported NOT_APPLICABLE.
* 2.2 - fully decidable. Plaintext behaviour, weak-TLS refusal and certificate
        validity are all observable from outside.
* 2.3 - the wire test is decidable: an unauthenticated request must be refused
        and the authenticated one accepted with an SSE-framed response. That is
        what the benchmark's own audit prints PASS for, so we do too. Per-hop
        forwarding is not decidable from outside -- the benchmark notes a proxy
        can authenticate, strip the credential, and forward an unauthenticated
        request the backend answers anyway -- so it stays a caveat in the
        evidence rather than downgrading the verdict.
* 2.4 - decidable on the wire, but the metadata headers and the -32020
        HeaderMismatch error only exist in 2026-07-28. Against a server that
        won't negotiate that revision the check reports REVISION_UNSUPPORTED.
* 2.5 - fully decidable, and not gated on 2026-07-28.
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
from urllib.parse import urlparse

from ..context import ProbeContext
from ..rawreq import (
    is_rejection,
    jsonrpc_error_code,
    raw_jsonrpc,
    raw_jsonrpc_headers,
)
from .base import Check, CheckResult, Level, register

_AUDIT_META = {
    "io.modelcontextprotocol/clientInfo": {
        "name": "cis-benchmark-audit",
        "version": "1.0",
    },
    "io.modelcontextprotocol/clientCapabilities": {},
}
RC_VERSION = "2026-07-28"

# Error codes the revision allocates. -32020 is the HeaderMismatch signature
# this section tests for; -32022 means the endpoint rejected our probe's
# protocol version, which makes the result unattributable rather than a failure.
HEADER_MISMATCH = -32020
UNSUPPORTED_PROTOCOL_VERSION = -32022

# The benchmark's own hostile Origin. Deliberately a domain that cannot resolve
# to anything an operator would allowlist.
HOSTILE_ORIGIN = "https://cis-rebinding-probe.example"

# Body value the mismatch probes name in the header, never in the body.
MISMATCH_SENTINEL = "cis-mismatch-probe"


def _rc_meta(version: str = RC_VERSION) -> dict:
    return {
        "io.modelcontextprotocol/protocolVersion": version,
        **_AUDIT_META,
    }


def _b64_sentinel(value: str) -> str:
    """Encode a header value in the specification's Base64 sentinel format."""
    encoded = base64.b64encode(value.encode()).decode()
    return f"=?base64?{encoded}?="


@register
class StdioPreferredForLocal(Check):
    id = "2.1"
    title = "stdio is preferred for local, single-user servers"
    section = "2"
    level = Level.L1
    remediation = (
        "Reconfigure eligible servers to use the stdio transport and confirm no "
        "TCP listener is owned by the server process. Record a documented "
        "operational justification for every server that must stay on a network "
        "transport."
    )

    async def run(self, ctx: ProbeContext) -> CheckResult:
        # The audit inventories service units and listeners, then requires a
        # manual determination of the configured transport. Neither half is
        # observable remotely, and a server we reached by domain is a network
        # transport by construction.
        return self._na(
            "operator-side: the unit/listener inventory and the manual transport "
            "determination are not observable from a remote client "
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
        "Terminate TLS in front of the server, redirect or refuse plaintext, "
        "restrict protocols to TLS 1.2 and 1.3, and keep the certificate valid."
    )

    async def run(self, ctx: ProbeContext) -> CheckResult:
        plaintext = ctx.http.get("plaintext")
        tls = ctx.http.get("tls")
        if plaintext is None or tls is None:
            return self._error("transport observations missing; cannot judge TLS posture")

        # The audit's precondition: a refused plaintext port on a dead
        # deployment proves nothing, so the TLS endpoint must answer first.
        if tls.error is not None and ctx.endpoint_url is None:
            return self._error(
                f"the TLS endpoint is unreachable ({tls.error}), so plaintext "
                f"behaviour is not attributable to a served deployment"
            )

        # Nothing here describes the server when something else terminated the TLS
        # connection. The certificate and the negotiated version are the
        # interceptor's, and the plaintext leg is unattributable too, because a
        # proxy that upgrades the scheme hides what the server would have done.
        if tls.tls_intercepted:
            issuer = (tls.tls_cert or {}).get("issuer") or {}
            named = issuer.get("commonName") or issuer.get("organizationName")
            return self._unknown(
                "this connection was terminated by a TLS-inspecting proxy, so the "
                "certificate and the negotiated version belong to it rather than to "
                f"the server (issuer: {named!r}). The chain verified against this "
                "machine's trust store but not against the public CA set. Re-run "
                "from a network without interception to decide this check",
                tls_intercepted=True,
                observed_issuer=issuer,
                negotiated=tls.tls_version,
            )

        failures: list[str] = []
        notes: list[str] = []
        details: dict[str, object] = {}

        # --- plaintext HTTP -------------------------------------------------
        verdict, note = self._plaintext_state(plaintext)
        details["plaintext"] = plaintext.status if plaintext.error is None else "refused"
        details["plaintext_redirect_target"] = (plaintext.headers or {}).get("location")
        if verdict == "fail":
            failures.append(note)
        else:
            notes.append(note)

        # --- weak TLS revisions must be refused -----------------------------
        weak_accepted: list[str] = []
        unattributable: list[str] = []
        for name in ("TLSv1", "TLSv1_1"):
            obs = ctx.http.get(f"tls:{name}")
            if obs is None:
                continue
            if obs.status == 0:  # handshake completed -> server accepted it
                weak_accepted.append(obs.tls_version or name)
            elif obs.error and "SSLV3_ALERT_HANDSHAKE_FAILURE" not in obs.error:
                # Distinguish "server refused" from "we could not offer it".
                if "no protocols available" in obs.error.lower():
                    unattributable.append(name)
        details["weak_tls_accepted"] = weak_accepted
        if unattributable:
            return self._error(
                f"the auditing host cannot offer {', '.join(unattributable)} even "
                f"at security level 0, so a refusal is not attributable to the "
                f"server; run from a host whose OpenSSL can offer TLS 1.0 and 1.1"
            )
        if weak_accepted:
            failures.append(f"weak TLS negotiated: {', '.join(weak_accepted)}")
        else:
            notes.append("TLS 1.0/1.1 refused")

        # --- the negotiated revision must be TLS 1.2+ ------------------------
        details["tls_version"] = tls.tls_version
        if tls.error is not None:
            failures.append(f"TLS handshake/validation failed: {tls.error}")
        elif tls.tls_version in ("TLSv1", "TLSv1.1"):
            failures.append(f"server negotiated {tls.tls_version} (below TLS 1.2)")
        elif tls.tls_version:
            notes.append(f"negotiated {tls.tls_version}")

        # --- certificate must be currently valid ----------------------------
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

    def _plaintext_state(self, obs) -> tuple[str, str]:
        """Classify the plaintext probe. Returns (verdict, note).

        Mirrors the audit's branches, including reading the redirect target: a
        3xx to a non-HTTPS location still serves the next request in cleartext.
        """
        if obs.error is not None:
            return ("pass", "plaintext port refused")
        status = obs.status
        if status == 200:
            return ("fail", "plaintext HTTP served (200)")
        if status == 426:
            return ("pass", "plaintext HTTP requires upgrade to TLS (426)")
        if status in (301, 302, 307, 308):
            target = (obs.headers or {}).get("location", "")
            if target.startswith("https://"):
                return ("pass", f"plaintext HTTP redirects to HTTPS ({status})")
            return (
                "fail",
                f"plaintext HTTP redirects to a non-HTTPS target ({status} to "
                f"{target or 'an empty target'})",
            )
        return ("pass", f"plaintext HTTP returned {status} (review)")

    def _cert_state(self, cert: dict | None) -> tuple[str, bool]:
        """Return (note, expired) from the observed certificate."""
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
        return (f"certificate valid for {(expires - now).days}d", False)


@register
class AuthPropagatesThroughProxies(Check):
    id = "2.3"
    title = "Authentication propagates through proxies on request-scoped SSE responses"
    section = "2"
    level = Level.L2
    remediation = (
        "Configure every proxy hop to forward the Authorization header to the "
        "upstream, unbuffered. Confirm arrival at the final upstream with "
        "backend-side evidence, not the wire status code at the proxy."
    )

    async def run(self, ctx: ProbeContext) -> CheckResult:
        if not ctx.endpoint_url:
            return self._error("no endpoint to test against")
        if not ctx.auth_required:
            # No N/A here: the subsection is not operator-side, and we do have a
            # check for it. A server that requires no authentication accepts an
            # unauthenticated request, which is the condition this check fails
            # on. The benchmark's own audit prints FAIL for the same observation.
            return self._fail(
                "server requires no authentication, so an unauthenticated "
                "request reaches a response: authentication is not enforced "
                "before the response is established",
                auth_required=False,
            )
        if not ctx.access_token:
            return self._unknown(
                "server requires auth but no access token was obtained; cannot "
                "compare the authenticated leg"
            )

        payload = {
            "jsonrpc": "2.0",
            "id": 31,
            "method": "tools/list",
            "params": {"_meta": _rc_meta()} if ctx.rc_supported else {},
        }
        extra = {"Mcp-Method": "tools/list"} if ctx.rc_supported else None

        no_status, no_data, _ = await raw_jsonrpc(
            ctx.endpoint_url, payload, token=None, extra_headers=extra
        )
        ok_status, _ok_data, _ok_text, ok_headers = await raw_jsonrpc_headers(
            ctx.endpoint_url,
            payload,
            token=ctx.access_token,
            session_id=ctx.session_id,
            extra_headers=extra,
        )

        unauth_refused = no_status in (401, 403) or is_rejection(no_status, no_data)
        auth_accepted = 200 <= ok_status < 300
        content_type = ok_headers.get("content-type", "")
        streamed = "text/event-stream" in content_type.lower()

        details = {
            "unauthenticated_status": no_status,
            "authenticated_status": ok_status,
            "authenticated_content_type": content_type or None,
            "response_streamed_sse": streamed,
            "per_hop_verification": "operator-side (backend evidence required)",
        }
        base = (
            f"unauthenticated -> HTTP {no_status} "
            f"({'refused' if unauth_refused else 'ACCEPTED'}); "
            f"authenticated -> HTTP {ok_status} "
            f"({'accepted' if auth_accepted else 'refused'}, "
            f"{content_type or 'no content-type'})"
        )

        # An accepted unauthenticated request is a definite failure: nothing
        # about proxy topology can make that compliant.
        if not unauth_refused:
            return self._fail(
                base + "; authentication is not enforced before the response is "
                "established",
                **details,
            )
        if not auth_accepted:
            return self._unknown(
                base + "; the valid credential was also refused, so the "
                "authenticated leg could not be exercised",
                **details,
            )

        # The response must actually be a stream for the SSE-specific assertion
        # to have been exercised. The benchmark calls this case REVIEW and says
        # to re-run against a tool that streams, which is a run that could
        # decide next time: UNKNOWN, not a failure.
        if not streamed:
            return self._unknown(
                base + "; the server chose a non-streamed response, so the "
                "SSE-specific assertion could not be exercised. Re-run against "
                "a tool or condition that yields a streamed response",
                **details,
            )
        # Wire test satisfied. Per-hop enforcement is not decidable from here,
        # so it stays in the evidence as a caveat rather than downgrading the
        # verdict -- the same convention every other reduced check uses.
        return self._pass(
            base + "; authentication is enforced before the SSE stream is "
            "established. Per-hop forwarding is not verified: confirm the final "
            "upstream with backend-side evidence (an access log recording the "
            "credential or a derived identity)",
            **details,
        )


@register
class RequestMetadataHeaders(Check):
    id = "2.4"
    title = "Required request metadata headers are present and consistent with the body"
    section = "2"
    level = Level.L1
    remediation = (
        "Reject any request missing MCP-Protocol-Version, Mcp-Method, or "
        "Mcp-Name where required, or whose header values disagree with the body "
        "after decoding Base64 sentinel values, with HTTP 400 and -32020."
    )

    async def run(self, ctx: ProbeContext) -> CheckResult:
        if not ctx.endpoint_url:
            return self._error("no endpoint to test against")
        if not ctx.rc_supported:
            negotiated = (
                ctx.rc_negotiated_version or ctx.negotiated_version or "unknown"
            )
            return self._revision_unsupported(
                f"the request metadata headers and -32020 HeaderMismatch exist "
                f"only in {RC_VERSION}. Server negotiated {negotiated}, so the "
                f"mechanism is absent and there is nothing to test.",
                required_revision=RC_VERSION,
                negotiated_revision=negotiated,
            )

        tool = ctx.tools[0].name if ctx.tools else None
        results: list[tuple[str, str, str]] = []  # (label, outcome, note)

        # (a) tools/list with no Mcp-Method. Mcp-Name is not required here.
        results.append(
            await self._probe(
                ctx,
                "missing Mcp-Method (tools/list)",
                {
                    "jsonrpc": "2.0",
                    "id": 41,
                    "method": "tools/list",
                    "params": {"_meta": _rc_meta()},
                },
                extra_headers={},
            )
        )

        # (b) tools/call with Mcp-Method but no Mcp-Name, which is required
        #     on tools/call, resources/read and prompts/get.
        if tool:
            results.append(
                await self._probe(
                    ctx,
                    "missing Mcp-Name (tools/call)",
                    self._call_body(42, tool),
                    extra_headers={"Mcp-Method": "tools/call"},
                )
            )
            # (c) Mcp-Name header contradicts the body. Rejected before the
            #     tool runs, so this has no side effect on the server.
            results.append(
                await self._probe(
                    ctx,
                    "header/body mismatch",
                    self._call_body(43, tool),
                    extra_headers={
                        "Mcp-Method": "tools/call",
                        "Mcp-Name": MISMATCH_SENTINEL,
                    },
                )
            )
            # (d) Base64 sentinel that decodes to a *different* value must also
            #     be rejected. The matching-value half of the audit would
            #     actually invoke the tool, so it is gated behind an opt-in.
            results.append(
                await self._probe(
                    ctx,
                    "encoded mismatching Mcp-Name",
                    self._call_body(44, tool),
                    extra_headers={
                        "Mcp-Method": "tools/call",
                        "Mcp-Name": _b64_sentinel(MISMATCH_SENTINEL),
                    },
                )
            )
        else:
            results.append(
                (
                    "tools/call probes",
                    "unknown",
                    "server exposes no tool to name, so the Mcp-Name and "
                    "mismatch probes could not be built",
                )
            )

        details = {label: outcome for label, outcome, _ in results}
        evidence = "; ".join(f"{label}: {note}" for label, _, note in results)

        if any(o == "fail" for _, o, _ in results):
            return self._fail(evidence, **details)
        if any(o == "error" for _, o, _ in results):
            return self._error(evidence, **details)
        if any(o == "unknown" for _, o, _ in results):
            return self._unknown(evidence, **details)

        decode_note = (
            " The decode-acceptance half (an encoded value that matches the body "
            "must be accepted) is not exercised: it would invoke the tool."
        )
        return self._pass(evidence + "." + decode_note, **details)

    def _call_body(self, req_id: int, tool: str) -> dict:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": "tools/call",
            "params": {"name": tool, "arguments": {}, "_meta": _rc_meta()},
        }

    async def _probe(
        self,
        ctx: ProbeContext,
        label: str,
        payload: dict,
        *,
        extra_headers: dict[str, str],
    ) -> tuple[str, str, str]:
        """Send one probe and classify it the way the audit does.

        A 400 carrying -32020 is the conforming rejection. A 400 without it is
        ERROR rather than PASS: gateways legitimately reject with a plain 400,
        so the result is not attributable to the MCP implementation.
        """
        status, data, _ = await raw_jsonrpc(
            ctx.endpoint_url or "",
            payload,
            token=ctx.access_token,
            session_id=ctx.session_id,
            protocol_header=RC_VERSION,
            extra_headers=extra_headers,
        )
        code = jsonrpc_error_code(data)
        note = f"HTTP {status}, JSON-RPC {code if code is not None else 'none'}"
        if 200 <= status < 300:
            return (label, "fail", note + " (accepted)")
        if status == 400:
            if code == HEADER_MISMATCH:
                return (label, "pass", note + " (HeaderMismatch)")
            if code == UNSUPPORTED_PROTOCOL_VERSION:
                return (
                    label,
                    "error",
                    note + " (endpoint rejected the probe protocol version)",
                )
            return (
                label,
                "error",
                note + " (400 without a HeaderMismatch body is not attributable)",
            )
        return (label, "unknown", note + " (unexpected status)")


@register
class OriginValidated(Check):
    id = "2.5"
    title = "Origin header is validated on all Streamable HTTP requests"
    section = "2"
    level = Level.L1
    remediation = (
        "Validate Origin on every request and return HTTP 403 for any present "
        "Origin not on an explicit allowlist, logging the rejection. Enforce in "
        "the server, not only at a gateway."
    )

    async def run(self, ctx: ProbeContext) -> CheckResult:
        if not ctx.endpoint_url:
            return self._error("no endpoint to test against")

        payload = {
            "jsonrpc": "2.0",
            "id": 51,
            "method": "tools/list",
            "params": {"_meta": _rc_meta()} if ctx.rc_supported else {},
        }

        def headers_for(origin: str | None) -> dict[str, str]:
            h: dict[str, str] = {}
            if ctx.rc_supported:
                h["Mcp-Method"] = "tools/list"
            if origin is not None:
                h["Origin"] = origin
            return h

        # All three legs are identical except for the Origin header. The token
        # is attached deliberately: on an auth-required server an
        # unauthenticated probe returns 401 for every Origin, which would mask
        # whether Origin is validated at all. No preceding OPTIONS is sent, so
        # this tests the request itself rather than a CORS preflight.
        async def leg(origin: str | None) -> tuple[int, dict | None]:
            status, data, _ = await raw_jsonrpc(
                ctx.endpoint_url or "",
                payload,
                token=ctx.access_token,
                session_id=ctx.session_id,
                extra_headers=headers_for(origin),
            )
            return status, data

        evil_status, evil_data = await leg(HOSTILE_ORIGIN)

        parsed = urlparse(ctx.endpoint_url)
        own_origin = f"{parsed.scheme}://{parsed.netloc}"
        good_status, _ = await leg(own_origin)
        none_status, _ = await leg(None)

        details = {
            "hostile_origin": HOSTILE_ORIGIN,
            "hostile_status": evil_status,
            "allowed_origin_probed": own_origin,
            "allowed_origin_status": good_status,
            "no_origin_status": none_status,
        }
        base = (
            f"hostile={evil_status} allowed={good_status} (own origin {own_origin}, "
            f"a stand-in for the operator allowlist, which is not externally "
            f"discoverable) no_origin={none_status} (informational)"
        )

        # A 400 on any leg means the request was rejected before Origin was
        # evaluated, most likely a routing-header mismatch. Not attributable.
        if 400 in (evil_status, good_status, none_status):
            return self._error(
                base + "; a probe was rejected 400 before Origin was evaluated, "
                "so the result is not attributable to Origin validation",
                **details,
            )

        if evil_status == 403:
            if 200 <= good_status < 400:
                return self._pass(
                    base + "; hostile Origin rejected with 403 on the request "
                    "itself and the stand-in allowed Origin accepted",
                    **details,
                )
            return self._unknown(
                base + "; hostile Origin correctly rejected, but the stand-in "
                "allowed Origin was also refused, so the positive leg is "
                "undecided. Re-run with the server's real allowlisted Origin",
                **details,
            )

        if is_rejection(evil_status, evil_data):
            return self._fail(
                base + f"; hostile Origin refused with {evil_status} rather than "
                f"403 — confirm this is Origin validation and not an unrelated "
                f"refusal",
                **details,
            )
        return self._fail(
            base + "; hostile Origin was accepted (no DNS-rebinding protection "
            "on the request itself)",
            **details,
        )
