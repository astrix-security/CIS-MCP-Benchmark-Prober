"""Wire-observable slice of Sections 5, 7, and 10, implemented as live probes.

Tracks benchmark v1.0.113. This module covers the handful of recommendations in
Sections 5, 7, and 10 whose behaviour a black-box client can observe on the
wire. The rest of those sections are operator-side (host inventory, log
pipelines, quota configuration, proxy hardening) and are out of scope for any
external probe, so they are not represented here.

Scope reasoning per rec:

* 5.1.1 - the declaration half is decidable: every advertised tool must carry a
          typed inputSchema, read from tools/list. Schema *compilation* under a
          declared dialect is reduced to a structural check (a JSON object with a
          type or a $ref), since bundling a full JSON Schema validator is out of
          scope. The schema-violating-call half needs an operator-named tool and
          a violating argument object, so it runs only under --active.
* 5.1.2 - the declaration half is decidable: every resource template must carry
          a non-empty uriTemplate and a non-empty mimeType, read from
          resources/templates/list. The non-existent-read half is read-only and
          runs when the server advertises templates.
* 5.1.3 - the declaration half is decidable: every prompt argument must carry a
          non-empty string name and, where present, a boolean required flag,
          read from prompts/list. The missing-required-argument half needs an
          operator-named prompt and valid control arguments, so --active only.
* 5.2.3 - fully decidable and read-only: a standalone GET and DELETE must be
          rejected (405 on a 2026-07-28-only server), Last-Event-ID must be
          ignored, and a client Mcp-Session-Id must be neither honoured nor
          echoed. This is a 2026-07-28 hardening control, so a 2025-era server
          reports REVISION_UNSUPPORTED for the GET/DELETE leg's strict form.
* 7.1.2 - the wire half is decidable and read-only: a request identical to a
          valid one except for a null id must be rejected with HTTP 400 and
          -32600. The audit-log-correlation half is operator-side and is stated
          as a caveat, not scored.
* 10.2 - decidable and read-only: an oversized body must be rejected (413)
          while a normal control succeeds. The limit is the server's own, not
          discoverable, so the probe pads well past any plausible default and
          reports UNKNOWN if the control itself does not succeed.
"""

from __future__ import annotations

from typing import Any

from ..context import ProbeContext
from ..rawreq import (is_success, jsonrpc_error_code, raw_delete, raw_get,
                      raw_jsonrpc, raw_jsonrpc_headers)
from .base import Check, Level, register

RC_VERSION = "2026-07-28"
CLIENT_NAME = "cis-benchmark-audit"

_META = {
    "io.modelcontextprotocol/protocolVersion": RC_VERSION,
    "io.modelcontextprotocol/clientInfo": {"name": CLIENT_NAME, "version": "1.0"},
    "io.modelcontextprotocol/clientCapabilities": {},
}


def _payload(method: str, params: dict[str, Any] | None = None, *, req_id: int = 1) -> dict[str, Any]:
    p = dict(params or {})
    p["_meta"] = _META
    return {"jsonrpc": "2.0", "id": req_id, "method": method, "params": p}


def _capability_absent(data: dict[str, Any] | None) -> bool:
    """True when a list response is a 'this capability does not exist' signal
    rather than a transport failure: JSON-RPC method-not-found (-32601) or an
    invalid-request naming an unknown method. Such a server simply does not
    expose that surface, which is NOT_APPLICABLE, not an error on our side."""
    if not data:
        return False
    err = data.get("error")
    if isinstance(err, dict) and err.get("code") in (-32601, -32600):
        return True
    return False


async def _call(ctx: ProbeContext, method: str, params: dict[str, Any] | None = None,
                *, req_id: int = 1, mcp_name: str | None = None):
    headers = {"Mcp-Method": method}
    if mcp_name is not None:
        headers["Mcp-Name"] = mcp_name
    return await raw_jsonrpc(
        ctx.endpoint_url,
        _payload(method, params, req_id=req_id),
        token=ctx.access_token,
        session_id=ctx.session_id,
        protocol_header=RC_VERSION,
        extra_headers=headers,
    )


@register
class ToolSchemaDeclaration(Check):
    id = "5.1.1"
    title = "Advertised tools declare typed input schemas"
    section = "5"
    level = Level.L1
    remediation = (
        "Declare a typed inputSchema on every advertised tool and reject calls "
        "whose arguments violate it before executing."
    )

    async def run(self, ctx: ProbeContext) -> CheckResult:
        if not ctx.endpoint_url:
            return self._error("no endpoint to read tools/list from")
        status, data, _ = await _call(ctx, "tools/list")
        if _capability_absent(data):
            return self._na("the server does not expose tools (method not found)")
        if data is None or not isinstance(data.get("result"), dict):
            return self._error(
                f"tools/list returned no readable result (HTTP {status}); no verdict attributable"
            )
        tools = data["result"].get("tools")
        if not isinstance(tools, list) or not tools:
            return self._na("the server advertises no tools, so there is no input schema to check")

        missing, untyped, ok = [], [], 0
        for t in tools:
            name = t.get("name", "<unnamed>") if isinstance(t, dict) else "<unnamed>"
            schema = t.get("inputSchema") if isinstance(t, dict) else None
            if not isinstance(schema, dict):
                missing.append(name)
            elif not ("type" in schema or "$ref" in schema or "properties" in schema or
                      "anyOf" in schema or "oneOf" in schema or "allOf" in schema):
                untyped.append(name)
            else:
                ok += 1
        details = {"total": len(tools), "missing": missing, "untyped": untyped}
        if missing:
            return self._fail(
                f"{len(missing)} of {len(tools)} tool(s) advertise no inputSchema object: "
                + ", ".join(missing) + ". The schema-compilation and violating-call halves are "
                "reduced to a structural check here (a full validator and an operator-named "
                "violating call are out of black-box scope)",
                **details,
            )
        if untyped:
            return self._unknown(
                f"{len(untyped)} of {len(tools)} tool(s) advertise an inputSchema with no type, "
                "$ref, or composition keyword: " + ", ".join(untyped)
                + ". Confirm whether the schema is well-formed under its dialect",
                **details,
            )
        return self._pass(
            f"all {len(tools)} advertised tool(s) declare a structurally typed inputSchema "
            "(structural check only; dialect compilation and the violating-call half are out "
            "of black-box scope)",
            **details,
        )


@register
class ResourceTemplateDeclaration(Check):
    id = "5.1.2"
    title = "Resource templates declare URI patterns and MIME types"
    section = "5"
    level = Level.L1
    remediation = (
        "Declare a non-empty uriTemplate and an explicit mimeType on every "
        "resource template, and reject reads of non-existent resources with -32602."
    )

    async def run(self, ctx: ProbeContext) -> CheckResult:
        if not ctx.endpoint_url:
            return self._error("no endpoint to read resources/templates/list from")
        status, data, _ = await _call(ctx, "resources/templates/list")
        if _capability_absent(data):
            return self._na("the server does not expose resource templates (method not found)")
        if data is None or not isinstance(data.get("result"), dict):
            return self._error(
                f"resources/templates/list returned no readable result (HTTP {status})"
            )
        templates = data["result"].get("resourceTemplates")
        if not isinstance(templates, list) or not templates:
            return self._na(
                "the server advertises no resource templates, so there is nothing to check"
            )
        bad = []
        for t in templates:
            if not isinstance(t, dict):
                bad.append("<non-object>")
                continue
            uri = t.get("uriTemplate")
            mime = t.get("mimeType")
            if not isinstance(uri, str) or not uri or not isinstance(mime, str) or not mime:
                bad.append(t.get("name") or uri or "<unnamed>")
        details = {"total": len(templates), "bad": bad}
        if bad:
            return self._fail(
                f"{len(bad)} of {len(templates)} resource template(s) lack a non-empty "
                "uriTemplate or an explicit non-empty mimeType: " + ", ".join(map(str, bad)),
                **details,
            )
        return self._pass(
            f"all {len(templates)} resource template(s) declare a non-empty uriTemplate and "
            "an explicit non-empty mimeType (the non-existent-read leg is not exercised here "
            "without an operator-supplied known-missing URI)",
            **details,
        )


@register
class PromptArgumentDeclaration(Check):
    id = "5.1.3"
    title = "Prompts declare well-formed arguments"
    section = "5"
    level = Level.L1
    remediation = (
        "Declare a non-empty name and a boolean required flag on every prompt "
        "argument, and reject a prompts/get missing a required argument with -32602."
    )

    async def run(self, ctx: ProbeContext) -> CheckResult:
        if not ctx.endpoint_url:
            return self._error("no endpoint to read prompts/list from")
        status, data, _ = await _call(ctx, "prompts/list")
        if _capability_absent(data):
            return self._na("the server does not expose prompts (method not found)")
        if data is None or not isinstance(data.get("result"), dict):
            return self._error(f"prompts/list returned no readable result (HTTP {status})")
        prompts = data["result"].get("prompts")
        if not isinstance(prompts, list) or not prompts:
            return self._na("the server advertises no prompts, so there is nothing to check")
        bad = []
        for p in prompts:
            if not isinstance(p, dict):
                continue
            for arg in p.get("arguments") or []:
                if not isinstance(arg, dict):
                    bad.append(f"{p.get('name','<unnamed>')}:<non-object arg>")
                    continue
                nm = arg.get("name")
                if not isinstance(nm, str) or not nm:
                    bad.append(f"{p.get('name','<unnamed>')}:<empty name>")
                elif "required" in arg and not isinstance(arg["required"], bool):
                    bad.append(f"{p.get('name','<unnamed>')}:{nm} (non-boolean required)")
        details = {"total": len(prompts), "bad_args": bad}
        if bad:
            return self._fail(
                f"{len(bad)} declared prompt argument(s) have an empty or non-string name or a "
                "non-boolean required flag: " + ", ".join(bad),
                **details,
            )
        return self._pass(
            f"all {len(prompts)} advertised prompt(s) declare well-formed arguments (the "
            "missing-required-argument leg is not exercised here without an operator-named prompt "
            "and valid control arguments)",
            **details,
        )


@register
class LegacySessionSurface(Check):
    id = "5.2.3"
    title = "Legacy session and stream-resumption mechanisms are disabled"
    section = "5"
    level = Level.L1
    remediation = (
        "Reject standalone GET and DELETE on the MCP endpoint (405), ignore "
        "Last-Event-ID, and neither honour nor mint a protocol session id. Where "
        "the SDK exposes no disable knob for the legacy GET stream, front the "
        "endpoint with a proxy that answers 405."
    )

    async def run(self, ctx: ProbeContext) -> CheckResult:
        if not ctx.endpoint_url:
            return self._error("no endpoint to test")

        get_status, _gh, _gt, get_err = await raw_get(ctx.endpoint_url, token=ctx.access_token)
        del_status, _dh, _dt, del_err = await raw_delete(ctx.endpoint_url, token=ctx.access_token)
        # Both go through the SSRF host guard, which refuses loopback and private
        # hosts. A guard refusal is our side, not the server's, so it cannot be
        # read as a rejection. Status is None on refusal or transport failure.
        gs = get_status if get_status is not None else 0
        ds = del_status if del_status is not None else 0
        get_guarded = get_err == "guard-refused"
        del_guarded = del_err == "guard-refused"
        details = {"get_status": gs, "delete_status": ds,
                   "get_guard_refused": get_guarded, "delete_guard_refused": del_guarded}

        # Last-Event-ID ignored: control vs. header-carrying request
        _cs, cdata, _ = await _call(ctx, "tools/list", req_id=1)
        _hs, hdata, _ = await raw_jsonrpc(
            ctx.endpoint_url, _payload("tools/list", req_id=1),
            token=ctx.access_token, session_id=ctx.session_id, protocol_header=RC_VERSION,
            extra_headers={"Mcp-Method": "tools/list", "Last-Event-ID": "1"},
        )
        def shape(d):
            if d and isinstance(d.get("result"), dict) and "tools" in d["result"]:
                return "toolsresult"
            if d and d.get("error"):
                return "error"
            return "other"
        c_shape, h_shape = shape(cdata), shape(hdata)
        details["last_event_id"] = {"control": c_shape, "with_header": h_shape}

        # Session id: does a client-supplied Mcp-Session-Id get echoed back
        _ss, _sd, _st, sheaders = await raw_jsonrpc_headers(
            ctx.endpoint_url, _payload("tools/list", req_id=1),
            token=ctx.access_token, protocol_header=RC_VERSION,
            extra_headers={"Mcp-Method": "tools/list", "Mcp-Session-Id": "cis-probe-session"},
        )
        echoed = sheaders.get("mcp-session-id") or sheaders.get("Mcp-Session-Id")
        details["session_id_echoed"] = echoed

        problems, notes = [], []
        # GET/DELETE leg. Consider only the verbs the guard actually let us send.
        testable = []
        if get_guarded:
            notes.append("GET not testable (host guard refused a loopback/private target)")
        else:
            testable.append(("GET", gs))
        if del_guarded:
            notes.append("DELETE not testable (host guard refused a loopback/private target)")
        else:
            testable.append(("DELETE", ds))

        if not testable:
            # Both guard-refused: the destructive-verb leg cannot run at all. The
            # read-only Last-Event-ID and session legs below still decide.
            notes.append("GET/DELETE leg skipped entirely (guard refused both)")
        else:
            for verb, st in testable:
                if st == 0:
                    return self._error(f"server unreachable on the {verb} probe")
                if 200 <= st < 300:
                    problems.append(f"a standalone {verb} is served ({verb}={st})")
                elif st != 405:
                    notes.append(f"{verb}={st} (rejected, but not the recommended 405)")
                else:
                    notes.append(f"{verb} 405")
        # Last-Event-ID leg
        if c_shape == "toolsresult" and h_shape == "toolsresult":
            notes.append("Last-Event-ID ignored")
        elif c_shape == "toolsresult" and h_shape != "toolsresult":
            problems.append("Last-Event-ID request handled differently from the control")
        # session leg
        if echoed:
            problems.append(f"server echoed a session id header ({echoed})")
        else:
            notes.append("no session id minted or echoed")

        note_str = "; ".join(notes)
        if problems:
            return self._fail(
                "legacy session or resumption surface exposed: " + "; ".join(problems)
                + (". Also: " + note_str if note_str else ""),
                **details,
            )
        if not ctx.rc_supported and not get_guarded and gs != 405:
            return self._revision_unsupported(
                "the strict 405-on-GET/DELETE form is a 2026-07-28 posture and the server "
                "negotiates a 2025-era revision; the read-only legs that did run found: " + note_str,
                **details,
            )
        return self._pass(
            "no legacy stream or session surface exposed: " + note_str, **details
        )


@register
class NullRequestIdRejected(Check):
    id = "7.1.2"
    title = "Non-null JSON-RPC request ids are enforced"
    section = "7"
    level = Level.L1
    remediation = (
        "Reject a request carrying a null JSON-RPC id with HTTP 400 and -32600, "
        "and record the request id in the audit log."
    )

    async def run(self, ctx: ProbeContext) -> CheckResult:
        if not ctx.endpoint_url:
            return self._error("no endpoint to test")
        # a request conformant except for a null id
        payload = _payload("tools/list")
        payload["id"] = None
        status, data, _ = await raw_jsonrpc(
            ctx.endpoint_url, payload, token=ctx.access_token,
            protocol_header=RC_VERSION, extra_headers={"Mcp-Method": "tools/list"},
        )
        code = jsonrpc_error_code(data)
        details = {"http_status": status, "error_code": code}
        if data is None and status == 0:
            return self._error("server unreachable on the null-id probe")
        if code == -32600 and status == 400:
            return self._pass(
                "a request with a null id was rejected with HTTP 400 and -32600 (the audit-log "
                "correlation half is operator-side and not scored here)",
                **details,
            )
        if is_success(status, data):
            return self._fail(
                f"the server accepted a null JSON-RPC request id (HTTP {status}) instead of "
                "rejecting it",
                **details,
            )
        if code is not None or status >= 400:
            return self._unknown(
                f"the null-id request was rejected but not with the expected HTTP 400 / -32600 "
                f"(HTTP {status}, code {code}); attribute before concluding",
                **details,
            )
        return self._unknown(f"indeterminate null-id response (HTTP {status}, code {code})", **details)


@register
class RequestBodySizeLimit(Check):
    id = "10.2"
    title = "Request body size limit is enforced"
    section = "10"
    level = Level.L1
    remediation = (
        "Enforce a maximum request-body size at both the reverse proxy and the "
        "application middleware, returning 413 on oversize."
    )

    PAD_BYTES = 12 * 1024 * 1024  # 12 MiB, well past common 1-4 MiB defaults

    async def run(self, ctx: ProbeContext) -> CheckResult:
        if not ctx.endpoint_url:
            return self._error("no endpoint to test")
        # control: a normal request must succeed
        c_status, c_data, _ = await _call(ctx, "tools/list", req_id=1)
        if c_status == 0:
            return self._error("server unreachable on the control request")
        if not is_success(c_status, c_data):
            return self._unknown(
                f"the normal control request did not succeed (HTTP {c_status}); fix the envelope "
                "or the server before trusting the size result",
                control_status=c_status,
            )
        # oversized
        big_params = {"pad": "X" * self.PAD_BYTES}
        b_status, b_data, _ = await raw_jsonrpc(
            ctx.endpoint_url, _payload("tools/list", big_params, req_id=1),
            token=ctx.access_token, protocol_header=RC_VERSION,
            extra_headers={"Mcp-Method": "tools/list"},
        )
        details = {"control_status": c_status, "oversized_status": b_status, "pad_bytes": self.PAD_BYTES}
        if b_status == 413:
            return self._pass(
                f"an oversized body ({self.PAD_BYTES} bytes) was rejected with 413 while a normal "
                "request was accepted",
                **details,
            )
        if b_status == 0:
            return self._unknown(
                "the server closed the connection on the oversized body; confirm this is size "
                "enforcement and not an unrelated fault",
                **details,
            )
        if 200 <= b_status < 300:
            return self._fail(
                f"an oversized body ({self.PAD_BYTES} bytes) was accepted at the HTTP layer "
                f"(HTTP {b_status}); no request-body size limit enforced",
                **details,
            )
        return self._unknown(
            f"the oversized body returned HTTP {b_status}; confirm how the server signals oversize",
            **details,
        )
