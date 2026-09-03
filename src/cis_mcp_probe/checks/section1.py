"""Section 1 checks, implemented as live probes.

Tracks the Section 1 text of benchmark v1.0.113.

Each check reflects the agreed scope from reviewing the benchmark text:

* 1.1 - tested on the wire with the benchmark's five probe shapes when the
        server speaks 2026-07-28: a server/discover supported-version reading
        (evidence only, the operator allowlist is not externally discoverable),
        then four rejection probes (bogus version, header absent, body version
        absent, header and body disagreeing) judged by the specific HTTP status
        and JSON-RPC error code the benchmark expects. Against a 2025-era
        server the version travels in the header alone, so the probe falls back
        to the two header-mechanism legs and the 2026-07-28 codes are
        revision-gated. The log-inspection half is out of scope.
* 1.2 - compares the full capability configuration leaf by leaf against a
        baseline we record ourselves per server URL (capture/refresh with
        --update-baseline), read from server/discover where the server speaks
        2026-07-28 and from the initialize result otherwise. An unapproved or
        changed leaf fails, a withdrawn leaf is UNKNOWN, matching the
        benchmark's drift classes. Name-level tool/resource/prompt additions
        also fail.
* 1.3 - waits briefly for a listChanged event, then tries the new tool;
        reports UNKNOWN if no event arrives in time. An invalid-params error
        on the invocation is UNKNOWN, not FAIL: the benchmark's audit design
        treats it as indistinguishable from a gate denial without schema-valid
        arguments and a control probe, which a black-box run does not have.
* 1.4 - reduced to: does the server expose non-empty serverInfo.
"""

from __future__ import annotations

import json
from typing import Any

import anyio

from .. import baseline
from ..context import ProbeContext
from ..rawreq import is_success, jsonrpc_error_code, raw_jsonrpc
from .base import Check, CheckResult, Level, register

RC_VERSION = "2026-07-28"
STALE_VERSION = "2025-03-26"
BOGUS_VERSION = "2024-01-01"

_AUDIT_META = {
    "io.modelcontextprotocol/clientInfo": {
        "name": "cis-benchmark-audit",
        "version": "1.0",
    },
    "io.modelcontextprotocol/clientCapabilities": {},
}


def _rc_payload(
    method: str, *, req_id: int, meta_version: str | None, include_meta: bool = True
) -> dict[str, Any]:
    """Build a request whose _meta carries the audit identity and, optionally,
    a protocol version. ``meta_version=None`` with ``include_meta=True`` sends
    the envelope without the version field (the body-absent probe)."""
    meta: dict[str, Any] = dict(_AUDIT_META)
    if meta_version is not None:
        meta = {"io.modelcontextprotocol/protocolVersion": meta_version, **meta}
    params: dict[str, Any] = {"_meta": meta} if include_meta else {}
    return {"jsonrpc": "2.0", "id": req_id, "method": method, "params": params}


async def _probe(
    ctx: ProbeContext,
    payload: dict[str, Any],
    *,
    header: str | None,
) -> tuple[int, dict[str, Any] | None]:
    """POST one probe. ``header=None`` omits MCP-Protocol-Version entirely.
    The Mcp-Method routing header mirrors the benchmark's probe shape."""
    status, data, _ = await raw_jsonrpc(
        ctx.endpoint_url,
        payload,
        token=ctx.access_token,
        session_id=ctx.session_id,
        protocol_header=header,
        extra_headers={"Mcp-Method": payload["method"]},
    )
    return status, data


def _leaves(obj: Any, prefix: str = "") -> dict[str, str]:
    """Flatten a capability object to leaf paths. Non-dict values (including
    lists) are leaves, serialized canonically so comparison is value-exact."""
    out: dict[str, str] = {}
    if isinstance(obj, dict):
        if not obj:
            out[prefix or "."] = "{}"
        for key in sorted(obj):
            path = f"{prefix}.{key}" if prefix else str(key)
            out.update(_leaves(obj[key], path))
        return out
    out[prefix or "."] = json.dumps(obj, sort_keys=True)
    return out


@register
class ProtocolVersionPinning(Check):
    id = "1.1"
    title = "Unapproved, absent, or disagreeing protocol version is rejected"
    section = "1"
    level = Level.L1
    remediation = (
        "Reject requests whose asserted protocol version is absent, outside the "
        "approved allowlist, or asserted inconsistently between the header and "
        "the request _meta, instead of falling back to a default revision."
    )

    async def run(self, ctx: ProbeContext) -> CheckResult:
        if ctx.session is None or not ctx.endpoint_url:
            return self._error("no live session to test against")
        if ctx.rc_supported:
            return await self._run_rc(ctx)
        return await self._run_legacy(ctx)

    # ----- 2026-07-28 mechanism: header and _meta, matching -----------------

    async def _run_rc(self, ctx: ProbeContext) -> CheckResult:
        details: dict[str, Any] = {"mechanism": "header + _meta (2026-07-28)"}
        notes: list[str] = []

        d_status, d_data = await _probe(
            ctx,
            _rc_payload("server/discover", req_id=1, meta_version=RC_VERSION),
            header=RC_VERSION,
        )
        supported = None
        if d_data and isinstance(d_data.get("result"), dict):
            sv = d_data["result"].get("supportedVersions")
            if isinstance(sv, list) and sv and all(isinstance(v, str) for v in sv):
                supported = sorted(sv)
        details["discover_status"] = d_status
        details["supported_versions"] = supported
        notes.append(
            f"discover -> supportedVersions {supported} (evidence only; the "
            f"operator allowlist is not externally discoverable)"
            if supported
            else f"discover -> no well-formed supportedVersions (HTTP {d_status})"
        )

        legs = [
            (
                "bogus",
                _rc_payload("tools/list", req_id=1, meta_version=BOGUS_VERSION),
                BOGUS_VERSION,
                self._judge_bogus,
            ),
            (
                "header_absent",
                _rc_payload("tools/list", req_id=1, meta_version=RC_VERSION),
                None,
                self._judge_header_absent,
            ),
            (
                "body_absent",
                _rc_payload("tools/list", req_id=1, meta_version=None),
                RC_VERSION,
                self._judge_body_absent,
            ),
            (
                "disagree",
                _rc_payload("tools/list", req_id=1, meta_version=RC_VERSION),
                STALE_VERSION,
                self._judge_disagree,
            ),
        ]

        verdicts: list[str] = []
        for name, payload, header, judge in legs:
            status, data = await _probe(ctx, payload, header=header)
            code = jsonrpc_error_code(data)
            if data is None and status < 400:
                verdict, note = "error", "response body is not JSON, verdict not attributable"
            else:
                verdict, note = judge(status, code)
            details[f"{name}_status"] = status
            details[f"{name}_code"] = code
            details[f"{name}_verdict"] = verdict
            verdicts.append(verdict)
            notes.append(f"{name} -> {verdict} (HTTP {status}, code {code}): {note}")

        evidence = "; ".join(notes)
        if "fail" in verdicts:
            return self._fail(evidence, **details)
        if "error" in verdicts:
            return self._error(evidence, **details)
        if "unknown" in verdicts:
            return self._unknown(evidence, **details)
        return self._pass(evidence, **details)

    @staticmethod
    def _judge_bogus(status: int, code: int | None) -> tuple[str, str]:
        if code == -32022 and status == 400:
            return "pass", "unapproved version rejected with UnsupportedProtocolVersion"
        if code == -32022:
            return "fail", "UnsupportedProtocolVersion at a non-400 status, the specification requires 400"
        if code is not None:
            return "unknown", "rejected with an unexpected code, confirm the rejection is version enforcement"
        if status >= 400:
            return "unknown", "HTTP rejection without a JSON-RPC error, not attributable to version enforcement"
        return "fail", "request asserting an unapproved protocol version was accepted"

    @staticmethod
    def _judge_header_absent(status: int, code: int | None) -> tuple[str, str]:
        if code == -32020 and status == 400:
            return "pass", "header-less request rejected with HeaderMismatch"
        if code == -32020:
            return "fail", "HeaderMismatch at a non-400 status, the specification requires 400"
        if code == -32022:
            return (
                "unknown",
                "rejected as an unsupported version rather than HeaderMismatch, a "
                "known reference-SDK divergence, confirm the client-support policy",
            )
        if code is not None:
            return "unknown", "rejected with an unexpected code, confirm the rejection is version enforcement"
        if status >= 400:
            return "unknown", "HTTP rejection without a JSON-RPC error, not attributable"
        return "fail", "request without the protocol version header was accepted"

    @staticmethod
    def _judge_body_absent(status: int, code: int | None) -> tuple[str, str]:
        if code == -32602 and status == 400:
            return "pass", "version-less _meta rejected as invalid params"
        if code == -32602:
            return "fail", "Invalid params at a non-400 status, the specification requires 400"
        if code == -32020 and status == 400:
            return (
                "unknown",
                "rejected as a header mismatch, defensible where the header/body "
                "comparison runs before required-field validation",
            )
        if code == -32022:
            return "unknown", "rejected as an unsupported version, the specification defines this as a malformed request"
        if code is not None:
            return "unknown", "rejected with an unexpected code, confirm the rejection is version enforcement"
        if status >= 400:
            return "unknown", "HTTP rejection without a JSON-RPC error, not attributable"
        return "fail", "request without a version field in the body was accepted"

    @staticmethod
    def _judge_disagree(status: int, code: int | None) -> tuple[str, str]:
        if code == -32020 and status == 400:
            return "pass", "disagreeing header and body rejected with HeaderMismatch"
        if code == -32020:
            return "fail", "HeaderMismatch at a non-400 status, the specification requires 400"
        if code == -32022:
            return (
                "fail",
                "rejected as an unsupported version, but the body carries a supported "
                "version, the specification requires HeaderMismatch on disagreement",
            )
        if code is not None:
            return "unknown", "rejected with an unexpected code, confirm the rejection is mismatch enforcement"
        if status >= 400:
            return "unknown", "HTTP rejection without a JSON-RPC error, not attributable"
        return "fail", "disagreeing header and body versions were accepted"

    # ----- 2025-era mechanism: header only ----------------------------------

    async def _run_legacy(self, ctx: ProbeContext) -> CheckResult:
        base_payload = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
        b_status, b_data, _ = await raw_jsonrpc(
            ctx.endpoint_url,
            base_payload,
            token=ctx.access_token,
            session_id=ctx.session_id,
            protocol_header=BOGUS_VERSION,
        )
        a_status, a_data, _ = await raw_jsonrpc(
            ctx.endpoint_url,
            base_payload,
            token=ctx.access_token,
            session_id=ctx.session_id,
            omit_protocol_header=True,
        )
        b_code = jsonrpc_error_code(b_data)
        a_code = jsonrpc_error_code(a_data)
        b_rejected = b_status >= 400 or b_code is not None
        a_rejected = a_status >= 400 or a_code is not None
        details = {
            "mechanism": "MCP-Protocol-Version header (2025-era)",
            "bogus_status": b_status,
            "bogus_code": b_code,
            "bogus_rejected": b_rejected,
            "absent_status": a_status,
            "absent_code": a_code,
            "absent_rejected": a_rejected,
        }
        evidence = (
            f"via header mechanism (server negotiates a 2025-era revision, so the "
            f"2026-07-28 error-code, body-version, and disagreement legs are "
            f"revision-gated): unapproved version -> "
            f"{'rejected' if b_rejected else 'accepted'} (HTTP {b_status}, code {b_code}); "
            f"absent version -> "
            f"{'rejected' if a_rejected else 'accepted'} (HTTP {a_status}, code {a_code})"
        )
        if b_rejected and a_rejected:
            return self._pass(evidence, **details)
        return self._fail(evidence, **details)


@register
class CapabilityBaseline(Check):
    id = "1.2"
    title = "Advertised capability configuration matches the recorded baseline (no drift)"
    section = "1"
    level = Level.L1
    remediation = (
        "Review and approve any new or changed capability setting into the "
        "baseline, or disable it on the server; unreviewed capability change is "
        "unauthorized drift."
    )

    BASELINE_SCHEMA = 2

    async def run(self, ctx: ProbeContext) -> CheckResult:
        if not ctx.endpoint_url:
            return self._error("no endpoint; cannot read advertised capabilities")

        current = await self._snapshot(ctx)
        if current is None:
            return self._error(
                "no capability object readable from server/discover or the "
                "initialize result, no verdict is attributable"
            )

        if ctx.update_baseline:
            path = baseline.save(ctx.endpoint_url, current)
            return self._unknown(
                f"baseline captured this run ({len(_leaves(current['capabilities']))} "
                f"capability leaf/leaves via {current['source']}, "
                f"{len(current['tools'])} tool(s)), so there was nothing to compare "
                f"against. Re-run without --update-baseline to decide drift",
                saved_to=str(path),
            )

        recorded = baseline.load(ctx.endpoint_url)
        if recorded is None:
            return self._unknown(
                "no baseline recorded yet; run once with --update-baseline to establish it"
            )
        if recorded.get("schema") != self.BASELINE_SCHEMA:
            return self._error(
                "recorded baseline uses the earlier name-level format, not a "
                "canonical capability object; re-capture it with --update-baseline "
                "before auditing"
            )

        base_leaves = _leaves(recorded.get("capabilities", {}))
        cur_leaves = _leaves(current["capabilities"])
        unapproved = sorted(k for k in cur_leaves if k not in base_leaves)
        changed = sorted(
            k for k in cur_leaves if k in base_leaves and cur_leaves[k] != base_leaves[k]
        )
        withdrawn = sorted(k for k in base_leaves if k not in cur_leaves)

        added_names: dict[str, list[str]] = {}
        gone_names: dict[str, list[str]] = {}
        for cat in ("tools", "resources", "prompts"):
            base_set = set(recorded.get(cat, []))
            cur_set = set(current.get(cat, []))
            new_items = sorted(cur_set - base_set)
            gone_items = sorted(base_set - cur_set)
            if new_items:
                added_names[cat] = new_items
            if gone_items:
                gone_names[cat] = gone_items

        details = {
            "source": current["source"],
            "unapproved": unapproved,
            "changed": {k: {"approved": base_leaves[k], "advertised": cur_leaves[k]} for k in changed},
            "withdrawn": withdrawn,
            "added_names": added_names,
            "withdrawn_names": gone_names,
        }

        parts: list[str] = []
        if unapproved:
            parts.append("unapproved: " + ", ".join(unapproved))
        if changed:
            parts.append(
                "changed: "
                + ", ".join(
                    f"{k} approved={base_leaves[k]} advertised={cur_leaves[k]}" for k in changed
                )
            )
        for cat, items in added_names.items():
            parts.append(f"new {cat}: " + ", ".join(items))
        if withdrawn:
            parts.append("withdrawn: " + ", ".join(withdrawn))
        for cat, items in gone_names.items():
            parts.append(f"withdrawn {cat}: " + ", ".join(items))

        if unapproved or changed or added_names:
            return self._fail(
                "the advertised capability configuration exceeds or differs from "
                "the recorded baseline -> " + "; ".join(parts),
                **details,
            )
        if withdrawn or gone_names:
            return self._unknown(
                "baselined capability settings are no longer advertised -> "
                + "; ".join(parts)
                + ". Confirm the withdrawal was approved, then re-capture the baseline",
                **details,
            )
        return self._pass(
            f"the advertised capability configuration matches the recorded "
            f"baseline ({len(cur_leaves)} leaf/leaves via {current['source']})",
            **details,
        )

    async def _snapshot(self, ctx: ProbeContext) -> dict[str, Any] | None:
        caps_obj: dict[str, Any] | None = None
        source = ""
        if ctx.rc_supported:
            status, data = await _probe(
                ctx,
                _rc_payload("server/discover", req_id=1, meta_version=RC_VERSION),
                header=RC_VERSION,
            )
            if data and isinstance(data.get("result"), dict):
                caps = data["result"].get("capabilities")
                if isinstance(caps, dict):
                    caps_obj, source = caps, "server/discover"
        if caps_obj is None and ctx.init_result is not None:
            caps = ctx.init_result.capabilities
            if caps is not None:
                caps_obj = caps.model_dump(exclude_none=True)
                source = "initialize result" + (
                    " (server/discover unavailable)" if ctx.rc_supported else ""
                )
        if caps_obj is None:
            return None
        return {
            "schema": self.BASELINE_SCHEMA,
            "endpoint": ctx.endpoint_url,
            "source": source,
            "capabilities": caps_obj,
            "tools": sorted(t.name for t in ctx.tools),
            "resources": sorted(str(r.uri) for r in ctx.resources),
            "prompts": sorted(p.name for p in ctx.prompts),
        }


@register
class ListChangedRevalidation(Check):
    id = "1.3"
    title = "Capabilities added via listChanged are not silently invocable"
    section = "1"
    level = Level.L2
    remediation = (
        "Hold capabilities newly advertised via listChanged in a staging state "
        "and deny invocation until they are explicitly re-approved."
    )

    WAIT_SECONDS = 6.0
    POLL_SECONDS = 0.3

    async def run(self, ctx: ProbeContext) -> CheckResult:
        if ctx.session is None or not ctx.endpoint_url:
            return self._error("no live session")

        before = {t.name for t in ctx.tools}
        notif = await self._wait_for_listchanged(ctx)
        if notif is None:
            note = ""
            if ctx.rc_supported:
                note = (
                    " (under 2026-07-28 the change signal is a subscriptions/listen "
                    "stream, which this passive wait does not open, so silence here "
                    "is expected behavior, not evidence)"
                )
            return self._unknown(
                f"no listChanged notification observed within "
                f"{self.WAIT_SECONDS:.0f}s{note}"
            )

        try:
            after = (await ctx.session.list_tools()).tools
        except Exception as e:  # noqa: BLE001
            return self._unknown(f"listChanged received but re-listing tools failed: {e!r}")

        added = [t.name for t in after if t.name not in before]
        if not added:
            return self._unknown(
                "listChanged received but no newly added tool could be identified"
            )

        new_tool = added[0]
        status, data, _ = await raw_jsonrpc(
            ctx.endpoint_url,
            {
                "jsonrpc": "2.0",
                "id": 9,
                "method": "tools/call",
                "params": {"name": new_tool, "arguments": {}},
            },
            token=ctx.access_token,
            session_id=ctx.session_id,
        )
        error_code = jsonrpc_error_code(data)
        if is_success(status, data):
            return self._fail(
                f"new tool '{new_tool}' from listChanged was invocable without "
                f"re-approval (HTTP {status})",
                new_tool=new_tool,
            )
        if error_code == -32602:
            return self._unknown(
                f"new tool '{new_tool}' answered the probe with invalid params "
                f"(HTTP {status}, code {error_code}). The benchmark's audit design "
                f"treats this as indistinguishable from a gate denial: deciding it "
                f"needs schema-valid arguments and an approved control probe, "
                f"which a black-box run does not have",
                new_tool=new_tool,
            )
        return self._pass(
            f"new tool '{new_tool}' from listChanged was not invocable "
            f"(HTTP {status}, code {error_code}); confirm this is an authorization "
            f"denial, not method-not-found",
            new_tool=new_tool,
        )

    async def _wait_for_listchanged(self, ctx: ProbeContext):
        waited = 0.0
        while waited < self.WAIT_SECONDS:
            for n in list(ctx.notifications):
                method = getattr(n, "method", "")
                if isinstance(method, str) and method.endswith("list_changed"):
                    return n
            await anyio.sleep(self.POLL_SECONDS)
            waited += self.POLL_SECONDS
        return None


@register
class ServerInfoExposed(Check):
    id = "1.4"
    title = "Server exposes non-empty identity metadata (serverInfo)"
    section = "1"
    level = Level.L1
    remediation = (
        "Populate serverInfo.name and serverInfo.version so the identity can be "
        "captured and validated against an inventory."
    )

    async def run(self, ctx: ProbeContext) -> CheckResult:
        if ctx.init_result is None:
            return self._error("no session; serverInfo unavailable")
        si = ctx.init_result.serverInfo
        name = (si.name or "").strip() if si else ""
        version = ((getattr(si, "version", "") or "").strip()) if si else ""
        rc_note = ""
        if ctx.rc_supported:
            rc_note = (
                "; under 2026-07-28 identity is asserted per-message in _meta and "
                "cross-referenced against the enterprise registry, both of which "
                "are operator-side, so this check reads the externally observable half"
            )
        if name:
            return self._pass(
                f"serverInfo present: name='{name}', version='{version or '(none)'}'"
                + rc_note,
                name=name,
                version=version,
            )
        return self._fail("serverInfo missing or empty (no name asserted)" + rc_note)
