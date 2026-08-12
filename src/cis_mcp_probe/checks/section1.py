"""Section 1 checks, implemented as live probes.

Each check reflects the agreed scope from reviewing the benchmark text:

* 1.1 - tested on the wire; the log-inspection half is out of scope.
* 1.2 - compared against a baseline we record ourselves per server URL
        (capture/refresh with --update-baseline).
* 1.3 - waits briefly for a listChanged event, then tries the new tool;
        reports UNKNOWN if no event arrives in time.
* 1.4 - reduced to: does the server expose non-empty serverInfo.

The probe talks 2026-07-28 when the server supports it, otherwise 2025-11-25.
Check 1.1 adapts its mechanism accordingly (per-request _meta vs. the
MCP-Protocol-Version header).
"""

from __future__ import annotations

import anyio

from .. import baseline
from ..context import ProbeContext
from ..rawreq import is_rejection, is_success, raw_jsonrpc
from .base import Check, CheckResult, Level, register

_AUDIT_META = {
    "io.modelcontextprotocol/clientInfo": {
        "name": "cis-benchmark-audit",
        "version": "1.0",
    },
    "io.modelcontextprotocol/clientCapabilities": {},
}


@register
class ProtocolVersionPinning(Check):
    id = "1.1"
    title = "Unapproved or absent protocol version is rejected"
    section = "1"
    level = Level.L1
    remediation = (
        "Reject requests whose asserted protocol version is absent or outside the "
        "approved allowlist instead of falling back to a default revision."
    )

    BOGUS_VERSION = "2024-01-01"

    async def run(self, ctx: ProbeContext) -> CheckResult:
        if ctx.session is None or not ctx.endpoint_url:
            return self._error("no live session to test against")

        endpoint, token, sid = ctx.endpoint_url, ctx.access_token, ctx.session_id

        if ctx.rc_supported:
            mechanism = "_meta protocolVersion (2026-07-28)"
            bogus_payload = self._tools_list_meta(self.BOGUS_VERSION)
            absent_payload = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list",
                "params": {},  # no _meta at all -> version absent
            }
            b_status, b_data, _ = await raw_jsonrpc(
                endpoint, bogus_payload, token=token, session_id=sid
            )
            a_status, a_data, _ = await raw_jsonrpc(
                endpoint, absent_payload, token=token, session_id=sid
            )
        else:
            mechanism = "MCP-Protocol-Version header (2025-11-25)"
            base_payload = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list",
                "params": {},
            }
            b_status, b_data, _ = await raw_jsonrpc(
                endpoint,
                base_payload,
                token=token,
                session_id=sid,
                protocol_header=self.BOGUS_VERSION,
            )
            a_status, a_data, _ = await raw_jsonrpc(
                endpoint,
                base_payload,
                token=token,
                session_id=sid,
                omit_protocol_header=True,
            )

        bogus_rejected = is_rejection(b_status, b_data)
        absent_rejected = is_rejection(a_status, a_data)
        evidence = (
            f"via {mechanism}: unapproved version -> "
            f"{'rejected' if bogus_rejected else 'accepted'} (HTTP {b_status}); "
            f"absent version -> "
            f"{'rejected' if absent_rejected else 'accepted'} (HTTP {a_status})"
        )
        details = {
            "mechanism": mechanism,
            "bogus_status": b_status,
            "absent_status": a_status,
            "bogus_rejected": bogus_rejected,
            "absent_rejected": absent_rejected,
        }
        if bogus_rejected and absent_rejected:
            return self._pass(evidence, **details)
        return self._fail(evidence, **details)

    def _tools_list_meta(self, version: str) -> dict:
        return {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": version,
                    **_AUDIT_META,
                }
            },
        }


@register
class CapabilityBaseline(Check):
    id = "1.2"
    title = "Advertised capabilities match the recorded baseline (no drift)"
    section = "1"
    level = Level.L1
    remediation = (
        "Review and approve any new capability into the baseline, or disable it "
        "on the server; unreviewed capability growth is unauthorized drift."
    )

    async def run(self, ctx: ProbeContext) -> CheckResult:
        if ctx.init_result is None or not ctx.endpoint_url:
            return self._error("no session; cannot read advertised capabilities")

        current = baseline.snapshot(ctx)

        if ctx.update_baseline:
            path = baseline.save(ctx.endpoint_url, current)
            # Capturing a baseline compares nothing, so this run cannot decide.
            # A later run against the stored baseline can: UNKNOWN, not PASS.
            return self._unknown(
                f"baseline captured this run ({len(current['capability_keys'])} "
                f"capability key(s), {len(current['tools'])} tool(s)), so there "
                f"was nothing to compare against. Re-run without "
                f"--update-baseline to decide drift",
                saved_to=str(path),
            )

        recorded = baseline.load(ctx.endpoint_url)
        if recorded is None:
            return self._unknown(
                "no baseline recorded yet; run once with --update-baseline to "
                "establish it"
            )

        added = baseline.diff(recorded, current)
        if not added:
            return self._pass("advertised capabilities are within the recorded baseline")
        parts = [f"{cat}: {', '.join(items)}" for cat, items in added.items()]
        return self._fail(
            "capability drift since baseline -> " + "; ".join(parts), added=added
        )


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
            return self._unknown(
                f"no listChanged notification observed within "
                f"{self.WAIT_SECONDS:.0f}s"
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

        # Reaching the tool at all (success, or an invalid-params error) means it
        # was invocable without re-approval. A method-not-found / auth error means
        # it was not reachable.
        error_code = (data or {}).get("error", {}).get("code") if data else None
        reached_tool = is_success(status, data) or error_code == -32602
        if reached_tool:
            return self._fail(
                f"new tool '{new_tool}' from listChanged was invocable without "
                f"re-approval (HTTP {status}, code {error_code})",
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
        if name:
            return self._pass(
                f"serverInfo present: name='{name}', version='{version or '(none)'}'",
                name=name,
                version=version,
            )
        return self._fail("serverInfo missing or empty (no name asserted)")
