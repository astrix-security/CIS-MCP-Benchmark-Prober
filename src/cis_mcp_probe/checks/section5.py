"""CIS MCP Benchmark Section 5 — Server Configuration.

Section 4 governs the host; Section 5 governs the server, which is the only side a
black-box probe sees. Five of the ten recommendations yield a check:

* 5.1.1 - tool schemas compile under their declared dialect; a violating call is
  surfaced as an execution error. The schema-violating leg needs an operator input.
* 5.1.2 - resource templates declare a URI pattern and a MIME type, and a read of a
  non-existent resource is rejected.
* 5.1.3 - prompts declare well-formed arguments, and an invalid name or a missing
  required argument is rejected. Read from a raw prompts/list: Pydantic coerces a
  non-boolean ``required``, so the SDK path would pass the violation it tests.
* 5.2.3 - the legacy session and stream-resumption surface is gone. Valid only for
  2026-07-28, so it reports NO-REV against every server on an older revision.
* 5.4.1 - a resource read that escapes the approved root is denied.

The other five are operator-side and return NOT_APPLICABLE with the reason.
"""

from __future__ import annotations

from typing import Any

from jsonschema.exceptions import SchemaError
from jsonschema.validators import (
    Draft7Validator,
    Draft201909Validator,
    Draft202012Validator,
)

from mcp.shared.exceptions import McpError

from .. import inputs
from ..client import RC_VERSION
from ..rawreq import (
    jsonrpc_error_code,
    raw_endpoint_request,
    raw_jsonrpc,
    raw_jsonrpc_headers,
)
from ..context import ProbeContext
from .base import Check, CheckResult, Level, register

# The dialects we implement, keyed by the token found in a declared $schema.
# Explicit rather than delegated: validator_for() falls back to the latest draft on
# an unknown value, which would grade a schema under rules it never declared.
_DIALECTS = {
    "": ("2020-12", Draft202012Validator),
    "2020-12": ("2020-12", Draft202012Validator),
    "2019-09": ("2019-09", Draft201909Validator),
    "draft-07": ("draft-07", Draft7Validator),
}


def _declared_dialect(schema: dict) -> str:
    """The _DIALECTS key for this schema's ``$schema``, or the raw value."""
    declared = schema.get("$schema")
    if not isinstance(declared, str) or not declared:
        return ""
    for token in ("2020-12", "2019-09", "draft-07"):
        if token in declared:
            return token
    return declared


def _has_external_ref(node: Any) -> bool:
    """Whether any ``$ref`` anywhere carries a URI scheme.

    check_schema() accepts such a schema without complaint, so this walk is the only
    thing that observes it.
    """
    if isinstance(node, dict):
        ref = node.get("$ref")
        if isinstance(ref, str) and "://" in ref:
            return True
        return any(_has_external_ref(v) for v in node.values())
    if isinstance(node, list):
        return any(_has_external_ref(v) for v in node)
    return False


def compile_schema(schema: dict) -> tuple[str, str, bool]:
    """Compile ``schema`` under the dialect it declares.

    Returns ``(outcome, dialect, has_external_ref)``. ``outcome`` is ``"ok"``,
    ``"unrecognised-dialect"``, or the first line of the SchemaError.
    """
    external = _has_external_ref(schema)
    entry = _DIALECTS.get(_declared_dialect(schema))
    if entry is None:
        return "unrecognised-dialect", _declared_dialect(schema), external
    dialect, validator = entry
    try:
        validator.check_schema(schema)
    except SchemaError as exc:
        return str(exc).splitlines()[0], dialect, external
    return "ok", dialect, external


# Which capability field gates each inventory. There is no resource_templates
# capability: _enumerate gates templates on resources.
_CAPABILITY_FOR = {
    "tools": "tools",
    "prompts": "prompts",
    "resources": "resources",
    "resource_templates": "resources",
}


def _inventory_state(ctx: ProbeContext, primitive: str) -> tuple[int, str]:
    """Which of five states an empty ``primitive`` inventory is in, and why.

    Only state 4 can carry a verdict. Three of the others are claims about this run
    rather than about the server, so they must not share one sentence.
    """
    if ctx.init_result is None:
        return 0, "the session never initialized, so nothing was observed"
    field = _CAPABILITY_FOR[primitive]
    if getattr(ctx.init_result.capabilities, field, None) is None:
        return 1, f"the server declares no {field} capability"
    if any(e.startswith(f"list_{primitive}:") for e in ctx.errors):
        # ctx.errors holds repr(e), so a validation error, a -32601 and a timeout
        # are indistinguishable. Say both rather than picking one.
        return 2, f"the {primitive} document did not parse or the method was refused"
    if not getattr(ctx, primitive):
        return 3, f"the server declares {field} and advertised no {primitive}"
    return 4, ""


@register
class ListChangedRateLimit(Check):
    """5.2.1, Assessment Status: Automated.

    Two blockers, either sufficient. The emission rate over time lives in the
    server's own log, and no external client can provoke a list change, so even a
    held-open subscription stream would have nothing to time.
    """

    id = "5.2.1"
    title = "listChanged notifications are rate-limited to prevent client flooding"
    section = "5"
    level = Level.L2
    remediation = (
        "Configure a minimum interval between two successive list_changed "
        "notifications of the same type, and log the emission rate per server."
    )

    async def run(self, ctx: ProbeContext) -> CheckResult:
        return self._na(
            "Read from the text, not reproduced live. Emission rate over time is "
            "visible only in the server's log, and no external client can provoke a "
            "list change to time two of them. The minimum interval is itself a CIS "
            "Level 2 choice the specification does not define, so there is no "
            "protocol default to test against either."
        )


@register
class SessionIsNotAuthentication(Check):
    """5.2.2, Assessment Status: Manual.

    The wire half needs a handle captured from an authorized session and a tool that
    accepts one as an argument. The recommendation is explicit that the handle is an
    application value rather than a protocol field, so nothing observable names such
    a tool. The rest is inspection of a value we never see.
    """

    id = "5.2.2"
    title = "Sessions are not used as authentication and are bound to user identity"
    section = "5"
    level = Level.L1
    remediation = (
        "Establish authorization independently per request. Where continuity is "
        "needed, issue a handle from a cryptographically secure source, bind it to "
        "the authenticated identity, re-validate it on every use, and expire it."
    )

    async def run(self, ctx: ProbeContext) -> CheckResult:
        return self._na(
            "Read from the text, not reproduced live. The probe needs a handle "
            "captured from an authorized session and a tool that accepts one as an "
            "argument, and neither is discoverable. The adjacent property, an "
            "unauthenticated request reaching a response, is already decided by "
            "check 2.3, so no coverage is lost here."
        )


@register
class StdioLogSeparation(Check):
    """5.3.1, Assessment Status: Automated.

    Scoped to stdio transport. This probe reaches servers by domain over HTTP and
    never launches a server process, so there is no stdout to capture.
    """

    id = "5.3.1"
    title = "Logs are separated from the protocol stream in stdio mode"
    section = "5"
    level = Level.L1
    remediation = (
        "Reserve stdout for JSON-RPC messages only and direct every log, banner and "
        "diagnostic line to stderr or a file sink."
    )

    async def run(self, ctx: ProbeContext) -> CheckResult:
        return self._na(
            "Transport mismatch, not a missing capability: this check applies to the "
            "stdio transport, and this probe speaks HTTP to a remote endpoint and "
            "never launches a server process."
        )


@register
class TaskAuthorization(Check):
    """5.5.1, Assessment Status: Manual.

    Cross-identity access needs a second bearer token. tasks/list was removed in
    2026-07-28, so an existing task cannot be enumerated either, and ttlMs cannot be
    read without creating one.
    """

    id = "5.5.1"
    title = "Authorization, scope and expiry controls are enforced on MCP Tasks"
    section = "5"
    level = Level.L2
    remediation = (
        "Enforce authorization independently at task creation, status polling and "
        "result retrieval, and set a finite non-null ttlMs."
    )

    async def run(self, ctx: ProbeContext) -> CheckResult:
        caps = ctx.init_result.capabilities if ctx.init_result else None
        declared = getattr(caps, "tasks", None) is not None
        observed = "declares" if declared else "declares no"
        return self._na(
            "Read from the text, not reproduced live. Cross-identity retrieval needs "
            "a second identity's bearer token, and tasks/list was removed in this "
            f"revision so an existing task cannot be enumerated. The server {observed} "
            "the Tasks capability.",
            tasks_declared=declared,
        )


@register
class IdempotencyKeys(Check):
    """5.6.1, Assessment Status: Manual.

    Two blockers. Every wire leg executes a side-effecting tool, and the only signal
    that would identify one is an annotation check 3.2.3 asserts must not be relied
    upon. And Idempotency-Key is a convention this recommendation defines rather than
    an MCP field, so a server that never adopted it would fail for not implementing
    a CIS convention.
    """

    id = "5.6.1"
    title = "Idempotency keys are required for side-effecting tool calls"
    section = "5"
    level = Level.L2
    remediation = (
        "Require a client-supplied idempotency key on every side-effecting tool "
        "call, return the stored result for a duplicate key with the same payload, "
        "and reject a reused key carrying a different payload as a conflict."
    )

    async def run(self, ctx: ProbeContext) -> CheckResult:
        return self._na(
            "Read from the text, not reproduced live. Every wire leg requires the "
            "deliberate execution of a side-effecting tool, and no wire observation "
            "identifies a reversible one. Separately, the Idempotency-Key header and "
            "the cached-result indicator are conventions this recommendation defines "
            "and are not MCP specification fields, so a FAIL against a server that "
            "never adopted them would be unearned."
        )


# Carried by every leg that reads an inventory: _enumerate takes one page and drops
# nextCursor, so no check can tell whether the inventory was truncated.
PAGE_ONE = (
    " Scope: page one of the advertised inventory only, because discovery reads a "
    "single page and does not retain nextCursor."
)

_ORDER = ("fail", "error", "unknown", "pass")


def _aggregate(
    results: list[tuple[str, str, str]], caveat: str = ""
) -> tuple[str, str, dict[str, str]]:
    """Fold per-leg outcomes into one verdict name, one evidence string and a map.

    A caveat is appended to evidence and never changes the fold: a reduction does
    not downgrade a verdict.
    """
    legs = {label: outcome for label, outcome, _ in results}
    evidence = "; ".join(f"{label}: {note}" for label, _, note in results)
    for candidate in _ORDER:
        if any(o == candidate for _, o, _ in results):
            return candidate, evidence + caveat, legs
    return "unknown", evidence + caveat, legs


def _violating_args(args: dict, schema: dict) -> tuple[dict | None, str]:
    """``args`` less one required property, or None and the reason.

    The removed key must be in both the operator's object and the schema's required
    list. Only in the object and the call stays schema-valid, so a conformant server
    executes it and the leg records a false fail.
    """
    required = schema.get("required")
    if not isinstance(required, list):
        return None, "the tool's inputSchema declares no required list"
    shared = [k for k in required if isinstance(k, str) and k in args]
    if not shared:
        return None, (
            "no property is both supplied by the operator and marked required, so "
            "no removal would violate the schema"
        )
    return {k: v for k, v in args.items() if k != shared[0]}, shared[0]


def _resolve_probe_tool(
    entry: dict, tools: list
) -> tuple[tuple[str, dict, str] | None, str]:
    """Leg 5.1.1d's input, or None and why nothing will be sent.

    Separate from the leg and synchronous, so the no-input paths are assertable
    without standing up a session.
    """
    name = entry.get("schema_probe_tool")
    if not name:
        return None, "no schema_probe_tool for this domain"
    args = entry.get("schema_probe_arguments")
    if not args:
        return None, f"schema_probe_tool {name!r} has no schema_probe_arguments"
    match = next((t for t in tools if t.name == name), None)
    if match is None:
        return None, f"the server does not advertise a tool named {name!r}"
    violating, why = _violating_args(args, match.inputSchema)
    if violating is None:
        return None, why
    return (name, violating, why), ""


def _leg_5111a(ctx: ProbeContext) -> tuple[str, str, str]:
    """Every advertised inputSchema compiles under its declared dialect."""
    state, note = _inventory_state(ctx, "tools")
    if state == 0:
        return "5.1.1a", "error", note
    if state != 4:
        return "5.1.1a", "unknown", note
    bad, unknown_dialect = [], []
    for tool in ctx.tools:
        outcome, dialect, _ = compile_schema(tool.inputSchema)
        if outcome == "unrecognised-dialect":
            unknown_dialect.append(f"{tool.name} declares {dialect!r}")
        elif outcome != "ok":
            bad.append(f"{tool.name} inputSchema under {dialect}: {outcome}")
    if bad:
        return "5.1.1a", "fail", "; ".join(bad)
    if unknown_dialect:
        return "5.1.1a", "unknown", "; ".join(unknown_dialect)
    return "5.1.1a", "pass", f"{len(ctx.tools)} inputSchema(s) compiled"


def _leg_5111b(ctx: ProbeContext) -> tuple[str, str, str]:
    """Every declared outputSchema compiles. None declared cannot pass."""
    state, note = _inventory_state(ctx, "tools")
    if state == 0:
        return "5.1.1b", "error", note
    if state != 4:
        return "5.1.1b", "unknown", note
    declared = [t for t in ctx.tools if t.outputSchema is not None]
    if not declared:
        # Optional under the revision, so its absence is not a finding -- but a leg
        # that compiled nothing cannot report a pass.
        return "5.1.1b", "unknown", "no tool declares an outputSchema"
    bad = []
    for tool in declared:
        outcome, dialect, _ = compile_schema(tool.outputSchema)
        if outcome != "ok":
            bad.append(f"{tool.name} outputSchema under {dialect}: {outcome}")
    if bad:
        return "5.1.1b", "fail", "; ".join(bad)
    return "5.1.1b", "pass", f"{len(declared)} outputSchema(s) compiled"


def _leg_5111c(ctx: ProbeContext) -> tuple[str, str, str]:
    """External $ref count. Evidence only: the requirement binds the server's own
    validator configuration, which nothing observable reaches."""
    names = [
        t.name
        for t in ctx.tools
        if compile_schema(t.inputSchema)[2]
        or (t.outputSchema is not None and compile_schema(t.outputSchema)[2])
    ]
    if not names:
        return "5.1.1c", "", "no advertised schema carries an external $ref"
    return (
        "5.1.1c",
        "",
        (
            f"{len(names)} schema(s) carry an external $ref ({', '.join(names)}), so "
            "5.1.1a compiled them with that reference unresolved"
        ),
    )


# The two codes that earn a fail on 5.1.1d. The recommendation is explicit that a
# schema violation is a tool execution error, so a protocol error is the finding --
# but only these two are attributable to the validation path. A -32601, a 500 or a
# bare 4xx from a gateway says nothing about which error the server chose.
_PROTOCOL_INSTEAD_OF_EXECUTION = (-32602, -32600)


async def _leg_5111d(ctx: ProbeContext) -> tuple[str, str, str]:
    """A schema-violating call is surfaced as an execution error, not executed."""
    if ctx.session is None:
        return "5.1.1d", "error", "no live session to call a tool through"
    resolved, why = _resolve_probe_tool(inputs.load(ctx.domain), ctx.tools)
    if resolved is None:
        return "5.1.1d", "unknown", f"{why}, so no tools/call was sent"
    name, args, dropped = resolved
    try:
        result = await ctx.session.call_tool(name, args)
    except McpError as exc:
        code = getattr(exc.error, "code", None)
        if code in _PROTOCOL_INSTEAD_OF_EXECUTION:
            return (
                "5.1.1d",
                "fail",
                (
                    f"omitting required {dropped!r} was rejected with protocol error "
                    f"{code}, not surfaced as a tool execution error"
                ),
            )
        return (
            "5.1.1d",
            "error",
            (
                f"the call failed with {code}, which does not show the server chose a "
                "protocol error over an execution error"
            ),
        )
    if getattr(result, "isError", False):
        return (
            "5.1.1d",
            "pass",
            (f"omitting required {dropped!r} was surfaced as a tool execution error"),
        )
    return (
        "5.1.1d",
        "fail",
        (
            f"the server returned a normal result for a call omitting required {dropped!r}"
        ),
    )


@register
class ToolSchemaValidation(Check):
    """5.1.1, Assessment Status: Automated.

    Scoped to what a client sees: the advertised schemas compile, and a violating
    call is not executed. Not probed: schema depth and validation-time bounds, and
    field sanitization, none of which has a wire signature.
    """

    id = "5.1.1"
    title = "Tool schemas and argument types are validated"
    section = "5"
    level = Level.L1
    remediation = (
        "Validate every tool input and output against the advertised schema before "
        "the tool executes, using the dialect each schema declares. Return a "
        "schema-violating call as a tool execution error with isError set, not as a "
        "protocol error."
    )

    async def run(self, ctx: ProbeContext) -> CheckResult:
        results = [_leg_5111a(ctx), _leg_5111b(ctx), await _leg_5111d(ctx)]
        reduction = (
            " Not probed: schema depth and validation-time bounds and field "
            "sanitization have no wire signature. Evidence only: "
            + _leg_5111c(ctx)[2]
            + "."
        )
        verdict, evidence, legs = _aggregate(
            [r for r in results if r[1]], caveat=PAGE_ONE + reduction
        )
        return getattr(self, f"_{verdict}")(evidence, legs=legs)


def _refusal_outcome(code: int | None, has_result: bool) -> tuple[str, str]:
    """Classify a rejection the recommendation requires but does not code exactly.

    Any attributable error code is a pass: the server refused, and which rule fired
    is ambiguous rather than absent. A served result is the failure.
    """
    if code == -32602:
        return "pass", "rejected with -32602"
    if code == -32002:
        return "pass", "rejected with the legacy -32002, which the audit text accepts"
    if code is not None:
        return "pass", f"rejected with {code}, a deviation from the recommended -32602"
    if has_result:
        return "fail", "the server returned a normal result"
    return "error", "neither an error code nor a result, so it is not attributable"


def _substitute_template(uri_template: str) -> str | None:
    """``uri_template`` with an implausible value for its first variable."""
    start = uri_template.find("{")
    end = uri_template.find("}", start + 1)
    if start == -1 or end == -1:
        return None
    return uri_template[:start] + "cis-audit-no-such-value" + uri_template[end + 1 :]


def _first_required_prompt(raw: dict) -> dict | None:
    """The first advertised prompt carrying a required argument, from raw JSON."""
    prompts = (raw.get("result") or {}).get("prompts")
    if not isinstance(prompts, list):
        return None
    for prompt in prompts:
        args = prompt.get("arguments") if isinstance(prompt, dict) else None
        if isinstance(args, list) and any(
            isinstance(a, dict) and a.get("required") for a in args
        ):
            return prompt
    return None


def _read_payload(req_id: int, uri: str) -> dict:
    """The resources/read payload, built by concatenation only.

    Returned rather than sent, so a self-check can inspect the exact uri that will
    go on the wire. AnyUrl and urljoin both apply RFC 3986 dot-segment removal,
    which would strip a traversal before it left.
    """
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "method": "resources/read",
        "params": {"uri": uri},
    }


def _raw_prompts(raw: dict) -> list | None:
    """The prompts array from a raw prompts/list result, or None."""
    prompts = (raw.get("result") or {}).get("prompts")
    return prompts if isinstance(prompts, list) else None


def _leg_5112a(ctx: ProbeContext) -> tuple[str, str, str]:
    """Every advertised resource template declares a non-empty uriTemplate."""
    state, note = _inventory_state(ctx, "resource_templates")
    if state == 0:
        return "5.1.2a", "error", note
    if state != 4:
        # Templates key off the resources capability, so state 1 cannot tell "no
        # template surface" from "no resource surface".
        return "5.1.2a", "unknown", note
    bad = [t for t in ctx.resource_templates if not (t.uriTemplate or "").strip()]
    if bad:
        return "5.1.2a", "fail", f"{len(bad)} template(s) declare an empty uriTemplate"
    return (
        "5.1.2a",
        "pass",
        (
            f"{len(ctx.resource_templates)} template(s) declare a uriTemplate. A null or "
            "non-string value is not observable: the SDK types the field str, so such a "
            "document fails validation before it reaches this check"
        ),
    )


def _leg_5112b(ctx: ProbeContext) -> tuple[str, str, str]:
    """Every advertised resource template declares an explicit MIME type."""
    state, note = _inventory_state(ctx, "resource_templates")
    if state == 0:
        return "5.1.2b", "error", note
    if state != 4:
        return "5.1.2b", "unknown", note
    bad = [t for t in ctx.resource_templates if not (t.mimeType or "").strip()]
    stricter = (
        "this requirement is stricter than base MCP, which makes mimeType optional"
    )
    if bad:
        return (
            "5.1.2b",
            "fail",
            (f"{len(bad)} template(s) declare no mimeType; {stricter}"),
        )
    return (
        "5.1.2b",
        "pass",
        (f"{len(ctx.resource_templates)} template(s) declare a mimeType; {stricter}"),
    )


def _leg_5113a(raw: dict) -> tuple[str, str, str]:
    """Every declared prompt argument names its parameter, read from raw JSON."""
    prompts = _raw_prompts(raw)
    if prompts is None:
        return (
            "5.1.3a",
            "unknown",
            "the raw prompts/list reply carried no prompts array",
        )
    if not prompts:
        return "5.1.3a", "unknown", "the server advertised no prompt"
    bad = [
        f"{p.get('name')!r} argument {a.get('name')!r}"
        for p in prompts
        for a in (p.get("arguments") or [])
        if not isinstance(a.get("name"), str) or not a["name"].strip()
    ]
    if bad:
        return "5.1.3a", "fail", f"non-string or empty argument name: {'; '.join(bad)}"
    return "5.1.3a", "pass", f"{len(prompts)} prompt(s) name every declared argument"


def _leg_5113b(raw: dict) -> tuple[str, str, str]:
    """``required`` is a JSON boolean where present.

    Read raw, because Pydantic runs in lax mode and coerces "yes", "1", 1 and 1.0 to
    True -- so a leg reading ctx.prompts would pass the violation it tests.
    """
    prompts = _raw_prompts(raw)
    if prompts is None:
        return (
            "5.1.3b",
            "unknown",
            "the raw prompts/list reply carried no prompts array",
        )
    if not prompts:
        return "5.1.3b", "unknown", "the server advertised no prompt"
    bad = [
        f"{p.get('name')!r} argument {a.get('name')!r} declares required={a['required']!r}"
        for p in prompts
        for a in (p.get("arguments") or [])
        if "required" in a and not isinstance(a["required"], bool)
    ]
    if bad:
        return "5.1.3b", "fail", "; ".join(bad)
    return "5.1.3b", "pass", f"{len(prompts)} prompt(s) declare a boolean required"


async def _read_uri(
    ctx: ProbeContext, req_id: int, uri: str
) -> tuple[dict | None, dict]:
    """resources/read through raw_jsonrpc, returning (parsed, payload_sent).

    Never session.read_resource: its signature takes a pydantic AnyUrl, which
    rewrites a URI on construction. The payload is returned so evidence renders from
    the exact dict that went on the wire.
    """
    payload = _read_payload(req_id, uri)
    _status, data, _text = await raw_jsonrpc(
        ctx.endpoint_url or "",
        payload,
        token=ctx.access_token,
        session_id=ctx.session_id,
    )
    return data, payload


async def _leg_5112c(ctx: ProbeContext) -> tuple[str, str, str]:
    """A read of a non-existent resource is rejected."""
    if ctx.session is None:
        return "5.1.2c", "error", "no live session to read through"
    if not ctx.resources:
        return (
            "5.1.2c",
            "unknown",
            (
                "no concrete resource to use as a positive control, so a refusal could "
                "not be attributed to existence checking"
            ),
        )
    if not ctx.resource_templates:
        return "5.1.2c", "unknown", "no advertised template to build a missing URI from"
    missing = _substitute_template(ctx.resource_templates[0].uriTemplate)
    if missing is None:
        return (
            "5.1.2c",
            "unknown",
            (
                f"template {ctx.resource_templates[0].uriTemplate!r} declares no variable, "
                "so no implausible URI could be built"
            ),
        )
    control, _ = await _read_uri(ctx, 1, str(ctx.resources[0].uri))
    if not ((control or {}).get("result") or {}).get("contents"):
        return "5.1.2c", "unknown", "the positive-control read returned no contents"
    data, payload = await _read_uri(ctx, 2, missing)
    outcome, note = _refusal_outcome(
        jsonrpc_error_code(data), bool((data or {}).get("result"))
    )
    return "5.1.2c", outcome, f"reading {payload['params']['uri']!r}: {note}"


async def _prompts_raw(ctx: ProbeContext) -> dict:
    """One raw prompts/list, serving legs 5.1.3a and 5.1.3b."""
    _status, data, _text = await raw_jsonrpc(
        ctx.endpoint_url or "",
        {"jsonrpc": "2.0", "id": 1, "method": "prompts/list", "params": {}},
        token=ctx.access_token,
        session_id=ctx.session_id,
    )
    return data or {}


async def _get_prompt(ctx: ProbeContext, req_id: int, name: str, args: dict) -> dict:
    _status, data, _text = await raw_jsonrpc(
        ctx.endpoint_url or "",
        {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": "prompts/get",
            "params": {"name": name, "arguments": args},
        },
        token=ctx.access_token,
        session_id=ctx.session_id,
    )
    return data or {}


async def _leg_5113c(ctx: ProbeContext, raw: dict) -> tuple[str, str, str]:
    """A prompts/get omitting a required argument is rejected."""
    if ctx.session is None:
        return "5.1.3c", "error", "no live session to call prompts/get through"
    prompt = _first_required_prompt(raw)
    if prompt is None:
        return "5.1.3c", "unknown", "no advertised prompt declares a required argument"
    name = prompt["name"]
    valid = {
        a["name"]: "cis-audit-placeholder"
        for a in prompt.get("arguments") or []
        if isinstance(a.get("name"), str)
    }
    control = await _get_prompt(ctx, 2, name, valid)
    if not ((control.get("result") or {}).get("messages")):
        # A placeholder is not a valid value for every argument, so this is a real
        # possibility rather than a defect, and the audit directs the same reading.
        return (
            "5.1.3c",
            "unknown",
            (
                f"the control prompts/get for {name!r} returned no messages, so a "
                "missing-argument rejection could not be attributed"
            ),
        )
    data = await _get_prompt(ctx, 3, name, {})
    outcome, note = _refusal_outcome(jsonrpc_error_code(data), bool(data.get("result")))
    return "5.1.3c", outcome, f"omitting a required argument of {name!r}: {note}"


async def _leg_5113d(ctx: ProbeContext, raw: dict) -> tuple[str, str, str]:
    """An invalid prompt name is rejected.

    Reuses 5.1.3c's control: answering prompts/list says nothing about prompts/get
    being implemented, and a server refusing every prompts/get would otherwise pass.
    """
    if ctx.session is None:
        return "5.1.3d", "error", "no live session to call prompts/get through"
    prompt = _first_required_prompt(raw)
    if prompt is None:
        return "5.1.3d", "unknown", "no prompt available to establish a passing control"
    data = await _get_prompt(ctx, 4, "cis-audit-no-such-prompt", {})
    outcome, note = _refusal_outcome(jsonrpc_error_code(data), bool(data.get("result")))
    return "5.1.3d", outcome, f"an unadvertised prompt name: {note}"


@register
class ResourceTemplateDeclarations(Check):
    """5.1.2, Assessment Status: Automated.

    Not probed: substitution ordering is server-internal, and the access-control
    namespace and nosniff halves are conditional on deployment intent this probe
    cannot read. The recommendation states both as a stricter CIS posture.
    """

    id = "5.1.2"
    title = "Resource templates with explicit URI patterns and MIME types are used"
    section = "5"
    level = Level.L1
    remediation = (
        "Declare a non-empty uriTemplate and an explicit mimeType on every resource "
        "template, and reject a read of a non-existent resource with -32602."
    )

    async def run(self, ctx: ProbeContext) -> CheckResult:
        results = [_leg_5112a(ctx), _leg_5112b(ctx), await _leg_5112c(ctx)]
        reduction = (
            " Not probed: substitution ordering is server-internal, and the "
            "approved-namespace and nosniff requirements depend on deployment intent "
            "this probe cannot read."
        )
        verdict, evidence, legs = _aggregate(results, caveat=PAGE_ONE + reduction)
        return getattr(self, f"_{verdict}")(evidence, legs=legs)


@register
class PromptArgumentDeclarations(Check):
    """5.1.3, Assessment Status: Automated.

    Legs a and b read a raw prompts/list rather than ctx.prompts: Pydantic coerces a
    non-boolean ``required``, so the SDK path would pass the violation leg b tests.

    Not probed: whether prompt logic runs only on an explicit prompts/get, and
    whether the prompt name is recorded per invocation. Neither has a wire signature.
    """

    id = "5.1.3"
    title = "Prompt templates declare and validate their arguments"
    section = "5"
    level = Level.L1
    remediation = (
        "Declare every prompt argument with a non-empty name and a boolean required "
        "flag, and reject an invalid prompt name or a missing required argument with "
        "-32602."
    )

    async def run(self, ctx: ProbeContext) -> CheckResult:
        state, note = _inventory_state(ctx, "prompts")
        if state == 0:
            return self._error(note)
        if state in (1, 2, 3):
            return self._unknown(note + PAGE_ONE, legs={})
        raw = await _prompts_raw(ctx)
        results = [
            _leg_5113a(raw),
            _leg_5113b(raw),
            await _leg_5113c(ctx, raw),
            await _leg_5113d(ctx, raw),
        ]
        reduction = (
            " Not probed: whether prompt logic runs only on an explicit prompts/get, "
            "and whether each invocation records the prompt name."
        )
        truncated = (raw.get("result") or {}).get("nextCursor")
        scope = (
            " The raw prompts/list reply carried a nextCursor, so a later page is "
            "unexamined."
            if truncated
            else " The raw prompts/list reply carried no nextCursor, so the prompt "
            "inventory is complete."
        )
        verdict, evidence, legs = _aggregate(results, caveat=scope + reduction)
        return getattr(self, f"_{verdict}")(evidence, legs=legs)


def _revision_gate(rc_supported: bool, rc_version: str | None) -> str:
    """Whether 5.2.3's probes may run, and if not, which verdict says so.

    rc_supported is False both when the server named an older revision and when our
    raw initialize never got an answer -- a 401, an unparseable SSE body, a timeout.
    Only the first is a property of the server, so only it earns NO-REV.
    """
    if rc_supported:
        return "run"
    if rc_version:
        return "no-rev"
    return "unknown"


def _status_outcome(status: int | None) -> tuple[str, str]:
    """Classify a GET or DELETE status against the required 405."""
    if status is None:
        return "error", "no status returned, so the result is not attributable"
    if status == 405:
        return "pass", "405, no legacy surface exposed"
    if 200 <= status < 300:
        return "fail", f"{status} served, the legacy surface is exposed"
    return "pass", f"{status}, a rejection but a deviation from the recommended 405"


def _tools_list_body(req_id: int) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "method": "tools/list", "params": {}}


def _is_tools_result(data: dict | None) -> bool:
    return isinstance((data or {}).get("result"), dict) and "tools" in data["result"]


@register
class LegacySessionSurfaceDisabled(Check):
    """5.2.3, Assessment Status: Automated.

    Valid only for 2026-07-28: under an older revision a server is supposed to mint
    Mcp-Session-Id and serve a standalone GET, so failing it would be wrong. Gated on
    ctx.rc_supported rather than the session's negotiated version, because removal of
    the legacy surface is a property of the endpoint rather than of one session.

    Every leg pins MCP-Protocol-Version. A server supporting both revisions would
    otherwise answer header-less requests under legacy semantics, correctly, and earn
    a fail it did not deserve.

    Not probed: whether a streamed response is scoped to its originating request. The
    recommendation assigns that half to configuration review.
    """

    id = "5.2.3"
    title = "Legacy Streamable HTTP session and stream-resumption are disabled"
    section = "5"
    level = Level.L1
    remediation = (
        "Under 2026-07-28, answer a standalone GET or DELETE on the MCP endpoint with "
        "405, ignore Last-Event-ID, and neither mint nor echo Mcp-Session-Id."
    )

    async def run(self, ctx: ProbeContext) -> CheckResult:
        gate = _revision_gate(ctx.rc_supported, ctx.rc_negotiated_version)
        if gate == "no-rev":
            return self._revision_unsupported(
                f"this check is valid only for {RC_VERSION}; the server negotiated "
                f"{ctx.rc_negotiated_version}. No probe was sent."
            )
        if gate == "unknown":
            return self._unknown(
                f"the raw initialize offering {RC_VERSION} never returned a version, "
                "so the server's revision is unmeasured and its legacy surface cannot "
                "be graded. No probe was sent."
            )

        endpoint = ctx.endpoint_url or ""
        pinned = {"MCP-Protocol-Version": RC_VERSION}
        results = []

        get_status, _h, _t, _e = await raw_endpoint_request(
            "GET",
            endpoint,
            extra_headers={**pinned, "Accept": "text/event-stream"},
            token=ctx.access_token,
        )
        outcome, note = _status_outcome(get_status)
        results.append(("5.2.3a", outcome, f"standalone GET: {note}"))

        # No Mcp-Session-Id: a DELETE carrying it would end the live session and
        # starve every check registered after this one.
        del_status, _h, _t, _e = await raw_endpoint_request(
            "DELETE", endpoint, extra_headers=pinned, token=ctx.access_token
        )
        outcome, note = _status_outcome(del_status)
        results.append(("5.2.3b", outcome, f"DELETE: {note}"))

        _s, control, _t = await raw_jsonrpc(
            endpoint,
            _tools_list_body(1),
            token=ctx.access_token,
            protocol_header=RC_VERSION,
        )
        _s, resumed, _t = await raw_jsonrpc(
            endpoint,
            _tools_list_body(2),
            token=ctx.access_token,
            protocol_header=RC_VERSION,
            extra_headers={"Last-Event-ID": "1"},
        )
        if not _is_tools_result(control):
            results.append(
                ("5.2.3c", "unknown", "the control tools/list returned no tools result")
            )
        elif _is_tools_result(resumed):
            results.append(
                (
                    "5.2.3c",
                    "pass",
                    (
                        "a Last-Event-ID request was served identically to the control. "
                        "Near-vacuous: resumption changes stream replay rather than "
                        "whether a POST returns a result, so a resumption-supporting "
                        "server also passes this leg"
                    ),
                )
            )
        else:
            results.append(
                ("5.2.3c", "fail", "the Last-Event-ID request was handled differently")
            )

        _s, c_data, _t, c_head = await raw_jsonrpc_headers(
            endpoint,
            _tools_list_body(3),
            token=ctx.access_token,
            protocol_header=RC_VERSION,
        )
        _s, s_data, _t, s_head = await raw_jsonrpc_headers(
            endpoint,
            _tools_list_body(4),
            token=ctx.access_token,
            protocol_header=RC_VERSION,
            extra_headers={"Mcp-Session-Id": "cis-audit-supplied-000"},
        )
        # The response headers, not ctx.session_id: that field cannot tell a header
        # the server minted from one the transport carried.
        minted = [h for h in (c_head, s_head) if "mcp-session-id" in h]
        if minted:
            results.append(
                (
                    "5.2.3d",
                    "fail",
                    "the server minted or echoed an Mcp-Session-Id header",
                )
            )
        elif _is_tools_result(s_data):
            results.append(
                (
                    "5.2.3d",
                    "pass",
                    (
                        "no Mcp-Session-Id was minted or echoed, and the request supplying "
                        "one was still served normally"
                    ),
                )
            )
        else:
            results.append(
                (
                    "5.2.3d",
                    "unknown",
                    (
                        "no Mcp-Session-Id was minted, but the request supplying one was "
                        "not served normally, so the header was not shown to be ignored"
                    ),
                )
            )

        reduction = (
            " Not probed: whether a streamed response is scoped to its originating "
            "authenticated request, which needs a second identity."
        )
        verdict, evidence, legs = _aggregate(results, caveat=reduction)
        return getattr(self, f"_{verdict}")(evidence, legs=legs)


# What a returned body must look like to establish escape. The root is not
# observable from the wire, so a comparison of two responses cannot answer "did this
# escape?" -- aiming at a known-outside target is what makes a body attributable.
_OUT_OF_ROOT_TARGET = "etc/passwd"
_TARGET_MARKERS = ("root:", "/bin/", "/usr/bin/", "nologin")


def _traversal_uri(control: str) -> tuple[str | None, str]:
    """A traversal aimed at a target outside any plausible root, or None and why.

    Built by concatenation only. AnyUrl and urljoin both apply RFC 3986 dot-segment
    removal, so either would strip the ../ before the request left and silently turn
    this into a different test that a non-conformant server passes.
    """
    scheme, sep, rest = control.partition("://")
    if not sep or "/" not in rest:
        return None, "the control URI has no path segments, so no target is outside it"
    depth = rest.count("/") + 2
    return f"{scheme}://{rest.rstrip('/')}/" + "../" * depth + _OUT_OF_ROOT_TARGET, ""


def _traversal_outcome(contents: bool, matches_target: bool) -> tuple[str, str]:
    """Classify the traversal read. Contents alone is not the finding."""
    if not contents:
        return "pass", "the traversal read returned no contents"
    if matches_target:
        return "fail", "the traversal read returned the out-of-root target's contents"
    return "unknown", (
        "the traversal read returned contents that are not the out-of-root target, "
        "which is what dot-segment removal to an in-root resource produces"
    )


def _looks_like_target(data: dict | None) -> bool:
    """Whether a resources/read result carries the out-of-root target's content."""
    contents = ((data or {}).get("result") or {}).get("contents") or []
    text = " ".join(str(c.get("text", "")) for c in contents if isinstance(c, dict))
    return any(marker in text for marker in _TARGET_MARKERS)


@register
class PathTraversalPrevented(Check):
    """5.4.1, Assessment Status: Automated.

    Only the ../ path is probed. The symlink path is guarded independently, and
    staging one is filesystem write access on the server host -- so a pass here says
    nothing about it. Applying the same probe to every path-taking tool is excluded
    on side-effect grounds rather than reach: it would mean calling an arbitrary tool
    surface with traversal values.
    """

    id = "5.4.1"
    title = "Path traversal and arbitrary filesystem access are prevented"
    section = "5"
    level = Level.L1
    remediation = (
        "Canonicalize every supplied path before any access check, comparing by path "
        "component rather than by string prefix, and guard the symlink path "
        "independently of the ../ path."
    )

    async def run(self, ctx: ProbeContext) -> CheckResult:
        reduction = (
            " Not probed: the symlink path, which needs filesystem write access on "
            "the server, and it is guarded independently of the ../ path so this says "
            "nothing about it. Excluded on side-effect grounds rather than reach: "
            "applying the same probe to every path-taking tool."
        )
        if ctx.session is None:
            return self._error("no live session to read through" + reduction)

        control = inputs.load(ctx.domain).get("traversal_control_uri")
        source = "operator-supplied"
        if not control and ctx.resources:
            control, source = str(ctx.resources[0].uri), "derived from ctx.resources[0]"
        if not control:
            return self._unknown(
                "no traversal_control_uri for this domain and the server advertises no "
                "resource, so no positive control exists and no read was sent."
                + reduction,
                legs={"5.4.1a": "unknown"},
            )

        traversal, why = _traversal_uri(control)
        if traversal is None:
            return self._pass(
                f"the control URI {control!r} ({source}) {why}, so nothing was escaped "
                "and no traversal was sent." + reduction,
                legs={"5.4.1a": "pass"},
            )

        control_data, _payload = await _read_uri(ctx, 1, control)
        if not ((control_data or {}).get("result") or {}).get("contents"):
            return self._unknown(
                f"the positive-control read of {control!r} ({source}) returned no "
                "contents, so a traversal denial could not be attributed to path "
                "confinement." + reduction,
                legs={"5.4.1a": "unknown"},
            )

        data, payload = await _read_uri(ctx, 2, traversal)
        contents = bool(((data or {}).get("result") or {}).get("contents"))
        outcome, note = _traversal_outcome(contents, _looks_like_target(data))
        # Rendered from the payload dict that went on the wire, so the evidence
        # cannot disagree with what was actually sent.
        evidence = (
            f"control {control!r} ({source}) returned contents; reading "
            f"{payload['params']['uri']!r}: {note}"
        )
        verdict, evidence, legs = _aggregate(
            [("5.4.1a", outcome, evidence)], caveat=reduction
        )
        return getattr(self, f"_{verdict}")(evidence, legs=legs)
