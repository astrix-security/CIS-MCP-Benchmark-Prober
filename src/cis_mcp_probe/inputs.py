"""Operator-supplied per-domain inputs for legs 3.3.1c, 3.3.4e, 10.1a, 10.1b and 10.2a.

Each leg needs something no black-box probe can derive: a downstream resource API
to present our token to, a tool to call for a scope-enforcement probe, a path to a
static or a per-user resource, and the request-body limit a deployment enforces. The
file is optional, and a check with no entry records ``unknown`` for that leg
rather than being gated on the file.

Keyed by the domain the operator typed, not by endpoint URL, because
``_detect_endpoint`` has not run when this is read. That is why the shape differs
from ``storage.py`` and ``baseline.py``, which both hash a resolved endpoint URL.

The Section 10 keys are not all alike, and only the first is a missing input:

* ``static_resource_path`` — leg 10.1a reads the cache headers of one static
  resource. There is no way to discover such a path: MCP defines no HTTP static
  asset, and ``resources/list`` returns protocol-layer URIs rather than files. So
  the leg records ``unknown`` until an operator names one, and the notice says so.
* ``per_user_resource_path`` — an override, not a missing input. Leg 10.1b grades
  the MCP endpoint's own response as dynamic content when this is absent, so it
  reaches a verdict either way. The notice never names it.
* ``max_request_bytes`` — the limit the deployment enforces. Its only effects are to
  change leg 10.2a's probe size and to make that leg's ``fail`` branch available at
  all. Absent, the leg still probes at ``DEFAULT_PROBE_BYTES`` and can reach
  ``pass``, so the notice never names it either.
* ``oversize_authorised`` — needed only to set ``max_request_bytes`` above
  ``DEFAULT_PROBE_BYTES``. Meaningless on its own.

These differ from ``scope_probe_tool``, whose contract is the inverse: that names a
tool the probe expects the server to **refuse**, so the leg fails when the call
succeeds. Every Section 10 key names something the probe expects to work, and a leg
reads the response rather than the refusal.

Shape of ``~/.cis-mcp-probe/probe-inputs.json``:

    { "mcp.example.com": {
        "scope_probe_tool": "<name>",
        "scope_probe_arguments": {},
        "downstream_endpoints": ["https://api.example.com/me"],
        "static_resource_path": "/static/app.js",
        "per_user_resource_path": "/api/me",
        "max_request_bytes": 1048576,
        "oversize_authorised": false } }
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PATH = Path.home() / ".cis-mcp-probe" / "probe-inputs.json"

# Leg 10.2a's probe size, in bytes. The default matches the recommendation's own
# nginx illustration, ``client_max_body_size 1m``, and the common reverse-proxy
# default. At that size the request is ordinary traffic that a large tool argument
# could reach, so it needs no separate authorisation from the target's owner.
DEFAULT_PROBE_BYTES = 1048576  # 1 MiB

# The hard bound on the probe SIZE an operator may state, ten times the default. Not
# a bound on the bytes that reach the wire: the caller pads one byte past this and
# wraps the padding in a JSON-RPC envelope, so the body exceeds the value by a couple
# of hundred bytes. Every leg quotes the length it actually sent.
#
# It admits the largest limit a real deployment configures -- an API gateway
# commonly caps a payload around 10 MB -- and refuses the shapes a typo produces: a
# limit stated in bits, or one carrying an extra digit. Above it the binding
# constraint stops being the server's limit and becomes the probe's own 30-second
# request timeout, so the upload would not finish and the leg would spend the bytes
# having decided nothing. That is why the ceiling is hard rather than a matter of
# authorisation.
ABSOLUTE_CEILING = 10485760  # 10 MiB


def _load_file(path: Path) -> dict:
    """Return the whole parsed document, or {} on a missing or unusable file.

    An absent file is the normal case and stays silent. Only a file that exists
    and cannot be used warrants a warning.
    """
    if not path.exists():
        return {}
    try:
        doc = json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        print(f"warning: could not read {path}: {exc}", file=sys.stderr)
        return {}
    if not isinstance(doc, dict):
        # A list or a bare value parses, so it needs its own warning: the
        # no-entry-for-this-domain message misdescribes content in the wrong shape.
        print(
            f"warning: {path} holds a {type(doc).__name__}, not an object keyed "
            "by domain; treating it as absent",
            file=sys.stderr,
        )
        return {}
    return doc


def load(domain: str) -> dict:
    """Return the operator entry for ``domain``, or {} when absent or malformed."""
    entry = _load_file(PATH).get(domain)
    return entry if isinstance(entry, dict) else {}


def resource_path(entry: dict, key: str) -> str | None:
    """Return ``entry[key]`` as a trimmed path or absolute URL, else None.

    Legs 10.1a and 10.1b each take one of these. A value that is not a non-empty
    string is treated as absent, so no leg builds a URL out of an int or a list.
    """
    value = entry.get(key)
    if not isinstance(value, str):
        return None
    return value.strip() or None


def probe_body_size(entry: dict) -> tuple[int | None, int | None, str | None]:
    """Resolve leg 10.2a's probe size, returning (bytes, stated_limit, rejection).

    ``stated_limit`` is the operator's ``max_request_bytes``, and is None when they
    stated none. The leg reads it to know whether ``fail`` is available at all: a 2xx
    to an oversized body proves only that no limit sits at or below the size sent,
    which is not the same claim as no limit at all.

    ``rejection`` is set exactly when the first member is None, and the leg then
    reports ``unknown`` naming it and sends nothing. The first member is None rather
    than 0 on a rejection so that a caller which ignored the reason cannot send a
    body at all.

    An absent value is not a rejection: the leg proceeds at ``DEFAULT_PROBE_BYTES``.
    A value that is stated but unusable is never quietly replaced by the default,
    because the operator meant to configure something.
    """
    stated = entry.get("max_request_bytes")
    if stated is None:
        return DEFAULT_PROBE_BYTES, None, None
    # ``isinstance(True, int)`` is True in Python, so bool is excluded first: a
    # ``max_request_bytes`` of ``true`` is a malformed entry, not a size of 1.
    if isinstance(stated, bool) or not isinstance(stated, int) or stated <= 0:
        reason = f"max_request_bytes is {stated!r}, not an integer above zero"
        return None, None, reason
    if stated > ABSOLUTE_CEILING:
        reason = (
            f"max_request_bytes is {stated}, above the {ABSOLUTE_CEILING}-byte "
            "ceiling, which is absolute: no authorisation raises it"
        )
        return None, None, reason
    authorised = entry.get("oversize_authorised")
    # Only the JSON boolean true authorises: a string like "false", or a number,
    # is truthy in Python but is not the operator's consent, so it is treated the
    # same as an absent key rather than silently accepted.
    if stated > DEFAULT_PROBE_BYTES and authorised is not True:
        if authorised is None:
            detail = "oversize_authorised is not set"
        else:
            detail = f"oversize_authorised is {authorised!r}, not the JSON boolean true"
        reason = (
            f"max_request_bytes is {stated}, above the {DEFAULT_PROBE_BYTES}-byte "
            f"default, and {detail}"
        )
        return None, None, reason
    return stated, stated, None


def missing_input_notice(domain: str, entry: dict) -> str | None:
    """Name which checks will record `unknown` on `domain` for want of an input."""
    missing = []
    if not entry.get("downstream_endpoints"):
        missing.append("3.3.1c (no downstream_endpoints)")
    if not entry.get("scope_probe_tool"):
        missing.append("3.3.4e (no scope_probe_tool)")
    # Only 10.1a. Leg 10.1b grades the endpoint's own response without its path, and
    # leg 10.2a probes at the default without a stated limit, so neither is unknown
    # for want of an input and this sentence would misdescribe both.
    if not entry.get("static_resource_path"):
        missing.append("10.1a (no static_resource_path)")
    if not missing:
        return None
    return (
        f"probe-inputs.json has no entry (or an incomplete one) for {domain!r}: "
        f"{'; '.join(missing)} will record unknown. See {PATH}."
    )
