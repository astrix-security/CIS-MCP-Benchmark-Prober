"""Operator-supplied per-domain inputs for legs 3.3.1c, 3.3.4e, 5.1.1d and 5.4.1a.

Each leg needs something no black-box probe can derive: a downstream resource API
to present our token to, a tool to call for a scope-enforcement probe, a tool to
call with schema-violating arguments, and a resource URI that reads successfully
so a traversal denial can be attributed. The file is optional, and a check with no
entry records ``unknown`` for that leg rather than being gated on the file.

Keyed by the domain the operator typed, not by endpoint URL, because
``_detect_endpoint`` has not run when this is read. That is why the shape differs
from ``storage.py`` and ``baseline.py``, which both hash a resolved endpoint URL.

Shape of ``~/.cis-mcp-probe/probe-inputs.json``:

    { "mcp.example.com": {
        "scope_probe_tool": "<name>",
        "scope_probe_arguments": {},
        "downstream_endpoints": ["https://api.example.com/me"],
        "schema_probe_tool": "<name>",
        "schema_probe_arguments": {},
        "traversal_control_uri": "<uri>" } }

``schema_probe_arguments`` is required alongside ``schema_probe_tool``: leg 5.1.1d
removes one property from the operator's own argument object and never invents the
rest, so a tool named without arguments cannot be probed.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PATH = Path.home() / ".cis-mcp-probe" / "probe-inputs.json"


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


def missing_input_notice(domain: str, entry: dict) -> str | None:
    """Name which checks will record `unknown` on `domain` for want of an input."""
    missing = []
    if not entry.get("downstream_endpoints"):
        missing.append("3.3.1c (no downstream_endpoints)")
    if not entry.get("scope_probe_tool"):
        missing.append("3.3.4e (no scope_probe_tool)")
    if not entry.get("schema_probe_tool"):
        missing.append("5.1.1d (no schema_probe_tool)")
    elif not entry.get("schema_probe_arguments"):
        # A tool with no argument object cannot be probed: the leg removes one
        # property from what the operator supplied, and never invents the rest.
        missing.append("5.1.1d (no schema_probe_arguments)")
    if not entry.get("traversal_control_uri"):
        # Not "will record unknown": 5.4.1a falls back to the first advertised
        # resource and still sends a traversal probe. The notice is what an operator
        # actually reads before authorising a run against a third party.
        traversal_note = (
            "5.4.1a (no traversal_control_uri) will derive its control from the first "
            "advertised resource and still send a traversal probe"
        )
    else:
        traversal_note = ""
    if not missing and not traversal_note:
        return None
    parts = []
    if missing:
        parts.append(f"{'; '.join(missing)} will record unknown")
    if traversal_note:
        parts.append(traversal_note)
    return (
        f"probe-inputs.json has no entry (or an incomplete one) for {domain!r}: "
        f"{'. '.join(parts)}. See {PATH}."
    )
