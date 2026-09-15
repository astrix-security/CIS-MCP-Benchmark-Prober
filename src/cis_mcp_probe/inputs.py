"""Operator-supplied per-domain inputs for legs 1.3a, 3.3.1c and 3.3.4e.

Each needs something no black-box probe can derive: a downstream resource API to
present our token to, a tool to call for a scope-enforcement probe, and arguments
valid for a tool this probe invokes. The file is optional. A check with no entry
records ``unknown`` for that leg rather than being gated on the file, except leg
1.3a: its control probe must execute cleanly, so a control tool that requires
arguments and has none supplied makes that leg record an error instead.

Keyed by the domain the operator typed, not by endpoint URL, because
``_detect_endpoint`` has not run when this is read. That is why the shape differs
from ``storage.py`` and ``baseline.py``, which both hash a resolved endpoint URL.

Shape of ``~/.cis-mcp-probe/probe-inputs.json``:

    { "mcp.example.com": {
        "scope_probe_tool": "<name>",
        "scope_probe_arguments": {},
        "tool_arguments": {"<name>": {"<arg>": "<value>"}},
        "downstream_endpoints": ["https://api.example.com/me"] } }

``scope_probe_tool`` and ``tool_arguments`` are not interchangeable, and confusing
them inverts a verdict. ``scope_probe_tool`` names a tool the operator asserts is
outside the token's grant, and leg 3.3.4e fails when it executes. ``tool_arguments``
asserts nothing about authorization: it supplies arguments for a tool leg 1.3a chose
itself, so that a tool which needs arguments can be invoked at all. Leg 1.3a's control
probe must execute cleanly, which is the opposite of what 3.3.4e wants.
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


def tool_arguments(domain: str) -> dict[str, dict]:
    """Arguments the operator supplied per tool name, for a tool this probe invokes.

    Leg 1.3a invokes two tools it chose from the baseline, and a tool whose arguments
    are required returns an error indistinguishable from a gate denial when called
    with none. A map keyed by tool name rather than a named tool, because which tool
    is staged depends on what the baseline recorded and the operator cannot know it in
    advance.
    """
    supplied = load(domain).get("tool_arguments")
    if not isinstance(supplied, dict):
        return {}
    return {k: v for k, v in supplied.items() if isinstance(v, dict)}


def missing_input_notice(domain: str, entry: dict) -> str | None:
    """Name which checks are affected by a missing input for `domain`, and how."""
    missing = []
    if not entry.get("downstream_endpoints"):
        missing.append("3.3.1c (no downstream_endpoints) will record unknown")
    if not entry.get("scope_probe_tool"):
        missing.append("3.3.4e (no scope_probe_tool) will record unknown")
    if not entry.get("tool_arguments"):
        missing.append(
            "1.3a (no tool_arguments) will record an error, not unknown, if the "
            "tool it picks as a control requires arguments"
        )
    if not missing:
        return None
    return (
        f"probe-inputs.json has no entry (or an incomplete one) for {domain!r}: "
        f"{'; '.join(missing)}. See {PATH}."
    )
