"""Operator-supplied per-domain inputs for checks that need one to run at all.

Two Section 3 legs need something no black-box probe can derive on its own:
3.5c needs a downstream resource API to test our token against, and 3.8e needs
a tool name to call for a scope-enforcement probe. Both are optional — the
checks always run and record ``unknown`` for the missing leg rather than being
gated on this file's presence.

The file is keyed by the domain string the operator typed on the command
line, not by endpoint URL: the endpoint URL doesn't exist yet at the point
this is read (``_detect_endpoint`` hasn't run), so it can't be the key. This
is why the shape below differs from ``storage.py`` and ``baseline.py``, which
both hash a resolved endpoint URL into a filename.

Shape of ``~/.cis-mcp-probe/probe-inputs.json``:

    { "mcp.example.com": {
        "scope_probe_tool": "<name>",
        "scope_probe_arguments": {},
        "downstream_endpoints": ["https://api.example.com/me"] } }

Recognised keys inside a domain entry: ``scope_probe_tool`` (str),
``scope_probe_arguments`` (dict), ``downstream_endpoints`` (list of str).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PATH = Path.home() / ".cis-mcp-probe" / "probe-inputs.json"


def _load_file(path: Path) -> dict:
    """Return the whole parsed document, or {} on a missing, unreadable or invalid file.

    An absent file is the normal case and is silent: the file is optional, and the
    checks that consume it record ``unknown`` on their own. Only a file that exists
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
        # A file holding a list or a bare value parses, so it reaches here rather
        # than the warning above. Say so, because the alternative message the
        # checks print -- no entry for this domain -- misdescribes a file that
        # has content in the wrong shape.
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
        missing.append("3.5c (no downstream_endpoints)")
    if not entry.get("scope_probe_tool"):
        missing.append("3.8e (no scope_probe_tool)")
    if not missing:
        return None
    return (
        f"probe-inputs.json has no entry (or an incomplete one) for {domain!r}: "
        f"{'; '.join(missing)} will record unknown. See {PATH}."
    )


if __name__ == "__main__":
    import json as _json, tempfile, pathlib

    # an absent input names both dependent legs, and names the domain
    note = missing_input_notice("mcp.example.com", {})
    assert note is not None, note
    assert "3.5c" in note and "3.8e" in note and "mcp.example.com" in note, note
    # a complete entry produces no notice
    assert (
        missing_input_notice(
            "h", {"scope_probe_tool": "t", "downstream_endpoints": ["https://api.h/me"]}
        )
        is None
    )
    # a partial entry names only the missing leg
    partial = missing_input_notice("h", {"scope_probe_tool": "t"})
    assert partial is not None and "3.5c" in partial and "3.8e" not in partial, partial
    # a malformed file is treated as absent, not fatal
    with tempfile.TemporaryDirectory() as d:
        p = pathlib.Path(d) / "probe-inputs.json"
        p.write_text("{not json")
        assert _load_file(p) == {}
        # valid JSON that isn't an object is also treated as absent
        for body in ("[]", '"x"', "123", "null"):
            p.write_text(body)
            assert _load_file(p) == {}, body
        # non-UTF-8 bytes are also treated as absent
        p.write_bytes(b'\xff\xfe{"a":1}')
        assert _load_file(p) == {}
        p.write_text(_json.dumps({"h": {"scope_probe_tool": "t"}}))
        assert _load_file(p)["h"]["scope_probe_tool"] == "t"
    print("inputs: all self-checks passed")
