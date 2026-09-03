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
