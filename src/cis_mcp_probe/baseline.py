"""Per-server capability baseline storage for check 1.2.

The benchmark's 1.2 audit compares a server's advertised capabilities against a
baseline held in an enterprise registry. We don't have that registry when we're
probing an arbitrary server, so instead we establish our own baseline: the first
time we see an MCP URL we record what it advertises, and on later runs we flag
anything new as drift. Refresh the baseline explicitly with --update-baseline.

The baseline captures the top-level capability categories (tools, resources,
prompts, ...) and the concrete tool / resource / prompt names, so we catch both
"a whole new capability appeared" and "a new tool showed up". It also records the
granted OAuth scopes and the advertised authorization servers, which other checks
compare through ``compare_category`` rather than through ``diff``.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .context import ProbeContext
from .tokens import jwt_claims, observed_scopes

DATA_DIR = Path.home() / ".cis-mcp-probe" / "baselines"


def _path(endpoint: str) -> Path:
    key = hashlib.sha256(endpoint.encode()).hexdigest()[:16]
    return DATA_DIR / f"{key}.json"


def snapshot(ctx: ProbeContext) -> dict[str, Any]:
    """Build a baseline record from what the server currently advertises.

    ``scopes`` and ``authorization_servers`` are None -- not [] -- when the run
    could not observe them at all. [] means "observed, and carries nothing", so a
    capture taken while authentication failed would otherwise make every scope
    look new next run.

    Which is which, per category:

    * ``scopes`` -- None when no source stated a scope, [] when one stated an
      empty set. ``observed_scopes`` owns that distinction.
    * ``authorization_servers`` -- None only when no protected-resource document
      was read at all. A document that answered and advertises none is an
      observed absence, so it records [], which is the same rule leg 3.3.4f applies
      to ``scopes_supported`` in the same document.
    """
    caps = ctx.init_result.capabilities if ctx.init_result else None
    capability_keys = sorted(caps.model_dump(exclude_none=True).keys()) if caps else []
    claims = jwt_claims(ctx.access_token or "")
    return {
        "endpoint": ctx.endpoint_url,
        "capability_keys": capability_keys,
        "tools": sorted(t.name for t in ctx.tools),
        "resources": sorted(str(r.uri) for r in ctx.resources),
        "prompts": sorted(p.name for p in ctx.prompts),
        "scopes": observed_scopes(ctx.token_scope, claims),
        # None only when no document was read at all; a document advertising none
        # is an observed absence and records [].
        "authorization_servers": (
            sorted(ctx.advertised_authorization_servers) if ctx.prm_documents else None
        ),
    }


def load(endpoint: str) -> dict[str, Any] | None:
    p = _path(endpoint)
    if p.exists():
        return json.loads(p.read_text())
    return None


def save(endpoint: str, data: dict[str, Any]) -> Path:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    p = _path(endpoint)
    p.write_text(json.dumps(data, indent=2))
    return p


def diff(baseline: dict[str, Any], current: dict[str, Any]) -> dict[str, list[str]]:
    """Return, per category, the capability items present now but not recorded.

    Covers the four capability categories check 1.2 reports as drift, and only
    those. ``or []`` rather than a ``.get`` default because a stored None is
    returned as-is by ``.get``, and ``set(None)`` raises.
    """
    added: dict[str, list[str]] = {}
    for key in ("capability_keys", "tools", "resources", "prompts"):
        base_set = set(baseline.get(key) or [])
        new_items = [x for x in current.get(key) or [] if x not in base_set]
        if new_items:
            added[key] = new_items
    return added


def compare_category(
    record: dict[str, Any], current: dict[str, Any], key: str
) -> tuple[list[str], str | None]:
    """Compare one category, reporting which side could not decide it.

    Returns ``(added, missing_in)``. ``missing_in`` is None when both sides carry
    a value for ``key``; ``"record"`` when the stored record does not -- the key
    is absent, or stored as None; ``"current"`` when this run did not observe the
    category at all. In both of the latter cases ``added`` is empty.

    A comparison needs two observed sides. A record from before the category was
    captured is not evidence that anything grew, and neither is a run that read
    nothing: reading an absent observation as an empty set would report "nothing
    was added" and pass, on a run that compared nothing at all.

    ``None`` and ``[]`` are different on both sides, which is the distinction
    ``snapshot`` records deliberately: ``[]`` was observed and carries nothing, so
    it decides.
    """
    recorded = record.get(key)
    if recorded is None:
        return [], "record"
    observed = current.get(key)
    if observed is None:
        return [], "current"
    base_set = set(recorded)
    return [x for x in observed if x not in base_set], None
