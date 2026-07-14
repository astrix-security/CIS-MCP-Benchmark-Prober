"""Per-server capability baseline storage for check 1.2.

The benchmark's 1.2 audit compares a server's advertised capabilities against a
baseline held in an enterprise registry. We don't have that registry when we're
probing an arbitrary server, so instead we establish our own baseline: the first
time we see an MCP URL we record what it advertises, and on later runs we flag
anything new as drift. Refresh the baseline explicitly with --update-baseline.

The baseline captures both the top-level capability categories (tools,
resources, prompts, ...) and the concrete tool / resource / prompt names, so we
catch both "a whole new capability appeared" and "a new tool showed up".
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .context import ProbeContext

DATA_DIR = Path.home() / ".cis-mcp-probe" / "baselines"


def _path(endpoint: str) -> Path:
    key = hashlib.sha256(endpoint.encode()).hexdigest()[:16]
    return DATA_DIR / f"{key}.json"


def snapshot(ctx: ProbeContext) -> dict[str, Any]:
    """Build a baseline record from what the server currently advertises."""
    caps = ctx.init_result.capabilities if ctx.init_result else None
    capability_keys = (
        sorted(caps.model_dump(exclude_none=True).keys()) if caps else []
    )
    return {
        "endpoint": ctx.endpoint_url,
        "capability_keys": capability_keys,
        "tools": sorted(t.name for t in ctx.tools),
        "resources": sorted(str(r.uri) for r in ctx.resources),
        "prompts": sorted(p.name for p in ctx.prompts),
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
    """Return, per category, the items present now but not in the baseline."""
    added: dict[str, list[str]] = {}
    for key in ("capability_keys", "tools", "resources", "prompts"):
        base_set = set(baseline.get(key, []))
        new_items = [x for x in current.get(key, []) if x not in base_set]
        if new_items:
            added[key] = new_items
    return added
