"""Per-server capability baseline storage for check 1.2.

The benchmark's 1.2 audit compares a server's advertised capabilities against a
baseline held in an enterprise registry. We don't have that registry when we're
probing an arbitrary server, so instead we establish our own baseline: the first
time we see an MCP URL we record what it advertises, and on later runs we flag
anything new as drift. Refresh the baseline explicitly with --update-baseline.

The baseline captures the capability configuration down to every nested leaf, so a
setting that changes value without any name changing is drift. ``resources.subscribe``
flipping from false to true is the case a name-level comparison cannot see. It also
keeps the top-level categories and the concrete tool / resource / prompt names, the
granted OAuth scopes, the advertised authorization servers, and the server's asserted
identity. Those five are compared through ``compare_category`` or ``diff`` rather than
through ``compare_leaves``.
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


def capability_leaves(obj: Any, path: tuple[str, ...] = ()) -> dict[str, Any]:
    """Flatten a capability object to one entry per leaf, keyed by its path.

    A leaf is a scalar, an empty object or an empty array -- the same three the
    benchmark's own audit flattens to. An empty object is a leaf rather than an
    absence, so a server advertising ``experimental: {}`` records that it advertises
    the category and nothing under it.

    A populated object recurses by key and a populated array by index. Indices make
    a reordered array read as changed, which is correct here: the audit compares
    values at paths, and it cannot know that an order change is harmless.

    The key is the path as a JSON array, which is what the audit's own expression
    produces. Joining the segments with a separator instead would collide, because a
    capability key may contain the separator: ``experimental`` sub-keys are
    server-chosen and reverse-DNS names are common there, so
    ``{"experimental": {"com.vendor.f": 1}}`` and
    ``{"experimental": {"com": {"vendor": {"f": 1}}}}`` would flatten alike and a
    server restructuring one into the other would report no drift.

    The whole object being empty is the one case that yields no leaves at all, rather
    than one leaf under the empty path. The audit walks the paths inside the
    capabilities object, so a server advertising nothing has no paths to compare, and
    recording one would make the next run report it as withdrawn.
    """
    if not path and isinstance(obj, (dict, list)) and not obj:
        return {}
    if isinstance(obj, dict) and obj:
        out: dict[str, Any] = {}
        for key, value in obj.items():
            out.update(capability_leaves(value, (*path, str(key))))
        return out
    if isinstance(obj, list) and obj:
        out = {}
        for index, value in enumerate(obj):
            out.update(capability_leaves(value, (*path, str(index))))
        return out
    return {json.dumps(list(path)): obj}


def render_leaf(key: str) -> str:
    """A leaf key as a reader sees it in an evidence string.

    The stored key is a JSON array so that it cannot collide. An operator reading a
    verdict wants ``resources.subscribe``, so the dotted form is produced here and
    only here, and it is never compared.
    """
    try:
        return ".".join(json.loads(key)) or "(root)"
    except (ValueError, TypeError):
        return key


def _identity_pair(server_info: Any) -> list[str] | None:
    """The server's asserted identity as one ``name|version`` entry, or None.

    None -- not [] -- when nothing was asserted, because [] would read as an
    observed empty set and make the next run's comparison decide on nothing. The
    delimiter matches the registry export format the benchmark's audit compares.

    Accepts either shape the identity arrives in: the session's ``initialize`` result
    carries a model with attributes, and a ``server/discover`` result carries the raw
    JSON object from ``_meta``.
    """
    if server_info is None:
        return None
    if isinstance(server_info, dict):
        name, version = server_info.get("name"), server_info.get("version")
    else:
        name, version = (
            getattr(server_info, "name", None),
            getattr(server_info, "version", None),
        )
    name = (name or "").strip() if isinstance(name, str) else ""
    if not name:
        return None
    version = (version or "").strip() if isinstance(version, str) else ""
    return [f"{name}|{version}"]


def snapshot(
    ctx: ProbeContext,
    *,
    capabilities: dict[str, Any] | None = None,
    substrate: str | None = None,
    server_info: Any = None,
) -> dict[str, Any]:
    """Build a baseline record from what the server currently advertises.

    ``capabilities``, ``substrate`` and ``server_info`` are optional. Omitted, they
    are read from the session's ``initialize`` result and the substrate records
    ``initialize``. Passed in, they let a caller record the object ``server/discover``
    returned, which is a different object under 2026-07-28 and is why the substrate
    is recorded beside it: comparing leaves across two substrates is not drift.

    ``scopes``, ``authorization_servers`` and ``server_identity`` are None -- not [] --
    when the run could not observe them at all. [] means "observed, and carries
    nothing", so a capture taken while authentication failed would otherwise make
    every scope look new next run.

    Which is which, per category:

    * ``scopes`` -- None when no source stated a scope, [] when one stated an
      empty set. ``observed_scopes`` owns that distinction.
    * ``authorization_servers`` -- None only when no protected-resource document
      was read at all. A document that answered and advertises none is an
      observed absence, so it records [], which is the same rule leg 3.3.4f applies
      to ``scopes_supported`` in the same document.
    * ``server_identity`` -- None when the server asserted no name.
    """
    if capabilities is not None and substrate is None:
        raise ValueError(
            "snapshot() requires substrate when capabilities is given explicitly"
        )
    if capabilities is None:
        caps = ctx.init_result.capabilities if ctx.init_result else None
        capabilities = caps.model_dump(exclude_none=True) if caps else {}
        substrate = substrate or "initialize"
    if server_info is None and ctx.init_result is not None:
        server_info = getattr(ctx.init_result, "serverInfo", None)
    claims = jwt_claims(ctx.access_token or "")
    return {
        "endpoint": ctx.endpoint_url,
        "capability_keys": sorted(capabilities.keys()),
        "capability_leaves": capability_leaves(capabilities),
        "capability_substrate": substrate,
        "server_identity": _identity_pair(server_info),
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


def _json_array_keys(leaves: dict[str, Any]) -> bool:
    """Whether every key is a JSON array, which is the current leaf-key format."""
    for key in leaves:
        try:
            if not isinstance(json.loads(key), list):
                return False
        except (ValueError, TypeError):
            return False
    return True


def compare_leaves(
    record: dict[str, Any], current: dict[str, Any]
) -> tuple[dict[str, list[str]], str | None]:
    """Compare capability leaves, reporting which side could not decide.

    Returns ``(changes, undecidable)``. ``changes`` holds three sorted lists:

    * ``added`` -- a leaf advertised now and not recorded.
    * ``changed`` -- a leaf in both whose value differs.
    * ``withdrawn`` -- a leaf recorded and no longer advertised.

    ``undecidable`` is None when the comparison decided, otherwise the reason it did
    not, and ``changes`` is then empty rather than partial:

    * ``"record"`` -- the stored record predates leaf capture, so it holds no leaves.
      Reading its absence as an empty set would report every advertised leaf as added.
    * ``"substrate"`` -- the two sides were read from different objects. Nearly every
      leaf would read as added or changed on the first run after a server adopts
      2026-07-28, which is not drift.
    * ``"current"`` -- this run observed no capability object at all.

    The caller decides the verdict. Total withdrawal -- everything recorded gone and
    nothing advertised -- is a decided comparison and reported as such, because
    whether that means a reconfiguration or a read that returned nothing is the
    check's call, not this function's.
    """
    empty: dict[str, list[str]] = {"added": [], "changed": [], "withdrawn": []}
    recorded = record.get("capability_leaves")
    if recorded is None or not _json_array_keys(recorded):
        # A record with no leaves, or with leaves keyed in the earlier dotted format,
        # cannot be compared. Reading a format change as drift would report every
        # leaf as both added and withdrawn, and fail a server that changed nothing.
        return empty, "record"
    observed = current.get("capability_leaves")
    if observed is None:
        return empty, "current"
    if record.get("capability_substrate") != current.get("capability_substrate"):
        return empty, "substrate"
    return {
        "added": sorted(k for k in observed if k not in recorded),
        "changed": sorted(k for k in observed if k in recorded and observed[k] != recorded[k]),
        "withdrawn": sorted(k for k in recorded if k not in observed),
    }, None


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
