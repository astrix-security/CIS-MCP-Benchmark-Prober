"""Rendering: turn probe runs across one or more live servers into a
**check-centric** report.

The goal is to validate the benchmark's checks against real MCP servers: for
each check, show which servers pass, fail, or don't apply. This helps the
benchmark authors see whether a check is sound and realistic (e.g. a check that
every server fails, or every server passes, may need rewording).

We deliberately do NOT compute a per-server L1/L2 "stamp" — the profile level is
kept only as metadata on each check for reference.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from .checks.base import CheckResult, Status
from .context import ProbeContext

_MARK = {
    Status.PASS: "PASS",
    Status.FAIL: "FAIL",
    Status.NOT_APPLICABLE: "N/A",
    Status.MANUAL: "MANUAL",
    Status.UNKNOWN: "UNKNOWN",
    Status.ERROR: "ERROR",
}

# Order statuses appear in the per-check breakdown.
_ORDER = [
    Status.PASS,
    Status.FAIL,
    Status.MANUAL,
    Status.UNKNOWN,
    Status.NOT_APPLICABLE,
    Status.ERROR,
]


@dataclass
class ProbeRun:
    """One server's probe: its context plus the results for every check."""

    ctx: ProbeContext
    results: list[CheckResult]


def _aggregate(runs: list[ProbeRun]) -> list[dict[str, Any]]:
    """Pivot per-server results into a per-check view."""
    checks: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for run in runs:
        for r in run.results:
            entry = checks.get(r.check_id)
            if entry is None:
                entry = {
                    "check_id": r.check_id,
                    "title": r.title,
                    "section": r.section,
                    "level": r.level.value,
                    "servers": {},  # domain -> CheckResult
                }
                checks[r.check_id] = entry
                order.append(r.check_id)
            entry["servers"][run.ctx.domain] = r
    return [checks[cid] for cid in sorted(order)]


def _counts(servers: dict[str, CheckResult]) -> dict[Status, list[str]]:
    buckets: dict[Status, list[str]] = {s: [] for s in _ORDER}
    for domain, r in servers.items():
        buckets[r.status].append(domain)
    return buckets


def render_servers_summary(runs: list[ProbeRun]) -> str:
    lines = ["=" * 72, f"Targets probed: {len(runs)}", "=" * 72]
    for run in runs:
        s = run.ctx.summary()
        si = s.get("server_info")
        name = f"{si['name']} {si.get('version') or ''}".strip() if si else "(no session)"
        reachable = "ok" if s["endpoint_url"] and s["server_info"] else "UNREACHABLE"
        ver = s.get("negotiated_version") or "?"
        rc = "RC-ready" if s.get("rc_supported") else "no-RC"
        lines.append(
            f"  {run.ctx.domain:28s} {reachable:11s} {name}"
            f"  [auth={s['auth_required']}, proto={ver}, {rc}]"
        )
        for e in s["errors"]:
            lines.append(f"      note: {e}")
    return "\n".join(lines)


def render_check_report(runs: list[ProbeRun]) -> str:
    agg = _aggregate(runs)
    if not agg:
        return "\n(no checks registered — connection/enumeration only)\n"

    lines = ["", "=" * 72, "Per-check validation across servers", "=" * 72]
    for entry in agg:
        servers: dict[str, CheckResult] = entry["servers"]
        buckets = _counts(servers)
        n_pass, n_fail = len(buckets[Status.PASS]), len(buckets[Status.FAIL])
        decidable = n_pass + n_fail
        rate = f"{n_pass}/{decidable} pass" if decidable else "no pass/fail decisions"

        lines.append("")
        lines.append(
            f"{entry['check_id']} ({entry['level']})  {entry['title']}   — {rate}"
        )
        for status in _ORDER:
            domains = buckets[status]
            if domains:
                lines.append(f"    {_MARK[status]:6s}: {', '.join(sorted(domains))}")
        # Show one representative evidence line per failing server for context.
        for domain in sorted(buckets[Status.FAIL]):
            ev = servers[domain].evidence
            if ev:
                lines.append(f"      · {domain}: {ev}")
    lines.append("")
    return "\n".join(lines)


def render_report(runs: list[ProbeRun]) -> str:
    return render_servers_summary(runs) + "\n" + render_check_report(runs)


def to_json(runs: list[ProbeRun]) -> str:
    agg = _aggregate(runs)
    checks_json = []
    for entry in agg:
        servers: dict[str, CheckResult] = entry["servers"]
        buckets = _counts(servers)
        checks_json.append(
            {
                "check_id": entry["check_id"],
                "title": entry["title"],
                "section": entry["section"],
                "level": entry["level"],
                "summary": {
                    _MARK[s].lower().replace("/", "a"): len(buckets[s]) for s in _ORDER
                },
                "servers": {
                    domain: {
                        "status": r.status.value,
                        "evidence": r.evidence,
                        "remediation": r.remediation,
                        "details": r.details,
                    }
                    for domain, r in servers.items()
                },
            }
        )
    return json.dumps(
        {
            "servers": [run.ctx.summary() for run in runs],
            "checks": checks_json,
        },
        indent=2,
        default=str,
    )
