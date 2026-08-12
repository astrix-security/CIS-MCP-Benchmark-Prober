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
    Status.REVISION_UNSUPPORTED: "NO-REV",
    Status.UNKNOWN: "UNKNOWN",
    Status.ERROR: "ERROR",
}

# Order statuses appear in the per-check breakdown.
_ORDER = [
    Status.PASS,
    Status.FAIL,
    Status.MANUAL,
    Status.REVISION_UNSUPPORTED,
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


def _version_map(runs: list[ProbeRun]) -> dict[str, str]:
    """domain -> negotiated protocol revision, for annotating every verdict."""
    return {
        run.ctx.domain: (run.ctx.negotiated_version or "no-session") for run in runs
    }


def render_check_report(runs: list[ProbeRun]) -> str:
    agg = _aggregate(runs)
    if not agg:
        return "\n(no checks registered — connection/enumeration only)\n"

    versions = _version_map(runs)

    def label(domain: str) -> str:
        return f"{domain} [{versions.get(domain, '?')}]"

    lines = ["", "=" * 72, "Per-check validation across servers", "=" * 72]
    lines.append("Each server is annotated with the protocol revision it negotiated.")
    for entry in agg:
        servers: dict[str, CheckResult] = entry["servers"]
        buckets = _counts(servers)
        n_pass, n_fail = len(buckets[Status.PASS]), len(buckets[Status.FAIL])
        decidable = n_pass + n_fail
        rate = f"{n_pass}/{decidable} pass" if decidable else "no pass/fail decisions"
        n_norev = len(buckets[Status.REVISION_UNSUPPORTED])
        if n_norev:
            rate += f", {n_norev} lack the required revision"

        lines.append("")
        lines.append(
            f"{entry['check_id']} ({entry['level']})  {entry['title']}   — {rate}"
        )
        for status in _ORDER:
            domains = buckets[status]
            if domains:
                shown = ", ".join(label(d) for d in sorted(domains))
                lines.append(f"    {_MARK[status]:7s}: {shown}")
        # Show one representative evidence line per failing server for context.
        # REVISION_UNSUPPORTED gets one too: it explains which revision is missing.
        for status in (Status.FAIL, Status.REVISION_UNSUPPORTED):
            for domain in sorted(buckets[status]):
                ev = servers[domain].evidence
                if ev:
                    lines.append(f"      · {domain}: {ev}")
    lines.append("")
    return "\n".join(lines)


def render_report(runs: list[ProbeRun]) -> str:
    return render_servers_summary(runs) + "\n" + render_check_report(runs)


def to_json(runs: list[ProbeRun]) -> str:
    agg = _aggregate(runs)
    versions = _version_map(runs)
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
                # Keyed by the status value itself so a new status can't collide
                # with another after case-folding.
                "summary": {s.value: len(buckets[s]) for s in _ORDER},
                "servers": {
                    domain: {
                        "status": r.status.value,
                        "negotiated_version": versions.get(domain),
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
