"""Command-line entry point.

    cis-mcp-probe mcp.notion.com                      # one server, run all checks
    cis-mcp-probe mcp.notion.com mcp.linear.app       # several servers
    cis-mcp-probe --servers-file servers.txt          # a list, one per line
    cis-mcp-probe mcp.notion.com --info               # connect + enumerate only
    cis-mcp-probe mcp.notion.com --json               # machine-readable report
    cis-mcp-probe mcp.notion.com --reauth             # forget cached tokens, re-login

The report is check-centric: for each benchmark check, it shows which servers
pass, fail, or don't apply.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import anyio

from . import checks as checks_pkg
from .client import connect_and_probe
from .report import ProbeRun, render_report, to_json


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="cis-mcp-probe",
        description="Validate CIS MCP Benchmark checks against live MCP servers.",
    )
    p.add_argument("domains", nargs="*", help="MCP server domain(s) or endpoint URL(s)")
    p.add_argument(
        "--servers-file",
        type=Path,
        help="file with one server domain/URL per line (# comments allowed)",
    )
    p.add_argument("--info", action="store_true", help="connect + enumerate only")
    p.add_argument("--json", action="store_true", help="emit JSON instead of text")
    p.add_argument(
        "--reauth", action="store_true", help="discard cached credentials"
    )
    p.add_argument(
        "--update-baseline",
        action="store_true",
        help="record/refresh the capability baseline for each server (check 1.2). "
        "Run this the first time you probe a server, and occasionally to update it.",
    )
    p.add_argument(
        "--timeout", type=float, default=30.0, help="per-request timeout seconds"
    )
    return p.parse_args(argv)


def _collect_targets(args: argparse.Namespace) -> list[str]:
    targets: list[str] = list(args.domains)
    if args.servers_file:
        for line in args.servers_file.read_text().splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                targets.append(line)
    # De-dupe while preserving order.
    seen: set[str] = set()
    return [t for t in targets if not (t in seen or seen.add(t))]


async def _run(args: argparse.Namespace) -> int:
    targets = _collect_targets(args)
    if not targets:
        print("error: no servers given (pass domains or --servers-file)", file=sys.stderr)
        return 2

    checks = [] if args.info else checks_pkg.all_checks()
    runs: list[ProbeRun] = []
    for domain in targets:
        if not args.json:
            print(f"# probing {domain} ...", file=sys.stderr)
        ctx, results = await connect_and_probe(
            domain,
            checks,
            force_reauth=args.reauth,
            update_baseline=args.update_baseline,
            timeout=args.timeout,
        )
        runs.append(ProbeRun(ctx=ctx, results=results))

    print(to_json(runs) if args.json else render_report(runs))

    from .checks.base import Status

    any_fail = any(
        r.status in (Status.FAIL, Status.ERROR) for run in runs for r in run.results
    )
    all_reachable = all(run.ctx.init_result is not None for run in runs)
    if not all_reachable:
        return 2
    return 1 if any_fail else 0


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        return anyio.run(_run, args)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
