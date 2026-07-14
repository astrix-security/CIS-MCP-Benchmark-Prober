# cis-mcp-probe

A validation tool for the **CIS MCP Security Benchmark**. It connects to a live
MCP server the way a real client would — by domain, over Streamable HTTP, doing
OAuth if required — and evaluates it against the benchmark's checks. The output
is **check-centric**: for each check, which servers pass, fail, or can't be
decided.

## Why this exists

We're co-authoring a CIS Benchmark for MCP security. Before a recommendation
ships, we want to know whether it is sound and realistic against real servers.
This tool runs each check against actual hosted MCP servers (Notion, Sentry,
Stripe, Linear, DeepWiki, …) so we can see, empirically, how the ecosystem
measures up — and catch checks that no real server can pass, or that don't apply
as written.

It is deliberately an **external, black-box probe**: it sees only what any client
connecting to the server by domain can see. That scopes which checks it can
decide automatically — see [Scope & limitations](#scope--limitations).

## What it does

- Connects to an MCP server by domain over Streamable HTTP, performs the
  `initialize` handshake, and enumerates tools / resources / prompts /
  capabilities.
- Handles interactive **OAuth 2.1** (PKCE + dynamic client registration): opens
  the browser, catches the redirect on a loopback port, and caches + refreshes
  tokens so repeat runs don't prompt again.
- Prefers protocol revision **2026-07-28** and falls back to **2025-11-25** when
  a server won't speak the newer one.
- Runs the Section 1 checks and prints a per-check report across all servers, as
  text or JSON.

## Section 1 checks implemented

| Check | Level | What the probe does |
|-------|-------|---------------------|
| 1.1 | L1 | Sends a bogus and an absent protocol version and confirms both are rejected. Uses the `MCP-Protocol-Version` header for 2025-11-25 servers and per-request `_meta` for 2026-07-28. (The benchmark's log-inspection half is out of scope for a black-box probe.) |
| 1.2 | L1 | Compares advertised capabilities and tool/resource/prompt names against a baseline we record ourselves per server URL. New items are flagged as drift. Capture/refresh with `--update-baseline`. |
| 1.3 | L2 | Waits briefly for a `listChanged` event, then tries to invoke the newly added tool. Reports UNKNOWN if no event arrives in time. |
| 1.4 | L1 | Confirms the server exposes non-empty `serverInfo` (name/version). |

## Install

```
uv sync
```

## Usage

```
uv run cis-mcp-probe mcp.notion.com                    # one server
uv run cis-mcp-probe mcp.sentry.dev mcp.stripe.com     # several at once
uv run cis-mcp-probe mcp.notion.com --update-baseline  # record/refresh baseline (run first for 1.2)
uv run cis-mcp-probe --json mcp.notion.com             # machine-readable, for a marketplace
uv run cis-mcp-probe mcp.notion.com --info             # connect + enumerate only, no checks
uv run cis-mcp-probe mcp.notion.com --reauth           # discard cached credentials and log in again
```

For OAuth servers a browser opens per server; complete the login and the probe
continues. Tokens and baselines cache under `~/.cis-mcp-probe/`.

## Example output

```
========================================================================
Targets probed: 4
========================================================================
  mcp.deepwiki.com   ok   DeepWiki 2.14.3    [auth=False, proto=2025-11-25, no-RC]
  mcp.sentry.dev     ok   Sentry MCP 0.37.0  [auth=True,  proto=2025-11-25, no-RC]
  mcp.stripe.com     ok   stripe-mcp 1.0.0   [auth=True,  proto=2025-03-26, no-RC]
  mcp.linear.app     ok   Linear MCP 1.0.0   [auth=True,  proto=2025-11-25, no-RC]

1.1 (L1)  Unapproved or absent protocol version is rejected   — 0/4 pass
    FAIL  : mcp.deepwiki.com, mcp.linear.app, mcp.sentry.dev, mcp.stripe.com

1.4 (L1)  Server exposes non-empty identity metadata (serverInfo)   — 4/4 pass
    PASS  : mcp.deepwiki.com, mcp.linear.app, mcp.sentry.dev, mcp.stripe.com
```

## Results so far

Across five well-known servers (Notion, DeepWiki, Linear, Sentry, Stripe),
**none pass 1.1 as written** — they either accept an absent protocol version, or
(Stripe) accept a bogus one too. All four reachable servers expose a proper
`serverInfo` (1.4). The full write-up, including the ticket-worthy issues we
found in the check text and audit scripts, is in
[docs/section1-findings.md](docs/section1-findings.md).

## Scope & limitations

- **Black-box only.** It can't see operator-side artifacts (audit logs,
  enterprise registry, approved-capability baselines). Benchmark checks that
  depend on those are reduced to their externally observable part or reported
  UNKNOWN/MANUAL.
- **Streamable HTTP only.** SSE-only servers won't establish a session yet.
- **Endpoint discovery** tries `/mcp` and `/`, not arbitrary paths (e.g.
  Atlassian's `/v1/...`).
- **2026-07-28 is a release candidate** with no live server speaking it yet, so
  RC-specific behavior is detected but not yet exercisable in practice.

## Repository layout

```
src/cis_mcp_probe/
  client.py       connect by domain, negotiate version, enumerate, run checks
  oauth.py        interactive OAuth: browser + loopback redirect catcher
  storage.py      per-server token / client-registration cache
  rawreq.py       raw JSON-RPC helper for hand-crafted requests
  baseline.py     per-URL capability baseline store (check 1.2)
  context.py      ProbeContext: the shared substrate every check reads
  report.py       check-centric text + JSON report
  cli.py          command-line entry point
  checks/
    base.py       Check base class, results, statuses, registry
    section1.py   checks 1.1–1.4
docs/
  section1-findings.md   review findings + empirical results
benchmark/        draft CIS benchmark source (git-ignored, confidential)
```

## Status

Section 1 checks 1.1–1.4 implemented and validated against live servers. More
checks and sections are added as the benchmark draft progresses.
