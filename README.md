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

## Checks implemented

| Check | Level | What the probe does |
|-------|-------|---------------------|
| 1.1 | L1 | Sends a bogus and an absent protocol version and confirms both are rejected. Uses the `MCP-Protocol-Version` header for 2025-11-25 servers and per-request `_meta` for 2026-07-28. (The benchmark's log-inspection half is out of scope for a black-box probe.) |
| 1.2 | L1 | Compares advertised capabilities and tool/resource/prompt names against a baseline we record ourselves per server URL. New items are flagged as drift. Capture/refresh with `--update-baseline`. |
| 1.3 | L2 | Waits briefly for a `listChanged` event, then tries to invoke the newly added tool. Reports UNKNOWN if no event arrives in time. |
| 1.4 | L1 | Confirms the server exposes non-empty `serverInfo` (name/version). |
| 2.1 | L2 | Reports N/A: the audit is a host-side transport inventory plus a registry lookup, and a server reached by domain is a network transport by definition. |
| 2.2 | L1 | Confirms plaintext HTTP isn't served, that TLS 1.0/1.1 are refused while 1.2+ is accepted, and that the certificate is currently valid. |
| 2.3 | L1 | Confirms an unauthenticated request is refused and the same request with a credential is accepted. Per-proxy-hop forwarding needs proxy logs and is reported as operator-side. |
| 2.4 | L1 | Confirms a request missing `Mcp-Method` is rejected, and that a header/body mismatch is rejected with `-32020`. 2026-07-28 only, so reports NO-REV against older servers. |
| 2.5 | L1 | Sends a hostile `Origin` with no preceding `OPTIONS` and confirms it's refused with 403. |

See [docs/checks.md](docs/checks.md) for what each check requires, how it's
implemented, and what was reduced to fit a black-box probe.

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

Across four reachable servers (DeepWiki, Linear, Sentry, Stripe), **none pass
1.1 as written** — they either accept an absent protocol version, or (Stripe)
accept a bogus one too. All four expose a proper `serverInfo` (1.4). Only one of
four validates the `Origin` header (2.5), and one serves plaintext HTTP while
accepting TLS 1.0/1.1 (2.2).

Every check, how it is implemented, what was reduced for a black-box probe, and
the full per-server results are in [docs/checks.md](docs/checks.md).

## Scope & limitations

- **Black-box only.** It can't see operator-side artifacts (audit logs,
  enterprise registry, approved-capability baselines, host process inventory).
  Benchmark checks that depend on those are reduced to their externally
  observable part, or reported N/A / UNKNOWN / MANUAL.
- **Streamable HTTP only.** SSE-only servers won't establish a session yet.
- **Endpoint discovery** tries `/mcp` and `/`, not arbitrary paths (e.g.
  Atlassian's `/v1/...`).
- **2026-07-28 is a release candidate** with no live server speaking it yet.
  Checks that test a mechanism unique to it report `NO-REV`, a verdict distinct
  from `UNKNOWN`: it can't be resolved by re-running, only by the server
  adopting the revision.
- **TLS interception breaks transport checks.** Behind an inspecting proxy the
  certificate and negotiated TLS version belong to the proxy, not the server.
  Check the certificate issuer before trusting a 2.2 result.

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
    section2.py   checks 2.1–2.5
docs/
  checks.md       what each check tests, how it's implemented, per-server results
benchmark/        draft CIS benchmark source and working notes
                  (git-ignored, confidential)
```

## Status

Section 1 checks 1.1–1.4 and Section 2 checks 2.1–2.5 implemented and validated
against live servers. More checks and sections are added as the benchmark draft
progresses.

## License

Released under the [MIT License](LICENSE).

## Disclaimer

This project is part of the **CIS MCP Security Benchmark** effort and was
developed by Tal Skverer. It is provided "as is", without warranty of any kind.
