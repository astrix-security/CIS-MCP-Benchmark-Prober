# cis-mcp-probe

A command-line tool that grades a live MCP server against the recommendations in
the **CIS MCP Server Benchmark**.

It connects the way an ordinary client would — by domain, over Streamable HTTP,
completing OAuth where the server requires it — and then evaluates what it can
observe from outside. The report is check-centric: for each recommendation, which
servers pass, which fail, and which the run could not decide.

The tool is an **external, black-box probe**. It sees only what any client
connecting to that domain sees, so a recommendation whose evidence lives in an
audit log, an enterprise registry or a host process inventory is reduced to its
externally observable part, or reported rather than graded. Every check states its
own reduction in the evidence it prints, so a report never implies coverage it did
not achieve.

## Why this exists

A recommendation is only worth relying on once a real server has been measured
against it. This tool runs each check against live hosted MCP servers — DeepWiki,
Linear, Sentry, Notion and Stripe — so the results are empirical: which
recommendations hold up in the field, which no server passes as written, and which
cannot be decided from outside at all.

## What it evaluates

36 checks across six of the benchmark's ten sections. "Verdict" says where the
answer comes from: `wire` decides from what the server sent, `in part` decides one
half of the recommendation and names the half it cannot reach, and `reported only`
means the recommendation is operator-side and the run records what it observed
instead of grading it.

### 1 — Governance & Versioning

| Check | Level | What it looks at | Verdict |
|---|---|---|---|
| 1.1 | L1 | Whether the server serves only approved protocol revisions, and refuses a request whose version is absent, unapproved or stated inconsistently | wire |
| 1.2 | L1 | Whether the advertised capability configuration still matches a recorded baseline, value by value | wire |
| 1.3 | L2 | Whether a capability advertised beyond the baseline is refused until it is re-approved | in part |
| 1.4 | L1 | Whether the server's name and version match the identity recorded for it | wire |

### 2 — Transport & Connectivity

| Check | Level | What it looks at | Verdict |
|---|---|---|---|
| 2.1 | L1 | Whether a local single-user server uses stdio rather than a network transport | reported only |
| 2.2 | L1 | Whether TLS is required, plaintext refused, obsolete TLS versions refused, and the certificate valid | wire |
| 2.3 | L2 | Whether authentication is enforced before a streamed response is established | wire |
| 2.4 | L1 | Whether the required request metadata headers are present and agree with the body | wire |
| 2.5 | L1 | Whether a request carrying a hostile `Origin` is refused | wire |

### 3 — Authentication & Authorization

| Check | Level | What it looks at | Verdict |
|---|---|---|---|
| 3.1.1 | L1 | Where a stdio server reads its credentials from | reported only |
| 3.1.2 | L1 | Whether the server requires OAuth or a short-lived token, and how long an issued token lives | wire |
| 3.2.1 | L2 | Whether authorization is enforced per tool | reported only |
| 3.2.2 | L1 | Whether the server passes our credential through to a downstream API | in part |
| 3.2.3 | L1 | Whether server-supplied tool annotations drive authorization or human-approval decisions | reported only |
| 3.3.1 | L1 | Whether the token is bound to this server as its audience | in part |
| 3.3.2 | L2 | Whether OAuth discovery metadata is served over TLS and names an approved authorization server | wire |
| 3.3.3 | L2 | Whether one downstream service-account identity is shared across tools or servers | reported only |
| 3.3.4 | L2 | Whether the granted scopes are minimal, free of wildcards, and within the recorded baseline | wire |
| 3.3.5 | L2 | Whether a static OAuth client id carries confused-deputy safeguards | in part |

### 5 — Server Configuration

| Check | Level | What it looks at | Verdict |
|---|---|---|---|
| 5.1.1 | L1 | Whether every advertised tool schema compiles under the JSON Schema dialect it declares | wire |
| 5.1.2 | L1 | Whether resource templates declare a URI pattern and a MIME type, and a non-existent read is refused | wire |
| 5.1.3 | L1 | Whether prompts declare well-formed arguments, and a call missing a required one is refused | wire |
| 5.2.1 | L2 | Whether `listChanged` notifications are rate-limited | reported only |
| 5.2.2 | L1 | Whether a session handle is used as authentication | reported only |
| 5.2.3 | L1 | Whether the legacy session and stream-resumption surface is gone | wire |
| 5.3.1 | L1 | Whether logs are kept out of the protocol stream in stdio mode | reported only |
| 5.4.1 | L1 | Whether a resource read that escapes the approved root is denied | wire |
| 5.5.1 | L2 | Whether authorization, scope and expiry are enforced on Tasks | reported only |
| 5.6.1 | L2 | Whether a side-effecting tool call requires an idempotency key | reported only |

### 7 — Observability & Audit

| Check | Level | What it looks at | Verdict |
|---|---|---|---|
| 7.1.1 | L1 | Whether lifecycle and invocation metadata is recorded | reported only |
| 7.1.2 | L1 | Whether a JSON-RPC request carrying a null id is refused | wire |
| 7.1.3 | L1 | Whether audit records carry accurate, non-decreasing timestamps | reported only |
| 7.2.1 | L1 | Whether a deliberately mis-scoped token is refused | in part |
| 7.2.2 | L2 | Whether server notifications name their sender and echo a token the run sent | in part |

### 10 — Resource Limits & Caching

| Check | Level | What it looks at | Verdict |
|---|---|---|---|
| 10.1 | L1 | Whether cache directives keep static content revalidated and per-user content out of shared caches | wire |
| 10.2 | L1 | Whether a request body above the configured limit is refused | wire |

### Sections with no checks here

Four sections were read and none of their recommendations is decidable from a client
connection.

- **4 — Client (Host) Configuration.** All ten recommendations audit the host or the
  client, never the server.
- **6 — Data Protection & Privacy.** A secret scan over the deployment's own
  manifests and filesystem, the resolver and outbound-proxy configuration on the
  path, and what a host chooses to send to the model.
- **8 — Supply Chain Security.** The allowlist and vetting records a host enforces,
  the content hash an installed artefact is pinned to, and the package source the
  production host resolves against.
- **9 — Isolation & Execution Safety.** The container, VM or kernel-level sandbox a
  server process runs inside, its least-privilege identity, and the gateway in front
  of it.

## Verdicts

| Verdict | Meaning |
|---|---|
| `PASS` | The server satisfied the part of the recommendation this probe can observe. |
| `FAIL` | It did not. |
| `UNKNOWN` | The run made the observation and it does not decide: no baseline recorded yet, an operator input nobody supplied, or a refusal whose reason answers a different question. A later run may decide. |
| `ERROR` | The observation was never made. The probe could not run, or the response cannot be attributed to the server. A bare status with no protocol error body is served the same way by a gateway in front of it. |
| `N/A` | The whole recommendation is operator-side and no check of our own is defined for it. |
| `NO-REV` | The check tests a mechanism that exists only in a protocol revision this server does not speak. Re-running cannot change it; only the server adopting the revision can. |

## How it connects

- Connects by domain over Streamable HTTP, completes the `initialize` handshake,
  and enumerates tools, resources, templates, prompts and capabilities.
- Handles interactive OAuth 2.1 with PKCE and dynamic client registration: opens a
  browser, catches the redirect on a loopback port, then caches and refreshes the
  tokens so a repeat run does not prompt.
- Prefers the newest protocol revision it knows and falls back when a server will
  not speak it.
- Records a per-server baseline for the checks that compare against one. Capture
  or refresh it with `--update-baseline`.

## Install

```
uv sync
```

## Usage

```
uv run cis-mcp-probe mcp.deepwiki.com                       # one server
uv run cis-mcp-probe mcp.linear.app mcp.sentry.dev          # several at once
uv run cis-mcp-probe mcp.notion.com --update-baseline       # record or refresh the baseline; run this first
uv run cis-mcp-probe mcp.deepwiki.com --json                # machine-readable report on stdout
uv run cis-mcp-probe mcp.stripe.com --info                  # connect and enumerate only, no checks
uv run cis-mcp-probe mcp.stripe.com --reauth                # discard cached credentials and log in again
```

Checks 1.2, 1.4 and 3.3.4 compare against a baseline, so they report `UNKNOWN` on
a first run and decide on the second. Tokens and baselines cache under
`~/.cis-mcp-probe/`. Some checks need an operator input that no probe can derive:
a downstream API to present the token to, a tool to call for a scope probe, a
static resource path. Those live in `~/.cis-mcp-probe/probe-inputs.json`, and a run
prints which checks are affected when an entry is missing.

## Example output

```
========================================================================
Targets probed: 1
========================================================================
  mcp.deepwiki.com             ok          DeepWiki 2.14.3  [auth=False, proto=2025-11-25, no-RC]

========================================================================
Per-check validation across servers
========================================================================
Negotiated revision: mcp.deepwiki.com [2025-11-25]

1.1 (L1)  Served protocol revisions are pinned and malformed assertions are rejected   — 0/1 pass
    FAIL   : mcp.deepwiki.com [2025-11-25]
      · mcp.deepwiki.com: 1.1a: serves 2024-11-05, 2025-03-26, earlier than the
        2025-06-18 floor this Recommendation sets, so an unapproved revision is
        reachable by negotiation; the operator allowlist itself was not read; 1.1b:
        rejected with error code -32600 at HTTP 400; ...

1.4 (L1)  Server identity matches the recorded identity (no unregistered identity)   — 1/1 pass
    PASS   : mcp.deepwiki.com [2025-11-25]
```

`--json` emits the same content as one object per check, with the per-server
verdicts, evidence and per-leg detail.

## Results so far

Probed 2026-09-15 against five hosted servers: DeepWiki, Linear, Sentry, Notion and
Stripe.

No server passes 1.1: each serves a revision below the floor the recommendation
sets. Two of the five validate the `Origin` header, one serves plaintext HTTP and
accepts obsolete TLS, and only Stripe issues a token whose lifetime is within the
3600-second baseline. Check 10.1 fails on the three servers that answered it, all
replying `no-cache, no-transform` where the recommendation requires `no-store` or
`private`. No server negotiates 2026-07-28, so two checks report `NO-REV` on all
five.

Every check, how it is implemented, what was reduced for a black-box probe, and the
recorded per-server results are in [docs/checks.md](docs/checks.md).

## Scope & limitations

- **Black-box only.** Operator-side evidence — audit logs, an enterprise registry,
  an approved-capability baseline, a host process inventory — is out of reach. A
  recommendation resting on it is reduced or reported.
- **Streamable HTTP only.** An SSE-only server does not establish a session yet.
- **Endpoint discovery** tries `/mcp` and `/`, not arbitrary paths.
- **One page of each inventory.** Discovery reads a single page and does not retain
  the pagination cursor, so a verdict covers page one. Affected evidence says so.
- **TLS interception breaks the transport checks.** Behind an inspecting proxy the
  certificate and the negotiated version belong to the proxy, so check 2.2 declines
  to grade and names the issuer.
- **A probe runs real requests.** Checks call tools, read resources and send one
  oversized body. Point it at a server you are authorised to test.

## Repository layout

```
src/cis_mcp_probe/
  cli.py          command-line entry point
  client.py       connect by domain, negotiate the revision, enumerate, run checks
  oauth.py        interactive OAuth: browser plus loopback redirect catcher
  storage.py      per-server token and client-registration cache
  baseline.py     per-endpoint capability and identity baseline
  context.py      the shared substrate every check reads
  inputs.py       operator-supplied per-domain inputs
  rawreq.py       raw JSON-RPC and HTTP helpers for hand-built requests
  netguard.py     host guard: where a request and a credential may go
  tokens.py       token and scope reading
  observations.py transport observations
  report.py       check-centric text and JSON report
  checks/
    base.py       the Check base class, results, verdicts, registry
    section1.py   checks 1.1-1.4
    section2.py   checks 2.1-2.5
    section3.py   checks 3.1.1-3.3.5
    section5.py   checks 5.1.1-5.6.1
    section7.py   checks 7.1.1-7.2.2
    section10.py  checks 10.1-10.2
docs/
  checks.md       what each check requires, how it is implemented, what was reduced,
                  and the per-server results
```

## Status

Sections 1, 2, 3, 5, 7 and 10 are implemented and exercised against live servers.
Sections 4, 6, 8 and 9 were read and hold nothing a client connection can decide.
Checks are added and revised as the benchmark text moves.

## Authors

Tal Skverer and Tomer Schwartz.

## License

Released under the [MIT License](LICENSE).

## Disclaimer

Provided "as is", without warranty of any kind. A verdict from this tool is one
client's observation of one server at one moment, not a certification.
