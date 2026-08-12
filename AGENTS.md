# Working on this repository

This probe validates CIS MCP Security Benchmark checks against live MCP servers.
The work arrives one benchmark section at a time. This file records the process
so a new session can pick up at the same standard.

## What this project is for

Two outputs, and they are kept apart on purpose:

1. **A public tool** that runs benchmark checks against real servers.
2. **Private review notes** on the benchmark draft itself — defects in the check
   text and audit scripts, filed as tickets in CIS WorkBench.

The benchmark draft is confidential. Never commit it, and never commit criticism
of it. `docs/` is public and describes only the checks, the implementation, and
the results. Everything else lives under `/benchmark/`, which is git-ignored.

## The per-section process

### 1. Tal pastes the section into `benchmark/section<N>.md`

Create the file if asked, under `/benchmark/`. Confirm it is ignored:

```
git check-ignore benchmark/section<N>.md
```

The section text gets revised between rounds. When Tal re-pastes it, diff your
assumptions against the new text before doing anything else — findings from the
previous round are frequently already fixed.

### 2. Triage each check for black-box decidability

For each check, decide which of these it is, and say so before implementing:

- **Fully decidable** — implement all sub-tests.
- **Partially decidable** — implement the observable part, report the rest.
  State the reduction in the check's evidence string at runtime, not only in docs.
- **Not decidable** — return `_na()` with the reason. Operator-side audits
  (`systemctl`, `ss`, audit logs, an enterprise registry, a manual configuration
  determination) are out of the prober's remit. That is a scope boundary, not a
  defect in the benchmark, and it does not become a ticket.

Ask which checks to build if the split is not obvious. Do not silently skip one.

### 3. Implement in `src/cis_mcp_probe/checks/section<N>.py`

- Subclass `Check`, decorate with `@register`, set `section = "<N>"` explicitly
  (the base class defaults to `"1"`).
- Set `level` and record the benchmark's own assessment status in the docstring.
- Import the module in `checks/__init__.py` for the registration side effect.
- Put shared transport observations in `client.py` so several checks can read one
  observation, rather than each check re-probing the network.
- Use `raw_jsonrpc` for hand-crafted or deliberately malformed requests,
  `raw_jsonrpc_headers` when a check must assert on response headers.

### 4. Verify against a live server, and cross-check anything surprising

Run `mcp.deepwiki.com` first: it needs no auth, so no browser prompt.

```
uv run cis-mcp-probe mcp.deepwiki.com
```

Then confirm any notable verdict with an independent tool — `curl`, `openssl`.
Two traps that have already cost time:

- **`openssl s_client` prints `Protocol: TLSv1` for the version you
  *requested*, not the one negotiated.** Read the `New,` line and the exit code
  instead. `New, (NONE), Cipher is (NONE)` with exit 1 means the server refused.
- **A modern OpenSSL will not offer TLS 1.0/1.1 without
  `DEFAULT@SECLEVEL=0`.** Without it the handshake fails locally, which is
  indistinguishable from the server refusing, and every server passes vacuously.

If a check passes against every server, suspect it is not discriminating before
believing it.

### 5. Report results and never overstate them

- A verdict that needs a mechanism the server does not speak is
  `REVISION_UNSUPPORTED` (`NO-REV`), not `UNKNOWN`. `UNKNOWN` means this run
  could not decide and a later one might.
- A response that cannot be attributed to the control is `ERROR`, not `PASS` or
  `FAIL`. A bare 400 with no protocol error body is the common case: a gateway
  may have rejected it, so it says nothing about the server.
- When a finding is read from the text rather than reproduced live, say so.

### 6. Write the tickets, keep them private

Ticket format Tal asks for, per finding:

1. **The subsection** — what the recommendation requires.
2. **The test** — the audit as written, quoted.
3. **The issue** — what is wrong and what verdict it produces.
4. **How you validated it** — reproduced live, or read from the text. Be explicit
   about which.

Write them to `benchmark/section<N>-tickets.md`. Tal validates each one and
replies which hold. Only survivors matter. Then, before opening anything in
WorkBench, re-verify the survivors against the freshly pasted section text: the
last round had all three validated tickets already fixed in the new revision.

## What does not become a ticket

Learned by getting these wrong:

- **"Servers on an older revision fail this."** The probe targets 2026-07-28.
  Older-revision failures are the premise, not a finding.
- **"This check's audit is operator-side."** Correct, and irrelevant. The prober
  just does not run it.
- **The author's own working notes** left in a Description field. Internal
  drafting residue, not a defect to file.

## Public documentation

`docs/checks.md` is the only public doc. Per check it states what the check
requires, how the probe implements it, what was reduced and why, and then the
results matrix. Rules:

- The negotiated protocol revision is the **first row** of the results table.
  Every verdict must be readable against the revision the server actually speaks.
- Describe reductions as facts about the probe's reach, never as faults in the
  benchmark.
- Record servers that could not be probed, with the reason.

## Hard-won environment notes

- **TLS interception invalidates transport checks.** Behind an inspecting proxy
  the certificate and negotiated TLS version belong to the proxy. Check the
  issuer before trusting a 2.2 result:
  `echo | openssl s_client -connect <host>:443 -servername <host> 2>/dev/null | grep issuer=`
  An issuer that is not the expected CA means stop and tell Tal, do not report.
- **`--json` output is preceded by console noise** when OAuth opens a browser.
  Strip everything before the first `{` when parsing.
- **`timeout` is not installed.** Use the Bash tool's own timeout parameter.
- The OAuth servers each open a browser and need Tal to log in. Probe one at a
  time and expect to wait.

## Git

- Branch, never commit straight to `main`.
- Confirm the confidential source is not staged before every commit:
  `git diff --cached --name-only | grep -i benchmark`
- Remotes use the `github-astrix` SSH alias, not `github.com`.
