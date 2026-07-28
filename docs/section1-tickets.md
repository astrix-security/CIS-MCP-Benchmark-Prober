# Section 1 — CIS WorkBench ticket drafts

Scope note: the probe validates the **2026-07-28** revision only. Findings that
amount to "servers on older revisions fail" are expected under that scope and
are not filed. Likewise, checks whose audit is entirely operator-side (audit
logs, enterprise registry) are simply out of the prober's remit — that's a scope
boundary, not a defect in the benchmark.

---

## Ticket 1 — 1.1 audit script: comment inside line continuation drops a header

- **Recommendation:** 1.1 Ensure MCP protocol version is pinned and logged
- **Type:** Bug (definite)
- **Severity:** High — the audit's second sub-test does not send the request it claims to

**Problem.** In the "absent version" sub-test, a shell comment sits between two
backslash-continued lines:

```bash
-H 'Content-Type: application/json' \
# Intentionally omit _meta to verify absent-version rejection
-H 'Mcp-Method: tools/list' \
```

The comment line has no trailing backslash, so the shell terminates the command
there. Everything after the comment is parsed as a separate command rather than
as arguments to `curl`.

**Consequences.**

1. The `Mcp-Method: tools/list` header never reaches the server.
2. The audit's two sub-tests (unapproved version vs. absent version) stop
   sending comparable requests, so the comparison between them is no longer
   valid — they differ in more than the variable under test.

Reproduced under `bash`, `sh`, and `zsh`: the shell runs the truncated command,
then fails on the remainder with `command not found` (exit 127). The failure is
easy to miss because the truncated `curl` still runs and the script's
`PASS`/`FAIL` line still prints — the only signal is a stray `command not found`
on stderr and the silently missing header.

**Suggested fix.** Move the comment above the `curl` invocation. Purely
mechanical; no change to the Recommendation text.
