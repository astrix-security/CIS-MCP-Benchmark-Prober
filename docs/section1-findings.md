# Section 1 — validation findings

What we did: implemented Section 1 checks 1.1–1.4 as live, black-box probes and
ran them against well-known hosted MCP servers. This documents the results and
the issues we found in the check text and audit scripts (ticket candidates for
CIS WorkBench).

## Servers tested

| Server | Endpoint | Auth | Protocol negotiated |
|--------|----------|------|---------------------|
| Notion | `mcp.notion.com` | OAuth | 2025-11-25 |
| DeepWiki | `mcp.deepwiki.com` | none | 2025-11-25 |
| Linear | `mcp.linear.app` | OAuth | 2025-11-25 |
| Sentry | `mcp.sentry.dev` | OAuth | 2025-11-25 |
| Stripe | `mcp.stripe.com` | OAuth | 2025-03-26 |

(Atlassian was attempted but its endpoint sits under `/v1/...`, which our
endpoint discovery doesn't try yet. Asana's OAuth would not complete.)

## Results

| Check | Notion | DeepWiki | Linear | Sentry | Stripe |
|-------|:------:|:--------:|:------:|:------:|:------:|
| 1.1 protocol version rejected | FAIL | FAIL | FAIL | FAIL | FAIL |
| 1.2 capability baseline (no drift) | PASS | PASS | PASS | PASS | PASS |
| 1.3 listChanged re-validation | UNKNOWN | UNKNOWN | UNKNOWN | UNKNOWN | UNKNOWN |
| 1.4 serverInfo non-empty | PASS | PASS | PASS | PASS | PASS |

Notes on interpretation:

- **1.1 — 0/5 pass.** Every server rejects a bogus protocol version *except*
  Stripe, but all five accept a request with the version *absent* and just
  default it. Stripe (on the older 2025-03-26 protocol) accepts a bogus version
  too — it doesn't validate the version header at all.
- **1.2 — passes by construction.** This is a drift check: we recorded each
  server's advertised capabilities as a baseline, and a re-run shows no drift.
  It becomes meaningful over time (detecting new tools/capabilities appearing).
- **1.3 — UNKNOWN everywhere.** None of these servers emitted a `listChanged`
  event during the observation window, so there was nothing to test.
- **1.4 — 5/5 pass.** All servers expose a proper `serverInfo` (name + version).

The headline: **five mature, widely used MCP servers, and not one passes 1.1 as
written.** That's the strongest signal from this round — it says the check needs
another look before it ships at L1.

## Ticket candidates (issues found while reviewing the checks)

### 1.1 — Ensure MCP protocol version is pinned and logged

1. **Audit script bug (definite).** The "absent version" test puts a shell
   comment inside a backslash line-continuation:

   ```bash
   -H 'Content-Type: application/json' \
   # Intentionally omit _meta to verify absent-version rejection
   -H 'Mcp-Method: tools/list' \
   ```

   The comment line has no trailing backslash, so the command is split: the
   `Mcp-Method` header is dropped from the request, and the two sub-tests
   (unapproved vs. absent) stop sending comparable requests. Move the comment
   above the command.

2. **Only the 2026-07-28 path is exercised.** The audit asserts the version in
   `_meta`, the 2026-07-28 mechanism. Live servers today use the
   `MCP-Protocol-Version` header (2025-11-25). Against such a server the `_meta`
   test does nothing, so a compliant server reads as FAIL. Cover both mechanisms
   or mark the check RC-only.

3. **"Reject absent version" isn't met by any current server.** Marked as an
   intentional override of the spec's silent-downgrade fallback — fine, but the
   empirical result (0/5 pass; see table) argues for deciding whether the
   "absent" clause belongs at L1 now or should phase in with 2026-07-28.

### 1.2 — Ensure server capability baseline is established and documented

4. **Relies on `server/discover`, which doesn't exist pre-2026-07-28.** On
   current servers, capabilities come from the `initialize` result. The audit's
   `server/discover` call returns nothing against a 2025-11-25 server. The audit
   should fall back to `initialize` capabilities on older servers.

### 1.3 — Re-validate capabilities introduced via listChanged

5. **Denial detection needs a concrete code.** An `.error` response alone
   doesn't prove the staging gate fired (method-not-found or a transport error
   also produce `.error`). We need the documented denial response (which
   `.error.code`) so the audit can tell a real authorization/pending denial from
   "tool reached but bad params" (which actually means the capability *was*
   invocable). Our probe treats `-32602` invalid-params as "reached the tool →
   fail".

### 1.4 — Capture & validate identity metadata against the asset inventory

6. **Labeled "Automated" but the audit is operator-side.** The audit is entirely
   log + registry grepping (`<MCP_AUDIT_LOG>`, `approved_identities.txt`), which
   an external probe can't do. The only externally observable part is "does the
   server expose non-empty `serverInfo`" — which is what our probe checks.
   Consider relabeling the operator-side audit as Manual, or splitting out the
   black-box-observable part as the Automated portion.

7. **Also references `server/discover`** (same issue as #4) for the capability
   half.
