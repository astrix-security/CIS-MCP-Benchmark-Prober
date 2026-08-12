# Section 2 — validation findings

What we did: implemented Section 2 checks 2.1–2.5 as live, black-box probes and
ran them against hosted MCP servers. This documents the results and the issues
we found in the check text and audit scripts (ticket candidates for CIS
WorkBench).

## Servers tested

| Server | Endpoint | Auth | Protocol negotiated |
|--------|----------|------|---------------------|
| DeepWiki | `mcp.deepwiki.com` | none | 2025-11-25 |
| Linear | `mcp.linear.app` | OAuth | 2025-11-25 |
| Sentry | `mcp.sentry.dev` | OAuth | 2025-11-25 |
| Stripe | `mcp.stripe.com` | OAuth | 2025-03-26 |

Notion (`mcp.notion.com`) was attempted but could not be probed. The host was
served through a TLS inspection proxy during testing, so the certificate chain
presented was not Notion's. Probing it would have measured the proxy rather than
the server, so it is excluded rather than reported.

## Results

| # | Check | deepwiki | linear | sentry | stripe |
|---|---|---|---|---|---|
| — | **Negotiated revision** | **2025-11-25** | **2025-11-25** | **2025-11-25** | **2025-03-26** |
| 1.1 | Unapproved or absent protocol version rejected | FAIL | FAIL | FAIL | FAIL |
| 1.2 | Capabilities match recorded baseline | UNKNOWN | UNKNOWN | UNKNOWN | UNKNOWN |
| 1.3 | listChanged capabilities not silently invocable | UNKNOWN | UNKNOWN | UNKNOWN | UNKNOWN |
| 1.4 | Server exposes non-empty serverInfo | PASS | PASS | PASS | PASS |
| 2.1 | stdio preferred for local, single-user servers | N/A | N/A | N/A | N/A |
| 2.2 | TLS required, plaintext disallowed | PASS | PASS | **FAIL** | PASS |
| 2.3 | Auth enforced and propagates through proxies | N/A | PASS | PASS | PASS |
| 2.4 | Routing headers present, mismatch rejected | NO-REV | NO-REV | NO-REV | NO-REV |
| 2.5 | Origin validated on all requests | **FAIL** | **FAIL** | PASS | **FAIL** |

Section 1 rows are carried in this run for context. `NO-REV` is the
`REVISION_UNSUPPORTED` verdict: the check tests a mechanism that exists only in
2026-07-28, and no server negotiates that revision.

Notes on interpretation:

- **2.1 — N/A by construction.** The audit is a host-side transport inventory
  plus an enterprise-registry lookup. Neither is observable from a remote
  client, and a server reached by domain is a network transport by definition.
- **2.2 — 3/4 pass, and the one failure is a real finding.** Sentry serves
  plaintext HTTP with 200 and negotiates both TLS 1.0 and TLS 1.1. The other
  three refuse the weak revisions. Plaintext handling differs across all four:
  DeepWiki refuses the port, Stripe redirects with 301, Linear answers 403.
- **2.3 — 3/3 pass on the servers that require auth.** All three refuse the
  unauthenticated request with 401 and accept the authenticated one with 200.
  Linear and Sentry return an SSE-framed response, Stripe returns plain JSON.
  The per-proxy-hop half of the audit is operator-side and is not attempted.
- **2.4 — NO-REV everywhere.** The routing headers and the `-32020`
  HeaderMismatch error exist only in 2026-07-28. No live server negotiates it,
  so the mechanism is absent rather than broken.
- **2.5 — 1/4 pass.** DeepWiki, Linear and Stripe all accept
  `Origin: http://evil.example.com` with HTTP 200. Sentry is the only server
  that returns 403.

The headline: **Sentry is the inverse of the other three.** It is the only
server that validates Origin, and the only one that accepts plaintext HTTP and
legacy TLS. No single server passes both 2.2 and 2.5.

## Evidence recorded per server

### 2.2 TLS and plaintext

| Server | Plaintext `http://` | TLS 1.0 / 1.1 | Negotiated | Cert expires in |
|--------|---------------------|---------------|------------|-----------------|
| DeepWiki | port refused | refused | TLSv1.3 | 83d |
| Linear | 403 | refused | TLSv1.3 | 65d |
| Sentry | **200 served** | **both accepted** | TLSv1.3 | 69d |
| Stripe | 301 redirect | refused | TLSv1.3 | 50d |

Sentry's TLS 1.0 handshake completed with cipher `ECDHE-RSA-AES128-SHA`.

### 2.3 Authentication

| Server | Unauthenticated | Authenticated | Response framing |
|--------|-----------------|---------------|------------------|
| DeepWiki | n/a (no auth) | n/a | n/a |
| Linear | 401 | 200 | SSE |
| Sentry | 401 | 200 | SSE |
| Stripe | 401 | 200 | plain JSON |

### 2.5 Origin

| Server | Hostile Origin | Own origin (stand-in) | Verdict |
|--------|----------------|------------------------|---------|
| DeepWiki | 200 | 200 | FAIL |
| Linear | 200 | 200 | FAIL |
| Sentry | **403** | 200 | PASS |
| Stripe | 200 | 200 | FAIL |

## Scope reductions applied

Three checks could not be implemented exactly as the audit specifies. Each
reduction is recorded in the check's evidence string at runtime, so a report
never implies coverage we do not have.

- **2.3 uses `tools/list`, not `<SAFE_STREAMING_TEST_TOOL>`.** The audit names a
  server-specific streaming tool. That name is not discoverable black-box, and
  invoking a guessed tool against a production server has side effects.
  `tools/list` exercises the same authentication path safely. The cost is that
  the response is not guaranteed to be SSE-framed, so the streaming-specific
  aspect is observed and reported rather than forced.
- **2.3 does not verify per-proxy-hop forwarding.** The audit's own text offers
  "inspect each proxy's access log" as the method. That is operator-side.
- **2.5 substitutes the server's own origin for `<ALLOWED_ORIGIN>`.** The
  allowlist is operator-configured and not externally discoverable. The hostile
  half of the check, which is the security-relevant direction, is fully decided.
  If the hostile Origin is correctly refused but the stand-in is also refused,
  the check reports UNKNOWN rather than claiming a pass.

## Ticket candidates (issues found while reviewing the checks)

Detailed write-ups are kept outside this repository. In summary:

1. **2.2 Description contains rewrite notes** instead of a description of the
   control.
2. **2.4 title and content disagree** — the title names the
   `MCP-Protocol-Version` header, the audit tests `Mcp-Method` and `Mcp-Name`.
3. **2.5 allowed-Origin request omits `Mcp-Name`**, which its own hostile
   request sends, so the two legs are not comparable.
4. **2.5 requires exactly 403**, which scores a server that refuses with another
   4xx as non-compliant.
5. **2.2 plaintext audit accepts any 3xx**, including a redirect to another
   plaintext location.
