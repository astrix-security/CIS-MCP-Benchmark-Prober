# Section 2 — CIS WorkBench ticket drafts

Five tickets from implementing Section 2 as a black-box probe. Each records the
check text as written, what we found, why it is a problem, and how we validated
it.

Scope note: the probe targets the **2026-07-28** revision. Findings that amount
to "servers on older revisions fail" are expected and are not filed. Checks
whose audit is operator-side are outside the prober's remit, which is a scope
boundary and not a defect.

Severity key: **Bug** = the audit produces a wrong verdict · **Gap** = the audit
does not test what the Recommendation claims · **Editorial** = the text is wrong
but the test is sound.

---

## Ticket 1 — 2.5 audit: the two Origin requests are not comparable

- **Recommendation:** 2.5 Ensure Origin header is validated on all Streamable
  HTTP requests to prevent DNS rebinding attacks
- **Type:** Bug
- **Severity:** High — the allowed-Origin leg can fail for reasons unrelated to Origin

### What the check says

The audit sends two POST requests and compares the status codes. The hostile
Origin must return 403, the allowed Origin must return 2xx or 3xx.

```bash
evil=$(curl -sS -o /dev/null -w '%{http_code}' -X POST \
  -H 'Origin: http://evil.example.com' \
  -H 'Content-Type: application/json' \
  -H 'Mcp-Method: tools/list' -H 'Mcp-Name: list' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' "$URL")
good=$(curl -sS -o /dev/null -w '%{http_code}' -X POST \
  -H 'Origin: https://<ALLOWED_ORIGIN>' \
  -H 'Content-Type: application/json' \
  -H 'Mcp-Method: tools/list' \
 -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{
 "_meta":{
 "io.modelcontextprotocol/protocolVersion":"2026-07-28",
 ...
 }}}' "$URL")
```

### What we found

The two requests differ in **three** ways, only one of which is the variable
under test:

1. **Origin** — the intended variable.
2. **`Mcp-Name`** — the hostile request sends `Mcp-Name: list`. The allowed
   request omits it.
3. **`_meta`** — the allowed request carries
   `io.modelcontextprotocol/protocolVersion`. The hostile request sends
   `"params":{}` with no `_meta` at all.

### Why it is a problem

Each extra difference gives the allowed-Origin leg a way to fail that has
nothing to do with Origin validation, and both interact with other
Recommendations in this benchmark:

- **Missing `Mcp-Name` contradicts 2.4.** Recommendation 2.4 requires that every
  Streamable HTTP request carry the `Mcp-Method` and `Mcp-Name` routing headers,
  and that the server reject a request that omits one. A server that complies
  with 2.4 must therefore reject the allowed-Origin request. That produces a
  4xx, the `case` statement does not match `2*` or `3*`, and 2.5 reports
  FAIL/REVIEW. **Complying with 2.4 makes a server fail 2.5.**
- **Missing `_meta` protocolVersion contradicts 1.1.** Recommendation 1.1
  requires rejecting a request whose asserted protocol version is absent. The
  hostile request asserts no version. A server that complies with 1.1 rejects it
  for that reason, not because of the Origin. The check then credits Origin
  validation that may not exist. If the rejection is a 400 rather than a 403 the
  check reports FAIL, and if the server happens to answer 403 for a missing
  version the check reports a **false PASS**.

The second case is the more serious one, because it can manufacture a pass.

### How we validated it

Read against the other two Recommendations in the same section, and confirmed
against our own implementation, which keeps both legs identical except for the
`Origin` header. Our probe sends the same payload and the same headers to both
legs, so a status difference is attributable to Origin alone. Across four live
servers the two legs never diverged for an unrelated reason.

We did not need to reproduce the failure against a live server, because no live
server implements 2.4's routing headers yet. The defect is latent today and
activates as servers adopt 2026-07-28.

### Suggested fix

Make the two requests byte-identical except for the `Origin` header. Send
`Mcp-Method`, `Mcp-Name` and the full `_meta` block on both.

---

## Ticket 2 — 2.5 requires exactly 403 and rejects other refusals

- **Recommendation:** 2.5
- **Type:** Gap
- **Severity:** Medium — a server that refuses correctly can be scored non-compliant

### What the check says

The Description requires the server to "return HTTP 403 for any Origin not on an
operator-configured allowlist". The audit asserts the exact code:

```bash
{ [ "$evil" = "403" ] && case "$good" in 2*|3*) true;; *) false;; esac; }
```

### What we found

The assertion is an exact string comparison against `403`. Any other refusal
fails it, including `400 Bad Request`, which is a defensible response to a
disallowed Origin.

### Why it is a problem

The security property the Recommendation protects is that the request is
**refused**. A server that refuses with 400 delivers that property and is scored
non-compliant. This is the false-FAIL pattern: it trains operators to distrust
results.

There is a real argument for pinning 403, since a specific code makes the audit
unambiguous and proves the refusal was an Origin decision rather than a parse
error. If that is the intent, the Description should say that the exact code is
itself the requirement, and the Rationale should explain why.

### How we validated it

Observed across four live servers. Three returned 200, one returned 403. No
server returned an intermediate 4xx, so we have no live example of the
false-FAIL case. The finding rests on reading the audit, not on a reproduction.

Our probe distinguishes the two cases rather than collapsing them. An exact 403
passes. Another refusal fails, but the evidence string states that the refusal
may not be an Origin decision, so a reviewer can tell the difference.

### Suggested fix

Either accept any 4xx as a refusal and note that 403 is preferred, or state
explicitly in the Description that the exact code 403 is part of the
requirement.

---

## Ticket 3 — 2.2 Description contains rewrite notes, not a description

- **Recommendation:** 2.2 Ensure TLS is required for HTTP and plaintext is disallowed
- **Type:** Editorial
- **Severity:** Medium — the field would ship as reviewer notes

### What the check says

The Description field reads, in full:

> The original remediation wrote a here-doc to
> `/etc/nginx/sites-available/mcp.conf` with an unexpanded `$host$request_uri`
> inside single quotes (which would not interpolate as intended) and an
> incomplete `server { listen 443 ssl; # ... }` stub. The audit was sound in
> intent but did not actually verify that weak TLS versions are refused. The
> rewrite adds explicit negative tests (TLS 1.0/1.1 must fail to connect), keeps
> the plaintext and certificate-validity checks, and attributes the
> TLS-1.2-minimum requirement to the MCP Security Best Practices guidance rather
> than the core spec. Description/Rationale/Impact carried over, with the
> spec-attribution corrected.

### What we found

This is a changelog entry describing edits made to an earlier draft. It
describes what changed about the Recommendation. It does not describe the
control an implementer must apply.

### Why it is a problem

A reader of the published benchmark has no access to "the original
remediation", so the text is not actionable. It also references a specific nginx
config path, which implies a single web server. The actual control is stated
only in the Audit Procedure.

### How we validated it

Read the field directly at `benchmark/section2.md:30`. The three sub-tests in
the Audit Procedure are sound and we implemented all three, so this is a text
problem only, not a test problem.

### Suggested fix

Replace the field with a description of the control. The substance is already
determinable from the audit: the server must not serve plaintext HTTP, must
refuse TLS 1.0 and TLS 1.1, must accept TLS 1.2 and above, and must present a
currently valid certificate. Keep the note that the TLS-1.2 minimum comes from
the MCP Security Best Practices guidance rather than the core spec, since that
attribution belongs in the published text.

---

## Ticket 4 — 2.4 title and content disagree

- **Recommendation:** 2.4 Ensure MCP-Protocol-Version header is required for HTTP transports
- **Type:** Editorial
- **Severity:** Medium — the title names a mechanism the audit does not test

### What the check says

The title names the `MCP-Protocol-Version` header. The Description then states
that the version is asserted in `_meta` and pinned by Recommendation 1.1, and
defines this Recommendation's subject as the `Mcp-Method` and `Mcp-Name` routing
headers plus header/body mismatch rejection. Both audit sub-tests operate on the
routing headers: one omits `Mcp-Method`, the other sets `Mcp-Name` to a
different tool than the body names.

### What we found

The title describes version pinning. The body and both sub-tests describe
routing-header enforcement. Version pinning is explicitly delegated to 1.1.

### Why it is a problem

Nothing in the audit tests the header the title names. A reader searching the
benchmark for routing-header requirements will not find this Recommendation, and
a reader who finds it by title will expect version pinning and see something
else. Since 1.1 already covers version pinning, the current title also reads as
a duplicate of 1.1.

### How we validated it

Read the title, Description and both audit sub-tests at
`benchmark/section2.md:115-171`. Our implementation follows the body rather than
the title: it tests the missing routing header and the header/body mismatch, and
asserts HTTP 400 with JSON-RPC `-32020`.

### Suggested fix

Retitle to match the content, for example "Ensure per-request MCP routing
headers are present and consistent with the request body".

---

## Ticket 5 — 2.2 plaintext test accepts a redirect to any destination

- **Recommendation:** 2.2
- **Type:** Gap
- **Severity:** Low — narrow case, but the audit states a stronger guarantee than it checks

### What the check says

```bash
case "$code" in
  200) echo "FAIL: plaintext HTTP served (200)" ;;
  301|302|307|308) echo "PASS: HTTP redirects to HTTPS ($code)" ;;
  000) echo "PASS: plaintext port refused" ;;
  *) echo "REVIEW: HTTP returned $code" ;;
esac
```

### What we found

The audit reports "HTTP redirects to HTTPS" on any 3xx, without reading the
`Location` header. A redirect to another `http://` URL passes.

### Why it is a problem

The claim in the PASS message is not the thing tested. A server that redirects
`http://host/` to `http://host/mcp` satisfies the check while still serving
plaintext. The credential-bearing request would then travel unencrypted, which
is the exposure the Recommendation exists to prevent.

### How we validated it

Observed four distinct plaintext behaviors across live servers, which is itself
worth recording:

| Server | `http://` response |
|--------|--------------------|
| DeepWiki | port refused (connection timeout) |
| Linear | 403 |
| Sentry | 200, plaintext served |
| Stripe | 301 redirect |

Only Stripe exercises the redirect branch, and its `Location` does point at
`https://`. So we have no live example of the bad case. The finding comes from
reading the audit. Our probe records the status code and does not follow the
redirect, so a future run can inspect `Location` without a second request.

Note that Linear's 403 falls into the `REVIEW` branch, which is a fifth
behavior the audit does not classify.

### Suggested fix

Read the `Location` header on a 3xx and require an `https://` scheme. Consider
classifying a 4xx refusal, such as Linear's 403, as a pass rather than REVIEW,
since it does not serve plaintext content.
