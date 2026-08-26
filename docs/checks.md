# Implemented checks

What each check tests, how this probe implements it, and how the servers we
tested held up.

The probe is an external, black-box client: it sees only what any client
connecting to the server by domain can see. Where a benchmark check depends on
operator-side artifacts — audit logs, an enterprise registry, host process
inventory — only the externally observable part is implemented, and the rest is
reported rather than guessed at. Each check's reduction is stated below and
repeated in the evidence string at runtime, so a report never implies coverage
that was not achieved.

## Verdicts

| Verdict | Meaning |
|---------|---------|
| `PASS` | The server satisfied the externally observable part of the check. |
| `FAIL` | The server did not satisfy it. |
| `N/A` | The entire subsection is operator-side and we defined no check of our own for it. |
| `NO-REV` | The check tests a mechanism that exists only in a protocol revision this server does not negotiate. Nothing about the run can change this. |
| `UNKNOWN` | This run could not decide, and a later run might. No baseline recorded yet, or no event arrived inside the wait window. |
| `ERROR` | The probe itself failed to reach a verdict. |

`NO-REV` and `UNKNOWN` are deliberately distinct. `UNKNOWN` is a property of the
run. `NO-REV` is a property of the server, and it clears only when the server
adopts the revision.

## Section 1 — protocol and capability integrity

### 1.1 Unapproved or absent protocol version is rejected

**Level:** L1

**What the check requires.** The server must reject a request whose asserted
protocol version is absent or outside the approved allowlist, instead of falling
back to a default revision.

**How the probe implements it.** Two requests per server: one asserting a bogus
version (`2024-01-01`), one asserting none. Both must be rejected.

The mechanism for asserting the version differs by revision, so the probe
detects which the server speaks and adapts:

- 2026-07-28 — per-request `_meta` field `io.modelcontextprotocol/protocolVersion`
- 2025-11-25 and earlier — the `MCP-Protocol-Version` HTTP header

**Reduction.** The benchmark also requires the version to be logged. Log
inspection is operator-side, so only the rejection half is implemented.

### 1.2 Advertised capabilities match the recorded baseline

**Level:** L1

**What the check requires.** Advertised capabilities must not grow without
review. New capabilities are unauthorized drift.

**How the probe implements it.** Capabilities and the tool, resource and prompt
inventory are captured from the `initialize` result and the `*/list` methods,
then compared against a baseline stored per endpoint URL under
`~/.cis-mcp-probe/`. Capture or refresh it with `--update-baseline`.

**Reduction.** The benchmark expects an operator-maintained approved-capability
baseline. The probe has no access to one, so it records its own and reports drift
relative to that. Until a baseline exists for a server, the verdict is `UNKNOWN`.
A run with `--update-baseline` is also `UNKNOWN`: capturing a baseline compares
nothing, so that run cannot decide.

### 1.3 Capabilities added via listChanged are not silently invocable

**Level:** L2

**What the check requires.** A capability newly advertised through a
`listChanged` notification must be held pending re-approval, not immediately
invocable.

**How the probe implements it.** Waits briefly for a `listChanged` notification,
re-lists tools to identify what was added, then attempts to invoke the new tool.
Reaching the tool means it was invocable without re-approval, which is a failure.
A JSON-RPC `-32602` invalid-params error counts as reaching the tool, because the
server had to resolve the tool name and validate arguments to produce it.

**Reduction.** The MCP specification does not define which error code a
conforming server returns when it denies a pending capability. The probe
therefore treats any other error as a probable denial and says so in the
evidence, so a reviewer can confirm it was an authorization denial rather than
method-not-found. If no notification arrives inside the window, the verdict is
`UNKNOWN`.

### 1.4 Server exposes non-empty identity metadata

**Level:** L1

**What the check requires.** The server identity must be capturable and
validatable against an asset inventory.

**How the probe implements it.** Confirms the `initialize` result carries a
non-empty `serverInfo.name`, and records the version.

**Reduction.** Reconciling that identity against an enterprise inventory is
operator-side. Only the externally observable half — that the server asserts an
identity at all — is implemented.

## Section 2 — transport security

### 2.1 stdio is preferred for local, single-user servers

**Level:** L1 · **Benchmark assessment status:** Manual

**What the check requires.** Local and single-user deployments should use the
stdio transport. Every server on a network transport needs a documented
operational justification on file.

**How the probe implements it.** It does not, and reports `N/A` with the detected
transport as evidence.

**Why.** Both halves are outside a remote client's view. The audit inventories
service units and their listening sockets, which needs host access, and then
requires a manual determination of the configured transport from the unit's
`ExecStart` or the client configuration. The check is also self-defeating
remotely: any server reached by domain is a network transport by construction, so
the answer would be predetermined.

### 2.2 TLS is required and plaintext is disallowed

**Level:** L1 · **Benchmark assessment status:** Automated

**What the check requires.** The server must not serve plaintext HTTP, must
refuse TLS 1.0 and TLS 1.1 while accepting TLS 1.2 and above, and must present a
currently valid certificate.

**How the probe implements it.** Three sub-tests, aggregated into one verdict.
Any failing sub-test fails the check, and every sub-result is kept in the JSON
`details`.

- **Plaintext.** A `GET http://host/` without following redirects. A 200 fails. A
  refused connection or a `426 Upgrade Required` passes. A 3xx passes only if its
  `Location` header names an `https://` target: a redirect to another plaintext
  URL still carries the next request in cleartext. Redirects are deliberately not
  followed, because following one would hide the destination behind a final 200.
- **Weak TLS.** One handshake per legacy revision, pinned so that minimum equals
  maximum, so the server cannot negotiate upward. A completed handshake means the
  server accepted that revision, which fails.
- **Certificate.** Expiry parsed from the chain observed during the main
  handshake, reported as days remaining.

**Implementation note.** The weak-TLS sub-test sets the client cipher string to
`DEFAULT@SECLEVEL=0`. Modern OpenSSL refuses to *offer* TLS 1.0 and 1.1 by
default. Without lowering the level, the handshake fails inside our own client
and is indistinguishable from the server refusing, which would make the check
pass against every server. With it, a failure is attributable to the server.

### 2.3 Authentication propagates through proxies on request-scoped SSE responses

**Level:** L2 · **Benchmark assessment status:** Manual

**What the check requires.** Authentication must be enforced before a
request-scoped SSE response stream is established, and enforcement must hold at
every proxy hop, so an unauthenticated request cannot reach a streamed response.

**How the probe implements it.** Sends the same request twice, once without a
credential and once with the cached bearer token. The unauthenticated request
must be refused, the authenticated one accepted, and the probe reads the response
`Content-Type` to see whether the reply was an SSE stream.

**Verdicts.** `PASS` when the unauthenticated request is refused and the
authenticated one is accepted with an SSE-framed response. That is what the
benchmark's own audit prints PASS for. `FAIL` when an unauthenticated request is
accepted — no proxy topology makes that compliant. `UNKNOWN` when the server
answers the authenticated request with a non-streamed response, since the
SSE-specific assertion was then never exercised and a re-run against a streaming
tool could decide it.

**Reduction: per-hop forwarding is not verified.** The benchmark notes that a
wire status code observed at the proxy does not prove the credential reached the
final upstream, because a proxy can authenticate, strip the credential, and
forward an unauthenticated request that the backend answers successfully.
Confirming arrival needs backend-side evidence: an access-log entry recording the
credential or a derived identity, or per-hop trace data. The probe states this
caveat in its evidence on every run rather than downgrading the verdict.

**Reduction.** The benchmark audit invokes a server-specific safe streaming tool.
That name is not discoverable from outside, and invoking a guessed tool against a
production server has side effects. The probe uses `tools/list`, which exercises
the same authentication path without them. The cost is that the response is not
guaranteed to be streamed, so the SSE-specific assertion is reported as
unexercised rather than forced.

A server that requires no authentication reports `FAIL`: an unauthenticated
request reaches a response, which is the condition this check tests. The
benchmark's own audit prints FAIL for the same observation.

### 2.4 Required request metadata headers are present and consistent with the body

**Level:** L1 · **Benchmark assessment status:** Automated

**What the check requires.** Under 2026-07-28, selected request body fields are
mirrored into HTTP headers so gateways can route without parsing the body.
`MCP-Protocol-Version` and `Mcp-Method` are required on every request.
`Mcp-Name` is required on `tools/call`, `resources/read` and `prompts/get`.
Values that cannot be represented as plain ASCII use the specification's Base64
sentinel format `=?base64?...?=`, which the server must decode before comparing
to the body. A missing or disagreeing header must be rejected with HTTP 400 and
JSON-RPC error `-32020` (HeaderMismatch).

**How the probe implements it.** Four sub-tests, all required to pass.

- `tools/list` with no `Mcp-Method`. `Mcp-Name` is correctly not required here.
- `tools/call` with `Mcp-Method` but no `Mcp-Name`.
- `tools/call` whose `Mcp-Name` header names a sentinel value while the body
  names a real tool.
- `tools/call` whose `Mcp-Name` is a Base64 sentinel that decodes to a value
  different from the body, which must also be rejected.

**Attribution rule.** A 400 that does *not* carry `-32020` is reported as `ERROR`,
not `PASS`. Gateways legitimately reject with a plain 400 and the specification
permits intermediaries to omit the JSON-RPC error body, so such a response is not
attributable to the MCP implementation. A `-32022`
(UnsupportedProtocolVersion) response is also `ERROR`: it means the endpoint
rejected the probe's own protocol version, so the header test never ran.

**Reduction.** The benchmark's decode-acceptance half — that an encoded value
which *matches* the body must be accepted — is not exercised, because a
successful request would invoke the tool. The probe tests only the
encoded-disagreement direction and states the omission in its evidence. If the
server exposes no tool at all, the three `tools/call` probes cannot be built and
the check reports `UNKNOWN`.

**Revision gate.** The metadata headers and the `-32020` code exist only in
2026-07-28. Against a server that will not negotiate that revision the probe
returns `NO-REV` and records both the required and the negotiated revision,
rather than reporting a failure for a mechanism that is simply absent.

### 2.5 Origin header is validated on all requests

**Level:** L1 · **Benchmark assessment status:** Automated

**What the check requires.** The server must validate `Origin` on every request
and refuse any Origin not on an operator-configured allowlist, returning HTTP
403. Enforcement must apply to the request itself, not only to a CORS preflight.

**How the probe implements it.** Three legs, identical except for the `Origin`
header, with no preceding `OPTIONS` request, so the test exercises the request
path rather than a preflight.

- Hostile `Origin: https://cis-rebinding-probe.example` must return 403.
- An allowlisted Origin must be accepted.
- No `Origin` at all, recorded for compatibility awareness. Per the benchmark,
  an absent Origin does not determine compliance, since non-browser MCP clients
  routinely send none.

The probe attaches the bearer token when it has one. On a server that requires
authentication, an unauthenticated probe returns 401 for every Origin, which
would hide whether Origin is validated at all.

**Attribution rule.** If any leg returns 400, the request was rejected before
Origin was evaluated — most likely a routing-header mismatch — so the probe
reports `ERROR` rather than reading it as an Origin decision.

**Reduction.** The allowlist is operator-configured and not externally
discoverable, so the benchmark's allowed-Origin leg cannot be reproduced exactly.
The probe substitutes the server's own origin and says so in the evidence. The
security-relevant direction, that a hostile Origin is refused, is fully decided.
If the hostile Origin is correctly refused but the stand-in is also refused, the
verdict is `UNKNOWN` rather than a claimed pass.

A refusal with a status other than 403 fails, but the evidence notes that the
refusal may not be an Origin decision, so a reviewer can tell the two apart.

## Results against tested servers

Probed on 2026-08-12 against hosted MCP servers, using the checks as described
above.

| Server | Endpoint | Auth | Protocol negotiated |
|--------|----------|------|---------------------|
| DeepWiki | `mcp.deepwiki.com` | none | 2025-11-25 |
| Linear | `mcp.linear.app` | OAuth | 2025-11-25 |
| Sentry | `mcp.sentry.dev` | OAuth | 2025-11-25 |
| Stripe | `mcp.stripe.com` | OAuth | 2025-03-26 |

| # | Check | deepwiki | linear | sentry | stripe |
|---|---|---|---|---|---|
| — | **Negotiated revision** | **2025-11-25** | **2025-11-25** | **2025-11-25** | **2025-03-26** |
| 1.1 | Unapproved or absent protocol version rejected | FAIL | FAIL | FAIL | FAIL |
| 1.2 | Capabilities match recorded baseline | UNKNOWN | UNKNOWN | UNKNOWN | UNKNOWN |
| 1.3 | listChanged capabilities not silently invocable | UNKNOWN | UNKNOWN | UNKNOWN | UNKNOWN |
| 1.4 | Server exposes non-empty serverInfo | PASS | PASS | PASS | PASS |
| 2.1 | stdio preferred for local, single-user servers | N/A | N/A | N/A | N/A |
| 2.2 | TLS required, plaintext disallowed | PASS | PASS | **FAIL** | PASS |
| 2.3 | Auth propagates through proxies on SSE responses | **FAIL** | PASS | PASS | UNKNOWN |
| 2.4 | Request metadata headers present and consistent | NO-REV | NO-REV | NO-REV | NO-REV |
| 2.5 | Origin validated on all requests | **FAIL** | **FAIL** | PASS | **FAIL** |

### Reading the results

- **1.1 — 0/4 pass.** Every server accepts a request with the protocol version
  absent and defaults it. Three reject a bogus version. Stripe, on the older
  2025-03-26 revision, accepts a bogus version too, so it does not validate the
  version at all.
- **1.2 and 1.3 — undecided.** 1.2 had no baseline recorded for these servers.
  1.3 saw no `listChanged` notification inside the wait window, so there was
  nothing to test.
- **1.4 — 4/4 pass.** Every server asserts a name and version.
- **2.2 — 3/4 pass.** Plaintext handling differs on every server: DeepWiki
  refuses the port, Linear answers 403, Stripe redirects with 301, Sentry serves
  content with 200. Sentry also negotiates TLS 1.0 and TLS 1.1, with cipher
  `ECDHE-RSA-AES128-SHA` on the TLS 1.0 handshake. The other three refuse both
  legacy revisions, which shows the sub-test discriminates rather than passing
  everything.
- **2.3 — 2/3 decided pass.** Linear and Sentry refuse the unauthenticated
  request with 401, accept the authenticated one with 200, and return
  `text/event-stream`, so the SSE assertion was exercised and both pass. Stripe
  answers with plain JSON, so that assertion could not be exercised and the
  verdict is UNKNOWN. DeepWiki requires no authentication at all, so an
  unauthenticated request reaches a response: FAIL.
- **2.4 — `NO-REV` everywhere.** No live server negotiates 2026-07-28, so the
  routing headers and the `-32020` error do not exist to test. These verdicts
  will resolve on their own as servers adopt the revision.
- **2.5 — 1/4 pass.** DeepWiki, Linear and Stripe all accept
  `Origin: http://evil.example.com` and answer 200. Sentry is the only server
  that returns 403.

Sentry is the inverse of the other three: the only server that validates Origin,
and the only one that serves plaintext HTTP and accepts legacy TLS. No server
passes both 2.2 and 2.5.

### Detail per check

**2.2 TLS and plaintext**

| Server | Plaintext `http://` | TLS 1.0 / 1.1 | Negotiated | Cert expires in |
|--------|---------------------|---------------|------------|-----------------|
| DeepWiki | port refused | refused | TLSv1.3 | 83d |
| Linear | 403 | refused | TLSv1.3 | 65d |
| Sentry | **200 served** | **both accepted** | TLSv1.3 | 69d |
| Stripe | 301 redirect | refused | TLSv1.3 | 50d |

**2.3 Authentication**

| Server | Unauthenticated | Authenticated | Response framing |
|--------|-----------------|---------------|------------------|
| DeepWiki | n/a (no auth) | n/a | n/a |
| Linear | 401 | 200 | SSE |
| Sentry | 401 | 200 | SSE |
| Stripe | 401 | 200 | plain JSON |

**2.5 Origin**

| Server | Hostile Origin | Own origin (stand-in) | Verdict |
|--------|----------------|------------------------|---------|
| DeepWiki | 200 | 200 | FAIL |
| Linear | 200 | 200 | FAIL |
| Sentry | **403** | 200 | PASS |
| Stripe | 200 | 200 | FAIL |

### Servers not covered

- **Notion** (`mcp.notion.com`) could not be probed. During testing the host was
  reached through a TLS inspection proxy, so the certificate chain presented was
  not Notion's. Any transport verdict would have described the proxy rather than
  the server, so it is excluded rather than reported.
- **Atlassian** exposes its endpoint under `/v1/...`, which the probe's endpoint
  discovery does not try.
