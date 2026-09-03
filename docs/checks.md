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

### 1.1 Served protocol revisions are pinned and malformed assertions are rejected

**Level:** L1 · **Benchmark assessment status:** Automated

**What the check requires.** An endpoint must serve only approved protocol
revisions, and must reject a request whose asserted version is unapproved, absent,
or stated inconsistently, rather than processing it under a default revision.

**How the probe implements it.** Five legs, each reported separately in the
evidence and in `details["legs"]`.

| Leg | Probe | Conforming outcome |
|---|---|---|
| 1.1a | the revisions the endpoint serves, against a `2025-06-18` floor | every served revision at or after the floor |
| 1.1b | `tools/list` asserting `2024-01-01` | `-32022` at HTTP 400 |
| 1.1c | `tools/list` with no `MCP-Protocol-Version` header | `-32020` at HTTP 400 |
| 1.1d | `tools/list` with a correct header and no version in `_meta` | `-32602` at HTTP 400 |
| 1.1e | `tools/list` whose header and `_meta` versions disagree | `-32020` at HTTP 400 |

Leg 1.1a answers one question two ways: is any revision earlier than the floor
served. Where the server negotiates 2026-07-28 it reads the full `supportedVersions`
array from `server/discover`. Otherwise it offers each sub-floor revision on its own
`initialize` and treats an echo of the requested revision as positive evidence that
the endpoint serves it, which the specification requires a server to send only for a
revision it supports. Both routes measure what the endpoint *serves*, which is what
this recommendation asks for rather than what it accepts per request.

A revision whose probe could not be sent is reported rather than dropped: a clean
result over an incomplete set would otherwise read as compliant when the revision
that never answered was the offending one.

The mechanism for asserting a version differs by revision, so the probe adapts:

- 2026-07-28 — the `MCP-Protocol-Version` header and the `_meta` field
  `io.modelcontextprotocol/protocolVersion`, which must agree
- 2025-11-25 and earlier — the header alone

**Reductions.** Three, and the first can be generous rather than strict.

1. The approved allowlist is an operator artifact the probe cannot read, so leg
   1.1a compares against the `2025-06-18` floor this recommendation sets. A server
   serving only revisions at or after the floor passes, even where an operator's
   own allowlist is narrower. The evidence says the allowlist was not read.
2. Legs 1.1d and 1.1e test the header-versus-`_meta` agreement that only
   2026-07-28 defines, so they report `NO-REV` below it. A leg reporting `NO-REV`
   is excluded from the check's verdict rather than lowering it, and the evidence
   records which legs were not reached.
3. The recommendation also requires the asserted version to be logged on every
   request. That is read from a deployment audit log, so it is not probed.

A rejection carrying an unexpected error code passes with the code named, since the
request was still refused. A bare rejection with no protocol error body is `ERROR`,
not `FAIL`: it may have come from a gateway that never reached the origin.

### 1.2 Advertised capability configuration matches the recorded baseline

**Level:** L1 · **Benchmark assessment status:** Manual

**What the check requires.** The capability configuration an endpoint advertises
must not exceed or differ from an approved baseline. Every nested setting counts,
not only the names, because a configuration can change materially without any name
being added.

**How the probe implements it.** The capability object is flattened to one entry
per leaf with its value, then compared against a baseline stored per endpoint URL
under `~/.cis-mcp-probe/baselines/`. Capture or refresh it with `--update-baseline`.

| Observation | Verdict |
|---|---|
| a leaf advertised and not baselined, or one whose value changed | `FAIL` |
| some baselined leaves withdrawn, others still advertised | `PASS`, withdrawal named |
| every baselined leaf withdrawn and none advertised | `UNKNOWN` |
| otherwise | `PASS` |

Comparing values rather than names is what lets the check see `resources.subscribe`
flip from `false` to `true`, or an extension limit rise. A name-level comparison
reports no drift for either.

Total withdrawal is `UNKNOWN` rather than `PASS` because a run where everything
vanished more likely read nothing than observed a reconfiguration.

**Reductions.** The probe has no access to a registry-approved baseline under
change control, so it records its own and reports drift against that. Four distinct
conditions give `UNKNOWN`, and the evidence names which applies: no baseline
recorded yet, a baseline written before capability leaves were captured, a baseline
whose capability object was read from a different source than this run's, and total
withdrawal. The first three are cleared by `--update-baseline`.

Tool, resource and prompt name drift is reported as leg 1.2b and gates no verdict.
This recommendation's audit compares the capability configuration object, and a tool
name is not part of that object. Check 1.3 invokes such a tool and decides whether
it was gated.

### 1.3 A capability advertised beyond the baseline is denied until re-approved

**Level:** L2 · **Benchmark assessment status:** Manual

**What the check requires.** A capability advertised beyond the approved baseline
must be held pending an explicit re-approval, and an attempt to invoke it must be
denied.

**How the probe implements it.** The staged capability is a tool advertised now and
absent from the recorded baseline. A control probe on a tool present in both the
baseline and the current inventory runs first, so a denial of the staged tool is
attributable to a gate rather than to the probe. `PASS` requires the denial message
to name a pending or unauthorized state, on either carrier a denial can arrive by: a
JSON-RPC error from a gateway, or a result carrying `isError` from a gate inside the
server's own tool handling.

Reaching the staged tool is a failure. A `-32601` method-not-found or `-32602`
invalid-params error is `UNKNOWN` instead: the staged name did not resolve, or its
arguments were rejected, so nothing about a staging gate was tested.

**Arguments.** They cannot be derived from a schema safely, so they come from a
`tool_arguments` entry in `~/.cis-mcp-probe/probe-inputs.json`, keyed by tool name.
Without one, both calls carry no arguments, and a tool whose arguments are required
then answers with a validation error indistinguishable from a gate denial. That is
why the control probe failing is `ERROR` and why an unmatched rejection on the
staged tool is `UNKNOWN` — neither is read as compliance.

**Reductions.** The approved baseline is the one the probe recorded itself, as in
1.2. The recommendation also requires every capability change to be logged with a
diff and an approval state, which is read from a deployment audit log and is not
probed.

**When this check decides.** Only where a tool appears beyond the recorded
baseline. Against a server whose inventory is unchanged between runs there is
nothing staged to gate, and `UNKNOWN` is the correct answer rather than a limitation.

### 1.4 Server identity matches the recorded identity

**Level:** L1 · **Benchmark assessment status:** Automated

**What the check requires.** Identity metadata that servers assert must be
captured and cross-referenced against the approved identities in an enterprise
registry. An observed identity absent from that registry is unauthorized asset
expansion.

**How the probe implements it.** The asserted `name` and `version` are read as one
pair and compared against the pair recorded for the endpoint. A pair absent from
the record is an unregistered identity and fails; a matching pair passes; no record
yet, or no identity asserted, is `UNKNOWN`.

The identity is read from the `initialize` result's `serverInfo`, where the schema
requires it. From 2026-07-28 a server asserts identity per response in `_meta`
instead. Reading it from there is not yet implemented: the probe holds one baseline
record per endpoint and several checks write it, so a check that sourced the identity
differently from the others would have its value overwritten by whichever wrote last,
and the next run would read the difference as drift.

A server that legitimately changes version fails this check until the new pair is
recorded with `--update-baseline`. That matches the recommendation, under which a
new `name|version` pair must be re-approved in the registry before it is compliant.

**Reductions.** The registry export is one the probe recorded itself, so the check
decides identity *drift* rather than conformance to an approved inventory, and a
registered identity never observed is not reported. Client identity is not compared:
this probe is the client, so comparing it would measure the probe. Whether the
asserted identity is well formed is reported as leg 1.4a and gates no verdict — the
recommendation's audit names no malformed-identity failure, and the schema makes the
per-response identity optional from 2026-07-28.

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

**TLS interception makes this check undecidable, and the probe detects it.** The
certificate observation is attempted against the bundled public CA set first. A
chain that verifies there is the server's. A chain that fails there and then
verifies against the machine's own trust store was signed by a CA only this
machine trusts, which is an inspecting proxy. The check then reports `UNKNOWN`
and names the observed issuer, because the certificate and the negotiated version
describe the proxy, and the plaintext leg is unattributable too if the proxy
upgrades the scheme. Re-run from a network without interception to decide it.

Verifying against the bundled set is the test itself, rather than matching CA
names against a list, which would need maintenance and would miss any proxy not on
it.

**Every other fetch verifies against the operating system's trust store**, so a host
behind an inspecting proxy is reachable with no setup: the corporate CA is normally
already in that store. This covers the MCP session too, which builds its own HTTP
client. `SSL_CERT_FILE` still works and is no longer required.

The two trust settings are deliberately different, and the difference is the whole
detection. Exactly one context — the certificate probe above — ignores the machine's
store, which is what makes a locally-trusted CA visible. Replacing the interpreter's
default context globally would collapse the two and report every intercepted host as
an ordinary one.

If neither attempt verifies, the host is unreachable to the probe. The evidence names
both plausible causes: a certificate that is expired or issued for another name, or a
proxy whose CA is missing from the machine's store, for which `SSL_CERT_FILE` is the
remedy.

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

## Section 3 — authentication and authorization

Ten recommendations. Six are probed on the wire. Four are entirely operator-side
and report `N/A`, naming the audit halves they would need.

### Credential handling during a Section 3 run

Three of these checks follow a URL the audited server itself chose, and one
presents a live bearer token to a host derived from that URL. Two rules bound
that.

- **Every server-supplied URL passes a host guard before it is fetched.** A URL
  naming a loopback, link-local, private or shared-address-space host is refused,
  as is every IPv6 literal and every non-dotted-quad IPv4 encoding. Both
  encodings defeat a naive guard: `https://[fd00::1]/x` truncates to `[fd00`
  under a pattern-based host parser, and `socket.inet_aton` resolves
  `2852039166`, `0x7f000001` and `127.1` to loopback and link-local addresses
  that `ipaddress.ip_address` rejects outright.
- **A bearer token is released only over https, and only to the audited
  endpoint's own registrable domain.** The registrable domain is computed from
  the bundled Public Suffix List, so a tenant on a shared hosting domain owns its
  own name and not its neighbours'. Check 3.3.1 records every candidate the gate
  refused, with the reason.

Check 3.3.5 registers real OAuth clients at the audited authorization server. Those
clients are cached under a scratch key of their own, never the key holding the
working token: a registration written over that key invalidates the cached token
and forces a fresh interactive login.

Check 3.3.1's `3.3.1b` leg spends the cached refresh token, so it runs as the last
credential operation of the run. An authorization server that rotates refresh
tokens on use replaces the cached one during that request, and the pair it returns
is bound to a resource the audited server does not serve. The probe never caches
that pair. Instead it spends the rotated token on one further refresh naming the
audited resource, and caches that response, so the stored credential is bound to
the right resource by construction. The leg states in its evidence whether the
restore succeeded. Without it, every run would end with a spent refresh token and
the next run would need an interactive login.

### 3.1.2 OIDC/OAuth 2.1 or short-lived API tokens are used for remote servers

**Level:** L1 · **Benchmark assessment status:** Manual

**What the check requires.** A remote server must refuse an unauthenticated
request with a 401 challenge naming `resource_metadata`, and the access token it
issues must be short-lived.

**How the probe implements it.** Four legs, of which two decide the verdict.

- `3.1.2a` — the unauthenticated `initialize` round-trip, recorded once before any
  check runs, must have been refused, and its `WWW-Authenticate` challenge must
  name `resource_metadata`. A challenge without it gives a client nowhere to look
  for how to authenticate.
- `3.1.2b` — the issued lifetime against a 3600-second baseline, read from the
  token response's `expires_in` or from the token body. It is never computed from
  the wall clock, so a token read late in its life is not mistaken for a short
  one.
- `3.1.2c` and `3.1.2d` — the authorization server's advertised
  `authorization_response_iss_parameter_supported`, `registration_endpoint` and
  `token_endpoint_auth_methods_supported`, recorded as evidence. Neither leg ever
  moves the verdict.

**Note on `3.1.2a`.** Endpoint detection accepts a candidate only on a 200 or a
401, so a reachable server's recorded status is always one of the two. "Refused"
is therefore identical to "authentication was required at all", and a 403 that
would pass with a caveat cannot arise here.

**Reduction.** An opaque token whose response carried no `expires_in` has no
readable lifetime, so `3.1.2b` records `UNKNOWN` and the check reports `UNKNOWN`
rather than passing on an unread value.

### 3.1.1 stdio server credentials are sourced from the environment or OS credential store

**Level:** L1 · **Benchmark assessment status:** Automated

**What the check requires.** A stdio server's credentials must be injected from
the environment or an OS secret store at launch, never as a command-line argument
and never through an interactive browser flow on the stdio connection.

**How the probe implements it.** It does not, and reports `N/A` with the detected
transport as evidence.

**Why.** The audit reads the stdio server's launch configuration and process
environment. Neither exists for a server reached over the network, and a server
reached by domain is not on the stdio transport.

### 3.2.1 Per-tool authorization policies are enforced

**Level:** L2 · **Benchmark assessment status:** Manual

**What the check requires.** Deny-by-default per-tool authorization, keyed to the
identity in the authenticated token and an operator-controlled tool risk
classification, with every allow and deny decision logged.

**How the probe implements it.** It does not, and reports `N/A` with the number
of tools listed as evidence.

**Why.** Three parts of the audit are all out of reach. It compares a
least-privileged identity against an authorized one, which needs a second
credential the probe cannot mint. Its positive control really invokes a
privileged tool, which the probe will not do for the side effect. Its
authoritative record is the server's authorization decision log, which no remote
client can read.

### 3.2.2 Token passthrough to downstream APIs is forbidden

**Level:** L1 · **Benchmark assessment status:** Manual

**What the check requires.** The token's `aud` claim must name only the resource
server the client asked for, so the token cannot be passed through to another
resource.

**How the probe implements it.** It reads the `aud` claim and compares every
entry against the canonical resource URI. The canonical URI is derived from the
endpoint, unless the protected-resource document advertises a value that is a
hierarchical parent of it under RFC 8707, in which case the advertised value
stands. One trailing slash is tolerated on either side, because a root-detected
endpoint carries a slash that an authorization server commonly omits.

**Verdicts.** An entry beyond the canonical resource fails, with the extra
entries named. The evidence states the limit of that finding: the token alone
does not say whether an extra entry is a genuine downstream API or passthrough.

**Reduction.** An `aud` claim lives only in a JWT body. An opaque token, or a JWT
carrying no `aud`, records `UNKNOWN` and never `FAIL` — reading an unobservable
claim as a missing audience would fail every server that issues an opaque token.
A server that offers no OAuth at all reports `N/A`: it issues no token whose
audience could be confined.

### 3.3.1 OAuth tokens are audience-bound to the MCP server using Resource Indicators

**Level:** L1 · **Benchmark assessment status:** Automated

**What the check requires.** The token's audience must name the resource that
requested it, the audited server must refuse a token minted for another
resource, and the authorization server must refuse a token request naming a
resource it does not serve.

**How the probe implements it.** Three legs, in this order.

- `3.3.1a` — the `aud` claim names the canonical resource URI.
- `3.3.1c` — a downstream identity endpoint must refuse the token. Candidate hosts
  are derived from the endpoint host, by replacing its leftmost label with `api`
  and by dropping that label, each crossed with five generic identity paths.
  Every candidate is fetched twice, with the token and without it, because a
  guessed path may be public and a bare 200 with the token would then prove
  nothing. A 401 with the token is a refusal and passes. A 200 or a 403 with the
  token, where the status without it differs, is acceptance and fails — a 403
  means the credential authenticated and was only then denied authorization.
  Redirects are not followed, so a redirect off a guessed host cannot carry the
  credential onward.
- `3.3.1b` — the refresh grant asks the authorization server for a token bound to
  `https://cis-probe.invalid/wrong-audience`, a name RFC 2606 reserves so no
  server can legitimately serve it. If a token is minted, it is presented to the
  audited endpoint alongside a control request carrying the probe's own token.
  Refusal of the minted token while the control is accepted passes. Acceptance
  fails. If that request rotated the cached refresh token, the leg re-establishes
  the chain for the audited resource before it compares anything.

**Attribution rules.** If the control request is refused too, the refusal of the
differently-bound token is not attributable to audience validation, so the leg
records `UNKNOWN`. If the authorization server refuses to mint the token —
`invalid_target` is the conforming answer — the leg also records `UNKNOWN`: that
is correct behaviour by the authorization server, and it leaves the audited
server's own audience validation untested.

**Reduction.** `3.3.1c`'s candidates are guesses, not downstream APIs discovered
from the server, and the credential-release gate refuses every candidate off the
endpoint's registrable domain, so a genuine downstream API hosted elsewhere is
never reached. The derived hosts are unavailable below three labels, so a
two-label endpoint host yields no derived candidate at all. `3.3.1b` cannot confirm
that an opaque minted token really carries the resource it asked for, rather than
the authorization server having ignored the parameter.

### 3.3.5 Confused-deputy safeguards are applied for static OAuth client IDs

**Level:** L2 · **Benchmark assessment status:** Manual

**What the check requires.** A server that fronts a separate authorization server
on one static client id must accept only a `redirect_uri` registered to the
client id in the request, bind every callback to state it issued itself, and
obtain consent for each client id the first time it sees one.

**How the probe implements it.** One precondition leg and three test legs.

- `3.3.5-pre` — whether the recommendation applies. A server whose authorization
  endpoint is on its own host authorizes for itself and fronts nothing, so the
  question is settled from metadata alone and no client is registered. Otherwise
  the probe registers two clients and compares the client id each authorize
  response carries onward. One shared value means the server fronts a separate
  authorization server on a static client id, and the recommendation applies.
- `3.3.5a` — an authorize request varying only `redirect_uri`, to a host under
  `.invalid` that can never resolve, must be refused while the registered value
  is accepted. A redirect carrying an authorization code to the varied target
  fails.
- `3.3.5b` — the callback must refuse a fabricated code carrying a state that was
  never issued. A nonsense path on the same origin is fetched as a control.
- `3.3.5c` — a client id the authorization server has never seen must meet a
  consent step, rather than being handed straight to the upstream authorization
  server on the shared client id.

**Attribution rules.** `3.3.5b`'s control is a parameter of the decision, not a
comparison made afterwards, because the same status means opposite things
depending on it. A server that answers a catch-all 200 for any unknown path never
reached a callback handler, and reading that as a handler accepting the code would
invent a finding. A bare 4xx with no OAuth error body says nothing either,
because a gateway serves those too. On `3.3.5a`, a refusal of the varied value
counts only if the registered value was itself accepted.

**Reduction.** No interactive login is performed, so only the part of each
safeguard that fires before authentication is observed. A `redirect_uri` or a
client id validated only after the user authenticates is not reachable from here.
`3.3.5b` sends a fabricated code, so the invalid code alone may explain a refusal
that the missing state would also have earned.

### 3.2.3 Server-provided tool annotations are not relied upon for authorization or HITL gating

**Level:** L1 · **Benchmark assessment status:** Manual

**What the check requires.** Authorization and human-in-the-loop gating must key
on an operator-controlled tool risk classification, not on `readOnlyHint`,
`destructiveHint`, `idempotentHint` or `openWorldHint`.

**How the probe implements it.** It does not, and reports `N/A` with a count of
how many listed tools assert each of the four hints.

**Why.** The requirement binds whoever consumes the annotations — the client,
host or gateway policy — not the server that publishes them. A server that
advertises a hint is conformant; trusting that hint for a gating decision is the
defect, and that decision is made outside the audited server. The gating
configuration and the risk classification it must key on are both operator-side.

### 3.3.4 OAuth scopes are minimized and elevated progressively

**Level:** L2 · **Benchmark assessment status:** Manual

**What the check requires.** A client must hold only the scopes its tools need.
Wildcard and admin-tier scopes must be absent from the issued token and from the
advertised `scopes_supported`, an out-of-scope call must be refused before it
executes, and a client must be able to discover which scopes to request.

**How the probe implements it.** Six legs.

- `3.3.4a` — the granted scopes are readable at all.
- `3.3.4b` — no granted scope is a wildcard.
- `3.3.4c` — the granted set has not grown since the recorded baseline.
- `3.3.4d` — the advertised `scopes_supported` carries no wildcard and no
  admin-tier scope.
- `3.3.4e` — a tool the operator names as outside the grant is refused rather than
  executed. The tool name and its arguments both come from the operator's input
  file; no tool is invented and no other tool is called.
- `3.3.4f` — at least one of three scope-discovery sources carries a value: the
  challenge `scope` parameter, the protected-resource `scopes_supported`, or the
  authorization server's own `scopes_supported`.

**Attribution rules.** `3.3.4f` fails only when all three sources are absent *and*
all three were observed. A protected-resource path that never answered, or an
advertised authorization server whose metadata was never read, leaves the leg
`UNKNOWN`, because "we could not read it" is not "it advertises nothing". A
challenge that disagrees with the advertised set is still a discovery path; the
disagreement is reported, not failed. On `3.3.4e`, a refusal counts only when it
names an authorization failure — a rejected argument or an unknown tool name says
nothing about scope, so the leg stays `UNKNOWN`.

**Reduction.** This check reads the wire and a baseline the probe recorded
itself. The operator's documented justification for a scope is not readable from
a client, so a documented exception for a flagged scope would change `3.3.4b` and
`3.3.4d`. A server offering no OAuth at all reports `N/A`: it has no granted or
advertised scope to minimize.

**A comparison needs two observed sides.** Leg `3.3.4c` reports `UNKNOWN` when either
side is missing, and its evidence names which. A baseline record written before the
scope category existed cannot decide, because reading its absence as drift would
report every granted scope as newly added. A run that read no granted scope cannot
decide either, because a run that compared nothing cannot report that nothing grew.
An empty scope set is a third case and it does decide: a server that states an empty
grant has stated the grant, so legs `3.3.4a` and `3.3.4c` both treat it as observed.

### 3.3.3 Shared downstream service account identities are prohibited across tools and servers

**Level:** L2 · **Benchmark assessment status:** Manual

**What the check requires.** Each server and each tool needs its own downstream
service identity with least privilege, recorded in an identity inventory, with
any remaining shared identity covered by a documented, time-bound exception.

**How the probe implements it.** It does not, and reports `N/A`.

**Why.** The authoritative evidence is the identity mapping inventory, and the
supplementary scan reads per-server credential configuration on the deployment
host. Which downstream identity a tool uses leaves no signature on the MCP wire.

### 3.3.2 OAuth discovery metadata is served over TLS and validated against the approved list

**Level:** L2 · **Benchmark assessment status:** Automated

**What the check requires.** One protected-resource metadata document, served
over TLS at every discovery path a client may try, with a `resource` value equal
to the server's canonical URI and a non-empty `authorization_servers` list. Each
advertised authorization server must publish metadata whose `issuer` matches the
advertised entry, and the advertised list must be change-controlled.

**How the probe implements it.** Seven legs.

- `3.3.2a` — the MCP endpoint is served over TLS. This is a precondition, not a
  graded property: check 2.2 owns the transport verdict, and grading it again
  would fail 3.3.2 for something already reported. A non-TLS endpoint leaves no
  chain below it to assess, so the check reports `UNKNOWN`.
- `3.3.2b` — the document a client selects agrees with the document the 401 challenge
  names, compared byte-equal after a canonical key sort. Those two are the pair a
  conforming client reads. Paths that answered but that a client would not read are
  recorded and not compared, because RFC 9728 path-insertion exists so a server can
  serve one document per resource: a client that got an answer from the inserted path
  never reads the root, and comparing the two would fail a server for being
  conformant. Where the challenge names no URL, one document was consulted and
  nothing can disagree with it.
- `3.3.2c` — every discovery path that answered was https.
- `3.3.2d` — the advertised `resource` covers the canonical URI.
- `3.3.2e` — `authorization_servers` is present and non-empty.
- `3.3.2f` — the advertised list is within the recorded baseline.
- `3.3.2g` — each advertised authorization server publishes an `issuer` that
  string-equals the advertised entry.

Two further legs of the recommendation carry no verdict. The host guard that
every server-supplied discovery URL passes is a property of this probe rather
than of the server. Write permissions on whatever the server serves its metadata
from are not observable from a remote client.

**Wider comparison on `3.3.2d`.** The probe applies the SDK's parent-prefix rule —
same origin, canonical path at or below the advertised path — rather than an exact
string match, because that is what a conforming client applies. Every `3.3.2d`
outcome states the rule it used. An advertised `resource` that is not a parsable
URI fails: RFC 9728 requires that member to be a URI, the value is present and
readable, and no conforming client could use it.

**Bounded discovery.** At most a fixed number of advertised authorization servers
are resolved, and every discovery fetch uses a fixed timeout. Both the number
advertised and the number left unresolved past the cap are recorded, so a longer
advertised list is never reported as fully assessed.

**Attribution rules.** A server that published no protected-resource metadata is
graded on what was observed, in three ways. An error, a guard refusal, another
status, or no attempt at all leaves the answer `UNKNOWN`, because neither outcome
was observed. Every path answering a clean 404 is the server stating it publishes
none — and then the verdict turns on whether it does OAuth at all. A server showing
no OAuth signal reports `N/A`, because there is no chain for the recommendation to
bite on. A server that requires OAuth reports `FAIL`: a client has no way to
discover the authorization server, which is what the recommendation exists to
guarantee.

Where the guard refused a URL the server supplied, `3.3.2c` records `UNKNOWN`: the
URL was never fetched, so its scheme was never seen.

Leg `3.3.2f` follows the same two-observed-sides rule as `3.3.4c`. A document that
answered and advertises no authorization server is an observed absence, so the leg
decides against the record rather than reporting `UNKNOWN` — the same reading `3.3.4f`
applies to `scopes_supported` in that document.

## Section 4 — client (host) configuration: not probed

All ten of Section 4's recommendations audit the **host or the client**, never the
server. This probe reaches a server by domain and sees only what a client on the far
side of that connection sees, so none of them is decidable here. That is a boundary of
this tool, not a gap in the benchmark.

Recommendation 4.1.5 states the boundary in its own audit text: verify behaviour "at
the enforcement point, not by calling the MCP server directly unless the server is
explicitly the enforcement point".

| Control | What it audits | Why it is out of reach |
|---|---|---|
| 4.1.1 | Per-tool consent or a pre-approved allowlist | Host configuration and audit log |
| 4.1.2 | Project-scoped server definitions | Client configuration, plus a workspace behavioural test |
| 4.1.3 | Elicitation consent and redaction | Host audit log |
| 4.1.4 | Sampling consent and redaction | A client capability and the sampling log |
| 4.1.5 | Human denial of tool invocations | The host, gateway or policy engine |
| 4.2.1 | Filesystem scope | OS-level controls on the server host |
| 4.2.2 | stdio subprocess environment | The environment of a process this probe never spawns |
| 4.2.3 | Untrusted Resource URI dereferencing | The host's direct-open surface |
| 4.3.1 | MCP Apps sandboxing and CSP | Host rendering and its audit log |
| 4.3.2 | MCP Apps permissions and logging | Host configuration and its audit log |

No Section 4 module exists. Ten not-applicable entries would add code and no coverage,
so the section is recorded here instead.

## Results against tested servers

Sections 1 and 2 were probed on 2026-08-12 against hosted MCP servers, using the
checks as described above. Section 3 was probed later, against a smaller target
set, and has its own table and dates below.

| Server | Endpoint | Auth | Protocol negotiated |
|--------|----------|------|---------------------|
| DeepWiki | `mcp.deepwiki.com` | none | 2025-11-25 |
| Linear | `mcp.linear.app` | OAuth | 2025-11-25 |
| Sentry | `mcp.sentry.dev` | OAuth | 2025-11-25 |
| Stripe | `mcp.stripe.com` | OAuth | 2025-03-26 |

| # | Check | deepwiki | linear | sentry | stripe |
|---|---|---|---|---|---|
| — | **Negotiated revision** | **2025-11-25** | **2025-11-25** | **2025-11-25** | **2025-03-26** |
| 1.1 | Served revisions pinned, malformed assertions rejected | **FAIL** | **FAIL** | **FAIL** | not run |
| 1.2 | Capability configuration matches recorded baseline | PASS | PASS | PASS | not run |
| 1.3 | Capability beyond the baseline denied until re-approved | UNKNOWN | UNKNOWN | UNKNOWN | not run |
| 1.4 | Server identity matches the recorded identity | PASS | PASS | PASS | not run |
| 2.1 | stdio preferred for local, single-user servers | N/A | N/A | N/A | N/A |
| 2.2 | TLS required, plaintext disallowed | PASS | PASS | **FAIL** | PASS |
| 2.3 | Auth propagates through proxies on SSE responses | **FAIL** | PASS | PASS | UNKNOWN |
| 2.4 | Request metadata headers present and consistent | NO-REV | NO-REV | NO-REV | NO-REV |
| 2.5 | Origin validated on all requests | **FAIL** | **FAIL** | PASS | **FAIL** |

### Reading the results

- **1.1 — 0/3 decided pass.** Two legs fail on all three servers. Leg `1.1a`: each
  serves `2024-11-05` and `2025-03-26`, both earlier than the `2025-06-18` floor,
  so each offers a downgrade path to a revision predating the current security
  model. Leg `1.1c`: each accepts a request carrying no `MCP-Protocol-Version`
  header and answers it, rather than refusing to process it under a default
  revision. Leg `1.1b` passes on all three, but none returns the specified
  `-32022`: each rejects the unapproved version with `-32600` at HTTP 400, which
  passes with the code named because the request was still refused. Legs `1.1d`
  and `1.1e` are `NO-REV` throughout — no server negotiates 2026-07-28, so the
  header-versus-`_meta` pair they test does not exist.
- **1.2 — 3/3 pass, on the second run.** Each server's advertised capability
  configuration matches the baseline recorded for it. A first run against a server
  reports `UNKNOWN`, because a run that records a baseline compares nothing.
- **1.3 — undecided on all three, and that is the servers' answer rather than the
  probe's limit.** No tool is advertised beyond the recorded baseline on any of
  them — 3 tools on DeepWiki, 65 on Linear, 9 on Sentry, all recorded — so no
  staged capability exists to be gated. The leg decides when a tool does appear:
  against a baseline with one DeepWiki tool removed, and arguments supplied, it
  reports `FAIL`, because the staged tool executed and no gate stopped it.
- **1.4 — 3/3 pass.** `DeepWiki|2.14.3`, `Linear MCP|1.0.0` and
  `Sentry MCP|0.39.0` each match the pair recorded for the endpoint. Against a
  baseline hand-edited to an older version the check reports `FAIL` and names both
  pairs, so it discriminates rather than passing on any identity at all.
- **Servers not covered, and runs that could not decide.** Stripe was not re-run for
  this section: its OAuth flow needs a fresh browser authorization on every run,
  because the loopback callback port changes and its cached client registration pins
  the previous one, and the authorization timed out. Its four cells read `not run`
  rather than carrying a stale verdict. Sentry is intermittent: one run in three
  established no session at all and reported `ERROR` for every Section 1 check
  together, which is a property of the run and not of the server. The verdicts above
  are from runs that reached a session, and two consecutive such runs agreed.
- **Leg 1.1a offers two `initialize` requests, not five.** Only two published
  revisions precede the `2025-06-18` floor, so probing the rest cannot change the
  answer. An earlier version probed all five and the resulting burst of nine requests
  per run drew connection refusals from one server.
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

### Section 3 results

Three targets carry a complete Section 3 column. DeepWiki needs no credential and
Stripe was re-authenticated, so both columns were run live for this table.
Linear's column comes from the authenticated run of 2026-08-27.

| # | Check | deepwiki | linear | stripe |
|---|---|---|---|---|
| — | **Negotiated revision** | **2025-11-25** | **2025-11-25** | **2025-03-26** |
| — | Run date | 2026-08-30 | 2026-08-27 | 2026-08-31 |
| 3.1.2 | Authentication required, tokens short-lived | **FAIL** | **FAIL** | PASS |
| 3.1.1 | stdio credentials from environment or store | N/A | N/A | N/A |
| 3.2.1 | Per-tool authorization enforced | N/A | N/A | N/A |
| 3.2.2 | Token audience confined to audited resource | N/A | UNKNOWN | UNKNOWN |
| 3.3.1 | Token bound to the audience that requested it | N/A | UNKNOWN | UNKNOWN |
| 3.3.5 | OAuth proxy validates redirect_uri, state, consent | N/A | N/A | N/A |
| 3.2.3 | Tool annotations not relied on for gating | N/A | N/A | N/A |
| 3.3.4 | Granted scopes minimized | N/A | UNKNOWN | UNKNOWN |
| 3.3.3 | Downstream identities not shared | N/A | N/A | N/A |
| 3.3.2 | Discovery metadata over TLS and validated | N/A | PASS | PASS |

No Section 3 leg depends on protocol revision 2026-07-28, so no Section 3 check
reports `NO-REV`. Stripe negotiates 2025-03-26, the oldest revision of the three,
and still serves RFC 9728 metadata that every discovery leg reads.

### Reading the Section 3 results

- **3.1.2 — 1/3 pass, and the two failures fail for opposite reasons.** DeepWiki
  requires no authentication, so an unauthenticated request reached a response and
  leg `3.1.2a` fails. Linear refuses correctly and names `resource_metadata`, then
  fails leg `3.1.2b`: its issued lifetime is 86100 seconds against the 3600-second
  baseline. Stripe passes all four legs: it refuses with a 401 naming
  `resource_metadata`, and its issued lifetime is exactly 3600 seconds.
- **DeepWiki is `N/A` on all six OAuth checks.** Every discovery path answered a
  clean 404 and no request drew a 401 challenge, so the server states it offers no
  OAuth. That is an observed absence, not an undecided run, which is why these are
  `N/A` rather than `UNKNOWN`.
- **3.2.2 and 3.3.1 are `UNKNOWN` on Linear because its access token is opaque.** No
  `aud` claim is readable, so neither audience leg can be observed. Leg `3.3.1c`
  probed ten candidates on `api.linear.app` and `linear.app`; each answered the
  same with and without the token, so none produced a usable comparison. Leg
  `3.3.1b` reached the wire and got the conforming answer: Linear's authorization
  server refused to mint a token for the wrong-audience resource with
  `invalid_target`, which is RFC 8707 enforcement, and which leaves Linear's own
  audience validation untested.
- **3.3.4 is `UNKNOWN` on Linear because leg `3.3.4e` has no operator input.** No tool
  is named as outside the grant, so no out-of-scope call was made. The other legs
  decided: granted scopes `read write`, no wildcard, within the recorded baseline,
  and the advertised surface carries no admin-tier scope.
- **3.3.2 passes on Linear.** Two discovery paths answered and serve the same
  document, both over https, the advertised `resource` equals the canonical URI,
  one authorization server is advertised, it is in the recorded baseline, and its
  published `issuer` string-equals the advertised entry. Linear's challenge
  `resource_metadata` equals its sub-path well-known URL, so the three URLs a
  client may try collapse to two documents.
- **3.2.2 and 3.3.1 are `UNKNOWN` on Stripe too, and its access token is opaque as
  well.** Leg `3.3.1c` produced the one live pass of that leg so far:
  `https://api.stripe.com/v1/account` answered 401 to the MCP token while answering
  differently without it, so a downstream API on the same registrable domain
  refused a credential minted for the MCP server. The other nine candidates
  answered the same either way and decided nothing. Leg `3.3.1b` is `UNKNOWN` for a
  reason of its own: the endpoint refused the control request carrying the probe's
  own token, so no refusal of a differently-bound token would have been
  attributable to audience validation.
- **3.3.4 is `UNKNOWN` on Stripe on two legs.** Granted scope is `mcp`, no wildcard,
  and within the recorded baseline. `3.3.4d` is undecided because the
  protected-resource document advertises no `scopes_supported` at all, and `3.3.4e`
  because no operator input names a tool outside the grant.
  `3.3.4f` passed on the third discovery source alone: the challenge carried no
  `scope`, the protected-resource `scopes_supported` was absent, and the
  authorization server advertised `['mcp']`. A check that consulted only the first
  two sources would have failed a working server.
- **3.3.2 passes on Stripe, and it took two runs.** Six legs passed on the first
  run: TLS, one answering discovery path, https, an advertised `resource` that is a
  hierarchical parent of the canonical URI, one advertised authorization server, and
  a published `issuer` that string-equals it. Leg `3.3.2f` was undecided, because no
  baseline held an `authorization_servers` category for this endpoint. A run with
  `--update-baseline` recorded `['https://access.stripe.com/mcp']`, and the next run
  compared against it and passed. `3.3.2f` is the one leg here that reports on drift
  rather than on a property of a single run, so it needs two runs by construction.
- **3.3.5 is `N/A` on all three targets, and each reaches that verdict differently.**
  DeepWiki serves no authorization-server metadata at all. Linear's authorization
  endpoint is `https://mcp.linear.app/authorize`, on the MCP endpoint's own host, so
  it authorizes for itself and fronts nothing; the gate settled that from metadata
  alone, and neither of those two targets left a scratch client in the token store.
  Stripe is the one target whose metadata gate opened: its authorization server is
  `https://access.stripe.com/mcp`, a separate host, so the probe registered two
  clients and compared what each authorize response carried onward. Both answered
  302, and neither `Location` carried a `client_id`. With no shared static client id
  established, the recommendation is vacuous for it and the three test legs never
  ran.

### Section 3 coverage gaps

Ten checks reporting verdicts do not mean the coverage is complete. Six gaps
remain, and each names what closing it needs.

1. **Check 3.3.5's three test legs — `3.3.5a`, `3.3.5b` and `3.3.5c` — have no live
   coverage on any target.** Stripe's metadata gate did open, and the two
   registrations that follow it ran, so the reachable part of the precondition is
   exercised. What no target has produced is a shared static client id in the
   onward redirect, which is the condition the three test legs sit behind. Closing
   this needs a server that hands a newly registered client to an upstream
   authorization server on one shared client id.
2. **Leg 3.3.4e is unverified on every target**, because no operator input file
   names a tool outside the grant. Its refusal classifier matches a broad marker
   list, so a tool error mentioning `scope`, `401` or `403` for an unrelated
   reason would read as a scope refusal. The evidence carries a 200-character
   excerpt of the refusal, so an operator can audit the call.
3. **Leg 3.3.1b's rotation path is untested.** No authorization server has minted a
   wrong-audience token yet. Linear refused the request with `invalid_target`, and
   on Stripe the control request was refused first, so the leg returned before it
   asked. A server that does mint such a token would exercise that path for the
   first time.
4. **Check 3.3.4 compares the granted scopes against a recorded baseline, not
   against an approved set.** The benchmark audit compares them against an approved
   cumulative scope set the deployment documents in its capability baseline, and
   fails any granted scope outside it. The probe has no access to such a set, so leg
   `3.3.4c` reports drift against its own recorded snapshot instead. Closing this
   needs the approved scope list as an operator input, in the same file that already
   names the out-of-grant tool for leg `3.3.4e`.
5. **Leg `3.3.4b` fails every granted wildcard scope.** The benchmark audit fails a
   wildcard only when it falls outside the approved cumulative set, and asks a human
   to confirm the documented exception when it falls inside. That distinction cannot
   be drawn without the approved set from gap 4, so this gap closes only after that
   one.
6. **Sentry has no Section 3 column at all.** See below.

Two legs need two runs by construction, because both report on drift rather than on
a property of one run: `3.3.4c` compares the granted scope set against the baseline,
and `3.3.2f` compares the advertised authorization server list. Both are decided on
every target in the table. On a server that rotates refresh tokens, that pair of
runs used to cost two interactive logins, because `3.3.1b` spent the cached token.
The refresh-chain restore described above removes that cost.

**One login therefore covers the capture run and every ordinary run after it, for
as long as the cached refresh token stays valid.** The access token expires on the
server's own schedule — an hour on some servers, a day on others — and a run whose
cached access token has expired spends the refresh token instead of asking for
another login. Two conditions end that: an authorization server that expires the
refresh token as well, and `--reauth`, which discards both on purpose. A run that
cannot refresh says so, opens a browser, and waits for the login.

### Servers not covered

- **Sentry** (`mcp.sentry.dev`) was unreachable during Section 3 testing, so it
  carries Section 1 and 2 verdicts only.
- **Notion** (`mcp.notion.com`) could not be probed. During testing the host was
  reached through a TLS inspection proxy, so the certificate chain presented was
  not Notion's. Any transport verdict would have described the proxy rather than
  the server, so it is excluded rather than reported.
- **Atlassian** (`mcp.atlassian.com`) has not been probed. Discovery against a bare
  domain tries `/mcp` and then `/`, and Atlassian answers 404 on both while answering
  401 on `/v1/mcp` and `/v1/sse`. It also serves no protected-resource metadata at
  the well-known path, so its endpoint is not discoverable from the wire either.
  Probing it means passing the endpoint URL directly, which skips discovery:
  `cis-mcp-probe https://mcp.atlassian.com/v1/mcp`. The default path list is
  deliberately short rather than a catalogue of vendor prefixes, because a version
  in a guessed path expires.
