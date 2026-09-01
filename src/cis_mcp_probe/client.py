"""The MCP client substrate: connect to a server by domain, authenticate if
required, enumerate its surface, and run checks against it.

This module is deliberately check-agnostic. It produces a fully populated
``ProbeContext`` and then hands it to whatever checks were passed in.
"""

from __future__ import annotations

import json
import socket
import ssl
import sys
import warnings
from urllib.parse import urlparse

import anyio
import certifi
import httpx
from mcp import types
from mcp.client.auth import OAuthClientProvider
from mcp.client.auth.utils import (
    build_oauth_authorization_server_metadata_discovery_urls,
    build_protected_resource_metadata_discovery_urls,
    extract_resource_metadata_from_www_auth,
    extract_scope_from_www_auth,
)
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from mcp.shared._httpx_utils import (
    MCP_DEFAULT_SSE_READ_TIMEOUT,
    MCP_DEFAULT_TIMEOUT,
)
from mcp.shared.auth import OAuthClientMetadata

from . import inputs
from .checks.base import Check, CheckResult, Status
from .context import HttpObservation, ProbeContext
from .netguard import verify_context
from .oauth import LoopbackCallbackServer
from .rawreq import raw_get, raw_jsonrpc
from .storage import FileTokenStorage

CLIENT_NAME = "CIS MCP Probe"
CLIENT_VERSION = "0.1.0"

# The revision this probe offers. A server that will not speak it negotiates the
# session down itself, and check 2.4 reports REVISION_UNSUPPORTED where a
# mechanism exists only here.
RC_VERSION = "2026-07-28"
PROTOCOL_VERSION = RC_VERSION

# Paths we try (in order) when the caller gives a bare domain.
# Tried in order against a bare domain, until one answers 200 or 401. Deliberately
# short: a server whose endpoint sits elsewhere is reached by passing its full URL,
# which skips discovery. Guessing version prefixes here would expire.
DEFAULT_PATHS = ("/mcp", "/")

# How many advertised authorization servers we resolve, and the timeout used for
# every discovery fetch. Both are fixed and independent of --timeout: the server
# controls how many hosts it advertises and whether they answer at all.
AS_LIST_CAP: int = 5
DISCOVERY_TIMEOUT: float = 8.0


def normalize(domain: str) -> tuple[str, str, list[str]]:
    """Return (host, base_url, candidate_endpoint_urls) for a domain or URL."""
    raw = domain.strip()
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urlparse(raw)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    host = parsed.hostname or parsed.netloc
    if parsed.path and parsed.path not in ("", "/"):
        candidates = [raw]  # caller gave an explicit endpoint path
    else:
        candidates = [base_url + p for p in DEFAULT_PATHS]
    return host, base_url, candidates


def _mcp_http_client(
    headers: dict[str, str] | None = None,
    timeout: httpx.Timeout | None = None,
    auth: httpx.Auth | None = None,
) -> httpx.AsyncClient:
    """The SDK's client factory, with our verification context.

    The session transport builds its own client, so without this the session would
    fail against a host the rest of the run can reach.

    The timeout fallback reads the SDK's own constants rather than restating their
    values. It is asymmetric on purpose: an SSE response stays open, so the read
    timeout is much longer than the connect one. The transport always passes an
    explicit timeout today, so this branch is defensive.
    """
    return httpx.AsyncClient(
        headers=headers,
        timeout=timeout
        if timeout is not None
        else httpx.Timeout(MCP_DEFAULT_TIMEOUT, read=MCP_DEFAULT_SSE_READ_TIMEOUT),
        auth=auth,
        follow_redirects=True,
        verify=verify_context(),
    )


def _handshake(
    obs: HttpObservation, host: str, port: int, context: ssl.SSLContext
) -> None:
    """Record one completed handshake into ``obs``, or raise."""
    with socket.create_connection((host, port), timeout=10) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            obs.tls_version = ssock.version()
            cipher = ssock.cipher()
            obs.tls_cipher = cipher[0] if cipher else None
            cert = ssock.getpeercert() or {}
            obs.tls_cert = {
                "subject": dict(x[0] for x in cert.get("subject", [])),
                "issuer": dict(x[0] for x in cert.get("issuer", [])),
                "notAfter": cert.get("notAfter"),
                "notBefore": cert.get("notBefore"),
            }
            obs.status = 0


def _tls_sync(host: str, port: int = 443) -> HttpObservation:
    """Observe the certificate and negotiated version, and whether we reached the server.

    The public CA set is tried first, on its own. A chain that verifies there is the
    server's. A chain that fails there and then verifies against the system or
    environment store was signed by a CA only this machine trusts, which is a
    TLS-inspecting proxy: the certificate and the negotiated version then describe
    the proxy, and check 2.2 says so instead of grading them.

    Testing against the bundled set is the test itself, rather than matching CA
    names against a list. A name list needs maintenance and misses every proxy that
    is not on it.
    """
    obs = HttpObservation(url=f"{host}:{port}", method="TLS")
    try:
        _handshake(obs, host, port, ssl.create_default_context(cafile=certifi.where()))
        return obs
    except ssl.SSLCertVerificationError as public_ca_error:
        # Retry against whatever this machine trusts, which honours SSL_CERT_FILE.
        try:
            _handshake(obs, host, port, verify_context())
            obs.tls_intercepted = True
            return obs
        except Exception:  # noqa: BLE001 — the public-CA failure is the useful one
            obs.error = (
                f"{public_ca_error!r}. The chain did not verify against the bundled "
                "public CA set, and not against this machine's trust store either. "
                "The certificate itself may be the problem -- expired, or issued "
                "for another name. If instead this host is reached through a "
                "TLS-inspecting proxy, set SSL_CERT_FILE to a bundle that includes "
                "the proxy's CA"
            )
            return obs
    except Exception as e:  # noqa: BLE001 — evidence, not control flow
        obs.error = repr(e)
    return obs


async def _observe_tls(ctx: ProbeContext, host: str) -> None:
    ctx.http["tls"] = await anyio.to_thread.run_sync(_tls_sync, host)


# Legacy revisions we must confirm the server *refuses* (check 2.2).
WEAK_TLS_VERSIONS = ("TLSv1", "TLSv1_1")


def _tls_version_sync(host: str, version_name: str, port: int = 443) -> HttpObservation:
    """Try to complete a handshake pinned to exactly one TLS version.

    ``status`` is 0 when the handshake succeeded (the server *accepted* that
    revision) and ``error`` is set when it failed. We pin min==max so the
    server can't negotiate up, and drop the client security level to 0 so a
    modern OpenSSL will still *offer* TLS 1.0/1.1 — otherwise our own stack
    would refuse locally and we'd misread that as the server refusing.
    """
    obs = HttpObservation(url=f"{host}:{port}", method=f"TLS:{version_name}")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            version = getattr(ssl.TLSVersion, version_name)
        sslctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        # We're testing which revisions are on offer, not trust; a cert problem
        # must not mask the handshake result.
        sslctx.check_hostname = False
        sslctx.verify_mode = ssl.CERT_NONE
        sslctx.minimum_version = version
        sslctx.maximum_version = version
        try:
            sslctx.set_ciphers("DEFAULT@SECLEVEL=0")
        except ssl.SSLError:
            pass  # older/stricter builds: proceed with defaults
        with socket.create_connection((host, port), timeout=10) as sock:
            with sslctx.wrap_socket(sock, server_hostname=host) as ssock:
                obs.tls_version = ssock.version()
                cipher = ssock.cipher()
                obs.tls_cipher = cipher[0] if cipher else None
                obs.status = 0  # handshake completed -> version accepted
    except Exception as e:  # noqa: BLE001 — a failure here is the evidence
        obs.error = repr(e)
    return obs


async def _observe_weak_tls(ctx: ProbeContext, host: str) -> None:
    for name in WEAK_TLS_VERSIONS:
        ctx.http[f"tls:{name}"] = await anyio.to_thread.run_sync(
            _tls_version_sync, host, name
        )


async def _observe_plaintext(ctx: ProbeContext, host: str) -> None:
    """GET http:// (no TLS) to see whether plaintext is served (check 2.2).

    Redirects are NOT followed: a 3xx to https is the compliant answer, and
    following it would hide the redirect behind the final 200.
    """
    url = f"http://{host}/"
    obs = HttpObservation(url=url, method="GET")
    try:
        async with httpx.AsyncClient(
            follow_redirects=False, timeout=10.0, verify=verify_context()
        ) as http:
            resp = await http.get(url)
        obs.status = resp.status_code
        obs.headers = dict(resp.headers)
        obs.body_snippet = resp.text[:200]
    except Exception as e:  # noqa: BLE001 — connection refused is a PASS signal
        obs.error = repr(e)
    ctx.http["plaintext"] = obs


def _initialize_body() -> dict:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": CLIENT_NAME, "version": CLIENT_VERSION},
        },
    }


async def _detect_endpoint(
    ctx: ProbeContext, http: httpx.AsyncClient, candidates: list[str]
) -> tuple[str | None, bool]:
    """Find which candidate URL is the MCP endpoint and whether it needs auth.

    We send an unauthenticated ``initialize`` POST. A well-behaved MCP server
    either answers (200) or rejects us for auth (401 with a WWW-Authenticate
    challenge) — both prove the path is the endpoint.
    """
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    for url in candidates:
        obs = HttpObservation(url=url, method="POST")
        try:
            resp = await http.post(url, json=_initialize_body(), headers=headers)
            obs.status = resp.status_code
            obs.headers = dict(resp.headers)
            obs.body_snippet = resp.text[:500]
            ctx.http[f"initialize:{url}"] = obs
            if resp.status_code in (200, 401):
                return url, resp.status_code == 401
        except Exception as e:  # noqa: BLE001
            obs.error = repr(e)
            ctx.http[f"initialize:{url}"] = obs
    return None, False


def _challenge_response(ctx: ProbeContext, endpoint: str) -> httpx.Response | None:
    """Rebuild the recorded initialize response as an ``httpx.Response``.

    The SDK's WWW-Authenticate parsers take a response object, and all we kept
    from the initialize round-trip is an ``HttpObservation``.
    """
    obs = ctx.http.get(f"initialize:{endpoint}")
    if obs is None or obs.status is None:
        return None
    try:
        return httpx.Response(status_code=obs.status, headers=obs.headers)
    except (UnicodeEncodeError, ValueError):
        # httpx encodes header values as ASCII. One non-ASCII byte in a header the
        # server sent would otherwise raise here, and this runs before any check,
        # so the whole run would end with no verdicts at all.
        return None


def _json_object(text: str) -> dict | None:
    """Parse ``text`` as a JSON object, or return None (including for a list)."""
    try:
        doc = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None
    return doc if isinstance(doc, dict) else None


async def _fetch_discovery_doc(ctx: ProbeContext, label: str, url: str) -> dict | None:
    """GET one discovery URL, recording the attempt whether it worked or not.

    The observation is what lets a check tell a 404 from a connection failure
    from a host-guard refusal; the parsed maps alone cannot.
    """
    status, _headers, text, error = await raw_get(url, timeout=DISCOVERY_TIMEOUT)
    ctx.http[label] = HttpObservation(
        url=url,
        method="GET",
        status=status,
        error=error,
        body_snippet=text[:200] if text else None,
    )
    if status != 200:
        return None
    return _json_object(text)


async def _resolve_authorization_server(ctx: ProbeContext, issuer: str) -> dict | None:
    """Try the SDK's discovery forms for ``issuer``, stopping at the first
    document that carries an ``issuer`` value."""
    try:
        forms = build_oauth_authorization_server_metadata_discovery_urls(issuer, issuer)
    except ValueError:
        # The advertised issuer is not a URL the builder can parse, so no form can
        # be built from it. Nothing is recorded, and the caller reads that as an
        # issuer never reached.
        return None
    for url in forms:
        doc = await _fetch_discovery_doc(ctx, f"as:{issuer}:{url}", url)
        if doc is not None and doc.get("issuer"):
            return doc
    return None


async def _resolve_authorization_servers(ctx: ProbeContext) -> None:
    """Resolve metadata for the advertised authorization servers, up to the cap.

    Every element is type-checked: ``authorization_servers`` is server-controlled
    and may be any JSON shape.
    """
    entries = ctx.advertised_authorization_servers
    if not entries:
        return

    # The raw list is read only to say how many elements were discarded.
    raw = (ctx.protected_resource_metadata or {}).get("authorization_servers")
    ignored = len(raw) - len(entries) if isinstance(raw, list) else 0
    if ignored:
        ctx.errors.append(
            f"authorization_servers: {ignored} entries ignored as not URL strings"
        )
    if len(entries) > AS_LIST_CAP:
        ctx.errors.append(
            f"authorization_servers: {len(entries) - AS_LIST_CAP} entries past the "
            f"cap of {AS_LIST_CAP} were not resolved"
        )

    for position, entry in enumerate(entries[:AS_LIST_CAP]):
        doc = await _resolve_authorization_server(ctx, entry)
        if doc is None:
            continue
        ctx.as_metadata_by_issuer[entry] = doc
        if position == 0:
            ctx.auth_server_metadata = doc


async def _fetch_oauth_metadata(
    ctx: ProbeContext, http: httpx.AsyncClient, endpoint: str
) -> None:
    """Fetch RFC 9728 protected-resource metadata from every discovery form, then
    the metadata of each advertised authorization server.

    ``http`` is the caller's shared client and is deliberately unused: every URL
    here comes from the server, so the fetches go through the guarded, non-
    redirect-following ``raw_get`` instead.

    ``prm_documents`` keeps every document that answered;
    ``protected_resource_metadata`` is the first of them in the SDK's order.
    Every attempt is recorded in ``ctx.http`` under ``prm:<url>`` or
    ``as:<issuer>:<url>``.

    Nothing here may raise: the caller runs before any check does, so an
    exception would leave the whole run with no verdicts at all.
    """
    try:
        challenge = _challenge_response(ctx, endpoint)
        www_auth_url = None
        if challenge is not None:
            ctx.challenge_scope = extract_scope_from_www_auth(challenge)
            www_auth_url = extract_resource_metadata_from_www_auth(challenge)
            ctx.challenge_resource_metadata = www_auth_url

        prm_urls = build_protected_resource_metadata_discovery_urls(
            www_auth_url, endpoint
        )
        for url in prm_urls:
            doc = await _fetch_discovery_doc(ctx, f"prm:{url}", url)
            if doc is None:
                continue
            ctx.prm_documents[url] = doc
            if ctx.protected_resource_metadata is None:
                ctx.protected_resource_metadata = doc

        await _resolve_authorization_servers(ctx)
    except Exception as e:  # noqa: BLE001 — a raise here would run zero checks
        ctx.errors.append(f"oauth discovery: {e!r}")


async def _enumerate(ctx: ProbeContext, session: ClientSession) -> None:
    caps = ctx.init_result.capabilities if ctx.init_result else None
    if caps and caps.tools is not None:
        try:
            ctx.tools = (await session.list_tools()).tools
        except Exception as e:  # noqa: BLE001
            ctx.errors.append(f"list_tools: {e!r}")
    if caps and caps.resources is not None:
        try:
            ctx.resources = (await session.list_resources()).resources
        except Exception as e:  # noqa: BLE001
            ctx.errors.append(f"list_resources: {e!r}")
        try:
            ctx.resource_templates = (
                await session.list_resource_templates()
            ).resourceTemplates
        except Exception as e:  # noqa: BLE001
            ctx.errors.append(f"list_resource_templates: {e!r}")
    if caps and caps.prompts is not None:
        try:
            ctx.prompts = (await session.list_prompts()).prompts
        except Exception as e:  # noqa: BLE001
            ctx.errors.append(f"list_prompts: {e!r}")


async def _detect_rc_support(ctx: ProbeContext) -> None:
    """Offer the 2026-07-28 revision on a raw initialize and see what comes back.

    A server that supports the RC echoes 2026-07-28 as the negotiated version; an
    older server negotiates down to whatever it does support. This is recorded so
    checks can tell which wire format the server actually speaks.
    """
    if not ctx.endpoint_url:
        return
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": RC_VERSION,
            "capabilities": {},
            "clientInfo": {"name": CLIENT_NAME, "version": CLIENT_VERSION},
        },
    }
    try:
        _status, data, _text = await raw_jsonrpc(
            ctx.endpoint_url, payload, token=ctx.access_token
        )
    except Exception as e:  # noqa: BLE001
        ctx.errors.append(f"rc-detect: {e!r}")
        return
    if data and isinstance(data.get("result"), dict):
        ver = data["result"].get("protocolVersion")
        ctx.rc_negotiated_version = ver
        ctx.rc_supported = ver == RC_VERSION


async def _run_checks(ctx: ProbeContext, checks: list[Check]) -> list[CheckResult]:
    results: list[CheckResult] = []
    for check in checks:
        try:
            results.append(await check.run(ctx))
        except Exception as e:  # noqa: BLE001 — one bad check shouldn't abort the run
            results.append(
                CheckResult(
                    check_id=check.id,
                    title=check.title,
                    section=check.section,
                    level=check.level,
                    status=Status.ERROR,
                    evidence=f"Check raised: {e!r}",
                )
            )
    return results


def _make_oauth_provider(
    server_url: str, storage: FileTokenStorage, callback: LoopbackCallbackServer
) -> OAuthClientProvider:
    metadata = OAuthClientMetadata(
        client_name=CLIENT_NAME,
        redirect_uris=[callback.redirect_uri],  # pydantic coerces str -> AnyUrl
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        token_endpoint_auth_method="none",
    )
    return OAuthClientProvider(
        server_url=server_url,
        client_metadata=metadata,
        storage=storage,
        redirect_handler=callback.redirect_handler,
        callback_handler=callback.callback_handler,
    )


async def connect_and_probe(
    domain: str,
    checks: list[Check],
    *,
    force_reauth: bool = False,
    update_baseline: bool = False,
    timeout: float = 30.0,
) -> tuple[ProbeContext, list[CheckResult]]:
    """Connect to ``domain``, authenticate if needed, enumerate, and run checks."""
    host, base_url, candidates = normalize(domain)
    ctx = ProbeContext(
        domain=domain, base_url=base_url, update_baseline=update_baseline
    )

    # --- Transport-level evidence (no MCP session needed) ---
    async with httpx.AsyncClient(
        follow_redirects=True, timeout=timeout, verify=verify_context()
    ) as http:
        await _observe_tls(ctx, host)
        await _observe_weak_tls(ctx, host)
        await _observe_plaintext(ctx, host)
        endpoint, auth_required = await _detect_endpoint(ctx, http, candidates)
        ctx.endpoint_url = endpoint
        ctx.auth_required = auth_required
        # Name the checks that will record unknown for want of an operator input.
        # stderr, because --json output is parsed by stripping to the first "{".
        notice = inputs.missing_input_notice(domain, inputs.load(domain))
        if notice:
            print(notice, file=sys.stderr)
        if endpoint is not None:
            ctx.transport = "streamable-http"
            await _fetch_oauth_metadata(ctx, http, endpoint)

    if endpoint is None:
        ctx.errors.append(f"No MCP endpoint responded among: {', '.join(candidates)}")
        return ctx, await _run_checks(ctx, checks)

    # --- MCP session (with interactive OAuth if the server demands it) ---
    # OAuth is keyed on the endpoint URL: RFC 9728 protected-resource metadata
    # identifies the resource as the full endpoint, and the SDK validates that
    # the advertised resource matches the server_url we hand it.
    storage = FileTokenStorage(endpoint)
    if force_reauth:
        storage.clear()

    # One retry: a cached access token can expire between runs, and an attempt can
    # race the refresh. A second try reuses the just-refreshed token and succeeds
    # without bothering the user again. But do NOT retry when the failure is the
    # interactive auth timing out — that just makes the user wait the full window
    # twice for a login they were never going to complete.
    for attempt in range(2):
        try:
            results = await _session_attempt(
                ctx, endpoint, storage, checks, auth_required, timeout
            )
            return ctx, results
        except Exception as e:  # noqa: BLE001
            ctx.errors.append(f"MCP session failed (attempt {attempt + 1}): {e!r}")
            _reset_session_state(ctx)
            if _contains_timeout(e):
                break

    # Session couldn't be established — still run checks against partial context.
    return ctx, await _run_checks(ctx, checks)


def _contains_timeout(exc: BaseException) -> bool:
    """True if a TimeoutError appears anywhere in the exception tree.

    OAuth failures surface wrapped in anyio ExceptionGroups, so we walk both the
    group members and the __cause__ chain. A timeout means the user didn't finish
    the browser login, which is pointless to retry.
    """
    if isinstance(exc, TimeoutError):
        return True
    inner = getattr(exc, "exceptions", None)
    if inner:
        return any(_contains_timeout(e) for e in inner)
    cause = exc.__cause__
    if cause is not None and cause is not exc:
        return _contains_timeout(cause)
    return False


def _reset_session_state(ctx: ProbeContext) -> None:
    """Clear everything a session produced, so a retry can't read last attempt's state.

    Deliberately limited to the session's own output. ``challenge_scope``,
    ``challenge_resource_metadata``, ``prm_documents`` and
    ``as_metadata_by_issuer`` are collected before the session, during endpoint
    detection, and this runs on every failed session attempt — the common case on
    an OAuth server, which is why the retry loop exists. Clearing them would leave
    check 3.3.4 with no scope-discovery input at all, and check 3.3.2 with nothing to
    cross-check its discovery documents against. Do not extend the list to them.
    """
    ctx.session = None
    ctx.init_result = None
    ctx.session_id = None
    ctx.access_token = None
    ctx.token_expires_in = None
    ctx.token_scope = None
    ctx.negotiated_version = None
    ctx.notifications.clear()


async def _session_attempt(
    ctx: ProbeContext,
    endpoint: str,
    storage: FileTokenStorage,
    checks: list[Check],
    auth_required: bool,
    timeout: float,
) -> list[CheckResult]:
    """Establish one MCP session, populate the context, and run the checks.

    Raises on connection/auth failure so the caller can retry.
    """
    callback = LoopbackCallbackServer()
    provider = _make_oauth_provider(endpoint, storage, callback)

    async def collect_notification(message: object) -> None:
        # The SDK's read task calls this for every inbound message; we keep the
        # server notifications (e.g. listChanged) so check 1.3 can react to them.
        if isinstance(message, types.ServerNotification):
            ctx.notifications.append(message.root)

    try:
        async with streamablehttp_client(
            endpoint,
            auth=provider,
            timeout=timeout,
            httpx_client_factory=_mcp_http_client,
        ) as (
            read,
            write,
            get_session_id,
        ):
            async with ClientSession(
                read, write, message_handler=collect_notification
            ) as session:
                ctx.session = session
                ctx.init_result = await session.initialize()
                ctx.authenticated = auth_required
                ctx.negotiated_version = ctx.init_result.protocolVersion
                try:
                    ctx.session_id = get_session_id()
                except Exception:  # noqa: BLE001
                    ctx.session_id = None
                tokens = await storage.get_tokens()
                if tokens:
                    ctx.access_token = tokens.access_token
                    ctx.token_expires_in = tokens.expires_in
                    ctx.token_scope = tokens.scope
                await _enumerate(ctx, session)
                await _detect_rc_support(ctx)
                return await _run_checks(ctx, checks)
    finally:
        callback.close()
