"""The MCP client substrate: connect to a server by domain, authenticate if
required, enumerate its surface, and run checks against it.

This module is deliberately check-agnostic. It produces a fully populated
``ProbeContext`` and then hands it to whatever checks were passed in.
"""

from __future__ import annotations

import socket
import ssl
import warnings
from urllib.parse import urlparse

import anyio
import httpx
from mcp import types
from mcp.client.auth import OAuthClientProvider
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from mcp.shared.auth import OAuthClientMetadata

from .checks.base import Check, CheckResult, Status
from .context import HttpObservation, ProbeContext
from .oauth import LoopbackCallbackServer
from .rawreq import raw_jsonrpc
from .storage import FileTokenStorage

CLIENT_NAME = "CIS MCP Probe"
CLIENT_VERSION = "0.1.0"

# We prefer the 2026-07-28 release candidate and fall back to the prior stable
# revision if a server won't speak it.
RC_VERSION = "2026-07-28"
PREV_VERSION = "2025-11-25"
PROTOCOL_VERSION = RC_VERSION

# Paths we try (in order) when the caller gives a bare domain.
DEFAULT_PATHS = ("/mcp", "/")


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


def _tls_sync(host: str, port: int = 443) -> HttpObservation:
    obs = HttpObservation(url=f"{host}:{port}", method="TLS")
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
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
        async with httpx.AsyncClient(follow_redirects=False, timeout=10.0) as http:
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


async def _fetch_oauth_metadata(
    ctx: ProbeContext, http: httpx.AsyncClient, endpoint: str
) -> None:
    """Best-effort fetch of RFC 9728 protected-resource + auth-server metadata."""
    parsed = urlparse(endpoint)
    base = f"{parsed.scheme}://{parsed.netloc}"

    # The 401 challenge may point us at the metadata; else use the well-known path.
    prm_url = None
    challenge = ctx.http.get(f"initialize:{endpoint}")
    if challenge and challenge.headers:
        www = challenge.headers.get("www-authenticate") or challenge.headers.get(
            "WWW-Authenticate"
        )
        if www and "resource_metadata=" in www:
            prm_url = www.split("resource_metadata=", 1)[1].strip().strip('"').split(
                ","
            )[0].strip('"')
    prm_url = prm_url or f"{base}/.well-known/oauth-protected-resource"

    try:
        r = await http.get(prm_url)
        if r.status_code == 200:
            ctx.protected_resource_metadata = r.json()
    except Exception as e:  # noqa: BLE001
        ctx.errors.append(f"protected-resource metadata: {e!r}")

    # Resolve the authorization server metadata if advertised.
    as_url = None
    prm = ctx.protected_resource_metadata
    if prm and prm.get("authorization_servers"):
        issuer = prm["authorization_servers"][0].rstrip("/")
        as_url = f"{issuer}/.well-known/oauth-authorization-server"
    if as_url:
        try:
            r = await http.get(as_url)
            if r.status_code == 200:
                ctx.auth_server_metadata = r.json()
        except Exception as e:  # noqa: BLE001
            ctx.errors.append(f"auth-server metadata: {e!r}")


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
    ctx = ProbeContext(domain=domain, base_url=base_url, update_baseline=update_baseline)

    # --- Transport-level evidence (no MCP session needed) ---
    async with httpx.AsyncClient(follow_redirects=True, timeout=timeout) as http:
        await _observe_tls(ctx, host)
        await _observe_weak_tls(ctx, host)
        await _observe_plaintext(ctx, host)
        endpoint, auth_required = await _detect_endpoint(ctx, http, candidates)
        ctx.endpoint_url = endpoint
        ctx.auth_required = auth_required
        if endpoint is not None:
            ctx.transport = "streamable-http"
            await _fetch_oauth_metadata(ctx, http, endpoint)

    if endpoint is None:
        ctx.errors.append(
            f"No MCP endpoint responded among: {', '.join(candidates)}"
        )
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
    ctx.session = None
    ctx.init_result = None
    ctx.session_id = None
    ctx.access_token = None
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
            endpoint, auth=provider, timeout=timeout
        ) as (read, write, get_session_id):
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
                await _enumerate(ctx, session)
                await _detect_rc_support(ctx)
                return await _run_checks(ctx, checks)
    finally:
        callback.close()
