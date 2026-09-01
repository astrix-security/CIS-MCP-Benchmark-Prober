"""Decide what this probe trusts on the network: which hosts it may fetch, which
may receive a credential, and which certificate authorities it verifies against.

The host rules come first, because they are the ones a server can attack.

Several checks follow a URL the server itself chose, and one of them presents a
live bearer token to the host it derives from that URL. A server that answers
with ``http://169.254.169.254/`` or ``http://127.0.0.1:9000/`` turns the probe
into its own credentialed HTTP client against whatever is reachable from the
machine running it, so every such fetch goes through ``is_safe_fetch_host``
first.

Two encodings make the naive version of this guard useless:

* A bracketed IPv6 literal. A host pattern like ``[^/:]+`` stops at the first
  colon and yields ``[fd00`` for ``https://[fd00::1]/x`` -- a string that looks
  like an unremarkable hostname to every subsequent test. ``host_of`` uses
  ``urllib.parse`` so the literal survives intact, and every IPv6 literal is
  then refused outright rather than range-tested.
* A non-dotted-quad IPv4 address. ``socket.inet_aton`` resolves
  ``2852039166``, ``0x7f000001`` and ``127.1`` to ``169.254.169.254``,
  ``127.0.0.1`` and ``127.0.0.1``, while ``ipaddress.ip_address`` raises
  ``ValueError`` for all three. Treating that ``ValueError`` as "then it must be
  a hostname" admits every one of them, so anything ``inet_aton`` accepts and
  ``ip_address`` does not is refused as well.
"""

from __future__ import annotations

import ipaddress
import socket
import ssl
from pathlib import Path
from urllib.parse import SplitResult, urlsplit

import truststore

# Names that resolve to something inside the network the probe runs in.
INTERNAL_SUFFIXES = (".internal", ".local", ".localhost")

# RFC 6598 shared address space. ipaddress.is_private does not cover it
# before Python 3.13.
_SHARED_ADDRESS_SPACE = ipaddress.ip_network("100.64.0.0/10")


def verify_context() -> ssl.SSLContext:
    """The context every fetch in this package verifies certificates with.

    Uses the operating system's trust store rather than only the bundled public CA
    set, so a host reached through a TLS-inspecting proxy is reachable without the
    operator first assembling a CA bundle by hand. ``SSL_CERT_FILE`` still works and
    is no longer required.

    ``truststore.inject_into_ssl()`` is the documented one-liner for this and is
    deliberately not used. It replaces ``ssl.SSLContext`` process-wide, which would
    make the certifi-only probe that detects interception consult this machine's
    trust store too, and every intercepted host would then read as an ordinary one.
    That probe works only because exactly one context in this process does not
    consult that store, so this one stays explicit.
    """
    return truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)


def parts_of(url: str) -> SplitResult | None:
    """Return ``url`` split into components, or None when it cannot be parsed.

    Use this for any URL the server under test chose. ``urlsplit`` raises
    ``ValueError`` for an authority holding an unbalanced bracket, such as
    ``https://exa[mple.com/x``, so a bare call on a server-supplied string turns
    one unusable URL into an exception the caller did not expect.
    """
    try:
        return urlsplit(url)
    except ValueError:
        return None


def host_of(url: str) -> str | None:
    """Return the lowercased host of ``url``, or None when it has none.

    A bracketed IPv6 literal comes back without its brackets: ``fd00::1`` for
    ``https://[fd00::1]/x``.
    """
    parts = parts_of(url)
    return parts.hostname if parts else None


def scheme_of(url: str) -> str | None:
    """Return the lowercased scheme of ``url``, or None when it cannot be parsed."""
    parts = parts_of(url)
    return parts.scheme.lower() if parts else None


def resource_covers(configured: str, requested: str) -> bool | None:
    """Whether ``configured`` covers ``requested`` under the SDK's rule, or None.

    None means the question could not be asked: one of the two strings is not a
    URL the SDK can parse, and its matcher raises rather than answering. Both
    values reach this from a document the server under test controls, so a caller
    needs an answer it can record instead of an exception.

    The hierarchical rule is the SDK's own, so a client and this probe agree on
    what a resource covers.
    """
    from mcp.shared.auth_utils import check_resource_allowed

    try:
        return check_resource_allowed(
            requested_resource=requested, configured_resource=configured
        )
    except ValueError:
        return None


def is_safe_fetch_host(url: str) -> bool:
    """Return True only if ``url``'s host may be fetched.

    Refused: private, loopback, link-local and 0.0.0.0/8 IPv4; ``localhost`` and
    the internal-by-convention suffixes; every IPv6 literal; and every IPv4
    encoding other than a plain dotted quad.
    """
    host = host_of(url)
    if not host:
        return False

    # A trailing dot is a valid absolute form of the same name, and it hides the
    # address from both parsers below, so drop it before any comparison.
    host = host.rstrip(".")
    if not host:
        return False

    # An IPv6 literal is the only host form that can contain a colon.
    if ":" in host:
        return False

    if host == "localhost" or host.endswith(INTERNAL_SUFFIXES):
        return False

    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        addr = None

    if addr is not None:
        if addr in _SHARED_ADDRESS_SPACE:
            # RFC 6598 carrier-grade NAT. Reachable inside some networks, and
            # ipaddress does not report it as private on every Python version.
            return False
        return not (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_unspecified
            or addr.is_multicast
            or addr.is_reserved
        )

    # ip_address rejected it, so it is not a dotted quad. If inet_aton still
    # reads it as an address, it is an alternative IPv4 encoding, not a name.
    try:
        socket.inet_aton(host)
    except OSError:
        return True
    return False


def derive_api_host(host: str) -> str | None:
    """Return ``host`` with its leftmost label replaced by ``api``.

    ``mcp.linear.app`` becomes ``api.linear.app``. Returns None for a host of
    fewer than three labels, where there is no subdomain to replace.
    """
    labels = host.split(".")
    if len(labels) < 3:
        return None
    return ".".join(["api"] + labels[1:])


def derive_apex_host(host: str) -> str | None:
    """Return ``host`` without its leftmost label.

    ``mcp.linear.app`` becomes ``linear.app``. Returns None for a host of fewer
    than three labels, where dropping a label would leave a bare suffix.
    """
    labels = host.split(".")
    if len(labels) < 3:
        return None
    return ".".join(labels[1:])


# The Public Suffix List, bundled beside this module. It answers the one question
# a credential decision turns on: may a stranger register a name directly under
# this one? A certificate cannot answer it. Domain Validation certificates carry
# no owner field at all, and a platform's wildcard certificate is identical for
# every tenant on it, so `victim.example-paas.com` and `attacker.example-paas.com`
# present the same certificate signed by the same authority.
_PSL_PATH = Path(__file__).parent / "data" / "public_suffix_list.dat"

# Populated on first use: plain rules, `*.x` wildcard rules, `!x` exception rules.
_psl: tuple[set[str], set[str], set[str]] | None = None


def _punycode(rule: str) -> str | None:
    """``rule`` with every label in its ASCII form, or None if it has none.

    The list stores international names as Unicode, while a host parsed out of a
    URL arrives already ASCII-encoded. Without this the two never match, and a
    failed match yields a shorter public suffix than the truth -- which widens
    what the credential gate accepts.
    """
    try:
        ascii_labels = [
            label.encode("idna").decode("ascii") for label in rule.split(".")
        ]
    except (UnicodeError, UnicodeDecodeError):
        return None
    return ".".join(ascii_labels)


def _load_psl() -> tuple[set[str], set[str], set[str]]:
    """Parse the bundled list once, keeping each rule in both its forms."""
    global _psl
    if _psl is not None:
        return _psl
    if not _PSL_PATH.exists():
        raise RuntimeError(
            f"the public suffix list is missing from this installation: {_PSL_PATH}. "
            "It decides which hosts may receive a credential, so the probe will not "
            "guess without it."
        )
    plain: set[str] = set()
    wildcard: set[str] = set()
    exception: set[str] = set()
    for raw in _PSL_PATH.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("//"):
            continue
        if line.startswith("!"):
            target, rule = exception, line[1:]
        elif line.startswith("*."):
            target, rule = wildcard, line[2:]
        else:
            target, rule = plain, line
        target.add(rule)
        ascii_form = _punycode(rule)
        if ascii_form and ascii_form != rule:
            target.add(ascii_form)
    _psl = (plain, wildcard, exception)
    return _psl


def public_suffix(host: str) -> str:
    """The part of ``host`` that no single party owns, per the bundled list.

    ``mcp.linear.app`` yields ``app``; ``mcp.example.co.uk`` yields ``co.uk``. A
    name under no listed rule falls back to its rightmost label.
    """
    plain, wildcard, exception = _load_psl()
    # A trailing dot is the absolute form of the same name, and an empty label
    # matches no rule at all -- which would make the fallback below return the
    # empty string and widen what the credential gate accepts.
    labels = [label for label in host.lower().rstrip(".").split(".") if label]
    if not labels:
        return ""
    for i in range(len(labels)):
        candidate = ".".join(labels[i:])
        if candidate in exception:
            # An exception rule names a domain somebody does own, inside a range
            # that is otherwise a registry, so the suffix is one label shorter.
            return ".".join(labels[i + 1 :])
        if candidate in plain:
            return candidate
        parent = ".".join(labels[i + 1 :])
        if parent and parent in wildcard:
            return candidate
    return labels[-1]


def registrable_domain(host: str) -> str | None:
    """The largest part of ``host`` that one party owns, or None when it has none.

    ``mcp.linear.app`` yields ``linear.app``, because one party holds
    ``linear.app``. A host on a shared platform yields **itself**: a hosting
    domain is on the list, so the party that owns ``app-one.example-paas.com``
    owns exactly that name and nothing wider. Returns None for a host that is a
    public suffix entire, such as ``co.uk``.
    """
    normalized = host.lower().rstrip(".")
    suffix = public_suffix(normalized)
    if not suffix or normalized == suffix:
        return None
    remainder = normalized[: -(len(suffix) + 1)]
    return f"{remainder.split('.')[-1]}.{suffix}"


def is_credential_safe_target(url: str, endpoint_host: str) -> bool:
    """Return True only if ``url`` may receive a live bearer token.

    Three conditions, all required: the scheme is https, the host passes the
    fetch guard, and the host is -- or sits under -- the same registrable domain
    as ``endpoint_host``. A host an operator named goes through this too. An
    operator may point the probe at a name it would not have derived, but not at
    a third party and not over plaintext.

    Registrable domain rather than "drop the leftmost label" is the whole point.
    Dropping a label from a host on a shared platform yields the platform, whose
    other names belong to unrelated tenants, and dropping one from
    ``example.co.uk`` yields a registry.
    """
    if scheme_of(url) != "https":
        return False
    if not is_safe_fetch_host(url):
        return False

    host = (host_of(url) or "").rstrip(".").lower()
    endpoint = endpoint_host.rstrip(".").lower()
    if not host or not endpoint:
        return False

    owned = registrable_domain(endpoint)
    if owned is None:
        # The endpoint owns no namespace a sibling name could share -- it is a
        # public suffix entire, or a single label such as an internal short name.
        # Its own host is still itself, so allow exactly that and nothing wider.
        return host == endpoint
    return host == owned or host.endswith("." + owned)


if __name__ == "__main__":
    # Dotted-quad private ranges, and names that resolve internally.
    for bad in (
        "https://169.254.169.254/x",
        "https://127.0.0.1/x",
        "https://10.0.0.1/x",
        "https://192.168.1.1/x",
        "https://172.16.0.1/x",
        "http://localhost/x",
        "https://foo.internal/x",
        "https://foo.local/x",
        # Every IPv6 literal: a host parser that stops at the first colon cannot judge these.
        "https://[fd00::1]/x",
        "https://[::ffff:169.254.169.254]/x",
        "https://[::1]/x",
        # non-dotted-quad IPv4 encodings: inet_aton resolves these, ip_address does not
        "https://2852039166/x",
        "https://0x7f000001/x",
        "https://127.1/x",
        # RFC 6598 shared address space, not is_private on 3.12
        "https://100.64.0.1/x",
    ):
        assert not is_safe_fetch_host(bad), bad
    for ok in ("https://mcp.linear.app/x", "https://api.stripe.com/v1/account"):
        assert is_safe_fetch_host(ok), ok
    # the parser must not truncate a bracketed literal at the first colon
    assert host_of("https://[fd00::1]/x") == "fd00::1"
    # derivation replaces only the leftmost label
    assert derive_api_host("mcp.linear.app") == "api.linear.app"
    assert derive_api_host("mcp.stripe.com") == "api.stripe.com"
    assert derive_api_host("example.com") is None
    # the apex form drops the leftmost label instead of replacing it
    assert derive_apex_host("mcp.linear.app") == "linear.app"
    assert derive_apex_host("a.b.c.d") == "b.c.d"
    assert derive_apex_host("linear.app") is None

    # The credential gate. Same registrable domain as the endpoint, https only.
    assert is_credential_safe_target("https://api.linear.app/", "mcp.linear.app")
    assert is_credential_safe_target("https://linear.app/", "mcp.linear.app")
    assert is_credential_safe_target("https://mcp.linear.app/x", "mcp.linear.app")
    # a third party never receives the token, however it arrived as a candidate
    assert not is_credential_safe_target("https://evil.com/", "mcp.linear.app")
    assert not is_credential_safe_target(
        "https://linear.app.evil.com/", "mcp.linear.app"
    )
    # plaintext never carries a credential, even on the right host
    assert not is_credential_safe_target("http://api.linear.app/", "mcp.linear.app")
    # the fetch guard still applies underneath
    assert not is_credential_safe_target("https://127.0.0.1/", "mcp.linear.app")
    # userinfo names one host in the string and resolves to another
    assert not is_credential_safe_target(
        "https://api.linear.app@evil.com/me", "mcp.linear.app"
    )

    # What one party owns, read from the bundled list.
    assert public_suffix("mcp.linear.app") == "app"
    assert public_suffix("mcp.example.co.uk") == "co.uk"
    assert registrable_domain("mcp.linear.app") == "linear.app"
    assert registrable_domain("mcp.example.co.uk") == "example.co.uk"
    assert registrable_domain("co.uk") is None
    # test-type: ground-truth-vendor | source: publicsuffix.org public_suffix_list.dat
    # captured-from: VERSION 2026-08-29_12-33-06_UTC, retrieved 2026-08-30
    # last-revalidated: 2026-09-01
    # Every entry asserted below is a rule in the bundled list, not a judgement of
    # ours. If a platform is dropped from the list upstream, these assertions start
    # passing for the wrong reason: a neighbour tenant would read as owning the whole
    # platform domain and the credential gate would open to it. Re-verify against a
    # fresh copy of the list when refreshing the bundled file.
    #
    # A host on a hosting domain owns only itself, because the hosting domain is
    # itself on the list. That is what keeps a token away from a neighbour.
    for tenant in ("app-one.onrender.com", "app-one.up.railway.app", "app-one.fly.dev"):
        assert registrable_domain(tenant) == tenant, tenant

    # A neighbour on a hosting domain is an unrelated party. Every pair below was
    # accepted before the list replaced a hand-written suffix table, and each
    # derives from the endpoint name alone, with no operator input.
    for endpoint, neighbour in (
        ("app-one.onrender.com", "https://api.onrender.com/me"),
        ("app-one.up.railway.app", "https://api.up.railway.app/me"),
        ("app-one.fly.dev", "https://api.fly.dev/me"),
        ("app-one.hf.space", "https://api.hf.space/me"),
        ("app-one.vercel.app", "https://api.vercel.app/me"),
        ("app-one.github.io", "https://evil.github.io/"),
    ):
        assert not is_credential_safe_target(neighbour, endpoint), (endpoint, neighbour)
    # the bare hosting domain too, which the suffix table admitted
    assert not is_credential_safe_target("https://vercel.app/", "app-one.vercel.app")
    # a tenant reaching its own name is still allowed
    assert is_credential_safe_target(
        "https://app-one.onrender.com/me", "app-one.onrender.com"
    )
    # a registry is not an owned namespace: without this, every .co.uk host
    # would be a credential target
    assert is_credential_safe_target("https://example.co.uk/", "example.co.uk")
    assert not is_credential_safe_target("https://other.co.uk/", "example.co.uk")
    assert is_credential_safe_target("https://api.example.co.uk/", "mcp.example.co.uk")
    assert not is_credential_safe_target("https://other.co.uk/", "mcp.example.co.uk")
    # A URL the server chose may be unparseable. Every accessor answers None
    # rather than raising, because a caller cannot guard what it cannot parse.
    assert parts_of("https://exa[mple.com/x") is None
    assert host_of("https://exa[mple.com/x") is None
    assert scheme_of("https://exa[mple.com/x") is None
    assert scheme_of("HTTPS://api.linear.app/x") == "https"
    assert not is_credential_safe_target("https://exa[mple.com/x", "mcp.linear.app")
    # A trailing dot is the absolute form of the same name, not a new label.
    assert public_suffix("a.b.com.") == "com"
    assert registrable_domain("a.b.com.") == "b.com"
    assert registrable_domain("MCP.Linear.App") == "linear.app"
    # A single-label host owns no namespace, but it is still itself.
    assert registrable_domain("myserver") is None
    assert is_credential_safe_target("https://myserver/x", "myserver")
    assert not is_credential_safe_target("https://other/x", "myserver")
    # test-type: ground-truth-vendor | source: mcp.shared.auth_utils.check_resource_allowed
    # captured-from: mcp 1.28.1 | last-revalidated: 2026-09-01
    # The hierarchical rule is the SDK's, not this project's: same origin, and the
    # requested path at or below the configured one. Checks 3.10d and 3.4 grade
    # servers against what a conforming client of that SDK accepts, so the vendor's
    # behaviour is pinned here rather than restated in our own words. The SDK's
    # matcher raises on a string it cannot parse, and both sides of this comparison
    # come from a document the server controls.
    assert resource_covers("https://host", "https://host/mcp") is True
    assert resource_covers("https://other", "https://host/mcp") is False
    assert resource_covers("https://exa[mple.com", "https://host/mcp") is None
    assert resource_covers("https://host", "https://exa[mple.com") is None
    # The interception test in check 2.2 needs exactly one context in this process
    # that does NOT consult the machine's trust store. That is the interpreter's own
    # default context, loaded with the bundled CA file; ours consults the machine.
    # The two must therefore be different types.
    #
    # This assertion is the guard against a later simplification to
    # `truststore.inject_into_ssl()`. That call rebinds `ssl.SSLContext` process-wide,
    # so `ssl.create_default_context()` would start returning a truststore context
    # too, the two types would converge, and every intercepted host would silently
    # read as an ordinary one. The verdict would look clean and describe a proxy.
    assert isinstance(verify_context(), truststore.SSLContext)
    assert type(verify_context()) is not type(ssl.create_default_context()), (
        "ssl.create_default_context() now returns the same type as verify_context(), "
        "which means the ssl module has been patched globally and the interception "
        "test in check 2.2 can no longer detect anything"
    )

    print("netguard: all self-checks passed")
