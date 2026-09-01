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

    Uses the operating system's trust store, so a host reached through a
    TLS-inspecting proxy needs no hand-assembled CA bundle.

    ``truststore.inject_into_ssl()`` is the documented one-liner for this and is
    deliberately not used: it replaces ``ssl.SSLContext`` process-wide, which would
    make the certifi-only probe that detects interception consult this machine's
    store too, and every intercepted host would then read as an ordinary one. That
    probe works only because exactly one context here does not consult that store.
    """
    return truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)


def parts_of(url: str) -> SplitResult | None:
    """Return ``url`` split into components, or None when it cannot be parsed.

    Use this for any URL the server under test chose. ``urlsplit`` raises on an
    unbalanced bracket -- ``https://exa[mple.com/x`` -- so a bare call turns one
    unusable URL into an exception the caller did not expect.
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

    None means the question could not be asked: the SDK's matcher raises on a
    string it cannot parse, and both values reach this from a document the server
    under test controls. The hierarchical rule is the SDK's own, so a client and
    this probe agree on what a resource covers.
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
