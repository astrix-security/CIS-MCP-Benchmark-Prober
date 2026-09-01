"""The shared substrate every check reads from.

A ``ProbeContext`` is assembled once per server by ``client.connect_and_probe``
and then handed to each check. It carries both the live MCP session (for checks
that need to call tools / read resources) and the passively collected evidence
(handshake result, capability inventory, raw HTTP observations).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from mcp import types
    from mcp.client.session import ClientSession


@dataclass
class HttpObservation:
    """A single raw HTTP round-trip recorded before/around the MCP session.

    Used by network-level checks (TLS, auth enforcement, security headers) that
    reason about the transport rather than MCP semantics.
    """

    url: str
    method: str
    status: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    tls_version: str | None = None
    tls_cipher: str | None = None
    tls_cert: dict[str, Any] | None = None
    # True when the chain verified against the system or environment trust store
    # but NOT against the bundled public CA set. The certificate and the negotiated
    # version then belong to whatever terminated the connection, not to the server.
    tls_intercepted: bool = False
    error: str | None = None
    body_snippet: str | None = None


@dataclass
class ProbeContext:
    """Everything discovered about one MCP server, shared across all checks."""

    domain: str
    base_url: str
    endpoint_url: str | None = None
    transport: str | None = None  # "streamable-http" | "sse" | None

    # Live session — present only while checks run inside the connection scope.
    session: "ClientSession | None" = None
    session_id: str | None = None  # Mcp-Session-Id, for raw follow-up requests
    access_token: str | None = None  # bearer token, for raw authenticated requests

    # Protocol version negotiation.
    negotiated_version: str | None = None  # what the live session actually uses
    rc_supported: bool = False  # server accepts the 2026-07-28 release candidate
    rc_negotiated_version: str | None = None  # version echoed when we offer 2026-07-28

    # listChanged and other server notifications collected during the session.
    notifications: list[Any] = field(default_factory=list)

    # When True, checks that maintain state (e.g. capability baseline) capture/
    # refresh it instead of comparing against it.
    update_baseline: bool = False

    # Handshake / capability inventory.
    init_result: "types.InitializeResult | None" = None
    tools: list["types.Tool"] = field(default_factory=list)
    resources: list["types.Resource"] = field(default_factory=list)
    resource_templates: list["types.ResourceTemplate"] = field(default_factory=list)
    prompts: list["types.Prompt"] = field(default_factory=list)

    # Auth posture.
    auth_required: bool = False
    authenticated: bool = False
    protected_resource_metadata: dict[str, Any] | None = None
    auth_server_metadata: dict[str, Any] | None = None

    # Section 3 — token lifetime/scope and OAuth discovery documents.
    token_expires_in: int | None = None  # expires_in from the stored token response
    token_scope: str | None = None  # scope from the stored token response
    challenge_scope: str | None = None  # scope parsed from WWW-Authenticate
    # resource_metadata URL named by the 401 challenge, when it named one. Leg 3.3.2b
    # cross-checks the document here against the one a client would select, which is
    # the pair a conforming client actually reads.
    challenge_resource_metadata: str | None = None
    # discovery URL -> parsed document, successes only
    prm_documents: dict[str, dict] = field(default_factory=dict)
    # advertised issuer -> its metadata, successes only
    as_metadata_by_issuer: dict[str, dict] = field(default_factory=dict)

    # Raw transport-level evidence, keyed by a short label.
    http: dict[str, HttpObservation] = field(default_factory=dict)

    # Non-fatal problems hit while assembling the context.
    errors: list[str] = field(default_factory=list)

    @property
    def server_name(self) -> str | None:
        if self.init_result and self.init_result.serverInfo:
            return self.init_result.serverInfo.name
        return None

    @property
    def offers_oauth(self) -> bool:
        """True when anything observed says this server does OAuth at all.

        Several checks are vacuous against a server that does not, and each needs
        the same answer. Any one of these five is enough, and no single one is
        necessary: a 401 challenge, a token we hold, a protected-resource document,
        authorization-server metadata we resolved, or a scope named in a challenge.

        Read this rather than testing a subset. Four checks previously hand-rolled
        it from two, four and five of these fields, which happened to agree only
        because of how the fields are populated today.
        """
        return bool(
            self.auth_required
            or self.access_token
            or self.prm_documents
            or self.as_metadata_by_issuer
            or self.challenge_scope
        )

    @property
    def advertised_authorization_servers(self) -> list[str]:
        """The usable ``authorization_servers`` entries, in advertised order.

        The document is server-controlled, so a non-list value carries no entries
        and a blank or non-string element is not a name. Callers that need to know
        how many elements were discarded compare against the raw list's length.

        Returns [] when no document was read. A caller that must tell that apart
        from a document advertising none reads ``prm_documents`` too, which is what
        the capability baseline does.
        """
        document = self.protected_resource_metadata
        advertised = document.get("authorization_servers") if document else None
        if not isinstance(advertised, list):
            return []
        return [e for e in advertised if isinstance(e, str) and e.strip()]

    def summary(self) -> dict[str, Any]:
        """A JSON-serializable snapshot of what we discovered (for reports/debug)."""
        info = self.init_result.serverInfo if self.init_result else None
        caps = self.init_result.capabilities if self.init_result else None
        return {
            "domain": self.domain,
            "endpoint_url": self.endpoint_url,
            "transport": self.transport,
            "auth_required": self.auth_required,
            "authenticated": self.authenticated,
            "protocol_version": (
                self.init_result.protocolVersion if self.init_result else None
            ),
            "negotiated_version": self.negotiated_version,
            "rc_supported": self.rc_supported,
            "rc_negotiated_version": self.rc_negotiated_version,
            "server_info": (
                {"name": info.name, "version": info.version} if info else None
            ),
            "capabilities": (
                caps.model_dump(exclude_none=True) if caps else None
            ),
            "counts": {
                "tools": len(self.tools),
                "resources": len(self.resources),
                "resource_templates": len(self.resource_templates),
                "prompts": len(self.prompts),
            },
            "errors": self.errors,
        }
