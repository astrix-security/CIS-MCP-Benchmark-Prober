"""Persistent OAuth token / client-registration storage, keyed per MCP server.

The MCP SDK's ``OAuthClientProvider`` needs somewhere to cache the dynamically
registered client and the issued tokens so a probe run does not force a fresh
browser login every time. We persist both under ``~/.cis-mcp-probe/tokens``.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from mcp.client.auth import TokenStorage
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

DATA_DIR = Path.home() / ".cis-mcp-probe" / "tokens"


def _key(server_url: str) -> str:
    return hashlib.sha256(server_url.encode()).hexdigest()[:16]


class FileTokenStorage(TokenStorage):
    """Stores tokens + client registration as JSON on disk, one pair per server."""

    def __init__(self, server_url: str) -> None:
        self.server_url = server_url
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        key = _key(server_url)
        self._tokens_path = DATA_DIR / f"{key}.tokens.json"
        self._client_path = DATA_DIR / f"{key}.client.json"

    async def get_tokens(self) -> OAuthToken | None:
        if self._tokens_path.exists():
            return OAuthToken.model_validate_json(self._tokens_path.read_text())
        return None

    async def set_tokens(self, tokens: OAuthToken) -> None:
        self._tokens_path.write_text(tokens.model_dump_json(indent=2))

    async def get_client_info(self) -> OAuthClientInformationFull | None:
        if self._client_path.exists():
            return OAuthClientInformationFull.model_validate_json(
                self._client_path.read_text()
            )
        return None

    async def set_client_info(self, client_info: OAuthClientInformationFull) -> None:
        self._client_path.write_text(client_info.model_dump_json(indent=2))

    def clear(self) -> None:
        """Forget any cached credentials for this server (forces re-auth)."""
        self._tokens_path.unlink(missing_ok=True)
        self._client_path.unlink(missing_ok=True)
