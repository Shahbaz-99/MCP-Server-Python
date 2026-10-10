"""Caller identity and scope checks. One resolver per server, configured by transport."""

from __future__ import annotations

from dataclasses import dataclass

from mcp.server.auth.middleware.auth_context import get_access_token

from mcp_hub.errors import AccessDenied

WILDCARD = "*"


@dataclass(frozen=True)
class Identity:
    subject: str
    scopes: frozenset[str]
    kind: str  # "local" | "oauth" | "apikey"

    def allows(self, required: tuple[str, ...]) -> bool:
        return WILDCARD in self.scopes or all(s in self.scopes for s in required)


LOCAL = Identity(subject="local", scopes=frozenset({WILDCARD}), kind="local")


class IdentityResolver:
    """Resolves who is calling.

    `local_trusted` is True only for stdio (the OS process boundary is the trust boundary) and for
    unauthenticated loopback HTTP. When False, a missing token means deny, never "local".
    """

    def __init__(self, *, local_trusted: bool) -> None:
        self._local_trusted = local_trusted

    def current(self) -> Identity:
        token = get_access_token()
        if token is None:
            if self._local_trusted:
                return LOCAL
            raise AccessDenied("Authentication required.")
        claims = token.claims or {}
        kind = "apikey" if claims.get("kind") == "apikey" else "oauth"
        return Identity(
            subject=token.subject or token.client_id,
            scopes=frozenset(token.scopes),
            kind=kind,
        )

    def require(self, scopes: tuple[str, ...]) -> Identity:
        ident = self.current()
        if not ident.allows(scopes):
            raise AccessDenied(f"Missing required scope: {', '.join(scopes)}")
        return ident
