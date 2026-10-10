"""Token verification: OIDC JWT access tokens plus the API-key fallback."""

from __future__ import annotations

import logging
from typing import Any

import anyio.to_thread
import jwt
from mcp.server.auth.provider import AccessToken

from mcp_hub import observability as obs
from mcp_hub.config import AuthSettings
from mcp_hub.errors import UpstreamError
from mcp_hub.security.apikeys import PREFIX, KeyStore
from mcp_hub.security.jwks import JwksCache

_log = logging.getLogger(__name__)

ALLOWED_ALGORITHMS = frozenset(
    {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "EdDSA"}
)


def _scopes(claims: dict[str, Any]) -> list[str]:
    """Union of the `scope` (RFC 9068, space-delimited) and `scp` (string or list) claims."""
    out: list[str] = []
    raw = claims.get("scope")
    if isinstance(raw, str):
        out.extend(raw.split())
    alt = claims.get("scp")
    if isinstance(alt, list):
        out.extend(str(s) for s in alt)
    elif isinstance(alt, str):
        out.extend(alt.split())
    return sorted(set(out))


class HubTokenVerifier:
    """SDK `TokenVerifier` implementation. Returns None for every rejection (fail closed)."""

    def __init__(
        self,
        cfg: AuthSettings,
        *,
        keystore: KeyStore | None = None,
        jwks: JwksCache | None = None,
    ) -> None:
        self._cfg = cfg
        self._keystore = keystore
        self._jwks = jwks
        if cfg.issuer and cfg.audience and jwks is None:
            self._jwks = JwksCache(
                issuer=cfg.issuer,
                jwks_url=cfg.jwks_url,
                ttl_seconds=cfg.jwks_cache_seconds,
            )

    async def verify_token(self, token: str) -> AccessToken | None:
        if token.startswith(PREFIX + "_"):
            return self._verify_api_key(token)
        if self._jwks is not None and token.count(".") == 2:
            try:
                return await anyio.to_thread.run_sync(self._verify_jwt, token)
            except Exception:
                # Anything unexpected must still mean "deny", never a 500 or an accidental allow.
                _log.exception("unexpected error verifying token")
                obs.AUTH_FAILURES.labels(reason="internal_error").inc()
                return None
        obs.AUTH_FAILURES.labels(reason="unsupported_token").inc()
        return None

    def _fail(self, reason: str) -> None:
        obs.AUTH_FAILURES.labels(reason=reason).inc()
        _log.warning("authentication rejected: %s", reason)

    def _verify_api_key(self, token: str) -> AccessToken | None:
        if self._keystore is None:
            self._fail("api_keys_disabled")
            return None
        rec, reason = self._keystore.verify(token)
        if rec is None:
            self._fail(f"apikey_{reason}")
            return None
        return AccessToken(
            token="",  # never retain the credential
            client_id=f"apikey:{rec.id}",
            scopes=list(rec.scopes),
            expires_at=rec.expires_at,
            resource=self._cfg.resource_url,
            subject=f"apikey:{rec.id}",
            claims={"kind": "apikey", "label": rec.label},
        )

    def _verify_jwt(self, token: str) -> AccessToken | None:
        assert self._jwks is not None
        cfg = self._cfg
        try:
            header = jwt.get_unverified_header(token)
            alg = header.get("alg")
            kid = header.get("kid")
            if (
                alg not in cfg.algorithms
                or alg not in ALLOWED_ALGORITHMS
                or not isinstance(kid, str)
            ):
                self._fail("jwt_header")
                return None
            key = self._jwks.get_key(kid)
            claims = jwt.decode(
                token,
                key,
                algorithms=[alg],
                audience=cfg.audience,
                issuer=cfg.issuer,
                leeway=cfg.clock_skew_seconds,
                options={"require": ["exp", "iss", "aud"], "verify_signature": True},
            )
        except jwt.ExpiredSignatureError:
            self._fail("jwt_expired")
            return None
        except jwt.InvalidAudienceError:
            self._fail("jwt_audience")
            return None
        except jwt.InvalidIssuerError:
            self._fail("jwt_issuer")
            return None
        except jwt.InvalidSignatureError:
            self._fail("jwt_signature")
            return None
        except UpstreamError as exc:
            self._fail("jwks_unavailable")
            _log.error("jwks problem: %s", exc.message)
            return None
        except (jwt.PyJWTError, ValueError):
            self._fail("jwt_invalid")
            return None
        sub = claims.get("sub")
        client = claims.get("azp") or claims.get("client_id") or sub
        if not isinstance(client, str):
            self._fail("jwt_no_subject")
            return None
        return AccessToken(
            token="",
            client_id=client,
            scopes=_scopes(claims),
            expires_at=int(claims["exp"]),
            resource=cfg.resource_url,
            subject=sub if isinstance(sub, str) else None,
            claims={"iss": claims.get("iss"), "kind": "oauth"},
        )
