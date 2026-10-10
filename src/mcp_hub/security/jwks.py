"""JWKS cache with a refresh rate limit so random `kid` values cannot trigger upstream fetches."""

from __future__ import annotations

import threading
import time
from typing import Any

import httpx
import jwt

from mcp_hub.errors import UpstreamError

MIN_REFRESH_SECONDS = 30.0
MAX_JWKS_BYTES = 1_000_000


class JwksCache:
    def __init__(
        self,
        *,
        issuer: str,
        jwks_url: str | None,
        ttl_seconds: int,
        min_refresh_seconds: float = MIN_REFRESH_SECONDS,
        timeout: float = 5.0,
    ) -> None:
        self._issuer = issuer
        self._jwks_url = jwks_url
        self._ttl = ttl_seconds
        self._min_refresh = min_refresh_seconds
        self._timeout = timeout
        self._keys: dict[str, Any] = {}
        self._fetched_at = 0.0
        self._last_attempt = 0.0
        self._lock = threading.Lock()

    def _get_json(self, url: str) -> dict[str, Any]:
        with httpx.Client(timeout=self._timeout, follow_redirects=False) as client:
            resp = client.get(url, headers={"Accept": "application/json"})
        if resp.status_code != 200 or len(resp.content) > MAX_JWKS_BYTES:
            raise UpstreamError("JWKS endpoint returned an unusable response.")
        data = resp.json()
        if not isinstance(data, dict):
            raise UpstreamError("JWKS endpoint returned an unexpected document.")
        return data

    def _discover(self) -> str:
        if self._jwks_url:
            return self._jwks_url
        doc = self._get_json(self._issuer.rstrip("/") + "/.well-known/openid-configuration")
        if str(doc.get("issuer", "")).rstrip("/") != self._issuer.rstrip("/"):
            raise UpstreamError("Issuer metadata does not match the configured issuer.")
        uri = doc.get("jwks_uri")
        if not isinstance(uri, str):
            raise UpstreamError("Issuer metadata has no jwks_uri.")
        self._jwks_url = uri
        return uri

    def _refresh_locked(self) -> None:
        self._last_attempt = time.monotonic()
        doc = self._get_json(self._discover())
        keys: dict[str, Any] = {}
        entries = doc.get("keys", [])
        if not isinstance(entries, list):
            raise UpstreamError("JWKS 'keys' is not a list.")
        for jwk in entries:
            if not isinstance(jwk, dict):
                continue
            try:
                parsed = jwt.PyJWK(jwk)
            except (jwt.PyJWTError, ValueError, TypeError):
                continue  # skip one bad key, keep the rest
            if parsed.key_id:
                keys[parsed.key_id] = parsed.key
        if not keys:
            raise UpstreamError("JWKS contains no usable keys.")
        self._keys = keys
        self._fetched_at = time.monotonic()

    def get_key(self, kid: str) -> Any:
        now = time.monotonic()
        with self._lock:
            stale = now - self._fetched_at > self._ttl
            if kid in self._keys and not stale:
                return self._keys[kid]
            may_refresh = now - self._last_attempt >= self._min_refresh
            if may_refresh:
                try:
                    self._refresh_locked()
                except (httpx.HTTPError, ValueError) as exc:
                    raise UpstreamError("JWKS fetch failed.") from exc
            key = self._keys.get(kid)
            if key is None:
                raise UpstreamError("Unknown signing key id.")
            return key
