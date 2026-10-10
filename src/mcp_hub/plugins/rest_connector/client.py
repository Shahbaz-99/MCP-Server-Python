"""Hardened outbound HTTP client. Used by the REST connector and anything else that fetches URLs.

Properties: https + host allowlist on every hop, DNS resolved by us and every address required to
be public, the request is sent to the vetted IP (so DNS cannot change between check and connect),
manual redirects with re-validation, no proxy env, hard timeouts and a streaming size cap.
"""

from __future__ import annotations

import asyncio
import ipaddress
from dataclasses import dataclass
from typing import Any
from urllib.parse import SplitResult, urljoin, urlunsplit

import httpx

from mcp_hub.config import RestSettings
from mcp_hub.errors import UpstreamError
from mcp_hub.plugins.rest_connector.ssrf import (
    Resolver,
    check_url,
    resolve_public,
    system_resolver,
)

USER_AGENT = "mcp-hub/0.1"
REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})


@dataclass
class FetchResult:
    status: int
    content_type: str
    body: bytes
    truncated: bool


def _origin(parts: SplitResult) -> tuple[str, str, int]:
    port = parts.port or (443 if parts.scheme == "https" else 80)
    return parts.scheme, (parts.hostname or "").lower(), port


class SafeFetcher:
    def __init__(
        self,
        cfg: RestSettings,
        *,
        resolver: Resolver = system_resolver,
        transport: httpx.AsyncBaseTransport | None = None,
        allow_private_ips: bool = False,  # tests only; the plugin never sets this
    ) -> None:
        self._cfg = cfg
        self._resolver = resolver
        self._transport = transport
        self._allow_private = allow_private_ips

    async def _vet(self, url: str) -> tuple[SplitResult, list[str]]:
        parts = check_url(
            url, allowed_hosts=self._cfg.allowed_hosts, allow_http=self._cfg.allow_http
        )
        host = parts.hostname or ""
        port = parts.port or (443 if parts.scheme == "https" else 80)
        if self._allow_private:
            try:
                ipaddress.ip_address(host.strip("[]"))
                return parts, [host.strip("[]")]
            except ValueError:
                return parts, await self._resolver(host, port)
        return parts, await resolve_public(host, port, self._resolver)

    async def fetch(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        sensitive_headers: frozenset[str] = frozenset(),
        json_body: Any = None,
    ) -> FetchResult:
        cfg = self._cfg
        headers = dict(headers or {})
        first_origin: tuple[str, str, int] | None = None
        try:
            async with asyncio.timeout(cfg.timeout_seconds + 2):
                for _hop in range(cfg.max_redirects + 1):
                    parts, addresses = await self._vet(url)
                    origin = _origin(parts)
                    first_origin = first_origin or origin
                    send_headers = {
                        k: v
                        for k, v in headers.items()
                        if origin == first_origin or k.lower() not in sensitive_headers
                    }
                    result, location = await self._send_once(
                        method, parts, addresses, send_headers, json_body
                    )
                    if location is None:
                        return result
                    if method not in ("GET", "HEAD"):
                        raise UpstreamError("Upstream redirected a non-GET request; not followed.")
                    url = urljoin(url, location)
                raise UpstreamError("Too many redirects.")
        except TimeoutError:
            raise UpstreamError("Request timed out.") from None

    async def _send_once(
        self,
        method: str,
        parts: SplitResult,
        addresses: list[str],
        headers: dict[str, str],
        json_body: Any,
    ) -> tuple[FetchResult, str | None]:
        host = parts.hostname or ""
        port = parts.port or (443 if parts.scheme == "https" else 80)
        last_error: Exception | None = None
        for addr in addresses:
            literal = f"[{addr}]" if ":" in addr else addr
            pinned = urlunsplit(
                (parts.scheme, f"{literal}:{port}", parts.path or "/", parts.query, "")
            )
            host_header = host if parts.port is None else f"{host}:{parts.port}"
            req_headers = {
                "User-Agent": USER_AGENT,
                "Accept": "application/json, text/plain;q=0.9, */*;q=0.1",
                **headers,
                "Host": host_header,
            }
            extensions: dict[str, Any] = {"sni_hostname": host} if parts.scheme == "https" else {}
            try:
                async with (
                    httpx.AsyncClient(
                        transport=self._transport,
                        timeout=httpx.Timeout(self._cfg.timeout_seconds),
                        follow_redirects=False,
                        trust_env=False,
                    ) as client,
                    client.stream(
                        method,
                        pinned,
                        headers=req_headers,
                        json=json_body,
                        extensions=extensions,
                    ) as resp,
                ):
                    if resp.status_code in REDIRECT_CODES and "location" in resp.headers:
                        return FetchResult(resp.status_code, "", b"", False), resp.headers[
                            "location"
                        ]
                    body, truncated = await self._read_capped(resp)
                    return (
                        FetchResult(
                            resp.status_code,
                            resp.headers.get("content-type", ""),
                            body,
                            truncated,
                        ),
                        None,
                    )
            except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
                last_error = exc  # try the next resolved address
            except httpx.HTTPError as exc:
                raise UpstreamError(f"Request failed: {type(exc).__name__}") from None
        raise UpstreamError(f"Could not connect: {type(last_error).__name__}")

    async def _read_capped(self, resp: httpx.Response) -> tuple[bytes, bool]:
        limit = self._cfg.max_response_bytes
        chunks: list[bytes] = []
        total = 0
        async for chunk in resp.aiter_bytes():
            total += len(chunk)
            if total > limit:
                chunks.append(chunk[: limit - (total - len(chunk))])
                return b"".join(chunks), True
            chunks.append(chunk)
        return b"".join(chunks), False
