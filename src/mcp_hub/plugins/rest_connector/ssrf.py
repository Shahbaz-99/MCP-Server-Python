"""SSRF defence: host allowlist, public-address-only resolution, scheme checks."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from collections.abc import Awaitable, Callable
from urllib.parse import SplitResult, urlsplit

from mcp_hub.errors import AccessDenied, ValidationFailed

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
Resolver = Callable[[str, int], Awaitable[list[str]]]


async def system_resolver(host: str, port: int) -> list[str]:
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise ValidationFailed("Host name could not be resolved.") from None
    return sorted({str(i[4][0]) for i in infos})


def is_public(ip: IPAddress) -> bool:
    """True only for globally routable unicast addresses."""
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:  # ::ffff:127.0.0.1 must be judged as 127.0.0.1
            return is_public(ip.ipv4_mapped)
        if ip.sixtofour is not None and not is_public(ip.sixtofour):
            return False
        if ip.teredo is not None:
            return False
    return ip.is_global and not ip.is_multicast and not ip.is_reserved


def host_allowed(host: str, allowed: list[str]) -> bool:
    host = host.lower().rstrip(".")
    for pattern in allowed:
        p = pattern.lower().rstrip(".")
        if p.startswith("*."):
            if host.endswith(p[1:]) and host != p[2:]:
                return True
        elif host == p:
            return True
    return False


def check_url(url: str, *, allowed_hosts: list[str], allow_http: bool) -> SplitResult:
    """Static checks that need no DNS. Raises AccessDenied / ValidationFailed."""
    try:
        parts = urlsplit(url)
        port = parts.port  # raises ValueError on a bad port
    except ValueError:
        raise ValidationFailed("Malformed URL.") from None
    if parts.scheme not in ("https", "http"):
        raise AccessDenied("Only https URLs are allowed.")
    if parts.scheme == "http" and not allow_http:
        raise AccessDenied("Plain http is not allowed.")
    if parts.username is not None or parts.password is not None:
        raise AccessDenied("URLs with embedded credentials are not allowed.")
    host = parts.hostname
    if not host:
        raise ValidationFailed("URL has no host.")
    if port is not None and port not in (80, 443, 8080, 8443):
        raise AccessDenied("Non-standard ports are not allowed.")
    if not host_allowed(host, allowed_hosts):
        raise AccessDenied("Host is not in the allowlist.")
    return parts


async def resolve_public(host: str, port: int, resolver: Resolver = system_resolver) -> list[str]:
    """Resolve and require EVERY returned address to be public (one bad record rejects)."""
    try:
        literal = ipaddress.ip_address(host.strip("[]"))
        addresses = [str(literal)]
    except ValueError:
        addresses = await resolver(host, port)
    if not addresses:
        raise ValidationFailed("Host name could not be resolved.")
    for addr in addresses:
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            raise AccessDenied("Resolver returned an invalid address.") from None
        if not is_public(ip):
            raise AccessDenied("Host resolves to a non-public address.")
    return addresses
