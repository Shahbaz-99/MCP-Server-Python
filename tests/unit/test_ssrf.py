"""SSRF guard and hardened fetcher: every bypass family gets an adversarial test."""

from __future__ import annotations

import ipaddress
import json
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from mcp_hub.config import RestSettings
from mcp_hub.errors import AccessDenied, HubError, UpstreamError, ValidationFailed
from mcp_hub.plugins.rest_connector.client import SafeFetcher
from mcp_hub.plugins.rest_connector.ssrf import (
    check_url,
    host_allowed,
    is_public,
    resolve_public,
)

PUBLIC = "93.184.216.34"


@pytest.mark.parametrize(
    "addr",
    [
        "127.0.0.1",
        "127.1.2.3",
        "0.0.0.0",
        "10.0.0.5",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.1.1",
        "169.254.169.254",  # cloud metadata
        "169.254.0.1",
        "100.64.0.1",  # carrier-grade NAT
        "192.0.0.1",
        "198.18.0.1",
        "224.0.0.1",
        "240.0.0.1",
        "255.255.255.255",
        "::1",
        "::",
        "::2",  # IETF-reserved block that Python still reports as is_global
        "::8",
        "fe80::1",
        "fc00::1",
        "fd00:ec2::254",  # AWS IPv6 metadata
        "ff02::1",
        "::ffff:127.0.0.1",  # IPv4-mapped loopback
        "::ffff:169.254.169.254",
        "::ffff:10.0.0.1",
        "2002:7f00:0001::",  # 6to4 embedding 127.0.0.1
        "2001:0:4136:e378:8000:63bf:3fff:fdd2",  # teredo
    ],
)
def test_non_public_addresses_blocked(addr: str) -> None:
    assert not is_public(ipaddress.ip_address(addr))


@pytest.mark.parametrize("addr", [PUBLIC, "8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"])
def test_public_addresses_allowed(addr: str) -> None:
    assert is_public(ipaddress.ip_address(addr))


def test_host_allowlist_semantics() -> None:
    allowed = ["api.example.com", "*.github.com"]
    assert host_allowed("api.example.com", allowed)
    assert host_allowed("API.Example.COM.", allowed)  # case and trailing dot
    assert host_allowed("raw.github.com", allowed)
    assert not host_allowed("github.com", allowed)  # wildcard needs a subdomain
    assert not host_allowed("evilgithub.com", allowed)
    assert not host_allowed("api.example.com.evil.com", allowed)
    assert not host_allowed("evil.com", allowed)
    assert not host_allowed("api.example.com", [])


@pytest.mark.parametrize(
    "url",
    [
        "ftp://api.example.com/x",
        "file:///etc/passwd",
        "gopher://api.example.com/",
        "javascript:alert(1)",
        "http://api.example.com/x",  # plain http denied by default
        "https://user:pw@api.example.com/x",
        "https://api.example.com@evil.com/x",
        "https://evil.com/x",
        "https://api.example.com.evil.com/",
        "https://api.example.com:22/x",
        "https://api.example.com:6379/x",
        "https:///nohost",
        "https://api.example.com:notaport/",
        "//api.example.com/x",
        "",
    ],
)
def test_url_checks_reject(url: str) -> None:
    with pytest.raises(HubError):
        check_url(url, allowed_hosts=["api.example.com"], allow_http=False)


def test_url_checks_accept() -> None:
    p = check_url(
        "https://api.example.com/v1?a=1", allowed_hosts=["api.example.com"], allow_http=False
    )
    assert p.hostname == "api.example.com"
    check_url("http://api.example.com/x", allowed_hosts=["api.example.com"], allow_http=True)
    check_url("https://api.example.com:8443/x", allowed_hosts=["api.example.com"], allow_http=False)


def _resolver(*addrs: str) -> Callable[[str, int], Any]:
    async def resolve(host: str, port: int) -> list[str]:
        return list(addrs)

    return resolve


async def test_resolve_requires_every_address_public() -> None:
    assert await resolve_public("a.example", 443, _resolver(PUBLIC)) == [PUBLIC]
    # one private record among public ones: reject the host (multi-record rebinding trick)
    with pytest.raises(AccessDenied):
        await resolve_public("a.example", 443, _resolver(PUBLIC, "10.0.0.1"))
    with pytest.raises(AccessDenied):
        await resolve_public("a.example", 443, _resolver("127.0.0.1"))
    with pytest.raises(AccessDenied):
        await resolve_public("a.example", 443, _resolver("::ffff:7f00:1"))
    with pytest.raises(ValidationFailed):
        await resolve_public("a.example", 443, _resolver())
    with pytest.raises(AccessDenied):
        await resolve_public("a.example", 443, _resolver("not-an-ip"))


@pytest.mark.parametrize(
    "literal", ["127.0.0.1", "169.254.169.254", "10.1.2.3", "[::1]", "0.0.0.0"]
)
async def test_literal_ip_hosts_are_judged_directly(literal: str) -> None:
    async def boom(host: str, port: int) -> list[str]:  # must never be consulted for literals
        raise AssertionError("resolver called for literal IP")

    with pytest.raises(AccessDenied):
        await resolve_public(literal, 443, boom)


# ---- fetcher ---------------------------------------------------------------------------------


def _cfg(**kw: Any) -> RestSettings:
    kw.setdefault("allowed_hosts", ["api.example.com", "other.example.com"])
    return RestSettings(**kw)


class Recorder:
    def __init__(self, handler: Callable[[httpx.Request], httpx.Response]) -> None:
        self.requests: list[httpx.Request] = []
        self._handler = handler

    def transport(self) -> httpx.MockTransport:
        def run(req: httpx.Request) -> httpx.Response:
            self.requests.append(req)
            return self._handler(req)

        return httpx.MockTransport(run)


async def test_request_is_pinned_to_vetted_ip_with_original_host_header() -> None:
    rec = Recorder(lambda r: httpx.Response(200, json={"ok": True}))
    f = SafeFetcher(_cfg(), resolver=_resolver(PUBLIC), transport=rec.transport())
    res = await f.fetch("GET", "https://api.example.com/v1/items?x=1")
    assert res.status == 200 and json.loads(res.body) == {"ok": True}
    req = rec.requests[0]
    assert req.url.host == PUBLIC  # connected to the vetted IP, not re-resolved
    assert req.headers["host"] == "api.example.com"
    assert req.extensions["sni_hostname"] == "api.example.com"
    assert req.url.path == "/v1/items" and req.url.query == b"x=1"


async def test_dns_rebinding_to_private_address_blocked_before_any_request() -> None:
    rec = Recorder(lambda r: httpx.Response(200))
    f = SafeFetcher(_cfg(), resolver=_resolver("169.254.169.254"), transport=rec.transport())
    with pytest.raises(AccessDenied):
        await f.fetch("GET", "https://api.example.com/latest/meta-data/")
    assert rec.requests == []


async def test_ipv6_pinning_uses_brackets() -> None:
    rec = Recorder(lambda r: httpx.Response(200))
    f = SafeFetcher(_cfg(), resolver=_resolver("2606:4700:4700::1111"), transport=rec.transport())
    await f.fetch("GET", "https://api.example.com/")
    assert rec.requests[0].url.host == "2606:4700:4700::1111"


async def test_redirect_to_private_ip_blocked() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "http://169.254.169.254/latest/"})

    rec = Recorder(handler)
    f = SafeFetcher(_cfg(allow_http=True), resolver=_resolver(PUBLIC), transport=rec.transport())
    with pytest.raises(AccessDenied):
        await f.fetch("GET", "https://api.example.com/start")
    assert len(rec.requests) == 1  # the redirect target was never contacted


@pytest.mark.parametrize(
    "location",
    [
        "https://evil.com/x",  # host not allowlisted
        "http://api.example.com/x",  # downgrade to http
        "file:///etc/passwd",
        "https://api.example.com:22/x",
        "https://user:pw@api.example.com/",
        "gopher://api.example.com/",
    ],
)
async def test_redirect_targets_are_revalidated(location: str) -> None:
    rec = Recorder(lambda r: httpx.Response(301, headers={"location": location}))
    f = SafeFetcher(_cfg(), resolver=_resolver(PUBLIC), transport=rec.transport())
    with pytest.raises(HubError):
        await f.fetch("GET", "https://api.example.com/x")
    assert len(rec.requests) == 1


async def test_redirect_to_allowed_host_followed_and_credentials_dropped_cross_origin() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        if req.headers["host"] == "api.example.com":
            return httpx.Response(302, headers={"location": "https://other.example.com/final"})
        return httpx.Response(200, text="done")

    rec = Recorder(handler)
    f = SafeFetcher(_cfg(), resolver=_resolver(PUBLIC), transport=rec.transport())
    res = await f.fetch(
        "GET",
        "https://api.example.com/start",
        headers={"Authorization": "Bearer s3cret", "X-Other": "keep"},
        sensitive_headers=frozenset({"authorization"}),
    )
    assert res.body == b"done"
    first, second = rec.requests
    assert first.headers["authorization"] == "Bearer s3cret"
    assert "authorization" not in second.headers  # not leaked to another origin
    assert second.headers["x-other"] == "keep"


async def test_redirect_loop_and_post_redirects() -> None:
    rec = Recorder(
        lambda r: httpx.Response(302, headers={"location": "https://api.example.com/loop"})
    )
    f = SafeFetcher(_cfg(max_redirects=3), resolver=_resolver(PUBLIC), transport=rec.transport())
    with pytest.raises(UpstreamError, match="Too many redirects"):
        await f.fetch("GET", "https://api.example.com/loop")
    assert len(rec.requests) == 4
    with pytest.raises(UpstreamError, match="non-GET"):
        await f.fetch("POST", "https://api.example.com/x", json_body={"a": 1})


async def test_response_size_cap_streams_and_truncates() -> None:
    big = b"x" * 5_000_000
    rec = Recorder(lambda r: httpx.Response(200, content=big))
    f = SafeFetcher(
        _cfg(max_response_bytes=2048), resolver=_resolver(PUBLIC), transport=rec.transport()
    )
    res = await f.fetch("GET", "https://api.example.com/big")
    assert res.truncated and len(res.body) == 2048


async def test_connect_failure_falls_through_addresses_then_errors() -> None:
    calls: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(req.url.host)
        if req.url.host == "93.184.216.34":
            raise httpx.ConnectError("refused")
        return httpx.Response(200, text="second")

    rec = Recorder(handler)
    f = SafeFetcher(_cfg(), resolver=_resolver(PUBLIC, "8.8.8.8"), transport=rec.transport())
    assert (await f.fetch("GET", "https://api.example.com/")).body == b"second"
    assert calls == [PUBLIC, "8.8.8.8"]

    def always_refuse(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    f2 = SafeFetcher(
        _cfg(), resolver=_resolver(PUBLIC), transport=Recorder(always_refuse).transport()
    )
    with pytest.raises(UpstreamError, match="Could not connect"):
        await f2.fetch("GET", "https://api.example.com/")


async def test_other_http_errors_are_masked() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        raise httpx.ReadError("secret detail leaked?")

    f = SafeFetcher(_cfg(), resolver=_resolver(PUBLIC), transport=Recorder(handler).transport())
    with pytest.raises(UpstreamError) as exc:
        await f.fetch("GET", "https://api.example.com/")
    assert "secret detail" not in str(exc.value)


async def test_overall_timeout() -> None:
    import asyncio

    async def slow(host: str, port: int) -> list[str]:
        await asyncio.sleep(10)
        return [PUBLIC]

    f = SafeFetcher(
        _cfg(timeout_seconds=0.2),
        resolver=slow,
        transport=Recorder(lambda r: httpx.Response(200)).transport(),
    )
    with pytest.raises(UpstreamError, match="timed out"):
        await f.fetch("GET", "https://api.example.com/")


async def test_allow_private_ips_is_test_only_switch() -> None:
    rec = Recorder(lambda r: httpx.Response(200, text="local"))
    f = SafeFetcher(
        _cfg(allowed_hosts=["127.0.0.1", "localhost"], allow_http=True),
        resolver=_resolver("127.0.0.1"),
        transport=rec.transport(),
        allow_private_ips=True,
    )
    assert (await f.fetch("GET", "http://127.0.0.1/x")).body == b"local"
    assert (await f.fetch("GET", "http://localhost/x")).body == b"local"
