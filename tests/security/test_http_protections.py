"""Origin/Host checks, size/rate/concurrency limits, health and metrics endpoints."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import httpx
import pytest
from starlette.types import Message, Receive, Scope, Send

from mcp_hub.config import Settings
from mcp_hub.http_app import build_http_stack
from mcp_hub.security.ratelimit import MAX_TRACKED_KEYS, LimitsMiddleware, TokenBucket
from tests.security.conftest import Http, Issuer, make_settings, running

# ---- Origin / Host (DNS rebinding) ----------------------------------------------------------


async def test_bad_origin_rejected(http: Http, issuer: Issuer) -> None:
    r = await http.rpc(
        "tools/list", token=issuer.mint(), headers={"Origin": "https://evil.example"}
    )
    assert r.status_code == 403


async def test_bad_host_rejected(http: Http, issuer: Issuer) -> None:
    r = await http.rpc("tools/list", token=issuer.mint(), headers={"Host": "evil.example"})
    assert r.status_code in (400, 403, 421)


async def test_allowed_origin_and_host_pass(issuer: Issuer, key_file: Path) -> None:
    settings = make_settings(
        issuer,
        key_file,
        http={"allowed_origins": ["https://app.example"], "allowed_hosts": ["127.0.0.1:*"]},
    )
    stack = build_http_stack(settings)
    async with running(stack):
        transport = httpx.ASGITransport(app=stack.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8000") as c:
            h = {
                "Accept": "application/json, text/event-stream",
                "Authorization": f"Bearer {issuer.mint()}",
            }
            body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
            ok = await c.post("/mcp", json=body, headers={**h, "Origin": "https://app.example"})
            assert ok.status_code == 200
            bad = await c.post("/mcp", json=body, headers={**h, "Origin": "https://other.example"})
            assert bad.status_code == 403


async def test_no_cors_headers_by_default(http: Http, issuer: Issuer) -> None:
    r = await http.rpc(
        "tools/list", token=issuer.mint(), headers={"Origin": "https://evil.example"}
    )
    assert "access-control-allow-origin" not in r.headers


# ---- size limits ----------------------------------------------------------------------------


async def test_oversize_content_length_rejected_before_auth(http: Http) -> None:
    big = "x" * 2_000_000
    r = await http.client.post("/mcp", content=big, headers={"Content-Type": "application/json"})
    assert r.status_code == 413  # rejected without even needing a token


async def test_oversize_body_without_content_length_rejected(
    issuer: Issuer, key_file: Path
) -> None:
    settings = make_settings(issuer, key_file, http={"max_body_bytes": 2048})
    stack = build_http_stack(settings)
    async with running(stack):
        transport = httpx.ASGITransport(app=stack.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8000") as c:

            async def chunks() -> Any:
                for _ in range(20):
                    yield b"x" * 1024

            r = await c.post(
                "/mcp",
                content=chunks(),  # chunked: no Content-Length header
                headers={
                    "Authorization": f"Bearer {issuer.mint()}",
                    "Accept": "application/json, text/event-stream",
                    "Content-Type": "application/json",
                },
            )
            assert r.status_code in (400, 413)


async def test_bad_content_length_header() -> None:
    called = False

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        nonlocal called
        called = True

    mw = LimitsMiddleware(app, rate_limit_per_minute=100, max_concurrency=4, max_body_bytes=10)
    sent: list[Message] = []

    async def send(m: Message) -> None:
        sent.append(m)

    scope: Scope = {
        "type": "http",
        "path": "/mcp",
        "headers": [(b"content-length", b"abc")],
        "client": ("1.1.1.1", 1),
    }

    async def receive() -> Message:
        return {"type": "http.request"}

    await mw(scope, receive, send)
    assert sent[0]["status"] == 400 and not called


# ---- rate limiting and concurrency ----------------------------------------------------------


def test_token_bucket_math_and_bounded_memory() -> None:
    now = [0.0]
    b = TokenBucket(60, clock=lambda: now[0])  # 1 token / second, burst 60
    assert all(b.allow("k") for _ in range(60))
    assert not b.allow("k")
    now[0] += 2
    assert b.allow("k") and b.allow("k") and not b.allow("k")
    for i in range(MAX_TRACKED_KEYS + 50):
        b.allow(f"key-{i}")
    assert len(b._state) <= MAX_TRACKED_KEYS


async def test_rate_limit_triggers_429_and_exempts_health(issuer: Issuer, key_file: Path) -> None:
    settings = make_settings(issuer, key_file, http={"rate_limit_per_minute": 5})
    stack = build_http_stack(settings)
    async with running(stack):
        transport = httpx.ASGITransport(app=stack.app, client=("198.51.100.7", 1))
        async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8000") as c:
            codes = [
                (await c.get("/.well-known/oauth-protected-resource/mcp")).status_code
                for _ in range(8)
            ]
            assert codes[:5] == [200] * 5 and set(codes[5:]) == {429}
            r = await c.get("/.well-known/oauth-protected-resource/mcp")
            assert r.headers["retry-after"] == "1"
            for _ in range(20):  # liveness/readiness must keep working under load
                assert (await c.get("/healthz")).status_code == 200


async def test_rate_limit_is_per_client_ip(issuer: Issuer, key_file: Path) -> None:
    settings = make_settings(issuer, key_file, http={"rate_limit_per_minute": 2})
    stack = build_http_stack(settings)
    async with running(stack):
        for ip, expect_last in (("198.51.100.1", 429), ("198.51.100.2", 200)):
            transport = httpx.ASGITransport(app=stack.app, client=(ip, 1))
            async with httpx.AsyncClient(
                transport=transport, base_url="http://127.0.0.1:8000"
            ) as c:
                url = "/.well-known/oauth-protected-resource/mcp"
                n = 3 if expect_last == 429 else 1
                last = [(await c.get(url)).status_code for _ in range(n)][-1]
                assert last == expect_last


async def test_concurrency_limit_returns_503() -> None:
    gate = asyncio.Event()

    async def slow(scope: Scope, receive: Receive, send: Send) -> None:
        await gate.wait()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    mw = LimitsMiddleware(slow, rate_limit_per_minute=1000, max_concurrency=1, max_body_bytes=1000)
    out: list[Message] = []

    async def send(m: Message) -> None:
        out.append(m)

    async def receive() -> Message:
        return {"type": "http.request"}

    scope: Scope = {"type": "http", "path": "/mcp", "headers": [], "client": ("1.1.1.1", 1)}
    first = asyncio.create_task(mw(scope, receive, send))
    await asyncio.sleep(0.05)
    await mw(scope, receive, send)  # second request while the first holds the only slot
    assert out[0]["status"] == 503
    gate.set()
    await first
    assert any(m.get("status") == 200 for m in out)


async def test_non_http_scopes_pass_through() -> None:
    seen: list[str] = []

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        seen.append(scope["type"])

    mw = LimitsMiddleware(app, rate_limit_per_minute=1, max_concurrency=1, max_body_bytes=10)
    await mw({"type": "lifespan"}, None, None)  # type: ignore[arg-type]
    assert seen == ["lifespan"]


# ---- health / readiness / metrics -----------------------------------------------------------


async def test_health_and_ready(http: Http) -> None:
    assert (await http.client.get("/healthz")).json() == {"status": "ok"}
    r = await http.client.get("/readyz")
    assert r.status_code == 200 and r.json()["plugins"] == ["sample"]


async def test_not_ready_before_start_and_after_shutdown(issuer: Issuer, key_file: Path) -> None:
    stack = build_http_stack(make_settings(issuer, key_file))
    transport = httpx.ASGITransport(app=stack.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8000") as c:
        assert (await c.get("/readyz")).status_code == 503
        async with running(stack):
            assert (await c.get("/readyz")).status_code == 200
        assert (await c.get("/readyz")).status_code == 503


async def test_metrics_requires_admin_scope(http: Http, issuer: Issuer) -> None:
    assert (await http.client.get("/metrics")).status_code == 401
    weak = {"Authorization": f"Bearer {issuer.mint(scope='sample:read')}"}
    assert (await http.client.get("/metrics", headers=weak)).status_code == 403
    admin = {"Authorization": f"Bearer {issuer.mint(scope='admin:metrics')}"}
    r = await http.client.get("/metrics", headers=admin)
    assert r.status_code == 200 and "mcp_hub_tool_calls_total" in r.text


async def test_metrics_record_auth_failures_and_tool_calls(http: Http, issuer: Issuer) -> None:
    await http.rpc("tools/list", token=issuer.mint(exp_delta=-3600))
    await http.call_tool("echo", {"message": "m"}, issuer.mint())
    admin = {"Authorization": f"Bearer {issuer.mint(scope='admin:metrics')}"}
    text = (await http.client.get("/metrics", headers=admin)).text
    assert 'mcp_hub_auth_failures_total{reason="jwt_expired"}' in text
    assert 'mcp_hub_tool_calls_total{outcome="ok",tool="echo"}' in text
    assert "mcp_hub_http_requests_total" in text


# ---- startup guards (FR-9) ------------------------------------------------------------------


def test_public_bind_refused_without_auth_or_flag(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="allow_public_bind"):
        build_http_stack(Settings(http={"host": "0.0.0.0"}))
    with pytest.raises(ValueError, match="without authentication"):
        build_http_stack(Settings(http={"host": "0.0.0.0", "allow_public_bind": True}))


def test_unauthenticated_loopback_is_allowed_and_trusted() -> None:
    stack = build_http_stack(Settings())
    assert stack.built.plugins == ["sample"]


def test_auth_on_but_misconfigured_refuses_to_start() -> None:
    with pytest.raises(ValueError, match="resource_url"):
        build_http_stack(Settings(auth={"enabled": True}))
