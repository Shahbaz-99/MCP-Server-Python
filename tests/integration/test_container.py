"""Runs against an already running container. Set both variables to enable:

MCP_HUB_TEST_CONTAINER_URL=http://127.0.0.1:18000
MCP_HUB_TEST_CONTAINER_KEY=<API key with scopes sample:read and admin:metrics>
"""

from __future__ import annotations

import os

import httpx
import httpx2
import pytest
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp_types import TextContent

URL = os.environ.get("MCP_HUB_TEST_CONTAINER_URL", "")
KEY = os.environ.get("MCP_HUB_TEST_CONTAINER_KEY", "")
pytestmark = pytest.mark.skipif(not (URL and KEY), reason="container env vars not set")

ACCEPT = "application/json, text/event-stream"
LIST = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}


def _client(key: str | None) -> Client:
    headers = {"Authorization": f"Bearer {key}"} if key else {}
    http = httpx2.AsyncClient(headers=headers, timeout=30)
    return Client(streamable_http_client(f"{URL}/mcp", http_client=http))


async def test_full_mcp_flow_against_container() -> None:
    async with _client(KEY) as c:
        names = {t.name for t in (await c.list_tools()).tools}
        assert {"echo", "current_time", "countdown"} <= names
        r = await c.call_tool("echo", {"message": "from-container"})
        assert r.is_error is False
        assert isinstance(r.content[0], TextContent) and r.content[0].text == "from-container"
        assert (await c.read_resource("hub://about")) is not None
        assert [p.name for p in (await c.list_prompts()).prompts] == ["review_text"]


async def test_unauthenticated_and_bad_tokens_rejected() -> None:
    async with httpx.AsyncClient() as c:
        for headers in (
            {},
            {"Authorization": "Bearer nope"},
            {"Authorization": "Bearer mcph_aaaaaaaa_x"},
        ):
            r = await c.post(f"{URL}/mcp", json=LIST, headers={"Accept": ACCEPT, **headers})
            assert r.status_code == 401
            assert "resource_metadata" in r.headers["www-authenticate"]


async def test_bad_origin_and_host_rejected() -> None:
    async with httpx.AsyncClient() as c:
        h = {"Accept": ACCEPT, "Authorization": f"Bearer {KEY}"}
        assert (
            await c.post(f"{URL}/mcp", json=LIST, headers={**h, "Origin": "https://evil.example"})
        ).status_code == 403
        assert (
            await c.post(f"{URL}/mcp", json=LIST, headers={**h, "Host": "evil.example"})
        ).status_code in (400, 403, 421)


async def test_health_ready_and_metrics() -> None:
    async with httpx.AsyncClient() as c:
        assert (await c.get(f"{URL}/healthz")).json() == {"status": "ok"}
        assert (await c.get(f"{URL}/readyz")).json()["status"] == "ready"
        assert (await c.get(f"{URL}/metrics")).status_code == 401
        r = await c.get(f"{URL}/metrics", headers={"Authorization": f"Bearer {KEY}"})
        assert r.status_code == 200 and "mcp_hub_tool_calls_total" in r.text


async def test_oversize_body_rejected() -> None:
    async with httpx.AsyncClient() as c:
        r = await c.post(
            f"{URL}/mcp", content=b"x" * 2_000_000, headers={"Authorization": f"Bearer {KEY}"}
        )
        assert r.status_code == 413
