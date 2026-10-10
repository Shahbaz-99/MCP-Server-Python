"""Fixtures: a local fake OIDC issuer (JWKS server + token minter) and an in-process HTTP stack."""

from __future__ import annotations

import asyncio
import json
import threading
import time
from collections.abc import AsyncIterator, Callable, Iterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from mcp_hub.config import Settings
from mcp_hub.http_app import HttpStack, build_http_stack
from mcp_hub.security.apikeys import KeyStore

RESOURCE = "https://mcp.test/mcp"
KID = "test-key-1"
ACCEPT = "application/json, text/event-stream"


def new_rsa() -> RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@dataclass
class Issuer:
    key: RSAPrivateKey
    url: str
    jwks_url: str
    hits: list[str] = field(default_factory=list)

    def mint(
        self,
        *,
        scope: str = "sample:read",
        aud: str | None = RESOURCE,
        iss: str | None = None,
        exp_delta: int = 300,
        key: RSAPrivateKey | None = None,
        kid: str | None = KID,
        alg: str = "RS256",
        drop: tuple[str, ...] = (),
        **extra: Any,
    ) -> str:
        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": iss or self.url,
            "aud": aud,
            "sub": "user-1",
            "azp": "client-1",
            "iat": now,
            "exp": now + exp_delta,
            "scope": scope,
            **extra,
        }
        for d in drop:
            claims.pop(d, None)
        headers = {"kid": kid} if kid else {}
        return jwt.encode(claims, key or self.key, algorithm=alg, headers=headers)


@pytest.fixture(scope="session")
def issuer_key() -> RSAPrivateKey:
    return new_rsa()


@pytest.fixture(scope="session")
def other_key() -> RSAPrivateKey:
    return new_rsa()


@pytest.fixture
def issuer(issuer_key: RSAPrivateKey) -> Iterator[Issuer]:
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(issuer_key.public_key()))
    jwk.update({"kid": KID, "use": "sig", "alg": "RS256"})
    body = json.dumps({"keys": [jwk]}).encode()
    hits: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            hits.append(self.path)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: Any) -> None:
            pass

    srv = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_port}"
    try:
        yield Issuer(issuer_key, base, f"{base}/jwks.json", hits)
    finally:
        srv.shutdown()
        srv.server_close()


@pytest.fixture
def key_file(tmp_path: Path) -> Path:
    return tmp_path / "keys.json"


def make_settings(issuer: Issuer, key_file: Path, **overrides: Any) -> Settings:
    base: dict[str, Any] = {
        "enabled_plugins": ["sample"],
        "auth": {
            "enabled": True,
            "issuer": issuer.url,
            "audience": RESOURCE,
            "resource_url": RESOURCE,
            "jwks_url": issuer.jwks_url,
            "api_key_file": str(key_file),
        },
    }
    for k, v in overrides.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            base[k] = {**base[k], **v}
        else:
            base[k] = v
    return Settings(**base)


@dataclass
class Http:
    client: httpx.AsyncClient
    stack: HttpStack
    keys: KeyStore

    async def rpc(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        *,
        token: str | None = None,
        headers: dict[str, str] | None = None,
        id_: int = 1,
    ) -> httpx.Response:
        h = {"Accept": ACCEPT, "Content-Type": "application/json", **(headers or {})}
        if token:
            h["Authorization"] = f"Bearer {token}"
        body = {"jsonrpc": "2.0", "id": id_, "method": method, "params": params or {}}
        return await self.client.post("/mcp", json=body, headers=h)

    async def call_tool(self, name: str, args: dict[str, Any], token: str) -> httpx.Response:
        return await self.rpc("tools/call", {"name": name, "arguments": args}, token=token)


HttpFactory = Callable[..., "AsyncIterator[Http]"]


@pytest.fixture
async def http(issuer: Issuer, key_file: Path) -> AsyncIterator[Http]:
    settings = make_settings(issuer, key_file)
    keys = KeyStore(key_file)
    stack = build_http_stack(settings, keystore=keys)
    async with running(stack):
        transport = httpx.ASGITransport(app=stack.app, client=("203.0.113.9", 5555))
        async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8000") as c:
            yield Http(c, stack, keys)


@asynccontextmanager
async def running(stack: HttpStack) -> AsyncIterator[None]:
    """Run the app lifespan inside ONE task (anyio cancel scopes must exit where they entered)."""
    ready, stop = asyncio.Event(), asyncio.Event()

    async def runner() -> None:
        async with stack.starlette.router.lifespan_context(stack.starlette):
            ready.set()
            await stop.wait()

    task = asyncio.create_task(runner())
    await asyncio.wait_for(ready.wait(), 10)
    try:
        yield
    finally:
        stop.set()
        await asyncio.wait_for(task, 10)
