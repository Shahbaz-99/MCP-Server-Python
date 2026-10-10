"""Real network end-to-end: uvicorn subprocess, API key from the CLI, official SDK client."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path

import httpx
import httpx2
import pytest
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp_types import TextContent

from mcp_hub.__main__ import main

Server = tuple[str, Path, "subprocess.Popen[str]"]
ACCEPT = "application/json, text/event-stream"
LIST_TOOLS = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _create_key(key_file: Path, scopes: str, capsys: pytest.CaptureFixture[str]) -> tuple[str, str]:
    argv = ["keys", "--key-file", str(key_file), "create", "--label", "e2e", "--scopes", scopes]
    assert main(argv) == 0
    out = capsys.readouterr().out
    fields = dict(line.split(":", 1) for line in out.splitlines() if ":" in line)
    return fields["id"].strip(), fields["key"].strip()


@pytest.fixture
def server(tmp_path: Path) -> Iterator[Server]:
    port = _free_port()
    key_file = tmp_path / "keys.json"
    env = dict(os.environ)
    env.update(
        {
            "MCP_HUB_ENABLED_PLUGINS": '["sample"]',
            "MCP_HUB_AUTH__ENABLED": "true",
            "MCP_HUB_AUTH__RESOURCE_URL": f"http://127.0.0.1:{port}/mcp",
            "MCP_HUB_AUTH__API_KEY_FILE": str(key_file),
        }
    )
    proc = subprocess.Popen(  # noqa: S603
        [sys.executable, "-m", "mcp_hub", "--transport", "http", "--port", str(port)],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    base = f"http://127.0.0.1:{port}"
    try:
        deadline = time.time() + 30
        while time.time() < deadline:
            try:
                if httpx.get(f"{base}/readyz", timeout=1).status_code == 200:
                    break
            except httpx.HTTPError:
                time.sleep(0.2)
        else:
            proc.kill()
            raise AssertionError(
                f"server did not start: {proc.stderr.read() if proc.stderr else ''}"
            )
        yield base, key_file, proc
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()


async def _post(url: str, key: str | None = None) -> httpx.Response:
    headers = {"Accept": ACCEPT}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    async with httpx.AsyncClient() as c:
        return await c.post(url, json=LIST_TOOLS, headers=headers)


def _client(base: str, key: str | None) -> Client:
    headers = {"Authorization": f"Bearer {key}"} if key else {}
    http = httpx2.AsyncClient(headers=headers, timeout=30)
    return Client(streamable_http_client(f"{base}/mcp", http_client=http))


async def test_full_flow_over_http(server: Server, capsys: pytest.CaptureFixture[str]) -> None:
    base, key_file, _ = server
    key_id, key = _create_key(key_file, "sample:read", capsys)

    async with _client(base, key) as c:
        names = {t.name for t in (await c.list_tools()).tools}
        assert {"echo", "current_time", "safe_fs_list", "safe_fs_read"} <= names
        r = await c.call_tool("echo", {"message": "over-http"})
        assert r.is_error is False
        assert isinstance(r.content[0], TextContent) and r.content[0].text == "over-http"
        assert (await c.read_resource("hub://about")) is not None
        assert [p.name for p in (await c.list_prompts()).prompts] == ["review_text"]

    # unauthenticated MCP request is refused at the HTTP layer
    anon = await _post(f"{base}/mcp")
    assert anon.status_code == 401 and "resource_metadata" in anon.headers["www-authenticate"]

    # revocation takes effect on the running server without a restart
    assert main(["keys", "--key-file", str(key_file), "revoke", key_id]) == 0
    assert (await _post(f"{base}/mcp", key)).status_code == 401


async def test_key_scope_limits_tools_over_http(
    server: Server, capsys: pytest.CaptureFixture[str]
) -> None:
    base, key_file, _ = server
    _, key = _create_key(key_file, "github:read", capsys)
    async with _client(base, key) as c:
        r = await c.call_tool("echo", {"message": "x"})
        assert r.is_error is True


async def test_server_logs_contain_no_secrets(
    server: Server, capsys: pytest.CaptureFixture[str]
) -> None:
    base, key_file, proc = server
    _, key = _create_key(key_file, "sample:read", capsys)
    assert (await _post(f"{base}/mcp", key)).status_code == 200
    proc.terminate()
    proc.wait(timeout=15)
    logs = proc.stderr.read() if proc.stderr else ""
    assert key not in logs and key.split("_", 2)[2] not in logs
    for line in logs.splitlines():
        if line.strip():
            json.loads(line)  # every log line is valid JSON


def test_public_bind_refused_by_cli(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--transport", "http", "--host", "0.0.0.0"]) == 2
    assert "allow_public_bind" in capsys.readouterr().err
    assert main(["--transport", "http", "--host", "0.0.0.0", "--allow-public-bind"]) == 2
    assert "authentication" in capsys.readouterr().err


def test_keys_cli_lifecycle(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    kf = tmp_path / "k.json"
    assert main(["keys", "--key-file", str(kf), "create", "--label", "a", "--scopes", "*"]) == 0
    out = capsys.readouterr().out
    key_id = next(ln.split(":", 1)[1].strip() for ln in out.splitlines() if ln.startswith("id"))
    assert main(["keys", "--key-file", str(kf), "list"]) == 0
    listing = capsys.readouterr().out
    assert key_id in listing and "active" in listing
    assert "mcph_" not in kf.read_text()  # hashes only, never the key
    assert main(["keys", "--key-file", str(kf), "revoke", key_id]) == 0
    assert main(["keys", "--key-file", str(kf), "revoke", "nonexistent"]) == 1
    assert main(["keys", "--key-file", str(kf), "list"]) == 0
    assert "revoked" in capsys.readouterr().out
    bad = ["keys", "--key-file", str(kf), "create", "--label", "b", "--scopes", "BAD SCOPE"]
    assert main(bad) == 1
