"""Spawns the real server as a subprocess and drives it over stdio."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from mcp import Client
from mcp.client.stdio import StdioServerParameters
from mcp_types import TextContent


def _env(sandbox: Path) -> dict[str, str]:
    env = dict(os.environ)
    env["MCP_HUB_ENABLED_PLUGINS"] = '["sample"]'
    env["MCP_HUB_SAMPLE__FS_ROOTS"] = json.dumps([str(sandbox)])
    return env


@pytest.fixture
def sandbox(tmp_path: Path) -> Path:
    box = tmp_path / "box"
    box.mkdir()
    (box / "hello.txt").write_text("hi there", encoding="utf-8")
    (box / "sub").mkdir()
    return box


def _params(sandbox: Path) -> StdioServerParameters:
    return StdioServerParameters(
        command=sys.executable, args=["-m", "mcp_hub", "--transport", "stdio"], env=_env(sandbox)
    )


def _text(result: object) -> str:
    content = result.content  # type: ignore[attr-defined]
    assert content and isinstance(content[0], TextContent)
    return str(content[0].text)


async def test_full_flow(sandbox: Path) -> None:
    async with Client(_params(sandbox)) as client:
        tools = {t.name: t for t in (await client.list_tools()).tools}
        assert set(tools) == {"echo", "current_time", "countdown", "safe_fs_list", "safe_fs_read"}
        for t in tools.values():
            assert t.annotations is not None
            assert t.annotations.read_only_hint is True
            assert t.description

        # schema survived the guard wrapper
        assert "message" in tools["echo"].input_schema["properties"]
        assert tools["echo"].input_schema["required"] == ["message"]

        assert _text(await client.call_tool("echo", {"message": "ping"})) == "ping"
        assert "T" in _text(await client.call_tool("current_time", {"timezone": "Asia/Tokyo"}))
        assert "hello.txt" in _text(await client.call_tool("safe_fs_list", {}))
        assert _text(await client.call_tool("safe_fs_read", {"path": "hello.txt"})) == "hi there"

        res = await client.read_resource("hub://about")
        assert "mcp_hub" in str(res)
        prompts = (await client.list_prompts()).prompts
        assert [p.name for p in prompts] == ["review_text"]
        got = await client.get_prompt("review_text", {"text": "abc"})
        assert "abc" in str(got)


async def test_errors_are_tool_errors(sandbox: Path) -> None:
    async with Client(_params(sandbox)) as client:
        for args in ({"path": "../x"}, {"path": "/etc/passwd"}, {"path": "C:\\Windows\\win.ini"}):
            r = await client.call_tool("safe_fs_read", args)
            assert r.is_error is True
        r = await client.call_tool("current_time", {"timezone": "Not/AZone"})
        assert r.is_error is True
        r = await client.call_tool("echo", {})  # missing arg
        assert r.is_error is True
        r = await client.call_tool("nope", {})
        assert r.is_error is True


def test_stdout_is_only_json_rpc(sandbox: Path) -> None:
    msgs = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "t", "version": "0"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "echo", "arguments": {"message": "x"}},
        },
    ]
    proc = subprocess.Popen(
        [sys.executable, "-m", "mcp_hub", "--transport", "stdio"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=_env(sandbox),
    )
    assert proc.stdin is not None
    assert proc.stdout is not None
    assert proc.stderr is not None
    lines: list[str] = []
    try:
        for m in msgs:
            proc.stdin.write(json.dumps(m) + "\n")
            proc.stdin.flush()
        # keep stdin open until every reply arrived; EOF legitimately ends the server
        while {json.loads(ln).get("id") for ln in lines} < {1, 2, 3}:
            line = proc.stdout.readline()
            assert line, "server closed stdout early"
            lines.append(line)
    finally:
        proc.stdin.close()
    rest = proc.stdout.read()
    stderr = proc.stderr.read()
    proc.wait(timeout=30)
    for ln in [*lines, *rest.splitlines()]:
        if ln.strip():
            obj = json.loads(ln)  # raises if any non-JSON byte leaks to stdout
            assert obj["jsonrpc"] == "2.0"
    assert "tool_call" in stderr  # audit + logs go to stderr


def test_print_config_masks_secrets() -> None:
    env = dict(os.environ)
    env["MCP_HUB_GITHUB__TOKEN"] = "ghp_" + "z" * 30
    out = subprocess.run(
        [sys.executable, "-m", "mcp_hub", "--print-config"],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
        check=True,
    ).stdout
    assert "ghp_" not in out
    assert json.loads(out)["http"]["host"] == "127.0.0.1"


def test_bad_config_exits_2() -> None:
    env = dict(os.environ)
    env["MCP_HUB_ENABLED_PLUGINS"] = '["nope"]'
    p = subprocess.run(
        [sys.executable, "-m", "mcp_hub", "--transport", "stdio"],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
        check=False,
    )
    assert p.returncode == 2
    assert p.stdout == ""
