"""Tool guard, identity and registry, exercised in-process."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

import pytest
from mcp import Client
from mcp.server.auth.provider import AccessToken
from mcp.server.mcpserver import MCPServer
from mcp_types import TextContent

from mcp_hub.__main__ import main
from mcp_hub.config import Settings
from mcp_hub.errors import AccessDenied, ConfigError, NotFound
from mcp_hub.plugins.base import Registrar
from mcp_hub.registry import load_plugin, register_plugins
from mcp_hub.security import identity as identity_mod
from mcp_hub.security.audit import args_hash
from mcp_hub.security.identity import Identity, IdentityResolver
from mcp_hub.server import build_server


def _registrar(local_trusted: bool = True, **settings: Any) -> Registrar:
    s = Settings(**settings)
    return Registrar(MCPServer("t"), s, IdentityResolver(local_trusted=local_trusted))


async def _call(reg: Registrar, tool: str, args: dict[str, Any]) -> tuple[bool, str]:
    async with Client(reg.server) as c:
        r = await c.call_tool(tool, args)
        assert isinstance(r.content[0], TextContent)
        return bool(r.is_error), r.content[0].text


async def test_guard_ok_denied_timeout_and_masking(caplog: pytest.LogCaptureFixture) -> None:
    reg = _registrar(tool_timeout_seconds=0.2)

    @reg.tool(name="ok", description="d", scopes=("x:read",), read_only=True)
    async def ok(a: int) -> int:
        return a + 1

    @reg.tool(name="slow", description="d", scopes=("x:read",), read_only=True)
    async def slow() -> str:
        await asyncio.sleep(5)
        return "never"

    @reg.tool(name="hub_err", description="d", scopes=("x:read",), read_only=True)
    async def hub_err() -> str:
        raise NotFound("thing missing")

    @reg.tool(name="crash", description="d", scopes=("x:read",), read_only=True)
    async def crash() -> str:
        raise RuntimeError("password=hunter2 in dsn")

    assert await _call(reg, "ok", {"a": 1}) == (False, "2")
    err, text = await _call(reg, "slow", {})
    assert err and "timed out" in text
    err, text = await _call(reg, "hub_err", {})
    assert err and text.endswith("thing missing")
    with caplog.at_level(logging.ERROR):
        err, text = await _call(reg, "crash", {})
    assert err and "hunter2" not in text and "Internal error" in text


async def test_scope_enforced_for_remote_without_token() -> None:
    reg = _registrar(local_trusted=False)

    @reg.tool(name="t", description="d", scopes=("x:read",), read_only=True)
    async def t() -> str:
        return "secret"

    err, text = await _call(reg, "t", {})
    assert err and "Authentication required" in text


def test_identity_scope_logic() -> None:
    ident = Identity("u", frozenset({"a", "b"}), "oauth")
    assert ident.allows(("a",)) and ident.allows(("a", "b")) and not ident.allows(("c",))
    assert Identity("l", frozenset({"*"}), "local").allows(("anything",))


def test_resolver_with_token(monkeypatch: pytest.MonkeyPatch) -> None:
    tok = AccessToken(token="t", client_id="c1", scopes=["a"], subject="sub1")
    monkeypatch.setattr(identity_mod, "get_access_token", lambda: tok)
    r = IdentityResolver(local_trusted=False)
    assert r.current().subject == "sub1" and r.current().kind == "oauth"
    assert r.require(("a",)).scopes == frozenset({"a"})
    with pytest.raises(AccessDenied):
        r.require(("b",))
    key_tok = AccessToken(token="t", client_id="c1", scopes=["a"], claims={"kind": "apikey"})
    monkeypatch.setattr(identity_mod, "get_access_token", lambda: key_tok)
    assert r.current().kind == "apikey"
    assert r.current().subject == "c1"


def test_registrar_rejects_bad_tools() -> None:
    reg = _registrar()

    async def f() -> str:
        return "x"

    def sync_fn() -> str:
        return "x"

    reg.tool(name="a", description="d", scopes=("s",), read_only=True)(f)
    with pytest.raises(ConfigError, match="duplicate"):
        reg.tool(name="a", description="d", scopes=("s",), read_only=True)
    with pytest.raises(ConfigError, match="scope"):
        reg.tool(name="b", description="d", scopes=(), read_only=True)
    with pytest.raises(ConfigError, match="async"):
        reg.tool(name="c", description="d", scopes=("s",), read_only=True)(sync_fn)  # type: ignore[arg-type]


async def test_shutdown_hooks_run_in_reverse_and_survive_errors() -> None:
    reg = _registrar()
    order: list[str] = []

    async def one() -> None:
        order.append("one")

    async def boom() -> None:
        raise RuntimeError("x")

    async def three() -> None:
        order.append("three")

    for fn in (one, boom, three):
        reg.on_shutdown(fn)
    await reg.run_shutdown()
    assert order == ["three", "one"]


def test_registry_rules() -> None:
    with pytest.raises(ConfigError, match="unknown plugin"):
        load_plugin("nope")
    with pytest.raises(ConfigError, match="twice"):
        register_plugins(_registrar(), ["sample", "sample"])


def test_sample_root_misconfig(tmp_path: Any) -> None:
    f = tmp_path / "file"
    f.write_text("x")
    with pytest.raises(ConfigError, match="not a directory"):
        register_plugins(_registrar(sample={"fs_roots": [str(f)]}), ["sample"])
    a = tmp_path / "a" / "same"
    b = tmp_path / "b" / "same"
    a.mkdir(parents=True)
    b.mkdir(parents=True)
    with pytest.raises(ConfigError, match="duplicate directory"):
        register_plugins(_registrar(sample={"fs_roots": [str(a), str(b)]}), ["sample"])


async def test_sample_tools_in_process(tmp_path: Any) -> None:
    a = tmp_path / "alpha"
    b = tmp_path / "beta"
    for d in (a, b):
        d.mkdir()
    (a / "f.txt").write_text("hello")
    (a / "bin.dat").write_bytes(b"\xff\xfe\x00")
    (a / "big.txt").write_text("x" * 50)
    built = build_server(
        Settings(
            sample={"fs_roots": [str(a), str(b)], "max_read_bytes": 20, "max_list_entries": 2}
        ),
        local_trusted=True,
    )
    async with Client(built.server) as c:

        async def call(name: str, args: dict[str, Any]) -> tuple[bool, str]:
            r = await c.call_tool(name, args)
            assert isinstance(r.content[0], TextContent)
            return bool(r.is_error), r.content[0].text

        assert (await call("safe_fs_read", {"path": "f.txt"}))[0]  # root required (2 roots)
        assert (await call("safe_fs_read", {"path": "f.txt", "root": "zzz"}))[0]
        assert await call("safe_fs_read", {"path": "f.txt", "root": "alpha"}) == (False, "hello")
        assert "alpha" in (await call("safe_fs_read", {"path": "f.txt"}))[1]
        assert (await call("safe_fs_read", {"path": "bin.dat", "root": "alpha"}))[0]
        assert "larger" in (await call("safe_fs_read", {"path": "big.txt", "root": "alpha"}))[1]
        assert (await call("safe_fs_read", {"path": "", "root": "alpha"}))[0]  # min_length
        assert (await call("safe_fs_list", {"root": "alpha"}))[0]  # >2 entries
        empty = await c.call_tool("safe_fs_list", {"root": "beta"})
        assert empty.is_error is False
        assert empty.structured_content == {"result": []}
        assert (await call("safe_fs_list", {"path": "f.txt", "root": "alpha"}))[0]
        assert (await call("safe_fs_read", {"path": ".", "root": "alpha"}))[0]  # dir, not file


async def test_no_roots_denies() -> None:
    built = build_server(Settings(), local_trusted=True)
    async with Client(built.server) as c:
        r = await c.call_tool("safe_fs_list", {})
        assert r.is_error


def test_args_hash_stable_and_hides_values() -> None:
    h = args_hash({"b": 2, "a": "secret-value"})
    assert h == args_hash({"a": "secret-value", "b": 2})
    assert "secret" not in h


def test_main_print_config_and_errors(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--print-config", "--port", "9123", "--log-level", "debug"]) == 0
    cfg = json.loads(capsys.readouterr().out)
    assert cfg["http"]["port"] == 9123 and cfg["log_level"] == "DEBUG"
    assert main(["--print-config", "--allow-public-bind", "--host", "0.0.0.0"]) == 0
    assert main(["--log-level", "LOUD"]) == 2
    assert "configuration error" in capsys.readouterr().err
