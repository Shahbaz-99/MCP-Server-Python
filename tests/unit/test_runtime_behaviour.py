"""Cancellation, progress, tracing and metrics behaviour of the tool guard."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import pytest
from mcp import Client
from mcp.server.mcpserver import MCPServer
from mcp_types import TextContent
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from prometheus_client import REGISTRY

from mcp_hub import observability
from mcp_hub.config import Settings
from mcp_hub.plugins import base
from mcp_hub.plugins.base import Registrar
from mcp_hub.security.identity import IdentityResolver
from mcp_hub.server import build_server


def _metric(name: str, **labels: str) -> float:
    return REGISTRY.get_sample_value(name, labels) or 0.0


async def test_progress_notifications_reach_the_client() -> None:
    built = build_server(Settings(), local_trusted=True)
    seen: list[tuple[float, float | None, str | None]] = []

    async def on_progress(progress: float, total: float | None, message: str | None) -> None:
        seen.append((progress, total, message))

    async with Client(built.server) as c:
        r = await c.call_tool("countdown", {"seconds": 2}, progress_callback=on_progress)
    assert r.is_error is False
    assert seen[0][0] == 0 and seen[-1] == (2, 2, "done")
    assert [p for p, _, _ in seen] == sorted(p for p, _, _ in seen)  # monotonic


async def test_countdown_input_is_bounded() -> None:
    built = build_server(Settings(), local_trusted=True)
    async with Client(built.server) as c:
        for bad in (0, -1, 31, 10_000):
            r = await c.call_tool("countdown", {"seconds": bad})
            assert r.is_error is True


async def test_cancellation_stops_the_tool_and_is_recorded_as_cancelled() -> None:
    server: MCPServer[Any] = MCPServer("t")
    reg = Registrar(server, Settings(), IdentityResolver(local_trusted=True))
    started, cleaned = asyncio.Event(), asyncio.Event()

    @reg.tool(name="hang", description="d", scopes=("x:read",), read_only=True)
    async def hang() -> str:
        started.set()
        try:
            await asyncio.sleep(60)
        finally:
            cleaned.set()  # cleanup code in tools must still run on cancellation
        return "never"

    before = _metric("mcp_hub_tool_calls_total", tool="hang", outcome="cancelled")
    async with Client(server) as c:
        task = asyncio.create_task(c.call_tool("hang", {}))
        await asyncio.wait_for(started.wait(), 5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await asyncio.wait_for(cleaned.wait(), 5)
        await asyncio.sleep(0.1)
    assert _metric("mcp_hub_tool_calls_total", tool="hang", outcome="cancelled") == before + 1
    assert _metric("mcp_hub_tool_calls_total", tool="hang", outcome="ok") == 0


async def test_timeout_cleans_up_and_counts_as_error() -> None:
    server: MCPServer[Any] = MCPServer("t")
    reg = Registrar(
        server, Settings(tool_timeout_seconds=0.2), IdentityResolver(local_trusted=True)
    )
    cleaned = asyncio.Event()

    @reg.tool(name="slow2", description="d", scopes=("x:read",), read_only=True)
    async def slow2() -> str:
        try:
            await asyncio.sleep(30)
        finally:
            cleaned.set()
        return "never"

    async with Client(server) as c:
        r = await c.call_tool("slow2", {})
    assert r.is_error is True and cleaned.is_set()
    assert _metric("mcp_hub_tool_errors_total", tool="slow2", code="timeout") == 1.0


async def test_spans_carry_tool_name_but_no_arguments_or_error_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    monkeypatch.setattr(base, "get_tracer", lambda: provider.get_tracer("test"))

    server: MCPServer[Any] = MCPServer("t")
    reg = Registrar(server, Settings(), IdentityResolver(local_trusted=True))

    @reg.tool(name="ok_tool", description="d", scopes=("x:read",), read_only=True)
    async def ok_tool(secret_arg: str) -> str:
        return "fine"

    @reg.tool(name="bad_tool", description="d", scopes=("x:read",), read_only=True)
    async def bad_tool() -> str:
        raise RuntimeError("password=hunter2")

    async with Client(server) as c:
        await c.call_tool("ok_tool", {"secret_arg": "sk-very-secret"})
        await c.call_tool("bad_tool", {})
    spans = {s.name: s for s in exporter.get_finished_spans()}
    assert set(spans) == {"tool ok_tool", "tool bad_tool"}
    dump = repr([(s.name, dict(s.attributes or {}), s.events) for s in spans.values()])
    assert "sk-very-secret" not in dump and "hunter2" not in dump
    assert spans["tool ok_tool"].attributes["mcp.tool"] == "ok_tool"  # type: ignore[index]
    assert spans["tool bad_tool"].events == ()  # exception text is never recorded


def test_setup_tracing_installs_otlp_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[Any] = []
    monkeypatch.setattr(trace, "set_tracer_provider", captured.append)
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:4318")
    observability.setup_tracing("svc")
    assert len(captured) == 1 and captured[0].resource.attributes["service.name"] == "svc"
    captured[0].shutdown()


def test_get_tracer_is_a_noop_without_provider() -> None:
    with observability.get_tracer().start_as_current_span("x") as span:
        assert span is not None  # never raises, costs nothing when tracing is off


async def test_audit_marks_cancelled_calls(caplog: pytest.LogCaptureFixture) -> None:
    server: MCPServer[Any] = MCPServer("t")
    reg = Registrar(server, Settings(), IdentityResolver(local_trusted=True))
    started = asyncio.Event()

    @reg.tool(name="hang2", description="d", scopes=("x:read",), read_only=True)
    async def hang2() -> str:
        started.set()
        await asyncio.sleep(60)
        return "never"

    with caplog.at_level(logging.INFO, logger="mcp_hub.audit"):
        async with Client(server) as c:
            task = asyncio.create_task(c.call_tool("hang2", {}))
            await asyncio.wait_for(started.wait(), 5)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            await asyncio.sleep(0.1)
    rec = [r for r in caplog.records if r.name == "mcp_hub.audit"]
    assert rec and rec[-1].fields["outcome"] == "cancelled"  # type: ignore[attr-defined]


async def test_text_content_of_tool_result_is_plain() -> None:
    built = build_server(Settings(), local_trusted=True)
    async with Client(built.server) as c:
        r = await c.call_tool("echo", {"message": "x"})
    assert isinstance(r.content[0], TextContent)
