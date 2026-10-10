"""Plugin contract and the hardened tool wrapper every plugin tool goes through."""

from __future__ import annotations

import asyncio
import functools
import inspect
import logging
import time
from collections.abc import Awaitable, Callable
from typing import Any, ParamSpec, TypeVar

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp_types import ToolAnnotations

from mcp_hub import observability as obs
from mcp_hub.config import Settings
from mcp_hub.errors import ConfigError, HubError, ToolTimeout, to_public_message
from mcp_hub.security.audit import record_tool_call
from mcp_hub.security.identity import IdentityResolver

P = ParamSpec("P")
R = TypeVar("R")
_log = logging.getLogger(__name__)


class Registrar:
    """Handed to each plugin's `register()`. Plugins never touch the MCPServer tool API directly."""

    def __init__(self, server: MCPServer[Any], settings: Settings, resolver: IdentityResolver):
        self.server = server
        self.settings = settings
        self._resolver = resolver
        self._tool_names: set[str] = set()
        self._shutdown: list[Callable[[], Awaitable[None]]] = []
        self.plugin = ""

    def on_shutdown(self, fn: Callable[[], Awaitable[None]]) -> None:
        self._shutdown.append(fn)

    async def run_shutdown(self) -> None:
        for fn in reversed(self._shutdown):
            try:
                await fn()
            except Exception:
                _log.exception("shutdown hook failed")

    def tool(
        self,
        *,
        name: str,
        description: str,
        scopes: tuple[str, ...],
        read_only: bool,
        destructive: bool = False,
        idempotent: bool = True,
        open_world: bool = False,
        timeout: float | None = None,
    ) -> Callable[[Callable[P, Awaitable[R]]], Callable[P, Awaitable[R]]]:
        if name in self._tool_names:
            raise ConfigError(f"duplicate tool name: {name}")
        if not scopes:
            raise ConfigError(f"tool {name} must declare at least one scope")
        self._tool_names.add(name)
        limit = timeout if timeout is not None else self.settings.tool_timeout_seconds
        annotations = ToolAnnotations(
            title=name,
            read_only_hint=read_only,
            destructive_hint=destructive,
            idempotent_hint=idempotent,
            open_world_hint=open_world,
        )

        def decorator(fn: Callable[P, Awaitable[R]]) -> Callable[P, Awaitable[R]]:
            if not inspect.iscoroutinefunction(fn):
                raise ConfigError(f"tool {name} must be an async function")

            @functools.wraps(fn)
            async def guarded(*args: P.args, **kwargs: P.kwargs) -> R:
                start = time.perf_counter()
                outcome, code = "ok", ""
                ident_subject, ident_kind = "unknown", "unknown"
                try:
                    ident = self._resolver.require(scopes)
                    ident_subject, ident_kind = ident.subject, ident.kind
                    async with asyncio.timeout(limit):
                        return await fn(*args, **kwargs)
                except TimeoutError:
                    outcome, code = "error", ToolTimeout.code
                    raise ToolError(f"Tool timed out after {limit:g}s.") from None
                except ToolError:
                    outcome, code = "error", "tool_error"
                    raise
                except Exception as exc:
                    code, message = to_public_message(exc)
                    outcome = "denied" if code == "access_denied" else "error"
                    if not isinstance(exc, HubError):
                        _log.exception("tool %s crashed", name)
                    raise ToolError(message) from None
                finally:
                    elapsed = time.perf_counter() - start
                    obs.TOOL_CALLS.labels(tool=name, outcome=outcome).inc()
                    obs.TOOL_LATENCY.labels(tool=name).observe(elapsed)
                    if code:
                        obs.TOOL_ERRORS.labels(tool=name, code=code).inc()
                    record_tool_call(
                        identity=ident_subject,
                        kind=ident_kind,
                        tool=name,
                        arguments=_bound_args(fn, args, kwargs),
                        outcome=outcome if not code else f"{outcome}:{code}",
                        latency_ms=elapsed * 1000,
                    )

            self.server.add_tool(
                guarded,
                name=name,
                description=description,
                annotations=annotations,
                meta={"scopes": list(scopes), "plugin": self.plugin},
            )
            return guarded

        return decorator


def _bound_args(
    fn: Callable[..., Any], args: tuple[Any, ...], kwargs: dict[str, Any]
) -> dict[str, Any]:
    try:
        bound = inspect.signature(fn).bind_partial(*args, **kwargs)
        return {k: v for k, v in bound.arguments.items() if k != "ctx"}
    except TypeError:
        return {}
