"""Sample plugin: echo, time, and sandboxed filesystem tools. Also proves resources and prompts."""

from __future__ import annotations

import asyncio
import datetime as dt
from pathlib import Path
from typing import Annotated, Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from mcp.server.mcpserver import Context
from pydantic import Field

from mcp_hub.errors import AccessDenied, ConfigError, LimitExceeded, NotFound, ValidationFailed
from mcp_hub.plugins.base import Registrar
from mcp_hub.plugins.sample.paths import resolve_safe

SCOPE_READ = "sample:read"


def _roots(registrar: Registrar) -> dict[str, Path]:
    roots: dict[str, Path] = {}
    for p in registrar.settings.sample.fs_roots:
        if not p.is_dir():
            raise ConfigError(f"sample.fs_roots entry is not a directory: {p}")
        alias = p.resolve().name
        if alias in roots:
            raise ConfigError(f"sample.fs_roots has duplicate directory name: {alias}")
        roots[alias] = p
    return roots


def register(registrar: Registrar) -> None:
    settings = registrar.settings.sample
    roots = _roots(registrar)

    def pick_root(root: str | None) -> Path:
        if not roots:
            raise AccessDenied("No filesystem roots are configured.")
        if root is None:
            if len(roots) == 1:
                return next(iter(roots.values()))
            raise ValidationFailed(f"Specify root, one of: {', '.join(sorted(roots))}")
        if root not in roots:
            raise NotFound(f"Unknown root. Available: {', '.join(sorted(roots))}")
        return roots[root]

    @registrar.tool(
        name="echo",
        description="Return the given message unchanged. Useful to test connectivity.",
        scopes=(SCOPE_READ,),
        read_only=True,
    )
    async def echo(message: Annotated[str, Field(max_length=10_000)]) -> str:
        return message

    @registrar.tool(
        name="current_time",
        description="Current date and time in an IANA timezone (default UTC), ISO 8601.",
        scopes=(SCOPE_READ,),
        read_only=True,
        idempotent=False,
    )
    async def current_time(timezone: Annotated[str, Field(max_length=64)] = "UTC") -> str:
        try:
            tz = ZoneInfo(timezone)
        except (ZoneInfoNotFoundError, ValueError, OSError):
            raise ValidationFailed(
                "Unknown timezone. Use an IANA name such as Europe/Paris."
            ) from None
        return dt.datetime.now(tz).isoformat()

    @registrar.tool(
        name="countdown",
        description=(
            "Count down from N seconds, reporting progress each second. Demonstrates progress "
            "notifications and cancellation for long-running tools."
        ),
        scopes=(SCOPE_READ,),
        read_only=True,
        idempotent=False,
    )
    async def countdown(seconds: Annotated[int, Field(ge=1, le=30)], ctx: Context[Any, Any]) -> str:
        for done in range(seconds):
            await ctx.report_progress(done, seconds, f"{seconds - done}s left")
            await asyncio.sleep(1)
        await ctx.report_progress(seconds, seconds, "done")
        return "done"

    @registrar.tool(
        name="safe_fs_list",
        description="List entries of a directory inside a configured sandbox root.",
        scopes=(SCOPE_READ,),
        read_only=True,
    )
    async def safe_fs_list(
        path: Annotated[str, Field(max_length=1024)] = "",
        root: Annotated[str | None, Field(max_length=255)] = None,
    ) -> list[str]:
        base = pick_root(root)
        target = resolve_safe(base, path)
        if not target.is_dir():
            raise ValidationFailed("Not a directory.")
        names = sorted(f"{e.name}/" if e.is_dir() else e.name for e in target.iterdir())
        if len(names) > settings.max_list_entries:
            raise LimitExceeded(f"Directory has more than {settings.max_list_entries} entries.")
        return names

    @registrar.tool(
        name="safe_fs_read",
        description="Read a UTF-8 text file inside a configured sandbox root (size-capped).",
        scopes=(SCOPE_READ,),
        read_only=True,
    )
    async def safe_fs_read(
        path: Annotated[str, Field(min_length=1, max_length=1024)],
        root: Annotated[str | None, Field(max_length=255)] = None,
    ) -> str:
        base = pick_root(root)
        target = resolve_safe(base, path)
        if not target.is_file():
            raise ValidationFailed("Not a regular file.")
        if target.stat().st_size > settings.max_read_bytes:
            raise LimitExceeded(f"File larger than {settings.max_read_bytes} bytes.")
        with target.open("rb") as fh:
            data = fh.read(settings.max_read_bytes + 1)
        if len(data) > settings.max_read_bytes:
            raise LimitExceeded(f"File larger than {settings.max_read_bytes} bytes.")
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            raise ValidationFailed("File is not valid UTF-8 text.") from None

    @registrar.server.resource("hub://about", name="about", mime_type="text/plain")
    def about() -> str:
        return "mcp_hub: plugin-based MCP server. Enabled plugins are listed by the tools you see."

    @registrar.server.prompt(name="review_text", description="Ask the model to review a text.")
    def review_text(text: str) -> str:
        return f"Review the following text for clarity and errors:\n\n{text}"
