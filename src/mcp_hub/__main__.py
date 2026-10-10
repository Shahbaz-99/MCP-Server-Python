"""CLI entry point: `python -m mcp_hub --transport stdio|http`."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from typing import Any

import anyio

from mcp_hub.config import CONFIG_FILE_ENV, Settings, masked_dump
from mcp_hub.errors import ConfigError
from mcp_hub.logging import configure_logging
from mcp_hub.server import build_server

_log = logging.getLogger("mcp_hub")


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="mcp_hub", description="Plugin-based MCP server.")
    p.add_argument("--transport", choices=["stdio", "http"], default="stdio")
    p.add_argument("--host")
    p.add_argument("--port", type=int)
    p.add_argument("--allow-public-bind", action="store_true")
    p.add_argument("--config", help="YAML config file")
    p.add_argument("--log-level")
    p.add_argument("--print-config", action="store_true", help="Print effective config and exit")
    return p


def _overrides(args: argparse.Namespace) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if args.log_level:
        out["log_level"] = args.log_level
    http: dict[str, Any] = {}
    if args.host:
        http["host"] = args.host
    if args.port:
        http["port"] = args.port
    if args.allow_public_bind:
        http["allow_public_bind"] = True
    if http:
        out["http"] = http
    return out


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.config:
        os.environ[CONFIG_FILE_ENV] = args.config
    try:
        settings = Settings(**_overrides(args))
        settings.check_startup_invariants()
    except (ValueError, OSError) as exc:
        print(f"configuration error: {exc}", file=sys.stderr)  # noqa: T201
        return 2

    if args.print_config:
        json.dump(masked_dump(settings), sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0

    configure_logging(settings.log_level)
    try:
        if args.transport == "stdio":
            built = build_server(settings, local_trusted=True)
            _log.info("starting stdio transport; plugins=%s", built.plugins)
            anyio.run(built.server.run_stdio_async)
        else:
            from mcp_hub.http_app import run_http

            run_http(settings)
    except ConfigError as exc:
        _log.error("startup failed: %s", exc)
        return 2
    except KeyboardInterrupt:
        _log.info("interrupted; shutting down")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
