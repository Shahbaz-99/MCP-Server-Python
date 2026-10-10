"""CLI entry point: `python -m mcp_hub --transport stdio|http`, and `python -m mcp_hub keys ...`."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any

import anyio

from mcp_hub.config import CONFIG_FILE_ENV, Settings, masked_dump
from mcp_hub.errors import ConfigError, HubError
from mcp_hub.logging import configure_logging
from mcp_hub.observability import setup_tracing
from mcp_hub.security.apikeys import KeyStore
from mcp_hub.server import BuiltServer, build_server

_log = logging.getLogger("mcp_hub")
DEFAULT_KEY_FILE = Path("data/keys.json")


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


def _keys_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="mcp_hub keys", description="Manage API keys.")
    p.add_argument("--key-file", type=Path, help="Key store (default: auth.api_key_file)")
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("create", help="Create a key. The secret is shown once.")
    c.add_argument("--label", required=True)
    c.add_argument("--scopes", required=True, help="Comma-separated, e.g. sample:read,sql:read")
    c.add_argument("--expires-days", type=float)
    sub.add_parser("list", help="List keys (no secrets are stored or shown).")
    r = sub.add_parser("revoke", help="Revoke a key by id.")
    r.add_argument("key_id")
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


def _fmt_time(ts: int | None) -> str:
    return "never" if ts is None else time.strftime("%Y-%m-%dT%H:%MZ", time.gmtime(ts))


def keys_main(argv: list[str]) -> int:
    args = _keys_parser().parse_args(argv)
    try:
        settings = Settings()
    except ValueError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)  # noqa: T201
        return 2
    path = args.key_file or settings.auth.api_key_file or DEFAULT_KEY_FILE
    store = KeyStore(path)
    try:
        if args.cmd == "create":
            token, rec = store.create(
                args.label,
                [s.strip() for s in args.scopes.split(",") if s.strip()],
                args.expires_days,
            )
            print(f"id:      {rec.id}")  # noqa: T201
            print(f"scopes:  {','.join(rec.scopes)}")  # noqa: T201
            print(f"expires: {_fmt_time(rec.expires_at)}")  # noqa: T201
            print(f"key:     {token}")  # noqa: T201
            print("Store this key now. It cannot be shown again.", file=sys.stderr)  # noqa: T201
        elif args.cmd == "list":
            for r in store.list():
                state = "revoked" if r.revoked else "active"
                print(  # noqa: T201
                    f"{r.id}  {state:8} {r.label}  scopes={','.join(r.scopes)}  "
                    f"expires={_fmt_time(r.expires_at)}"
                )
        else:
            if not store.revoke(args.key_id):
                print(f"no such key: {args.key_id}", file=sys.stderr)  # noqa: T201
                return 1
            print(f"revoked {args.key_id}")  # noqa: T201
    except (HubError, OSError) as exc:
        print(f"error: {getattr(exc, 'message', exc)}", file=sys.stderr)  # noqa: T201
        return 1
    return 0


async def _run_stdio(built: BuiltServer) -> None:
    try:
        await built.server.run_stdio_async()
    finally:
        await built.registrar.run_shutdown()


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "keys":
        return keys_main(argv[1:])
    args = _parser().parse_args(argv)
    if args.config:
        os.environ[CONFIG_FILE_ENV] = args.config
    try:
        settings = Settings(**_overrides(args))
        settings.check_startup_invariants()
        if args.transport == "http":
            settings.check_http_invariants()
    except (ValueError, OSError) as exc:
        print(f"configuration error: {exc}", file=sys.stderr)  # noqa: T201
        return 2

    if args.print_config:
        json.dump(masked_dump(settings), sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0

    configure_logging(settings.log_level)
    try:
        if settings.tracing_enabled:
            setup_tracing(settings.server_name)
        if args.transport == "stdio":
            built = build_server(settings, local_trusted=True)
            _log.info("starting stdio transport; plugins=%s", built.plugins)
            anyio.run(_run_stdio, built)
        else:
            from mcp_hub.http_app import run_http

            run_http(settings)
    except (ConfigError, ValueError) as exc:
        _log.error("startup failed: %s", getattr(exc, "message", exc))
        return 2
    except KeyboardInterrupt:
        _log.info("interrupted; shutting down")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
