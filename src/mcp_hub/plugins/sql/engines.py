"""Database engines. Every session is read-only at the database level (layer 2)."""

from __future__ import annotations

import asyncio
import base64
import datetime as dt
import decimal
import json
import re
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import unquote, urlparse

import aiosqlite
import asyncpg

from mcp_hub.config import SqlConnection
from mcp_hub.errors import ConfigError, LimitExceeded, UpstreamError, ValidationFailed

TABLE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_$]{0,127}(\.[A-Za-z_][A-Za-z0-9_$]{0,127})?$")
MAX_PARAMS = 50
Param = str | int | float | bool | None


@dataclass
class QueryResult:
    columns: list[str]
    rows: list[list[Any]]
    truncated: bool
    truncated_reason: str | None = None


class Engine(Protocol):
    dialect: str

    async def query(self, sql: str, params: list[Param]) -> QueryResult: ...
    async def list_tables(self) -> QueryResult: ...
    async def describe_table(self, table: str) -> QueryResult: ...
    async def close(self) -> None: ...


def jsonable(value: Any) -> Any:
    if value is None or isinstance(value, bool | int | str):
        return value
    if isinstance(value, float):
        return value if value == value and abs(value) != float("inf") else str(value)
    if isinstance(value, decimal.Decimal | uuid.UUID):
        return str(value)
    if isinstance(value, dt.datetime | dt.date | dt.time):
        return value.isoformat()
    if isinstance(value, bytes | bytearray | memoryview):
        raw = bytes(value)
        head = base64.b64encode(raw[:64]).decode()
        return f"<{len(raw)} bytes, base64 prefix: {head}>"
    if isinstance(value, dict | list | tuple):
        return json.loads(json.dumps(value, default=str))
    return str(value)


class _Collector:
    """Applies the row and byte caps while rows stream in."""

    def __init__(self, max_rows: int, max_bytes: int) -> None:
        self.max_rows, self.max_bytes = max_rows, max_bytes
        self.rows: list[list[Any]] = []
        self._bytes = 0
        self.reason: str | None = None

    def add(self, row: list[Any]) -> bool:
        if len(self.rows) >= self.max_rows:
            self.reason = f"row limit of {self.max_rows} reached"
            return False
        converted = [jsonable(v) for v in row]
        size = len(json.dumps(converted))
        if self._bytes + size > self.max_bytes:
            self.reason = f"size limit of {self.max_bytes} bytes reached"
            return False
        self._bytes += size
        self.rows.append(converted)
        return True


def _check_params(params: list[Param]) -> None:
    if len(params) > MAX_PARAMS:
        raise ValidationFailed(f"At most {MAX_PARAMS} parameters are allowed.")


def _check_table(name: str) -> None:
    if not TABLE_RE.match(name):
        raise ValidationFailed("Invalid table name.")


class SqliteEngine:
    dialect = "sqlite"

    def __init__(self, path: Path, cfg: SqlConnection) -> None:
        self._uri = f"{path.resolve().as_uri()}?mode=ro"
        self._cfg = cfg

    async def _run(self, sql: str, params: list[Param]) -> QueryResult:
        _check_params(params)
        coll = _Collector(self._cfg.max_rows, self._cfg.max_bytes)
        async with aiosqlite.connect(self._uri, uri=True) as db:
            await db.execute("PRAGMA query_only = ON")  # layer 2: refuse writes at the engine
            await db.execute("PRAGMA trusted_schema = OFF")
            try:
                async with asyncio.timeout(self._cfg.timeout_seconds):
                    async with db.execute(sql, params) as cur:
                        columns = [d[0] for d in cur.description or []]
                        while True:
                            batch = await cur.fetchmany(100)
                            if not batch:
                                break
                            if not all(coll.add(list(r)) for r in batch):
                                break
            except TimeoutError:
                await db.interrupt()
                raise LimitExceeded(
                    f"Query exceeded the {self._cfg.timeout_seconds:g}s time limit."
                ) from None
            except aiosqlite.Error as exc:
                raise UpstreamError(f"Database error: {exc}") from None
        return QueryResult(columns, coll.rows, coll.reason is not None, coll.reason)

    async def query(self, sql: str, params: list[Param]) -> QueryResult:
        return await self._run(sql, params)

    async def list_tables(self) -> QueryResult:
        return await self._run(
            "SELECT name, type FROM sqlite_master WHERE type IN ('table','view') "
            "AND name NOT LIKE 'sqlite_%' ORDER BY name",
            [],
        )

    async def describe_table(self, table: str) -> QueryResult:
        _check_table(table)
        return await self._run(
            'SELECT name, type, "notnull" AS not_null, dflt_value AS default_value, pk '
            "FROM pragma_table_info(?)",
            [table],
        )

    async def close(self) -> None:
        return None


class PostgresEngine:
    dialect = "postgres"

    def __init__(self, dsn: str, cfg: SqlConnection) -> None:
        self._dsn = dsn
        self._cfg = cfg
        self._pool: asyncpg.Pool | None = None
        self._lock = asyncio.Lock()

    async def _get_pool(self) -> asyncpg.Pool:
        async with self._lock:
            if self._pool is None:
                try:
                    self._pool = await asyncpg.create_pool(
                        self._dsn,
                        min_size=0,
                        max_size=4,
                        command_timeout=self._cfg.timeout_seconds + 5,
                        server_settings={
                            "default_transaction_read_only": "on",
                            "statement_timeout": str(int(self._cfg.timeout_seconds * 1000)),
                            "idle_in_transaction_session_timeout": "30000",
                            "application_name": "mcp_hub",
                        },
                    )
                except (OSError, asyncpg.PostgresError) as exc:
                    raise UpstreamError(
                        f"Cannot connect to database: {type(exc).__name__}"
                    ) from None
            return self._pool

    async def _run(self, sql: str, params: list[Param]) -> QueryResult:
        _check_params(params)
        pool = await self._get_pool()
        coll = _Collector(self._cfg.max_rows, self._cfg.max_bytes)
        try:
            async with pool.acquire() as conn, conn.transaction(readonly=True):  # layer 2
                stmt = await conn.prepare(sql)
                columns = [a.name for a in stmt.get_attributes()]
                cursor = await stmt.cursor(*params)
                while True:
                    batch = await cursor.fetch(100)
                    if not batch:
                        break
                    if not all(coll.add(list(r.values())) for r in batch):
                        break
        except asyncpg.QueryCanceledError:
            raise LimitExceeded(
                f"Query exceeded the {self._cfg.timeout_seconds:g}s time limit."
            ) from None
        except asyncpg.PostgresError as exc:
            raise UpstreamError(f"Database error: {exc.__class__.__name__}: {exc}") from None
        except (OSError, asyncpg.InterfaceError):
            raise UpstreamError("Database connection failed.") from None
        return QueryResult(columns, coll.rows, coll.reason is not None, coll.reason)

    async def query(self, sql: str, params: list[Param]) -> QueryResult:
        return await self._run(sql, params)

    async def list_tables(self) -> QueryResult:
        return await self._run(
            "SELECT table_schema AS schema, table_name AS name, table_type AS type "
            "FROM information_schema.tables "
            "WHERE table_schema NOT IN ('pg_catalog','information_schema') "
            "ORDER BY table_schema, table_name",
            [],
        )

    async def describe_table(self, table: str) -> QueryResult:
        _check_table(table)
        schema, _, name = table.rpartition(".")
        return await self._run(
            "SELECT column_name AS name, data_type AS type, is_nullable AS nullable, "
            "column_default AS default_value FROM information_schema.columns "
            "WHERE table_name = $1 AND ($2 = '' OR table_schema = $2) "
            "AND table_schema NOT IN ('pg_catalog','information_schema') ORDER BY ordinal_position",
            [name, schema],
        )

    async def close(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None


def build_engine(name: str, cfg: SqlConnection) -> Engine:
    url = cfg.url.get_secret_value()
    parsed = urlparse(url)
    scheme = parsed.scheme.split("+")[0]
    if scheme == "sqlite":
        raw = unquote(parsed.path)
        windows_drive = raw.startswith("/") and len(raw) > 2 and raw[2] == ":"  # sqlite:///C:/x.db
        # sqlite:////abs/path keeps one slash; sqlite:///relative.db loses all of them
        raw = raw[1:] if windows_drive or raw.startswith("//") else raw.lstrip("/")
        if not raw or raw == ":memory:":
            raise ConfigError(f"sql connection '{name}': in-memory SQLite is not supported")
        path = Path(raw)
        if not path.is_file():
            raise ConfigError(f"sql connection '{name}': database file not found: {path}")
        return SqliteEngine(path, cfg)
    if scheme in {"postgres", "postgresql"}:
        return PostgresEngine(url, cfg)
    raise ConfigError(f"sql connection '{name}': unsupported URL scheme '{parsed.scheme}'")
