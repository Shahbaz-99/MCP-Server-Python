"""Rate, concurrency and size limits as a pure ASGI middleware (runs before authentication)."""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from collections import OrderedDict
from collections.abc import Callable

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from mcp_hub import observability as obs

EXEMPT_FROM_RATE_LIMIT = frozenset({"/healthz", "/readyz"})
MAX_TRACKED_KEYS = 10_000


class TokenBucket:
    """Per-key token buckets. Memory is bounded: least recently used keys are evicted."""

    def __init__(self, per_minute: int, clock: Callable[[], float] = time.monotonic) -> None:
        self.capacity = float(per_minute)
        self.refill_per_sec = per_minute / 60.0
        self._clock = clock
        self._state: OrderedDict[str, tuple[float, float]] = OrderedDict()

    def allow(self, key: str) -> bool:
        now = self._clock()
        tokens, last = self._state.pop(key, (self.capacity, now))
        tokens = min(self.capacity, tokens + (now - last) * self.refill_per_sec)
        allowed = tokens >= 1.0
        if allowed:
            tokens -= 1.0
        self._state[key] = (tokens, now)
        while len(self._state) > MAX_TRACKED_KEYS:
            self._state.popitem(last=False)
        return allowed


async def _reply(send: Send, status: int, error: str, extra: list[tuple[bytes, bytes]]) -> None:
    body = json.dumps({"error": error}).encode()
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
                *extra,
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


class LimitsMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        *,
        rate_limit_per_minute: int,
        max_concurrency: int,
        max_body_bytes: int,
    ) -> None:
        self.app = app
        self._ip_bucket = TokenBucket(rate_limit_per_minute)
        self._cred_bucket = TokenBucket(rate_limit_per_minute)
        self._sem = asyncio.Semaphore(max_concurrency)
        self._max_body = max_body_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        headers = {k.lower(): v for k, v in scope.get("headers", [])}

        if path not in EXEMPT_FROM_RATE_LIMIT:
            client = scope.get("client")
            ip = client[0] if client else "unknown"
            blocked = not self._ip_bucket.allow(ip)
            auth = headers.get(b"authorization")
            if auth is not None:
                cred = hashlib.sha256(auth).hexdigest()[:16]
                blocked = (not self._cred_bucket.allow(cred)) or blocked
            if blocked:
                obs.RATE_LIMITED.inc()
                obs.HTTP_REQUESTS.labels(path=_label(path), status="429").inc()
                await _reply(send, 429, "rate_limited", [(b"retry-after", b"1")])
                return

        length = headers.get(b"content-length")
        if length is not None:
            try:
                too_big = int(length) > self._max_body
            except ValueError:
                await _reply(send, 400, "bad_content_length", [])
                return
            if too_big:
                obs.HTTP_REQUESTS.labels(path=_label(path), status="413").inc()
                await _reply(send, 413, "request_too_large", [])
                return

        if self._sem.locked():
            await _reply(send, 503, "server_busy", [(b"retry-after", b"1")])
            return
        async with self._sem:
            status = {"code": "0"}

            async def counting_send(message: Message) -> None:
                if message["type"] == "http.response.start":
                    status["code"] = str(message["status"])
                await send(message)

            await self.app(scope, receive, counting_send)
            obs.HTTP_REQUESTS.labels(path=_label(path), status=status["code"]).inc()


def _label(path: str) -> str:
    """Bounded label set so scanners cannot inflate metric cardinality."""
    if path in {"/mcp", "/healthz", "/readyz", "/metrics"}:
        return path
    if path.startswith("/.well-known/"):
        return "/.well-known"
    return "other"
