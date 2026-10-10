"""Minimal GitHub REST client: bounded, retries only safe requests, maps errors to HubError."""

from __future__ import annotations

import asyncio
import contextlib
import random
import re
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

import httpx

from mcp_hub.config import GithubSettings
from mcp_hub.errors import (
    AccessDenied,
    LimitExceeded,
    NotFound,
    UpstreamError,
    ValidationFailed,
)

OWNER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
REPO_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
REF_RE = re.compile(r"^[A-Za-z0-9._/@-]{1,200}$")
MAX_RETRIES = 3
MAX_WAIT_SECONDS = 30.0
TRUNC_MARK = "\n…[truncated]"
NEXT_LINK = re.compile(r'<[^>]*[?&]page=(\d+)[^>]*>;\s*rel="next"')


@dataclass
class GhResponse:
    data: Any
    next_page: int | None
    rate_remaining: int | None


def truncate(text: str | None, limit: int) -> str | None:
    if text is None or len(text) <= limit:
        return text
    return text[:limit] + TRUNC_MARK


def check_owner_repo(owner: str, repo: str) -> None:
    if not OWNER_RE.match(owner):
        raise ValidationFailed("Invalid owner name.")
    if not REPO_RE.match(repo) or repo in (".", ".."):
        raise ValidationFailed("Invalid repository name.")


def check_ref(ref: str) -> str:
    if not REF_RE.match(ref) or ".." in ref:
        raise ValidationFailed("Invalid ref.")
    return ref


def check_file_path(path: str) -> str:
    if not path or path.startswith("/") or "\\" in path or "\x00" in path:
        raise ValidationFailed("Invalid file path.")
    segments = path.split("/")
    if any(s in ("", ".", "..") for s in segments):
        raise ValidationFailed("Invalid file path.")
    return "/".join(quote(s, safe="") for s in segments)


class GithubClient:
    def __init__(
        self,
        cfg: GithubSettings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        sleep: Any = asyncio.sleep,
        timeout: float = 15.0,
    ) -> None:
        self._cfg = cfg
        self._transport = transport
        self._sleep = sleep
        self._timeout = timeout

    def _headers(self) -> dict[str, str]:
        h = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "mcp-hub/0.1",
        }
        if self._cfg.token is not None:
            h["Authorization"] = f"Bearer {self._cfg.token.get_secret_value()}"
        return h

    @staticmethod
    def _wait_seconds(resp: httpx.Response, attempt: int) -> float | None:
        """Seconds to wait before retrying, or None if this response is not retryable."""
        remaining = resp.headers.get("x-ratelimit-remaining")
        limited = resp.status_code == 429 or (resp.status_code == 403 and remaining == "0")
        secondary = resp.status_code == 403 and "retry-after" in resp.headers
        if resp.status_code >= 500 and resp.status_code != 501:
            return min(2.0**attempt, 8.0) + random.uniform(0, 0.5)  # noqa: S311
        if limited or secondary:
            if "retry-after" in resp.headers:
                try:
                    return float(resp.headers["retry-after"]) + random.uniform(0, 0.5)  # noqa: S311
                except ValueError:
                    return None
            reset = resp.headers.get("x-ratelimit-reset")
            if reset and reset.isdigit():
                return max(0.0, float(reset) - time.time()) + 1.0
        return None

    def _raise_for(self, resp: httpx.Response) -> None:
        code = resp.status_code
        if code == 404:
            raise NotFound("Not found, or the token has no access to it.")
        if code == 401:
            raise UpstreamError("GitHub rejected the configured token.")
        if code in (301, 302, 307, 308):
            raise UpstreamError("Repository moved or renamed; use its current name.")
        if code == 403 or code == 429:
            if resp.headers.get("x-ratelimit-remaining") == "0" or code == 429:
                raise LimitExceeded("GitHub rate limit reached. Try again later.")
            raise AccessDenied("GitHub denied the request (insufficient token permissions).")
        if code == 422:
            msg = ""
            with contextlib.suppress(ValueError):
                msg = str(resp.json().get("message", ""))[:200]
            raise ValidationFailed(f"GitHub rejected the input. {msg}".strip())
        if code >= 400:
            raise UpstreamError(f"GitHub returned HTTP {code}.")

    async def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> GhResponse:
        retryable = method == "GET"  # never auto-retry writes: that could duplicate them
        url = self._cfg.api_url.rstrip("/") + path
        last: httpx.Response | None = None
        for attempt in range(MAX_RETRIES + 1):
            try:
                async with httpx.AsyncClient(
                    transport=self._transport,
                    timeout=self._timeout,
                    follow_redirects=False,
                    trust_env=False,
                ) as client:
                    resp = await client.request(
                        method, url, params=params, json=json_body, headers=self._headers()
                    )
            except httpx.TimeoutException:
                if retryable and attempt < MAX_RETRIES:
                    await self._sleep(min(2.0**attempt, 8.0))
                    continue
                raise UpstreamError("GitHub request timed out.") from None
            except httpx.HTTPError as exc:
                raise UpstreamError(f"GitHub request failed: {type(exc).__name__}") from None
            last = resp
            if resp.status_code < 400:
                break
            wait = self._wait_seconds(resp, attempt) if retryable else None
            if wait is None or attempt == MAX_RETRIES:
                break
            if wait > MAX_WAIT_SECONDS:
                raise LimitExceeded(f"GitHub rate limit reached; it resets in about {int(wait)}s.")
            await self._sleep(wait)
        assert last is not None
        self._raise_for(last)
        try:
            data = last.json() if last.content else None
        except ValueError:
            raise UpstreamError("GitHub returned a non-JSON response.") from None
        link = NEXT_LINK.search(last.headers.get("link", ""))
        remaining = last.headers.get("x-ratelimit-remaining")
        return GhResponse(
            data,
            int(link.group(1)) if link else None,
            int(remaining) if remaining and remaining.isdigit() else None,
        )
