"""Typed configuration. Precedence: CLI flag (init kwargs) > env > YAML file > defaults."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, SecretStr, field_validator
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)

ENV_PREFIX = "MCP_HUB_"
CONFIG_FILE_ENV = "MCP_HUB_CONFIG_FILE"


class HttpSettings(BaseModel):
    host: str = "127.0.0.1"
    port: int = Field(8000, ge=1, le=65535)
    allow_public_bind: bool = False
    allowed_hosts: list[str] = Field(default_factory=lambda: ["127.0.0.1:*", "localhost:*"])
    allowed_origins: list[str] = Field(default_factory=list)
    max_body_bytes: int = Field(1_000_000, ge=1_024)
    rate_limit_per_minute: int = Field(120, ge=1)
    max_concurrency: int = Field(64, ge=1)
    metrics_requires_auth: bool = True
    forwarded_allow_ips: str | None = None  # trusted proxy IPs for X-Forwarded-For (uvicorn)
    json_response: bool = False  # reply with plain JSON instead of an SSE stream (no streaming)


class AuthSettings(BaseModel):
    enabled: bool = False
    issuer: str | None = None
    audience: str | None = None
    resource_url: str | None = None
    jwks_url: str | None = None
    algorithms: list[str] = Field(default_factory=lambda: ["RS256", "ES256"])
    required_scopes: list[str] = Field(default_factory=list)
    clock_skew_seconds: int = Field(30, ge=0, le=300)
    jwks_cache_seconds: int = Field(600, ge=1)

    @field_validator("algorithms")
    @classmethod
    def _asymmetric_only(cls, v: list[str]) -> list[str]:
        bad = [a for a in v if not a.startswith(("RS", "ES", "PS")) and a != "EdDSA"]
        if bad or not v:
            raise ValueError(f"only asymmetric JWT algorithms are allowed, got: {bad or 'none'}")
        return v

    api_key_file: Path | None = None


class SampleSettings(BaseModel):
    fs_roots: list[Path] = Field(default_factory=list)
    max_read_bytes: int = Field(1_000_000, ge=1)
    max_list_entries: int = Field(500, ge=1)


class GithubSettings(BaseModel):
    token: SecretStr | None = None
    api_url: str = "https://api.github.com"
    allowed_repos: list[str] = Field(default_factory=list)
    allowed_owners: list[str] = Field(default_factory=list)
    enable_write: bool = False
    max_items: int = Field(100, ge=1, le=1000)
    max_output_chars: int = Field(50_000, ge=1_000)


class SqlConnection(BaseModel):
    url: SecretStr
    read_only: bool = True
    max_rows: int = Field(500, ge=1)
    max_bytes: int = Field(1_000_000, ge=1_024)
    timeout_seconds: float = Field(10.0, gt=0)


class SqlSettings(BaseModel):
    connections: dict[str, SqlConnection] = Field(default_factory=dict)


class RestParam(BaseModel):
    type: Literal["string", "integer", "number", "boolean"] = "string"
    description: str = ""
    required: bool = True
    default: str | int | float | bool | None = None
    max_length: int = Field(1000, ge=1, le=10_000)  # strings only


class RestEndpoint(BaseModel):
    """One REST call exposed as one MCP tool named `rest_<name>`.

    `url` may contain `{param}` placeholders in the path or query, never in scheme/host/port.
    `query` and `body` values may be `{param}` placeholders or literals.
    """

    name: str = Field(pattern=r"^[a-z][a-z0-9_]{0,59}$")
    description: str = Field(min_length=1)
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"] = "GET"
    url: str
    params: dict[str, RestParam] = Field(default_factory=dict)
    query: dict[str, str] = Field(default_factory=dict)
    body: dict[str, Any] | None = None
    auth_type: Literal["none", "header", "bearer", "basic", "query"] = "none"
    auth_name: str | None = None  # header or query parameter name
    auth_secret_env: str | None = None  # NAME of the env var holding the secret (never the secret)
    response_path: str | None = None  # dotted path into the JSON response, e.g. data.items.0


class RestSettings(BaseModel):
    allowed_hosts: list[str] = Field(default_factory=list)
    allow_http: bool = False
    max_redirects: int = Field(3, ge=0, le=10)
    timeout_seconds: float = Field(10.0, gt=0)
    max_response_bytes: int = Field(1_000_000, ge=1_024)
    endpoints: list[RestEndpoint] = Field(default_factory=list)


class _YamlSource(PydanticBaseSettingsSource):
    def __init__(self, settings_cls: type[BaseSettings]) -> None:
        super().__init__(settings_cls)
        path = os.environ.get(CONFIG_FILE_ENV)
        self._data: dict[str, Any] = {}
        if path:
            raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
            if not isinstance(raw, dict):
                raise ValueError(f"{path}: top level must be a mapping")
            self._data = raw

    def get_field_value(self, field: Any, field_name: str) -> tuple[Any, str, bool]:
        return self._data.get(field_name), field_name, False

    def __call__(self) -> dict[str, Any]:
        return self._data


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix=ENV_PREFIX,
        env_nested_delimiter="__",
        extra="forbid",
    )

    server_name: str = "mcp-hub"
    log_level: str = "INFO"
    tool_timeout_seconds: float = Field(30.0, gt=0)
    shutdown_grace_seconds: float = Field(10.0, ge=0)
    tracing_enabled: bool = False
    enabled_plugins: list[str] = Field(default_factory=lambda: ["sample"])
    http: HttpSettings = Field(default_factory=HttpSettings)
    auth: AuthSettings = Field(default_factory=AuthSettings)
    sample: SampleSettings = Field(default_factory=SampleSettings)
    github: GithubSettings = Field(default_factory=GithubSettings)
    sql: SqlSettings = Field(default_factory=SqlSettings)
    rest: RestSettings = Field(default_factory=RestSettings)

    @field_validator("log_level")
    @classmethod
    def _level(cls, v: str) -> str:
        v = v.upper()
        if v not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError("invalid log level")
        return v

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (init_settings, env_settings, _YamlSource(settings_cls))

    def check_startup_invariants(self) -> None:
        """Fail fast on unsafe or inconsistent combinations."""
        a = self.auth
        if a.enabled:
            if not a.resource_url:
                raise ValueError("auth.enabled requires: resource_url")
            if bool(a.issuer) != bool(a.audience):
                raise ValueError("auth.enabled requires issuer and audience together")
            if not a.issuer and not a.api_key_file:
                raise ValueError("auth.enabled requires: issuer+audience and/or api_key_file")
            for name in ("issuer", "jwks_url", "resource_url"):
                url = getattr(a, name)
                if url and not _is_https_or_loopback(url):
                    raise ValueError(f"auth.{name} must be https")

    def check_http_invariants(self) -> None:
        """Extra rules that only apply when serving over HTTP."""
        h = self.http
        if not _is_loopback_host(h.host):
            if not h.allow_public_bind:
                raise ValueError(
                    f"refusing to bind {h.host}: non-loopback binding needs allow_public_bind"
                )
            if not self.auth.enabled:
                raise ValueError("refusing public bind without authentication (auth.enabled)")
            if all(_is_loopback_host(x.rsplit(":", 1)[0]) for x in h.allowed_hosts):
                raise ValueError(
                    "public bind needs http.allowed_hosts to list the public host name(s)"
                )


def _is_loopback_host(host: str) -> bool:
    return host.strip("[]") in {"127.0.0.1", "localhost", "::1"}


def _is_https_or_loopback(url: str) -> bool:
    from urllib.parse import urlparse

    parsed = urlparse(url)
    return parsed.scheme == "https" or (
        parsed.scheme == "http" and _is_loopback_host(parsed.hostname or "")
    )


def masked_dump(settings: Settings) -> dict[str, Any]:
    """Effective config with secrets masked (SecretStr already renders as '**********')."""
    return settings.model_dump(mode="json")
