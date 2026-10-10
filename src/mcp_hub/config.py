"""Typed configuration. Precedence: CLI flag (init kwargs) > env > YAML file > defaults."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

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


class RestEndpoint(BaseModel):
    name: str = Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")
    description: str
    method: str = Field("GET", pattern=r"^(GET|POST|PUT|PATCH|DELETE)$")
    url: str
    params: dict[str, str] = Field(default_factory=dict)
    auth_type: str = Field("none", pattern=r"^(none|header|bearer|basic|query)$")
    auth_name: str | None = None
    auth_secret_env: str | None = None
    response_path: str | None = None
    read_only: bool = True


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
        if self.auth.enabled:
            missing = [
                n for n in ("issuer", "audience", "resource_url") if not getattr(self.auth, n)
            ]
            if missing and not self.auth.api_key_file:
                raise ValueError(f"auth.enabled requires: {', '.join(missing)} (or api_key_file)")
            issuer = self.auth.issuer
            if issuer and not issuer.startswith("https://") and not _is_loopback_url(issuer):
                raise ValueError("auth.issuer must be https")


def _is_loopback_url(url: str) -> bool:
    from urllib.parse import urlparse

    return (urlparse(url).hostname or "") in {"127.0.0.1", "localhost", "::1"}


def masked_dump(settings: Settings) -> dict[str, Any]:
    """Effective config with secrets masked (SecretStr already renders as '**********')."""
    return settings.model_dump(mode="json")
