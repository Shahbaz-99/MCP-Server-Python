"""HTTP transport. Placeholder until Phase 3: refuses to start rather than run unauthenticated."""

from __future__ import annotations

from mcp_hub.config import Settings
from mcp_hub.errors import ConfigError


def run_http(settings: Settings) -> None:
    raise ConfigError("HTTP transport is not implemented yet (Phase 3).")
