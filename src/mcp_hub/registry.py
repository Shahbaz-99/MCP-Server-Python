"""Plugin discovery. Plugins are an explicit allowlist, never discovered from the filesystem."""

from __future__ import annotations

import importlib
from collections.abc import Callable
from types import ModuleType

from mcp_hub.errors import ConfigError
from mcp_hub.plugins.base import Registrar

KNOWN_PLUGINS: frozenset[str] = frozenset({"sample", "sql", "rest_connector", "github"})


def load_plugin(name: str) -> Callable[[Registrar], None]:
    if name not in KNOWN_PLUGINS:
        raise ConfigError(f"unknown plugin '{name}'. Known: {', '.join(sorted(KNOWN_PLUGINS))}")
    try:
        module: ModuleType = importlib.import_module(f"mcp_hub.plugins.{name}")
    except ModuleNotFoundError as exc:
        raise ConfigError(f"plugin '{name}' is not available: {exc}") from exc
    register = getattr(module, "register", None)
    if not callable(register):
        raise ConfigError(f"plugin '{name}' has no register() function")
    return register  # type: ignore[no-any-return]


def register_plugins(registrar: Registrar, enabled: list[str]) -> list[str]:
    seen: set[str] = set()
    for name in enabled:
        if name in seen:
            raise ConfigError(f"plugin '{name}' enabled twice")
        seen.add(name)
        registrar.plugin = name
        load_plugin(name)(registrar)
    return sorted(seen)
