"""Audit trail for tool calls. Records an argument hash, never raw arguments."""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any

from mcp_hub.logging import log_fields

_log = logging.getLogger("mcp_hub.audit")


def args_hash(arguments: dict[str, Any]) -> str:
    canonical = json.dumps(arguments, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]


def record_tool_call(
    *,
    identity: str,
    kind: str,
    tool: str,
    arguments: dict[str, Any],
    outcome: str,
    latency_ms: float,
) -> None:
    log_fields(
        _log,
        logging.INFO,
        "tool_call",
        event="tool_call",
        identity=identity,
        identity_kind=kind,
        tool=tool,
        args_sha256=args_hash(arguments),
        outcome=outcome,
        latency_ms=round(latency_ms, 2),
    )
