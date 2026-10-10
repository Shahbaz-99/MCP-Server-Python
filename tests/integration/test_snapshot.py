"""Tool metadata is frozen in a snapshot so any description/schema change shows up in review."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

from mcp import Client
from mcp.client.stdio import StdioServerParameters

SNAPSHOT = Path(__file__).parent.parent / "snapshots" / "tools_sample.json"


async def _tools_view() -> list[dict[str, Any]]:
    env = dict(os.environ)
    env["MCP_HUB_ENABLED_PLUGINS"] = '["sample"]'
    params = StdioServerParameters(
        command=sys.executable, args=["-m", "mcp_hub", "--transport", "stdio"], env=env
    )
    async with Client(params) as client:
        tools = (await client.list_tools()).tools
    return [
        {
            "name": t.name,
            "description": t.description,
            "input_schema": t.input_schema,
            "annotations": t.annotations.model_dump(mode="json", exclude_none=True)
            if t.annotations
            else None,
        }
        for t in sorted(tools, key=lambda t: t.name)
    ]


async def test_tools_list_matches_snapshot() -> None:
    current = await _tools_view()
    if os.environ.get("UPDATE_SNAPSHOTS") == "1":
        SNAPSHOT.parent.mkdir(exist_ok=True)
        SNAPSHOT.write_text(json.dumps(current, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    expected = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    assert json.loads(json.dumps(current, sort_keys=True)) == expected
