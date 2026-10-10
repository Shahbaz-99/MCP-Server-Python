"""Frozen tool metadata for every plugin (rug-pull / description-tampering guard)."""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from typing import Any

from mcp import Client

from mcp_hub.config import Settings
from mcp_hub.server import build_server

SNAPSHOT = Path(__file__).parent.parent / "snapshots" / "tools_all.json"


async def test_all_plugin_tools_match_snapshot(tmp_path: Path, monkeypatch: Any) -> None:
    db = tmp_path / "x.db"
    sqlite3.connect(db).close()
    monkeypatch.setenv("SNAPSHOT_REST_TOKEN", "x")
    settings = Settings(
        enabled_plugins=["sample", "sql", "rest_connector", "github"],
        sql={"connections": {"main": {"url": f"sqlite:///{db.as_posix()}"}}},
        github={"allowed_repos": ["acme/widgets"], "enable_write": True, "token": "t"},
        rest={
            "allowed_hosts": ["api.example.com"],
            "endpoints": [
                {
                    "name": "get_user",
                    "description": "Fetch a user by id.",
                    "url": "https://api.example.com/users/{user_id}",
                    "params": {"user_id": {"type": "string", "description": "User id"}},
                    "auth_type": "bearer",
                    "auth_secret_env": "SNAPSHOT_REST_TOKEN",
                },
                {
                    "name": "create_note",
                    "description": "Create a note.",
                    "method": "POST",
                    "url": "https://api.example.com/notes",
                    "params": {"title": {"type": "string"}},
                    "body": {"title": "{title}"},
                },
            ],
        },
    )
    built = build_server(settings, local_trusted=True)
    async with Client(built.server) as client:
        tools = (await client.list_tools()).tools
    current = [
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
    if os.environ.get("UPDATE_SNAPSHOTS") == "1":
        SNAPSHOT.write_text(json.dumps(current, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    expected = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    assert json.loads(json.dumps(current, sort_keys=True)) == expected
    assert len(current) == 5 + 4 + 2 + 10  # sample + sql + rest + github(with writes)
