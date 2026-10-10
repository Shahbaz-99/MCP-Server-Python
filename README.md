# mcp_hub

Plugin-based, production-oriented MCP server in Python. Runs over stdio (local clients such as Claude Code) and Streamable HTTP (remote, OAuth 2.1 / API key).

Status: under construction. See [PROJECT_SPEC.md](PROJECT_SPEC.md) for the spec and [docs/DECISIONS.md](docs/DECISIONS.md) for decisions.

## Quick start

```bash
uv sync
uv run python -m mcp_hub --transport stdio
```

More documentation arrives in `docs/` as phases complete.
