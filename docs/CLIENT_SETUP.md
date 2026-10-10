# Client setup

## Claude Code, local (stdio)

Project-scoped (committed `.mcp.json`; Claude Code asks you to approve it on first use):

```json
{
  "mcpServers": {
    "mcp-hub": {
      "type": "stdio",
      "command": "uv",
      "args": ["run", "--directory", "/path/to/MCP-Server-Python", "mcp-hub"],
      "env": { "MCP_HUB_ENABLED_PLUGINS": "[\"sample\"]" }
    }
  }
}
```

Or add it for your user account (replace the path):

```bash
claude mcp add mcp-hub --scope user -- uv run --directory /path/to/MCP-Server-Python mcp-hub
```

Verify: `claude mcp list` shows `mcp-hub ... Connected`. A one-off check without approval prompts:

```bash
claude -p "Call the echo tool from mcp-hub with message hi" --mcp-config .mcp.json --strict-mcp-config --allowedTools "mcp__mcp-hub__echo"
```

Verified on this repository with Claude Code 2.1.292: the call returned the echoed text.

## MCP Inspector

Use the console script. Passing `python -m ...` or `--transport` through the Inspector CLI breaks because the Inspector consumes those flags itself.

```bash
npx @modelcontextprotocol/inspector --cli .venv/Scripts/mcp-hub.exe --method tools/list
```

## Remote (HTTP) clients

Documented in Phase 3.
