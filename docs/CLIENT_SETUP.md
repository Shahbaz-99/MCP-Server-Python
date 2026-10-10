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

## Remote (Streamable HTTP)

Endpoint: `POST /mcp` (stateless, so it scales horizontally). Other routes: `/healthz`, `/readyz`, `/metrics` (needs scope `admin:metrics` when auth is on), and `/.well-known/oauth-protected-resource/mcp` (OAuth Protected Resource Metadata).

### 1. Start the server

Loopback, no auth (development only; the server refuses non-loopback binds without auth):

```bash
uv run mcp-hub --transport http --port 8000
```

With authentication (API keys, and/or an OIDC issuer):

```bash
export MCP_HUB_AUTH__ENABLED=true
export MCP_HUB_AUTH__RESOURCE_URL=https://mcp.example.com/mcp   # the public URL of /mcp
export MCP_HUB_AUTH__API_KEY_FILE=./data/keys.json              # API keys
# OIDC (optional, both required together):
export MCP_HUB_AUTH__ISSUER=https://idp.example.com
export MCP_HUB_AUTH__AUDIENCE=https://mcp.example.com/mcp
uv run mcp-hub --transport http --host 0.0.0.0 --allow-public-bind --port 8000
# plus MCP_HUB_HTTP__ALLOWED_HOSTS='["mcp.example.com"]'
```

Public binding needs all of: `--allow-public-bind`, `auth.enabled`, and `http.allowed_hosts` naming your public host. Otherwise startup fails with an explanation. Put TLS in front (reverse proxy or platform load balancer); `resource_url` and `issuer` must be `https` unless they are loopback.

### 2. Create an API key

```bash
uv run mcp-hub keys create --label laptop --scopes sample:read
uv run mcp-hub keys list
uv run mcp-hub keys revoke <id>        # takes effect immediately, no restart
```

The key is printed once and only a salted hash is stored. Scopes decide which tools the key may call (`sample:read`, `github:read`, `sql:read`, ...). Use `*` only for fully trusted keys.

### 3. Connect Claude Code

```bash
claude mcp add --transport http mcp-hub https://mcp.example.com/mcp --header "Authorization: Bearer mcph_<id>_<secret>"
```

### 4. Generic client (Python SDK)

```python
import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

http = httpx2.AsyncClient(headers={"Authorization": "Bearer mcph_<id>_<secret>"})
async with Client(streamable_http_client("https://mcp.example.com/mcp", http_client=http)) as c:
    print(await c.call_tool("echo", {"message": "hi"}))
```

### Proxy note

Behind a load balancer every request appears to come from the proxy's IP, which collapses per-IP rate limiting to one bucket. Set `MCP_HUB_HTTP__FORWARDED_ALLOW_IPS` to the proxy's address so uvicorn trusts `X-Forwarded-For`. Never set it to `*` on an internet-facing server.
