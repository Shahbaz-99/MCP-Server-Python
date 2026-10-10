# Architecture

## Protocol and SDK

- SDK: official `mcp` 2.3.0 (`mcp.server.mcpserver.MCPServer`), see ADR-001 in DECISIONS.md.
- Protocol revision negotiated with a 2025-11-25 client: `2025-11-25` (verified by an `initialize` call). The SDK also supports 2024-11-05 through 2025-06-18 handshakes (verified) and the newer 2026-07-28 revision.
- Advertised capabilities: tools, resources, prompts. `listChanged` is `false` everywhere because tool metadata is static after startup.

## Layers

```
Clients -> transport (stdio | Streamable HTTP) -> security -> MCPServer -> Registrar -> plugins
```

| Module | Role |
|---|---|
| `config.py` | Typed settings. Precedence: CLI flag, env (`MCP_HUB_*`, nested with `__`), YAML (`MCP_HUB_CONFIG_FILE`), defaults. Unknown keys are rejected. |
| `logging.py` | JSON logs to stderr only, with key-name and value-pattern redaction. |
| `errors.py` | Error taxonomy. Only `HubError` messages reach the model; any other exception is masked as "Internal error". |
| `registry.py` | Explicit plugin allowlist (`sample`, `sql`, `rest_connector`, `github`). |
| `plugins/base.py` | `Registrar`: the only way plugins register tools. Every tool is wrapped. |
| `security/identity.py` | Resolves the caller and enforces per-tool scopes. |
| `security/audit.py` | One audit log line per tool call (argument hash only). |
| `observability.py` | Prometheus metrics. |

## The tool guard

Every tool registered through `Registrar.tool()` runs through one wrapper, so no plugin can skip it:

1. Resolve identity and check the tool's declared scopes (deny by default over HTTP; stdio is a trusted local process).
2. Run with a hard timeout (`tool_timeout_seconds`, default 30 s).
3. Convert errors: `HubError` text is passed on, anything else is logged with a traceback and masked.
4. Always record metrics and an audit line, including for denied and failed calls.

Tools must be `async` and must declare at least one scope. Duplicate tool names stop startup.

## Trust model by transport

- stdio: no network auth. The OS process boundary is the trust boundary; identity is `local` with all scopes.
- HTTP: see Phase 3 documentation (OAuth 2.1 resource server, API keys, Origin/Host checks, limits).

## Known deviation from the spec

Plugins receive the whole `Settings` object and read their own section (`settings.sample`, `settings.github`, ...) instead of defining a separate settings model file. All plugin sections live in `config.py`, so one place validates all configuration at startup.
