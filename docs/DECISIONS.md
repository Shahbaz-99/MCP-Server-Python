# Architecture Decision Records

## ADR-001: MCP SDK version

- Status: accepted (owner confirmed, 2026-10-10)
- Decision: use the official `mcp` package pinned to `2.3.0`.
- Context: the spec named "FastMCP". In `mcp` 2.x, `FastMCP` was renamed to `mcp.server.mcpserver.MCPServer`, and importing `mcp.server.fastmcp` raises `ModuleNotFoundError`. The 1.x line (latest 1.30.0) is still published.
- Verified in the installed 2.3.0 package: `MCPServer` accepts `token_verifier` (a `TokenVerifier` protocol with `async verify_token(token) -> AccessToken | None`) together with `AuthSettings`; `mcp.server.transport_security.TransportSecuritySettings` exists; `mcp.server.stdio`, `mcp.server.streamable_http` and `mcp.server.streamable_http_manager` exist.
- Protocol revisions present in the SDK: 2025-11-25 and 2026-07-28 (newest). The negotiated revision is recorded in `docs/ARCHITECTURE.md` once the server runs.
- Consequence: PROJECT_SPEC.md says "FastMCP"; read that as `MCPServer` for this repository.

## ADR-002: Python version

- Decision: `requires-python >= 3.12`. Development machine has 3.12 and 3.14; CI tests both.

## ADR-003: Identity provider

- Decision: build a generic OIDC resource server. Issuer URL, audience and JWKS are configuration. No vendor is chosen yet. Tests use a local fake issuer.

## ADR-004: Deployment target

- Decision: produce a container image and a provider-neutral deployment guide. No cloud account is touched and nothing is deployed without owner approval.

## ADR-005: Package name and license

- Decision: Python package `mcp_hub`, MIT license.

## ADR-006: Databases

- Decision: SQLite and PostgreSQL (the spec default).

## Environment check (2026-10-10, Windows 11)

| Tool | Version |
|---|---|
| Python | 3.14.7 (default), 3.12 also installed |
| uv | 0.12.23 |
| Docker | 29.7.2 |
| git | 2.45.1 |
| Node | 24.20.0 |
| Claude Code | 2.1.292 |
