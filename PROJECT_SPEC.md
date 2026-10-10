# PROJECT SPEC & EXECUTION PROMPT: Production MCP Server (Python)

> How to use this file: open Claude Code in this repository and say "Execute PROJECT_SPEC.md, starting at Phase 0." The agent must follow the phases in order, obey the Rules of Engagement (section 1), and meet every Gate before moving on. Do not skip phases.

---

## 0. Role and Mission

You are a senior Python engineer and MCP (Model Context Protocol) expert. Build a production-grade, general-purpose MCP server that the owner can use anywhere: locally with Claude Code and other MCP clients, and remotely in the cloud, and wired to real applications and personal projects.

Success means: a stranger can clone the repo, run one command, connect Claude Code to it, and every capability works, is secured, is tested, is observable, and is documented. No placeholder code, no TODO stubs, no unverified claims.

## 1. Rules of Engagement (non-negotiable)

1. Spec-driven. This file is the source of truth. If code and spec disagree, stop and either fix the code or propose a spec change to the user. Never silently deviate.
2. Verify, do not assume. MCP SDK APIs change between versions. Before using any SDK, auth, or transport API, read the installed package's source or docs (and the official spec at https://modelcontextprotocol.io/specification) and pin the version you verified. Never invent API names.
3. Ask before guessing. If a requirement is ambiguous, or a decision is the owner's (cost, cloud provider, identity provider, credentials), stop and ask. Do not pick silently.
4. Definition of Done per phase = its Gate passes with real command output shown. Say plainly if something fails or was skipped.
5. No secrets in the repo, ever. No real credentials in code, tests, fixtures, logs, or commits. Provide `.env.example` only.
6. Least privilege and deny-by-default. Every tool that touches the filesystem, network, database, or an external API must enforce an explicit allowlist and limits.
7. Small commits, one per task, Conventional Commits. At every step, throughout development: stage, commit, and push to GitHub (`origin`). Push is standing-approved by the owner; never force-push. Do not deploy without the owner's explicit approval.
8. Stdout hygiene. In stdio mode, stdout carries only JSON-RPC. All logs go to stderr. A stray `print()` is a bug.
9. Keep scope. Build what this spec lists. Put extra ideas in `docs/BACKLOG.md`.

## 2. Decisions Already Made

| Topic | Decision |
|---|---|
| Language | Python 3.12+ |
| MCP SDK | Official `mcp` Python SDK (FastMCP API). Pin the exact version after verifying it. |
| Transports | `stdio` (local, Claude Code) and Streamable HTTP (remote). Legacy SSE is not implemented. |
| Remote auth | OAuth 2.1 resource server (validate bearer JWTs from an external identity provider, publish protected-resource metadata) plus static API-key fallback for personal use |
| v1 capabilities | Plugin framework with sample tools; GitHub integration; guarded SQL database access; generic config-driven REST connector |
| Package manager | `uv` |

Open decisions to confirm with the owner during Phase 0 (do not assume):
- Identity provider for OAuth (Auth0, Keycloak, Entra ID, other) and the issuer/audience values.
- Cloud target for deployment (container-based: Cloud Run, Fly.io, Azure Container Apps, AWS, other).
- Which database engines to support first (SQLite and PostgreSQL are the default proposal).
- Project/package name and license.

## 3. Architecture

### 3.1 Layers

```
 Clients (Claude Code, other MCP clients, custom apps)
        |  stdio                    |  Streamable HTTP (HTTPS)
        v                           v
 +--------------------------------------------------------+
 | Transport layer   (stdio runner | ASGI app via uvicorn)  |
 +--------------------------------------------------------+
 | Security layer    (auth verifier, origin check, rate     |
 |                    limit, request size limit, audit log) |
 +--------------------------------------------------------+
 | MCP core          (FastMCP server: tools, resources,     |
 |                    prompts, lifecycle, capability negot.)|
 +--------------------------------------------------------+
 | Plugin registry   (discovers & loads enabled plugins)    |
 +--------------------------------------------------------+
 | Plugins: sample | github | sql | rest_connector | ...    |
 +--------------------------------------------------------+
 | Platform services (config, logging, metrics, tracing,    |
 |                    secrets, HTTP client, error mapping)  |
 +--------------------------------------------------------+
```

### 3.2 Request flow (HTTP mode)

1. Client sends a POST to `/mcp` with an `Authorization: Bearer <token>` header.
2. Origin/Host validation (DNS-rebinding protection), body-size limit, and rate limit run first.
3. Auth verifier validates the token: JWT signature via the IdP's JWKS, `iss`, `aud`, `exp`, `nbf`, and required scopes. If OAuth validation does not apply and the token matches a configured API key (constant-time compare, hashed at rest), treat it as the fallback identity. On failure return `401` with a correct `WWW-Authenticate` header pointing to the protected-resource metadata.
4. MCP core handles JSON-RPC: `initialize` (capability negotiation), `tools/list`, `tools/call`, `resources/*`, `prompts/*`, ping, cancellation, progress.
5. The tool handler validates input (pydantic schemas), checks per-tool scope, runs with a timeout, maps errors, and writes an audit record.
6. Response returns structured content plus text content; failures return tool errors (`isError: true`) for tool-level problems and JSON-RPC errors for protocol-level problems.

### 3.3 Request flow (stdio mode)

Launched as a subprocess by the client. No network auth (the OS process boundary is the trust boundary). Same tools, same validation, same limits. Logs to stderr only.

### 3.4 Plugin contract

Each plugin is a Python package under `src/<pkg>/plugins/<name>/` exposing a `register(server, settings)` function and a pydantic `Settings` model. Plugins are enabled by name in config. A plugin must: declare its required scopes per tool, declare its required secrets, validate its config at startup (fail fast), and never import another plugin. The registry rejects duplicate tool names and fails startup on invalid plugin config.

## 4. Repository Layout (target)

```
.
├── PROJECT_SPEC.md
├── README.md
├── pyproject.toml
├── uv.lock
├── .env.example
├── .gitignore
├── .pre-commit-config.yaml
├── Dockerfile
├── docker-compose.yml
├── Makefile                  # or justfile: install, lint, type, test, run, build
├── docs/
│   ├── ARCHITECTURE.md
│   ├── SECURITY.md
│   ├── THREAT_MODEL.md
│   ├── CONFIGURATION.md
│   ├── DEPLOYMENT.md
│   ├── CLIENT_SETUP.md       # Claude Code (stdio + http) and generic clients
│   ├── PLUGIN_GUIDE.md
│   ├── RUNBOOK.md
│   └── BACKLOG.md
├── src/<pkg>/
│   ├── __main__.py           # CLI entry: `--transport stdio|http`
│   ├── server.py             # builds FastMCP instance
│   ├── config.py             # pydantic-settings
│   ├── logging.py            # structured logging to stderr
│   ├── observability.py      # metrics, tracing
│   ├── errors.py             # error taxonomy + mapping
│   ├── security/             # auth.py, apikeys.py, ratelimit.py, origin.py, audit.py
│   ├── registry.py           # plugin discovery/loading
│   └── plugins/
│       ├── sample/           # echo, time, safe_fs
│       ├── github/
│       ├── sql/
│       └── rest_connector/
├── tests/
│   ├── unit/
│   ├── integration/          # real server over stdio and HTTP
│   ├── security/
│   └── conftest.py
└── .github/workflows/ci.yml
```

## 5. Functional Requirements

### 5.1 MCP core

- FR-1: Implement the MCP spec revision supported by the pinned SDK (record the revision in `docs/ARCHITECTURE.md`). Support tools, resources, and prompts, with correct capability advertisement and `listChanged` only where truly supported.
- FR-2: Every tool has a precise name, description written for an LLM reader, a JSON Schema derived from typed pydantic models, and `annotations` (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`) set accurately.
- FR-3: Tool results are structured (`structuredContent` with an output schema) where the SDK supports it, plus a text fallback.
- FR-4: Support request cancellation and progress notifications for long-running tools. Every tool has a hard timeout (configurable, default 30 s).
- FR-5: Server `instructions` text in `initialize` explains what the server offers.
- FR-6: Graceful shutdown on SIGTERM/SIGINT: stop accepting requests, finish in-flight calls up to a grace period, close pools.

### 5.2 Transports

- FR-7: `python -m <pkg> --transport stdio` and `--transport http --host --port`.
- FR-8: HTTP mode uses Streamable HTTP at a single endpoint (`/mcp`), stateless-capable so it scales horizontally. Also expose `/healthz` (liveness), `/readyz` (readiness, checks plugin init), `/metrics` (Prometheus, protected or network-restricted).
- FR-9: HTTP mode binds to `127.0.0.1` by default. Binding to `0.0.0.0` requires an explicit flag and authentication enabled; refuse to start otherwise.

### 5.3 Auth and security

- FR-10: OAuth 2.1 resource-server behavior: validate JWT access tokens against the configured issuer's JWKS (with caching and key rotation), enforce `aud` equal to this server's resource identifier, enforce scopes per tool, and serve OAuth Protected Resource Metadata (RFC 9728). Do not pass received tokens through to upstream APIs (no token passthrough).
- FR-11: API-key fallback: keys are generated by a CLI command, shown once, stored only as salted hashes, support labels, expiry, and revocation, and map to a fixed scope set.
- FR-12: Origin header validation and Host allowlist on HTTP. CORS disabled unless explicitly configured.
- FR-13: Per-identity rate limiting and global concurrency limit. Request body size limit.
- FR-14: Audit log: for each tool call record timestamp, identity, tool, argument hash (not raw secrets), outcome, latency. Never log tokens or secret values; redact by key name and pattern.
- FR-15: Secrets come from environment variables or a secret manager interface; never from the repo. Settings that hold secrets use `SecretStr`.

### 5.4 Plugins

#### 5.4.1 `sample`
- `echo`, `current_time` (timezone-aware), and `safe_fs_read` / `safe_fs_list` confined to configured root directories. Path handling must resolve symlinks and reject traversal (`..`, absolute paths outside roots, symlink escape, Windows device names and alternate data streams). Size cap on reads.
- Exposes one sample resource and one sample prompt to prove the full capability set.

#### 5.4.2 `github`
- Tools (read-first): list/search repos and issues, get issue/PR, list PR files, get file contents. Write tools (create issue, comment) behind a separate scope and a config flag, default off.
- Authenticates with a fine-grained personal access token or GitHub App credentials from secrets. Handles pagination, rate-limit headers, retries with backoff on 5xx/secondary limits, and returns bounded output (truncate with an explicit marker).
- Allowlist of owners/repos the server may access.

#### 5.4.3 `sql`
- Engines: SQLite and PostgreSQL via async drivers, selected by config. Named connections, each with its own read-only flag (default read-only).
- Read-only enforcement is layered: DB-level read-only transaction or role, plus statement parsing that rejects anything but a single SELECT/EXPLAIN-type statement. Do not rely on string matching alone.
- Tools: `list_tables`, `describe_table`, `run_query`. Parameterized queries only; row cap, byte cap, and statement timeout.
- Writes are out of scope for v1 unless the owner enables a separate, scope-gated tool; default off.

#### 5.4.4 `rest_connector`
- Config-driven (YAML) definitions of REST endpoints exposed as tools: method, URL template, parameters schema, auth type (none, header, bearer, basic, query), and response extraction.
- SSRF defense: allowlist of hosts, block private/loopback/link-local/metadata IP ranges after DNS resolution (and on redirects), restrict schemes to https (http only if explicitly allowed), cap redirects, timeouts, and response size.
- Config is validated at startup; invalid definitions fail fast with a clear error.

### 5.5 Configuration

- FR-16: `pydantic-settings` with env vars (`<PKG>_` prefix) and an optional YAML config file. Precedence: CLI flag > env > file > default. Invalid config stops startup with a readable message. A `--print-config` command shows effective config with secrets masked.

### 5.6 Observability

- FR-17: Structured JSON logs (stderr) with request/correlation IDs. Log level configurable.
- FR-18: Prometheus metrics: request count, latency histogram, errors by type, per-tool call counts, rate-limit rejections, auth failures.
- FR-19: OpenTelemetry tracing hooks (optional, off by default, OTLP exporter via env).

## 6. Non-Functional Requirements

| Area | Requirement |
|---|---|
| Quality | `ruff` (lint + format), `mypy --strict` clean, no `Any` leaking from public APIs |
| Testing | Unit + integration + security tests; coverage >= 85% overall, >= 95% on `security/` and path/SSRF/SQL guards |
| Performance | p95 latency for local trivial tool < 50 ms; documented load test (e.g. 100 concurrent clients) with results |
| Reliability | Timeouts everywhere, bounded retries with jitter, no unbounded memory growth, clean shutdown |
| Portability | Runs on Windows, macOS, Linux; CI matrix covers Windows and Linux |
| Supply chain | Locked deps (`uv.lock`), `pip-audit`/`uv` audit in CI, pinned base image digest, SBOM generated, Dependabot or Renovate config |
| Container | Multi-stage, non-root user, read-only root filesystem compatible, healthcheck, minimal image |
| Docs | Every config option and tool documented; docs are tested where possible (examples run in CI) |

## 7. Security Requirements (threat-model driven)

Produce `docs/THREAT_MODEL.md` and mitigate at minimum:

1. Prompt injection via tool outputs (GitHub issue text, DB rows, REST responses): treat all external content as untrusted data; label it; never let it select tools or arguments on the server side; document client-side risk.
2. Confused deputy and token passthrough: never forward client tokens upstream; use server-held credentials with least privilege.
3. SSRF, path traversal, SQL injection and write-escalation: layered guards from section 5, each with adversarial tests.
4. DNS rebinding and cross-origin attacks on HTTP: Origin/Host validation, localhost-default binding.
5. Credential theft and leakage: secrets never logged; redaction tests.
6. DoS and resource exhaustion: size, time, concurrency, and rate limits.
7. Session hijacking: do not use session IDs for authentication; bind authorization to the token on every request.
8. Dependency compromise: locking, auditing, minimal dependencies.
9. Tool-description tampering and rug-pulls: tool metadata is static at build time; changes are visible in version control and tests (snapshot test of `tools/list`).

## 8. Execution Phases

Each phase ends with a Gate. Show real command output as evidence. Stage, commit, and push to GitHub after every step and at each phase end.

### Phase 0: Discovery and confirmation
- Tasks: read this file; check Python 3.12+, `uv`, Docker, and git availability on this Windows machine; read the installed `mcp` SDK docs/source and the current MCP spec; confirm the open decisions in section 2 with the owner; write a short `docs/DECISIONS.md` (ADR style) recording the SDK version and spec revision.
- Gate: owner has confirmed open decisions; `docs/DECISIONS.md` exists.

### Phase 1: Project scaffold
- Tasks: `uv init` with `src/` layout; `pyproject.toml` with pinned deps and tool configs (ruff, mypy, pytest, coverage); `.gitignore`, `.env.example`, pre-commit, Makefile/justfile, CI skeleton; `config.py`, `logging.py`, `errors.py`.
- Gate: `uv sync`, lint, type-check, and an empty test suite all pass locally and in CI.

### Phase 2: MCP core and stdio
- Tasks: `server.py`, plugin registry, `sample` plugin, CLI entry point for stdio, graceful shutdown, tools/list snapshot test.
- Gate: an integration test spawns the server over stdio, runs `initialize`, `tools/list`, `tools/call`, resources and prompts successfully; stdout contains only valid JSON-RPC (tested). The MCP Inspector connects. Claude Code connects with `claude mcp add` and calls a tool (document the exact command in `docs/CLIENT_SETUP.md`).

### Phase 3: HTTP transport and security layer
- Tasks: Streamable HTTP app, health/ready/metrics endpoints, origin/host checks, rate and size limits, OAuth JWT verifier plus protected-resource metadata, API-key CLI and verifier, audit logging, scope enforcement.
- Gate: security tests prove: no token = 401 with correct `WWW-Authenticate`; wrong `aud`, expired, bad signature, and missing scope are all rejected; revoked key rejected; bad Origin rejected; oversize body rejected; rate limit triggers; binding non-local without auth refuses to start. Integration test runs the full MCP flow over HTTP.

### Phase 4: Plugins
- Order: `sql`, then `rest_connector`, then `github`. For each: implement, document, add unit tests, integration tests against local fixtures (SQLite file, local mock HTTP server, recorded/mocked GitHub API), and adversarial tests.
- Gate per plugin: all its guards are proven by tests (traversal, SSRF incl. redirect and DNS-rebind cases, multi-statement and write-attempt SQL, truncation and pagination), coverage targets met.

### Phase 5: Observability and hardening
- Tasks: metrics, tracing hooks, redaction tests, timeouts/cancellation tests, load test with documented results, memory/leak check over a sustained run, fuzz tests on input schemas (e.g. Hypothesis).
- Gate: metrics visible at `/metrics`; load test results recorded in `docs/RUNBOOK.md`; no secret appears in any log in the redaction test.

### Phase 6: Packaging and deployment
- Tasks: Dockerfile, docker-compose for local HTTP mode, image scan, SBOM, release workflow (build, test, tag), deployment guide for the confirmed cloud target with TLS termination, secret injection, and rollback steps. Do not deploy without owner approval.
- Gate: container builds, runs as non-root, passes healthcheck, and the full integration suite passes against the container.

### Phase 7: Documentation and acceptance
- Tasks: finish all docs in section 4, including `CLIENT_SETUP.md` (Claude Code stdio, Claude Code remote HTTP with auth, and a generic client example), plugin authoring guide, runbook (alerts, common failures, key rotation), and a final traceability table mapping each FR/NFR to its test.
- Gate: section 9 checklist fully ticked by the agent with evidence, then reviewed by the owner.

## 9. Final Acceptance Checklist (the "no loopholes" gate)

- [ ] Every FR and NFR maps to at least one passing test (traceability table committed).
- [ ] `ruff`, `mypy --strict`, tests, coverage thresholds, and dependency audit all pass in CI on Windows and Linux.
- [ ] stdio: stdout is clean JSON-RPC only; verified by test.
- [ ] HTTP: all auth, origin, size, and rate-limit negative tests pass.
- [ ] Each plugin guard has adversarial tests that fail if the guard is removed (mutation-style check done manually for the critical ones).
- [ ] No secret in repo history, logs, or test fixtures (secret scan run, e.g. gitleaks).
- [ ] Threat model reviewed; every listed threat has a mitigation and a test or a documented residual risk.
- [ ] Container runs non-root with healthcheck; image scan has no unaddressed high/critical findings.
- [ ] A fresh-clone walkthrough from the README works end to end on a clean machine (agent performs and records it).
- [ ] Claude Code connected both locally (stdio) and via HTTP, and called a tool from each plugin; evidence recorded.
- [ ] `docs/BACKLOG.md` lists everything deliberately left out of v1.

## 10. Reporting Format

At the end of every phase, reply with: what was built, the Gate commands and their real output, what failed or was skipped, open questions for the owner, and the next phase. Never claim a Gate passed without running it.

## 11. Out of Scope for v1 (go to BACKLOG)

Legacy SSE transport; multi-tenant user management UI; write-capable SQL by default; a plugin marketplace; MCP client features (sampling/elicitation) beyond what the SDK gives for free; non-container deployment automation (Terraform etc.).
