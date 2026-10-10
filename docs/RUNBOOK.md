# Runbook

## Performance (measured)

Method: `uv run python scripts/loadtest.py --clients 100 --duration 20 --paced-rps 3 --soak 120`. It starts the real server (HTTP, API-key auth on, `echo` tool, audit logging at WARNING so disk I/O is not measured) and drives it with threads over keep-alive connections.

Machine: Windows 11 laptop, Python 3.14.7, one server process, load generator on the same machine.

| Scenario | Clients | Requests | Errors | Throughput | p50 | p95 | p99 |
|---|---|---|---|---|---|---|---|
| idle (sequential) | 1 | 3,678 | 0 | 368 req/s | 2.5 ms | **3.7 ms** | 4.7 ms |
| saturate (closed loop) | 100 | 8,770 | 0 | 436 req/s | 216 ms | 309 ms | 330 ms |
| paced, 3 req/s per client | 100 | 6,000 | 0 | 298 req/s | 143 ms | 197 ms | 216 ms |
| soak, 120 s | 100 | 51,331 | 0 | 427 req/s | 219 ms | 311 ms | 335 ms |

Memory (server process RSS): 92 MB at start, 118 MB at steady state, 121.6 MB peak. Growth between the start and end of the steady state was **0.0%** over the 120 s soak. A separate 260 s run at 50 clients stayed flat at 107-108 MB. No leak was observed.

How to read this:

- Spec target "p95 < 50 ms for a trivial local tool": **met for an unloaded server** (3.7 ms). **Not met at 100 concurrent clients on one process**: one process serves about 430 tool calls per second, so with 100 clients in a closed loop each request waits behind the others (latency is about clients divided by throughput). This is queueing, not slowness per request.
- Scale out by running more replicas behind a load balancer. The HTTP transport is stateless, so any replica can serve any request. Rate limits are per process, so the effective limit is the configured limit times the number of replicas.
- Setting `MCP_HUB_HTTP__JSON_RESPONSE=true` (plain JSON instead of an SSE stream) gave about 40-60% more throughput in a quick measurement (roughly 700 req/s). The cost is that a tool cannot stream progress notifications to the client.
- The load generator shares the machine and the GIL with the 100 client threads, so the paced-scenario latency is partly client-side. Treat these numbers as a baseline, not as a capacity guarantee. Re-measure on your target hardware.

## Metrics

`GET /metrics` (Prometheus text format). With auth enabled it needs a token with scope `admin:metrics`.

| Metric | Meaning |
|---|---|
| `mcp_hub_tool_calls_total{tool,outcome}` | outcome: `ok`, `error`, `denied`, `cancelled` |
| `mcp_hub_tool_latency_seconds{tool}` | histogram |
| `mcp_hub_tool_errors_total{tool,code}` | stable error codes (`timeout`, `access_denied`, `upstream_error`, ...) |
| `mcp_hub_auth_failures_total{reason}` | `jwt_expired`, `jwt_audience`, `apikey_revoked`, `jwks_unavailable`, ... |
| `mcp_hub_rate_limited_total` | requests rejected with 429 |
| `mcp_hub_http_requests_total{path,status}` | bounded path labels |

More sections (alerts, failure modes, key rotation) are completed in Phase 7.
