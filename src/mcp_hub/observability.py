"""Prometheus metrics. Labels are low-cardinality only (tool name, outcome, error code)."""

from __future__ import annotations

from prometheus_client import Counter, Histogram

TOOL_CALLS = Counter("mcp_hub_tool_calls_total", "Tool calls", ["tool", "outcome"])
TOOL_LATENCY = Histogram(
    "mcp_hub_tool_latency_seconds",
    "Tool call latency",
    ["tool"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30),
)
TOOL_ERRORS = Counter("mcp_hub_tool_errors_total", "Tool errors by code", ["tool", "code"])
AUTH_FAILURES = Counter(
    "mcp_hub_auth_failures_total", "Rejected authentication attempts", ["reason"]
)
RATE_LIMITED = Counter("mcp_hub_rate_limited_total", "Requests rejected by rate limiting")
HTTP_REQUESTS = Counter("mcp_hub_http_requests_total", "HTTP requests", ["path", "status"])
