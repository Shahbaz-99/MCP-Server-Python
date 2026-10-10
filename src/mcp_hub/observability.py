"""Prometheus metrics and optional OpenTelemetry tracing.

Metric labels are low-cardinality only (tool name, outcome, error code). Tracing is off unless
`tracing_enabled` is set; spans never carry tool arguments or exception text.
"""

from __future__ import annotations

import logging
from typing import Any

from opentelemetry import trace
from prometheus_client import Counter, Histogram

from mcp_hub.errors import ConfigError

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

_log = logging.getLogger(__name__)


def get_tracer() -> trace.Tracer:
    """No-op tracer unless a provider was configured (setup_tracing or the host application)."""
    return trace.get_tracer("mcp_hub")


def setup_tracing(service_name: str) -> None:
    """Configure an OTLP/HTTP exporter. Endpoint and headers come from the standard
    OTEL_EXPORTER_OTLP_* environment variables. Requires the optional `otel` extra."""
    try:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError as exc:
        raise ConfigError(
            "tracing_enabled needs the optional dependencies: pip install 'mcp-hub[otel]'"
        ) from exc
    provider: Any = TracerProvider(resource=Resource.create({"service.name": service_name}))
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
    trace.set_tracer_provider(provider)
    _log.info("tracing enabled (OTLP/HTTP)")
