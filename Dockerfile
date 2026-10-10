# syntax=docker/dockerfile:1.7

# Base images are pinned by digest. Refresh both together (Dependabot opens PRs for the tags):
#   python:3.12-slim-bookworm   ghcr.io/astral-sh/uv:0.12.23
FROM ghcr.io/astral-sh/uv:0.12.23@sha256:61d393e44e249f2e4b526b6c7ddcecce245946826e608e11c93ad4f5bba55b21 AS uv

FROM python:3.14-slim-bookworm@sha256:48b13b003dda20b16f9442b8475aa05fe21bf6579a8c881db92ffb4d8fd20f83 AS builder
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never UV_NO_CACHE=1
WORKDIR /app
# Dependencies first: this layer is cached until pyproject.toml or uv.lock change.
COPY pyproject.toml uv.lock README.md LICENSE ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable

FROM python:3.14-slim-bookworm@sha256:48b13b003dda20b16f9442b8475aa05fe21bf6579a8c881db92ffb4d8fd20f83 AS runtime
LABEL org.opencontainers.image.title="mcp-hub" \
      org.opencontainers.image.description="Plugin-based MCP server (stdio + Streamable HTTP)" \
      org.opencontainers.image.licenses="MIT"
RUN groupadd --system --gid 10001 app \
 && useradd --system --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app \
 && install -d -o app -g app -m 0750 /data
COPY --from=builder --chown=root:root /app/.venv /app/.venv
ENV PATH=/app/.venv/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONHASHSEED=random \
    MCP_HUB_AUTH__API_KEY_FILE=/data/keys.json
USER 10001:10001
WORKDIR /data
EXPOSE 8000
# Nothing here needs a shell or curl. /healthz is liveness; use /readyz for load balancer checks.
HEALTHCHECK --interval=15s --timeout=4s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import sys,urllib.request as u; sys.exit(0 if u.urlopen('http://127.0.0.1:8000/healthz', timeout=3).status == 200 else 1)"]
ENTRYPOINT ["mcp-hub"]
# Binding 0.0.0.0 inside a container is required. The server still refuses to start unless auth is
# enabled (MCP_HUB_AUTH__ENABLED=true plus MCP_HUB_AUTH__RESOURCE_URL and a key file or issuer).
CMD ["--transport", "http", "--host", "0.0.0.0", "--allow-public-bind", "--port", "8000"]
