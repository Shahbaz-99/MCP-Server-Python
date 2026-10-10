"""Streamable HTTP transport: SDK app + health/metrics routes + limits + auth."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field

import uvicorn
from mcp.server.auth.settings import AuthSettings as SdkAuthSettings
from mcp.server.transport_security import TransportSecuritySettings
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

from mcp_hub.config import Settings
from mcp_hub.security.apikeys import KeyStore
from mcp_hub.security.auth import HubTokenVerifier
from mcp_hub.security.identity import WILDCARD
from mcp_hub.security.jwks import JwksCache
from mcp_hub.security.ratelimit import LimitsMiddleware
from mcp_hub.server import BuiltServer, build_server

_log = logging.getLogger("mcp_hub")
METRICS_SCOPE = "admin:metrics"


@dataclass
class ReadyState:
    ready: bool = False


@dataclass
class HttpStack:
    app: ASGIApp  # outermost ASGI callable; give this to the server
    starlette: Starlette  # inner app; its lifespan must run
    built: BuiltServer
    state: ReadyState = field(default_factory=ReadyState)


def build_http_stack(
    settings: Settings,
    *,
    keystore: KeyStore | None = None,
    jwks: JwksCache | None = None,
) -> HttpStack:
    settings.check_startup_invariants()
    settings.check_http_invariants()
    h, a = settings.http, settings.auth

    verifier: HubTokenVerifier | None = None
    sdk_auth: SdkAuthSettings | None = None
    if a.enabled:
        if keystore is None and a.api_key_file:
            keystore = KeyStore(a.api_key_file)
        verifier = HubTokenVerifier(a, keystore=keystore, jwks=jwks)
        assert a.resource_url is not None  # guaranteed by check_startup_invariants
        sdk_auth = SdkAuthSettings(
            issuer_url=a.issuer or a.resource_url,
            resource_server_url=a.resource_url,
            required_scopes=a.required_scopes or None,
            validate_token_resource=True,
        )

    built = build_server(
        settings, local_trusted=not a.enabled, token_verifier=verifier, sdk_auth=sdk_auth
    )
    state = ReadyState()
    server = built.server

    async def healthz(_: Request) -> Response:
        return JSONResponse({"status": "ok"})

    async def readyz(_: Request) -> Response:
        if not state.ready:
            return JSONResponse({"status": "not_ready"}, status_code=503)
        return JSONResponse({"status": "ready", "plugins": built.plugins})

    async def metrics(request: Request) -> Response:
        if verifier is not None and h.metrics_requires_auth:
            header = request.headers.get("authorization", "")
            token = header[7:] if header.lower().startswith("bearer ") else ""
            access = await verifier.verify_token(token) if token else None
            if access is None:
                return Response(status_code=401, headers={"WWW-Authenticate": "Bearer"})
            if METRICS_SCOPE not in access.scopes and WILDCARD not in access.scopes:
                return Response(status_code=403)
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    for path, handler in (("/healthz", healthz), ("/readyz", readyz), ("/metrics", metrics)):
        server.custom_route(path, methods=["GET"], include_in_schema=False)(handler)

    starlette = server.streamable_http_app(
        stateless_http=True,
        json_response=h.json_response,
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=list(h.allowed_hosts),
            allowed_origins=list(h.allowed_origins),
        ),
        max_request_body_size=h.max_body_bytes,
        host=h.host,
    )

    inner = starlette.router.lifespan_context

    @asynccontextmanager
    async def lifespan(app: Starlette) -> AsyncIterator[None]:
        async with inner(app):
            state.ready = True
            try:
                yield
            finally:
                state.ready = False  # fail readiness first so load balancers drain us
                await built.registrar.run_shutdown()

    starlette.router.lifespan_context = lifespan

    outer = LimitsMiddleware(
        starlette,
        rate_limit_per_minute=h.rate_limit_per_minute,
        max_concurrency=h.max_concurrency,
        max_body_bytes=h.max_body_bytes,
    )
    return HttpStack(app=outer, starlette=starlette, built=built, state=state)


def run_http(settings: Settings) -> None:
    stack = build_http_stack(settings)
    h = settings.http
    _log.info(
        "starting http transport on %s:%d auth=%s plugins=%s",
        h.host,
        h.port,
        settings.auth.enabled,
        stack.built.plugins,
    )
    uvicorn.run(
        stack.app,
        host=h.host,
        port=h.port,
        log_config=None,
        access_log=False,
        server_header=False,
        date_header=False,
        proxy_headers=bool(h.forwarded_allow_ips),
        forwarded_allow_ips=h.forwarded_allow_ips,
        timeout_graceful_shutdown=int(settings.shutdown_grace_seconds),
    )
