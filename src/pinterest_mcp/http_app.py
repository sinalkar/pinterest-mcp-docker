"""Starlette HTTP app with StreamableHTTPSessionManager and SseServerTransport.

Supports bearer auth middleware, CORS, DNS-rebinding protection, and transport options.
"""

from __future__ import annotations

import hmac
import logging
from contextlib import asynccontextmanager
from typing import Any

from mcp.server.sse import SseServerTransport
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Mount, Route
from starlette.types import Receive, Scope, Send

from . import __version__
from .app import get_lowlevel_server
from .config import Settings, Transport, load_settings
from .event_store import InMemoryEventStore

logger = logging.getLogger(__name__)


class BearerAuthMiddleware(BaseHTTPMiddleware):
    """Bearer token authorization middleware."""

    def __init__(
        self, app: Any, auth_token: str | None, exempt_paths: set[str] | None = None
    ) -> None:
        super().__init__(app)
        self.auth_token = auth_token
        self.exempt_paths = exempt_paths or {"/healthz"}

    async def dispatch(self, request: Request, call_next: Any) -> Any:
        if request.url.path in self.exempt_paths:
            return await call_next(request)

        if self.auth_token is not None:
            auth_header = request.headers.get("Authorization", "")
            expected = f"Bearer {self.auth_token}"
            if not auth_header or not hmac.compare_digest(auth_header.encode(), expected.encode()):
                return JSONResponse({"error": "Unauthorized"}, status_code=401)

        return await call_next(request)


def create_http_app(settings: Settings | None = None) -> Starlette:
    """Create the Starlette application with /healthz and MCP endpoint(s)."""
    if settings is None:
        settings = load_settings()

    if not settings.dns_rebinding_protection:
        logger.warning(
            "DNS-rebinding protection is disabled via MCP_DNS_REBINDING_PROTECTION=false"
        )

    security_settings = TransportSecuritySettings(
        enable_dns_rebinding_protection=settings.dns_rebinding_protection,
        allowed_hosts=settings.effective_allowed_hosts,
        allowed_origins=settings.effective_allowed_origins_for_security,
    )

    event_store = (
        InMemoryEventStore(max_events_per_stream=settings.event_store_max_events)
        if settings.resumability
        else None
    )

    session_manager = StreamableHTTPSessionManager(
        app=get_lowlevel_server(),
        event_store=event_store,
        json_response=settings.json_response,
        stateless=settings.stateless,
        security_settings=security_settings,
        retry_interval=settings.sse_retry_interval_ms,
        session_idle_timeout=settings.session_idle_timeout,
        max_request_body_size=settings.max_request_bytes,
    )

    @asynccontextmanager
    async def lifespan(app_instance: Starlette):
        async with session_manager.run():
            yield

    surfaces: dict[str, str] = {}
    routes: list[Route | Mount] = []

    is_oauth = settings.effective_auth_mode == "oauth"

    resource_metadata_url = None
    if is_oauth and settings.resource_url:
        from mcp.server.auth.routes import build_resource_metadata_url
        from pydantic import AnyHttpUrl

        resource_metadata_url = build_resource_metadata_url(AnyHttpUrl(settings.resource_url))

    if settings.transport in (Transport.HTTP, Transport.HTTP_SSE):
        surfaces["streamable_http"] = settings.path
        if is_oauth:
            from mcp.server.auth.middleware.bearer_auth import RequireAuthMiddleware

            routes.append(
                Mount(
                    settings.path,
                    app=RequireAuthMiddleware(
                        session_manager.handle_request,
                        settings.oauth_required_scopes,
                        resource_metadata_url,
                    ),
                )
            )
        else:
            routes.append(Mount(settings.path, app=session_manager.handle_request))

    if settings.transport in (Transport.SSE, Transport.HTTP_SSE):
        surfaces["sse"] = settings.sse_path
        surfaces["messages"] = settings.message_path
        sse_transport = SseServerTransport(
            endpoint=settings.message_path,
            security_settings=security_settings,
        )

        async def handle_sse(scope: Scope, receive: Receive, send: Send) -> None:
            async with sse_transport.connect_sse(scope, receive, send) as streams:
                lowlevel = get_lowlevel_server()
                await lowlevel.run(streams[0], streams[1], lowlevel.create_initialization_options())

        if is_oauth:
            from mcp.server.auth.middleware.bearer_auth import RequireAuthMiddleware

            routes.append(
                Route(
                    settings.sse_path,
                    endpoint=RequireAuthMiddleware(
                        handle_sse,
                        settings.oauth_required_scopes,
                        resource_metadata_url,
                    ),
                    methods=["GET"],
                )
            )
            routes.append(
                Mount(
                    settings.message_path,
                    app=RequireAuthMiddleware(
                        sse_transport.handle_post_message,
                        settings.oauth_required_scopes,
                        resource_metadata_url,
                    ),
                )
            )
        else:

            async def sse_endpoint(request: Request) -> Response:
                await handle_sse(request.scope, request.receive, request._send)
                return Response()

            routes.append(Route(settings.sse_path, endpoint=sse_endpoint, methods=["GET"]))
            routes.append(Mount(settings.message_path, app=sse_transport.handle_post_message))

    # Add protected resource metadata endpoint if configured in OAuth mode
    if is_oauth and settings.resource_url and settings.oauth_issuer:
        from mcp.server.auth.routes import create_protected_resource_routes
        from pydantic import AnyHttpUrl

        routes.extend(
            create_protected_resource_routes(
                resource_url=AnyHttpUrl(settings.resource_url),
                authorization_servers=[AnyHttpUrl(settings.oauth_issuer)],
                scopes_supported=settings.oauth_required_scopes or None,
            )
        )

    async def healthz(request: Request) -> JSONResponse:
        return JSONResponse(
            {
                "status": "ok",
                "version": __version__,
                "transport": settings.transport.value,
                "surfaces": surfaces,
                "stateless": settings.stateless,
                "json_response": settings.json_response,
                "resumability": settings.resumability,
                "auth_mode": settings.effective_auth_mode,
            }
        )

    routes.insert(0, Route("/healthz", healthz, methods=["GET"]))

    middleware: list[Middleware] = []

    if settings.allowed_origins:
        middleware.append(
            Middleware(
                CORSMiddleware,
                allow_origins=settings.allowed_origins,
                allow_credentials=settings.cors_allow_credentials,
                allow_methods=["*"],
                allow_headers=["*"],
                expose_headers=["Mcp-Session-Id", "MCP-Protocol-Version"],
            )
        )

    if settings.effective_auth_mode == "bearer":
        auth_token_str = settings.auth_token.get_secret_value() if settings.auth_token else None
        middleware.append(
            Middleware(
                BearerAuthMiddleware,
                auth_token=auth_token_str,
                exempt_paths={"/healthz"},
            )
        )
    elif settings.effective_auth_mode == "oauth":
        from mcp.server.auth.middleware.auth_context import AuthContextMiddleware
        from mcp.server.auth.middleware.bearer_auth import BearerAuthBackend
        from starlette.middleware.authentication import AuthenticationMiddleware

        from .oauth import JWTTokenVerifier

        verifier = JWTTokenVerifier(
            issuer=settings.oauth_issuer,  # type: ignore[arg-type]
            resource_url=settings.resource_url,
            jwks_url=settings.oauth_jwks_url,
        )
        middleware.append(
            Middleware(
                AuthenticationMiddleware,
                backend=BearerAuthBackend(verifier),
            )
        )
        middleware.append(Middleware(AuthContextMiddleware))

    return Starlette(routes=routes, middleware=middleware, lifespan=lifespan)
