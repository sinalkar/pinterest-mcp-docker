"""Starlette HTTP app with StreamableHTTPSessionManager.

Supports bearer auth middleware (Tasks 5.2-5.5).
"""

from __future__ import annotations

import hmac
import logging
from contextlib import asynccontextmanager
from typing import Any

from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route

from . import __version__
from .app import mcp_app
from .config import Settings, load_settings

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
    """Create the Starlette application with /healthz and MCP endpoint."""
    if settings is None:
        settings = load_settings()

    session_manager = StreamableHTTPSessionManager(mcp_app)

    @asynccontextmanager
    async def lifespan(app_instance: Starlette):
        async with session_manager.run():
            yield

    async def healthz(request: Request) -> JSONResponse:
        return JSONResponse(
            {
                "status": "ok",
                "version": __version__,
                "transport": "http",
            }
        )

    auth_token_str = settings.auth_token.get_secret_value() if settings.auth_token else None

    middleware = [
        Middleware(
            BearerAuthMiddleware,
            auth_token=auth_token_str,
            exempt_paths={"/healthz"},
        )
    ]

    routes = [
        Route("/healthz", healthz, methods=["GET"]),
        Mount(settings.path, app=session_manager.handle_request),
    ]

    return Starlette(routes=routes, middleware=middleware, lifespan=lifespan)
