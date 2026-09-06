"""Private HTTPS-only ASGI ingress. Mount separately from the public MCP application."""

import asyncio
import logging
from contextlib import asynccontextmanager, suppress

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from .ingress import IngressSecurityError, authenticate_ingress
from .pending import expire_pending, process_pending

INGRESS_PATH = "/internal/credential-ingress"


def create_credential_ingress(*, session_factory, cipher, nonce_store, shared_secret, issuer):
    if not shared_secret or not issuer:
        raise ValueError("Private ingress authentication configuration is required")

    async def cleanup():
        async with session_factory.begin() as session:
            await expire_pending(session)

    async def maintain():
        while True:
            try:
                await cleanup()
            except Exception:
                # No exception details: database errors can contain credentials/parameters.
                logging.getLogger(__name__).warning("Pending credential cleanup unavailable")
            await asyncio.sleep(30)

    @asynccontextmanager
    async def lifespan(app):
        task = asyncio.create_task(maintain())
        try:
            yield
        finally:
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task

    async def handoff(request: Request):
        try:
            if request.url.scheme != "https" or request.url.query:
                raise IngressSecurityError("Private HTTPS required")
            # Preserve detection of duplicate headers before converting to a mapping.
            raw_headers = request.scope["headers"]
            if len({key.lower() for key, _ in raw_headers}) != len(raw_headers):
                raise IngressSecurityError("Duplicate headers")
            body = bytearray()
            async for chunk in request.stream():
                body.extend(chunk)
                if len(body) > 65536:
                    return JSONResponse({"error": "invalid_handoff"}, status_code=413)
            await authenticate_ingress(
                nonce_store,
                shared_secret,
                request.method,
                INGRESS_PATH,
                dict(request.headers),
                bytes(body),
            )
            import json

            payload = json.loads(body)
            if not isinstance(payload, dict) or payload.get("issuer") != issuer:
                raise IngressSecurityError("Issuer mismatch")
            # Cleanup commits even if the subsequent request is invalid or expired.
            await cleanup()
            async with session_factory.begin() as session:
                result = await process_pending(session, cipher, payload)
            # Transaction context has committed before an acknowledgment is sent.
            return JSONResponse(result, headers={"Cache-Control": "no-store"})
        except (IngressSecurityError, ValueError, TypeError):
            return JSONResponse({"error": "invalid_handoff"}, status_code=400)
        except Exception:
            return JSONResponse({"error": "handoff_unavailable"}, status_code=503)

    return Starlette(routes=[Route(INGRESS_PATH, handoff, methods=["POST"])], lifespan=lifespan)
