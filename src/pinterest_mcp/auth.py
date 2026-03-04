"""OAuth 2.0 authorization flow for Pinterest.

Run once to get your access + refresh tokens:
    pinterest-mcp-auth
"""

from __future__ import annotations

import asyncio
import json
import os
import time
import secrets
import webbrowser
from pathlib import Path
from urllib.parse import urlencode

import httpx
from aiohttp import web  # type: ignore[import]

PINTEREST_AUTH_URL = "https://www.pinterest.com/oauth/"
PINTEREST_TOKEN_URL = "https://api.pinterest.com/v5/oauth/token"
TOKEN_FILE = Path(".pinterest_token.json")
REDIRECT_URI = "http://localhost:8089/callback"
SCOPES = "boards:read,boards:write,pins:read,pins:write,user_accounts:read"


async def _run_local_server() -> str:
    """Run a minimal local server to receive the OAuth callback."""
    code_future: asyncio.Future[str] = asyncio.get_event_loop().create_future()

    async def callback(request: web.Request) -> web.Response:
        code = request.query.get("code")
        if code:
            code_future.set_result(code)
            return web.Response(text="✅ Authorized! You can close this window.")
        return web.Response(text="❌ No code in callback.", status=400)

    app = web.Application()
    app.router.add_get("/callback", callback)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "localhost", 8089)
    await site.start()
    code = await code_future
    await runner.cleanup()
    return code


def run_auth_flow() -> None:
    """Entrypoint for `pinterest-mcp-auth` CLI command."""
    client_id = os.environ.get("PINTEREST_CLIENT_ID") or input("Pinterest Client ID: ").strip()
    client_secret = (
        os.environ.get("PINTEREST_CLIENT_SECRET") or input("Pinterest Client Secret: ").strip()
    )

    state = secrets.token_urlsafe(16)
    params = {
        "client_id": client_id,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": SCOPES,
        "state": state,
    }
    auth_url = f"{PINTEREST_AUTH_URL}?{urlencode(params)}"
    print(f"Opening browser: {auth_url}")
    webbrowser.open(auth_url)

    async def _exchange() -> None:
        code = await _run_local_server()
        async with httpx.AsyncClient() as http:
            resp = await http.post(
                PINTEREST_TOKEN_URL,
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": REDIRECT_URI,
                },
                auth=(client_id, client_secret),
            )
            resp.raise_for_status()
            token_data = resp.json()
        TOKEN_FILE.write_text(
            json.dumps({
                "access_token": token_data["access_token"],
                "refresh_token": token_data.get("refresh_token"),
                "expiry": time.time() + token_data.get("expires_in", 3600),
            })
        )
        print(f"✅ Token saved to {TOKEN_FILE}")

    asyncio.run(_exchange())
