"""OAuth 2.0 authorization flow for Pinterest.

Run once to get your access + refresh tokens:
    pinterest-mcp-auth
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import secrets
import time
import webbrowser
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx

from .config import load_settings
from .security import save_atomic_token_file

PINTEREST_AUTH_URL = "https://www.pinterest.com/oauth/"
PINTEREST_TOKEN_URL = "https://api.pinterest.com/v5/oauth/token"  # nosec B105 # noqa: S105
REDIRECT_URI = "http://localhost:8089/callback"
SCOPES = "boards:read,boards:write,pins:read,pins:write,user_accounts:read"
CALLBACK_TIMEOUT_SECONDS = 300.0
_MAX_CALLBACK_REQUEST_LINE = 8 * 1024


def _process_callback_request(
    request_line: bytes, expected_state: str, code_future: asyncio.Future[str]
) -> tuple[int, str]:
    """Validate one callback request line without exposing its credentials."""
    if len(request_line) > _MAX_CALLBACK_REQUEST_LINE:
        return 400, "Invalid callback request."
    try:
        method, target, _version = request_line.decode("ascii").rstrip("\r\n").split(" ", 2)
        parsed = urlsplit(target)
    except (UnicodeDecodeError, ValueError):
        return 400, "Invalid callback request."

    if method != "GET" or parsed.path != "/callback":
        return 404, "Not found."

    query = parse_qs(parsed.query)
    code = query.get("code", [None])[0]
    received_state = query.get("state", [None])[0]
    if not code:
        return 400, "No authorization code in callback."
    if not isinstance(received_state, str) or not secrets.compare_digest(
        received_state, expected_state
    ):
        return 400, "Invalid OAuth state. Please restart authorization."
    if code_future.done():
        return 400, "Authorization is already complete."
    code_future.set_result(code)
    return 200, "Authorized. You can close this window."


async def _run_local_server(
    expected_state: str,
    *,
    timeout: float = CALLBACK_TIMEOUT_SECONDS,
    host: str = "localhost",
    port: int = 8089,
) -> str:
    """Receive one OAuth callback on loopback and return its authorization code."""
    loop = asyncio.get_running_loop()
    code_future: asyncio.Future[str] = loop.create_future()

    async def respond(writer: asyncio.StreamWriter, status: int, body: str) -> None:
        encoded_body = body.encode("utf-8")
        reason = {200: "OK", 400: "Bad Request", 404: "Not Found"}[status]
        writer.write(
            (
                f"HTTP/1.1 {status} {reason}\r\n"
                "Content-Type: text/plain; charset=utf-8\r\n"
                f"Content-Length: {len(encoded_body)}\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii")
            + encoded_body
        )
        await writer.drain()

    async def callback(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            request_line = await asyncio.wait_for(reader.readline(), timeout=5.0)
            status, body = _process_callback_request(request_line, expected_state, code_future)
            await respond(writer, status, body)
        except (ConnectionError, TimeoutError):
            # A malformed or abandoned browser connection must not end the auth flow.
            return
        finally:
            writer.close()
            with contextlib.suppress(ConnectionError):
                await writer.wait_closed()

    server = await asyncio.start_server(callback, host, port)
    try:
        try:
            return await asyncio.wait_for(code_future, timeout=timeout)
        except TimeoutError as exc:
            raise RuntimeError(
                "Timed out waiting for OAuth callback. Please restart authorization."
            ) from exc
    finally:
        server.close()
        await server.wait_closed()


def run_auth_flow() -> None:
    """Entrypoint for `pinterest-mcp-auth` CLI command."""
    settings = load_settings()
    client_id = (
        (settings.client_id.get_secret_value() if settings.client_id else None)
        or os.environ.get("PINTEREST_CLIENT_ID")
        or input("Pinterest Client ID: ").strip()
    )
    client_secret = (
        (settings.client_secret.get_secret_value() if settings.client_secret else None)
        or os.environ.get("PINTEREST_CLIENT_SECRET")
        or input("Pinterest Client Secret: ").strip()
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
        code = await _run_local_server(state)
        async with httpx.AsyncClient(verify=True) as http:
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

        save_atomic_token_file(
            settings.token_path,
            {
                "access_token": token_data["access_token"],
                "refresh_token": token_data.get("refresh_token"),
                "expiry": time.time() + token_data.get("expires_in", 3600),
            },
        )
        print(f"✅ Token saved to {settings.token_path}")

    asyncio.run(_exchange())
