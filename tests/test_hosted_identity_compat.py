"""Hosted-auth SDK spike: real JWT middleware and the production tool dispatcher.

These tests do not claim Pinterest account isolation is implemented. They prove
the identity and metadata interfaces the hosted implementation will depend on.
Only JWKS retrieval and the final Pinterest API client are replaced.
"""

from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import AsyncMock, MagicMock

import anyio
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from mcp import types
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.mcpserver import MCPServer
from starlette.testclient import TestClient

from pinterest_mcp import app as application
from pinterest_mcp.config import Settings
from pinterest_mcp.http_app import create_http_app

ISSUER = "https://identity.example.com"
RESOURCE = "https://pinterest.example.com/mcp"


@pytest.fixture
def signed_tokens(monkeypatch):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwks = MagicMock()
    jwks.get_signing_key_from_jwt.return_value.key = key.public_key()
    monkeypatch.setattr("pinterest_mcp.oauth.PyJWKClient", lambda *a, **kw: jwks)

    def mint(subject: str, *, audience: str = RESOURCE, expires_in: int = 300) -> str:
        now = int(time.time())
        return jwt.encode(
            {
                "iss": ISSUER,
                "aud": audience,
                "sub": subject,
                "client_id": "same-chatgpt-client",
                "scope": "pinterest.read",
                "iat": now,
                "exp": now + expires_in,
            },
            key,
            algorithm="RS256",
            headers={"kid": "ephemeral-test-key"},
        )

    return mint


def hosted_transport():
    """Exercise the existing OAuth transport in the planned stateless shape."""
    return create_http_app(
        Settings(
            MCP_TRANSPORT="http",
            MCP_HOST="127.0.0.1",
            MCP_OAUTH_ISSUER=ISSUER,
            MCP_RESOURCE_URL=RESOURCE,
            MCP_OAUTH_REQUIRED_SCOPES="pinterest.read",
            MCP_STATELESS=True,
            MCP_JSON_RESPONSE=True,
        )
    )


def tool_request(client, token: str, protocol: str, request_id: int):
    params = {"name": "list_boards", "arguments": {}}
    if protocol == "2026-07-28":
        from mcp_types import CLIENT_CAPABILITIES_META_KEY, PROTOCOL_VERSION_META_KEY

        params["_meta"] = {
            PROTOCOL_VERSION_META_KEY: protocol,
            CLIENT_CAPABILITIES_META_KEY: {},
        }
    return client.post(
        "/mcp",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": protocol,
            "Mcp-Method": "tools/call",
            "Mcp-Name": "list_boards",
        },
        json={
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": params,
        },
    )


@pytest.mark.parametrize("protocol", ["2024-11-05", "2025-03-26", "2025-06-18", "2026-07-28"])
def test_verified_identity_reaches_custom_dispatch_concurrently(
    signed_tokens, monkeypatch, protocol
):
    pinterest = MagicMock()
    pinterest.list_boards = AsyncMock(return_value=[{"id": "test-board"}])
    monkeypatch.setattr(application, "get_client", lambda: pinterest)
    server = application.get_lowlevel_server()
    observed = {}
    both_entered = None

    async def inspect_dispatch(ctx, params):
        nonlocal both_entered
        # Use the per-message Request supplied by the SDK, not unverified
        # request headers, a client ID, or the session's first caller.
        user = ctx.request.scope["user"]
        assert isinstance(user, AuthenticatedUser)
        token = user.access_token
        principal = (token.claims["iss"], token.subject)
        observed[ctx.request_id] = principal
        if both_entered is None:
            both_entered = anyio.Event()
        if len(observed) == 2:
            both_entered.set()
        with anyio.fail_after(5):
            await both_entered.wait()
        result = await application._handle_call_tool(ctx, params)
        assert (user.access_token.claims["iss"], user.access_token.subject) == principal
        return result

    server.add_request_handler("tools/call", types.CallToolRequestParams, inspect_dispatch)
    try:
        with (
            TestClient(hosted_transport(), base_url="http://127.0.0.1:8080") as client,
            ThreadPoolExecutor(max_workers=2) as pool,
        ):
            first = pool.submit(tool_request, client, signed_tokens("alice"), protocol, 1)
            second = pool.submit(tool_request, client, signed_tokens("bob"), protocol, 2)
            responses = [first.result(timeout=10), second.result(timeout=10)]
        for response in responses:
            assert response.status_code == 200, response.text
            result = response.json()["result"]
            assert not result.get("isError", False)
            assert json.loads(result["content"][0]["text"]) == [{"id": "test-board"}]
        assert observed == {1: (ISSUER, "alice"), 2: (ISSUER, "bob")}
        assert pinterest.list_boards.await_count == 2
    finally:
        server.add_request_handler(
            "tools/call", types.CallToolRequestParams, application._handle_call_tool
        )


@pytest.mark.parametrize("invalid", ["expired", "wrong-audience", "not-a-jwt"])
def test_unverified_identity_never_reaches_dispatch(signed_tokens, monkeypatch, invalid):
    get_client = MagicMock(side_effect=AssertionError("Unauthorized request reached dispatch"))
    monkeypatch.setattr(application, "get_client", get_client)
    token = {
        "expired": signed_tokens("alice", expires_in=-300),
        "wrong-audience": signed_tokens("alice", audience="https://other.example.com"),
        "not-a-jwt": "invalid-token",
    }[invalid]
    with TestClient(hosted_transport(), base_url="http://127.0.0.1:8080") as client:
        response = tool_request(client, token, "2025-06-18", 1)
    assert response.status_code == 401
    assert "resource_metadata=" in response.headers["www-authenticate"]
    get_client.assert_not_called()


@pytest.mark.asyncio
async def test_sdk_preserves_tool_security_metadata_and_auth_challenges():
    # Isolated SDK server avoids changing the production tool registry during
    # the compatibility spike. Actual hosted declarations follow in task 3.4.
    server = MCPServer(name="hosted-metadata-spike")
    schemes = [{"type": "oauth2", "scopes": ["pinterest.read"]}]

    async def connection_status() -> str:
        return "connected"

    server.add_tool(connection_status, meta={"securitySchemes": schemes})
    tool = (await server.list_tools())[0]
    wire = tool.model_dump(by_alias=True, exclude_none=True)
    assert wire["_meta"]["securitySchemes"] == schemes
    # SDK 2.0.0 silently drops this top-level extension. Record the boundary:
    # the hosted tools/list adapter must emit a raw mapping for the top-level
    # declaration, while retaining the supported _meta mirror.
    extended = types.Tool.model_validate({**wire, "securitySchemes": schemes})
    assert "securitySchemes" not in extended.model_dump(by_alias=True)
    challenge = 'Bearer error="insufficient_scope", error_description="Login required"'
    result = types.CallToolResult(
        content=[types.TextContent(type="text", text="Authentication required")],
        is_error=True,
        meta={"mcp/www_authenticate": [challenge]},
    )
    assert result.model_dump(by_alias=True)["_meta"]["mcp/www_authenticate"] == [challenge]
