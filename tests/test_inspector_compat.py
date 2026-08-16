"""Integration tests for @modelcontextprotocol/inspector (Tasks 1.1-1.3)."""

from __future__ import annotations

from starlette.testclient import TestClient

from pinterest_mcp.config import Settings, Transport
from pinterest_mcp.http_app import create_http_app


def test_mcp_inspector_streamable_http_handshake_and_tools_inspection():
    """Test standard MCP Inspector initialization and tools inspection over streamable HTTP."""
    settings = Settings(
        MCP_TRANSPORT=Transport.HTTP,
        MCP_HOST="127.0.0.1",
        MCP_AUTH_TOKEN="inspector-test-token",
        MCP_JSON_RESPONSE=True,
    )
    app = create_http_app(settings)

    with TestClient(app, base_url="http://127.0.0.1:8080") as client:
        # Step 1: Initialize handshake from MCP Inspector
        init_req = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "roots": {"listChanged": True},
                    "sampling": {},
                },
                "clientInfo": {
                    "name": "mcp-inspector",
                    "version": "0.1.0",
                },
            },
        }
        res_init = client.post(
            "/mcp",
            headers={
                "Authorization": "Bearer inspector-test-token",
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            json=init_req,
        )
        assert res_init.status_code == 200
        init_data = res_init.json()
        assert init_data["jsonrpc"] == "2.0"
        assert init_data["id"] == 1
        result = init_data["result"]
        assert "capabilities" in result
        assert "tools" in result["capabilities"]
        assert result["serverInfo"]["name"] == "pinterest-mcp"

        # Capture session ID if provided in header
        session_id = res_init.headers.get("mcp-session-id") or res_init.headers.get(
            "Mcp-Session-Id"
        )
        headers = {
            "Authorization": "Bearer inspector-test-token",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        if session_id:
            headers["Mcp-Session-Id"] = session_id

        # Step 2: notifications/initialized
        res_notif = client.post(
            "/mcp",
            headers=headers,
            json={"jsonrpc": "2.0", "method": "notifications/initialized"},
        )
        assert res_notif.status_code in (200, 202, 204)

        # Step 3: tools/list inspection
        res_tools = client.post(
            "/mcp",
            headers=headers,
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        )
        assert res_tools.status_code == 200
        tools_data = res_tools.json()
        assert tools_data["id"] == 2
        tools_list = tools_data["result"]["tools"]
        assert len(tools_list) == 11

        tool_names = {t["name"] for t in tools_list}
        assert "create_pin" in tool_names
        assert "bulk_create_pins" in tool_names
        assert "list_boards" in tool_names
        assert "get_pin_analytics" in tool_names

        # Verify all tools have valid inputSchema
        for t in tools_list:
            assert "name" in t
            assert "description" in t
            assert "inputSchema" in t
            assert t["inputSchema"]["type"] == "object"


def test_mcp_inspector_sse_compatibility_transport():
    """Test MCP Inspector connection sequence over legacy SSE transport."""
    settings = Settings(
        MCP_TRANSPORT=Transport.HTTP_SSE,
        MCP_HOST="127.0.0.1",
        MCP_AUTH_TOKEN="inspector-test-token",
        MCP_SSE_PATH="/sse",
        MCP_MESSAGE_PATH="/messages/",
    )
    app = create_http_app(settings)

    with (
        TestClient(app, base_url="http://127.0.0.1:8080") as client,
        client.stream(
            "GET", "/sse", headers={"Authorization": "Bearer inspector-test-token"}
        ) as response,
    ):
        assert response.status_code == 200
        assert "text/event-stream" in response.headers.get("content-type", "")


def test_mcp_inspector_auth_challenge_and_unauthorized():
    """Test unauthenticated inspector requests receive standard 401 challenge."""
    settings = Settings(
        MCP_TRANSPORT=Transport.HTTP,
        MCP_HOST="127.0.0.1",
        MCP_AUTH_TOKEN="inspector-test-token",
    )
    app = create_http_app(settings)

    with TestClient(app, base_url="http://127.0.0.1:8080") as client:
        # Missing Authorization header -> 401
        res = client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
        )
        assert res.status_code == 401
        assert "Bearer" in res.headers.get("www-authenticate", "")

        # Invalid Bearer token -> 401
        res_bad = client.post(
            "/mcp",
            headers={"Authorization": "Bearer wrong-token"},
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
        )
        assert res_bad.status_code == 401
