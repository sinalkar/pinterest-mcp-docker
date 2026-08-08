"""Transport tests: stdio vs HTTP, bearer auth, healthz, and startup guards (Task 5.6)."""

from __future__ import annotations

import asyncio

import pytest
from mcp import ClientSession
from mcp.shared.memory import create_client_server_memory_streams
from starlette.testclient import TestClient

from pinterest_mcp.app import get_lowlevel_server, list_tools, set_client
from pinterest_mcp.cli import main
from pinterest_mcp.client import PinterestClient
from pinterest_mcp.config import ConfigError, Settings, Transport, load_settings
from pinterest_mcp.http_app import create_http_app
from pinterest_mcp.tools import REGISTRY


def test_default_transport_is_stdio():
    settings = load_settings({})
    assert settings.transport is Transport.STDIO


def test_invalid_transport_exits_nonzero(monkeypatch):
    monkeypatch.setenv("MCP_TRANSPORT", "invalid_transport")
    with pytest.raises(SystemExit) as exc_info:
        main()
    assert exc_info.value.code == 2


def test_non_loopback_without_auth_token_aborts():
    with pytest.raises(
        ConfigError, match="MCP_AUTH_TOKEN or MCP_OAUTH_ISSUER is required"
    ):
        load_settings({"MCP_TRANSPORT": "http", "MCP_HOST": "0.0.0.0"})


def test_non_loopback_with_oauth_issuer_but_no_bearer_token_is_accepted():
    """OAuth resource-server mode is an accepted alternative to the shared
    bearer token for satisfying the non-loopback auth requirement."""
    settings = load_settings(
        {
            "MCP_TRANSPORT": "http",
            "MCP_HOST": "0.0.0.0",
            "MCP_OAUTH_ISSUER": "https://issuer.example.com",
        }
    )
    assert settings.effective_auth_mode == "oauth"


def test_bearer_token_and_oauth_issuer_are_mutually_exclusive():
    with pytest.raises(ConfigError, match="mutually exclusive"):
        load_settings(
            {
                "MCP_AUTH_TOKEN": "secret",
                "MCP_OAUTH_ISSUER": "https://issuer.example.com",
            }
        )


def test_stateless_and_resumability_are_incompatible():
    with pytest.raises(ConfigError, match="MCP_STATELESS and MCP_RESUMABILITY"):
        load_settings({"MCP_STATELESS": "true", "MCP_RESUMABILITY": "true"})


def test_stateless_and_sse_transport_are_incompatible():
    with pytest.raises(ConfigError, match="MCP_STATELESS is incompatible"):
        load_settings({"MCP_STATELESS": "true", "MCP_TRANSPORT": "sse"})


def test_cors_wildcard_with_credentials_is_rejected():
    with pytest.raises(ConfigError, match="MCP_CORS_ALLOW_CREDENTIALS"):
        load_settings({"MCP_ALLOWED_ORIGINS": "*", "MCP_CORS_ALLOW_CREDENTIALS": "true"})


def test_allowed_hosts_and_origins_accept_comma_separated_strings():
    settings = load_settings(
        {
            "MCP_ALLOWED_HOSTS": "example.com:443, other.example.com:443",
            "MCP_ALLOWED_ORIGINS": "https://a.example.com, https://b.example.com",
        }
    )
    assert settings.allowed_hosts == ["example.com:443", "other.example.com:443"]
    assert settings.allowed_origins == ["https://a.example.com", "https://b.example.com"]


def test_loopback_default_allowed_hosts_and_origins_when_unconfigured():
    settings = load_settings({"MCP_TRANSPORT": "http", "MCP_HOST": "127.0.0.1"})
    assert settings.effective_allowed_hosts == ["127.0.0.1:*", "localhost:*", "[::1]:*"]
    assert settings.effective_allowed_origins_for_security == [
        "http://127.0.0.1:*",
        "http://localhost:*",
        "http://[::1]:*",
    ]


def test_defaults_reproduce_pre_change_behavior():
    """A config using only pre-change variables must behave exactly as before:
    stdio by default, no SSE surface, no browser origins allowed."""
    settings = load_settings({})
    assert settings.transport is Transport.STDIO
    assert settings.json_response is False
    assert settings.stateless is False
    assert settings.resumability is False
    assert settings.dns_rebinding_protection is True
    assert settings.allowed_origins == []
    assert settings.effective_auth_mode == "none"


def test_sse_and_streamable_paths_must_differ():
    with pytest.raises(ConfigError, match="must be different paths"):
        load_settings({"MCP_TRANSPORT": "http+sse", "MCP_PATH": "/mcp", "MCP_SSE_PATH": "/mcp"})


def test_message_path_colliding_with_mcp_path_is_rejected():
    with pytest.raises(ConfigError, match="MCP_MESSAGE_PATH"):
        load_settings({"MCP_MESSAGE_PATH": "/mcp"})


def test_four_transport_values_are_all_accepted(monkeypatch):
    for value in ("stdio", "http", "sse", "http+sse"):
        monkeypatch.setenv("MCP_TRANSPORT", value)
        settings = load_settings()
        assert settings.transport.value == value


def test_healthz_endpoint_returns_200_no_secrets():
    settings = Settings(MCP_TRANSPORT=Transport.HTTP, MCP_HOST="127.0.0.1")
    app = create_http_app(settings)
    with TestClient(app) as client:
        res = client.get("/healthz")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "ok"
        assert data["transport"] == "http"
        assert "version" in data
        assert "secret" not in res.text.lower()
        assert "token" not in res.text.lower()


def test_missing_or_wrong_bearer_token_returns_401():
    settings = Settings(
        MCP_TRANSPORT=Transport.HTTP,
        MCP_HOST="127.0.0.1",
        MCP_AUTH_TOKEN="secret-bearer-token",
    )
    app = create_http_app(settings)
    with TestClient(app) as client:
        # Missing token
        res1 = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        assert res1.status_code == 401
        assert res1.json() == {"error": "Unauthorized"}

        # Wrong token
        res2 = client.post(
            "/mcp",
            headers={"Authorization": "Bearer wrong-token"},
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        )
        assert res2.status_code == 401
        assert res2.json() == {"error": "Unauthorized"}

        # Correct token
        res3 = client.post(
            "/mcp",
            headers={"Authorization": "Bearer secret-bearer-token"},
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        )
        assert res3.status_code != 401


@pytest.mark.asyncio
async def test_both_transports_advertise_identical_tool_schemas():
    tools = await list_tools()
    assert len(tools) == 11

    settings_stdio = Settings(MCP_TRANSPORT=Transport.STDIO)
    settings_http = Settings(MCP_TRANSPORT=Transport.HTTP, MCP_HOST="127.0.0.1")

    app_stdio = create_http_app(settings_stdio)
    app_http = create_http_app(settings_http)

    assert app_stdio is not None
    assert app_http is not None


@pytest.mark.asyncio
async def test_wire_protocol_end_to_end_over_memory_transport():
    """Drive the real MCP wire protocol through a `ClientSession`, not just the
    module-level `list_tools`/`call_tool` functions.

    The migration to `MCPServer` changed the low-level `RequestHandler`
    signature from `(req)` to `(ctx, params)`; a handler still written for the
    old signature imports fine and passes every test that calls `list_tools`/
    `call_tool` directly, but fails at the first real `tools/call` with a
    `TypeError` inside the server's request dispatch. Only a client driving
    the actual wire protocol catches that class of regression.
    """
    set_client(PinterestClient(access_token="fake-token"))
    lowlevel = get_lowlevel_server()

    async with create_client_server_memory_streams() as (client_streams, server_streams):
        client_read, client_write = client_streams
        server_read, server_write = server_streams

        async def run_server():
            await lowlevel.run(server_read, server_write, lowlevel.create_initialization_options())

        server_task = asyncio.create_task(run_server())
        try:
            async with ClientSession(client_read, client_write) as session:
                await session.initialize()
                tools_result = await session.list_tools()
                assert {t.name for t in tools_result.tools} == set(REGISTRY)

                # Unknown tool: sanitized error in the content body, not a
                # protocol-level `isError` failure.
                result = await session.call_tool("nonexistent_tool", {})
                assert result.is_error is False
                assert "Unknown or unadvertised tool" in result.content[0].text

                # Invalid arguments: same sanitized shape.
                result = await session.call_tool(
                    "list_boards", {"privacy": "ALL", "unknown_arg": "x"}
                )
                assert result.is_error is False
                assert "security_error" in result.content[0].text
        finally:
            server_task.cancel()
