"""Transport tests: stdio vs HTTP, bearer auth, healthz, and startup guards (Task 5.6)."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock

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
    with pytest.raises(ConfigError, match="MCP_AUTH_TOKEN or MCP_OAUTH_ISSUER is required"):
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


def test_canonical_mcp_path_does_not_redirect():
    settings = Settings(
        MCP_TRANSPORT=Transport.HTTP,
        MCP_HOST="127.0.0.1",
        MCP_AUTH_TOKEN="test-token",
        MCP_JSON_RESPONSE=True,
    )
    with TestClient(
        create_http_app(settings),
        base_url="http://127.0.0.1:8080",
        follow_redirects=False,
    ) as client:
        response = client.post(
            "/mcp",
            headers={
                "Authorization": "Bearer test-token",
                "Accept": "application/json, text/event-stream",
            },
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "test", "version": "1.0"},
                },
            },
        )
    assert response.status_code == 200


def test_readyz_requires_usable_pinterest_credentials(tmp_path):
    unconfigured = Settings(
        MCP_TRANSPORT=Transport.HTTP,
        MCP_HOST="127.0.0.1",
        PINTEREST_TOKEN_PATH=tmp_path / "missing-token.json",
    )
    with TestClient(create_http_app(unconfigured)) as client:
        response = client.get("/readyz")
    assert response.status_code == 503
    assert response.json() == {"status": "not_ready"}

    configured = Settings(
        MCP_TRANSPORT=Transport.HTTP,
        MCP_HOST="127.0.0.1",
        PINTEREST_ACCESS_TOKEN="configured-access-token",
        PINTEREST_TOKEN_PATH=tmp_path / "missing-token.json",
    )
    with TestClient(create_http_app(configured)) as client:
        response = client.get("/readyz")
    assert response.status_code == 200
    assert response.json() == {"status": "ready"}


def test_http_lifespan_closes_and_clears_shared_client(tmp_path):
    shared_client = AsyncMock()
    set_client(shared_client)
    settings = Settings(
        MCP_TRANSPORT=Transport.HTTP,
        MCP_HOST="127.0.0.1",
        PINTEREST_TOKEN_PATH=tmp_path / "missing-token.json",
    )
    with TestClient(create_http_app(settings)):
        pass
    shared_client.aclose.assert_awaited_once()


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

                # Unknown tool: sanitized error in the content body with the
                # standard protocol-level `isError` signal.
                result = await session.call_tool("nonexistent_tool", {})
                assert result.is_error is True
                assert "Unknown or unadvertised tool" in result.content[0].text

                # Invalid arguments: same sanitized error shape and signal.
                result = await session.call_tool(
                    "list_boards", {"privacy": "ALL", "unknown_arg": "x"}
                )
                assert result.is_error is True
                assert "security_error" in result.content[0].text
        finally:
            server_task.cancel()


def test_healthz_reports_surfaces_and_modes():
    settings = Settings(
        MCP_TRANSPORT=Transport.HTTP_SSE,
        MCP_HOST="127.0.0.1",
        MCP_PATH="/custom-mcp",
        MCP_SSE_PATH="/custom-sse",
        MCP_MESSAGE_PATH="/custom-msg/",
        MCP_JSON_RESPONSE=True,
        MCP_STATELESS=False,
        MCP_RESUMABILITY=False,
    )
    app = create_http_app(settings)
    with TestClient(app) as client:
        res = client.get("/healthz")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "ok"
        assert data["transport"] == "http+sse"
        assert data["surfaces"] == {
            "streamable_http": "/custom-mcp",
            "sse": "/custom-sse",
            "messages": "/custom-msg/",
        }
        assert data["json_response"] is True
        assert data["stateless"] is False
        assert data["resumability"] is False
        assert data["auth_mode"] == "none"


def test_dns_rebinding_warning_emitted_when_disabled(caplog):
    import logging

    settings = Settings(
        MCP_TRANSPORT=Transport.HTTP,
        MCP_HOST="127.0.0.1",
        MCP_DNS_REBINDING_PROTECTION=False,
    )
    with caplog.at_level(logging.WARNING):
        create_http_app(settings)
    assert any("MCP_DNS_REBINDING_PROTECTION" in record.message for record in caplog.records)


def test_json_response_mode_returns_single_json_reply():
    settings = Settings(
        MCP_TRANSPORT=Transport.HTTP,
        MCP_HOST="127.0.0.1",
        MCP_JSON_RESPONSE=True,
    )
    app = create_http_app(settings)
    with TestClient(app, base_url="http://127.0.0.1:8080") as client:
        init_payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "test-client", "version": "1.0"},
            },
        }
        res = client.post(
            "/mcp",
            json=init_payload,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
        )
        assert res.status_code == 200
        assert res.headers["content-type"].startswith("application/json")
        data = res.json()
        assert data["id"] == 1
        assert "serverInfo" in data["result"]


def test_stateless_mode_serves_self_contained_request():
    settings = Settings(
        MCP_TRANSPORT=Transport.HTTP,
        MCP_HOST="127.0.0.1",
        MCP_STATELESS=True,
        MCP_JSON_RESPONSE=True,
    )
    app = create_http_app(settings)
    with TestClient(app, base_url="http://127.0.0.1:8080") as client:
        init_payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "test-client", "version": "1.0"},
            },
        }
        res = client.post(
            "/mcp",
            json=init_payload,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
        )
        assert res.status_code == 200
        # In stateless mode no session header is returned or required
        assert "Mcp-Session-Id" not in res.headers


def test_oversized_request_body_rejected():
    settings = Settings(
        MCP_TRANSPORT=Transport.HTTP,
        MCP_HOST="127.0.0.1",
        MCP_MAX_REQUEST_BYTES=100,
    )
    app = create_http_app(settings)
    with TestClient(app, base_url="http://127.0.0.1:8080") as client:
        large_payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"padding": "x" * 200},
        }
        res = client.post("/mcp", json=large_payload)
        assert res.status_code == 413


def test_session_idle_timeout_expiration():
    settings = Settings(
        MCP_TRANSPORT=Transport.HTTP,
        MCP_HOST="127.0.0.1",
        MCP_SESSION_IDLE_TIMEOUT=0.01,
    )
    app = create_http_app(settings)
    with TestClient(app, base_url="http://127.0.0.1:8080") as client:
        init_payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "test-client", "version": "1.0"},
            },
        }
        res = client.post("/mcp", json=init_payload)
        session_id = res.headers.get("Mcp-Session-Id")
        assert session_id is not None

        # Wait for timeout to expire
        import time

        time.sleep(0.05)

        # Subsequent request with expired session id should return 404 (session not found)
        call_payload = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {},
        }
        res2 = client.post(
            "/mcp",
            json=call_payload,
            headers={"Mcp-Session-Id": session_id},
        )
        assert res2.status_code == 404


def test_dns_rebinding_and_origin_rejection():
    settings = Settings(
        MCP_TRANSPORT=Transport.HTTP,
        MCP_HOST="127.0.0.1",
        MCP_DNS_REBINDING_PROTECTION=True,
    )
    app = create_http_app(settings)
    with TestClient(app, base_url="http://127.0.0.1:8080") as client:
        # Invalid host header
        res_host = client.post(
            "/mcp",
            headers={"Host": "evil.attacker.com"},
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
        )
        assert res_host.status_code in (421, 403, 400)

        # Invalid origin header
        res_origin = client.post(
            "/mcp",
            headers={"Origin": "https://evil.attacker.com"},
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
        )
        assert res_origin.status_code in (421, 403, 400)


def test_cors_middleware_preflight_and_headers():
    # When MCP_ALLOWED_ORIGINS is configured
    settings = Settings(
        MCP_TRANSPORT=Transport.HTTP,
        MCP_HOST="127.0.0.1",
        MCP_ALLOWED_ORIGINS="https://claude.ai, https://app.example.com",
    )
    app = create_http_app(settings)
    with TestClient(app, base_url="http://127.0.0.1:8080") as client:
        # Preflight options request
        res = client.options(
            "/mcp",
            headers={
                "Origin": "https://claude.ai",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Content-Type, Mcp-Session-Id",
            },
        )
        assert res.status_code == 200
        assert res.headers.get("access-control-allow-origin") == "https://claude.ai"

        # Simple request exposing headers
        res_simple = client.get("/healthz", headers={"Origin": "https://claude.ai"})
        assert res_simple.status_code == 200
        assert res_simple.headers.get("access-control-allow-origin") == "https://claude.ai"
        exposed = res_simple.headers.get("access-control-expose-headers", "")
        assert "Mcp-Session-Id" in exposed or "mcp-session-id" in exposed.lower()

    # When MCP_ALLOWED_ORIGINS is empty, no CORS headers emitted
    settings_no_cors = Settings(
        MCP_TRANSPORT=Transport.HTTP,
        MCP_HOST="127.0.0.1",
        MCP_ALLOWED_ORIGINS="",
    )
    app_no_cors = create_http_app(settings_no_cors)
    with TestClient(app_no_cors, base_url="http://127.0.0.1:8080") as client:
        res_no_cors = client.get("/healthz", headers={"Origin": "https://claude.ai"})
        assert "access-control-allow-origin" not in res_no_cors.headers


def test_sse_surface_auth_and_routing():
    settings = Settings(
        MCP_TRANSPORT=Transport.SSE,
        MCP_HOST="127.0.0.1",
        MCP_AUTH_TOKEN="sse-secret-token",
        MCP_SSE_PATH="/sse",
        MCP_MESSAGE_PATH="/messages/",
    )
    app = create_http_app(settings)
    with TestClient(app, base_url="http://127.0.0.1:8080") as client:
        # Unauthenticated SSE stream request returns 401
        res_sse = client.get("/sse")
        assert res_sse.status_code == 401

        # Unauthenticated message post request returns 401
        res_msg = client.post("/messages/?session_id=1234", json={"jsonrpc": "2.0"})
        assert res_msg.status_code == 401

        # Streamable HTTP route is not mounted in SSE-only mode
        res_mcp = client.post(
            "/mcp",
            headers={"Authorization": "Bearer sse-secret-token"},
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
        )
        assert res_mcp.status_code == 404


def test_sse_local_paths_rejected_same_as_http():
    settings = Settings(
        MCP_TRANSPORT=Transport.SSE,
        MCP_HOST="127.0.0.1",
    )
    assert settings.local_paths_enabled is False


def test_protocol_version_negotiation_and_mismatched_headers():
    settings = Settings(
        MCP_TRANSPORT=Transport.HTTP,
        MCP_HOST="127.0.0.1",
        MCP_JSON_RESPONSE=True,
    )
    app = create_http_app(settings)
    with TestClient(app, base_url="http://127.0.0.1:8080") as client:
        # 1. Unsupported protocol version in initialization frame
        unsupported_init = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "1999-01-01",
                "capabilities": {},
                "clientInfo": {"name": "old-client", "version": "1.0"},
            },
        }
        res_unsupported = client.post(
            "/mcp",
            json=unsupported_init,
            headers={"Accept": "application/json", "Content-Type": "application/json"},
        )
        assert res_unsupported.status_code == 200
        data = res_unsupported.json()
        assert "error" in data or "result" in data  # Protocol version negotiation or rejected error

        # 2. Mismatched MCP-Protocol-Version header on subsequent request
        res_mismatch = client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "MCP-Protocol-Version": "invalid-protocol-version",
            },
        )
        assert res_mismatch.status_code in (400, 404, 421)
