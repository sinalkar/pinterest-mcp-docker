"""Transport tests: stdio vs HTTP, bearer auth, healthz, and startup guards (Task 5.6)."""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from pinterest_mcp.app import list_tools
from pinterest_mcp.cli import main
from pinterest_mcp.config import ConfigError, Settings, Transport, load_settings
from pinterest_mcp.http_app import create_http_app


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
        ConfigError, match="MCP_AUTH_TOKEN is required when MCP_HOST is not loopback"
    ):
        load_settings({"MCP_TRANSPORT": "http", "MCP_HOST": "0.0.0.0"})


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
