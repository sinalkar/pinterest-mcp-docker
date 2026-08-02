"""Dispatch tests for ToolSpec registry, input validation, and error sanitization (Task 4.6)."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest

from pinterest_mcp.app import call_tool, list_tools, set_client
from pinterest_mcp.client import PinterestClient


@pytest.fixture
def mock_client() -> PinterestClient:
    c = PinterestClient(access_token="fake-token")
    c._token_expiry = float("inf")
    set_client(c)
    return c


@pytest.mark.asyncio
async def test_list_tools_count_and_schema():
    tools = await list_tools()
    assert len(tools) == 11
    names = {t.name for t in tools}
    assert "create_pin" in names
    assert "dry_run_pin" not in names  # dead branch removed


@pytest.mark.asyncio
async def test_unknown_tool_refused(mock_client: PinterestClient):
    with patch.object(mock_client, "_request") as mock_req:
        res = await call_tool("unadvertised_tool", {})
        assert not mock_req.called
        data = json.loads(res[0].text)
        assert data["category"] == "security_error"
        assert "Unknown or unadvertised tool" in data["message"]


@pytest.mark.asyncio
async def test_unknown_argument_rejected(mock_client: PinterestClient):
    with patch.object(mock_client, "_request") as mock_req:
        res = await call_tool(
            "list_boards",
            {"privacy": "ALL", "unknown_arg": "invalid"},
        )
        assert not mock_req.called
        data = json.loads(res[0].text)
        assert data["category"] == "security_error"
        assert "Invalid arguments" in data["message"]


@pytest.mark.asyncio
async def test_credential_shaped_argument_rejected_without_leaking(mock_client: PinterestClient):
    with patch.object(mock_client, "_request") as mock_req:
        secret_arg = "pina_secret12345678901234567890"
        res = await call_tool(
            "list_boards",
            {"PINTEREST_ACCESS_TOKEN": secret_arg},
        )
        assert not mock_req.called
        text = res[0].text
        assert secret_arg not in text
        data = json.loads(text)
        assert data["category"] == "security_error"


@pytest.mark.asyncio
async def test_missing_required_board_id(mock_client: PinterestClient):
    with patch.object(mock_client, "_request") as mock_req:
        res = await call_tool(
            "create_pin",
            {"title": "Title", "description": "Desc", "image_url": "https://example.com/a.png"},
        )
        assert not mock_req.called
        data = json.loads(res[0].text)
        assert data["category"] == "security_error"


@pytest.mark.asyncio
async def test_invalid_date_format_rejected(mock_client: PinterestClient):
    with patch.object(mock_client, "_request") as mock_req:
        res = await call_tool(
            "get_pin_analytics",
            {"pin_id": "pin1", "start_date": "08/02/2026", "end_date": "2026-08-02"},
        )
        assert not mock_req.called
        data = json.loads(res[0].text)
        assert data["category"] == "security_error"


@pytest.mark.asyncio
async def test_oversized_bulk_batch_rejected(mock_client: PinterestClient):
    with patch.object(mock_client, "_request") as mock_req:
        too_many_pins = [
            {"title": f"Pin {i}", "image_url": "https://example.com/i.png"} for i in range(51)
        ]
        res = await call_tool("bulk_create_pins", {"board_id": "b1", "pins": too_many_pins})
        assert not mock_req.called
        data = json.loads(res[0].text)
        assert data["category"] == "security_error"


@pytest.mark.asyncio
async def test_upstream_4xx_error_never_echoes_raw_body(mock_client: PinterestClient):
    import httpx

    with patch.object(mock_client._http, "request", new_callable=AsyncMock) as mock_http:
        # Mock 400 response with raw secret error body from upstream
        req = httpx.Request("GET", "https://api.pinterest.com/v5/boards")
        raw_upstream_body = json.dumps({"error": "Invalid token pina_secret_raw_upstream_12345"})
        resp = httpx.Response(400, content=raw_upstream_body.encode(), request=req)
        mock_http.return_value = resp

        res = await call_tool("list_boards", {})
        text = res[0].text
        assert "pina_secret_raw_upstream_12345" not in text
        data = json.loads(text)
        assert data["category"] == "error"
