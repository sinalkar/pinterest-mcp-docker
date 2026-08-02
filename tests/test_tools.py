"""Tests for pinterest-mcp tools.

All HTTP calls are mocked — no real Pinterest traffic.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pinterest_mcp.client import PinterestClient


@pytest.fixture(autouse=True)
def mock_dns():
    with patch("socket.getaddrinfo") as mock_gai:
        mock_gai.side_effect = lambda host, port, *args, **kwargs: [
            (2, 1, 6, "", ("93.184.216.34", port))
        ]
        yield mock_gai


@pytest.fixture
def client() -> PinterestClient:
    c = PinterestClient(access_token="fake-token")
    c._token_expiry = float("inf")  # never expires in tests
    return c


def _mock_resp(data: dict) -> MagicMock:
    m = MagicMock()
    m.status_code = 200
    m.raise_for_status = MagicMock()
    m.json = MagicMock(return_value=data)
    return m


# ---------------------------------------------------------------------------
# create_pin
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_pin(client: PinterestClient):
    resp_data = {
        "id": "pin_001",
        "title": "Dragon Miniature",
        "link": "https://cults3d.com/en/3d-model/dragon",
    }
    with patch.object(
        client._http, "request", new_callable=AsyncMock, return_value=_mock_resp(resp_data)
    ):
        result = await client.create_pin(
            board_id="board_123",
            title="Dragon Miniature",
            description="A fierce D\u0026D dragon for 3D printing",
            image_url="https://example.com/dragon.jpg",
            link="https://cults3d.com/en/3d-model/dragon",
        )
    assert result["id"] == "pin_001"
    assert result["title"] == "Dragon Miniature"


# ---------------------------------------------------------------------------
# list_boards
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_boards(client: PinterestClient):
    resp_data = {
        "items": [
            {"id": "b1", "name": "DnD Miniatures", "pin_count": 42},
            {"id": "b2", "name": "Warhammer", "pin_count": 18},
        ]
    }
    with patch.object(
        client._http, "request", new_callable=AsyncMock, return_value=_mock_resp(resp_data)
    ):
        boards = await client.list_boards()
    assert len(boards) == 2
    assert boards[0]["name"] == "DnD Miniatures"


# ---------------------------------------------------------------------------
# search_pins
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_search_pins(client: PinterestClient):
    resp_data = {
        "items": [
            {"id": "p1", "title": "Resin Dragon Print"},
            {"id": "p2", "title": "FDM Dragon"},
        ]
    }
    with patch.object(
        client._http, "request", new_callable=AsyncMock, return_value=_mock_resp(resp_data)
    ):
        results = await client.search_pins("dragon miniature")
    assert len(results) == 2
    assert results[0]["title"] == "Resin Dragon Print"


# ---------------------------------------------------------------------------
# get_pin_analytics
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_pin_analytics(client: PinterestClient):
    resp_data = {
        "all": {
            "daily_metrics": [],
            "summary_metrics": {"IMPRESSION": 1250, "SAVE": 34, "OUTBOUND_CLICK": 8},
        }
    }
    with patch.object(
        client._http, "request", new_callable=AsyncMock, return_value=_mock_resp(resp_data)
    ):
        analytics = await client.get_pin_analytics(
            pin_id="pin_001", start_date="2026-02-01", end_date="2026-03-01"
        )
    assert analytics["all"]["summary_metrics"]["IMPRESSION"] == 1250


# ---------------------------------------------------------------------------
# bulk_create_pins respects rate limit
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_bulk_create_pins_calls_create_for_each(client: PinterestClient):
    pins = [
        {"title": f"Pin {i}", "description": "desc", "image_url": f"https://img.com/{i}.jpg"}
        for i in range(3)
    ]
    resp_data = {"id": "pin_x"}
    with patch.object(
        client._http, "request", new_callable=AsyncMock, return_value=_mock_resp(resp_data)
    ):
        results = await client.bulk_create_pins(board_id="b1", pins=pins)
    assert len(results) == 3
