"""respx-based tests for PinterestClient and security fetchers (Task 3.8)."""

from __future__ import annotations

import asyncio
import os
import stat
import time
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx

from pinterest_mcp.client import PinterestClient
from pinterest_mcp.config import Settings
from pinterest_mcp.security import SecurityError, fetch_public_image_url


@pytest.mark.asyncio
async def test_direct_access_token_is_usable_without_expiry(tmp_path: Path):
    client = PinterestClient(
        access_token="direct-token",
        refresh_token="refresh-token",
        settings=Settings(PINTEREST_TOKEN_PATH=tmp_path / "token.json"),
    )
    try:
        assert await client._ensure_token() == "direct-token"
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_concurrent_token_refresh_happens_once(tmp_path: Path):
    client = PinterestClient(
        refresh_token="refresh-token",
        settings=Settings(PINTEREST_TOKEN_PATH=tmp_path / "token.json"),
    )
    try:
        with respx.mock(assert_all_called=True) as respx_mock:
            refresh = respx_mock.post("https://api.pinterest.com/v5/oauth/token").respond(
                json={"access_token": "new-token", "expires_in": 3600}
            )
            tokens = await asyncio.gather(*[client._ensure_token() for _ in range(5)])

        assert tokens == ["new-token"] * 5
        assert refresh.call_count == 1
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_cross_origin_redirect_drops_auth_header():
    with patch("pinterest_mcp.security.socket.getaddrinfo") as mock_gai:
        mock_gai.side_effect = lambda host, port, *args, **kwargs: [
            (2, 1, 6, "", ("93.184.216.34", port))
        ]

        with respx.mock(assert_all_called=False) as respx_mock:
            respx_mock.get("https://example.com/image.jpg").respond(
                status_code=302,
                headers={"Location": "https://otherdomain.com/image.jpg"},
            )
            route_other = respx_mock.get("https://otherdomain.com/image.jpg").respond(
                status_code=200,
                content=b"\x89PNG\r\n\x1a\n" + b"\x00" * 20,
            )

            _content, mime = await fetch_public_image_url(
                "https://example.com/image.jpg", user_agent="test"
            )
            assert mime == "image/png"

            assert route_other.called
            last_req = route_other.calls.last.request
            assert "authorization" not in last_req.headers
            assert "Authorization" not in last_req.headers


@pytest.mark.asyncio
async def test_hung_upstream_trips_timeout(tmp_path: Path):
    settings = Settings(
        PINTEREST_HTTP_TIMEOUT=0.1,
        PINTEREST_TOKEN_PATH=tmp_path / "token.json",
    )
    client = PinterestClient(access_token="fake-token", settings=settings)
    client._token_expiry = float("inf")

    with respx.mock as respx_mock:
        respx_mock.get("https://api.pinterest.com/v5/boards").mock(
            side_effect=httpx.ReadTimeout("Read timed out")
        )

        with pytest.raises((httpx.TimeoutException, httpx.ReadTimeout)):
            await client.list_boards()


@pytest.mark.asyncio
async def test_oversized_response_aborts(tmp_path: Path):
    with patch("pinterest_mcp.security.socket.getaddrinfo") as mock_gai:
        mock_gai.side_effect = lambda host, port, *args, **kwargs: [
            (2, 1, 6, "", ("93.184.216.34", port))
        ]

        with respx.mock as respx_mock:
            respx_mock.get("https://example.com/huge.png").respond(
                status_code=200,
                content=b"\x89PNG\r\n\x1a\n" + b"\x00" * 200,
            )

            with pytest.raises(SecurityError, match="exceeds limit"):
                await fetch_public_image_url(
                    "https://example.com/huge.png", user_agent="test", max_bytes=50
                )


@pytest.mark.asyncio
async def test_pin_rate_limiter_shared_between_single_and_bulk(tmp_path: Path):
    client = PinterestClient(
        access_token="fake-token",
        settings=Settings(PINTEREST_TOKEN_PATH=tmp_path / "token.json"),
    )
    client._token_expiry = float("inf")

    with (
        patch("pinterest_mcp.security.socket.getaddrinfo") as mock_gai,
        patch.object(client, "_request", return_value={"id": "pin_mock"}),
        patch.object(client, "create_pin", wraps=client.create_pin),
    ):
        mock_gai.side_effect = lambda host, port, *args, **kwargs: [
            (2, 1, 6, "", ("93.184.216.34", port))
        ]
        now = time.time()
        client._pin_timestamps = [now] * 9

        # Single create_pin -> 10th pin (dry_run)
        await client.create_pin(
            board_id="b1",
            title="p1",
            description="d",
            image_url="https://example.com/1.png",
            dry_run=True,
        )
        assert len(client._pin_timestamps) == 9

        # Real create_pin -> 10th pin
        await client.create_pin(
            board_id="b1",
            title="p1",
            description="d",
            image_url="https://example.com/1.png",
        )
        assert len(client._pin_timestamps) == 10

        # Next bulk create pin should trigger sleep/rate limiting logic
        with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
            await client.bulk_create_pins(
                board_id="b1",
                pins=[
                    {
                        "title": "b1",
                        "description": "d",
                        "image_url": "https://example.com/2.png",
                    }
                ],
            )
            assert mock_sleep.called


def test_token_file_permissions(tmp_path: Path):
    token_file = tmp_path / "subdir" / "token.json"
    settings = Settings(PINTEREST_TOKEN_PATH=token_file)

    client = PinterestClient(access_token="test_token", settings=settings)
    client._save_token_file()

    assert token_file.exists()
    assert token_file.parent.exists()

    parent_mode = stat.S_IMODE(os.stat(token_file.parent).st_mode)
    file_mode = stat.S_IMODE(os.stat(token_file).st_mode)

    assert parent_mode == 0o700
    assert file_mode == 0o600
