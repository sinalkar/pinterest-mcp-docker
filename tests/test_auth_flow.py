"""Focused tests for the local Pinterest OAuth callback listener."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from pinterest_mcp import auth


@pytest.mark.asyncio
async def test_callback_requires_matching_state() -> None:
    code_future: asyncio.Future[str] = asyncio.get_running_loop().create_future()
    wrong_status, _ = auth._process_callback_request(
        b"GET /callback?code=secret-code&state=wrong-state HTTP/1.1\r\n",
        "expected-state",
        code_future,
    )
    assert wrong_status == 400
    assert not code_future.done()

    ok_status, _ = auth._process_callback_request(
        b"GET /callback?code=authorization-code&state=expected-state HTTP/1.1\r\n",
        "expected-state",
        code_future,
    )
    assert ok_status == 200
    assert await code_future == "authorization-code"


@pytest.mark.asyncio
async def test_callback_listener_times_out_and_closes(monkeypatch: pytest.MonkeyPatch) -> None:
    server = MagicMock()
    server.wait_closed = AsyncMock()
    monkeypatch.setattr(auth.asyncio, "start_server", AsyncMock(return_value=server))
    with pytest.raises(RuntimeError, match="Timed out waiting for OAuth callback"):
        await auth._run_local_server("state", timeout=0.01)
    server.close.assert_called_once()
    server.wait_closed.assert_awaited_once()
