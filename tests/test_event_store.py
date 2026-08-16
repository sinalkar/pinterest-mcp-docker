"""Tests for InMemoryEventStore stream resumability (Design D4, Tasks 6.1-6.5)."""

from __future__ import annotations

import pytest
from mcp_types import JSONRPCNotification

from pinterest_mcp.event_store import InMemoryEventStore


@pytest.mark.asyncio
async def test_store_and_replay_events_after_id():
    store = InMemoryEventStore(max_events_per_stream=10)

    stream_id = "stream-1"
    msg1 = JSONRPCNotification(
        jsonrpc="2.0", method="notifications/message", params={"text": "first"}
    )
    msg2 = JSONRPCNotification(
        jsonrpc="2.0", method="notifications/message", params={"text": "second"}
    )
    msg3 = JSONRPCNotification(
        jsonrpc="2.0", method="notifications/message", params={"text": "third"}
    )

    id1 = await store.store_event(stream_id, msg1)
    id2 = await store.store_event(stream_id, msg2)
    id3 = await store.store_event(stream_id, msg3)

    replayed = []

    async def callback(event_msg):
        replayed.append(event_msg)

    # Replaying after id1 should deliver id2 and id3
    res_stream = await store.replay_events_after(id1, callback)
    assert res_stream == stream_id
    assert len(replayed) == 2
    assert replayed[0].event_id == id2
    assert replayed[0].message == msg2
    assert replayed[1].event_id == id3
    assert replayed[1].message == msg3


@pytest.mark.asyncio
async def test_event_retention_is_bounded():
    store = InMemoryEventStore(max_events_per_stream=2)
    stream_id = "stream-bound"

    msg1 = JSONRPCNotification(jsonrpc="2.0", method="test", params={"idx": 1})
    msg2 = JSONRPCNotification(jsonrpc="2.0", method="test", params={"idx": 2})
    msg3 = JSONRPCNotification(jsonrpc="2.0", method="test", params={"idx": 3})

    id1 = await store.store_event(stream_id, msg1)
    id2 = await store.store_event(stream_id, msg2)
    id3 = await store.store_event(stream_id, msg3)

    # id1 should have been evicted because max_events_per_stream=2
    replayed = []

    async def callback(event_msg):
        replayed.append(event_msg)

    # Replaying after evicted id1 returns None without raising
    res = await store.replay_events_after(id1, callback)
    assert res is None
    assert len(replayed) == 0

    # Replaying after id2 delivers id3
    res2 = await store.replay_events_after(id2, callback)
    assert res2 == stream_id
    assert len(replayed) == 1
    assert replayed[0].event_id == id3


@pytest.mark.asyncio
async def test_unknown_event_id_returns_none_without_raising():
    store = InMemoryEventStore(max_events_per_stream=10)
    replayed = []

    async def callback(event_msg):
        replayed.append(event_msg)

    res = await store.replay_events_after("non-existent-uuid", callback)
    assert res is None
    assert len(replayed) == 0
