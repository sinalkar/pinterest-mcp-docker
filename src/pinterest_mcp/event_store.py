"""In-memory event store for Streamable HTTP stream resumability (Design D4)."""

from __future__ import annotations

import collections
import uuid
from collections.abc import Awaitable, Callable

from mcp.server.streamable_http import EventId, EventMessage, EventStore, StreamId
from mcp_types import JSONRPCMessage

EventCallback = Callable[[EventMessage], Awaitable[None]]


class InMemoryEventStore(EventStore):
    """In-memory event store bounded per stream with UUID4 event IDs."""

    def __init__(self, max_events_per_stream: int = 1000) -> None:
        self.max_events_per_stream = max_events_per_stream
        self._streams: dict[StreamId, collections.deque[tuple[EventId, JSONRPCMessage | None]]] = {}
        self._event_to_stream: dict[EventId, StreamId] = {}

    async def store_event(self, stream_id: StreamId, message: JSONRPCMessage | None) -> EventId:
        event_id = str(uuid.uuid4())
        if stream_id not in self._streams:
            self._streams[stream_id] = collections.deque(maxlen=self.max_events_per_stream)

        deque = self._streams[stream_id]
        if len(deque) == deque.maxlen:
            oldest_event_id, _ = deque[0]
            self._event_to_stream.pop(oldest_event_id, None)

        deque.append((event_id, message))
        self._event_to_stream[event_id] = stream_id
        return event_id

    async def replay_events_after(
        self,
        last_event_id: EventId,
        send_callback: EventCallback,
    ) -> StreamId | None:
        stream_id = self._event_to_stream.get(last_event_id)
        if stream_id is None or stream_id not in self._streams:
            return None

        deque = self._streams[stream_id]
        found = False
        events_to_replay = []
        for eid, msg in deque:
            if found:
                events_to_replay.append((eid, msg))
            elif eid == last_event_id:
                found = True

        if not found:
            return None

        for eid, msg in events_to_replay:
            if msg is not None:
                await send_callback(EventMessage(message=msg, event_id=eid))

        return stream_id
