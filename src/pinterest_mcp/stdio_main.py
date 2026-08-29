"""Stdio transport entry point (Task 5.1)."""

from __future__ import annotations

import asyncio
import contextlib
import signal
import sys

from .app import close_client, mcp_app


async def run_stdio_server() -> None:
    """Run the MCP server over standard input/output (stdio)."""
    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()

    def handle_signal():
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError, RuntimeError):
            loop.add_signal_handler(sig, handle_signal)

    server_task = asyncio.create_task(mcp_app.run_stdio_async())
    stop_task = asyncio.create_task(stop_event.wait())

    try:
        _done, pending = await asyncio.wait(
            [server_task, stop_task],
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
    finally:
        await close_client()


def main() -> None:
    try:
        asyncio.run(run_stdio_server())
    except KeyboardInterrupt:
        sys.exit(0)
