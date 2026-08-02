"""Pinterest MCP server entry point."""

from __future__ import annotations

from .cli import main
from .stdio_main import run_stdio_server

__all__ = ["main", "run_stdio_server"]

if __name__ == "__main__":
    main()
