"""CLI entry point for starting the MCP server in stdio or http mode (Tasks 5.4 & 5.5)."""

from __future__ import annotations

import os
import sys

from .config import TRANSPORT_VALUES, Transport, load_settings_or_exit
from .logging_setup import configure_logging
from .stdio_main import main as stdio_main


def main() -> None:
    raw_transport = os.environ.get("MCP_TRANSPORT", "stdio").lower()
    if raw_transport not in TRANSPORT_VALUES:
        accepted = ", ".join(repr(v) for v in TRANSPORT_VALUES)
        print(
            f"Error: Invalid MCP_TRANSPORT value {raw_transport!r}. "
            f"Accepted values are: {accepted}.",
            file=sys.stderr,
        )
        sys.exit(2)

    settings = load_settings_or_exit()
    # Configure stderr-only, redacted logging before either transport starts.
    configure_logging(settings.log_level, settings.log_format)

    if settings.transport is Transport.STDIO:
        stdio_main()
    elif settings.is_http:
        try:
            import uvicorn
        except ImportError:
            print(
                "Error: HTTP transport dependencies not installed. "
                "Install with `pip install pinterest-mcp-docker[http]`.",
                file=sys.stderr,
            )
            sys.exit(1)

        from .http_app import create_http_app

        http_app = create_http_app(settings)
        uvicorn.run(
            http_app,
            host=settings.host,
            port=settings.port,
            log_level=settings.log_level.lower(),
            log_config=None,
        )


if __name__ == "__main__":
    main()
