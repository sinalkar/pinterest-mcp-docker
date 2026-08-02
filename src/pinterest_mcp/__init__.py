"""Pinterest MCP server.

A hardened, containerized fork of https://github.com/clugtu/pinterest-mcp
by Carlos Lugtu. See NOTICE.md for attribution details.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version

SERVER_NAME = "pinterest-mcp"
DISTRIBUTION_NAME = "pinterest-mcp-docker"


def get_version() -> str:
    """The single source of truth for the version reported anywhere.

    MCP initialization, /healthz, and the outbound User-Agent all read this, so
    they agree by construction rather than by discipline.
    """
    try:
        return _pkg_version(DISTRIBUTION_NAME)
    except PackageNotFoundError:  # running from a source tree, not installed
        try:
            from ._version import __version__ as _v  # type: ignore[import-not-found]

            return str(_v)
        except ImportError:
            return "0.0.0+unknown"


__version__ = get_version()
USER_AGENT = f"{SERVER_NAME}/{__version__} (+https://github.com/sinalkar/pinterest-mcp-docker)"

__all__ = ["DISTRIBUTION_NAME", "SERVER_NAME", "USER_AGENT", "__version__", "get_version"]
