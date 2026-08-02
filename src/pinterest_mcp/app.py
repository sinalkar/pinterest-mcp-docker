"""Transport-agnostic MCP server application and dispatch logic (Tasks 4.1-4.5 & Task 5.1)."""

from __future__ import annotations

import json
import logging
from typing import Any

from mcp import types
from mcp.server import Server
from pydantic import ValidationError

from .client import PinterestClient
from .security import SecurityError, sanitize_error
from .tools import REGISTRY

logger = logging.getLogger(__name__)

mcp_app = Server("pinterest-mcp")
_client: PinterestClient | None = None


def get_client() -> PinterestClient:
    global _client
    if _client is None:
        _client = PinterestClient()
    return _client


def set_client(client: PinterestClient | None) -> None:
    global _client
    _client = client


async def list_tools() -> list[types.Tool]:
    """Expose tools derived directly from the ToolSpec registry."""
    return [
        types.Tool(
            name=spec.name,
            description=spec.description,
            inputSchema=spec.input_schema,
        )
        for spec in REGISTRY.values()
    ]


async def call_tool(name: str, arguments: dict[str, Any]) -> list[types.TextContent]:
    """Validated dispatch through Pydantic models with error sanitization."""
    spec = REGISTRY.get(name)
    if spec is None:
        err = SecurityError(f"Unknown or unadvertised tool: {name!r}")
        sanitized = sanitize_error(err)
        return [types.TextContent(type="text", text=json.dumps(sanitized))]

    try:
        parsed_args = spec.model(**arguments)
    except ValidationError:
        msg = f"Invalid arguments for tool {name!r}"
        sanitized = sanitize_error(SecurityError(msg))
        return [types.TextContent(type="text", text=json.dumps(sanitized))]

    client = get_client()
    try:
        result = await spec.handler(client, parsed_args)
    except Exception as exc:
        logger.error("Error executing tool %s: %s", name, exc, exc_info=True)
        sanitized = sanitize_error(exc)
        return [types.TextContent(type="text", text=json.dumps(sanitized))]

    return [types.TextContent(type="text", text=json.dumps(result, indent=2, default=str))]


async def _handle_list_tools(req: types.ListToolsRequest) -> types.ListToolsResult:
    tools_list = await list_tools()
    return types.ListToolsResult(tools=tools_list)


async def _handle_call_tool(req: types.CallToolRequest) -> types.CallToolResult:
    content = await call_tool(req.params.name, req.params.arguments or {})
    return types.CallToolResult(content=content)


mcp_app.add_request_handler("tools/list", types.ListToolsRequest, _handle_list_tools)
mcp_app.add_request_handler("tools/call", types.CallToolRequest, _handle_call_tool)
