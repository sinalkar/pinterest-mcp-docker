"""Transport-agnostic MCP server application and dispatch logic (Tasks 4.1-4.5 & Task 5.1)."""

from __future__ import annotations

import inspect
import json
import logging
from typing import Annotated, Any

from mcp import types
from mcp.server.lowlevel.server import Server
from mcp.server.mcpserver import MCPServer
from pydantic import ValidationError

from . import __version__
from .client import PinterestClient
from .security import SecurityError, sanitize_error
from .tools import REGISTRY, ToolSpec

logger = logging.getLogger(__name__)

mcp_app = MCPServer(name="pinterest-mcp", version=__version__)
_client: PinterestClient | None = None


def get_lowlevel_server() -> Server:
    """The single accessor for the SDK's low-level `Server`.

    `MCPServer` composes but does not fully expose the low-level server, and
    the streamable-HTTP session manager and SSE transport both need it
    directly. Every other module reaches it through this function rather than
    touching the private attribute itself, so an SDK upgrade that removes or
    renames the attribute fails here instead of at an arbitrary call site.
    """
    return mcp_app._lowlevel_server


def get_client() -> PinterestClient:
    global _client
    if _client is None:
        _client = PinterestClient()
    return _client


def set_client(client: PinterestClient | None) -> None:
    global _client
    _client = client


async def close_client() -> None:
    """Close and forget the process-wide Pinterest client, if it exists.

    A server instance can be started and stopped more than once in a test
    process (and application lifespan shutdown is expected to be restartable).
    Clearing the reference before awaiting close prevents a later startup from
    reusing a closed ``httpx.AsyncClient``.
    """
    global _client
    client, _client = _client, None
    if client is not None:
        await client.aclose()


def _placeholder_tool_fn(spec: ToolSpec) -> Any:
    """Build a flattened-signature callable so `MCPServer.add_tool` can derive
    a real advertised schema from the tool's Pydantic model.

    The model (not this function) is the source of truth: schema, defaults,
    lengths, and descriptions all come from `spec.model.model_fields` via
    `Annotated[type, FieldInfo]`, so the two can never drift apart. The
    function body is never on the call path — `call_tool` below is what
    actually executes a tool call on every transport — but it has to be
    real and correctly annotated because the SDK derives the schema from it.
    """

    async def _run(**kwargs: Any) -> Any:  # pragma: no cover - not on the call path
        content = await call_tool(spec.name, kwargs)
        return json.loads(content[0].text)

    parameters = [
        inspect.Parameter(
            field_name,
            inspect.Parameter.KEYWORD_ONLY,
            default=inspect.Parameter.empty if field.is_required() else field.default,
            annotation=Annotated[field.annotation, field],
        )
        for field_name, field in spec.model.model_fields.items()
    ]
    _run.__signature__ = inspect.Signature(parameters)  # type: ignore[attr-defined]
    _run.__name__ = spec.name
    return _run


for _spec in REGISTRY.values():
    mcp_app.add_tool(
        _placeholder_tool_fn(_spec),
        name=_spec.name,
        description=_spec.description,
        annotations=types.ToolAnnotations(
            read_only_hint=_spec.read_only,
            destructive_hint=_spec.destructive,
            idempotent_hint=_spec.idempotent,
            open_world_hint=_spec.open_world,
        ),
        structured_output=False,
    )
del _spec


async def list_tools() -> list[types.Tool]:
    """Expose tools as advertised by the `MCPServer` tool manager.

    The schema for each tool is derived from its Pydantic model rather than
    hand-written, so it carries real field constraints (lengths, enums) that
    the previous hand-written schemas omitted. One consequence: a cross-field
    constraint such as "exactly one of image_url or image_path" cannot be
    expressed in a per-field JSON Schema and no longer appears in the
    advertised schema, though it is still enforced at call time by the
    model's validator (see `CreatePinInput._check_image_source`).
    """
    return await mcp_app.list_tools()


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


async def _handle_call_tool(ctx: Any, params: types.CallToolRequestParams) -> types.CallToolResult:
    """Override the SDK's default `tools/call` dispatch.

    `MCPServer`'s own dispatch runs each registered tool's flattened wrapper
    function through per-field argument validation and, on any failure,
    raises `ToolError` — which the SDK turns into `CallToolResult(isError=True,
    content=[...])` carrying the raw exception message. That both changes the
    wire shape (`isError` was never set before this migration) and risks an
    unsanitized message reaching the client. Overriding this handler keeps
    `call_tool()`'s validate -> dispatch -> `sanitize_error` path as the only
    way a tool call is executed on every transport. Failures retain their safe
    JSON body and also set the standard `isError` result flag.

    `tools/list` is intentionally left on the SDK's default handler: it is
    backed by the same `_tool_manager` populated via `add_tool` below, so it
    already reflects the schema `list_tools()` derives, with no dispatch risk.
    """
    content = await call_tool(params.name, params.arguments or {})
    # All failures are encoded by ``sanitize_error`` as a JSON object with a
    # category.  Preserve the safe JSON body while setting the MCP-standard
    # signal clients use to distinguish an unsuccessful tool invocation.
    try:
        payload = json.loads(content[0].text)
        is_error = isinstance(payload, dict) and "category" in payload
    except (json.JSONDecodeError, IndexError):
        is_error = False
    return types.CallToolResult(content=content, is_error=is_error)


get_lowlevel_server().add_request_handler(
    "tools/call", types.CallToolRequestParams, _handle_call_tool
)
