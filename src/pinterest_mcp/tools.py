"""Tool specifications, Pydantic input models, and dispatch registry (Tasks 4.1-4.5)."""

from __future__ import annotations

import datetime
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .client import PinterestClient


class BaseToolInput(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _validate_yyyy_mm_dd(v: str) -> str:
    try:
        datetime.date.fromisoformat(v)
    except Exception:
        raise ValueError(f"Invalid date {v!r}. Must be in YYYY-MM-DD format.") from None
    return v


# ---------------------------------------------------------------------------
# Pydantic Input Models
# ---------------------------------------------------------------------------


class CreatePinInput(BaseToolInput):
    board_id: str = Field(min_length=1, max_length=100, description="Target board ID")
    title: str = Field(min_length=1, max_length=100, description="Pin title")
    description: str = Field(default="", max_length=800, description="Pin description")
    image_url: str | None = Field(
        default=None, max_length=2048, description="Publicly accessible image URL"
    )
    image_path: str | None = Field(
        default=None, max_length=1024, description="Local path to image file"
    )
    link: str | None = Field(default=None, max_length=2048, description="Destination URL")
    alt_text: str | None = Field(default=None, max_length=500, description="Alt text")
    dry_run: bool = Field(default=False, description="Validate without posting")

    @model_validator(mode="after")
    def _check_image_source(self) -> CreatePinInput:
        has_url = bool(self.image_url)
        has_path = bool(self.image_path)
        if not (has_url ^ has_path):
            raise ValueError("Exactly one of image_url or image_path must be provided.")
        return self


class UpdatePinInput(BaseToolInput):
    pin_id: str = Field(min_length=1, max_length=100)
    title: str | None = Field(default=None, max_length=100)
    description: str | None = Field(default=None, max_length=800)
    link: str | None = Field(default=None, max_length=2048)
    board_id: str | None = Field(default=None, max_length=100)


class DeletePinInput(BaseToolInput):
    pin_id: str = Field(min_length=1, max_length=100)


class GetPinAnalyticsInput(BaseToolInput):
    pin_id: str = Field(min_length=1, max_length=100)
    start_date: str = Field(description="YYYY-MM-DD")
    end_date: str = Field(description="YYYY-MM-DD")
    metrics: list[str] | None = Field(default=None, max_length=20)

    @field_validator("start_date", "end_date")
    @classmethod
    def _check_date(cls, v: str) -> str:
        return _validate_yyyy_mm_dd(v)


class ListBoardsInput(BaseToolInput):
    privacy: Literal["ALL", "PUBLIC", "SECRET"] = "ALL"


class CreateBoardInput(BaseToolInput):
    name: str = Field(min_length=1, max_length=100)
    description: str = Field(default="", max_length=500)
    privacy: Literal["PUBLIC", "SECRET"] = "PUBLIC"


class GetBoardPinsInput(BaseToolInput):
    board_id: str = Field(min_length=1, max_length=100)
    page_size: int = Field(default=25, ge=1, le=250)


class SearchPinsInput(BaseToolInput):
    query: str = Field(min_length=1, max_length=200)
    page_size: int = Field(default=25, ge=1, le=250)


class GetAccountAnalyticsInput(BaseToolInput):
    start_date: str = Field(description="YYYY-MM-DD")
    end_date: str = Field(description="YYYY-MM-DD")
    metrics: list[str] | None = Field(default=None, max_length=20)

    @field_validator("start_date", "end_date")
    @classmethod
    def _check_date(cls, v: str) -> str:
        return _validate_yyyy_mm_dd(v)


class BulkCreatePinItem(BaseToolInput):
    title: str = Field(min_length=1, max_length=100)
    description: str = Field(default="", max_length=800)
    image_url: str | None = Field(default=None, max_length=2048)
    image_path: str | None = Field(default=None, max_length=1024)
    link: str | None = Field(default=None, max_length=2048)
    alt_text: str | None = Field(default=None, max_length=500)

    @model_validator(mode="after")
    def _check_image_source(self) -> BulkCreatePinItem:
        has_url = bool(self.image_url)
        has_path = bool(self.image_path)
        if not (has_url ^ has_path):
            raise ValueError("Exactly one of image_url or image_path must be provided.")
        return self


class BulkCreatePinsInput(BaseToolInput):
    board_id: str = Field(min_length=1, max_length=100)
    pins: list[BulkCreatePinItem] = Field(min_length=1, max_length=50)
    dry_run: bool = False


class GetTrendingInput(BaseToolInput):
    interest: str = Field(default="miniatures", max_length=100)
    region: str = Field(default="US", max_length=10)


# ---------------------------------------------------------------------------
# ToolSpec & Registry
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ToolSpec:
    """A tool's dispatch contract.

    The advertised JSON Schema is no longer hand-written here: it is derived
    from ``model`` (see ``app.py``), so the schema and the validator can never
    drift apart. ``model`` remains the single source of truth for both.
    """

    name: str
    description: str
    model: type[BaseToolInput]
    handler: Callable[[PinterestClient, Any], Awaitable[Any]]


REGISTRY: dict[str, ToolSpec] = {
    "create_pin": ToolSpec(
        name="create_pin",
        description=(
            "Create a new Pinterest pin. An image is always required — provide either "
            "image_url (remote URL) or image_path (local file path). Exactly one must "
            "be supplied. Use dry_run=true to validate without posting."
        ),
        model=CreatePinInput,
        handler=lambda client, args: client.create_pin(**args.model_dump()),
    ),
    "update_pin": ToolSpec(
        name="update_pin",
        description="Update metadata on an existing pin.",
        model=UpdatePinInput,
        handler=lambda client, args: client.update_pin(**args.model_dump(exclude_unset=True)),
    ),
    "delete_pin": ToolSpec(
        name="delete_pin",
        description="Delete a pin.",
        model=DeletePinInput,
        handler=lambda client, args: client.delete_pin(args.pin_id),
    ),
    "get_pin_analytics": ToolSpec(
        name="get_pin_analytics",
        description="Get analytics for a pin: impressions, saves, link clicks, engagement.",
        model=GetPinAnalyticsInput,
        handler=lambda client, args: client.get_pin_analytics(
            pin_id=args.pin_id,
            start_date=args.start_date,
            end_date=args.end_date,
            metrics=args.metrics,
        ),
    ),
    "list_boards": ToolSpec(
        name="list_boards",
        description="List your Pinterest boards.",
        model=ListBoardsInput,
        handler=lambda client, args: client.list_boards(privacy=args.privacy),
    ),
    "create_board": ToolSpec(
        name="create_board",
        description="Create a new Pinterest board.",
        model=CreateBoardInput,
        handler=lambda client, args: client.create_board(
            name=args.name,
            description=args.description,
            privacy=args.privacy,
        ),
    ),
    "get_board_pins": ToolSpec(
        name="get_board_pins",
        description="List all pins on a specific board.",
        model=GetBoardPinsInput,
        handler=lambda client, args: client.get_board_pins(
            board_id=args.board_id,
            page_size=args.page_size,
        ),
    ),
    "search_pins": ToolSpec(
        name="search_pins",
        description="Search public Pinterest pins by keyword. Useful for trend research.",
        model=SearchPinsInput,
        handler=lambda client, args: client.search_pins(
            query=args.query,
            page_size=args.page_size,
        ),
    ),
    "get_account_analytics": ToolSpec(
        name="get_account_analytics",
        description="Get account-level Pinterest analytics: impressions, saves, clicks.",
        model=GetAccountAnalyticsInput,
        handler=lambda client, args: client.get_account_analytics(
            start_date=args.start_date,
            end_date=args.end_date,
            metrics=args.metrics,
        ),
    ),
    "bulk_create_pins": ToolSpec(
        name="bulk_create_pins",
        description=(
            "Create multiple pins on a board. Automatically rate-limited to 10/min. "
            "Each pin must include either image_url or image_path."
        ),
        model=BulkCreatePinsInput,
        handler=lambda client, args: client.bulk_create_pins(
            board_id=args.board_id,
            pins=[p.model_dump() for p in args.pins],
            dry_run=args.dry_run,
        ),
    ),
    "get_trending": ToolSpec(
        name="get_trending",
        description="Get trending searches and topics in a Pinterest interest category.",
        model=GetTrendingInput,
        handler=lambda client, args: client.get_trending(
            interest=args.interest,
            region=args.region,
        ),
    ),
}
