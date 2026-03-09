"""Pinterest API v5 client.

OAuth 2.0 with automatic token refresh.
Docs: https://developers.pinterest.com/docs/api/v5/
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import time
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger(__name__)

PINTEREST_BASE = "https://api.pinterest.com/v5"
PINTEREST_AUTH = "https://api.pinterest.com/v5/oauth/token"
TOKEN_FILE = Path(".pinterest_token.json")

# Rate limit: 10 pins/minute
_PIN_RATE_LIMIT = 10
_PIN_RATE_WINDOW = 60.0


class PinterestClient:
    """Pinterest API v5 client with OAuth 2.0 and token refresh."""

    def __init__(
        self,
        client_id: str | None = None,
        client_secret: str | None = None,
        access_token: str | None = None,
        refresh_token: str | None = None,
    ) -> None:
        self.client_id = client_id or os.environ.get("PINTEREST_CLIENT_ID", "")
        self.client_secret = client_secret or os.environ.get("PINTEREST_CLIENT_SECRET", "")
        self._access_token = access_token or os.environ.get("PINTEREST_ACCESS_TOKEN")
        self._refresh_token = refresh_token or os.environ.get("PINTEREST_REFRESH_TOKEN")
        self._token_expiry: float = 0
        self._pin_timestamps: list[float] = []
        self._http = httpx.AsyncClient(
            timeout=30.0,
            base_url=PINTEREST_BASE,
            headers={"User-Agent": "pinterest-mcp/0.1.0"},
        )
        # Try loading stored token
        if not self._access_token and TOKEN_FILE.exists():
            self._load_token_file()

    def _load_token_file(self) -> None:
        try:
            data = json.loads(TOKEN_FILE.read_text())
            self._access_token = data.get("access_token")
            self._refresh_token = data.get("refresh_token")
            self._token_expiry = data.get("expiry", 0)
            logger.info("Loaded Pinterest token from %s", TOKEN_FILE)
        except Exception as e:
            logger.warning("Could not load token file: %s", e)

    def _save_token_file(self) -> None:
        TOKEN_FILE.write_text(
            json.dumps({
                "access_token": self._access_token,
                "refresh_token": self._refresh_token,
                "expiry": self._token_expiry,
            })
        )

    async def _ensure_token(self) -> str:
        if self._access_token and time.time() < self._token_expiry - 60:
            return self._access_token
        if self._refresh_token:
            await self._refresh()
            return self._access_token  # type: ignore[return-value]
        raise RuntimeError(
            "No Pinterest access token. Run `pinterest-mcp-auth` to authenticate."
        )

    async def _refresh(self) -> None:
        resp = await self._http.post(
            PINTEREST_AUTH,
            data={
                "grant_type": "refresh_token",
                "refresh_token": self._refresh_token,
            },
            auth=(self.client_id, self.client_secret),
        )
        resp.raise_for_status()
        data = resp.json()
        self._access_token = data["access_token"]
        self._refresh_token = data.get("refresh_token", self._refresh_token)
        self._token_expiry = time.time() + data.get("expires_in", 3600)
        self._save_token_file()
        logger.info("Pinterest token refreshed")

    async def _request(
        self,
        method: str,
        path: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        token = await self._ensure_token()
        resp = await self._http.request(
            method,
            path,
            headers={"Authorization": f"Bearer {token}"},
            **kwargs,
        )
        resp.raise_for_status()
        if resp.status_code == 204:
            return {}
        return resp.json()

    async def _rate_limited_pin(self, pin_data: dict[str, Any]) -> dict[str, Any]:
        """Create a pin with rate limiting (10/min)."""
        now = time.time()
        self._pin_timestamps = [t for t in self._pin_timestamps if now - t < _PIN_RATE_WINDOW]
        if len(self._pin_timestamps) >= _PIN_RATE_LIMIT:
            sleep_for = _PIN_RATE_WINDOW - (now - self._pin_timestamps[0])
            logger.info("Rate limit: sleeping %.1fs", sleep_for)
            await asyncio.sleep(sleep_for)
        result = await self._request("POST", "/pins", json=pin_data)
        self._pin_timestamps.append(time.time())
        return result

    # ------------------------------------------------------------------
    # Pins
    # ------------------------------------------------------------------

    async def create_pin(
        self,
        board_id: str,
        title: str,
        description: str,
        image_url: str | None = None,
        image_path: str | None = None,
        link: str | None = None,
        alt_text: str | None = None,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """Create a Pinterest pin.

        Either ``image_url`` (remote) or ``image_path`` (local file) must be
        supplied — a pin cannot be created without an image. ``image_path``
        takes precedence if both are given (file is base64-encoded and sent
        directly, avoiding the need for a public CDN URL).

        Pinterest has no sandbox environment. Use ``dry_run=True`` during
        development to validate inputs without making a real API call — the
        app runs in dev mode so only your own account can see posts anyway,
        but dry_run gives a zero-side-effect test path.
        """
        if not image_url and not image_path:
            raise ValueError("Either image_url or image_path must be provided")

        if image_path:
            img_bytes = Path(image_path).read_bytes()
            img_b64 = base64.b64encode(img_bytes).decode()
            content_type = "image/png" if image_path.lower().endswith(".png") else "image/jpeg"
            media_source: dict[str, Any] = {
                "source_type": "image_base64",
                "content_type": content_type,
                "data": img_b64,
            }
        else:
            media_source = {"source_type": "image_url", "url": image_url}

        payload: dict[str, Any] = {
            "board_id": board_id,
            "title": title,
            "description": description,
            "media_source": media_source,
        }
        if link:
            payload["link"] = link
        if alt_text:
            payload["alt_text"] = alt_text

        if dry_run:
            return {
                "dry_run": True,
                "status": "validated",
                "board_id": board_id,
                "title": title,
                "image_source": image_path or image_url,
                "link": link,
            }

        return await self._rate_limited_pin(payload)

    async def update_pin(
        self,
        pin_id: str,
        title: str | None = None,
        description: str | None = None,
        link: str | None = None,
        board_id: str | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {}
        if title is not None:
            payload["title"] = title
        if description is not None:
            payload["description"] = description
        if link is not None:
            payload["link"] = link
        if board_id is not None:
            payload["board_id"] = board_id
        return await self._request("PATCH", f"/pins/{pin_id}", json=payload)

    async def delete_pin(self, pin_id: str) -> dict[str, Any]:
        return await self._request("DELETE", f"/pins/{pin_id}")

    async def get_pin_analytics(
        self,
        pin_id: str,
        start_date: str,
        end_date: str,
        metrics: list[str] | None = None,
    ) -> dict[str, Any]:
        if metrics is None:
            metrics = ["IMPRESSION", "SAVE", "PIN_CLICK", "OUTBOUND_CLICK", "ENGAGEMENT"]
        params = {
            "start_date": start_date,
            "end_date": end_date,
            "metric_types": ",".join(metrics),
            "app_types": "ALL",
        }
        return await self._request("GET", f"/pins/{pin_id}/analytics", params=params)

    async def bulk_create_pins(
        self,
        board_id: str,
        pins: list[dict[str, Any]],
        dry_run: bool = False,
    ) -> list[dict[str, Any]]:
        """Create multiple pins, respecting the 10/min rate limit.

        Each pin dict must include either ``image_url`` or ``image_path``.
        """
        results = []
        for pin in pins:
            result = await self.create_pin(
                board_id=board_id,
                title=pin.get("title", ""),
                description=pin.get("description", ""),
                image_url=pin.get("image_url"),
                image_path=pin.get("image_path"),
                link=pin.get("link"),
                alt_text=pin.get("alt_text"),
                dry_run=dry_run,
            )
            results.append(result)
        return results

    # ------------------------------------------------------------------
    # Boards
    # ------------------------------------------------------------------

    async def list_boards(self, privacy: str = "ALL") -> list[dict[str, Any]]:
        data = await self._request("GET", "/boards", params={"privacy": privacy})
        return data.get("items", [])

    async def create_board(
        self,
        name: str,
        description: str = "",
        privacy: str = "PUBLIC",
    ) -> dict[str, Any]:
        return await self._request(
            "POST",
            "/boards",
            json={"name": name, "description": description, "privacy": privacy},
        )

    async def get_board_pins(
        self, board_id: str, page_size: int = 25
    ) -> list[dict[str, Any]]:
        data = await self._request(
            "GET", f"/boards/{board_id}/pins", params={"page_size": page_size}
        )
        return data.get("items", [])

    # ------------------------------------------------------------------
    # Search
    # ------------------------------------------------------------------

    async def search_pins(
        self, query: str, page_size: int = 25
    ) -> list[dict[str, Any]]:
        data = await self._request(
            "GET",
            "/search/pins",
            params={"query": query, "page_size": page_size},
        )
        return data.get("items", [])

    # ------------------------------------------------------------------
    # Analytics (account-level)
    # ------------------------------------------------------------------

    async def get_account_analytics(
        self,
        start_date: str,
        end_date: str,
        metrics: list[str] | None = None,
    ) -> dict[str, Any]:
        if metrics is None:
            metrics = ["IMPRESSION", "SAVE", "OUTBOUND_CLICK", "PIN_CLICK", "ENGAGEMENT"]
        return await self._request(
            "GET",
            "/user_account/analytics",
            params={
                "start_date": start_date,
                "end_date": end_date,
                "metric_types": ",".join(metrics),
            },
        )

    async def get_trending(
        self,
        interest: str = "miniatures",
        region: str = "US",
    ) -> dict[str, Any]:
        return await self._request(
            "GET",
            "/trends/keywords",
            params={"interests": interest, "region": region},
        )

    async def aclose(self) -> None:
        await self._http.aclose()
