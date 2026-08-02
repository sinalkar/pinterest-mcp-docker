"""Application security primitives: SSRF prevention, path traversal defense,
and error sanitization.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import urllib.parse
from pathlib import Path
from typing import Any

import httpx


class SecurityError(ValueError):
    """Raised when a security constraint or validation rule is violated."""


ALLOWED_SCHEMES = frozenset({"http", "https"})


def is_public_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Check if an IP address is a publicly routable global address."""
    if (
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return False
    return ip.is_global


def validate_public_url(url: str) -> tuple[str, str]:
    """Validate that a URL uses http(s) and resolves only to public IP addresses."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise SecurityError(f"Disallowed URL scheme: {parsed.scheme!r}. Must be http or https.")

    hostname = parsed.hostname
    if not hostname:
        raise SecurityError("URL missing hostname.")

    port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    try:
        addr_info = socket.getaddrinfo(hostname, port)
    except socket.gaierror as e:
        raise SecurityError(f"Failed to resolve host {hostname!r}: {e}") from e

    if not addr_info:
        raise SecurityError(f"No IP addresses resolved for host {hostname!r}.")

    resolved_ip = ""
    for _family, _, _, _, sockaddr in addr_info:
        ip_str = sockaddr[0]
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            raise SecurityError(f"Invalid IP address resolved: {ip_str!r}") from None

        if not is_public_ip(ip_obj):
            raise SecurityError(
                f"URL resolves to non-public IP address {ip_str} for host {hostname!r}"
            )
        if not resolved_ip:
            resolved_ip = ip_str

    return url, resolved_ip


# Magic bytes for image formats
_JPEG_MAGIC = b"\xff\xd8\xff"
_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
_GIF87_MAGIC = b"GIF87a"
_GIF89_MAGIC = b"GIF89a"
_RIFF_MAGIC = b"RIFF"
_WEBP_MAGIC = b"WEBP"


def sniff_image_format(data: bytes) -> str:
    """Sniff image format from header magic bytes."""
    if data.startswith(_JPEG_MAGIC):
        return "image/jpeg"
    if data.startswith(_PNG_MAGIC):
        return "image/png"
    if data.startswith(_GIF87_MAGIC) or data.startswith(_GIF89_MAGIC):
        return "image/gif"
    if data.startswith(_RIFF_MAGIC) and len(data) >= 12 and data[8:12] == _WEBP_MAGIC:
        return "image/webp"
    raise SecurityError("File content does not match allowed image formats (JPEG, PNG, GIF, WebP).")


def resolve_local_image_path(
    path_str: str | Path,
    allowed_dir: Path,
    max_bytes: int = 10 * 1024 * 1024,
) -> tuple[Path, str]:
    """Resolve and validate a local image path."""
    path_obj = Path(path_str)
    try:
        resolved_path = path_obj.resolve(strict=True)
    except Exception as e:
        raise SecurityError(f"Invalid or non-existent file path: {e}") from e

    try:
        allowed_dir_resolved = Path(allowed_dir).resolve(strict=True)
    except Exception:
        allowed_dir_resolved = Path(allowed_dir).resolve()

    try:
        resolved_path.relative_to(allowed_dir_resolved)
    except ValueError:
        raise SecurityError(
            f"Path escape detected: {path_str!r} resolves outside allowed directory."
        ) from None

    try:
        st_size = resolved_path.stat().st_size
    except Exception as e:
        raise SecurityError(f"Cannot stat file: {e}") from e

    if st_size > max_bytes:
        raise SecurityError(
            f"File size ({st_size} bytes) exceeds maximum limit ({max_bytes} bytes)."
        )

    try:
        with open(resolved_path, "rb") as f:
            header = f.read(16)
    except Exception as e:
        raise SecurityError(f"Cannot read file header: {e}") from e

    mime_type = sniff_image_format(header)
    return resolved_path, mime_type


class IPPinningTransport(httpx.AsyncHTTPTransport):
    """Transport that pins HTTP requests to a validated target IP address."""

    def __init__(self, pinned_ip: str, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.pinned_ip = pinned_ip


async def fetch_public_image_url(
    url: str,
    user_agent: str,
    timeout: float = 30.0,
    max_bytes: int = 10 * 1024 * 1024,
) -> tuple[bytes, str]:
    """Fetch an image from a public URL with SSRF validation, max 3 redirects, and size limits."""
    current_url = url
    headers = {"User-Agent": user_agent}

    for _hop in range(4):  # max 3 redirects (0..3)
        validated_url, resolved_ip = validate_public_url(current_url)
        parsed = urllib.parse.urlparse(validated_url)

        transport = IPPinningTransport(pinned_ip=resolved_ip, verify=True)
        async with httpx.AsyncClient(
            transport=transport,
            timeout=httpx.Timeout(timeout),
            verify=True,
            follow_redirects=False,
        ) as client:
            resp = await client.get(validated_url, headers=headers)

            if resp.is_redirect:
                location = resp.headers.get("Location")
                if not location:
                    raise SecurityError("Redirect response missing Location header.")
                next_url = urllib.parse.urljoin(validated_url, location)
                next_parsed = urllib.parse.urlparse(next_url)

                if (parsed.scheme.lower(), parsed.netloc.lower()) != (
                    next_parsed.scheme.lower(),
                    next_parsed.netloc.lower(),
                ):
                    headers.pop("Authorization", None)
                    headers.pop("authorization", None)

                current_url = next_url
                continue

            resp.raise_for_status()

            content_length = resp.headers.get("Content-Length")
            if content_length and int(content_length) > max_bytes:
                raise SecurityError(
                    f"Remote image size ({content_length} bytes) exceeds limit ({max_bytes} bytes)."
                )

            content = resp.content
            if len(content) > max_bytes:
                raise SecurityError(
                    f"Remote image size ({len(content)} bytes) exceeds limit ({max_bytes} bytes)."
                )

            mime_type = sniff_image_format(content[:16])
            return content, mime_type

    raise SecurityError("Too many redirects (exceeded maximum of 3 hops).")


def save_atomic_token_file(token_path: Path, data: dict[str, Any]) -> None:
    """Save token data atomically with 0600 file permissions and 0700 parent directory."""
    token_path = Path(token_path)
    parent = token_path.parent
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp_path = token_path.with_name(f".{token_path.name}.tmp.{os.getpid()}")
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with open(fd, "w", encoding="utf-8") as f:
            import json

            json.dump(data, f, indent=2)
    except Exception:
        if tmp_path.exists():
            tmp_path.unlink()
        raise

    os.replace(tmp_path, token_path)


def sanitize_error(exc: Exception) -> dict[str, str]:
    """Map exceptions to a stable category + safe message without leaking internal details."""
    if isinstance(exc, SecurityError):
        return {"category": "security_error", "message": str(exc)}

    exc_type = type(exc).__name__
    return {
        "category": "error",
        "message": f"An operation failed due to a {exc_type}. Details have been logged securely.",
    }
