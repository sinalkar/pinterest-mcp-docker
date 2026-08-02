"""Tests for security primitives: SSRF defenses, path traversal, error sanitization."""

from __future__ import annotations

import socket
from pathlib import Path
from unittest.mock import patch

import pytest

from pinterest_mcp.security import (
    SecurityError,
    resolve_local_image_path,
    sanitize_error,
    validate_public_url,
)


def mock_getaddrinfo(ip_address: str):
    """Helper to return a mock getaddrinfo response for a given IP."""

    def _mock(host, port, *args, **kwargs):
        family = socket.AF_INET6 if ":" in ip_address else socket.AF_INET
        return [(family, socket.SOCK_STREAM, 6, "", (ip_address, port))]

    return _mock


def test_ssrf_disallowed_schemes():
    for url in [
        "file:///etc/passwd",
        "gopher://example.com/1",
        "ftp://example.com/file.txt",
        "javascript:alert(1)",
    ]:
        with pytest.raises(SecurityError, match="Disallowed URL scheme"):
            validate_public_url(url)


def test_ssrf_private_and_loopback_ips():
    bad_ips = [
        "127.0.0.1",  # IPv4 loopback
        "10.0.0.1",  # IPv4 private class A
        "172.16.0.1",  # IPv4 private class B
        "192.168.1.1",  # IPv4 private class C
        "169.254.169.254",  # AWS metadata endpoint / link-local
        "100.64.0.1",  # CGNAT
        "0.0.0.0",  # Unspecified
        "::1",  # IPv6 loopback
        "fd00::1",  # IPv6 unique-local
        "fe80::1",  # IPv6 link-local
    ]

    for ip in bad_ips:
        with (
            patch("socket.getaddrinfo", side_effect=mock_getaddrinfo(ip)),
            pytest.raises(SecurityError, match="non-public IP address"),
        ):
            validate_public_url("https://example.com/image.jpg")


def test_ssrf_public_https_accepted():
    with patch("socket.getaddrinfo", side_effect=mock_getaddrinfo("93.184.216.34")):
        url, ip = validate_public_url("https://example.com/image.jpg")
        assert url == "https://example.com/image.jpg"
        assert ip == "93.184.216.34"


def test_path_traversal_relative_escape(tmp_path: Path):
    allowed_dir = tmp_path / "allowed"
    allowed_dir.mkdir()
    outside_file = tmp_path / "outside.png"
    outside_file.write_bytes(b"\x89PNG\r\n\x1a\n")

    with pytest.raises(SecurityError, match="Path escape detected"):
        resolve_local_image_path(allowed_dir / "../outside.png", allowed_dir=allowed_dir)


def test_path_traversal_symlink_escape(tmp_path: Path):
    allowed_dir = tmp_path / "allowed"
    allowed_dir.mkdir()
    target_file = tmp_path / "target.jpg"
    target_file.write_bytes(b"\xff\xd8\xff")

    symlink_file = allowed_dir / "link.jpg"
    symlink_file.symlink_to(target_file)

    with pytest.raises(SecurityError, match="Path escape detected"):
        resolve_local_image_path(symlink_file, allowed_dir=allowed_dir)


def test_oversized_file_rejected(tmp_path: Path):
    allowed_dir = tmp_path / "allowed"
    allowed_dir.mkdir()
    large_file = allowed_dir / "large.jpg"
    large_file.write_bytes(b"\xff\xd8\xff" + b"\x00" * 100)

    with pytest.raises(SecurityError, match="exceeds maximum limit"):
        resolve_local_image_path(large_file, allowed_dir=allowed_dir, max_bytes=50)


def test_non_image_content_rejected(tmp_path: Path):
    allowed_dir = tmp_path / "allowed"
    allowed_dir.mkdir()
    text_file = allowed_dir / "test.txt"
    text_file.write_text("Hello World!")

    with pytest.raises(SecurityError, match="File content does not match allowed image formats"):
        resolve_local_image_path(text_file, allowed_dir=allowed_dir)


def test_valid_image_accepted(tmp_path: Path):
    allowed_dir = tmp_path / "allowed"
    allowed_dir.mkdir()
    png_file = allowed_dir / "test.png"
    png_file.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 20)

    resolved, mime = resolve_local_image_path(png_file, allowed_dir=allowed_dir)
    assert resolved == png_file.resolve()
    assert mime == "image/png"


def test_sanitize_error():
    sec_err = SecurityError("Path escape detected")
    sanitized = sanitize_error(sec_err)
    assert sanitized["category"] == "security_error"
    assert "Path escape detected" in sanitized["message"]

    raw_err = ValueError("Secret key in /home/user/secret.txt")
    sanitized_gen = sanitize_error(raw_err)
    assert sanitized_gen["category"] == "error"
    assert "ValueError" in sanitized_gen["message"]
    assert "/home/user/secret.txt" not in sanitized_gen["message"]
