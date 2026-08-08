# Changelog

All notable changes to `pinterest-mcp-docker` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### ⚠️ BREAKING CHANGES

- **`mcp` dependency floor raised to `>=2.0.0`:** the code already required SDK 2.0 behavior (the installed and pinned version was already `2.0.0`), but `pyproject.toml` understated the floor as `>=1.9.0`. Installs pinned below `2.0.0` will now fail to resolve rather than installing an incompatible SDK.
- **Internal server API migrated from the low-level `mcp.server.Server` to `mcp.server.mcpserver.MCPServer`:** no MCP client observes a wire-protocol difference, but the advertised tool input schemas are now derived from each tool's Pydantic model instead of hand-written. This adds real field constraints (string/array lengths) that were previously undeclared, and drops the cross-field "exactly one of `image_url`/`image_path`" hint from the advertised schema for `create_pin` and each item of `bulk_create_pins` — that rule is still enforced at call time, just no longer visible in the schema. Modules that imported `pinterest_mcp.app.mcp_app` expecting a low-level `Server` should use the new `pinterest_mcp.app.get_lowlevel_server()` accessor instead.

## [0.2.0] - 2026-08-02

### ⚠️ BREAKING CHANGES

- **Token Path Location & Permissions:** Default token storage path has moved from `./.pinterest_token.json` (relative CWD) to `$XDG_STATE_HOME/pinterest-mcp/token.json` (defaulting to `~/.local/state/pinterest-mcp/token.json` on Linux/macOS and container-writable volume under `/home/app`).
  - *Migration:* Existing users should move `.pinterest_token.json` to the new path, or set the `PINTEREST_TOKEN_PATH` environment variable.
  - Token directory permissions are created with `0700` and token files are written atomically with `0600` file permissions.

### Added

- **Multi-Transport Server Support:** The MCP server now supports both standard input/output (`stdio`) and Streamable HTTP (`http`) via Starlette and Uvicorn.
- **OWASP Application Security Hardening:**
  - SSRF protections on `image_url` fetching with scheme allowlists, public IP DNS checks, IP-pinned HTTP transport, manual redirect handling (max 3 hops), and automatic `Authorization` header stripping across origins.
  - Path traversal protections on `image_path` using `Path.resolve()`, containment checks against `PINTEREST_ALLOWED_IMAGE_DIR`, maximum file size caps, and magic-byte image format sniffing (JPEG, PNG, GIF, WebP).
  - Secret redaction filter applied to all logging output and MCP error messages (`sanitize_error`).
  - Bearer token authentication middleware for HTTP transport mode.
- **Pydantic Tool Input Registry:** All 11 tools are declared in a strict `ToolSpec` registry enforcing `extra="forbid"`, string/array length bounds, enum validation, `YYYY-MM-DD` date validation, and max batch caps. Removed the dead `dry_run_pin` branch.
- **Hardened Multi-Stage Docker Container:**
  - Three-stage build on digest-pinned `python:3.12-slim` producing a minimal runtime image running as unprivileged user `10001` (`app`).
  - Full read-only rootfs compatibility with `/tmp` tmpfs mount and container healthcheck.
  - Multi-architecture builds (`linux/amd64` and `linux/arm64`).
- **Comprehensive CI/CD & Security Pipelines:**
  - GitHub Actions workflows for matrix testing (Python 3.11, 3.12, 3.13), CodeQL SAST, Semgrep, Bandit, pip-audit, Trivy (FS & Container), OpenSSF Scorecard, and Dependabot.
- **Release Automation & Attribution:**
  - Automated tag releases publishing to GHCR, Docker Hub, and PyPI via Trusted Publishing.
  - SPDX SBOM, SLSA provenance, and keyless cosign image signatures.
  - Prominent upstream attribution to Carlos Lugtu (`clugtu/pinterest-mcp`) in `NOTICE.md`, `LICENSE`, `pyproject.toml`, and OCI image labels.
