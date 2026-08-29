# Changelog

All notable changes to `pinterest-mcp-docker` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [0.2.4] - 2026-08-29

### Changed

- Harden release workflows and OAuth callback handling
## [0.2.3] - 2026-08-16

### Changed

- test: add MCP Inspector compatibility tests and perform minor code cleanup
## [0.2.2] - 2026-08-16

### Changed

- feat: implement OAuth and event store support while hardening transport security and session management
- feat: upgrade to MCP SDK 2.0 with streamable-HTTP transport, OAuth support, and enhanced security controls
- refactor: remove deprecated version field and switch to Docker Hub image registry
- docs: update project branding and expand privacy policy with comprehensive legal compliance
## [0.2.1] - 2026-08-08

### Changed

- feat: add automatic changelog updates and push-based tagging with concurrency controls
- feat: add auto-increment versioning logic and direct release workflow triggering to tag creation process
- refactor: consolidate docker authentication token usage using workflow environment variables
- ci: align secret names DOCKER_TOKEN and DOCKER_USERNAME with shradhanjali-banner workflow
- ci: push to Docker Hub under username sinalkar on successful main build
- fix(ci): separate Docker CI and Docker Hub release workflows cleanly
- ci: add continue-on-error to Docker Hub login in docker.yml

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
