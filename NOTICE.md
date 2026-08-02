# Notice

## Upstream Project Attribution

This software is a modified derivative of **pinterest-mcp**, originally created and authored by **Carlos Lugtu** (`clugtu/pinterest-mcp`).

- **Original Project:** https://github.com/clugtu/pinterest-mcp
- **Original Author:** Carlos Lugtu
- **Original License:** MIT License

## Fork Modifications

This repository (`sinalkar/pinterest-mcp-docker`) extends and hardens the upstream project with:

1. **Multi-Transport Support:** Runs as stdio or Streamable HTTP (via Starlette/Uvicorn) with bearer token auth.
2. **OWASP Security Hardening:** SSRF defenses (public IP resolution, scheme allowlist, custom IP-pinned transport, redirect policy), path traversal guards, input validation via Pydantic, token permission hardening (0600 file / 0700 dir), and error/log secret redaction.
3. **Containerization:** Multi-stage, digest-pinned non-root Docker container with read-only rootfs compatibility and healthcheck.
4. **CI/CD & Security Workflows:** CodeQL, Semgrep, Bandit, pip-audit, Trivy, Scorecard, and Dependabot automation.
5. **Release Publishing:** Automated multi-arch builds (GHCR & Docker Hub), SPDX SBOM, SLSA provenance, and keyless cosign signatures.

All original copyrights are preserved in `LICENSE`.
