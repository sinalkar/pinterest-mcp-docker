# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.2.x   | Yes       |
| < 0.2.0 | No        |

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it privately:

- **Email / Channel:** Create a private GitHub Security Advisory in this repository under `Security` -> `Advisories`.
- **Response Time:** We aim to acknowledge receipt within 48 hours and issue a fix within 7 business days for high/critical severity items.

Please do not open public issues for unpatched security vulnerabilities.

## Threat Model & Security Controls

### Trust Boundaries
1. **MCP Client -> Server:** In stdio mode, local pipe IPC is trusted. In HTTP mode, bearer token authentication protects the endpoint from untrusted network clients.
2. **Server -> Pinterest API:** Authentication uses OAuth 2.0 access tokens. TLS verification is strictly enforced (`verify=True`).
3. **Server -> External Image URLs (`image_url`):** Caller-supplied URLs are treated as untrusted input.

### Implemented Controls
- **SSRF Defenses:** `validate_public_url` resolves DNS hostnames and blocks loopback, private, link-local, CGNAT, and multicast IP addresses across IPv4 and IPv6. Outbound fetches use custom IP-pinned transports and manual 3-hop redirect limits with origin-change authorization stripping.
- **Path Traversal Defenses:** `image_path` is restricted to `PINTEREST_ALLOWED_IMAGE_DIR`, enforces realpath resolution (blocking symlink escapes), caps file sizes, and sniffs magic bytes for JPEG/PNG/GIF/WebP formats.
- **Credential Protection:** Tokens are stored atomically in `$XDG_STATE_HOME/pinterest-mcp/token.json` with `0600` file permissions and `0700` parent directory permissions. Secret redaction filters strip tokens and credentials from logs and MCP error responses.
- **Container Hardening:** Runs as unprivileged UID/GID `10001` (`app`), supports `--read-only` rootfs, drops all Linux capabilities (`--cap-drop ALL`), and prevents privilege escalation (`no-new-privileges`).

### Residual Risks & Limitations
- **Single-Account Auth:** HTTP mode provides bearer token authentication for a single shared Pinterest account. Per-user OAuth isolation is out of scope.
- **DNS Rebinding (TOCTOU):** Short DNS TTLs could allow IP changes between validation and connection. IP-pinned transports mitigate this on direct fetch paths.
