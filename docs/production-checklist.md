# Production checklist

Do not merge, tag, or publish until each required P0 item is complete.

## Required before release

- [ ] GitHub CI, Docker smoke tests, and security workflows pass on the exact commit.
- [ ] Pinterest scopes and access tier are verified against a non-production account.
- [ ] The public HTTPS endpoint serves `/mcp` without a redirect and has a trusted certificate.
- [ ] The external OAuth issuer, JWT audience (`MCP_RESOURCE_URL`), and allowed subjects are configured.
- [ ] Secrets are held in a secret manager; no production credentials are committed or logged.
- [ ] Claude Desktop and every hosted client offered to users complete an initialize, list-tools, read, and dry-run-write smoke test.

## Release and rollback

- [ ] The PyPI trusted publisher and container registry credentials are configured in the `release` environment.
- [ ] Verify the package version, image digest, SBOM, provenance, and Cosign signature.
- [ ] Test readiness, token persistence, rate-limit handling, and rollback to the previous immutable image.
