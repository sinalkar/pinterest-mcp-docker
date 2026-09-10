# Hosted authentication compatibility record

Status: public HTTPS authorization-service checks passed, 2026-09-05.
This record does not certify ChatGPT acceptance, Pinterest account isolation, or scheduled publishing.

## Verified locally

The workspace has MCP Python SDK 2.0.0. Run:

```sh
.venv/bin/python -m pytest tests/test_hosted_identity_compat.py tests/test_oauth.py tests/test_dispatch.py tests/test_inspector_compat.py -q --timeout=20
```

Result: 26 tests pass, including eight hosted identity/metadata checks.

- Real RS256 JWT verification and the HTTP authentication middleware populate `ctx.request.scope["user"]` with an SDK `AuthenticatedUser` in the custom `tools/call` dispatcher.
- `user.access_token.subject` and `user.access_token.claims["iss"]` distinguish two concurrent users sharing the same OAuth client ID. The test waits until both dispatches are active before allowing either to finish.
- Stateless Streamable HTTP dispatch works for protocol revisions 2024-11-05, 2025-03-26, 2025-06-18 and 2026-07-28. The latter uses its required per-request metadata and matching routing headers.
- Expired tokens, foreign audiences and malformed JWTs receive 401 before the Pinterest client is resolved, with a resource-discovery challenge.
- `MCPServer.add_tool(meta=...)` retains `_meta.securitySchemes`. SDK 2.0.0's `Tool` model drops an added top-level `securitySchemes` field. The hosted `tools/list` adapter must return a raw mapping carrying the top-level declaration and `_meta` mirror, and have an HTTP wire assertion when implemented.
- `CallToolResult(meta=...)` preserves `_meta["mcp/www_authenticate"]` for tool-level authorization challenges.

The harness substitutes JWKS retrieval with an ephemeral test public key and substitutes the final Pinterest client. All tokens are generated in memory; no real account is read or modified. A wrapper observes the context and then calls the existing production `_handle_call_tool` implementation. The tests prove transport identity propagation, not database ownership enforcement. Hosted code must use the verified per-message context and must still reject absent subjects and enforce tool permissions.

## Authentication spike evidence

A private deployment spike exercised public discovery and MCP challenges, S256 code exchange, audience verification, refresh, refresh revocation and code replay rejection using disposable test identities. No Pinterest account was accessed and no Pin was created. These observations do not establish full ChatGPT/Pinterest acceptance.

Host-specific Compose files, bootstrap/reconciliation scripts, runtime environment, credentials and verification output are excluded from the public commit. They are historical spike material, not the GitHub Actions deployment implementation. Public hosted deployment remains pending the checks below and the new release/deployment workflow.

## External checks still required

Tasks 1.1, 1.2, 1.3 and 1.5 remain incomplete:

1. Complete real ChatGPT OAuth acceptance using the user-confirmed callback.
   The predefined client is configured, but its
   ChatGPT interoperability is not established by the protocol-test client.
2. Implement and verify authenticated browser setup with the same issuer/subject,
   including first/return login and subject mismatch rejection.
3. Verify Pinterest application access tier, registered HTTPS linking callback,
   granted boards/pins/user-account scopes, stable account identity and
   continuous-refresh responses using the designated test accounts.
4. Extend provider checks to wrong PKCE verifier and expiry rejection after a
   real token expires. The current live check verifies the expiry claim only;
   local tests separately prove rejection of expired signed tokens. Refresh
   revocation does not establish immediate revocation of issued JWT access tokens.
5. Resolve registration metadata before claiming compliance: Keycloak discovery
   advertises `registration_endpoint`, while CIMD/DCR remain unverified. The
   initial connection method is a predefined client, and unsupported methods
   must not be advertised under the hosted spec.

Keycloak is deployed for the spike; final provider acceptance remains pending
these checks. Public users remain disabled until account isolation exists.

## Source references

- [OpenAI authentication](https://developers.openai.com/plugins/build/auth) defines discovery, authorization-code/S256, supported registration paths, tool security declarations and runtime challenges.
- [Keycloak OIDC endpoints](https://www.keycloak.org/securing-apps/oidc-layers) describes the candidate's discovery, authorization, token and revocation endpoints.
- [Keycloak database configuration](https://www.keycloak.org/server/db) describes supported PostgreSQL persistence and database secret configuration.
- [Keycloak offline access](https://www.keycloak.org/docs/latest/server_admin/#_offline-access) describes optional client scope assignment and offline refresh grants.
- [Pinterest OAuth](https://developers.pinterest.com/docs/getting-started/set-up-authentication-and-authorization/) and [access tiers](https://developers.pinterest.com/docs/key-concepts/access-tiers/) remain the references for the pending application checks.
