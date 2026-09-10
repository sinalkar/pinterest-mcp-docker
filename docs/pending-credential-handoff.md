# Pending Pinterest credential handoff

The private credential service uses two stages because Keycloak 26.7.3 serializes broker context during first login. `storeToken=false` alone does not protect raw tokens placed in that context.

1. The broker initializes a random transaction and a five-minute deadline when authorization starts. The binding hashes the server-side root authentication session, tab, client and exact client redirect.
2. After a validated Pinterest callback and authenticated account lookup, the broker sends `action: stage` to `/internal/credential-ingress`. The service encrypts the full envelope using the vault's versioned AES-GCM keys. Authenticated data binds the transaction, issuer, browser/client binding, account and deadline. No owner or usable connection is created yet.
3. Keycloak receives only `pinterest_pending_reference` in broker context. Tokens are never included in that context or in generic federated token storage.
4. The first/return-login hook sends `action: complete`, the same reference/binding/account and finalized subject. The service atomically creates or updates the owned connection, saves the receipt and erases pending ciphertext. It commits before returning `completed`. Any error aborts the broker hook.

All requests require verified private HTTPS and a fresh HMAC nonce. Sign the exact transmitted bytes with the existing method/path/timestamp/nonce/body-digest format. The service validates its configured issuer, rejects duplicate/forwarded headers and limits bodies to 64 KiB. The broker rejects redirects, uses bounded request timeouts and checks the receipt's status and transaction. The JVM trust store must contain the private CA; do not disable certificate verification.

A matching `stage` retry returns the existing reference without changing the deadline. A matching `complete` retry returns the receipt without updating credentials. A changed payload, owner or binding is rejected. Completion also rejects an intervening connection-version change. PostgreSQL account locks serialize staging, completion and disconnect; disconnect erases staged credentials and prevents completion retries from reactivating the connection.

`action: cancel` immediately erases pending ciphertext. Abandoned login envelopes become unusable at the original deadline; the service's lifespan cleanup erases their ciphertext on a 30-second interval and before authenticated requests. During a database outage cleanup retries; expired records remain unusable when access resumes. Noncredential tombstones and receipts remain for later retention-policy cleanup.

The ASGI factory is `pinterest_mcp.persistence.ingress_app.create_credential_ingress`. Supply a transactional async session factory, versioned cipher, Redis nonce store, dedicated handoff secret and exact expected issuer. Run it on a separate private TLS listener with trusted proxy-header handling disabled, never mount it on the public MCP app. Apply Alembic revision `002_pending_credentials` before starting it. Wiring the production listener, private CA/secrets and migrations belongs to the GitHub Actions deployment work.

## Verification

- `pytest tests/test_pending_credentials.py` exercises encryption, ownership, expiry/cancellation, rollback, idempotency and private ASGI request validation.
- To also test PostgreSQL locks and Redis replay handling, set `PENDING_TEST_DATABASE_URL` and `PENDING_TEST_REDIS_URL` to **disposable local test services** and run the same test file. The fixture creates tables and writes synthetic records; never supply a production database.
- The Java suite uses Keycloak's actual `SerializedBrokeredIdentityContext` to verify serialized session notes contain no sentinel access or refresh token. It also checks stage failure and reference-only first/return-login completion.

These checks do not replace real browser/Pinterest callback acceptance, full Keycloak federation failure recovery, or private TLS/network deployment verification. No live Pins are created by these tests.


## Automated hosted validation

`.github/workflows/hosted-validation.yml` runs on PRs and main and can be called by a future release workflow. It checks the exact source SHA, uses immutable action and database-service references, and grants only repository read access. It does not use GitHub environment secrets, publish images, or connect to the deployment host.

The PostgreSQL job first runs `scripts/verify_hosted_migrations.py` against an empty disposable database, checks that an existing owner survives the additive upgrade, then runs the real PostgreSQL/Redis tests with automatic table creation disabled. The Java job runs the broker suite, workflow lint and container build. Only both successful jobs expose the `tested_sha` output. Existing CI/security/container gates are still required separately; this output alone does not authorize deployment.
