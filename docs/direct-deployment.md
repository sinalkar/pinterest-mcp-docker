# Direct deployment of the MCP foundation

`deploy.sh` provides the direct SSH deployment requested for the existing server. It is an explicit manual alternative to the planned GitHub Actions release process, not an Actions deployment or full hosted Pinterest release.

```sh
DEPLOY_HOST=your-ssh-user@your-server ./deploy.sh
```

The script uses an existing SSH agent/key and a previously trusted host key. It never stores a password or disables host-key verification. Set `DEPLOY_IDENTITY_FILE` to a private key path if the agent is not used. Keep keys and deployment configuration outside Git.

Defaults:

- `DEPLOY_BRANCH`: the current local branch; its latest remote commit is fetched from `origin`.
- `DEPLOY_DIR`: `/docker/pinterest-mcp`, containing the existing `compose.yaml` and private `.env`.
- `DEPLOY_URL`: `https://mcp.pheniox.cloud`.

It uploads only tracked Docker build inputs from the resolved commit. Uncommitted edits, `.env`, SSH keys, tokens and host configuration are excluded. Docker builds a commit-tagged image on the server, checks imports, then replaces only the `mcp` service. Keycloak, database services and their volumes are retained. The existing public-user restriction must be present and unchanged; the script refuses a foundation rollout to an unrestricted service.

Container health, public HTTPS `/healthz`, and the unauthenticated `/mcp` challenge must pass. Only then does it persist `MCP_IMAGE` in the private `.env`. Failures restore the prior image and environment. `rollout-state.json` records the commit, previous image and phase without credentials. A host lock prevents overlapping runs. If a run is interrupted during replacement, the next run restores the recorded image and stops for verification; run again after checking recovery. No database migrations or Keycloak broker changes are performed by this foundation script.

This does not enable Pinterest-first login, per-user token dispatch or posting. Those features and the signed GitHub Actions deployment remain separate unfinished work. Do not report a successful foundation rollout as full hosted readiness.
