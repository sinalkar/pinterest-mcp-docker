#!/usr/bin/env bash
# Direct, key-authenticated rollout of the MCP foundation to an existing Compose host.
set -euo pipefail
cd "$(dirname "$0")"
: "${DEPLOY_HOST:?Set DEPLOY_HOST to the existing SSH host or user@host}"
DEPLOY_DIR=${DEPLOY_DIR:-/docker/pinterest-mcp}
DEPLOY_URL=${DEPLOY_URL:-https://mcp.pheniox.cloud}
DEPLOY_BRANCH=${DEPLOY_BRANCH:-$(git branch --show-current)}
[[ "$DEPLOY_HOST" =~ ^[a-zA-Z0-9_.@-]+$ && "$DEPLOY_HOST" != -* ]] || exit 2
[[ "$DEPLOY_DIR" =~ ^/[a-zA-Z0-9_/-]+$ ]] || exit 2
[[ "$DEPLOY_URL" =~ ^https://[a-zA-Z0-9.-]+$ ]] || exit 2
git check-ref-format --branch "$DEPLOY_BRANCH" >/dev/null
SSH_OPTS=(-o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=15)
if [[ -n ${DEPLOY_IDENTITY_FILE:-} ]]; then
  SSH_OPTS+=(-i "$DEPLOY_IDENTITY_FILE" -o IdentitiesOnly=yes)
fi
# No password prompts, embedded passwords, or disabled host-key verification.
ssh "${SSH_OPTS[@]}" "$DEPLOY_HOST" true
git fetch --no-tags origin "refs/heads/$DEPLOY_BRANCH"
REVISION=$(git rev-parse --verify 'FETCH_HEAD^{commit}')
[[ "$REVISION" =~ ^[0-9a-f]{40}$ ]] || exit 2
LOCAL_ARCHIVE=$(mktemp "${TMPDIR:-/tmp}/pinterest-deploy.XXXXXXXX")
REMOTE_ARCHIVE="/tmp/pinterest-source-$REVISION-$(date +%s)-$$.tar.gz"
cleanup() {
  rm -f -- "$LOCAL_ARCHIVE"
  # The locally generated archive name expands on the client intentionally.
  # shellcheck disable=SC2029
  ssh "${SSH_OPTS[@]}" "$DEPLOY_HOST" "rm -f -- '$REMOTE_ARCHIVE'" || true
}
trap cleanup EXIT
# Explicit build inputs: never archive .env, local tokens, keys, or host config.
git archive --format=tar.gz "$REVISION" Dockerfile requirements.txt pyproject.toml \
  README.md NOTICE.md LICENSE CHANGELOG.md src > "$LOCAL_ARCHIVE"
printf 'Deploying commit %s from %s to %s\n' "$REVISION" "$DEPLOY_BRANCH" "$DEPLOY_URL"
scp "${SSH_OPTS[@]}" "$LOCAL_ARCHIVE" "$DEPLOY_HOST:$REMOTE_ARCHIVE"
# Arguments are validated locally before remote shell quoting.
# shellcheck disable=SC2029
ssh "${SSH_OPTS[@]}" "$DEPLOY_HOST" \
  "python3 - '$DEPLOY_DIR' '$REMOTE_ARCHIVE' '$REVISION' '$DEPLOY_URL'" \
  < deploy/remote_rollout.py
