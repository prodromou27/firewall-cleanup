#!/usr/bin/env bash
#
# PolicyInsight — pull the latest code for THIS host's branch and re-deploy.
# Run on the DEV host (tracks the DEV branch) or the PROD host (tracks PROD).
# Migrations run automatically (compose backend runs `alembic upgrade head`).
#
# Usage (from the repo root on the host):
#   sudo bash deploy/update.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
cd "$REPO_DIR"

log()  { printf '\033[1;32m[update]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n'  "$*"; }
die()  { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; exit 1; }

# Use sudo for docker only if the current user can't reach the daemon directly.
DC="docker compose"
docker info >/dev/null 2>&1 || DC="sudo docker compose"

[ -f "$REPO_DIR/.env" ] || die "No .env — run deploy/almalinux-deploy.sh first."
[ -f "$REPO_DIR/docker-compose.yml" ] || die "Not a PolicyInsight checkout."

BRANCH="$(git rev-parse --abbrev-ref HEAD)"
HTTP_PORT="$(grep -E '^HTTP_PORT=' .env | cut -d= -f2- | tr -d '[:space:]')"; HTTP_PORT="${HTTP_PORT:-8080}"

BEFORE="$(git rev-parse --short HEAD)"
log "Branch '${BRANCH}' at ${BEFORE} — fetching updates…"
git fetch --quiet origin "$BRANCH"
git pull --ff-only origin "$BRANCH"
AFTER="$(git rev-parse --short HEAD)"

if [ "$BEFORE" = "$AFTER" ]; then
  log "Already up to date (${AFTER}). Rebuilding anyway to pick up any local image changes…"
else
  log "Updated ${BEFORE} -> ${AFTER}. Changes:"
  git --no-pager log --oneline "${BEFORE}..${AFTER}" | sed 's/^/    /'
fi

log "Rebuilding and restarting the stack…"
$DC up -d --build

log "Waiting for health…"
ok=0
for _ in $(seq 1 60); do
  if curl -fsS "http://localhost:${HTTP_PORT}/api/health" >/dev/null 2>&1; then ok=1; break; fi
  sleep 3
done

echo
if [ "$ok" = "1" ]; then
  log "✅ Update applied and healthy on branch '${BRANCH}' (now at ${AFTER})."
else
  warn "Health check failed after update. Inspect and consider rolling back:"
  echo "    $DC logs --tail=80 backend"
  echo "    # rollback:  git reset --hard ${BEFORE} && $DC up -d --build"
  exit 1
fi
