#!/usr/bin/env bash
#
# PolicyInsight — pull the latest code for THIS host's branch and re-deploy the
# Docker stack. Run on the DEV host (tracks DEV) or PROD host (tracks PROD).
# Migrations run inside the backend container (`alembic upgrade head`).
#
#   sudo bash deploy/update.sh              # always rebuild
#   sudo bash deploy/update.sh --if-changed # only when the branch advanced
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
cd "$REPO_DIR"

log()  { printf '\033[1;32m[update]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n'  "$*"; }
die()  { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; exit 1; }

DC="docker compose"; docker info >/dev/null 2>&1 || DC="sudo docker compose"
[ -f "$REPO_DIR/.env" ] || die "No .env — run deploy/almalinux-deploy.sh first."
[ -f "$REPO_DIR/docker-compose.yml" ] || die "Not a PolicyInsight checkout."

# TLS overlay is used when APP_DOMAIN is configured in .env.
APP_DOMAIN="$(grep -E '^APP_DOMAIN=' .env | cut -d= -f2- | tr -d '[:space:]' || true)"
COMPOSE=(-f docker-compose.yml); [ -n "$APP_DOMAIN" ] && COMPOSE+=(-f docker-compose.tls.yml)
HTTP_PORT="$(grep -E '^HTTP_PORT=' .env | cut -d= -f2- | tr -d '[:space:]')"; HTTP_PORT="${HTTP_PORT:-8080}"

IF_CHANGED=0; [ "${1:-}" = "--if-changed" ] && IF_CHANGED=1
BRANCH="$(git rev-parse --abbrev-ref HEAD)"
BEFORE="$(git rev-parse --short HEAD)"
git fetch --quiet origin "$BRANCH"
REMOTE="$(git rev-parse --short "origin/${BRANCH}")"
if [ "$BEFORE" = "$REMOTE" ] && [ "$IF_CHANGED" = "1" ]; then
  log "No new commits on '${BRANCH}' (${BEFORE}); nothing to do."; exit 0
fi

# Capture the current DB migration so a failed update can be rolled back exactly.
DB_REV_BEFORE="$($DC "${COMPOSE[@]}" exec -T backend alembic current 2>/dev/null | awk '{print $1}' || true)"

log "Updating '${BRANCH}': ${BEFORE} -> ${REMOTE}"
git pull --ff-only origin "$BRANCH"
AFTER="$(git rev-parse --short HEAD)"
[ "$BEFORE" != "$AFTER" ] && git --no-pager log --oneline "${BEFORE}..${AFTER}" | sed 's/^/    /'

log "Rebuilding and restarting the stack…"
# --remove-orphans clears containers from services that no longer exist. If up
# still fails (e.g. a stale container from a failed/older run holds a compose
# name — "Conflict. The container name … is already in use"), tear the stack
# down and bring it up fresh rather than leaving the host half-updated.
if ! $DC "${COMPOSE[@]}" up -d --build --remove-orphans; then
  warn "compose up failed — removing the old stack and retrying once…"
  $DC "${COMPOSE[@]}" down --remove-orphans || true
  $DC "${COMPOSE[@]}" up -d
fi

log "Waiting for health…"
ok=0
if [ -n "$APP_DOMAIN" ]; then
  for _ in $(seq 1 60); do curl -fsS -k --max-time 5 --resolve "${APP_DOMAIN}:443:127.0.0.1" "https://${APP_DOMAIN}/api/health" >/dev/null 2>&1 && { ok=1; break; }; sleep 3; done
else
  for _ in $(seq 1 60); do curl -fsS "http://localhost:${HTTP_PORT}/api/health" >/dev/null 2>&1 && { ok=1; break; }; sleep 3; done
fi

echo
if [ "$ok" = "1" ]; then
  log "✅ Updated and healthy on '${BRANCH}' (now ${AFTER})."
else
  warn "Health check failed after update. Inspect:"
  echo "    $DC ${COMPOSE[*]} logs --tail=80 backend"
  warn "Roll back (code + DB) — run in order:"
  echo "    git reset --hard ${BEFORE}"
  echo "    $DC ${COMPOSE[*]} up -d --build"
  [ -n "${DB_REV_BEFORE:-}" ] && echo "    $DC ${COMPOSE[*]} exec backend alembic downgrade ${DB_REV_BEFORE}"
  exit 1
fi
