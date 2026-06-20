#!/usr/bin/env bash
#
# PolicyInsight — bare-metal in-place update. Pulls this host's branch (dev_red
# on the DEV box, PROD on the PROD box), updates deps, runs migrations, rebuilds
# the frontend, and restarts services. Used directly or by the self-update timer.
#
#   sudo bash deploy/update.sh              # always rebuild
#   sudo bash deploy/update.sh --if-changed # only when the branch advanced
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
cd "$REPO_DIR"

WEBROOT="/var/www/policyinsight"
ENV_FILE="$REPO_DIR/backend/.env"

log()  { printf '\033[1;32m[update]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n'  "$*"; }
die()  { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; exit 1; }
[ "$(id -u)" = "0" ] || die "Run with sudo/root."
[ -f "$ENV_FILE" ] || die "No backend/.env — run deploy/almalinux-install.sh first."

IF_CHANGED=0; [ "${1:-}" = "--if-changed" ] && IF_CHANGED=1
BRANCH="$(git rev-parse --abbrev-ref HEAD)"
HTTP_PORT="$(grep -E '^ALLOWED_ORIGINS=' "$ENV_FILE" | grep -oE ':[0-9]+' | head -1 | tr -d ':')"; HTTP_PORT="${HTTP_PORT:-80}"

BEFORE="$(git rev-parse --short HEAD)"
git fetch --quiet origin "$BRANCH"
REMOTE="$(git rev-parse --short "origin/${BRANCH}")"
if [ "$BEFORE" = "$REMOTE" ] && [ "$IF_CHANGED" = "1" ]; then
  log "No new commits on '${BRANCH}' (${BEFORE}); nothing to do."; exit 0
fi
log "Updating '${BRANCH}': ${BEFORE} -> ${REMOTE}"
git pull --ff-only origin "$BRANCH"

log "Backend deps + migrations…"
backend/.venv/bin/pip install --quiet -r backend/requirements.txt
# Capture the current migration revision first so a failed update can be rolled
# back to exactly this DB state (code rollback alone leaves the DB ahead).
DB_REV_BEFORE="$( cd backend && set -a && . ./.env && set +a && ./.venv/bin/alembic current 2>/dev/null | awk '{print $1}' )"
( cd backend && set -a && . ./.env && set +a && ./.venv/bin/alembic upgrade head )

log "Rebuilding frontend…"
( cd frontend && npm ci --no-audit --no-fund && npm run build )
rm -rf "${WEBROOT:?}/"* && cp -r frontend/dist/* "$WEBROOT/"
command -v restorecon >/dev/null 2>&1 && restorecon -R "$WEBROOT" 2>/dev/null || true
chown -R policyinsight:policyinsight backend 2>/dev/null || true

log "Restarting services…"
systemctl restart policyinsight-backend.service
nginx -t && systemctl reload nginx

log "Health check…"
ok=0
for _ in $(seq 1 40); do curl -fsS "http://localhost:${HTTP_PORT}/api/health" >/dev/null 2>&1 && { ok=1; break; }; sleep 2; done
AFTER="$(git rev-parse --short HEAD)"
echo
if [ "$ok" = "1" ]; then
  log "✅ Updated and healthy on '${BRANCH}' (now ${AFTER})."
else
  warn "Health check failed. Inspect:"
  echo "    journalctl -u policyinsight-backend.service --no-pager -n 80"
  warn "Roll back fully (code + DB + deps + webroot) — run in order:"
  if [ -n "${DB_REV_BEFORE:-}" ]; then
    echo "    ( cd backend && set -a && . ./.env && set +a && ./.venv/bin/alembic downgrade ${DB_REV_BEFORE} )"
  else
    warn "    (no prior DB revision captured — review backend/alembic/versions before downgrading)"
  fi
  echo "    git reset --hard ${BEFORE}"
  echo "    backend/.venv/bin/pip install -r backend/requirements.txt   # restore old deps"
  echo "    ( cd frontend && npm ci && npm run build ) && rm -rf ${WEBROOT}/* && cp -r frontend/dist/* ${WEBROOT}/"
  echo "    systemctl restart policyinsight-backend.service && systemctl reload nginx"
  exit 1
fi
