#!/usr/bin/env bash
#
# PolicyInsight — bare-metal install on AlmaLinux 8/9 (no Docker).
# Stack: PostgreSQL + Python/uvicorn (systemd) + nginx serving the built SPA.
# Idempotent: safe to re-run. Run from the cloned repo root:
#   sudo bash deploy/almalinux-install.sh
# PROD (behind TLS): APP_URL=https://fw.example.com COOKIE_SECURE=true sudo bash deploy/almalinux-install.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
cd "$REPO_DIR"

APP_USER="policyinsight"
WEBROOT="/var/www/policyinsight"
HTTP_PORT="${HTTP_PORT:-80}"
COOKIE_SECURE="${COOKIE_SECURE:-false}"
ENV_FILE="$REPO_DIR/backend/.env"
PG_DB="policyinsight"; PG_USER="policyinsight"

log()  { printf '\033[1;32m[install]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n'  "$*"; }
die()  { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; exit 1; }
[ "$(id -u)" = "0" ] || die "Run with sudo/root."
[ -f "$REPO_DIR/backend/requirements.txt" ] || die "Run from the cloned repo root."

# ── 1. System packages ────────────────────────────────────────────────────────
log "Installing system packages (postgresql, python3.12, nginx, nodejs, weasyprint libs)…"
dnf -y install dnf-plugins-core >/dev/null 2>&1 || true
# Node 20 for the frontend build.
dnf -y module reset nodejs >/dev/null 2>&1 || true
dnf -y module enable nodejs:20 >/dev/null 2>&1 || true
dnf -y install \
    postgresql-server postgresql-contrib \
    python3.12 python3.12-pip \
    nginx git nodejs \
    pango harfbuzz dejavu-sans-fonts \
    >/dev/null
PY=python3.12; command -v $PY >/dev/null 2>&1 || PY=python3

# ── 2. Dedicated service user ─────────────────────────────────────────────────
id "$APP_USER" >/dev/null 2>&1 || { log "Creating service user '$APP_USER'…"; useradd --system --shell /sbin/nologin --home-dir "$REPO_DIR" "$APP_USER"; }

# ── 3. PostgreSQL ─────────────────────────────────────────────────────────────
if [ ! -s /var/lib/pgsql/data/PG_VERSION ]; then
  log "Initializing PostgreSQL data directory…"
  postgresql-setup --initdb
fi
# Require password auth on loopback (RHEL default is 'ident', which the app user can't use).
HBA=/var/lib/pgsql/data/pg_hba.conf
if [ -f "$HBA" ]; then
  sed -i -E 's@^(host\s+all\s+all\s+127\.0\.0\.1/32\s+)\w+@\1scram-sha-256@' "$HBA"
  sed -i -E 's@^(host\s+all\s+all\s+::1/128\s+)\w+@\1scram-sha-256@' "$HBA"
fi
systemctl enable --now postgresql

# Reuse the existing password from backend/.env when present (parsed robustly,
# URL-decoded); otherwise generate a fresh one. Never rotate an existing one.
if [ -f "$ENV_FILE" ]; then
  PG_PASS="$("$PY" - "$ENV_FILE" <<'PY'
import re, sys
from urllib.parse import urlsplit, unquote
txt = open(sys.argv[1], encoding="utf-8").read()
m = re.search(r'^DATABASE_URL=(.+)$', txt, re.M)
print(unquote(urlsplit(m.group(1).strip()).password or "") if m else "")
PY
)"
fi
PG_PASS="${PG_PASS:-$(openssl rand -hex 24)}"

# Escape for a PostgreSQL string literal (standard_conforming_strings=on, the
# default): double any single quotes. Avoids breakage/injection from custom
# passwords containing quotes.
ESC_PASS="${PG_PASS//\'/\'\'}"

log "Ensuring PostgreSQL role + database…"
if sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='${PG_USER}'" | grep -q 1; then
  sudo -u postgres psql -v ON_ERROR_STOP=1 -q -c "ALTER ROLE ${PG_USER} LOGIN PASSWORD '${ESC_PASS}'"
else
  sudo -u postgres psql -v ON_ERROR_STOP=1 -q -c "CREATE ROLE ${PG_USER} LOGIN PASSWORD '${ESC_PASS}'"
fi
# Create the database if it doesn't exist (owned by the app role).
sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='${PG_DB}'" | grep -q 1 \
  || sudo -u postgres createdb -O "${PG_USER}" "${PG_DB}"

# ── 4. Backend .env (generate once, never clobber) ────────────────────────────
gen_admin(){ printf 'Pi%s#7Az' "$(openssl rand -hex 6)"; }
if [ ! -f "$ENV_FILE" ]; then
  log "Generating backend/.env…"
  SERVER_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"; SERVER_IP="${SERVER_IP:-localhost}"
  if [ -n "${APP_URL:-}" ]; then ORIGINS="$APP_URL"; else ORIGINS="http://${SERVER_IP}:${HTTP_PORT},http://localhost:${HTTP_PORT}"; fi
  ADMIN_PW="$(gen_admin)"
  umask 077
  cat > "$ENV_FILE" <<EOF
DATABASE_URL=postgresql+psycopg2://${PG_USER}:${PG_PASS}@127.0.0.1:5432/${PG_DB}
SECRET_KEY=$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '\n')
ENVIRONMENT=production
ALLOWED_ORIGINS=${ORIGINS}
ALLOWED_ORIGIN_SUBNETS=
COOKIE_SECURE=${COOKIE_SECURE}
BOOTSTRAP_ADMIN_EMAIL=admin@policyinsight.local
BOOTSTRAP_ADMIN_PASSWORD=${ADMIN_PW}
UPLOAD_DIR=${REPO_DIR}/backend/uploads
EOF
  log "Initial admin password: ${ADMIN_PW}  (change it after first login)"
  NEW_ENV=1
else
  log "backend/.env exists — keeping it."
  NEW_ENV=0
fi
rm -f "$PG_PASS_FILE" 2>/dev/null || true

# ── 5. Python venv + deps + migrations ────────────────────────────────────────
log "Setting up Python virtualenv and dependencies…"
[ -d backend/.venv ] || $PY -m venv backend/.venv
backend/.venv/bin/pip install --quiet --upgrade pip
backend/.venv/bin/pip install --quiet -r backend/requirements.txt
mkdir -p backend/uploads
log "Applying database migrations (alembic upgrade head)…"
( cd backend && set -a && . ./.env && set +a && ./.venv/bin/alembic upgrade head )

# ── 6. Frontend build → web root ──────────────────────────────────────────────
log "Building the frontend…"
( cd frontend && npm ci --no-audit --no-fund && npm run build )
mkdir -p "$WEBROOT"
rm -rf "${WEBROOT:?}/"*
cp -r frontend/dist/* "$WEBROOT/"

# ── 7. systemd backend service ────────────────────────────────────────────────
log "Installing systemd backend service…"
sed "s#__REPO_DIR__#${REPO_DIR}#g; s#__APP_USER__#${APP_USER}#g" \
    "$SCRIPT_DIR/systemd/policyinsight-backend.service" > /etc/systemd/system/policyinsight-backend.service

# ── 8. nginx site ─────────────────────────────────────────────────────────────
log "Configuring nginx…"
sed "s#__WEBROOT__#${WEBROOT}#g; s#__HTTP_PORT__#${HTTP_PORT}#g" \
    "$SCRIPT_DIR/nginx/policyinsight.conf" > /etc/nginx/conf.d/policyinsight.conf
# Drop the default server on :80 if present so ours wins.
[ -f /etc/nginx/nginx.conf ] && sed -i 's/^\(\s*listen\s\+80 default_server;\)/#\1/' /etc/nginx/nginx.conf || true

# ── 9. Ownership + SELinux ────────────────────────────────────────────────────
chown -R "$APP_USER":"$APP_USER" backend
chown -R nginx:nginx "$WEBROOT" 2>/dev/null || true
if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce)" != "Disabled" ]; then
  log "Applying SELinux settings…"
  setsebool -P httpd_can_network_connect 1            # let nginx proxy to 127.0.0.1:8000
  command -v restorecon >/dev/null 2>&1 && restorecon -R "$WEBROOT" || true
fi

# ── 10. firewalld ─────────────────────────────────────────────────────────────
if systemctl is-active --quiet firewalld; then
  log "Opening ${HTTP_PORT}/tcp in firewalld…"
  if [ "$HTTP_PORT" = "80" ]; then firewall-cmd --permanent --add-service=http >/dev/null
  else firewall-cmd --permanent --add-port="${HTTP_PORT}/tcp" >/dev/null; fi
  firewall-cmd --reload >/dev/null
fi

# ── 11. Start services ────────────────────────────────────────────────────────
systemctl daemon-reload
systemctl enable --now policyinsight-backend.service
nginx -t && systemctl enable --now nginx && systemctl reload nginx

# ── 12. Health check ──────────────────────────────────────────────────────────
log "Waiting for the app to become healthy…"
ok=0
for _ in $(seq 1 40); do curl -fsS "http://localhost:${HTTP_PORT}/api/health" >/dev/null 2>&1 && { ok=1; break; }; sleep 2; done
echo
SERVER_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"; SERVER_IP="${SERVER_IP:-localhost}"
if [ "$ok" = "1" ]; then
  log "✅ PolicyInsight is up at: http://${SERVER_IP}:${HTTP_PORT}"
  log "   Login: admin@policyinsight.local"
  [ "$NEW_ENV" = "1" ] && log "   Password: $(grep '^BOOTSTRAP_ADMIN_PASSWORD=' "$ENV_FILE" | cut -d= -f2-)"
else
  warn "Health check failed. Inspect:"
  echo "    systemctl status policyinsight-backend.service"
  echo "    journalctl -u policyinsight-backend.service --no-pager -n 80"
  echo "    nginx -t && systemctl status nginx"
  exit 1
fi
