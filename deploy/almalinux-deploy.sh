#!/usr/bin/env bash
#
# PolicyInsight — one-shot AlmaLinux 8/9 Docker deployment.
# Idempotent: installs Docker, generates secrets/.env (only if missing), opens
# the firewall, builds, launches, and health-checks the stack.
#
# Plain HTTP:
#   sudo bash deploy/almalinux-deploy.sh
#   HTTP_PORT=80 sudo bash deploy/almalinux-deploy.sh
#
# HTTPS with automatic Let's Encrypt certs (Caddy) — needs a public domain that
# resolves to this host and inbound 80+443:
#   APP_DOMAIN=fw.example.com ACME_EMAIL=you@example.com sudo bash deploy/almalinux-deploy.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
cd "$REPO_DIR"

HTTP_PORT="${HTTP_PORT:-8080}"
ENV_FILE="$REPO_DIR/.env"

log()  { printf '\033[1;32m[deploy]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n'  "$*"; }
die()  { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; exit 1; }
[ -f "$REPO_DIR/docker-compose.yml" ] || die "Run from the cloned repo (docker-compose.yml missing)."

# ── TLS mode is enabled when APP_DOMAIN is set (env var or existing .env) ──────
if [ -f "$ENV_FILE" ]; then
  EXIST_DOMAIN="$(grep -E '^APP_DOMAIN=' "$ENV_FILE" | cut -d= -f2- | tr -d '[:space:]' || true)"
  APP_DOMAIN="${APP_DOMAIN:-$EXIST_DOMAIN}"
fi
APP_DOMAIN="${APP_DOMAIN:-}"
ACME_EMAIL="${ACME_EMAIL:-}"
TLS=0; [ -n "$APP_DOMAIN" ] && TLS=1
# Plain HTTP (DEV/LAN) runs as "development" so the production HTTPS security gate
# (validate_security_posture) is not tripped by http/localhost origins. TLS mode
# runs as "production" (docs off, HTTPS-only cookies, real origin).
if [ "$TLS" = "1" ]; then
  COOKIE_SECURE="${COOKIE_SECURE:-true}";  APP_ENV="${ENVIRONMENT:-production}"
else
  COOKIE_SECURE="${COOKIE_SECURE:-false}"; APP_ENV="${ENVIRONMENT:-development}"
fi

COMPOSE=(-f docker-compose.yml)
[ "$TLS" = "1" ] && COMPOSE+=(-f docker-compose.tls.yml)

# ── 1. Docker Engine + Compose plugin ─────────────────────────────────────────
if ! command -v docker >/dev/null 2>&1; then
  log "Installing Docker Engine (docker-ce)…"
  dnf -y install dnf-plugins-core
  dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
  dnf -y install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
else
  log "Docker already installed: $(docker --version)"
fi
systemctl enable --now docker
docker compose version >/dev/null 2>&1 || die "Docker Compose v2 plugin not available after install."

# ── 2. Generate .env (only if absent — never clobber existing secrets) ────────
gen_key()  { openssl rand -base64 32 | tr '+/' '-_' | tr -d '\n'; }   # Fernet-compatible
gen_pass() { openssl rand -hex 24; }
gen_admin(){ printf 'Pi%s#7Az' "$(openssl rand -hex 6)"; }

if [ ! -f "$ENV_FILE" ]; then
  log "Generating $ENV_FILE with fresh secrets…"
  SERVER_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"; SERVER_IP="${SERVER_IP:-localhost}"
  ADMIN_PW="$(gen_admin)"
  if [ "$TLS" = "1" ]; then ORIGINS="https://${APP_DOMAIN}"
  else ORIGINS="http://${SERVER_IP}:${HTTP_PORT},http://localhost:${HTTP_PORT}"; fi
  umask 077
  cat > "$ENV_FILE" <<EOF
POSTGRES_USER=policyinsight
POSTGRES_PASSWORD=$(gen_pass)
POSTGRES_DB=policyinsight

SECRET_KEY=$(gen_key)
ENVIRONMENT=${APP_ENV}
ALLOWED_ORIGINS=${ORIGINS}
ALLOWED_ORIGIN_SUBNETS=
COOKIE_SECURE=${COOKIE_SECURE}

BOOTSTRAP_ADMIN_EMAIL=admin@policyinsight.local
BOOTSTRAP_ADMIN_PASSWORD=${ADMIN_PW}

HTTP_PORT=${HTTP_PORT}
# TLS (Caddy auto-HTTPS) — set APP_DOMAIN to enable; leave blank for plain HTTP.
APP_DOMAIN=${APP_DOMAIN}
ACME_EMAIL=${ACME_EMAIL}
EOF
  chmod 600 "$ENV_FILE"
  log "Generated .env (mode 600). Initial admin password: ${ADMIN_PW}"
  warn "Save that password now — change it after first login (Settings → Security)."
  NEW_ENV=1
else
  log ".env already exists — keeping existing secrets."
  # A present-but-incomplete .env (e.g. copied from .env.example) makes compose
  # fall back to insecure defaults and the backend crash-loops. Fail loud instead.
  if ! grep -qE '^SECRET_KEY=.+' "$ENV_FILE"; then
    die ".env exists but SECRET_KEY is empty/missing. Run 'rm .env' and re-run this script to regenerate it, or set SECRET_KEY in .env."
  fi
  if grep -qE '^ENVIRONMENT=production' "$ENV_FILE" && grep -qE '^COOKIE_SECURE=false' "$ENV_FILE"; then
    die ".env has ENVIRONMENT=production with COOKIE_SECURE=false — the security gate will reject this. For plain HTTP set ENVIRONMENT=development; for HTTPS set COOKIE_SECURE=true and an https origin. Or 'rm .env' and re-run."
  fi
  NEW_ENV=0
fi

# ── 3. firewalld ──────────────────────────────────────────────────────────────
if systemctl is-active --quiet firewalld; then
  if [ "$TLS" = "1" ]; then
    log "Opening 80/tcp + 443/tcp in firewalld (TLS)…"
    firewall-cmd --permanent --add-service=http  >/dev/null
    firewall-cmd --permanent --add-service=https >/dev/null
  else
    log "Opening ${HTTP_PORT}/tcp in firewalld…"
    firewall-cmd --permanent --add-port="${HTTP_PORT}/tcp" >/dev/null
  fi
  firewall-cmd --reload >/dev/null
else
  warn "firewalld not active — ensure the needed ports are reachable."
fi

# ── 4. Build & launch ─────────────────────────────────────────────────────────
[ "$TLS" = "1" ] && log "TLS mode: serving https://${APP_DOMAIN} via Caddy (auto Let's Encrypt)."
log "Building and starting the stack (first run can take a few minutes)…"
docker compose "${COMPOSE[@]}" up -d --build

# ── 5. Health check ───────────────────────────────────────────────────────────
log "Waiting for the app to become healthy…"
ok=0
if [ "$TLS" = "1" ]; then
  for _ in $(seq 1 60); do
    if curl -fsS -k --max-time 5 --resolve "${APP_DOMAIN}:443:127.0.0.1" \
         "https://${APP_DOMAIN}/api/health" >/dev/null 2>&1; then ok=1; break; fi
    sleep 3
  done
else
  for _ in $(seq 1 60); do
    if curl -fsS "http://localhost:${HTTP_PORT}/api/health" >/dev/null 2>&1; then ok=1; break; fi
    sleep 3
  done
fi

echo
SERVER_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"; SERVER_IP="${SERVER_IP:-localhost}"
if [ "$ok" = "1" ]; then
  if [ "$TLS" = "1" ]; then log "✅ PolicyInsight is up at: https://${APP_DOMAIN}"
  else log "✅ PolicyInsight is up at: http://${SERVER_IP}:${HTTP_PORT}"; fi
  log "   Login: admin@policyinsight.local"
  [ "$NEW_ENV" = "1" ] && log "   Password: $(grep '^BOOTSTRAP_ADMIN_PASSWORD=' "$ENV_FILE" | cut -d= -f2-)"
else
  if [ "$TLS" = "1" ]; then
    warn "App not reachable over HTTPS yet. Certificate issuance needs public DNS"
    warn "for ${APP_DOMAIN} → this host and inbound 80/443. Check Caddy:"
    echo "    docker compose ${COMPOSE[*]} logs --tail=60 caddy"
  fi
  warn "Inspect:"
  echo "    docker compose ${COMPOSE[*]} ps"
  echo "    docker compose ${COMPOSE[*]} logs --tail=80 backend"
  exit 1
fi
