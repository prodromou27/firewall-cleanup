#!/usr/bin/env bash
#
# PolicyInsight — one-shot AlmaLinux 8/9 deployment.
# Idempotent: safe to re-run. Installs Docker, generates secrets/.env (only if
# missing), opens the firewall, builds, launches, and health-checks the stack.
#
# Usage (from the repo root, on the AlmaLinux host):
#   sudo bash deploy/almalinux-deploy.sh
#   HTTP_PORT=80 sudo bash deploy/almalinux-deploy.sh     # override the port
#
set -euo pipefail

# ── Resolve repo root (this script lives in <repo>/deploy) ────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
cd "$REPO_DIR"

HTTP_PORT="${HTTP_PORT:-8080}"
ENV_FILE="$REPO_DIR/.env"

log()  { printf '\033[1;32m[deploy]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n'  "$*"; }
die()  { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; exit 1; }

[ -f "$REPO_DIR/docker-compose.yml" ] || die "docker-compose.yml not found — run this from the cloned repo (deploy/ subdir)."

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
gen_key()  { openssl rand -base64 32 | tr '+/' '-_' | tr -d '\n'; }     # Fernet-compatible
gen_pass() { openssl rand -hex 24; }
# Policy-compliant admin password: >=12 chars, upper+lower+digit+symbol, no weak words.
gen_admin(){ printf 'Pi%s#7Az' "$(openssl rand -hex 6)"; }

if [ ! -f "$ENV_FILE" ]; then
  log "Generating $ENV_FILE with fresh secrets…"
  SERVER_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"; SERVER_IP="${SERVER_IP:-localhost}"
  ADMIN_PW="$(gen_admin)"
  umask 077
  cat > "$ENV_FILE" <<EOF
POSTGRES_USER=policyinsight
POSTGRES_PASSWORD=$(gen_pass)
POSTGRES_DB=policyinsight

SECRET_KEY=$(gen_key)
ENVIRONMENT=production
ALLOWED_ORIGINS=http://${SERVER_IP}:${HTTP_PORT},http://localhost:${HTTP_PORT}
ALLOWED_ORIGIN_SUBNETS=
COOKIE_SECURE=false

BOOTSTRAP_ADMIN_EMAIL=admin@policyinsight.local
BOOTSTRAP_ADMIN_PASSWORD=${ADMIN_PW}

HTTP_PORT=${HTTP_PORT}
EOF
  chmod 600 "$ENV_FILE"
  log "Generated .env (mode 600). Initial admin password: ${ADMIN_PW}"
  warn "Save that password now — change it after first login (Settings → Security)."
  NEW_ENV=1
else
  log ".env already exists — keeping existing secrets."
  NEW_ENV=0
fi

# ── 3. Open the app port in firewalld (if running) ────────────────────────────
if systemctl is-active --quiet firewalld; then
  log "Opening ${HTTP_PORT}/tcp in firewalld…"
  firewall-cmd --permanent --add-port="${HTTP_PORT}/tcp" >/dev/null
  firewall-cmd --reload >/dev/null
else
  warn "firewalld not active — skipping firewall rule (ensure ${HTTP_PORT}/tcp is reachable)."
fi

# ── 4. Build & launch ─────────────────────────────────────────────────────────
log "Building and starting the stack (this can take a few minutes on first run)…"
docker compose up -d --build

# ── 5. Health check ───────────────────────────────────────────────────────────
log "Waiting for the app to become healthy…"
ok=0
for i in $(seq 1 60); do
  if curl -fsS "http://localhost:${HTTP_PORT}/api/health" >/dev/null 2>&1; then ok=1; break; fi
  sleep 3
done

echo
if [ "$ok" = "1" ]; then
  SERVER_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"; SERVER_IP="${SERVER_IP:-localhost}"
  log "✅ PolicyInsight is up at: http://${SERVER_IP}:${HTTP_PORT}"
  log "   Login: admin@policyinsight.local"
  if [ "$NEW_ENV" = "1" ]; then
    log "   Password: $(grep '^BOOTSTRAP_ADMIN_PASSWORD=' "$ENV_FILE" | cut -d= -f2-)"
  else
    log "   Password: (from your existing .env / unchanged)"
  fi
  warn "For production, terminate TLS in front and set COOKIE_SECURE=true in .env, then 'docker compose up -d'."
else
  warn "Health check did not pass in time. Inspect logs:"
  echo "    docker compose ps"
  echo "    docker compose logs --tail=80 backend"
  echo "    docker compose logs --tail=40 db frontend"
  exit 1
fi
