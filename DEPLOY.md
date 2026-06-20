# Deploying PolicyInsight (Linux / Docker / PostgreSQL)

This is the containerized stack used on the `DEV` and `PROD` branches. The
Windows + SQLite developer setup lives on the `WindowServer` branch.

## Stack
- **db** — PostgreSQL 16 (the only supported database for this stack)
- **backend** — FastAPI (uvicorn), Python 3.12
- **frontend** — SPA built with Vite, served by nginx, which proxies `/api` to
  the backend (so the app is same-origin: session cookie + CSRF work cleanly)

## Two environments (DEV + PROD, separate machines)
Both run the identical PostgreSQL stack; they differ only in branch and `.env`.

| | DEV host | PROD host |
|---|---|---|
| Git branch | `DEV` | `PROD` |
| Purpose | testing / iteration | live |
| TLS / `COOKIE_SECURE` | off (http) | on (behind TLS) |

**First-time bring-up (run once per machine):**
```bash
git clone https://github.com/prodromou27/firewall-cleanup.git && cd firewall-cleanup

# DEV host:
git checkout DEV
sudo bash deploy/almalinux-deploy.sh

# PROD host (behind a TLS reverse proxy at APP_URL):
git checkout PROD
APP_URL=https://fw.example.com COOKIE_SECURE=true sudo bash deploy/almalinux-deploy.sh
```

**The promotion loop (DEV → PROD on every change):**
1. Develop & test on the DEV host: push fixes to `origin/DEV`, then on the DEV
   host run `sudo bash deploy/update.sh` (pulls `DEV`, rebuilds, migrates,
   health-checks).
2. When validated, promote: merge `DEV → PROD` and push (`git checkout PROD &&
   git merge --no-ff DEV && git push`).
3. On the PROD host run `sudo bash deploy/update.sh` (pulls `PROD`, rebuilds,
   runs `alembic upgrade head`, health-checks). Roll back with the command the
   script prints if health fails.

`update.sh` rebuilds in place from the host's current branch, so DEV pulls DEV
and PROD pulls PROD automatically. Schema changes ride along via Alembic.

### Fully hands-off auto-deploy
Two options to remove the manual `update.sh` step:

**A) Pull-based self-update (recommended for private-LAN hosts).** Each host
polls its branch and redeploys on change — no inbound access required:
```bash
sudo bash deploy/install-autoupdate.sh        # installs a systemd timer (~2 min poll)
# logs:        journalctl -u policyinsight-update.service -f
# uninstall:   sudo bash deploy/install-autoupdate.sh --uninstall
```
Now: push to `DEV` → DEV host self-updates; promote `DEV→PROD` → PROD host
self-updates. PROD promotion stays gated behind the branch merge you approve.

**B) Push-based via GitHub Actions** (`.github/workflows/deploy.yml`). On push
to `DEV`/`PROD` it SSHes into the matching host and runs `update.sh`. Requires
the host to be reachable from the runner (public IP or a self-hosted runner on
the LAN) and these repo secrets: `DEV_HOST/DEV_USER/DEV_SSH_KEY` and the `PROD_*`
equivalents. Adjust `REPO_PATH` in the workflow to the clone location.

## Prerequisites
- Docker Engine + Docker Compose v2

## AlmaLinux — automated (recommended)
One idempotent script does everything (install Docker, generate `.env` + secrets,
open the firewall, build, launch, health-check). From the cloned repo on the host:
```bash
git clone https://github.com/prodromou27/firewall-cleanup.git
cd firewall-cleanup && git checkout DEV
sudo bash deploy/almalinux-deploy.sh          # or: HTTP_PORT=80 sudo bash deploy/almalinux-deploy.sh
```
On success it prints the URL and the generated admin password (saved in `.env`,
mode 600). Re-running is safe — it preserves an existing `.env`. The manual
steps below are the same thing broken out, for reference or troubleshooting.

## HTTPS / TLS on port 443 (certificates)
The stack can serve HTTPS via a built-in **Caddy** reverse proxy
(`docker-compose.tls.yml` + `deploy/caddy/Caddyfile`). Three certificate paths:

### A) Automatic Let's Encrypt (recommended — zero manual cert handling)
Caddy obtains and **auto-renews** a free certificate. Requirements: a public
domain whose DNS A/AAAA record points at the server, and inbound **TCP 80 + 443**
open from the internet (used for the ACME challenge).
```bash
APP_DOMAIN=fw.example.com ACME_EMAIL=you@example.com sudo bash deploy/almalinux-deploy.sh
```
The installer sets `COOKIE_SECURE=true`, `ALLOWED_ORIGINS=https://fw.example.com`,
opens 80/443, and brings up the Caddy overlay. Nothing else to install — the
cert is fetched on first start and renewed automatically. App: `https://fw.example.com`.

### B) Bring your own certificate (corporate/internal CA, or purchased)
Put your `fullchain.pem` + `privkey.pem` on the host, mount them into Caddy, and
point the Caddyfile at them. In `docker-compose.tls.yml` add to the `caddy`
service:
```yaml
    volumes:
      - /etc/ssl/policyinsight/fullchain.pem:/certs/fullchain.pem:ro
      - /etc/ssl/policyinsight/privkey.pem:/certs/privkey.pem:ro
```
and replace the site block in `deploy/caddy/Caddyfile` with:
```
{$APP_DOMAIN} {
    tls /certs/fullchain.pem /certs/privkey.pem
    reverse_proxy frontend:80
}
```
Then `APP_DOMAIN=fw.example.com sudo bash deploy/almalinux-deploy.sh`. (No
ACME, no public ports needed — good for internal-only servers.)

### C) Internal / no public domain (self-signed)
For a quick internal cert with no CA, use Caddy's local CA — in the Caddyfile:
```
{$APP_DOMAIN} { tls internal
    reverse_proxy frontend:80 }
```
Browsers will warn unless you distribute Caddy's root to clients. Alternatively
generate a self-signed pair with `openssl req -x509 -newkey rsa:2048 ...` and use
path B.

> Whichever path: when serving HTTPS, keep `COOKIE_SECURE=true` and
> `ALLOWED_ORIGINS=https://<domain>` in `.env` (the installer does this for you
> when `APP_DOMAIN` is set).

## AlmaLinux 8/9 (manual / step by step)
```bash
# 1. Install Docker Engine + Compose plugin
sudo dnf -y install dnf-plugins-core
sudo dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
sudo dnf -y install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker
sudo usermod -aG docker "$USER"      # log out/in for group to take effect

# 2. Get the code (Docker stack lives on the DEV branch)
git clone https://github.com/prodromou27/firewall-cleanup.git
cd firewall-cleanup && git checkout DEV

# 3. Configure
cp .env.example .env
openssl rand -base64 32 | tr '+/' '-_'   # paste as SECRET_KEY in .env
# also set POSTGRES_PASSWORD, BOOTSTRAP_ADMIN_PASSWORD, ALLOWED_ORIGINS=http://<server-ip>:8080

# 4. Open the app port in firewalld
sudo firewall-cmd --permanent --add-port=8080/tcp
sudo firewall-cmd --reload

# 5. Build & start
docker compose up -d --build
docker compose logs -f backend          # watch alembic upgrade + startup
```
App: `http://<server-ip>:8080`.

**AlmaLinux notes**
- SELinux (enforcing by default) is fine here — compose uses *named volumes*
  (`pgdata`, `uploads`), which Docker labels automatically; no `:Z` needed
  (only bind-mounts would require it).
- DB persists in the `pgdata` volume across restarts. `docker compose down -v`
  wipes it.
- First boot runs `alembic upgrade head` then seeds the bootstrap admin.

## Quick start
```bash
cp .env.example .env
# Edit .env: set SECRET_KEY, POSTGRES_PASSWORD, BOOTSTRAP_ADMIN_PASSWORD, ALLOWED_ORIGINS
docker compose up -d --build
```
App: `http://localhost:8080` (or the `HTTP_PORT` you set).

### Generate a SECRET_KEY
A Fernet key is 32 random bytes, url-safe base64 encoded. No Python needed:
```bash
openssl rand -base64 32 | tr '+/' '-_'
```
(Or, where the cryptography package is installed:
`python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`.)

## Key environment variables
See `.env.example` for the full list. Notable:
- `DATABASE_URL` is assembled in compose as
  `postgresql+psycopg2://<user>:<pass>@db:5432/<db>`.
- `ENVIRONMENT=production` disables the interactive API docs.
- `ALLOWED_ORIGINS` must include the URL users hit (e.g. `http://localhost:8080`).
- `ALLOWED_ORIGIN_SUBNETS` optionally allows whole LAN CIDRs (also editable at
  runtime in Settings → Security).
- `COOKIE_SECURE=true` only behind HTTPS.

## Schema & migrations (Alembic)
Schema is managed by **Alembic** on PostgreSQL. The compose `backend` service
runs `alembic upgrade head` before starting uvicorn, so a fresh database is
provisioned automatically (the baseline revision creates all tables).

- SQLite (dev on the `WindowServer` branch) bootstraps directly via
  `create_all`; Alembic is skipped there but still available for authoring
  migrations.
- **Add a schema change:** edit the models, then
  `cd backend && alembic revision --autogenerate -m "describe change"`, review
  the generated file in `alembic/versions/`, and commit it. Compose applies it
  on the next deploy.
- **Adopt Alembic on an existing create_all database:** `alembic stamp head`
  once (marks it at the baseline without re-creating tables), then use
  `upgrade` for subsequent changes.
- `alembic` reads `DATABASE_URL` from the environment (via `app.config`), so the
  same commands work against SQLite and PostgreSQL.

## Notes / TODO before PROD
- Put a TLS-terminating reverse proxy in front and set `COOKIE_SECURE=true`.
- Initialize Alembic (`alembic init`) and wire an autogenerate baseline against
  the current models, replacing reliance on `create_all`.
- Database backups: **Settings → Backup → Download database** produces a
  `pg_dump` custom-format archive (`.dump`) on PostgreSQL (or a `.db` copy on
  SQLite). Restore a PostgreSQL archive with:
  ```bash
  # copy the .dump onto the host, then:
  docker compose exec -T db pg_restore --clean --if-exists --no-owner \
    -U policyinsight -d policyinsight < policyinsight_backup_YYYYMMDD_HHMMSS.dump
  ```
  Restore is intentionally a deliberate CLI step (it overwrites data), not an
  API action. Managed-Postgres snapshots also work.
- The in-process rate limiter and login throttle are per-container; for
  multi-replica backends, back them with Redis.
