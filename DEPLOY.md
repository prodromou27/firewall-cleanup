# Deploying PolicyInsight (Linux / Docker / PostgreSQL)

This is the containerized stack used on the `DEV` and `PROD` branches. The
Windows + SQLite developer setup lives on the `WindowServer` branch.

## Stack
- **db** — PostgreSQL 16
- **backend** — FastAPI (uvicorn), Python 3.12
- **frontend** — SPA built with Vite, served by nginx, which proxies `/api` to
  the backend (so the app is same-origin: session cookie + CSRF work cleanly)

## Prerequisites
- Docker Engine + Docker Compose v2

## AlmaLinux 8/9 (step by step)
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
- Database backups: the in-app SQLite backup endpoint does not apply to
  PostgreSQL — use `pg_dump` / managed snapshots.
- The in-process rate limiter and login throttle are per-container; for
  multi-replica backends, back them with Redis.
