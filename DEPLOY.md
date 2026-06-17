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

## Quick start
```bash
cp .env.example .env
# Edit .env: set SECRET_KEY, POSTGRES_PASSWORD, BOOTSTRAP_ADMIN_PASSWORD, ALLOWED_ORIGINS
docker compose up -d --build
```
App: `http://localhost:8080` (or the `HTTP_PORT` you set).

### Generate a SECRET_KEY
```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

## Key environment variables
See `.env.example` for the full list. Notable:
- `DATABASE_URL` is assembled in compose as
  `postgresql+psycopg2://<user>:<pass>@db:5432/<db>`.
- `ENVIRONMENT=production` disables the interactive API docs.
- `ALLOWED_ORIGINS` must include the URL users hit (e.g. `http://localhost:8080`).
- `ALLOWED_ORIGIN_SUBNETS` optionally allows whole LAN CIDRs (also editable at
  runtime in Settings → Security).
- `COOKIE_SECURE=true` only behind HTTPS.

## Schema
On first start the backend creates the full schema via SQLAlchemy
`create_all`. The SQLite-only `PRAGMA` column migrations are skipped on
PostgreSQL. Ongoing schema changes should be managed with **Alembic** (already
a dependency) — initialize migrations before the first production release.

## Notes / TODO before PROD
- Put a TLS-terminating reverse proxy in front and set `COOKIE_SECURE=true`.
- Initialize Alembic (`alembic init`) and wire an autogenerate baseline against
  the current models, replacing reliance on `create_all`.
- Database backups: the in-app SQLite backup endpoint does not apply to
  PostgreSQL — use `pg_dump` / managed snapshots.
- The in-process rate limiter and login throttle are per-container; for
  multi-replica backends, back them with Redis.
