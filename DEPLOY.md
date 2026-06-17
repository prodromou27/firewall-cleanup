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
