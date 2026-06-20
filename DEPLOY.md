# Deploying PolicyInsight (AlmaLinux + PostgreSQL, no Docker)

Bare-metal deployment on AlmaLinux 8/9. The Windows + SQLite developer setup
lives on the `WindowServer` branch; the Linux/PostgreSQL line is `dev_red`
(and `PROD`).

## Stack (native systemd services)
- **PostgreSQL** — the application database
- **backend** — FastAPI served by uvicorn under systemd (`policyinsight-backend.service`), bound to `127.0.0.1:8000`
- **nginx** — serves the built SPA and reverse-proxies `/api` to the backend (same-origin: session cookie + CSRF work cleanly)

## Two environments (DEV + PROD, separate machines)
Identical native stack; they differ only by git branch and `backend/.env`.

| | DEV host | PROD host |
|---|---|---|
| Git branch | `dev_red` | `PROD` |
| Purpose | testing / iteration | live |
| TLS / `COOKIE_SECURE` | off (http) | on (behind TLS) |

## Install (run once per machine)
```bash
git clone https://github.com/prodromou27/firewall-cleanup.git
cd firewall-cleanup

# DEV host:
git checkout dev_red
sudo bash deploy/almalinux-install.sh

# PROD host (behind a TLS reverse proxy at APP_URL):
git checkout PROD
APP_URL=https://fw.example.com COOKIE_SECURE=true sudo bash deploy/almalinux-install.sh
```
The installer is idempotent. It:
1. installs packages (`postgresql-server`, `python3.12`, `nginx`, `nodejs:20`, and WeasyPrint libs `pango`/`harfbuzz`/`dejavu-sans-fonts`);
2. inits PostgreSQL, sets loopback auth to `scram-sha-256`, creates the role + database;
3. generates `backend/.env` with fresh secrets (Fernet `SECRET_KEY`, DB password, a policy-compliant bootstrap admin password) — only if absent;
4. creates a Python venv, installs deps, runs `alembic upgrade head`;
5. builds the frontend into `/var/www/policyinsight`;
6. installs the systemd backend service + nginx site;
7. applies SELinux (`httpd_can_network_connect`) + firewalld, starts everything, and health-checks.

On success it prints the URL and the generated admin password.

## Updating (apply code changes)
```bash
sudo bash deploy/update.sh        # pull branch, deps, migrate, rebuild SPA, restart
```
`update.sh` pulls whichever branch the host is on, so the DEV box tracks
`dev_red` and the PROD box tracks `PROD`. Schema changes ride along via Alembic.

### Hands-off auto-deploy (recommended for private-LAN hosts)
```bash
sudo bash deploy/install-autoupdate.sh    # systemd timer polls the branch ~2 min
# logs:      journalctl -u policyinsight-update.service -f
# uninstall: sudo bash deploy/install-autoupdate.sh --uninstall
```
Push to `dev_red` → DEV host self-updates. Promote `dev_red → PROD` → PROD host
self-updates. (A push-based GitHub Actions alternative is in
`.github/workflows/deploy.yml` for hosts reachable by the runner.)

## DEV → PROD promotion
1. Develop & test on DEV (push to `origin/dev_red`; the DEV host self-updates).
2. When validated, merge `dev_red → PROD` and push.
3. The PROD host self-updates (or run `deploy/update.sh` there).

## Schema & migrations (Alembic)
Schema is managed by Alembic. The installer and `update.sh` run
`alembic upgrade head`, so a fresh database is provisioned automatically and
schema changes apply on update.
- **Add a change:** edit the models, then
  `cd backend && .venv/bin/alembic revision --autogenerate -m "describe change"`,
  review the file in `backend/alembic/versions/`, and commit it.
- Alembic reads `DATABASE_URL` from `backend/.env`.

## Operational notes
- Backend logs: `journalctl -u policyinsight-backend.service -f`
- Restart backend: `systemctl restart policyinsight-backend.service`
- DB backups: use `pg_dump` (the in-app backup endpoint is SQLite-only and
  returns 400 on PostgreSQL).
- For PROD over HTTPS, use the TLS site template instead of the default HTTP
  one, then set `COOKIE_SECURE=true` and `ALLOWED_ORIGINS=https://<domain>`:
  ```bash
  cp deploy/nginx/policyinsight-tls.conf.example /etc/nginx/conf.d/policyinsight.conf
  # edit the domain + cert paths (certbot --nginx works), then:
  nginx -t && systemctl reload nginx
  ```
- The in-process rate limiter / login throttle are per-process; for multiple
  backend workers, back them with Redis.

## Useful service map
| Component | Unit / path |
|---|---|
| Backend | `policyinsight-backend.service` |
| Web server | `nginx` → `/etc/nginx/conf.d/policyinsight.conf` |
| Web root | `/var/www/policyinsight` |
| Database | `postgresql` |
| Config | `backend/.env` |
| Auto-update | `policyinsight-update.timer` |
