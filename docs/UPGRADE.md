# PolicyInsight Upgrade Procedure

PolicyInsight has two supported runtime paths:

- Local development on Windows/desktop: `.venv` + local Node/npm.
- Production deployment on Linux: Docker Compose rebuilds backend/frontend images.

Do not upgrade Python, Node, npm, or dependencies directly on a production host
outside the documented flow. Production should be upgraded by pulling code and
rebuilding containers.

For firewall vendor advisory/release-note data sources, see
`docs/ADVISORY_SOURCES.md`.

## Local Development

Required local tools:

- Python 3.12 or newer
- Node.js 20 LTS or newer, with npm

Refresh the local environment after pulling new code:

```powershell
git pull --ff-only origin DEV
.\setup.ps1
.\.venv\Scripts\python.exe -m pytest backend\tests
cd frontend
npm test
npm run build
```

`setup.ps1` recreates missing pieces, upgrades `pip`, installs Python packages
from `backend/requirements.txt`, runs Alembic migrations, and installs frontend
packages from `frontend/package-lock.json` using `npm ci`.

If Python itself must be upgraded, install Python 3.12+ first, then recreate the
virtual environment:

```powershell
Remove-Item -Recurse -Force .\.venv
.\setup.ps1
```

If Node.js/npm must be upgraded, install Node.js 20 LTS or newer, then refresh
frontend dependencies:

```powershell
cd frontend
npm ci
npm run build
```

## Python Package Upgrades

1. Edit `backend/requirements.txt`.
2. Reinstall locally:

```powershell
.\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe -m pytest backend\tests
```

3. If database models changed, create and test an Alembic migration.
4. Commit `backend/requirements.txt`, migrations, and tests together.

## Node/npm Package Upgrades

1. Edit `frontend/package.json` intentionally.
2. Refresh the lockfile:

```powershell
cd frontend
npm install
npm test
npm run build
```

3. Commit both `frontend/package.json` and `frontend/package-lock.json`.

Use `npm ci` in clean installs and CI/deployment. Use `npm install` only when
intentionally changing dependency versions and updating the lockfile.

## Production Docker Upgrade

On a DEV or PROD host, use the update script from the checked-out branch:

```bash
sudo bash deploy/update.sh
```

For scheduled/automatic updates:

```bash
sudo bash deploy/update.sh --if-changed
```

The script:

1. Fetches the current branch.
2. Pulls with `--ff-only`.
3. Rebuilds Docker images.
4. Runs Alembic migrations inside the backend container.
5. Health-checks `/api/health`.
6. Prints rollback commands if the health check fails.

Python and Node runtime upgrades in production happen through Dockerfile base
image changes:

- Backend Python: `backend/Dockerfile`
- Frontend Node build image: `frontend/Dockerfile`
- PostgreSQL image: `docker-compose.yml`

After changing any base image or dependency file, rebuild and validate:

```bash
docker compose up -d --build
docker compose exec backend alembic current
docker compose exec backend python -m pytest tests
curl -fsS http://localhost:${HTTP_PORT:-8080}/api/health
```

For TLS deployments include the TLS compose overlay as normal.

## Rollback

If production update health checks fail, use the commands printed by
`deploy/update.sh`. The rollback path is:

1. Reset code to the previous commit.
2. Rebuild/restart containers.
3. Downgrade Alembic to the previous database revision if the update migrated
   the database.

Do not manually delete Docker volumes as a rollback method; volumes contain
PostgreSQL data and uploaded customer files.
