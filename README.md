# PolicyInsight

A web-based platform for analyzing firewall rulebases across multiple vendors to
surface cleanup and risk-reduction opportunities — duplicate rules, shadowed
rules, disabled/inactive rules, unused and duplicate objects, overly permissive
rules, risky services, weak logging, and policy hygiene — with explainable risk
scoring, compliance checks, and professional multi-format reporting.

> **Safety / read-only:** PolicyInsight operates in read-only analysis mode. It
> never deletes, disables, modifies, reorders, or installs firewall policies or
> objects. All findings and recommendations support review and planning only and
> require validation and formal change approval before any implementation.

## Features

### Vendor parsers
- **FortiGate** — full `.conf` exports and JSON exports
- **Check Point** — JSON policy package exports
- **Palo Alto** — PAN-OS XML config exports
- **Cisco ASA** — running-config exports
- **Huawei USG** — config exports

### Analysis
- **Duplicate Rule Detection** — compares expanded, normalized objects, not just names
- **Shadow Rule Detection** — full and partial shadowing with policy-order awareness
- **Disabled / Inactive Rules** — disabled and zero-hit rules
- **Overly Permissive Rules** — any source / destination / service
- **Risky Service Detection** — RDP, SSH, Telnet, SMB, SQL, VNC, and more
- **Unused & Duplicate Object Detection** — unreferenced objects; same value, different names
- **Compliance Checks** — policy evaluated against a library of rule/object hygiene checks
- **CVE / risky-exposure checks** and **policy health assessment**
- **Risk Scoring** — explainable 0–100 score per rule and per finding
- **Recommendation library** — review-only, vendor-aware remediation guidance

### Platform
- **Multi-tenant** — customers/firewalls with per-tenant data isolation
- **Authentication & RBAC** — session login, capability-gated endpoints
- **Audit trail** — persistent, tenant-scoped record of sensitive actions
- **Findings workflow** — review status, priority, assignee, risk acceptance (review-only; no change execution)
- **Dashboards** — exposure and risk posture, executive cleanup plan, "what changed since last sync"
- **Reporting** — modular templates (customer-facing vs internal), branding/logos,
  dynamic placeholders, and export to **HTML, PDF, DOCX, XLSX, CSV, JSON**

## Requirements

- Python 3.12
- Node.js 18+
- (Production) Docker Engine + Docker Compose v2

## Production deployment (Docker + PostgreSQL)

The supported production stack is Linux + Docker + PostgreSQL (FastAPI backend,
Vite/nginx frontend, Postgres 16). On a fresh AlmaLinux/RHEL host:

```bash
git clone https://github.com/prodromou27/firewall-cleanup.git
cd firewall-cleanup && git checkout DEV
sudo bash deploy/almalinux-deploy.sh
```

The installer is idempotent: it installs Docker, generates `.env` + secrets,
opens the firewall, builds, launches, runs `alembic upgrade head`, seeds the
bootstrap admin, and health-checks the stack. See **[DEPLOY.md](DEPLOY.md)** for
HTTPS/TLS, the DEV→PROD promotion loop, auto-update, and troubleshooting.

## Local development

### Quick start on Windows

```powershell
.\setup.ps1
.\start.ps1 -SeedDemo
```

`setup.ps1` creates a root `.venv`, installs backend and frontend dependencies,
and runs Alembic migrations. `start.ps1 -SeedDemo` starts both servers and, on
first run, imports the sample vendor policies into a demo tenant.

Demo login created by the seed script:

- Email: `demo@policyinsight.local`
- Password: `PolicyInsightDemo!2026`

### Manual backend setup

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/Mac:
source .venv/bin/activate

pip install -r backend/requirements.txt
cd backend
python -m alembic upgrade head
python -m uvicorn app.main:app --reload --port 8000
```

API: http://localhost:8000  ·  Interactive docs (non-production only): http://localhost:8000/docs

By default the dev backend uses SQLite. Set `DATABASE_URL=postgresql+psycopg2://...`
to point at Postgres. See `.env.example` and [docs/ENVIRONMENT.md](docs/ENVIRONMENT.md)
for all settings.

### Demo seed data

After migrations, seed a realistic local workspace:

```bash
python backend/scripts/seed_demo.py
```

Use `--replace` to reimport the demo policies after changing parser or analysis
logic:

```bash
python backend/scripts/seed_demo.py --replace
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

UI: http://localhost:3000 (Vite proxies `/api` to the backend — same-origin, no CORS issues).

## Running tests

```bash
python -m pytest backend/tests/ -v
cd frontend
npm test
npm run build
```

> Note: PDF export uses WeasyPrint, which is only importable inside the Linux
> Docker image; the PDF test skips automatically on Windows/macOS.

## Sample data

Sample policy files for each vendor live in `sample_data/`:

- `fortigate_sample.conf`
- `checkpoint_sample.json`
- `paloalto_sample.xml`
- `ciscoasa_sample.txt`
- `huawei_sample.txt`

Upload these via the **Upload Policy** page or run `backend/scripts/seed_demo.py`
to import all samples automatically.

## Project structure

```
cleanup_project/
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI app entry point
│   │   ├── config.py            # Settings and thresholds
│   │   ├── database.py          # SQLAlchemy setup
│   │   ├── models/              # Database models
│   │   ├── api/                 # API route handlers
│   │   ├── parsers/             # Vendor parsers (FortiGate, Check Point, Palo Alto, Cisco ASA, Huawei)
│   │   ├── analysis/            # Analysis engine + detectors, scoring, compliance, health
│   │   ├── reporting/           # Shared ReportData, section catalog, exporters (6 formats)
│   │   ├── security/            # Auth, RBAC, crypto
│   │   ├── connectors/          # Live read-only device sync + syslog listener
│   │   └── services/            # Notifications and supporting services
│   ├── alembic/                 # Database migrations (Postgres schema source of truth)
│   ├── tests/                   # Unit/integration tests
│   └── requirements.txt
├── frontend/
│   └── src/
│       ├── pages/               # Dashboard, Upload, Policies, Findings, Reporting, etc.
│       ├── components/          # Shared UI components
│       ├── api/                 # API client
│       └── types/               # TypeScript types
├── deploy/                      # Installer, update script, systemd auto-update, Caddy TLS
├── docker-compose.yml           # Production stack (Postgres + backend + frontend)
└── sample_data/                 # Per-vendor sample policy files
```

## Developer landmarks

```text
backend/scripts/seed_demo.py      Demo tenant, user, policies, findings, and report templates
docs/ENVIRONMENT.md               Environment variable reference
frontend/src/api/http.ts          Shared axios instance and session handling
frontend/src/api/client.ts        Typed frontend endpoint helpers
frontend/src/utils/errors.ts      Frontend API error normalization
sample_data/                      Realistic parser/import samples
```

## Architecture notes

- **Database:** SQLite for local dev; **PostgreSQL** for the Docker stack. Schema
  is managed by **Alembic** (`alembic upgrade head` runs on backend startup in
  Docker). See [DEPLOY.md](DEPLOY.md) for migration workflow.
- **Vendor parsers** are independent modules extending `BaseParser`. Add a vendor
  by creating a new parser class.
- **Analysis engine** (`engine.py`) orchestrates all detectors. New analysis types
  are added as functions returning finding dicts.
- **Reporting** builds one shared `ReportData` model and feeds every exporter, so
  output stays consistent across HTML/PDF/DOCX/XLSX/CSV/JSON.
- **Frontend** is same-origin with the API (Vite proxy in dev, nginx proxy in prod).
- **API client** code is split between `frontend/src/api/http.ts` for the shared
  axios/session setup and `frontend/src/api/client.ts` for typed endpoint helpers.

## Adding a new vendor

1. Create `backend/app/parsers/newvendor.py` extending `BaseParser`
2. Register it in `backend/app/parsers/__init__.py`
3. Add the vendor option to the Upload page frontend

## Finding statuses

Statuses track the **review and planning** of a finding — never change execution.
The wording is deliberately read-only ("…Outside Tool"): any cleanup happens
outside the platform through the approved change-management process.

| Status | Description |
|--------|-------------|
| New | Newly produced by an analysis run |
| Review Required | Default — needs engineer review |
| In Review | Under active review |
| Requires Business Validation | Pending confirmation of business need |
| Requires Customer Confirmation | Pending customer sign-off |
| Confirmed Cleanup Candidate | Reviewed and agreed as a candidate |
| Manual Change Required | Needs a manual change (planned externally) |
| Change Planned Outside Tool | Change scheduled in the change-management process |
| Cleanup Completed Outside Tool | Change implemented outside the platform |
| False Positive | Finding is not valid |
| Accepted Risk | Risk acknowledged with reason / expiry / approval reference |
| Deferred | Intentionally postponed |

## Disclaimer

The findings and recommendations generated by this platform are based on the
policy data available at the time of analysis. Firewall policy cleanup should
only be performed after validation of business requirements, risk assessment,
and formal change approval.
