# PolicyInsight Environment Variables

This file documents the settings most developers and deployers need. Values are read by `backend/app/config.py` from environment variables and `.env`.

## Core

| Variable | Default | Purpose |
| --- | --- | --- |
| `DATABASE_URL` | `sqlite:///./firewall_cleanup.db` | SQLAlchemy database URL. Use SQLite for local dev, PostgreSQL for Docker/prod. |
| `SECRET_KEY` | empty | Required in production. Used to derive encryption keys for stored firewall credentials. |
| `UPLOAD_DIR` | `./uploads` | Directory for uploaded configs, generated reports, and branding assets. |
| `MAX_UPLOAD_SIZE_MB` | `100` | Maximum accepted upload size. |
| `ENVIRONMENT` | `development` | Set `production` only behind TLS with secure cookies and real origins. |
| `ENABLE_DOCS` | `false` | Enables docs in production when explicitly true. Docs are enabled automatically in development. |

## Browser Security

| Variable | Default | Purpose |
| --- | --- | --- |
| `ALLOWED_ORIGINS` | localhost dev origins | Comma-separated browser origins allowed by CORS/CSRF checks. |
| `ALLOWED_ORIGIN_SUBNETS` | empty | Optional CIDR list for trusted LAN origins. |
| `COOKIE_SECURE` | `false` | Set `true` behind HTTPS so session cookies are HTTPS-only. |

## Authentication

| Variable | Default | Purpose |
| --- | --- | --- |
| `BOOTSTRAP_ADMIN_EMAIL` | empty | Creates a first `system_admin` if no users exist. |
| `BOOTSTRAP_ADMIN_PASSWORD` | empty | Initial password for the bootstrap admin. Change after first login. |
| `SESSION_TTL_HOURS` | `12` | Absolute session lifetime. |
| `SESSION_IDLE_TIMEOUT_MINUTES` | `60` | Idle timeout. Set `0` to disable idle expiry. |
| `RATE_LIMIT_PER_MINUTE` | `300` | In-process per-IP request limit. Set `0` to disable locally. |

## Device Safety

| Variable | Default | Purpose |
| --- | --- | --- |
| `ALLOW_UNSAFE_DEVICE_HOSTS` | `false` | Keep false outside isolated labs. Blocks localhost/link-local/metadata device targets. |

## Analysis Tuning

| Variable | Default | Purpose |
| --- | --- | --- |
| `INACTIVITY_THRESHOLD_LOW` | `90` | Low inactivity threshold in days. |
| `INACTIVITY_THRESHOLD_MEDIUM` | `180` | Medium inactivity threshold in days. |
| `INACTIVITY_THRESHOLD_HIGH` | `365` | High inactivity threshold in days. |
| `INTERNAL_NETWORKS` | RFC1918 ranges | Internal CIDRs for exposure and lateral-movement checks. |
| `SENSITIVE_NETWORKS` | empty | Optional high-value network CIDRs. |

## Docker-Only Convenience

| Variable | Default | Purpose |
| --- | --- | --- |
| `POSTGRES_USER` | `policyinsight` | PostgreSQL user for Docker Compose. |
| `POSTGRES_PASSWORD` | `change-me...` | PostgreSQL password for Docker Compose. |
| `POSTGRES_DB` | `policyinsight` | PostgreSQL database name. |
| `HTTP_PORT` | `8080` | Host port for plain HTTP Compose deployment. |
| `APP_DOMAIN` | empty | Enables TLS/Caddy overlay when set. |
| `ACME_EMAIL` | empty | Email for Let's Encrypt certificate registration. |
