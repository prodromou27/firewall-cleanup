"""FastAPI application entry point."""
import asyncio
import logging
import logging.config
import threading
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from app.config import settings
from app.database import engine, Base
from app.api import upload, policies, findings, objects, reports, settings as settings_api
from app.api import customers, devices, revisions, compliance, auth as auth_api, users as users_api
from app.api import audit as audit_api
from app.api import cleanup as cleanup_api
from app.api import changes as changes_api
import app.models  # ensure models are registered

# ── Logging configuration ─────────────────────────────────────────────────────

LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "standard": {
            "format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        },
        "audit": {
            "format": "%(asctime)s AUDIT %(message)s",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "standard",
            "level": "INFO",
        },
        "audit_file": {
            "class": "logging.handlers.RotatingFileHandler",
            "filename": "audit.log",
            "maxBytes": 10 * 1024 * 1024,   # 10 MB
            "backupCount": 5,
            "formatter": "audit",
            "level": "INFO",
        },
    },
    "loggers": {
        "audit": {
            "handlers": ["console", "audit_file"],
            "level": "INFO",
            "propagate": False,
        },
    },
    "root": {
        "handlers": ["console"],
        "level": "INFO",
    },
}

logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger("app")
auto_sync_logger = logging.getLogger("auto_sync")


# ── Auto-sync background scheduler ───────────────────────────────────────────

def _run_device_sync_thread(device_id: str) -> None:
    """Thread target for scheduled auto-sync. Uses its own DB session."""
    from app.database import SessionLocal
    from app.models.device import FirewallDevice
    from app.connectors.live_sync import sync_device
    db = SessionLocal()
    try:
        device = db.query(FirewallDevice).filter(FirewallDevice.id == device_id).first()
        if device:
            auto_sync_logger.info("Auto-sync starting for device %s (%s)", device_id, device.name)
            sync_device(device, db)
            auto_sync_logger.info("Auto-sync completed for device %s (%s)", device_id, device.name)
    except Exception as exc:
        auto_sync_logger.error("Auto-sync failed for device %s: %s", device_id, exc)
    finally:
        db.close()


async def _auto_sync_loop() -> None:
    """
    Asyncio background task — wakes every 5 minutes, fires sync threads for
    any device whose sync_interval_hours has elapsed since last_sync_at.
    """
    auto_sync_logger.info("Auto-sync scheduler started (check interval: 5 min)")
    while True:
        await asyncio.sleep(5 * 60)
        try:
            from app.database import SessionLocal
            from app.models.device import FirewallDevice
            db = SessionLocal()
            try:
                now = datetime.utcnow()
                due_devices = (
                    db.query(FirewallDevice)
                    .filter(
                        FirewallDevice.sync_interval_hours.isnot(None),
                        FirewallDevice.sync_status != "running",
                    )
                    .all()
                )
                for dev in due_devices:
                    interval = dev.sync_interval_hours
                    if not interval or interval <= 0:
                        continue
                    is_due = (
                        dev.last_sync_at is None
                        or (now - dev.last_sync_at) >= timedelta(hours=interval)
                    )
                    if is_due:
                        auto_sync_logger.info(
                            "Scheduling auto-sync for device %s (%s) — interval %sh",
                            dev.id, dev.name, interval,
                        )
                        dev.sync_status = "running"
                        db.commit()
                        threading.Thread(
                            target=_run_device_sync_thread,
                            args=(dev.id,),
                            daemon=True,
                            name=f"autosync-{dev.id[:8]}",
                        ).start()
            finally:
                db.close()
        except Exception as exc:
            auto_sync_logger.error("Auto-sync scheduler error: %s", exc)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # SQLite (dev) bootstraps the schema directly; PostgreSQL/other engines are
    # managed by Alembic (`alembic upgrade head`, run before the app starts).
    if engine.dialect.name == "sqlite":
        Base.metadata.create_all(bind=engine)
    else:
        logger.info("Non-sqlite dialect '%s': schema managed by Alembic.", engine.dialect.name)

    # ── Schema migrations (additive-only, safe to re-run) ─────────────────────
    # These are SQLite-specific PRAGMA-based column adds for pre-existing dev
    # databases. On PostgreSQL (and other engines) create_all above already
    # builds the full current schema, so they are skipped — proper schema
    # evolution there is handled by Alembic.
    if engine.dialect.name != "sqlite":
        logger.info("Skipping SQLite PRAGMA migrations on '%s' dialect.", engine.dialect.name)
    else:
      try:
        with engine.connect() as _conn:
            from sqlalchemy import text as _text
            # Add device_id FK column to firewall_policies if not present
            _cols = [r[1] for r in _conn.execute(_text("PRAGMA table_info(firewall_policies)"))]
            if "device_id" not in _cols:
                _conn.execute(_text(
                    "ALTER TABLE firewall_policies ADD COLUMN device_id TEXT REFERENCES firewall_devices(id) ON DELETE SET NULL"
                ))
                _conn.commit()
                logger.info("Schema migration: added device_id column to firewall_policies.")
            if "complexity_breakdown" not in _cols:
                _conn.execute(_text(
                    "ALTER TABLE firewall_policies ADD COLUMN complexity_breakdown TEXT"
                ))
                _conn.commit()
                logger.info("Schema migration: added complexity_breakdown column to firewall_policies.")
            # Add analysis_run_id column to findings if not present
            _fcols = [r[1] for r in _conn.execute(_text("PRAGMA table_info(findings)"))]
            if "analysis_run_id" not in _fcols:
                _conn.execute(_text(
                    "ALTER TABLE findings ADD COLUMN analysis_run_id TEXT"
                ))
                _conn.commit()
                logger.info("Schema migration: added analysis_run_id column to findings.")
            # Add severity_snapshot column to analysis_runs if not present
            _rcols = [r[1] for r in _conn.execute(_text("PRAGMA table_info(analysis_runs)"))]
            if "severity_snapshot" not in _rcols:
                _conn.execute(_text(
                    "ALTER TABLE analysis_runs ADD COLUMN severity_snapshot TEXT"
                ))
                _conn.commit()
                logger.info("Schema migration: added severity_snapshot column to analysis_runs.")
      except Exception as _mig_exc:
        logger.error("Schema migration failed: %s", _mig_exc)

    # Recover any devices stuck in "running" state from a previous crashed process
    try:
        from app.database import SessionLocal
        from app.models.device import FirewallDevice
        _db = SessionLocal()
        try:
            stuck = _db.query(FirewallDevice).filter(FirewallDevice.sync_status == "running").all()
            if stuck:
                logger.warning(
                    "Recovering %d device(s) stuck in sync_status='running' from previous run.",
                    len(stuck),
                )
                for _dev in stuck:
                    _dev.sync_status = "error"
                _db.commit()
        finally:
            _db.close()
    except Exception as _exc:
        logger.error("Startup recovery failed: %s", _exc)

    # Load runtime origin-subnet allow-list from DB (overrides the env seed).
    try:
        from app.database import SessionLocal
        from app.models.settings import AppSettings
        _odb = SessionLocal()
        try:
            row = _odb.query(AppSettings).filter(AppSettings.key == "allowed_origin_subnets").first()
            if row and row.value:
                cidrs = [c.strip() for c in row.value.split(",") if c.strip()]
                origin_policy.set_subnets(cidrs)
                logger.info("Loaded allowed_origin_subnets from DB: %s", origin_policy.get_cidrs())
        finally:
            _odb.close()
    except Exception as _osub_exc:
        logger.error("Failed to load origin subnets from DB: %s", _osub_exc)

    task = asyncio.create_task(_auto_sync_loop())

    # Start syslog listener for real-time policy-change detection
    try:
        from app.services.syslog_listener import start_syslog_listener
        syslog_port = int(getattr(settings, "syslog_port", 5140))
        start_syslog_listener(port=syslog_port)
    except Exception as _syslog_exc:
        logger.warning("Syslog listener startup skipped: %s", _syslog_exc)

    # Warn if running in insecure dev mode
    if not settings.secret_key.strip():
        logger.warning(
            "⚠  SECRET_KEY is not set — credentials will be encrypted with a "
            "dev key. Set SECRET_KEY in .env for production deployments."
        )

    # ── Credential migration: encrypt any legacy plaintext credentials ─────────
    try:
        from app.database import SessionLocal
        from app.security.migrate_credentials import migrate_device_credentials
        _mdb = SessionLocal()
        try:
            _count = migrate_device_credentials(_mdb)
            if _count:
                logger.info(
                    "Startup credential migration: re-encrypted %d device record(s) "
                    "that had plaintext credentials stored.",
                    _count,
                )
        finally:
            _mdb.close()
    except Exception as _mig_exc:
        logger.error("Credential migration failed: %s", _mig_exc)

    # ── Bootstrap initial admin user (Phase 1 auth) ───────────────────────────
    try:
        from app.database import SessionLocal
        from app.models.user import User, ROLE_SYSTEM_ADMIN
        from app.security.passwords import hash_password
        _adb = SessionLocal()
        try:
            email = (settings.bootstrap_admin_email or "").strip().lower()
            password = (settings.bootstrap_admin_password or "").strip()
            user_count = _adb.query(User).count()
            if user_count == 0 and email and password:
                _adb.add(User(
                    email=email,
                    full_name="System Administrator",
                    password_hash=hash_password(password),
                    role=ROLE_SYSTEM_ADMIN,
                    is_active=True,
                ))
                _adb.commit()
                logger.info("Bootstrap: created initial system_admin user '%s'. Change the password after first login.", email)
            elif user_count == 0:
                logger.warning(
                    "No users exist and BOOTSTRAP_ADMIN_EMAIL/PASSWORD are not set — "
                    "login is unavailable until an admin user is created."
                )
        finally:
            _adb.close()
    except Exception as _boot_exc:
        logger.error("Admin bootstrap failed: %s", _boot_exc)

    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


# ── App ───────────────────────────────────────────────────────────────────────

# Interactive docs are exposed only when docs_enabled (non-production, or
# explicitly enabled). In production they (and the OpenAPI schema) return 404.
_docs_on = settings.docs_enabled
if not _docs_on:
    logger.info("Interactive API docs disabled (environment=%s).", settings.environment)

app = FastAPI(
    title="PolicyInsight",
    description="Multi-tenant firewall policy analysis and live monitoring for FortiGate and Check Point.",
    version="2.1.0",
    lifespan=lifespan,
    docs_url="/docs" if _docs_on else None,
    redoc_url="/redoc" if _docs_on else None,
    openapi_url="/openapi.json" if _docs_on else None,
)

# ── CORS — restricted to an explicit allow-list of origins ─────────────────────
# Session auth uses cookies, so cross-origin requests must send credentials.
# That requires an EXPLICIT origin list — the "*" wildcard is incompatible with
# credentialed requests and would be a security hole, so we drop it if present.
_allowed_origins = [
    o.strip() for o in settings.allowed_origins.split(",")
    if o.strip() and o.strip() != "*"
]
if not _allowed_origins:
    logger.warning(
        "ALLOWED_ORIGINS is empty (or only '*') — cross-origin browser requests "
        "will be rejected. Set ALLOWED_ORIGINS to your frontend URL(s)."
    )

# Optional: allow whole IP subnets (CIDRs) as origins, for LAN access.
import ipaddress as _ipaddress
from urllib.parse import urlparse as _urlparse

from app.security import origin_policy

# Seed the runtime subnet allow-list from env (a DB override, if set, is loaded
# during startup in lifespan). CSRF consults origin_policy live; CORS builds its
# regex once below from this initial set.
_env_cidrs = [c.strip() for c in (settings.allowed_origin_subnets or "").split(",") if c.strip()]
_invalid = origin_policy.set_subnets(_env_cidrs)
if _invalid:
    logger.warning("Ignoring invalid ALLOWED_ORIGIN_SUBNETS entries: %s", _invalid)
_allowed_networks = [_ipaddress.ip_network(c, strict=False) for c in origin_policy.get_cidrs()]


def _cidr_to_host_regex(net) -> Optional[str]:
    """Build a host regex for an octet-aligned IPv4 CIDR (/8,/16,/24,/32)."""
    if net.version != 4 or net.prefixlen % 8 != 0:
        logger.warning(
            "Subnet %s is not octet-aligned; CORS regex skipped (CSRF still "
            "honors it via membership).", net,
        )
        return None
    fixed = net.prefixlen // 8
    octets = str(net.network_address).split(".")
    parts = [octets[i] if i < fixed else r"\d{1,3}" for i in range(4)]
    return r"\.".join(parts)


_origin_regex = None
_host_regexes = [r for net in _allowed_networks if (r := _cidr_to_host_regex(net))]
if _host_regexes:
    _origin_regex = r"^https?://(" + "|".join(_host_regexes) + r")(:\d+)?$"
    logger.info("CORS/CSRF subnet origin regex enabled: %s", _origin_regex)


_origin_in_allowed_subnet = origin_policy.origin_in_allowed_subnet


app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_origin_regex=_origin_regex,   # whole-subnet origins, when configured
    allow_credentials=True,       # cookies ride along on cross-origin requests
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Accept", "Authorization"],
)


# ── Security headers middleware ───────────────────────────────────────────────

# Swagger/ReDoc load their bundle + fonts from jsdelivr; the SPA pulls webfonts
# from Google Fonts. Allow exactly those origins and nothing else.
_CSP_DOCS = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "img-src 'self' data: https://fastapi.tiangolo.com; "
    "font-src 'self' data:; "
    "worker-src 'self' blob:; "
    "frame-ancestors 'none'"
)
# App CSP. 'unsafe-inline'/'unsafe-eval' are required by the Vite dev server
# (HMR injects inline scripts and uses eval) and inline styles; connect-src
# allows the HMR websocket. Tighten script-src for a production build behind a
# real bundler if desired.
_CSP_APP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src 'self' data: https://fonts.gstatic.com; "
    "img-src 'self' data:; "
    "connect-src 'self' ws: wss:; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'"
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    # HSTS: browsers ignore this over plain HTTP, so it's safe to always send;
    # it takes effect once the app is served over TLS.
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    # Disable powerful browser features the app never uses.
    response.headers["Permissions-Policy"] = (
        "accelerometer=(), camera=(), geolocation=(), gyroscope=(), "
        "magnetometer=(), microphone=(), payment=(), usb=()"
    )
    # Content-Security-Policy — docs pages need a looser policy than the app.
    path = request.url.path
    if path in {"/docs", "/redoc"} or path.startswith("/redoc") or path == "/openapi.json":
        response.headers["Content-Security-Policy"] = _CSP_DOCS
    else:
        response.headers["Content-Security-Policy"] = _CSP_APP
    # NOTE: uvicorn writes its own `Server: uvicorn` banner at the protocol
    # layer, after ASGI middleware runs, so it can't be stripped here. Suppress
    # it at launch with `uvicorn --no-server-header` (or hide it behind a
    # reverse proxy) in production.
    return response


# ── CSRF protection middleware ────────────────────────────────────────────────

# Session auth rides on a cookie the browser attaches automatically, so a
# malicious third-party page could forge state-changing requests (CSRF). The
# cookie is already SameSite=Lax (which blocks cross-site mutating requests in
# modern browsers); this middleware is defense-in-depth on top of that: every
# mutating request must carry an Origin (or, failing that, a Referer) that
# matches an allow-listed origin or the app's own origin. Safe/idempotent
# methods are never checked.
_CSRF_SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}
_ALLOWED_ORIGIN_SET = set(_allowed_origins)


def _request_self_origin(request: Request) -> str:
    """The app's own origin (scheme://host[:port]) — a same-origin request is
    never a CSRF vector. Honors X-Forwarded-* so it works behind a TLS proxy.
    """
    fwd_proto = request.headers.get("x-forwarded-proto")
    scheme = fwd_proto.split(",")[0].strip() if fwd_proto else request.url.scheme
    host = request.headers.get("x-forwarded-host") or request.headers.get("host")
    return f"{scheme}://{host}" if host else ""


@app.middleware("http")
async def csrf_protect(request: Request, call_next):
    if request.method not in _CSRF_SAFE_METHODS and request.url.path.startswith("/api/"):
        origin = request.headers.get("origin")
        if not origin:
            # No Origin header — derive one from Referer if present.
            referer = request.headers.get("referer")
            if referer:
                from urllib.parse import urlparse
                p = urlparse(referer)
                if p.scheme and p.netloc:
                    origin = f"{p.scheme}://{p.netloc}"
        # A browser performing a CSRF attack always sends an Origin on a
        # cross-site mutating fetch/XHR. If one is present, it must be trusted.
        # (Absent Origin+Referer ⇒ not a browser CSRF vector — e.g. server-side
        # API client — so we let endpoint auth handle it.)
        if origin:
            if (origin not in _ALLOWED_ORIGIN_SET
                    and origin != _request_self_origin(request)
                    and not _origin_in_allowed_subnet(origin)):
                return JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content={"detail": "Cross-origin request rejected (CSRF protection)."},
                )
    return await call_next(request)


# ── Session authentication middleware ─────────────────────────────────────────

# Paths reachable without an authenticated session.
_PUBLIC_PATHS = {"/api/health"}

@app.middleware("http")
async def session_auth_middleware(request: Request, call_next):
    """Coarse, defense-in-depth gate: every protected path requires a valid
    server-side session. Per-endpoint dependencies (get_current_user /
    require_capability / require_customer_access) still perform the real
    fine-grained authorization — this middleware just ensures no endpoint is
    reachable anonymously, even one that forgot to declare a dependency.
    """
    path = request.url.path

    # Always-public paths.
    if path in _PUBLIC_PATHS:
        return await call_next(request)
    # Auth endpoints manage their own login/logout/session flow.
    if path.startswith("/api/auth/"):
        return await call_next(request)
    # OPTIONS preflight — let CORS middleware handle.
    if request.method == "OPTIONS":
        return await call_next(request)

    # Everything else (API routes + docs) requires a valid session cookie.
    from app.security.identity import SESSION_COOKIE_NAME, _resolve_user
    from app.database import SessionLocal

    raw_token = request.cookies.get(SESSION_COOKIE_NAME)
    if not raw_token:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"detail": "Authentication required"},
        )
    _db = SessionLocal()
    try:
        user = _resolve_user(_db, raw_token)
    finally:
        _db.close()
    if user is None:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"detail": "Authentication required"},
        )
    return await call_next(request)


# ── Rate limiting middleware (outermost) ──────────────────────────────────────

# Registered last so it runs FIRST — abusive bursts are rejected before they
# reach auth/session resolution or DB work.
from app.security.ratelimit import _RateLimiter

_api_rate_limiter = _RateLimiter(int(getattr(settings, "rate_limit_per_minute", 300) or 0))


def _client_key(request: Request) -> str:
    # Honor a proxy's forwarded client IP when present, else the socket peer.
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    if request.url.path.startswith("/api/") and request.method != "OPTIONS":
        allowed, retry_after = _api_rate_limiter.allow(_client_key(request))
        if not allowed:
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"detail": "Rate limit exceeded. Slow down and retry shortly."},
                headers={"Retry-After": str(retry_after)},
            )
    return await call_next(request)


# ── Routers ───────────────────────────────────────────────────────────────────

app.include_router(auth_api.router)
app.include_router(users_api.router)
app.include_router(customers.router)
app.include_router(devices.router)
app.include_router(revisions.router)
app.include_router(upload.router)
app.include_router(policies.router)
app.include_router(findings.router)
app.include_router(objects.router)
app.include_router(reports.router)
app.include_router(settings_api.router)
app.include_router(compliance.router)
app.include_router(audit_api.router)
app.include_router(cleanup_api.router)
app.include_router(changes_api.router)


@app.get("/api/health")
def health():
    return {"status": "ok", "version": "2.1.0"}


@app.get("/api/recommendations")
def list_recommendations():
    """Return the full centralised recommendation library.
    Used by reports and the frontend to render consistent guidance per finding type.
    """
    from app.analysis.recommendation_library import all_types
    return {"recommendations": all_types()}


@app.get("/api/recommendations/{finding_type}")
def get_recommendation(finding_type: str):
    """Return the standard recommendation for a specific finding type."""
    from app.analysis.recommendation_library import get as _get
    return {"finding_type": finding_type, "recommendation": _get(finding_type)}


@app.get("/api/remediation")
def get_remediation(finding_type: str, vendor: str = None):
    """Per-vendor review/remediation guidance for a finding type (read-only)."""
    from app.analysis.remediation_templates import get as _get_rem
    return _get_rem(vendor, finding_type)
