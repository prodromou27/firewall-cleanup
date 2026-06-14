"""FastAPI application entry point."""
import asyncio
import logging
import logging.config
import threading
from contextlib import asynccontextmanager
from datetime import datetime, timedelta

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from app.config import settings
from app.database import engine, Base
from app.api import upload, policies, findings, objects, reports, settings as settings_api
from app.api import customers, devices, revisions, compliance, auth as auth_api, users as users_api
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
    Base.metadata.create_all(bind=engine)

    # ── Schema migrations (additive-only, safe to re-run) ─────────────────────
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

app = FastAPI(
    title="PolicyInsight",
    description="Multi-tenant firewall policy analysis and live monitoring for FortiGate and Check Point.",
    version="2.1.0",
    lifespan=lifespan,
    # Disable automatic docs exposure in production (can be re-enabled per env)
    docs_url="/docs",
    redoc_url="/redoc",
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

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
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
