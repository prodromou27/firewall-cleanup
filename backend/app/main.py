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
from app.api import customers, devices, revisions, compliance
from app.security.auth import require_api_key
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

    # Warn if running in insecure dev mode
    if not settings.api_key.strip():
        logger.warning(
            "⚠  API_KEY is not set — authentication is DISABLED. "
            "Set API_KEY in .env before exposing this server on a network."
        )
    if not settings.secret_key.strip():
        logger.warning(
            "⚠  SECRET_KEY is not set — credentials will be encrypted with a "
            "dev key. Set SECRET_KEY in .env for production deployments."
        )

    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Firewall Policy Cleanup & Monitoring Assistant",
    description="Multi-tenant firewall policy analysis and live monitoring for FortiGate and Check Point.",
    version="2.1.0",
    lifespan=lifespan,
    # Disable automatic docs exposure in production (can be re-enabled per env)
    docs_url="/docs",
    redoc_url="/redoc",
)

# ── CORS — restricted to configured origins only ──────────────────────────────
_allowed_origins = [o.strip() for o in settings.allowed_origins.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=False,      # credentials=True + wildcard is forbidden by browsers anyway
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "X-API-Key", "Accept", "Authorization"],
)


# ── Security headers middleware ───────────────────────────────────────────────

@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    # Remove server banner
    if "server" in response.headers:
        del response.headers["server"]
    return response


# ── API key authentication middleware ─────────────────────────────────────────

_PUBLIC_PATHS = {"/api/health"}

@app.middleware("http")
async def api_key_middleware(request: Request, call_next):
    """Enforce API key on all non-public paths when API_KEY is configured."""
    configured_key = settings.api_key.strip()
    if not configured_key:
        # Auth disabled — dev mode
        return await call_next(request)

    path = request.url.path
    # Health check is always public
    if path in _PUBLIC_PATHS:
        return await call_next(request)
    # API docs — allow only when accessed with a valid key OR in dev mode (no key configured)
    if path in {"/docs", "/openapi.json", "/redoc"} or path.startswith("/redoc"):
        provided_key = request.headers.get("X-API-Key", "")
        if provided_key == configured_key:
            return await call_next(request)
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"detail": "API documentation requires a valid X-API-Key header"},
        )

    # OPTIONS preflight — let CORS middleware handle
    if request.method == "OPTIONS":
        return await call_next(request)

    provided_key = request.headers.get("X-API-Key", "")
    if provided_key != configured_key:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"detail": "Invalid or missing API key"},
        )
    return await call_next(request)


# ── Routers ───────────────────────────────────────────────────────────────────

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
