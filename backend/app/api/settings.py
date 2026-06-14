"""Settings API."""
import json
import os
import shutil
import tempfile
from datetime import datetime
from fastapi import APIRouter, Depends
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.settings import AppSettings
from app.config import settings as app_settings
from app.models.user import User
from app.security.identity import get_current_user, require_capability
from app.security.rbac import CAP_MANAGE_SETTINGS, CAP_DOWNLOAD_BACKUP
from pydantic import BaseModel
from typing import Optional, List

router = APIRouter(prefix="/api/settings", tags=["settings"])

_WEBHOOK_EVENTS_ALL = ["sync_completed", "sync_error", "high_finding"]


class SettingsUpdate(BaseModel):
    inactivity_threshold_low: Optional[int] = None
    inactivity_threshold_medium: Optional[int] = None
    inactivity_threshold_high: Optional[int] = None
    # Webhook notifications
    webhook_url: Optional[str] = None
    webhook_events: Optional[List[str]] = None  # list of event names to notify on
    # NVD API key (optional, increases rate limits)
    nvd_api_key: Optional[str] = None
    # Analysis thresholds (stored in DB, override config defaults)
    severity_critical_threshold: Optional[int] = None
    severity_high_threshold: Optional[int] = None
    severity_medium_threshold: Optional[int] = None
    severity_low_threshold: Optional[int] = None


_THRESHOLD_KEYS = [
    "inactivity_threshold_low",
    "inactivity_threshold_medium",
    "inactivity_threshold_high",
    "severity_critical_threshold",
    "severity_high_threshold",
    "severity_medium_threshold",
    "severity_low_threshold",
]


def _get_syslog_status() -> dict:
    try:
        from app.services.syslog_listener import get_listener_status
        from app.config import settings as _s
        port = int(getattr(_s, "syslog_port", 5140))
        return get_listener_status(port)
    except Exception:
        return {"active": False, "port": 5140}


def _get_db_setting(db: Session, key: str, default=None):
    row = db.query(AppSettings).filter(AppSettings.key == key).first()
    if row and row.value:
        return row.value
    return default


def _set_db_setting(db: Session, key: str, value: str):
    row = db.query(AppSettings).filter(AppSettings.key == key).first()
    if row:
        row.value = value
    else:
        db.add(AppSettings(key=key, value=value))
    db.commit()


def _get_threshold(db: Session, key: str, default: int) -> int:
    """Return DB-stored threshold override, or fall back to config default."""
    raw = _get_db_setting(db, key)
    if raw is not None:
        try:
            return int(raw)
        except (ValueError, TypeError):
            pass
    return default


@router.get("")
def get_settings(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    webhook_events_raw = _get_db_setting(db, "webhook_events")
    try:
        webhook_events = json.loads(webhook_events_raw) if webhook_events_raw else _WEBHOOK_EVENTS_ALL
    except Exception:
        webhook_events = _WEBHOOK_EVENTS_ALL

    # Thresholds: DB-stored overrides take precedence over config file defaults
    inact_low    = _get_threshold(db, "inactivity_threshold_low",    app_settings.inactivity_threshold_low)
    inact_medium = _get_threshold(db, "inactivity_threshold_medium", app_settings.inactivity_threshold_medium)
    inact_high   = _get_threshold(db, "inactivity_threshold_high",   app_settings.inactivity_threshold_high)
    sev_critical = _get_threshold(db, "severity_critical_threshold", app_settings.severity_critical_threshold)
    sev_high     = _get_threshold(db, "severity_high_threshold",     app_settings.severity_high_threshold)
    sev_medium   = _get_threshold(db, "severity_medium_threshold",   app_settings.severity_medium_threshold)
    sev_low      = _get_threshold(db, "severity_low_threshold",      app_settings.severity_low_threshold)

    # Security status (no sensitive values exposed)
    auth_enabled = bool(app_settings.api_key.strip())
    secret_set   = bool(app_settings.secret_key.strip())

    return {
        "inactivity_threshold_low":    inact_low,
        "inactivity_threshold_medium": inact_medium,
        "inactivity_threshold_high":   inact_high,
        "risk_weights": {
            "any_source":     app_settings.risk_any_source,
            "any_destination": app_settings.risk_any_destination,
            "any_service":    app_settings.risk_any_service,
            "risky_service":  app_settings.risk_risky_service,
            "no_logging":     app_settings.risk_no_logging,
            "disabled":       app_settings.risk_disabled,
            "no_hits_180d":   app_settings.risk_no_hits_180d,
            "duplicate":      app_settings.risk_duplicate,
            "fully_shadowed": app_settings.risk_fully_shadowed,
            "temp_keyword":   app_settings.risk_temp_keyword,
        },
        "severity_thresholds": {
            "critical": sev_critical,
            "high":     sev_high,
            "medium":   sev_medium,
            "low":      sev_low,
        },
        "temp_keywords":    app_settings.temp_keywords,
        "risky_services":   app_settings.risky_services,
        "internal_networks": app_settings.internal_networks,
        # Webhook settings (stored in DB)
        "webhook_url":              _get_db_setting(db, "webhook_url", ""),
        "webhook_events":           webhook_events,
        "webhook_events_available": _WEBHOOK_EVENTS_ALL,
        "nvd_api_key_set":          bool(_get_db_setting(db, "nvd_api_key")),
        # Syslog listener status
        "syslog_listener": _get_syslog_status(),
        # Security posture
        "security": {
            "auth_enabled":     auth_enabled,
            "secret_key_set":   secret_set,
            "api_key_prefix":   app_settings.api_key[:8] + "…" if auth_enabled else None,
        },
        # App info
        "app_version": "2.1.0",
    }


@router.patch("")
def update_settings(
    body: SettingsUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(require_capability(CAP_MANAGE_SETTINGS)),
):
    updated = []

    if body.webhook_url is not None:
        _set_db_setting(db, "webhook_url", body.webhook_url.strip())
        updated.append("webhook_url")

    if body.webhook_events is not None:
        valid = [e for e in body.webhook_events if e in _WEBHOOK_EVENTS_ALL]
        _set_db_setting(db, "webhook_events", json.dumps(valid))
        updated.append("webhook_events")

    if body.nvd_api_key is not None:
        _set_db_setting(db, "nvd_api_key", body.nvd_api_key.strip())
        updated.append("nvd_api_key")

    # Threshold overrides stored in DB
    for key in _THRESHOLD_KEYS:
        val = getattr(body, key, None)
        if val is not None:
            if val < 0:
                from fastapi import HTTPException
                raise HTTPException(status_code=400, detail=f"{key} must be non-negative")
            _set_db_setting(db, key, str(val))
            updated.append(key)

    return {"updated": updated, "message": "Settings saved"}


# ── Backup endpoint ────────────────────────────────────────────────────────────

@router.get("/backup/database")
def download_database_backup(
    user: User = Depends(require_capability(CAP_DOWNLOAD_BACKUP)),
):
    """
    Stream a copy of the SQLite database for backup purposes.
    The file is copied to a temp path first so there's no read contention.
    """
    db_url = app_settings.database_url
    if not db_url.startswith("sqlite:///"):
        return JSONResponse(status_code=400, content={"detail": "Backup only supported for SQLite databases."})

    db_path = db_url.replace("sqlite:///", "")
    if not os.path.exists(db_path):
        return JSONResponse(status_code=404, content={"detail": "Database file not found."})

    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    try:
        shutil.copy2(db_path, tmp.name)
    except Exception as e:
        return JSONResponse(status_code=500, content={"detail": f"Backup failed: {e}"})

    filename = f"policyinsight_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
    return FileResponse(
        tmp.name,
        media_type="application/octet-stream",
        filename=filename,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/backup/settings")
def export_settings_json(
    db: Session = Depends(get_db),
    user: User = Depends(require_capability(CAP_DOWNLOAD_BACKUP)),
):
    """Export all DB-stored settings as a JSON file for backup/migration."""
    rows = db.query(AppSettings).all()
    data = {
        "exported_at": datetime.now().isoformat(),
        "settings": {r.key: r.value for r in rows},
    }
    buf_bytes = json.dumps(data, indent=2).encode()
    filename = f"policyinsight_settings_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    from fastapi.responses import Response
    return Response(
        content=buf_bytes,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/backup/settings/restore")
def import_settings_json(
    payload: dict,
    db: Session = Depends(get_db),
    user: User = Depends(require_capability(CAP_MANAGE_SETTINGS)),
):
    """
    Restore DB settings from a previously exported JSON payload.
    Payload format: { "settings": { "key": "value", ... } }
    """
    settings_data = payload.get("settings", {})
    if not isinstance(settings_data, dict):
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail="Invalid payload: 'settings' must be an object.")

    restored = 0
    for key, value in settings_data.items():
        if isinstance(value, str) and key:
            _set_db_setting(db, key, value)
            restored += 1

    return {"restored": restored, "message": f"Restored {restored} settings entries."}
