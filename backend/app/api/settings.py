"""Settings API."""
import json
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.settings import AppSettings
from app.config import settings as app_settings
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


@router.get("")
def get_settings(db: Session = Depends(get_db)):
    webhook_events_raw = _get_db_setting(db, "webhook_events")
    try:
        webhook_events = json.loads(webhook_events_raw) if webhook_events_raw else _WEBHOOK_EVENTS_ALL
    except Exception:
        webhook_events = _WEBHOOK_EVENTS_ALL

    return {
        "inactivity_threshold_low": app_settings.inactivity_threshold_low,
        "inactivity_threshold_medium": app_settings.inactivity_threshold_medium,
        "inactivity_threshold_high": app_settings.inactivity_threshold_high,
        "risk_weights": {
            "any_source": app_settings.risk_any_source,
            "any_destination": app_settings.risk_any_destination,
            "any_service": app_settings.risk_any_service,
            "risky_service": app_settings.risk_risky_service,
            "no_logging": app_settings.risk_no_logging,
            "disabled": app_settings.risk_disabled,
            "no_hits_180d": app_settings.risk_no_hits_180d,
            "duplicate": app_settings.risk_duplicate,
            "fully_shadowed": app_settings.risk_fully_shadowed,
            "temp_keyword": app_settings.risk_temp_keyword,
        },
        "severity_thresholds": {
            "high": app_settings.severity_high_threshold,
            "medium": app_settings.severity_medium_threshold,
            "low": app_settings.severity_low_threshold,
        },
        "temp_keywords": app_settings.temp_keywords,
        "risky_services": app_settings.risky_services,
        "internal_networks": app_settings.internal_networks,
        # Webhook settings (stored in DB)
        "webhook_url":    _get_db_setting(db, "webhook_url", ""),
        "webhook_events": webhook_events,
        "webhook_events_available": _WEBHOOK_EVENTS_ALL,
        "nvd_api_key_set": bool(_get_db_setting(db, "nvd_api_key")),
        # Syslog listener status
        "syslog_listener": _get_syslog_status(),
    }


@router.patch("")
def update_settings(body: SettingsUpdate, db: Session = Depends(get_db)):
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

    return {"updated": updated, "message": "Settings saved"}
