"""
Webhook Notification Service
==============================
Sends structured event payloads to a configured webhook URL when key events
occur (sync completed, high finding detected, sync error, etc.).

Supports any HTTP webhook receiver: Slack, Teams, generic, custom SOC endpoints.

Webhook payload structure:
    {
      "event":      "sync_completed" | "sync_error" | "high_finding" | "analysis_completed",
      "timestamp":  "2024-01-01T12:00:00Z",
      "platform":   "PolicyInsight",
      "data":       { ... event-specific ... }
    }

SAFETY: Notifications are fire-and-forget. Failure does not affect core analysis.
"""
from __future__ import annotations

import json
import logging
import threading
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)


def _get_webhook_url(db) -> Optional[str]:
    """Read the webhook URL from app settings."""
    try:
        from app.models.settings import AppSettings
        row = db.query(AppSettings).filter(AppSettings.key == "webhook_url").first()
        return (row.value or "").strip() if row else None
    except Exception:
        return None


def _get_webhook_events(db) -> set:
    """Read enabled webhook events from settings."""
    try:
        from app.models.settings import AppSettings
        row = db.query(AppSettings).filter(AppSettings.key == "webhook_events").first()
        if row and row.value:
            return set(json.loads(row.value))
    except Exception:
        pass
    return {"sync_completed", "sync_error", "high_finding"}


def _fire_webhook(url: str, payload: dict) -> None:
    """POST payload to webhook URL. Runs in a daemon thread."""
    try:
        import httpx
        with httpx.Client(timeout=10) as client:
            resp = client.post(
                url,
                json=payload,
                headers={"Content-Type": "application/json", "User-Agent": "PolicyInsight/2.1"},
            )
            if resp.status_code >= 300:
                logger.warning("Webhook returned %d: %s", resp.status_code, resp.text[:200])
            else:
                logger.debug("Webhook delivered: event=%s status=%d", payload.get("event"), resp.status_code)
    except Exception as exc:
        logger.warning("Webhook delivery failed (non-fatal): %s", exc)


def _send_async(url: str, payload: dict) -> None:
    """Send webhook in a background thread so it never blocks the main flow."""
    t = threading.Thread(target=_fire_webhook, args=(url, payload), daemon=True)
    t.start()


def _base_payload(event: str, data: dict) -> dict:
    return {
        "event":     event,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "platform":  "PolicyInsight",
        "version":   "2.1",
        "data":      data,
    }


# ── Public notification senders ──────────────────────────────────────────────

def notify_sync_completed(
    db,
    device_id: str,
    device_name: str,
    vendor: str,
    customer_name: str,
    policy_id: str,
    rule_count: int,
    finding_count: int,
    high_finding_count: int,
    change_summary: str,
) -> None:
    """Fire after a successful live sync."""
    url = _get_webhook_url(db)
    if not url:
        return
    events = _get_webhook_events(db)
    if "sync_completed" not in events:
        return

    payload = _base_payload("sync_completed", {
        "device_id":          device_id,
        "device_name":        device_name,
        "vendor":             vendor,
        "customer":           customer_name,
        "policy_id":          policy_id,
        "rule_count":         rule_count,
        "finding_count":      finding_count,
        "high_finding_count": high_finding_count,
        "change_summary":     change_summary,
    })
    _send_async(url, payload)


def notify_sync_error(
    db,
    device_id: str,
    device_name: str,
    vendor: str,
    customer_name: str,
    error_message: str,
) -> None:
    """Fire when a live sync fails."""
    url = _get_webhook_url(db)
    if not url:
        return
    events = _get_webhook_events(db)
    if "sync_error" not in events:
        return

    payload = _base_payload("sync_error", {
        "device_id":    device_id,
        "device_name":  device_name,
        "vendor":       vendor,
        "customer":     customer_name,
        "error":        error_message,
    })
    _send_async(url, payload)


def notify_high_findings(
    db,
    policy_id: str,
    firewall_name: str,
    customer_name: str,
    high_count: int,
    new_high_count: int,
    top_findings: list,
) -> None:
    """Fire when analysis produces new high-severity findings."""
    url = _get_webhook_url(db)
    if not url:
        return
    events = _get_webhook_events(db)
    if "high_finding" not in events or new_high_count == 0:
        return

    payload = _base_payload("high_finding", {
        "policy_id":       policy_id,
        "firewall_name":   firewall_name,
        "customer":        customer_name,
        "high_count":      high_count,
        "new_high_count":  new_high_count,
        "top_findings":    top_findings[:5],  # send top 5 details
    })
    _send_async(url, payload)
