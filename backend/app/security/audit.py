"""
Structured audit logging for security-relevant events.

Every state-changing operation (create/update/delete device/customer,
sync trigger, credential access) is written to a dedicated audit logger.
Configure handlers in your logging config to ship these to a SIEM or
write to a separate audit.log file.

Usage:
    from app.security.audit import audit_log
    audit_log("device.create", device_id=dev.id, customer_id=dev.customer_id, name=dev.name)
"""
import json
import logging
from datetime import datetime, timezone

_audit_logger = logging.getLogger("audit")


def _derive_target(event: str, kwargs: dict):
    """Best-effort (target_type, target_id) for filtering/grouping."""
    if kwargs.get("target_user_id"):
        return "user", kwargs["target_user_id"]
    if kwargs.get("policy_id"):
        return "policy", kwargs["policy_id"]
    if kwargs.get("device_id"):
        return "device", kwargs["device_id"]
    if event.startswith("customer.") and kwargs.get("customer_id"):
        return "customer", kwargs["customer_id"]
    if event.startswith("user.") and kwargs.get("user_id"):
        return "user", kwargs["user_id"]
    return None, None


def _persist(event: str, kwargs: dict) -> None:
    """Append the event to the audit_events table. Best-effort: any failure is
    swallowed (and logged) so auditing never breaks the originating request.
    Uses its own short-lived session, independent of the caller's transaction.
    """
    try:
        from app.database import SessionLocal
        from app.models.audit import AuditEvent

        target_type, target_id = _derive_target(event, kwargs)
        db = SessionLocal()
        try:
            db.add(AuditEvent(
                event=event,
                user_id=kwargs.get("user_id"),
                actor_email=kwargs.get("email"),
                customer_id=kwargs.get("customer_id"),
                source_ip=kwargs.get("source_ip"),
                target_type=target_type,
                target_id=target_id,
                detail=json.dumps(kwargs, default=str),
            ))
            db.commit()
        finally:
            db.close()
    except Exception as exc:  # pragma: no cover — never let auditing break a request
        _audit_logger.warning(json.dumps({"event": "audit.persist_failed", "error": str(exc)}))


def audit_log(event: str, **kwargs) -> None:
    """
    Emit a structured audit log entry — to the audit logger (file/SIEM) and to
    the queryable audit_events table.

    Args:
        event: dot-separated event name, e.g. "device.create", "sync.trigger"
        **kwargs: arbitrary context — ids, names, IP addresses, etc.
                  NEVER pass raw credential values here.
    """
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": event,
        **kwargs,
    }
    _audit_logger.info(json.dumps(record))
    _persist(event, kwargs)
