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


def audit_log(event: str, **kwargs) -> None:
    """
    Emit a structured audit log entry.

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
