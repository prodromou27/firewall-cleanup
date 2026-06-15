"""
AuditEvent — persistent, queryable record of security-relevant actions.

Every state-changing operation is recorded here in addition to the audit log
file, so the activity trail is visible in the application (for compliance /
accountability) and survives log rotation. Records are append-only: the
application never updates or deletes audit rows.
"""
from sqlalchemy import Column, String, DateTime, Text, Index
from sqlalchemy.sql import func
import uuid

from app.database import Base


def _uuid():
    return str(uuid.uuid4())


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id = Column(String, primary_key=True, default=_uuid)
    ts = Column(DateTime, server_default=func.now(), nullable=False, index=True)
    event = Column(String, nullable=False, index=True)   # e.g. "policy.reanalyze"

    # Actor — denormalised email kept so the trail is readable even if the
    # user record is later removed.
    user_id = Column(String, nullable=True, index=True)
    actor_email = Column(String, nullable=True)

    # Tenant scope (nullable for tenant-less events such as auth.login).
    customer_id = Column(String, nullable=True, index=True)

    source_ip = Column(String, nullable=True)

    # Best-effort target of the action, for filtering/grouping.
    target_type = Column(String, nullable=True)   # "policy" | "device" | "user" | "customer"
    target_id = Column(String, nullable=True)

    # Full structured context (JSON-encoded kwargs), never contains secrets.
    detail = Column(Text, nullable=True)

    __table_args__ = (
        Index("ix_audit_events_ts_event", "ts", "event"),
    )
