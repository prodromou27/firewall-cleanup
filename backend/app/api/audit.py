"""Audit trail API — read-only, RBAC-gated, tenant-isolated activity log."""
import json
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.audit import AuditEvent
from app.models.user import User
from app.security.identity import require_capability, require_customer_access, accessible_customer_ids
from app.security.rbac import CAP_VIEW_AUDIT

router = APIRouter(prefix="/api/audit", tags=["audit"])


def _parse_dt(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        # Accept date (YYYY-MM-DD) or full ISO timestamp.
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid datetime value: {value}")


def _serialize(e: AuditEvent) -> dict:
    try:
        detail = json.loads(e.detail) if e.detail else {}
    except (ValueError, TypeError):
        detail = {}
    return {
        "id": e.id,
        "ts": e.ts.isoformat() if e.ts else None,
        "event": e.event,
        "user_id": e.user_id,
        "actor_email": e.actor_email,
        "customer_id": e.customer_id,
        "source_ip": e.source_ip,
        "target_type": e.target_type,
        "target_id": e.target_id,
        "detail": detail,
    }


@router.get("")
def list_audit_events(
    event: Optional[str] = None,
    actor: Optional[str] = None,
    customer_id: Optional[str] = None,
    since: Optional[str] = None,
    until: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    user: User = Depends(require_capability(CAP_VIEW_AUDIT)),
):
    """Return audit events, newest first.

    Tenant isolation: global roles see everything; a tenant admin sees events
    scoped to customers they may access, plus their own actions. Filters:
    event (prefix), actor (email substring), customer_id, since/until (ISO).
    """
    q = db.query(AuditEvent)

    allowed = accessible_customer_ids(db, user)  # None == all customers
    if allowed is not None:
        # Non-global: events for accessible customers OR performed by this user.
        from sqlalchemy import or_
        scope = [AuditEvent.user_id == user.id]
        if allowed:
            scope.append(AuditEvent.customer_id.in_(allowed))
        q = q.filter(or_(*scope))

    if event:
        q = q.filter(AuditEvent.event.like(f"{event}%"))
    if actor:
        q = q.filter(AuditEvent.actor_email.ilike(f"%{actor}%"))
    if customer_id:
        require_customer_access(db, user, customer_id)
        q = q.filter(AuditEvent.customer_id == customer_id)
    since_dt = _parse_dt(since)
    if since_dt:
        q = q.filter(AuditEvent.ts >= since_dt)
    until_dt = _parse_dt(until)
    if until_dt:
        q = q.filter(AuditEvent.ts <= until_dt)

    total = q.count()
    rows = (
        q.order_by(AuditEvent.ts.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "events": [_serialize(e) for e in rows],
    }
