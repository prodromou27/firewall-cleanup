"""Policy revision history — change tracking (Tufin-style)."""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.revision import PolicyRevision
from app.models.policy import FirewallPolicy
from app.models.device import FirewallDevice
from app.models.user import User
from app.security.identity import (
    get_current_user, require_customer_access, accessible_customer_ids,
)

router = APIRouter(prefix="/api/revisions", tags=["revisions"])


def _revision_customer_id(r: PolicyRevision, db: Session) -> Optional[str]:
    """Resolve the owning customer for a revision via its policy or device."""
    if r.policy_id:
        p = db.query(FirewallPolicy).filter(FirewallPolicy.id == r.policy_id).first()
        if p:
            return p.customer_id
    if r.device_id:
        d = db.query(FirewallDevice).filter(FirewallDevice.id == r.device_id).first()
        if d:
            return d.customer_id
    return None


@router.get("")
def list_revisions(
    policy_id: Optional[str] = None,
    device_id: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    q = db.query(PolicyRevision)
    if policy_id:
        p = db.query(FirewallPolicy).filter(FirewallPolicy.id == policy_id).first()
        if not p:
            raise HTTPException(status_code=404, detail="Policy not found")
        require_customer_access(db, user, p.customer_id)
        q = q.filter(PolicyRevision.policy_id == policy_id)
    if device_id:
        d = db.query(FirewallDevice).filter(FirewallDevice.id == device_id).first()
        if not d:
            raise HTTPException(status_code=404, detail="Device not found")
        require_customer_access(db, user, d.customer_id)
        q = q.filter(PolicyRevision.device_id == device_id)

    # Per-user tenant filtering before the limit so result size is predictable.
    allowed = accessible_customer_ids(db, user)  # None => global (all)
    if allowed is not None and not (policy_id or device_id):
        if not allowed:
            return []
        policy_ids = [pid for (pid,) in db.query(FirewallPolicy.id).filter(FirewallPolicy.customer_id.in_(allowed)).all()]
        device_ids = [did for (did,) in db.query(FirewallDevice.id).filter(FirewallDevice.customer_id.in_(allowed)).all()]
        q = q.filter(
            (PolicyRevision.policy_id.in_(policy_ids)) |
            (PolicyRevision.device_id.in_(device_ids))
        )

    revisions = q.order_by(PolicyRevision.synced_at.desc()).limit(limit).all()
    return [_rev_dict(r) for r in revisions]


@router.get("/{revision_id}")
def get_revision(
    revision_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    r = db.query(PolicyRevision).filter(PolicyRevision.id == revision_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Revision not found")
    require_customer_access(db, user, _revision_customer_id(r, db))
    return _rev_dict(r, include_detail=True)


def _rev_dict(r: PolicyRevision, include_detail: bool = False) -> dict:
    d = {
        "id": r.id,
        "policy_id": r.policy_id,
        "device_id": r.device_id,
        "revision_number": r.revision_number,
        "synced_at": r.synced_at.isoformat() if r.synced_at else None,
        "sync_source": r.sync_source,
        "rule_count": r.rule_count,
        "object_count": r.object_count,
        "finding_count": r.finding_count,
        "high_finding_count": r.high_finding_count,
        "rules_added": r.rules_added,
        "rules_removed": r.rules_removed,
        "rules_modified": r.rules_modified,
        "change_summary": r.change_summary,
        "policy_hash": r.policy_hash,
        "notes": r.notes,
    }
    if include_detail:
        d["change_detail"] = r.change_detail
    return d
