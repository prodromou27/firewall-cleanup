"""Policy revision history — change tracking (Tufin-style)."""
from typing import Optional
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.revision import PolicyRevision

router = APIRouter(prefix="/api/revisions", tags=["revisions"])


@router.get("")
def list_revisions(
    policy_id: Optional[str] = None,
    device_id: Optional[str] = None,
    limit: int = 50,
    db: Session = Depends(get_db),
):
    q = db.query(PolicyRevision)
    if policy_id:
        q = q.filter(PolicyRevision.policy_id == policy_id)
    if device_id:
        q = q.filter(PolicyRevision.device_id == device_id)
    revisions = q.order_by(PolicyRevision.synced_at.desc()).limit(limit).all()
    return [_rev_dict(r) for r in revisions]


@router.get("/{revision_id}")
def get_revision(revision_id: str, db: Session = Depends(get_db)):
    r = db.query(PolicyRevision).filter(PolicyRevision.id == revision_id).first()
    if not r:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Revision not found")
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
