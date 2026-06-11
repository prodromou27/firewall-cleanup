"""Object analysis API."""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import Optional
from app.database import get_db
from app.models.policy import FirewallObject, FirewallPolicy
from app.models.finding import Finding

router = APIRouter(prefix="/api/objects", tags=["objects"])


@router.get("")
def list_objects(
    policy_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    object_type: Optional[str] = None,
    search: Optional[str] = None,
    unused_only: Optional[bool] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=1000),
    db: Session = Depends(get_db),
):
    q = db.query(FirewallObject)

    # Resolve policy IDs for scope
    scoped_policy_ids: Optional[list] = None
    if policy_id:
        q = q.filter(FirewallObject.policy_id == policy_id)
        scoped_policy_ids = [policy_id]
    elif customer_id:
        scoped_policy_ids = [
            p.id for p in db.query(FirewallPolicy)
            .filter(FirewallPolicy.customer_id == customer_id).all()
        ]
        if not scoped_policy_ids:
            return {"total": 0, "page": page, "page_size": page_size, "objects": []}
        q = q.filter(FirewallObject.policy_id.in_(scoped_policy_ids))

    if object_type:
        q = q.filter(FirewallObject.object_type == object_type)
    if search:
        q = q.filter(
            FirewallObject.object_name.ilike(f"%{search}%")
            | FirewallObject.value.ilike(f"%{search}%")
        )

    # Compute unused object IDs from findings
    unused_ids: set = set()
    findings_q = db.query(Finding).filter(Finding.finding_type == "unused_object")
    if scoped_policy_ids:
        findings_q = findings_q.filter(Finding.policy_id.in_(scoped_policy_ids))
    for f in findings_q.all():
        for oid in (f.affected_objects or []):
            unused_ids.add(oid)

    # Filter by unused if requested
    if unused_only:
        if unused_ids:
            q = q.filter(FirewallObject.id.in_(unused_ids))
        else:
            return {"total": 0, "page": page, "page_size": page_size, "objects": []}

    total = q.count()
    objects = q.order_by(FirewallObject.object_name).offset((page - 1) * page_size).limit(page_size).all()

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "objects": [_obj_dict(o, unused_ids) for o in objects],
    }


@router.get("/{object_id}")
def get_object(
    object_id: str,
    customer_id: Optional[str] = None,
    db: Session = Depends(get_db),
):
    obj = db.query(FirewallObject).filter(FirewallObject.id == object_id).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Object not found")
    if customer_id:
        from app.api.tenant import assert_policy_customer
        assert_policy_customer(obj.policy_id, customer_id, db)
    return _obj_dict(obj, set())


def _obj_dict(o: FirewallObject, unused_ids: set) -> dict:
    return {
        "id": o.id,
        "policy_id": o.policy_id,
        "object_name": o.object_name,
        "object_type": o.object_type,
        "value": o.value,
        "protocol": o.protocol,
        "port_start": o.port_start,
        "port_end": o.port_end,
        "members": o.members or [],
        "comment": o.comment,
        "is_unused": o.id in unused_ids,
    }
