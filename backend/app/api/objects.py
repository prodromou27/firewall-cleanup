"""Object analysis API."""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import Optional
from app.database import get_db
from app.models.policy import FirewallObject, FirewallPolicy
from app.models.finding import Finding
from app.models.user import User
from app.security.identity import (
    get_current_user, require_customer_access, accessible_customer_ids,
)

router = APIRouter(prefix="/api/objects", tags=["objects"])


# Object hygiene categories that map to existing finding types.
# Keeps the Objects page consistent with the analysis engine.
_CATEGORY_FINDING_TYPE = {
    "unused": "unused_object",
    "duplicates": "duplicate_object",
    "empty_groups": "empty_group",
    "large_groups": "large_group",
}


def _object_ids_for_finding_type(
    db: Session, finding_type: str, scoped_policy_ids: Optional[list]
) -> set:
    """Collect object IDs referenced by findings of a given type, within scope."""
    ids: set = set()
    fq = db.query(Finding).filter(Finding.finding_type == finding_type)
    if scoped_policy_ids:
        fq = fq.filter(Finding.policy_id.in_(scoped_policy_ids))
    for f in fq.all():
        for oid in (f.affected_objects or []):
            ids.add(oid)
    return ids


@router.get("")
def list_objects(
    policy_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    object_type: Optional[str] = None,
    search: Optional[str] = None,
    unused_only: Optional[bool] = None,
    category: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=1000),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    q = db.query(FirewallObject)

    # Per-user tenant scope: the set of customers this user may access.
    allowed = accessible_customer_ids(db, user)  # None => global (all)

    # Resolve policy IDs for scope
    scoped_policy_ids: Optional[list] = None
    if policy_id:
        # Confirm the user can access the policy's owning customer.
        pol = db.query(FirewallPolicy).filter(FirewallPolicy.id == policy_id).first()
        if not pol:
            return {"total": 0, "page": page, "page_size": page_size, "objects": []}
        require_customer_access(db, user, pol.customer_id)
        q = q.filter(FirewallObject.policy_id == policy_id)
        scoped_policy_ids = [policy_id]
    else:
        pol_q = db.query(FirewallPolicy.id)
        if allowed is not None:
            if not allowed:
                return {"total": 0, "page": page, "page_size": page_size, "objects": []}
            pol_q = pol_q.filter(FirewallPolicy.customer_id.in_(allowed))
        if customer_id:
            if allowed is not None and customer_id not in allowed:
                raise HTTPException(status_code=403, detail="Access denied: you are not authorized for this customer.")
            pol_q = pol_q.filter(FirewallPolicy.customer_id == customer_id)
        if allowed is not None or customer_id:
            scoped_policy_ids = [pid for (pid,) in pol_q.all()]
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

    # Build hygiene category sets from findings (single source of truth = engine)
    unused_ids = _object_ids_for_finding_type(db, "unused_object", scoped_policy_ids)
    duplicate_ids = _object_ids_for_finding_type(db, "duplicate_object", scoped_policy_ids)
    empty_group_ids = _object_ids_for_finding_type(db, "empty_group", scoped_policy_ids)
    large_group_ids = _object_ids_for_finding_type(db, "large_group", scoped_policy_ids)

    flag_sets = {
        "unused": unused_ids,
        "duplicates": duplicate_ids,
        "empty_groups": empty_group_ids,
        "large_groups": large_group_ids,
    }

    # Apply category filter (unused_only kept for backward compatibility)
    if unused_only:
        category = category or "unused"
    if category in flag_sets:
        target = flag_sets[category]
        if target:
            q = q.filter(FirewallObject.id.in_(target))
        else:
            return {"total": 0, "page": page, "page_size": page_size, "objects": []}

    total = q.count()
    objects = q.order_by(FirewallObject.object_name).offset((page - 1) * page_size).limit(page_size).all()

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "objects": [_obj_dict(o, flag_sets) for o in objects],
    }


@router.get("/{object_id}")
def get_object(
    object_id: str,
    customer_id: Optional[str] = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    obj = db.query(FirewallObject).filter(FirewallObject.id == object_id).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Object not found")
    pol = db.query(FirewallPolicy).filter(FirewallPolicy.id == obj.policy_id).first()
    require_customer_access(db, user, pol.customer_id if pol else None)
    if customer_id:
        from app.api.tenant import assert_policy_customer
        assert_policy_customer(obj.policy_id, customer_id, db)
    return _obj_dict(obj, {})


def _obj_dict(o: FirewallObject, flag_sets: dict) -> dict:
    """flag_sets maps category name -> set of object IDs (unused/duplicates/etc.)."""
    members = o.members or []
    oid = o.id
    return {
        "id": o.id,
        "policy_id": o.policy_id,
        "object_name": o.object_name,
        "object_type": o.object_type,
        "value": o.value,
        "protocol": o.protocol,
        "port_start": o.port_start,
        "port_end": o.port_end,
        "members": members,
        "member_count": len(members),
        "comment": o.comment,
        "is_unused": oid in flag_sets.get("unused", set()),
        "is_duplicate": oid in flag_sets.get("duplicates", set()),
        "is_empty_group": oid in flag_sets.get("empty_groups", set()),
        "is_large_group": oid in flag_sets.get("large_groups", set()),
    }
