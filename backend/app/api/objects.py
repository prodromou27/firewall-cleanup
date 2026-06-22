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
from app.api.common import validate_choice, validate_sort

router = APIRouter(prefix="/api/objects", tags=["objects"])


# Object hygiene categories that map to existing finding types.
# Keeps the Objects page consistent with the analysis engine.
_CATEGORY_FINDING_TYPE = {
    "unused": "unused_object",
    "duplicates": "duplicate_object",
    "empty_groups": "empty_group",
    "large_groups": "large_group",
}


def _object_ids_for_finding_types(
    db: Session, finding_types: list[str], scoped_policy_ids: Optional[list]
) -> dict[str, set]:
    """Collect object IDs referenced by hygiene findings in one query."""
    ids_by_type: dict[str, set] = {t: set() for t in finding_types}
    if not finding_types:
        return ids_by_type
    fq = (
        db.query(Finding.finding_type, Finding.affected_objects)
        .filter(Finding.finding_type.in_(finding_types))
    )
    if scoped_policy_ids:
        fq = fq.filter(Finding.policy_id.in_(scoped_policy_ids))
    for finding_type, affected_objects in fq.all():
        target = ids_by_type.setdefault(finding_type, set())
        for oid in (affected_objects or []):
            target.add(oid)
    return ids_by_type


@router.get("")
def list_objects(
    policy_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    object_type: Optional[str] = None,
    search: Optional[str] = None,
    unused_only: Optional[bool] = None,
    category: Optional[str] = None,
    sort_by: Optional[str] = None,
    sort_dir: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=1000),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if category:
        validate_choice(category, tuple(_CATEGORY_FINDING_TYPE), "category")
    _OBJECT_SORTS = {
        "object_name": FirewallObject.object_name,
        "object_type": FirewallObject.object_type,
        "value": FirewallObject.value,
        "created_at": FirewallObject.created_at,
    }
    sort_field, direction = validate_sort(sort_by, sort_dir, tuple(_OBJECT_SORTS), "object_name")
    q = db.query(FirewallObject)

    # Per-user tenant scope: the set of customers this user may access.
    allowed = accessible_customer_ids(db, user)  # None => global (all)

    # Resolve policy IDs for scope
    scoped_policy_ids: Optional[list] = None
    if policy_id:
        # Confirm the user can access the policy's owning customer.
        pol = db.query(FirewallPolicy).filter(FirewallPolicy.id == policy_id).first()
        if not pol:
            raise HTTPException(status_code=404, detail="Policy not found")
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

    # Apply category filter (unused_only kept for backward compatibility)
    if unused_only:
        category = category or "unused"
    category_sets: dict[str, set] = {}
    if category in _CATEGORY_FINDING_TYPE:
        finding_type = _CATEGORY_FINDING_TYPE[category]
        category_sets = _object_ids_for_finding_types(db, [finding_type], scoped_policy_ids)
        target = category_sets.get(finding_type, set())
        if target:
            q = q.filter(FirewallObject.id.in_(target))
        else:
            return {"total": 0, "page": page, "page_size": page_size, "objects": []}

    total = q.count()
    sort_col = _OBJECT_SORTS[sort_field]
    if direction == "desc":
        sort_col = sort_col.desc()
    objects = q.order_by(sort_col).offset((page - 1) * page_size).limit(page_size).all()

    hygiene_sets = _object_ids_for_finding_types(db, list(_CATEGORY_FINDING_TYPE.values()), scoped_policy_ids)
    flag_sets = {
        "unused": hygiene_sets.get("unused_object", set()),
        "duplicates": hygiene_sets.get("duplicate_object", set()),
        "empty_groups": hygiene_sets.get("empty_group", set()),
        "large_groups": hygiene_sets.get("large_group", set()),
    }

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
