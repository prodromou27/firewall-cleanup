"""User management API — create/edit users, assign roles + customer access.

Gated by CAP_MANAGE_USERS. System admins manage everyone; tenant admins may
only manage non-global users whose customer assignments fall entirely within
their own accessible customers, and may never grant global (system_admin) roles
or assign customers they cannot access themselves.

Passwords are never returned. This API governs *application* access only — it
grants no ability to modify firewall policy (PolicyInsight stays read-only).
"""
import uuid
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import (
    User, UserCustomerAccess, UserSession,
    ALL_ROLES, GLOBAL_ROLES, ROLE_SYSTEM_ADMIN,
)
from app.models.customer import Customer
from app.security.passwords import hash_password
from app.security.identity import (
    get_current_user, require_capability, accessible_customer_ids,
)
from app.security.rbac import CAP_MANAGE_USERS
from app.security.audit import audit_log

router = APIRouter(prefix="/api/users", tags=["users"])

_MIN_PASSWORD_LEN = 8


# ── Schemas ────────────────────────────────────────────────────────────────────

class UserCreate(BaseModel):
    email: str
    password: str
    full_name: Optional[str] = None
    role: str
    customer_ids: List[str] = []


class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None
    customer_ids: Optional[List[str]] = None


class PasswordReset(BaseModel):
    password: str


# ── Helpers ──────────────────────────────────────────────────────────────────

def _validate_password(password: str) -> None:
    if not password or len(password) < _MIN_PASSWORD_LEN:
        raise HTTPException(
            status_code=400,
            detail=f"Password must be at least {_MIN_PASSWORD_LEN} characters.",
        )


def _validate_role(role: str) -> None:
    if role not in ALL_ROLES:
        raise HTTPException(status_code=400, detail=f"Unknown role: {role!r}.")


def _target_customer_ids(db: Session, target: User) -> List[str]:
    rows = (
        db.query(UserCustomerAccess.customer_id)
        .filter(UserCustomerAccess.user_id == target.id)
        .all()
    )
    return [r[0] for r in rows]


def _assert_can_manage_target(db: Session, actor: User, target: User) -> None:
    """A tenant admin may only manage non-global users whose customer
    assignments are all within the actor's accessible customers. System admins
    can manage anyone."""
    if actor.role in GLOBAL_ROLES:
        return
    if target.role in GLOBAL_ROLES:
        raise HTTPException(status_code=403, detail="You cannot manage system administrators.")
    allowed = set(accessible_customer_ids(db, actor) or [])
    target_customers = set(_target_customer_ids(db, target))
    # The target must not have access to any customer outside the actor's scope.
    if target_customers - allowed:
        raise HTTPException(status_code=403, detail="This user has access outside your customers.")


def _assert_assignable(db: Session, actor: User, role: str, customer_ids: List[str]) -> None:
    """Validate that the actor may assign the given role + customer set."""
    _validate_role(role)
    # Only system admins may create/assign global roles.
    if role in GLOBAL_ROLES and actor.role not in GLOBAL_ROLES:
        raise HTTPException(status_code=403, detail="Only a system administrator may assign that role.")

    # Validate customer IDs exist.
    if customer_ids:
        rows = db.query(Customer.id).filter(Customer.id.in_(customer_ids)).all()
        existing = {r[0] for r in rows}
        missing = set(customer_ids) - existing
        if missing:
            raise HTTPException(status_code=400, detail=f"Unknown customer ids: {', '.join(sorted(missing))}")

    # Tenant admins may only assign customers they themselves can access.
    if actor.role not in GLOBAL_ROLES:
        allowed = set(accessible_customer_ids(db, actor) or [])
        outside = set(customer_ids) - allowed
        if outside:
            raise HTTPException(status_code=403, detail="You can only assign customers you have access to.")


def _set_customer_access(db: Session, user: User, customer_ids: List[str]) -> None:
    """Replace the user's customer-access rows with the given set."""
    db.query(UserCustomerAccess).filter(UserCustomerAccess.user_id == user.id).delete()
    seen = set()
    for cid in customer_ids:
        if cid in seen:
            continue
        seen.add(cid)
        db.add(UserCustomerAccess(id=str(uuid.uuid4()), user_id=user.id, customer_id=cid))


def _user_public(db: Session, user: User) -> dict:
    return {
        "id": user.id,
        "email": user.email,
        "full_name": user.full_name,
        "role": user.role,
        "is_active": user.is_active,
        # None => all customers (global role); else explicit list.
        "customer_ids": accessible_customer_ids(db, user),
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None,
    }


def _visible_to_actor(db: Session, actor: User, target: User) -> bool:
    if actor.role in GLOBAL_ROLES:
        return True
    if target.role in GLOBAL_ROLES:
        return False
    if target.id == actor.id:
        return True
    allowed = set(accessible_customer_ids(db, actor) or [])
    target_customers = set(_target_customer_ids(db, target))
    # Visible if the target shares at least one of the actor's customers and has
    # no access outside the actor's scope.
    return bool(target_customers) and not (target_customers - allowed)


# ── Routes ──────────────────────────────────────────────────────────────────

@router.get("")
def list_users(
    db: Session = Depends(get_db),
    actor: User = Depends(require_capability(CAP_MANAGE_USERS)),
):
    users = db.query(User).order_by(User.email).all()
    visible = [u for u in users if _visible_to_actor(db, actor, u)]
    return [_user_public(db, u) for u in visible]


@router.post("", status_code=201)
def create_user(
    body: UserCreate,
    db: Session = Depends(get_db),
    actor: User = Depends(require_capability(CAP_MANAGE_USERS)),
):
    email = body.email.strip().lower()
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="A valid email is required.")
    _validate_password(body.password)
    _assert_assignable(db, actor, body.role, body.customer_ids)

    if db.query(User).filter(User.email == email).first():
        raise HTTPException(status_code=409, detail=f"A user with email {email} already exists.")

    u = User(
        id=str(uuid.uuid4()),
        email=email,
        full_name=(body.full_name or "").strip() or None,
        password_hash=hash_password(body.password),
        role=body.role,
        is_active=True,
    )
    db.add(u)
    db.flush()
    # Global roles span all customers implicitly — ignore any supplied list.
    _set_customer_access(db, u, [] if body.role in GLOBAL_ROLES else body.customer_ids)
    db.commit()
    db.refresh(u)
    audit_log("user.create", user_id=actor.id, target_user_id=u.id, email=u.email, role=u.role)
    return _user_public(db, u)


@router.get("/{user_id}")
def get_user(
    user_id: str,
    db: Session = Depends(get_db),
    actor: User = Depends(require_capability(CAP_MANAGE_USERS)),
):
    u = db.query(User).filter(User.id == user_id).first()
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    if not _visible_to_actor(db, actor, u):
        raise HTTPException(status_code=403, detail="You are not permitted to view this user.")
    return _user_public(db, u)


@router.patch("/{user_id}")
def update_user(
    user_id: str,
    body: UserUpdate,
    db: Session = Depends(get_db),
    actor: User = Depends(require_capability(CAP_MANAGE_USERS)),
):
    u = db.query(User).filter(User.id == user_id).first()
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    _assert_can_manage_target(db, actor, u)

    # Determine the resulting role + customer set for assignment validation.
    new_role = body.role if body.role is not None else u.role
    new_customer_ids = (
        body.customer_ids if body.customer_ids is not None
        else _target_customer_ids(db, u)
    )
    if body.role is not None or body.customer_ids is not None:
        _assert_assignable(db, actor, new_role, [] if new_role in GLOBAL_ROLES else new_customer_ids)

    # Guard: don't allow demoting/deactivating the last active system admin.
    if u.role == ROLE_SYSTEM_ADMIN:
        demoting = body.role is not None and body.role != ROLE_SYSTEM_ADMIN
        deactivating = body.is_active is False
        if demoting or deactivating:
            other_admins = (
                db.query(User)
                .filter(User.role == ROLE_SYSTEM_ADMIN, User.is_active == True, User.id != u.id)
                .count()
            )
            if other_admins == 0:
                raise HTTPException(status_code=400, detail="Cannot remove the last active system administrator.")

    if body.full_name is not None:
        u.full_name = body.full_name.strip() or None
    if body.role is not None:
        u.role = body.role
    if body.is_active is not None:
        u.is_active = body.is_active
        # Revoke active sessions when deactivating.
        if body.is_active is False:
            db.query(UserSession).filter(UserSession.user_id == u.id).delete()

    if body.role is not None or body.customer_ids is not None:
        _set_customer_access(db, u, [] if new_role in GLOBAL_ROLES else new_customer_ids)

    db.commit()
    db.refresh(u)
    audit_log("user.update", user_id=actor.id, target_user_id=u.id, role=u.role, is_active=u.is_active)
    return _user_public(db, u)


@router.post("/{user_id}/password")
def reset_password(
    user_id: str,
    body: PasswordReset,
    db: Session = Depends(get_db),
    actor: User = Depends(require_capability(CAP_MANAGE_USERS)),
):
    u = db.query(User).filter(User.id == user_id).first()
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    _assert_can_manage_target(db, actor, u)
    _validate_password(body.password)
    u.password_hash = hash_password(body.password)
    # Force re-login everywhere after a password reset.
    db.query(UserSession).filter(UserSession.user_id == u.id).delete()
    db.commit()
    audit_log("user.password_reset", user_id=actor.id, target_user_id=u.id)
    return {"message": "Password updated. Existing sessions revoked."}


@router.delete("/{user_id}")
def delete_user(
    user_id: str,
    db: Session = Depends(get_db),
    actor: User = Depends(require_capability(CAP_MANAGE_USERS)),
):
    u = db.query(User).filter(User.id == user_id).first()
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    if u.id == actor.id:
        raise HTTPException(status_code=400, detail="You cannot delete your own account.")
    _assert_can_manage_target(db, actor, u)

    if u.role == ROLE_SYSTEM_ADMIN:
        other_admins = (
            db.query(User)
            .filter(User.role == ROLE_SYSTEM_ADMIN, User.is_active == True, User.id != u.id)
            .count()
        )
        if other_admins == 0:
            raise HTTPException(status_code=400, detail="Cannot delete the last active system administrator.")

    db.delete(u)  # cascades to customer_access + sessions
    db.commit()
    audit_log("user.delete", user_id=actor.id, target_user_id=user_id, email=u.email)
    return {"message": "User deleted"}
