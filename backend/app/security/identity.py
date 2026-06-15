"""Session lifecycle + FastAPI auth dependencies.

Sessions are server-side: a random token is set in an HttpOnly cookie and only
its SHA-256 hash is stored in the DB. This gives us revocation, expiry, and
resistance to DB-leak session resurrection. No session token ever appears in
localStorage, URLs, logs, or API responses.
"""
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.config import settings
from app.models.user import User, UserSession, UserCustomerAccess, GLOBAL_ROLES
from app.security.rbac import has_capability

SESSION_COOKIE_NAME = "pi_session"
_SESSION_TTL_HOURS = int(getattr(settings, "session_ttl_hours", 12) or 12)
_IDLE_TIMEOUT_MINUTES = int(getattr(settings, "session_idle_timeout_minutes", 60) or 0)


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_session(db: Session, user: User, *, source_ip: str = None, user_agent: str = None) -> str:
    """Create a session row and return the RAW token (to be set as a cookie)."""
    raw_token = secrets.token_urlsafe(48)
    sess = UserSession(
        user_id=user.id,
        token_hash=_hash_token(raw_token),
        expires_at=datetime.utcnow() + timedelta(hours=_SESSION_TTL_HOURS),
        source_ip=source_ip,
        user_agent=(user_agent or "")[:500] or None,
    )
    db.add(sess)
    db.commit()
    return raw_token


def revoke_session(db: Session, raw_token: str) -> None:
    if not raw_token:
        return
    row = db.query(UserSession).filter(UserSession.token_hash == _hash_token(raw_token)).first()
    if row:
        db.delete(row)
        db.commit()


def revoke_all_sessions(db: Session, user_id: str, *, except_token: Optional[str] = None) -> int:
    """Revoke every session for a user (e.g. 'sign out everywhere'). Optionally
    keep the caller's current session alive. Returns the number revoked.
    """
    q = db.query(UserSession).filter(UserSession.user_id == user_id)
    if except_token:
        q = q.filter(UserSession.token_hash != _hash_token(except_token))
    count = q.delete(synchronize_session=False)
    db.commit()
    return count


def _resolve_user(db: Session, raw_token: Optional[str]) -> Optional[User]:
    if not raw_token:
        return None
    row = (
        db.query(UserSession)
        .filter(UserSession.token_hash == _hash_token(raw_token))
        .first()
    )
    if not row:
        return None
    now = datetime.utcnow()
    if row.expires_at and row.expires_at < now:
        # Absolute TTL elapsed — clean up and reject.
        db.delete(row)
        db.commit()
        return None
    # Idle timeout: no activity within the idle window revokes the session even
    # if the absolute TTL has not yet elapsed.
    if _IDLE_TIMEOUT_MINUTES > 0 and row.last_seen_at:
        idle_deadline = row.last_seen_at + timedelta(minutes=_IDLE_TIMEOUT_MINUTES)
        if idle_deadline < now:
            db.delete(row)
            db.commit()
            return None
    user = db.query(User).filter(User.id == row.user_id).first()
    if not user or not user.is_active:
        return None
    row.last_seen_at = now
    # Sliding absolute expiry: active sessions are extended up to the TTL from
    # now, so a continuously-used session is not cut off at the original cap.
    row.expires_at = now + timedelta(hours=_SESSION_TTL_HOURS)
    db.commit()
    return user


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    """Dependency: require a valid session cookie."""
    raw_token = request.cookies.get(SESSION_COOKIE_NAME)
    user = _resolve_user(db, raw_token)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )
    return user


def get_optional_user(request: Request, db: Session = Depends(get_db)) -> Optional[User]:
    """Dependency: return the user if logged in, else None (no error)."""
    return _resolve_user(db, request.cookies.get(SESSION_COOKIE_NAME))


def require_capability(capability: str):
    """Dependency factory: require the current user's role to hold a capability."""
    def _dep(user: User = Depends(get_current_user)) -> User:
        if not has_capability(user.role, capability):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Your role ({user.role}) is not permitted to perform this action.",
            )
        return user
    return _dep


def user_has_customer_access(db: Session, user: User, customer_id: str) -> bool:
    """True if the user may access the given customer (tenant)."""
    if user.role in GLOBAL_ROLES:
        return True
    if not customer_id:
        return False
    row = (
        db.query(UserCustomerAccess)
        .filter(
            UserCustomerAccess.user_id == user.id,
            UserCustomerAccess.customer_id == customer_id,
        )
        .first()
    )
    return row is not None


def require_customer_access(db: Session, user: User, customer_id: str) -> None:
    """Raise 403 unless the user may access this customer. SERVER-SIDE source of
    truth — never trust customer IDs from URLs/localStorage/headers without this.
    """
    if not user_has_customer_access(db, user, customer_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: you are not authorized for this customer.",
        )


def accessible_customer_ids(db: Session, user: User) -> Optional[list]:
    """Return the list of customer IDs the user can access, or None meaning
    'all customers' (global roles). Callers use None to skip filtering.
    """
    if user.role in GLOBAL_ROLES:
        return None
    rows = (
        db.query(UserCustomerAccess.customer_id)
        .filter(UserCustomerAccess.user_id == user.id)
        .all()
    )
    return [r[0] for r in rows]
