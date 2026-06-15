"""Authentication API — login, logout, current user.

Sessions are delivered as HttpOnly cookies; the frontend never sees or stores
the token. Passwords are never returned. Failed logins are audited without
leaking which factor was wrong.
"""
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.config import settings
from app.models.user import User
from app.security.passwords import verify_password, hash_password, validate_password_policy
from app.security.identity import (
    create_session,
    revoke_session,
    revoke_all_sessions,
    get_current_user,
    accessible_customer_ids,
    SESSION_COOKIE_NAME,
)
from app.security.audit import audit_log
from app.security.throttle import login_throttle

router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginRequest(BaseModel):
    email: str
    password: str


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _user_public(db: Session, user: User) -> dict:
    return {
        "id": user.id,
        "email": user.email,
        "full_name": user.full_name,
        "role": user.role,
        # None means "all customers" (global role).
        "customer_ids": accessible_customer_ids(db, user),
    }


@router.post("/login")
def login(body: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    ip = _client_ip(request)
    email = body.email.lower()

    # Brute-force throttle: reject early if this (ip, email) is locked out.
    wait = login_throttle.retry_after(ip, email)
    if wait > 0:
        audit_log("auth.login_throttled", email=email, source_ip=ip, retry_after=wait)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts. Try again later.",
            headers={"Retry-After": str(wait)},
        )

    user = db.query(User).filter(User.email == email).first()

    # Constant-ish path: always run verify to reduce user-enumeration timing.
    valid = bool(user) and user.is_active and verify_password(body.password, user.password_hash)
    if not valid:
        login_throttle.record_failure(ip, email)
        audit_log("auth.login_failed", email=email, source_ip=ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    # Successful auth clears the failure counter for this (ip, email).
    login_throttle.reset(ip, email)

    raw_token = create_session(
        db, user, source_ip=ip, user_agent=request.headers.get("user-agent"),
    )
    user.last_login_at = datetime.utcnow()
    db.commit()

    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=raw_token,
        httponly=True,
        secure=bool(getattr(settings, "cookie_secure", False)),
        samesite="lax",
        max_age=int(getattr(settings, "session_ttl_hours", 12)) * 3600,
        path="/",
    )
    audit_log("auth.login", user_id=user.id, email=user.email, role=user.role, source_ip=ip)
    return {"user": _user_public(db, user)}


@router.post("/logout")
def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    raw_token = request.cookies.get(SESSION_COOKIE_NAME)
    revoke_session(db, raw_token)
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
    return {"message": "Logged out"}


@router.post("/logout-all")
def logout_all(request: Request, response: Response, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Sign out of every session for the current user (all devices)."""
    revoked = revoke_all_sessions(db, user.id)
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
    audit_log("auth.logout_all", user_id=user.id, email=user.email, sessions_revoked=revoked)
    return {"message": "Signed out of all sessions.", "sessions_revoked": revoked}


@router.post("/change-password")
def change_password(
    body: ChangePasswordRequest,
    request: Request,
    response: Response,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Self-service password change. Verifies the current password, enforces the
    password policy, updates the hash, and revokes all OTHER sessions (the
    caller's current session is kept alive).
    """
    if not verify_password(body.current_password, user.password_hash):
        audit_log("auth.change_password_failed", user_id=user.id, email=user.email)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Current password is incorrect.")
    if body.new_password == body.current_password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="New password must differ from the current password.")
    try:
        validate_password_policy(body.new_password)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    user.password_hash = hash_password(body.new_password)
    db.commit()
    # Revoke every other session so a stolen/old session can't survive a change.
    current_token = request.cookies.get(SESSION_COOKIE_NAME)
    revoked = revoke_all_sessions(db, user.id, except_token=current_token)
    audit_log("auth.change_password", user_id=user.id, email=user.email, other_sessions_revoked=revoked)
    return {"message": "Password changed.", "other_sessions_revoked": revoked}


@router.get("/me")
def me(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return {"user": _user_public(db, user)}
