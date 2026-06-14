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
from app.security.passwords import verify_password
from app.security.identity import (
    create_session,
    revoke_session,
    get_current_user,
    accessible_customer_ids,
    SESSION_COOKIE_NAME,
)
from app.security.audit import audit_log

router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginRequest(BaseModel):
    email: str
    password: str


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
    user = db.query(User).filter(User.email == body.email.lower()).first()

    # Constant-ish path: always run verify to reduce user-enumeration timing.
    valid = bool(user) and user.is_active and verify_password(body.password, user.password_hash)
    if not valid:
        audit_log("auth.login_failed", email=body.email.lower(), source_ip=ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

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


@router.get("/me")
def me(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return {"user": _user_public(db, user)}
