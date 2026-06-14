"""User, role-based access, tenant mapping, and session models.

Part of the security hardening Phase 1 (real user authentication + RBAC +
per-user tenant isolation). These models intentionally do NOT grant any
write capability over firewall policies — PolicyInsight remains read-only.
Roles gate *application* actions (upload, sync, report download, settings,
user management), never firewall mutations.
"""
from sqlalchemy import Column, String, DateTime, Boolean, ForeignKey, UniqueConstraint
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.database import Base
import uuid


def gen_uuid():
    return str(uuid.uuid4())


# ── Roles ─────────────────────────────────────────────────────────────────────
# Ordered loosely from most to least privileged. Permission checks key off the
# role string; see app/security/rbac.py for the capability matrix.
ROLE_SYSTEM_ADMIN = "system_admin"   # full global access incl. user management
ROLE_TENANT_ADMIN = "tenant_admin"   # manage assigned customers, users within them
ROLE_ENGINEER = "engineer"           # upload, run sync, generate reports (assigned customers)
ROLE_REVIEWER = "reviewer"           # view + comment + generate reports (assigned customers)
ROLE_REPORT_VIEWER = "report_viewer" # download existing reports only (assigned customers)
ROLE_READ_ONLY = "read_only"         # read-only view (assigned customers)

ALL_ROLES = {
    ROLE_SYSTEM_ADMIN,
    ROLE_TENANT_ADMIN,
    ROLE_ENGINEER,
    ROLE_REVIEWER,
    ROLE_REPORT_VIEWER,
    ROLE_READ_ONLY,
}

# Roles whose access spans every customer without explicit mapping rows.
GLOBAL_ROLES = {ROLE_SYSTEM_ADMIN}


class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=gen_uuid)
    email = Column(String, nullable=False, unique=True, index=True)
    full_name = Column(String, nullable=True)
    # bcrypt hash — never the plaintext. Never returned by any API.
    password_hash = Column(String, nullable=False)
    role = Column(String, nullable=False, default=ROLE_READ_ONLY)
    is_active = Column(Boolean, nullable=False, default=True)

    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())
    last_login_at = Column(DateTime, nullable=True)

    customer_access = relationship(
        "UserCustomerAccess", back_populates="user", cascade="all, delete-orphan"
    )
    sessions = relationship(
        "UserSession", back_populates="user", cascade="all, delete-orphan"
    )


class UserCustomerAccess(Base):
    """Explicit mapping of which customers (tenants) a non-global user may access.

    The presence of a row grants access; absence denies it. System admins
    bypass this table entirely (GLOBAL_ROLES).
    """
    __tablename__ = "user_customer_access"
    __table_args__ = (
        UniqueConstraint("user_id", "customer_id", name="uq_user_customer"),
    )

    id = Column(String, primary_key=True, default=gen_uuid)
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    customer_id = Column(String, ForeignKey("customers.id", ondelete="CASCADE"), nullable=False, index=True)
    created_at = Column(DateTime, server_default=func.now())

    user = relationship("User", back_populates="customer_access")


class UserSession(Base):
    """Server-side session. The raw token lives only in the client's HttpOnly
    cookie; we store only its SHA-256 hash so a DB leak cannot resurrect a live
    session. Supports server-side revocation (logout) and expiry.
    """
    __tablename__ = "user_sessions"

    id = Column(String, primary_key=True, default=gen_uuid)
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    token_hash = Column(String, nullable=False, unique=True, index=True)
    created_at = Column(DateTime, server_default=func.now())
    expires_at = Column(DateTime, nullable=False)
    last_seen_at = Column(DateTime, server_default=func.now())
    source_ip = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)

    user = relationship("User", back_populates="sessions")
