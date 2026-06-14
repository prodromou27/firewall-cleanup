"""Customer management API — multi-tenant onboarding."""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import Optional
from pydantic import BaseModel
from app.database import get_db
from app.models.customer import Customer
from app.models.policy import FirewallPolicy, FirewallRule
from app.models.finding import Finding
from app.models.user import User
from app.security.identity import (
    get_current_user, require_capability, require_customer_access, accessible_customer_ids,
)
from app.security.rbac import CAP_MANAGE_CUSTOMERS
from app.security.audit import audit_log

router = APIRouter(prefix="/api/customers", tags=["customers"])


class CustomerCreate(BaseModel):
    name: str
    description: Optional[str] = None
    contact_name: Optional[str] = None
    contact_email: Optional[str] = None
    industry: Optional[str] = None
    tags: Optional[str] = None
    notes: Optional[str] = None


class CustomerUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    contact_name: Optional[str] = None
    contact_email: Optional[str] = None
    industry: Optional[str] = None
    status: Optional[str] = None
    tags: Optional[str] = None
    notes: Optional[str] = None


@router.get("")
def list_customers(
    status: Optional[str] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    q = db.query(Customer)
    if status:
        q = q.filter(Customer.status == status)
    if search:
        q = q.filter(Customer.name.ilike(f"%{search}%"))
    # Tenant isolation: non-global users see only their assigned customers.
    allowed = accessible_customer_ids(db, user)
    if allowed is not None:
        q = q.filter(Customer.id.in_(allowed)) if allowed else q.filter(False)
    customers = q.order_by(Customer.name).all()
    return [_customer_summary(c) for c in customers]


@router.post("", status_code=201)
def create_customer(
    body: CustomerCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_capability(CAP_MANAGE_CUSTOMERS)),
):
    existing = db.query(Customer).filter(Customer.name == body.name).first()
    if existing:
        raise HTTPException(status_code=409, detail=f"Customer '{body.name}' already exists.")
    import uuid
    c = Customer(
        id=str(uuid.uuid4()),
        name=body.name,
        description=body.description,
        contact_name=body.contact_name,
        contact_email=body.contact_email,
        industry=body.industry,
        tags=body.tags,
        notes=body.notes,
        status="active",
    )
    db.add(c)
    db.commit()
    db.refresh(c)
    audit_log("customer.create", user_id=user.id, customer_id=c.id, name=c.name)
    return _customer_summary(c)


@router.get("/{customer_id}")
def get_customer(
    customer_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    require_customer_access(db, user, customer_id)
    c = db.query(Customer).filter(Customer.id == customer_id).first()
    if not c:
        raise HTTPException(status_code=404, detail="Customer not found")
    return _customer_detail(c, db)


@router.patch("/{customer_id}")
def update_customer(
    customer_id: str,
    body: CustomerUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(require_capability(CAP_MANAGE_CUSTOMERS)),
):
    require_customer_access(db, user, customer_id)
    c = db.query(Customer).filter(Customer.id == customer_id).first()
    if not c:
        raise HTTPException(status_code=404, detail="Customer not found")
    if body.name is not None:
        c.name = body.name
    if body.description is not None:
        c.description = body.description
    if body.contact_name is not None:
        c.contact_name = body.contact_name
    if body.contact_email is not None:
        c.contact_email = body.contact_email
    if body.industry is not None:
        c.industry = body.industry
    if body.status is not None:
        c.status = body.status
    if body.tags is not None:
        c.tags = body.tags
    if body.notes is not None:
        c.notes = body.notes
    db.commit()
    db.refresh(c)
    return _customer_summary(c)


@router.delete("/{customer_id}")
def delete_customer(
    customer_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_capability(CAP_MANAGE_CUSTOMERS)),
):
    require_customer_access(db, user, customer_id)
    c = db.query(Customer).filter(Customer.id == customer_id).first()
    if not c:
        raise HTTPException(status_code=404, detail="Customer not found")
    db.delete(c)
    db.commit()
    audit_log("customer.delete", user_id=user.id, customer_id=customer_id, name=c.name)
    return {"message": "Customer deleted"}


@router.get("/{customer_id}/stats")
def customer_stats(
    customer_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    require_customer_access(db, user, customer_id)
    c = db.query(Customer).filter(Customer.id == customer_id).first()
    if not c:
        raise HTTPException(status_code=404, detail="Customer not found")

    policies = db.query(FirewallPolicy).filter(FirewallPolicy.customer_id == customer_id).all()
    policy_ids = [p.id for p in policies]

    total_rules = db.query(func.count(FirewallRule.id)).filter(
        FirewallRule.policy_id.in_(policy_ids)
    ).scalar() if policy_ids else 0

    enabled_rules = db.query(func.count(FirewallRule.id)).filter(
        FirewallRule.policy_id.in_(policy_ids),
        FirewallRule.enabled == True,
    ).scalar() if policy_ids else 0

    disabled_rules = total_rules - enabled_rules

    total_findings = db.query(func.count(Finding.id)).filter(
        Finding.policy_id.in_(policy_ids)
    ).scalar() if policy_ids else 0

    findings_by_severity = (
        db.query(Finding.severity, func.count(Finding.id))
        .filter(Finding.policy_id.in_(policy_ids))
        .group_by(Finding.severity)
        .all()
    ) if policy_ids else []

    findings_by_type = (
        db.query(Finding.finding_type, func.count(Finding.id))
        .filter(Finding.policy_id.in_(policy_ids))
        .group_by(Finding.finding_type)
        .all()
    ) if policy_ids else []

    findings_by_status = (
        db.query(Finding.status, func.count(Finding.id))
        .filter(Finding.policy_id.in_(policy_ids))
        .group_by(Finding.status)
        .all()
    ) if policy_ids else []

    vendor_dist = (
        db.query(FirewallPolicy.vendor, func.count(FirewallPolicy.id))
        .filter(FirewallPolicy.customer_id == customer_id)
        .group_by(FirewallPolicy.vendor)
        .all()
    )

    sev_map = {s: c for s, c in findings_by_severity}

    return {
        "customer": _customer_summary(c),
        "total_policies": len(policies),
        "total_rules": total_rules,
        "enabled_rules": enabled_rules,
        "disabled_rules": disabled_rules,
        "total_findings": total_findings,
        "critical_findings": sev_map.get("Critical", 0),
        "high_findings": sev_map.get("High", 0),
        "medium_findings": sev_map.get("Medium", 0),
        "low_findings": sev_map.get("Low", 0),
        "info_findings": sev_map.get("Informational", 0),
        "findings_by_severity": [{"severity": s, "count": cnt} for s, cnt in findings_by_severity],
        "findings_by_type": [{"type": t, "count": cnt} for t, cnt in findings_by_type],
        "findings_by_status": [{"status": s, "count": cnt} for s, cnt in findings_by_status],
        "vendor_distribution": [{"vendor": v, "count": cnt} for v, cnt in vendor_dist],
        "policies": [_policy_row(p) for p in policies],
    }


def _customer_summary(c: Customer) -> dict:
    return {
        "id": c.id,
        "name": c.name,
        "description": c.description,
        "contact_name": c.contact_name,
        "contact_email": c.contact_email,
        "industry": c.industry,
        "status": c.status,
        "tags": c.tags,
        "notes": c.notes,
        "total_policies": c.total_policies or 0,
        "total_rules": c.total_rules or 0,
        "total_findings": c.total_findings or 0,
        "high_findings": c.high_findings or 0,
        "created_at": c.created_at.isoformat() if c.created_at else None,
        "updated_at": c.updated_at.isoformat() if c.updated_at else None,
    }


def _customer_detail(c: Customer, db: Session) -> dict:
    return _customer_summary(c)


def _policy_row(p: FirewallPolicy) -> dict:
    return {
        "id": p.id,
        "firewall_name": p.firewall_name,
        "vendor": p.vendor,
        "policy_package": p.policy_package,
        "upload_date": p.upload_date.isoformat() if p.upload_date else None,
        "rule_count": p.rule_count,
        "finding_count": p.finding_count,
        "high_finding_count": p.high_finding_count,
        "analysis_status": p.analysis_status,
    }
