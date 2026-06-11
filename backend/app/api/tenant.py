"""Tenant ownership helpers — used by all API routers to enforce per-customer isolation."""
from fastapi import HTTPException
from sqlalchemy.orm import Session
from app.models.policy import FirewallPolicy
from app.models.finding import Finding
from app.models.policy import FirewallObject


def _get_policy_customer(policy_id: str, db: Session) -> str:
    """Return the customer_id that owns this policy, or raise 404."""
    p = db.query(FirewallPolicy.customer_id).filter(FirewallPolicy.id == policy_id).first()
    if not p:
        raise HTTPException(status_code=404, detail="Policy not found")
    return p[0]


def assert_policy_customer(policy_id: str, customer_id: str, db: Session) -> None:
    """
    Raise 403 if the policy does not belong to the given customer.
    Call this on every single-resource read or mutation that accepts both IDs.
    """
    p = db.query(FirewallPolicy.customer_id).filter(FirewallPolicy.id == policy_id).first()
    if not p:
        raise HTTPException(status_code=404, detail="Policy not found")
    if p[0] != customer_id:
        raise HTTPException(status_code=403, detail="Access denied: policy belongs to a different customer")


def get_finding_with_customer_check(
    finding_id: str,
    customer_id: str | None,
    db: Session,
) -> Finding:
    """
    Fetch a finding by ID.  If customer_id is provided, verify the finding's
    policy belongs to that customer — raises 403 otherwise.
    """
    f = db.query(Finding).filter(Finding.id == finding_id).first()
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    if customer_id:
        assert_policy_customer(f.policy_id, customer_id, db)
    return f


def filter_finding_ids_by_customer(
    finding_ids: list[str],
    customer_id: str | None,
    db: Session,
) -> list[str]:
    """
    For bulk operations: return only the finding IDs that belong to policies
    owned by the given customer.  When customer_id is None, all IDs pass through.
    """
    if not customer_id:
        return finding_ids

    allowed_policy_ids = {
        p.id for p in db.query(FirewallPolicy.id)
        .filter(FirewallPolicy.customer_id == customer_id).all()
    }
    findings = db.query(Finding.id, Finding.policy_id).filter(Finding.id.in_(finding_ids)).all()
    return [f_id for f_id, pid in findings if pid in allowed_policy_ids]
