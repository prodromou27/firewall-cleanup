"""
Compliance Framework API
==========================
GET /api/compliance/{policy_id}?framework=pci-dss|cis|nist|iso27001
GET /api/compliance/{policy_id}/all
GET /api/compliance/frameworks  — list available frameworks
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.analysis.compliance_checker import run_compliance, run_all_frameworks, SUPPORTED_FRAMEWORKS
from app.models.policy import FirewallPolicy
from app.models.user import User
from app.security.identity import get_current_user, require_customer_access

router = APIRouter(prefix="/api/compliance", tags=["compliance"])


def _authz_policy_access(policy_id: str, db: Session, user: User) -> None:
    """Confirm the policy exists and the current user may access its customer."""
    policy = db.query(FirewallPolicy).filter(FirewallPolicy.id == policy_id).first()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    require_customer_access(db, user, policy.customer_id)


@router.get("/frameworks")
def list_frameworks(user: User = Depends(get_current_user)):
    """Return the list of supported compliance frameworks."""
    return [
        {
            "key":  k,
            "name": name,
        }
        for k, (name, _) in SUPPORTED_FRAMEWORKS.items()
    ]


@router.get("/{policy_id}/all")
def get_all_compliance(
    policy_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Run all compliance frameworks against a policy and return an aggregate summary."""
    _authz_policy_access(policy_id, db, user)
    try:
        results = run_all_frameworks(policy_id, db)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Compliance check failed: {exc}")

    # Build aggregate summary
    framework_summaries = []
    for fw_key, result in results.items():
        if "error" in result:
            framework_summaries.append({
                "framework": fw_key,
                "framework_name": SUPPORTED_FRAMEWORKS[fw_key][0],
                "score": None,
                "grade": None,
                "error": result["error"],
            })
        else:
            framework_summaries.append({
                "framework":       result["framework"],
                "framework_name":  result["framework_name"],
                "score":           result["score"],
                "grade":           result["grade"],
                "summary":         result["summary"],
            })

    return {
        "policy_id":  policy_id,
        "frameworks": framework_summaries,
        "details":    results,
    }


@router.get("/{policy_id}")
def get_compliance(
    policy_id: str,
    framework: str = Query("pci-dss", description="pci-dss | cis | nist | iso27001"),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Run a single compliance framework check against a policy."""
    _authz_policy_access(policy_id, db, user)
    try:
        result = run_compliance(policy_id, framework, db)
    except ValueError as exc:
        raise HTTPException(status_code=400 if "Unknown framework" in str(exc) else 404, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Compliance check failed: {exc}")

    return result
