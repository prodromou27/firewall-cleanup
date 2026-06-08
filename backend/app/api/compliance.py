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

router = APIRouter(prefix="/api/compliance", tags=["compliance"])


@router.get("/frameworks")
def list_frameworks():
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
):
    """Run all compliance frameworks against a policy and return an aggregate summary."""
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
):
    """Run a single compliance framework check against a policy."""
    try:
        result = run_compliance(policy_id, framework, db)
    except ValueError as exc:
        raise HTTPException(status_code=400 if "Unknown framework" in str(exc) else 404, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Compliance check failed: {exc}")

    return result
