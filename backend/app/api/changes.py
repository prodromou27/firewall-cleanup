"""What Changed Since Last Sync — per-policy change feed built from policy
revisions (rule add/remove/modify) and the severity delta between the two most
recent analysis runs (new high-risk exposure). Read-only.
"""
import json
from typing import Optional

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.policy import FirewallPolicy, AnalysisRun
from app.models.revision import PolicyRevision
from app.models.user import User
from app.security.identity import get_current_user, accessible_customer_ids, require_customer_access

router = APIRouter(prefix="/api/changes", tags=["changes"])

_SEVS = ["Critical", "High", "Medium", "Low", "Informational"]


def _severity_delta(curr: dict, prev: dict) -> dict:
    """Per-severity change (curr - prev); only non-zero entries are returned."""
    out = {}
    for s in _SEVS:
        d = int(curr.get(s, 0) or 0) - int(prev.get(s, 0) or 0)
        if d != 0:
            out[s] = d
    return out


def _snapshot(run: Optional[AnalysisRun]) -> dict:
    if not run or not run.severity_snapshot:
        return {}
    try:
        return json.loads(run.severity_snapshot)
    except (ValueError, TypeError):
        return {}


@router.get("")
def get_changes(
    customer_id: Optional[str] = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Return the change feed for the accessible policies."""
    allowed = accessible_customer_ids(db, user)
    if customer_id:
        require_customer_access(db, user, customer_id)

    pol_q = db.query(FirewallPolicy)
    if allowed is not None:
        if not allowed:
            return {"customer_id": customer_id, "policies": []}
        pol_q = pol_q.filter(FirewallPolicy.customer_id.in_(allowed))
    if customer_id:
        pol_q = pol_q.filter(FirewallPolicy.customer_id == customer_id)
    policies = pol_q.all()

    out = []
    for p in policies:
        latest_rev = (
            db.query(PolicyRevision)
            .filter(PolicyRevision.policy_id == p.id)
            .order_by(PolicyRevision.revision_number.desc())
            .first()
        )
        runs = (
            db.query(AnalysisRun)
            .filter(AnalysisRun.policy_id == p.id, AnalysisRun.status == "completed")
            .order_by(AnalysisRun.completed_at.desc())
            .limit(2)
            .all()
        )
        curr_snap = _snapshot(runs[0]) if runs else {}
        prev_snap = _snapshot(runs[1]) if len(runs) > 1 else {}
        sev_delta = _severity_delta(curr_snap, prev_snap)

        rule_changes = 0
        change_detail = []
        if latest_rev:
            rule_changes = (latest_rev.rules_added or 0) + (latest_rev.rules_removed or 0) + (latest_rev.rules_modified or 0)
            change_detail = (latest_rev.change_detail or [])[:25]

        # Only surface policies that actually have a change signal.
        if not latest_rev and not sev_delta:
            continue

        out.append({
            "policy_id": p.id,
            "firewall_name": p.firewall_name,
            "vendor": p.vendor,
            "last_synced": latest_rev.synced_at.isoformat() if (latest_rev and latest_rev.synced_at) else None,
            "revision_number": latest_rev.revision_number if latest_rev else None,
            "rules_added": latest_rev.rules_added if latest_rev else 0,
            "rules_removed": latest_rev.rules_removed if latest_rev else 0,
            "rules_modified": latest_rev.rules_modified if latest_rev else 0,
            "rule_changes_total": rule_changes,
            "change_summary": latest_rev.change_summary if latest_rev else None,
            "severity_delta": sev_delta,
            # Alert when new Critical/High findings appeared since the prior run.
            "new_high_risk": sev_delta.get("Critical", 0) > 0 or sev_delta.get("High", 0) > 0,
            "sample_changes": change_detail,
        })

    # Most-changed first.
    out.sort(key=lambda x: (x["new_high_risk"], x["rule_changes_total"]), reverse=True)
    return {"customer_id": customer_id, "policies": out}
