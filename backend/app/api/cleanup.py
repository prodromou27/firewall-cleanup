"""Executive Cleanup Plan — groups findings into safe, sequenced cleanup waves
with risk-reduction estimates, candidate counts, and exportable change tickets.

Read-only: every item is a review/validation task phrased for the approved
change-management process. The tool never pushes, deletes, or modifies policy.
"""
import csv
import io
from typing import Optional

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.finding import Finding
from app.models.policy import FirewallPolicy
from app.models.user import User
from app.security.identity import get_current_user, accessible_customer_ids, require_customer_access

router = APIRouter(prefix="/api/cleanup-plan", tags=["cleanup"])

# Severity → risk weight, used to estimate how much risk each wave removes.
_SEV_WEIGHT = {"Critical": 25, "High": 10, "Medium": 5, "Low": 2, "Informational": 0}

# Findings in these states are no longer actionable cleanup candidates.
_TERMINAL = {"False Positive", "Accepted Risk", "Cleanup Completed Outside Tool"}

# Sequenced cleanup waves (safest first). Each maps the finding types it covers.
WAVES = [
    {
        "id": 1,
        "name": "Quick Wins — Safe Removal",
        "description": "High-confidence dead or redundant items that can be removed or consolidated with minimal operational risk.",
        "rollback": "Re-create or re-enable the rule/object from the captured configuration baseline (revision snapshot) if needed.",
        "types": {
            "disabled_rule", "zero_hit_rule", "duplicate_rule", "shadowed_rule",
            "unused_object", "duplicate_object", "empty_group",
        },
    },
    {
        "id": 2,
        "name": "Hygiene & Optimization",
        "description": "Documentation, naming, logging, ordering and consolidation improvements — low risk, mostly non-functional.",
        "rollback": "Revert the documentation/logging/ordering change; no traffic impact expected.",
        "types": {
            "low_usage_rule", "mergeable_rules", "large_rule_section", "no_documentation",
            "naming_quality", "no_logging", "no_cleanup_rule", "temporary_rule",
            "expired_rule", "broad_network", "service_range", "large_group",
            "rule_order_optimization", "nat_complexity", "negated_object",
        },
    },
    {
        "id": 3,
        "name": "Security Hardening — Validate First",
        "description": "Permissive or exposed access that reduces risk the most but requires business validation and change approval before tightening.",
        "rollback": "Restore the previous (broader) rule scope from the captured baseline; coordinate with the requesting team.",
        "types": {
            "overly_permissive", "risky_service", "rdp_exposed", "ssh_exposed",
            "database_exposed", "cleartext_service", "inbound_from_internet",
            "lateral_movement_risk", "vpn_access",
        },
    },
]

_TYPE_TO_WAVE = {t: w["id"] for w in WAVES for t in w["types"]}


def _scoped_findings(db: Session, user: User, customer_id: Optional[str]):
    """Tenant-isolated, actionable findings + a policy_id->name map."""
    allowed = accessible_customer_ids(db, user)
    if customer_id:
        require_customer_access(db, user, customer_id)

    pol_q = db.query(FirewallPolicy.id, FirewallPolicy.firewall_name)
    if allowed is not None:
        if not allowed:
            return [], {}
        pol_q = pol_q.filter(FirewallPolicy.customer_id.in_(allowed))
    if customer_id:
        pol_q = pol_q.filter(FirewallPolicy.customer_id == customer_id)
    policy_map = {pid: name for pid, name in pol_q.all()}
    if not policy_map:
        return [], {}

    findings = (
        db.query(Finding)
        .filter(Finding.policy_id.in_(list(policy_map.keys())))
        .filter(~Finding.status.in_(_TERMINAL))
        .all()
    )
    return findings, policy_map


@router.get("")
def get_cleanup_plan(
    customer_id: Optional[str] = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Return the sequenced cleanup plan with per-wave risk reduction and counts."""
    findings, _ = _scoped_findings(db, user, customer_id)
    total_weight = sum(_SEV_WEIGHT.get(f.severity, 0) for f in findings) or 1

    waves_out = []
    for w in WAVES:
        wf = [f for f in findings if f.finding_type in w["types"]]
        rule_ids, obj_ids = set(), set()
        sev_counts = {}
        weight = 0
        for f in wf:
            weight += _SEV_WEIGHT.get(f.severity, 0)
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
            for rid in (f.affected_rules or []):
                rule_ids.add(rid)
            for oid in (f.affected_objects or []):
                obj_ids.add(oid)
        waves_out.append({
            "id": w["id"],
            "name": w["name"],
            "description": w["description"],
            "finding_count": len(wf),
            "candidate_rule_count": len(rule_ids),
            "candidate_object_count": len(obj_ids),
            "risk_weight": weight,
            "risk_reduction_pct": round(100 * weight / total_weight, 1),
            "severity_breakdown": sev_counts,
        })

    unscheduled = [f for f in findings if f.finding_type not in _TYPE_TO_WAVE]
    return {
        "customer_id": customer_id,
        "total_findings": len(findings),
        "total_risk_weight": total_weight,
        "waves": waves_out,
        "unscheduled_count": len(unscheduled),
        "generated_for": user.email,
    }


@router.get("/tickets.csv")
def export_cleanup_tickets(
    customer_id: Optional[str] = None,
    wave: Optional[int] = Query(None, ge=1, le=3),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Export change tickets (one row per finding) with rollback notes, as CSV."""
    findings, policy_map = _scoped_findings(db, user, customer_id)
    wave_meta = {w["id"]: w for w in WAVES}

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Wave", "Wave Name", "Finding ID", "Severity", "Confidence", "Finding Type",
        "Policy", "Title", "Recommendation", "Rollback Note", "Status",
        "Affected Rules", "Affected Objects",
    ])
    for f in findings:
        wid = _TYPE_TO_WAVE.get(f.finding_type)
        if wid is None or (wave is not None and wid != wave):
            continue
        w = wave_meta[wid]
        writer.writerow([
            wid, w["name"], f.id, f.severity, f.confidence, f.finding_type,
            policy_map.get(f.policy_id, ""), f.title, f.recommendation or "",
            w["rollback"], f.status,
            len(f.affected_rules or []), len(f.affected_objects or []),
        ])

    output.seek(0)
    fname = "cleanup_tickets" + (f"_wave{wave}" if wave else "") + ".csv"
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )
