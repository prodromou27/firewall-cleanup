"""Policy management API."""
import csv
import io
import json
from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session, selectinload
from sqlalchemy import func, or_
from typing import Optional
from app.database import get_db
from app.models.policy import FirewallPolicy, FirewallRule, FirewallObject, AnalysisRun
from app.models.finding import Finding
from app.analysis.engine import run_analysis
import logging

router = APIRouter(prefix="/api/policies", tags=["policies"])
logger = logging.getLogger(__name__)

from app.api.tenant import assert_policy_customer  # noqa: E402 — after router init
from app.models.user import User
from app.security.identity import (
    get_current_user, require_capability, require_customer_access, accessible_customer_ids,
)
from app.security.rbac import CAP_VIEW_GLOBAL, CAP_DELETE_DATA, CAP_UPLOAD
from app.security.audit import audit_log
from app.api.common import validate_choice, validate_csv_choices, validate_sort
from app.reporting.export_safety import attachment_headers, spreadsheet_row


def _authz_policy(policy_id: str, db: Session, user: User) -> FirewallPolicy:
    """Fetch a policy and enforce the user may access its owning customer (tenant)."""
    policy = db.query(FirewallPolicy).filter(FirewallPolicy.id == policy_id).first()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    require_customer_access(db, user, policy.customer_id)
    return policy

# ── Helpers ───────────────────────────────────────────────────────────────────

_ANY_VALUES = {"any", "all", "*", "0.0.0.0/0", "::/0"}

def _is_any(values: list) -> bool:
    """Return True if the list contains a wildcard/any value."""
    return bool(values and any(str(v).lower().strip() in _ANY_VALUES for v in values))


def _policy_risk_score(p: FirewallPolicy, db: Session,
                        _rules: list | None = None,
                        _sev_map: dict | None = None) -> int:
    """
    Compute a 0–100 risk score for a policy based on:
    - Weighted finding severity counts
    - % of permissive rules (any source / any dest / any service)
    - % zero-hit enabled rules

    Pass pre-fetched _rules / _sev_map to avoid redundant DB queries.
    """
    if p.rule_count == 0:
        return 0

    if _rules is None:
        _rules = db.query(FirewallRule).filter(FirewallRule.policy_id == p.id).all()
    enabled = [r for r in _rules if r.enabled]
    if not enabled:
        return 0

    # Finding severity score (0–50)
    if _sev_map is None:
        sev_counts = (
            db.query(Finding.severity, func.count(Finding.id))
            .filter(Finding.policy_id == p.id)
            .group_by(Finding.severity).all()
        )
        _sev_map = {s: c for s, c in sev_counts}
    finding_score = min(50, (
        (_sev_map.get("Critical", 0) * 8) +
        (_sev_map.get("High", 0) * 5) +
        (_sev_map.get("Medium", 0) * 2) +
        (_sev_map.get("Low", 0) * 0.5)
    ))

    # Permissive rule score (0–30)
    permissive = sum(
        1 for r in enabled
        if _is_any(r.sources or []) or _is_any(r.destinations or []) or _is_any(r.services or [])
    )
    perm_pct = permissive / len(enabled)
    perm_score = perm_pct * 30

    # Zero-hit score (0–20)
    zero_hit = sum(
        1 for r in enabled
        if r.hit_count is not None and r.hit_count == 0
    )
    zero_pct = zero_hit / len(enabled)
    zero_score = zero_pct * 20

    return min(100, round(finding_score + perm_score + zero_score))


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("")
def list_policies(
    id: Optional[str] = None,
    customer_id: Optional[str] = None,
    vendor: Optional[str] = None,
    analysis_status: Optional[str] = None,
    search: Optional[str] = None,
    sort_by: Optional[str] = None,
    sort_dir: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    _POLICY_SORTS = {
        "upload_date": FirewallPolicy.upload_date,
        "firewall_name": FirewallPolicy.firewall_name,
        "vendor": FirewallPolicy.vendor,
        "policy_package": FirewallPolicy.policy_package,
        "rule_count": FirewallPolicy.rule_count,
        "finding_count": FirewallPolicy.finding_count,
        "high_finding_count": FirewallPolicy.high_finding_count,
        "analysis_status": FirewallPolicy.analysis_status,
    }
    sort_field, direction = validate_sort(sort_by, sort_dir or "desc", tuple(_POLICY_SORTS), "upload_date")
    q = db.query(FirewallPolicy)
    if customer_id:
        require_customer_access(db, user, customer_id)
        q = q.filter(FirewallPolicy.customer_id == customer_id)
    else:
        allowed = accessible_customer_ids(db, user)
        if allowed is not None:
            q = q.filter(FirewallPolicy.customer_id.in_(allowed)) if allowed else q.filter(False)
    if id:
        q = q.filter(FirewallPolicy.id == id)
    if vendor:
        q = q.filter(FirewallPolicy.vendor == vendor)
    if analysis_status:
        validate_choice(analysis_status, ("pending", "parsing", "running", "completed", "failed"), "analysis_status")
        q = q.filter(FirewallPolicy.analysis_status == analysis_status)
    if search:
        q = q.filter(
            or_(
                FirewallPolicy.firewall_name.ilike(f"%{search}%"),
                FirewallPolicy.policy_package.ilike(f"%{search}%"),
                FirewallPolicy.original_filename.ilike(f"%{search}%"),
            )
        )
    total = q.count()
    sort_col = _POLICY_SORTS[sort_field]
    if direction == "desc":
        sort_col = sort_col.desc()
    policies = (
        q.order_by(sort_col)
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "policies": [_policy_summary(p) for p in policies],
    }


@router.get("/stats")
def get_dashboard_stats(
    customer_id: Optional[str] = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Global dashboard statistics, optionally scoped to a single customer.

    Tenant isolation: a non-global user only ever sees aggregates over the
    customers they are assigned to. Global (system_admin) users see everything.
    """
    from app.models.customer import Customer

    allowed_customer_ids = accessible_customer_ids(db, user)  # None == all

    # Determine the customer-id set this request may aggregate over.
    if customer_id:
        require_customer_access(db, user, customer_id)
        effective_customer_ids = [customer_id]
    elif allowed_customer_ids is not None:
        effective_customer_ids = allowed_customer_ids
    else:
        effective_customer_ids = None  # global, no scoping

    # Base policy id set when scoped to a specific customer set
    scoped_policy_ids: Optional[list] = None
    if effective_customer_ids is not None:
        scoped_policy_ids = [
            p.id for p in db.query(FirewallPolicy.id)
            .filter(FirewallPolicy.customer_id.in_(effective_customer_ids)).all()
        ] if effective_customer_ids else []

    def _policy_filter(q):
        if scoped_policy_ids is not None:
            return q.filter(FirewallPolicy.id.in_(scoped_policy_ids))
        return q

    def _rule_filter(q):
        if scoped_policy_ids is not None:
            return q.filter(FirewallRule.policy_id.in_(scoped_policy_ids))
        return q

    def _finding_filter(q):
        if scoped_policy_ids is not None:
            return q.filter(Finding.policy_id.in_(scoped_policy_ids))
        return q

    def _customer_filter(q):
        if effective_customer_ids is not None:
            return q.filter(Customer.id.in_(effective_customer_ids)) if effective_customer_ids else q.filter(False)
        return q

    total_customers = _customer_filter(db.query(func.count(Customer.id))).scalar()
    total_policies = _policy_filter(db.query(func.count(FirewallPolicy.id))).scalar()
    total_rules = _rule_filter(db.query(func.count(FirewallRule.id))).scalar()
    enabled_rules = _rule_filter(
        db.query(func.count(FirewallRule.id)).filter(FirewallRule.enabled == True)
    ).scalar()
    disabled_rules = _rule_filter(
        db.query(func.count(FirewallRule.id)).filter(FirewallRule.enabled == False)
    ).scalar()
    total_findings = _finding_filter(db.query(func.count(Finding.id))).scalar()
    high_findings = _finding_filter(
        db.query(func.count(Finding.id)).filter(Finding.severity.in_(["High", "Critical"]))
    ).scalar()

    findings_by_type = (
        _finding_filter(db.query(Finding.finding_type, func.count(Finding.id)))
        .group_by(Finding.finding_type).all()
    )
    findings_by_severity = (
        _finding_filter(db.query(Finding.severity, func.count(Finding.id)))
        .group_by(Finding.severity).all()
    )

    # Exposure posture — derived from findings_by_type (no extra query). Surfaces
    # the highest-signal "reachable from untrusted networks / unencrypted" findings.
    _EXPOSURE_LABELS = [
        ("rdp_exposed", "RDP exposed"),
        ("ssh_exposed", "SSH exposed"),
        ("database_exposed", "Database exposed"),
        ("cleartext_service", "Cleartext protocols"),
    ]
    _ftype_counts = {t: c for t, c in findings_by_type}
    exposure_summary = {
        "total": sum(_ftype_counts.get(t, 0) for t, _ in _EXPOSURE_LABELS),
        "by_type": [
            {"type": t, "label": lbl, "count": _ftype_counts.get(t, 0)}
            for t, lbl in _EXPOSURE_LABELS if _ftype_counts.get(t, 0) > 0
        ],
    }
    vendor_dist = (
        _policy_filter(db.query(FirewallPolicy.vendor, func.count(FirewallPolicy.id)))
        .group_by(FirewallPolicy.vendor).all()
    )

    top_customers = (
        _customer_filter(db.query(Customer))
        .order_by(Customer.high_findings.desc())
        .limit(5).all()
    )

    # Policy risk heatmap data
    heatmap_q = (
        db.query(FirewallPolicy)
        .options(selectinload(FirewallPolicy.customer))
        .filter(FirewallPolicy.analysis_status == "completed")
    )
    if scoped_policy_ids is not None:
        heatmap_q = heatmap_q.filter(FirewallPolicy.id.in_(scoped_policy_ids))
    policies = (
        heatmap_q
        .order_by(
            FirewallPolicy.high_finding_count.desc(),
            FirewallPolicy.finding_count.desc(),
            FirewallPolicy.rule_count.desc(),
        )
        .limit(100)
        .all()
    )

    # Preload all rules and findings for heatmap policies in 2 bulk queries (avoids N+1)
    heatmap_policy_ids = [p.id for p in policies]
    _bulk_rules: dict[str, list] = {pid: [] for pid in heatmap_policy_ids}
    if heatmap_policy_ids:
        for r in db.query(FirewallRule).filter(FirewallRule.policy_id.in_(heatmap_policy_ids)).all():
            _bulk_rules.setdefault(r.policy_id, []).append(r)

    _bulk_sev: dict[str, dict] = {pid: {} for pid in heatmap_policy_ids}
    if heatmap_policy_ids:
        sev_rows = (
            db.query(Finding.policy_id, Finding.severity, func.count(Finding.id))
            .filter(Finding.policy_id.in_(heatmap_policy_ids))
            .group_by(Finding.policy_id, Finding.severity)
            .all()
        )
        for pid, sev, cnt in sev_rows:
            _bulk_sev.setdefault(pid, {})[sev] = cnt

    def _heatmap_risk(p: FirewallPolicy) -> int:
        """Risk score computed from preloaded bulk data — no extra DB calls."""
        if p.rule_count == 0:
            return 0
        rules = _bulk_rules.get(p.id, [])
        enabled = [r for r in rules if r.enabled]
        if not enabled:
            return 0
        sev_map = _bulk_sev.get(p.id, {})
        finding_score = min(50, (
            (sev_map.get("Critical", 0) * 8) +
            (sev_map.get("High", 0) * 5) +
            (sev_map.get("Medium", 0) * 2) +
            (sev_map.get("Low", 0) * 0.5)
        ))
        permissive = sum(
            1 for r in enabled
            if _is_any(r.sources or []) or _is_any(r.destinations or []) or _is_any(r.services or [])
        )
        perm_score = (permissive / len(enabled)) * 30
        zero_hit = sum(1 for r in enabled if r.hit_count is not None and r.hit_count == 0)
        zero_score = (zero_hit / len(enabled)) * 20
        return min(100, round(finding_score + perm_score + zero_score))

    risk_heatmap = []
    for p in policies:
        risk_heatmap.append({
            "policy_id": p.id,
            "firewall_name": p.firewall_name,
            "customer_id": p.customer_id,
            "customer_name": p.customer.name if p.customer else "",
            "vendor": p.vendor,
            "risk_score": _heatmap_risk(p),
            "finding_count": p.finding_count,
            "high_finding_count": p.high_finding_count,
            "rule_count": p.rule_count,
        })
    risk_heatmap.sort(key=lambda x: -x["risk_score"])

    return {
        "total_customers": total_customers,
        "total_policies": total_policies,
        "total_rules": total_rules,
        "enabled_rules": enabled_rules,
        "disabled_rules": disabled_rules,
        "total_findings": total_findings,
        "high_findings": high_findings,
        "findings_by_type": [{"type": t, "count": c} for t, c in findings_by_type],
        "findings_by_severity": [{"severity": s, "count": c} for s, c in findings_by_severity],
        "exposure_summary": exposure_summary,
        "vendor_distribution": [{"vendor": v, "count": c} for v, c in vendor_dist],
        "top_customers_by_risk": [
            {
                "id": c.id, "name": c.name,
                "high_findings": c.high_findings or 0,
                "total_findings": c.total_findings or 0,
                "total_policies": c.total_policies or 0,
                "total_rules": c.total_rules or 0,
            }
            for c in top_customers
        ],
        "risk_heatmap": risk_heatmap[:20],  # top 20 riskiest policies
    }


@router.get("/findings-trend")
def get_findings_trend(
    customer_id: Optional[str] = None,
    days: int = Query(90, ge=7, le=365),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Findings-over-time trend from completed analysis runs, bucketed by day.

    Tenant-isolated identically to the dashboard: a non-global user only sees
    runs for policies of customers they may access. Each completed run
    contributes its findings count (and severity snapshot, when available) to
    the day it completed.
    """
    from datetime import datetime, timedelta

    allowed = accessible_customer_ids(db, user)  # None == all customers
    if customer_id:
        require_customer_access(db, user, customer_id)

    policy_q = db.query(FirewallPolicy.id)
    if allowed is not None:
        if not allowed:
            return {"days": days, "points": []}
        policy_q = policy_q.filter(FirewallPolicy.customer_id.in_(allowed))
    if customer_id:
        policy_q = policy_q.filter(FirewallPolicy.customer_id == customer_id)
    scoped_ids = [pid for (pid,) in policy_q.all()]
    if not scoped_ids:
        return {"days": days, "points": []}

    cutoff = datetime.utcnow() - timedelta(days=days)
    runs = (
        db.query(AnalysisRun)
        .filter(
            AnalysisRun.policy_id.in_(scoped_ids),
            AnalysisRun.status == "completed",
            AnalysisRun.completed_at.isnot(None),
            AnalysisRun.completed_at >= cutoff,
        )
        .order_by(AnalysisRun.completed_at.asc())
        .all()
    )

    _SEVS = ["Critical", "High", "Medium", "Low", "Informational"]
    buckets: dict = {}
    for r in runs:
        day = r.completed_at.date().isoformat()
        b = buckets.setdefault(day, {"date": day, "total": 0, "runs": 0,
                                     **{s: 0 for s in _SEVS}})
        b["total"] += r.findings_created or 0
        b["runs"] += 1
        if r.severity_snapshot:
            try:
                snap = json.loads(r.severity_snapshot)
                for s in _SEVS:
                    b[s] += int(snap.get(s, 0))
            except (ValueError, TypeError):
                pass

    return {"days": days, "points": [buckets[k] for k in sorted(buckets)]}


@router.get("/{policy_id}")
def get_policy(
    policy_id: str,
    customer_id: Optional[str] = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    policy = _authz_policy(policy_id, db, user)
    if customer_id:
        assert_policy_customer(policy_id, customer_id, db)
    return _policy_detail(policy, db)


@router.delete("/{policy_id}")
def delete_policy(
    policy_id: str,
    customer_id: Optional[str] = None,
    db: Session = Depends(get_db),
    user: User = Depends(require_capability(CAP_DELETE_DATA)),
):
    policy = _authz_policy(policy_id, db, user)
    if customer_id:
        assert_policy_customer(policy_id, customer_id, db)
    cid = policy.customer_id
    db.delete(policy)
    db.commit()
    _refresh_customer_counters(cid, db)
    audit_log("policy.delete", user_id=user.id, policy_id=policy_id, customer_id=cid)
    return {"message": "Policy deleted"}


@router.post("/{policy_id}/reanalyze")
def reanalyze_policy(
    policy_id: str,
    background_tasks: BackgroundTasks,
    customer_id: Optional[str] = None,
    db: Session = Depends(get_db),
    user: User = Depends(require_capability(CAP_UPLOAD)),
):
    policy = _authz_policy(policy_id, db, user)
    if customer_id:
        assert_policy_customer(policy_id, customer_id, db)
    policy.analysis_status = "pending"
    db.commit()
    background_tasks.add_task(_run_bg, policy_id, policy.customer_id)
    audit_log("policy.reanalyze", user_id=user.id, policy_id=policy_id, customer_id=policy.customer_id)
    return {"message": "Re-analysis started"}


@router.get("/{policy_id}/risk-score")
def get_policy_risk_score(
    policy_id: str,
    customer_id: Optional[str] = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Return the computed risk score and breakdown for a policy."""
    p = _authz_policy(policy_id, db, user)
    if customer_id:
        assert_policy_customer(policy_id, customer_id, db)

    rules = db.query(FirewallRule).filter(FirewallRule.policy_id == policy_id).all()
    enabled = [r for r in rules if r.enabled]

    sev_counts = (
        db.query(Finding.severity, func.count(Finding.id))
        .filter(Finding.policy_id == policy_id)
        .group_by(Finding.severity).all()
    )
    sev_map = {s: c for s, c in sev_counts}

    permissive = [
        r for r in enabled
        if _is_any(r.sources or []) or _is_any(r.destinations or []) or _is_any(r.services or [])
    ]
    zero_hit = [r for r in enabled if r.hit_count is not None and r.hit_count == 0]

    return {
        "policy_id": policy_id,
        "risk_score": _policy_risk_score(p, db, _rules=rules, _sev_map=sev_map),
        "breakdown": {
            "critical_findings": sev_map.get("Critical", 0),
            "high_findings": sev_map.get("High", 0),
            "medium_findings": sev_map.get("Medium", 0),
            "low_findings": sev_map.get("Low", 0),
            "permissive_rule_count": len(permissive),
            "zero_hit_rule_count": len(zero_hit),
            "total_enabled_rules": len(enabled),
            "permissive_pct": round(len(permissive) / max(len(enabled), 1) * 100, 1),
            "zero_hit_pct": round(len(zero_hit) / max(len(enabled), 1) * 100, 1),
        }
    }


@router.get("/{policy_id}/health")
def get_policy_health(
    policy_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Run the Firewall Health & Best Practice Assessment.

    Returns configuration health checks, NAT review, and attack surface analysis.
    SAFETY NOTE: Read-only analysis. No firewall configuration is modified.
    """
    p = _authz_policy(policy_id, db, user)
    from app.analysis.health_assessor import run_health_assessment
    return run_health_assessment(policy_id, db)


@router.get("/{policy_id}/scorecard")
def get_policy_scorecard(
    policy_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Return a Hygiene Scorecard for a policy.

    Score (0–100) is a weighted average across six hygiene dimensions.
    Strengths are dimensions scoring ≥ 80 %.
    Improvement areas are dimensions scoring < 60 % or with notable absolute counts.

    SAFETY NOTE: Read-only analysis. No firewall rules are modified.
    """
    p = _authz_policy(policy_id, db, user)

    rules   = db.query(FirewallRule).filter(FirewallRule.policy_id == policy_id).all()
    objects = db.query(FirewallObject).filter(FirewallObject.policy_id == policy_id).all()

    total_rules   = len(rules)
    enabled       = [r for r in rules if r.enabled]
    allow_rules   = [r for r in enabled if (r.action or "").lower() in ("accept", "allow", "permit")]
    disabled      = [r for r in rules if not r.enabled]
    total_objects = len(objects)

    # ── Raw counts ───────────────────────────────────────────────────────────
    n_allow = len(allow_rules)

    # 1. Logging
    logging_ok    = sum(1 for r in allow_rules if r.logging_enabled)
    logging_pct   = round(logging_ok / max(n_allow, 1) * 100, 1)

    # 2. Documentation (comment ≥ 10 chars with at least one letter)
    def has_doc(r):
        c = (r.comments or "").strip()
        return len(c) >= 10 and any(ch.isalpha() for ch in c)
    documented    = sum(1 for r in allow_rules if has_doc(r))
    undocumented  = n_allow - documented
    doc_pct       = round(documented / max(n_allow, 1) * 100, 1)

    # 3. Permissiveness
    any_src = lambda r: _is_any(r.sources or [])
    any_dst = lambda r: _is_any(r.destinations or [])
    any_svc = lambda r: _is_any(r.services or [])
    permissive_rules  = [r for r in allow_rules if any_src(r) or any_dst(r) or any_svc(r)]
    any_svc_rules     = [r for r in allow_rules if any_svc(r)]
    n_perm            = len(permissive_rules)
    perm_pct          = round(n_perm / max(n_allow, 1) * 100, 1)

    # 4. Usage (zero-hit among enabled rules that have hit data)
    rules_with_data = [r for r in enabled if r.hit_count is not None]
    zero_hit        = [r for r in rules_with_data if r.hit_count == 0]
    n_zero_hit      = len(zero_hit)
    usage_score_pct = round((1 - n_zero_hit / max(len(rules_with_data), 1)) * 100, 1)

    # 5. Temporary rules
    from app.config import settings as cfg
    temp_rules = [
        r for r in rules
        if any(kw in (r.rule_name or "").lower() or kw in (r.comments or "").lower()
               for kw in cfg.temp_keywords)
    ]
    n_temp = len(temp_rules)

    # 6. Object hygiene — unused objects
    used_names: set[str] = set()
    for r in rules:
        for n in (r.sources or []) + (r.destinations or []) + (r.services or []):
            used_names.add(n.lower())
    unused_objects = [
        o for o in objects
        if o.object_name.lower() not in used_names
        and o.object_name.lower() not in ("any", "all")
    ]
    n_unused_obj = len(unused_objects)
    obj_hygiene_pct = round((1 - n_unused_obj / max(total_objects, 1)) * 100, 1)

    # 7. Duplicate objects
    from collections import Counter
    val_counts = Counter(
        (o.value or "").strip().lower()
        for o in objects
        if o.object_type not in ("group", "service-group")
        and (o.value or "").strip().lower() not in ("", "any", "all")
    )
    n_duplicate_obj = sum(c - 1 for c in val_counts.values() if c > 1)

    # ── Dimension scores (0–100) ─────────────────────────────────────────────
    dim_logging   = logging_pct                          # 20 % weight
    dim_doc       = doc_pct                              # 20 % weight
    dim_perm      = max(0, 100 - perm_pct)               # 25 % weight
    dim_usage     = usage_score_pct                      # 20 % weight
    dim_obj       = obj_hygiene_pct                      # 15 % weight

    weights       = [0.20, 0.20, 0.25, 0.20, 0.15]
    dim_scores    = [dim_logging, dim_doc, dim_perm, dim_usage, dim_obj]
    total_score   = round(sum(w * s for w, s in zip(weights, dim_scores)))

    # ── Strengths (dimension ≥ 80 %) ─────────────────────────────────────────
    strengths = []
    if dim_logging >= 80:
        strengths.append(f"Logging enabled on {logging_pct:.0f}% of allow rules ({logging_ok}/{n_allow})")
    if dim_doc >= 80:
        strengths.append(f"Documentation present on {doc_pct:.0f}% of allow rules")
    if dim_perm >= 80:
        strengths.append(f"Only {n_perm} permissive rule{'s' if n_perm != 1 else ''} — good least-privilege posture")
    if dim_usage >= 80 and rules_with_data:
        strengths.append(f"Hit-count data available for {len(rules_with_data)}/{len(enabled)} enabled rules")
    if n_zero_hit == 0 and rules_with_data:
        strengths.append("No zero-hit rules detected")
    if n_temp == 0:
        strengths.append("No temporary or test rules detected")
    if dim_obj >= 90:
        strengths.append(f"Object database is clean — only {n_unused_obj} unused object{'s' if n_unused_obj != 1 else ''}")
    if len(disabled) == 0:
        strengths.append("No disabled rules — policy is fully active")
    elif len(disabled) <= 2:
        strengths.append(f"Low number of disabled rules ({len(disabled)})")

    # ── Improvement areas (dimension < 60 % or notable count) ────────────────
    improvements = []

    if len(any_svc_rules) > 0:
        improvements.append({
            "metric": "any_service",
            "label": f"{len(any_svc_rules)} rule{'s' if len(any_svc_rules) != 1 else ''} use Any service",
            "count": len(any_svc_rules),
            "severity": "High" if len(any_svc_rules) > 5 else "Medium",
        })
    if n_perm > 0 and len(any_svc_rules) != n_perm:
        improvements.append({
            "metric": "overly_permissive",
            "label": f"{n_perm} overly permissive rule{'s' if n_perm != 1 else ''} (any src/dst/svc)",
            "count": n_perm,
            "severity": "High" if n_perm > 3 else "Medium",
        })
    if undocumented > 0:
        improvements.append({
            "metric": "no_documentation",
            "label": f"{undocumented} rule{'s have' if undocumented != 1 else ' has'} no owner or documentation",
            "count": undocumented,
            "severity": "Medium",
        })
    if n_unused_obj > 0:
        improvements.append({
            "metric": "unused_objects",
            "label": f"{n_unused_obj} object{'s are' if n_unused_obj != 1 else ' is'} unused",
            "count": n_unused_obj,
            "severity": "Low",
        })
    if n_temp > 0:
        improvements.append({
            "metric": "temporary_rules",
            "label": f"{n_temp} rule{'s appear' if n_temp != 1 else ' appears'} temporary or test",
            "count": n_temp,
            "severity": "Medium",
        })
    if n_zero_hit > 0:
        improvements.append({
            "metric": "zero_hit",
            "label": f"{n_zero_hit} rule{'s have' if n_zero_hit != 1 else ' has'} zero hits",
            "count": n_zero_hit,
            "severity": "Medium",
        })
    if len(disabled) > 2:
        improvements.append({
            "metric": "disabled_rules",
            "label": f"{len(disabled)} rule{'s are' if len(disabled) != 1 else ' is'} disabled",
            "count": len(disabled),
            "severity": "Low",
        })
    if n_duplicate_obj > 0:
        improvements.append({
            "metric": "duplicate_objects",
            "label": f"{n_duplicate_obj} duplicate object value{'s' if n_duplicate_obj != 1 else ''} detected",
            "count": n_duplicate_obj,
            "severity": "Low",
        })

    # Sort improvements by severity weight
    _sev_order = {"High": 0, "Medium": 1, "Low": 2}
    improvements.sort(key=lambda x: _sev_order.get(x["severity"], 9))

    return {
        "policy_id": policy_id,
        "firewall_name": p.firewall_name,
        "vendor": p.vendor,
        "score": total_score,
        "grade": (
            "A" if total_score >= 90 else
            "B" if total_score >= 80 else
            "C" if total_score >= 65 else
            "D" if total_score >= 50 else
            "F"
        ),
        "dimensions": [
            {"key": "logging",       "label": "Logging Coverage",    "score": round(dim_logging),  "weight": 20, "detail": f"{logging_ok}/{n_allow} allow rules log traffic"},
            {"key": "documentation", "label": "Documentation",       "score": round(dim_doc),      "weight": 20, "detail": f"{documented}/{n_allow} rules have comments"},
            {"key": "permissiveness","label": "Least Privilege",     "score": round(dim_perm),     "weight": 25, "detail": f"{n_perm} permissive rules out of {n_allow}"},
            {"key": "usage",         "label": "Rule Usage",          "score": round(dim_usage),    "weight": 20, "detail": f"{n_zero_hit} zero-hit rules detected"},
            {"key": "objects",       "label": "Object Hygiene",      "score": round(dim_obj),      "weight": 15, "detail": f"{n_unused_obj} unused objects out of {total_objects}"},
        ],
        "strengths": strengths,
        "improvements": improvements,
        "meta": {
            "total_rules": total_rules,
            "enabled_rules": len(enabled),
            "allow_rules": n_allow,
            "total_objects": total_objects,
        },
    }


_NAT_EXPOSURE_FINDING_TYPES = {
    "nat_public_to_internal", "nat_static", "nat_source", "nat_duplicate",
    "nat_overlap", "nat_without_policy", "policy_without_nat",
    "any_service_public_exposure", "rdp_public_exposure", "ssh_public_exposure",
    "telnet_public_exposure", "smb_public_exposure", "winrm_public_exposure",
    "vnc_public_exposure", "database_public_exposure", "sensitive_destination_exposure",
    "public_exposure_no_logging", "mgmt_on_public_interface",
}


@router.get("/{policy_id}/public-exposure")
def get_public_exposure(
    policy_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """NAT & Public Exposure review for a policy (read-only).

    Returns the public-exposure inventory (public IPs, published internal
    services, exposed ports, related NAT/security rules, risk score) plus the
    related persisted findings. When no NAT data exists, ``nat_available`` is
    False so the UI can show "NAT Analysis Not Available" instead of fabricating
    findings. PolicyInsight never writes to the firewall.
    """
    import json as _json
    from app.analysis import nat_exposure, interfaces as iface_mod
    from app.analysis.normalizer import build_object_map
    from app.analysis.engine import _rule_to_dict, _obj_to_dict
    from app.models.device import FirewallDevice

    p = _authz_policy(policy_id, db, user)

    rules_orm = db.query(FirewallRule).filter(FirewallRule.policy_id == policy_id).all()
    objects_orm = db.query(FirewallObject).filter(FirewallObject.policy_id == policy_id).all()
    rules = [_rule_to_dict(r) for r in rules_orm]
    obj_map = build_object_map([_obj_to_dict(o) for o in objects_orm])

    result = nat_exposure.analyze(rules, p.nat_rules, obj_map)

    # Interface / public-IP inventory from the linked device (where interface
    # data was captured during sync). Degrades gracefully when absent.
    device_ifaces: list = []
    if p.device_id:
        dev = db.query(FirewallDevice).filter(FirewallDevice.id == p.device_id).first()
        if dev and dev.device_interfaces:
            try:
                device_ifaces = _json.loads(dev.device_interfaces) or []
            except (ValueError, TypeError):
                device_ifaces = []
    iface_result = iface_mod.analyze(device_ifaces, p.nat_rules, obj_map, p.firewall_name or "")

    findings = [
        {"id": f.id, "finding_type": f.finding_type, "severity": f.severity,
         "confidence": f.confidence, "title": f.title, "status": f.status,
         "evidence": f.evidence}
        for f in db.query(Finding).filter(
            Finding.policy_id == policy_id,
            Finding.finding_type.in_(_NAT_EXPOSURE_FINDING_TYPES),
        ).all()
    ]

    exp = result["exposure"]
    return {
        "policy_id": policy_id,
        "firewall_name": p.firewall_name,
        "vendor": p.vendor,
        "nat_available": result["nat_available"],
        "nat_rule_count": len(p.nat_rules or []),
        "public_ips": exp["public_ips"],
        "exposed_ports": exp["exposed_ports"],
        "exposures": exp["exposures"],
        "risk_score": exp["risk_score"],
        "interfaces_available": iface_result["interfaces_available"],
        "public_interfaces": iface_result["public_interfaces"],
        "public_ip_inventory": iface_result["public_ip_inventory"],
        "findings": findings,
    }


@router.get("/{policy_id}/permissive-analysis")
def get_permissive_analysis(
    policy_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Analyze overly permissive rules and return specific hardening suggestions.

    For each permissive rule (any source / any dest / any service), generates
    targeted recommendations. Sorted by risk score (highest first).

    SAFETY NOTE: All suggestions require engineer validation and change-approval
    before implementation. The tool never modifies firewall rules.
    """
    p = _authz_policy(policy_id, db, user)

    rules = db.query(FirewallRule).filter(
        FirewallRule.policy_id == policy_id,
        FirewallRule.enabled == True,
        FirewallRule.action.in_(["accept", "allow", "permit"]),
    ).order_by(FirewallRule.risk_score.desc()).all()

    # Pre-load findings for this policy
    all_findings = db.query(Finding).filter(Finding.policy_id == policy_id).all()
    rule_findings: dict[str, list] = {}
    for f in all_findings:
        for rid in (f.affected_rules or []):
            rule_findings.setdefault(rid, []).append({
                "id": f.id, "type": f.finding_type, "severity": f.severity, "title": f.title,
            })

    suggestions = []
    for r in rules:
        src_any  = _is_any(r.sources or [])
        dst_any  = _is_any(r.destinations or [])
        svc_any  = _is_any(r.services or [])

        if not (src_any or dst_any or svc_any):
            continue

        rule_suggestions = []
        risk_level = "High" if src_any and dst_any else "Medium" if src_any or dst_any else "Low"

        if src_any:
            rule_suggestions.append({
                "field": "source",
                "issue": "Source is set to Any — allows traffic from all IP addresses including the internet",
                "suggestion": "Restrict source to specific IP addresses, subnets, or named objects (e.g., internal network 10.0.0.0/8)",
                "severity": "High" if dst_any else "Medium",
            })
        if dst_any:
            rule_suggestions.append({
                "field": "destination",
                "issue": "Destination is set to Any — allows traffic to any internal or external host",
                "suggestion": "Restrict destination to specific servers, subnets, or security zones that this rule should protect",
                "severity": "High" if src_any else "Medium",
            })
        if svc_any:
            rule_suggestions.append({
                "field": "service",
                "issue": "Service/port is set to Any — permits all protocols and ports",
                "suggestion": "Specify only required protocols and ports. If HTTP/HTTPS is needed, use explicit service objects rather than Any",
                "severity": "Medium",
            })

        # Additional suggestions based on context
        if not r.logging_enabled:
            rule_suggestions.append({
                "field": "logging",
                "issue": "Logging is disabled on this permissive rule — traffic is invisible to monitoring",
                "suggestion": "Enable logging to capture traffic flow data and support incident response",
                "severity": "High",
            })

        hit_note = None
        if r.hit_count is not None and r.hit_count > 0 and r.last_hit:
            hit_note = f"Last hit: {r.last_hit} · Total hits: {r.hit_count}"
        elif r.hit_count == 0:
            hit_note = "Zero hits — rule may be unused or unreachable"

        suggestions.append({
            "rule_id":      r.id,
            "rule_number":  r.rule_number,
            "rule_name":    r.rule_name or f"Rule #{r.rule_number}",
            "section":      r.section,
            "sources":      r.sources or [],
            "destinations": r.destinations or [],
            "services":     r.services or [],
            "action":       r.action,
            "enabled":      r.enabled,
            "logging_enabled": r.logging_enabled,
            "hit_count":    r.hit_count,
            "last_hit":     r.last_hit,
            "risk_score":   r.risk_score or 0,
            "risk_level":   risk_level,
            "src_any":      src_any,
            "dst_any":      dst_any,
            "svc_any":      svc_any,
            "hit_note":     hit_note,
            "suggestions":  rule_suggestions,
            "findings":     rule_findings.get(r.id, []),
        })

    return {
        "policy_id":        policy_id,
        "policy_name":      p.firewall_name,
        "vendor":           p.vendor,
        "total_rules":      p.rule_count,
        "permissive_count": len(suggestions),
        "safety_note":      (
            "⚠ All suggestions require engineer validation and formal change approval "
            "before implementation. This tool operates in read-only analysis mode."
        ),
        "suggestions":      suggestions,
    }


@router.get("/{policy_id}/rules")
def get_rules(
    policy_id: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    search: Optional[str] = None,
    action: Optional[str] = None,
    enabled: Optional[bool] = None,
    zero_hits: Optional[bool] = None,
    has_findings: Optional[bool] = None,
    has_any: Optional[bool] = None,       # any source/dest/service
    min_risk: Optional[int] = Query(None, ge=0, le=100),       # minimum risk score
    sort_by: Optional[str] = None,        # rule_number|risk_score|hit_count|rule_name
    sort_dir: Optional[str] = None,       # asc|desc
    export: Optional[bool] = None,        # return CSV
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    _authz_policy(policy_id, db, user)
    sort_by, sort_dir = validate_sort(
        sort_by, sort_dir,
        ("rule_number", "risk_score", "hit_count", "rule_name"),
        "rule_number",
    )
    q = db.query(FirewallRule).filter(FirewallRule.policy_id == policy_id)

    if search:
        q = q.filter(
            or_(
                FirewallRule.rule_name.ilike(f"%{search}%"),
                FirewallRule.comments.ilike(f"%{search}%"),
                FirewallRule.rule_id.ilike(f"%{search}%"),
                FirewallRule.section.ilike(f"%{search}%"),
            )
        )
    if action:
        # Support comma-separated list (e.g. "accept,allow,permit") and case-insensitive match
        action_values = [
            a.lower() for a in validate_csv_choices(
                action.lower(), ("accept", "allow", "permit", "deny", "drop", "reject"), "action"
            )
        ]
        q = q.filter(func.lower(FirewallRule.action).in_(action_values))
    if enabled is not None:
        q = q.filter(FirewallRule.enabled == enabled)
    if zero_hits:
        q = q.filter(
            FirewallRule.enabled == True,
            FirewallRule.hit_count == 0,
        )
    if min_risk is not None:
        q = q.filter(FirewallRule.risk_score >= min_risk)

    # Sorting
    sort_col_map = {
        "risk_score": FirewallRule.risk_score,
        "hit_count": FirewallRule.hit_count,
        "rule_name": FirewallRule.rule_name,
        "rule_number": FirewallRule.rule_number,
    }
    sort_col = sort_col_map[sort_by]
    if sort_dir == "desc":
        sort_col = sort_col.desc()

    # Pre-load finding counts for this policy (needed for has_findings filter too)
    findings_all = db.query(Finding).filter(Finding.policy_id == policy_id).all()
    finding_counts: dict[str, int] = {}
    finding_types: dict[str, list[str]] = {}
    for f in findings_all:
        for rid in (f.affected_rules or []):
            finding_counts[rid] = finding_counts.get(rid, 0) + 1
            finding_types.setdefault(rid, [])
            if f.finding_type not in finding_types[rid]:
                finding_types[rid].append(f.finding_type)

    # Fetch all (needed for has_findings / has_any post-filter or export)
    if has_findings is not None or has_any is not None or export:
        all_rules = q.order_by(sort_col).all()

        if has_any is not None:
            all_rules = [
                r for r in all_rules
                if has_any == (_is_any(r.sources or []) or _is_any(r.destinations or []) or _is_any(r.services or []))
            ]
        if has_findings is not None:
            all_rules = [
                r for r in all_rules
                if has_findings == (finding_counts.get(r.id, 0) > 0)
            ]

        if export:
            return _rules_csv(all_rules, finding_counts, finding_types)

        total = len(all_rules)
        offset = (page - 1) * page_size
        rules = all_rules[offset: offset + page_size]
    else:
        total = q.count()
        rules = q.order_by(sort_col).offset((page - 1) * page_size).limit(page_size).all()

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "rules": [_rule_dict(r, finding_counts, finding_types) for r in rules],
    }


def _rules_csv(rules, finding_counts, finding_types) -> StreamingResponse:
    """Export rules to CSV."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Rule #", "Rule ID", "Name", "Section",
        "Sources", "Destinations", "Services", "Applications",
        "Action", "Enabled", "Logging", "Hit Count", "Last Hit",
        "Risk Score", "Findings", "Finding Types", "Comments",
    ])
    for r in rules:
        writer.writerow(spreadsheet_row([
            r.rule_number, r.rule_id, r.rule_name, r.section,
            "; ".join(r.sources or []),
            "; ".join(r.destinations or []),
            "; ".join(r.services or []),
            "; ".join(r.applications or []),
            r.action, "Yes" if r.enabled else "No",
            "Yes" if r.logging_enabled else "No",
            r.hit_count if r.hit_count is not None else "",
            r.last_hit or "",
            r.risk_score or 0,
            finding_counts.get(r.id, 0),
            "; ".join(finding_types.get(r.id, [])),
            r.comments or "",
        ]))
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers=attachment_headers("rulebase.csv"),
    )


@router.get("/{policy_id}/rules/{rule_id}")
def get_rule(
    policy_id: str,
    rule_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    _authz_policy(policy_id, db, user)
    rule = db.query(FirewallRule).filter(
        FirewallRule.policy_id == policy_id,
        FirewallRule.id == rule_id,
    ).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    findings = db.query(Finding).filter(Finding.policy_id == policy_id).all()
    rule_findings = [f for f in findings if rule_id in (f.affected_rules or [])]

    return {
        **_rule_dict(rule, {}, {}),
        "risk_factors": rule.risk_factors or {},
        "findings": [_finding_dict(f) for f in rule_findings],
        "raw_data": rule.raw_data,
    }


# ── Background tasks ──────────────────────────────────────────────────────────

def _run_bg(policy_id: str, customer_id: str):
    from app.database import SessionLocal
    db = SessionLocal()
    try:
        run_analysis(policy_id, db)
        _refresh_customer_counters(customer_id, db)
    finally:
        db.close()


def _refresh_customer_counters(customer_id: str, db):
    from app.models.customer import Customer
    c = db.query(Customer).filter(Customer.id == customer_id).first()
    if not c:
        return
    policies = db.query(FirewallPolicy).filter(FirewallPolicy.customer_id == customer_id).all()
    pids = [p.id for p in policies]
    c.total_policies = len(policies)
    c.total_rules = db.query(func.count(FirewallRule.id)).filter(
        FirewallRule.policy_id.in_(pids)).scalar() if pids else 0
    c.total_findings = db.query(func.count(Finding.id)).filter(
        Finding.policy_id.in_(pids)).scalar() if pids else 0
    c.high_findings = db.query(func.count(Finding.id)).filter(
        Finding.policy_id.in_(pids), Finding.severity.in_(["High", "Critical"])).scalar() if pids else 0
    db.commit()


# ── Serialization helpers ─────────────────────────────────────────────────────

def _policy_summary(p: FirewallPolicy) -> dict:
    return {
        "id": p.id,
        "customer_id": p.customer_id,
        "customer_name": p.customer.name if p.customer else "",
        "firewall_name": p.firewall_name,
        "vendor": p.vendor,
        "policy_package": p.policy_package,
        "upload_date": p.upload_date.isoformat() if p.upload_date else None,
        "original_filename": p.original_filename,
        "rule_count": p.rule_count,
        "object_count": p.object_count,
        "finding_count": p.finding_count,
        "high_finding_count": p.high_finding_count,
        "analysis_status": p.analysis_status,
        "analysis_error": p.analysis_error,
        "complexity_score": p.complexity_score,
        "cleanup_readiness_score": p.cleanup_readiness_score,
        "health_score": p.health_score,
        "import_quality_score": p.import_quality_score,
    }


def _policy_detail(p: FirewallPolicy, db: Session) -> dict:
    findings_by_type = (
        db.query(Finding.finding_type, func.count(Finding.id))
        .filter(Finding.policy_id == p.id)
        .group_by(Finding.finding_type).all()
    )
    findings_by_severity = (
        db.query(Finding.severity, func.count(Finding.id))
        .filter(Finding.policy_id == p.id)
        .group_by(Finding.severity).all()
    )
    return {
        **_policy_summary(p),
        "notes": p.notes,
        "findings_by_type": [{"type": t, "count": c} for t, c in findings_by_type],
        "findings_by_severity": [{"severity": s, "count": c} for s, c in findings_by_severity],
        "complexity_score": p.complexity_score,
        "complexity_breakdown": p.complexity_breakdown or {},
        "cleanup_readiness_score": p.cleanup_readiness_score,
        "health_score": p.health_score,
        "import_quality_score": p.import_quality_score,
        "import_quality": p.import_quality or {},
        "top_risk_drivers": p.top_risk_drivers or [],
    }


def _rule_dict(r: FirewallRule, finding_counts: dict, finding_types: dict = None) -> dict:
    src_any = _is_any(r.sources or [])
    dst_any = _is_any(r.destinations or [])
    svc_any = _is_any(r.services or [])
    return {
        "id": r.id,
        "rule_id": r.rule_id,
        "rule_uid": r.rule_uid,
        "rule_number": r.rule_number,
        "rule_name": r.rule_name,
        "section": r.section,
        "source_interfaces": r.source_interfaces,
        "destination_interfaces": r.destination_interfaces,
        "sources": r.sources,
        "destinations": r.destinations,
        "services": r.services,
        "applications": r.applications,
        "action": r.action,
        "schedule": r.schedule,
        "enabled": r.enabled,
        "logging_enabled": r.logging_enabled,
        "nat_enabled": r.nat_enabled,
        "comments": r.comments,
        "hit_count": r.hit_count,
        "last_hit": r.last_hit,
        "first_hit": r.first_hit,
        "risk_score": r.risk_score,
        "finding_count": finding_counts.get(r.id, 0),
        "finding_types": (finding_types or {}).get(r.id, []),
        # Permissive flags for frontend highlighting
        "src_any": src_any,
        "dst_any": dst_any,
        "svc_any": svc_any,
        "is_permissive": src_any or dst_any or svc_any,
    }


def _finding_dict(f: Finding) -> dict:
    return {
        "id": f.id,
        "finding_type": f.finding_type,
        "severity": f.severity,
        "confidence": f.confidence,
        "title": f.title,
        "description": f.description,
        "recommendation": f.recommendation,
        "status": f.status,
    }
