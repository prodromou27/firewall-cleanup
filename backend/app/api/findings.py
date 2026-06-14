"""Findings management API."""
import csv
import io
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import Optional, List
from app.database import get_db
from app.models.finding import Finding, FindingComment
from app.models.policy import FirewallPolicy, FirewallRule
from app.api.tenant import get_finding_with_customer_check, filter_finding_ids_by_customer
from pydantic import BaseModel

router = APIRouter(prefix="/api/findings", tags=["findings"])

# Spec-aligned finding statuses (Section 15)
VALID_STATUSES = [
    "New",
    "Review Required",
    "In Review",
    "Requires Business Validation",
    "Requires Customer Confirmation",
    "Confirmed Cleanup Candidate",
    "Manual Change Required",
    "Change Planned Outside Tool",
    "Cleanup Completed Outside Tool",
    "False Positive",
    "Accepted Risk",
    "Deferred",
    "Reopened",
]

VALID_PRIORITIES = [
    "Immediate",
    "High",
    "Standard",
    "Low",
    "Monitor",
]


class UpdateFindingRequest(BaseModel):
    status: Optional[str] = None
    engineer_comment: Optional[str] = None
    priority: Optional[str] = None
    assigned_to: Optional[str] = None
    due_date: Optional[str] = None
    risk_acceptance_reason: Optional[str] = None
    risk_acceptance_expiry: Optional[str] = None
    risk_acceptance_ref: Optional[str] = None
    risk_accepted_by: Optional[str] = None


class AddCommentRequest(BaseModel):
    comment: str
    author: Optional[str] = "engineer"

    @property
    def safe_author(self) -> str:
        """Return sanitised author string — strip whitespace, cap at 64 chars, fallback to 'engineer'."""
        raw = (self.author or "").strip()
        return raw[:64] if raw else "engineer"


@router.get("")
def list_findings(
    policy_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    severity: Optional[str] = None,
    confidence: Optional[str] = None,
    finding_type: Optional[str] = None,
    status: Optional[str] = None,
    priority: Optional[str] = None,
    assigned_to: Optional[str] = None,
    vendor: Optional[str] = None,
    export: Optional[bool] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
):
    q = db.query(Finding)

    if customer_id:
        policy_ids = [
            p.id for p in db.query(FirewallPolicy)
            .filter(FirewallPolicy.customer_id == customer_id).all()
        ]
        if not policy_ids:
            return {"total": 0, "page": page, "page_size": page_size, "findings": []}
        q = q.filter(Finding.policy_id.in_(policy_ids))

    if policy_id:
        q = q.filter(Finding.policy_id == policy_id)
    if severity:
        q = q.filter(Finding.severity == severity)
    if confidence:
        q = q.filter(Finding.confidence == confidence)
    if finding_type:
        q = q.filter(Finding.finding_type == finding_type)
    if status:
        q = q.filter(Finding.status == status)
    if priority:
        q = q.filter(Finding.priority == priority)
    if assigned_to:
        q = q.filter(Finding.assigned_to == assigned_to)
    if vendor:
        q = q.filter(Finding.vendor == vendor)

    from sqlalchemy import case
    sev_order = case(
        {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4},
        value=Finding.severity,
        else_=5,
    )

    if export:
        _EXPORT_LIMIT = 10_000
        all_findings = q.order_by(sev_order, Finding.created_at.desc()).limit(_EXPORT_LIMIT).all()
        # Scope policy_map to the same customer filter used above (no cross-tenant leakage)
        policy_q = db.query(FirewallPolicy)
        if customer_id:
            policy_q = policy_q.filter(FirewallPolicy.customer_id == customer_id)
        policy_map = {p.id: p for p in policy_q.all()}
        return _findings_csv(all_findings, policy_map)

    total = q.count()
    findings = (
        q.order_by(sev_order, Finding.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    all_rule_ids: List[str] = []
    for f in findings:
        for rid in (f.affected_rules or []):
            if rid not in all_rule_ids:
                all_rule_ids.append(rid)

    rule_map: dict = {}
    if all_rule_ids:
        rules = db.query(FirewallRule).filter(FirewallRule.id.in_(all_rule_ids)).all()
        rule_map = {r.id: _rule_dict(r) for r in rules}

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "findings": [_finding_dict(f, rule_map) for f in findings],
    }


def _findings_csv(findings, policy_map) -> StreamingResponse:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "ID", "Policy", "Vendor", "Type", "Severity", "Confidence", "Priority",
        "Title", "Affected Rules (count)", "Status", "Assigned To", "Due Date",
        "Risk Score", "Engineer Comment", "Recommendation", "Created",
    ])
    for f in findings:
        p = policy_map.get(f.policy_id)
        writer.writerow([
            f.id,
            p.firewall_name if p else f.policy_id,
            f.vendor or (p.vendor if p else ""),
            f.finding_type,
            f.severity,
            f.confidence,
            f.priority or "Standard",
            f.title,
            len(f.affected_rules or []),
            f.status,
            f.assigned_to or "",
            f.due_date or "",
            f.risk_score,
            f.engineer_comment or "",
            f.recommendation or "",
            f.created_at.isoformat() if f.created_at else "",
        ])
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=findings.csv"},
    )


@router.get("/{finding_id}")
def get_finding(
    finding_id: str,
    customer_id: Optional[str] = None,
    db: Session = Depends(get_db),
):
    f = get_finding_with_customer_check(finding_id, customer_id, db)
    return _finding_detail(f, db)


@router.patch("/{finding_id}")
def update_finding(
    finding_id: str,
    body: UpdateFindingRequest,
    customer_id: Optional[str] = None,
    db: Session = Depends(get_db),
):
    f = get_finding_with_customer_check(finding_id, customer_id, db)

    old_status = f.status

    if body.status and body.status not in VALID_STATUSES:
        raise HTTPException(status_code=400, detail=f"Invalid status: {body.status}")
    if body.priority and body.priority not in VALID_PRIORITIES:
        raise HTTPException(status_code=400, detail=f"Invalid priority: {body.priority}")

    if body.status:
        f.status = body.status
    if body.engineer_comment is not None:
        f.engineer_comment = body.engineer_comment
    if body.priority is not None:
        f.priority = body.priority
    if body.assigned_to is not None:
        f.assigned_to = body.assigned_to
    if body.due_date is not None:
        f.due_date = body.due_date
    if body.risk_acceptance_reason is not None:
        f.risk_acceptance_reason = body.risk_acceptance_reason
    if body.risk_acceptance_expiry is not None:
        f.risk_acceptance_expiry = body.risk_acceptance_expiry
    if body.risk_acceptance_ref is not None:
        f.risk_acceptance_ref = body.risk_acceptance_ref
    if body.risk_accepted_by is not None:
        f.risk_accepted_by = body.risk_accepted_by

    # Only create a comment record when there is meaningful content to record
    if body.status or body.engineer_comment:
        comment = FindingComment(
            finding_id=finding_id,
            author="engineer",
            comment=body.engineer_comment or "",
            old_status=old_status,
            new_status=body.status or old_status,
        )
        db.add(comment)
    db.commit()
    db.refresh(f)
    return _finding_dict(f)


@router.post("/bulk-update")
def bulk_update_findings(
    finding_ids: List[str],
    body: UpdateFindingRequest,
    customer_id: Optional[str] = None,
    db: Session = Depends(get_db),
):
    if body.status and body.status not in VALID_STATUSES:
        raise HTTPException(status_code=400, detail="Invalid status.")
    if body.priority and body.priority not in VALID_PRIORITIES:
        raise HTTPException(status_code=400, detail="Invalid priority.")

    # Cap batch size to prevent abuse
    finding_ids = finding_ids[:500]

    # Enforce tenant isolation — only allow updates to findings owned by this customer
    finding_ids = filter_finding_ids_by_customer(finding_ids, customer_id, db)

    findings = (
        db.query(Finding)
        .filter(Finding.id.in_(finding_ids))
        .all()
    )
    updated = 0
    for f in findings:
        old_status = f.status
        if body.status:
            f.status = body.status
        if body.engineer_comment is not None:
            f.engineer_comment = body.engineer_comment
        if body.priority is not None:
            f.priority = body.priority
        if body.assigned_to is not None:
            f.assigned_to = body.assigned_to
        if body.due_date is not None:
            f.due_date = body.due_date
        db.add(FindingComment(
            finding_id=f.id, author="engineer",
            comment=body.engineer_comment or "",
            old_status=old_status,
            new_status=body.status or old_status,
        ))
        updated += 1

    db.commit()
    return {"updated": updated}


@router.post("/{finding_id}/comments")
def add_comment(
    finding_id: str,
    body: AddCommentRequest,
    customer_id: Optional[str] = None,
    db: Session = Depends(get_db),
):
    f = get_finding_with_customer_check(finding_id, customer_id, db)
    c = FindingComment(
        finding_id=finding_id,
        author=body.safe_author,
        comment=body.comment[:4000],  # cap comment length
        old_status=f.status,
        new_status=f.status,
    )
    db.add(c)
    db.commit()
    return {
        "id": c.id,
        "author": c.author,
        "comment": c.comment,
        "created_at": c.created_at.isoformat() if c.created_at else None,
    }


@router.get("/{finding_id}/comments")
def get_comments(
    finding_id: str,
    customer_id: Optional[str] = None,
    db: Session = Depends(get_db),
):
    f = get_finding_with_customer_check(finding_id, customer_id, db)
    comments = (
        db.query(FindingComment)
        .filter(FindingComment.finding_id == finding_id)
        .order_by(FindingComment.created_at)
        .all()
    )
    return [
        {
            "id": c.id,
            "author": c.author,
            "comment": c.comment,
            "old_status": c.old_status,
            "new_status": c.new_status,
            "created_at": c.created_at.isoformat() if c.created_at else None,
        }
        for c in comments
    ]


def _rule_dict(r: FirewallRule) -> dict:
    def _any_highlight(vals: list) -> bool:
        return any(str(v).strip().lower() in ("any", "all", "*") for v in (vals or []))

    return {
        "id": r.id,
        "rule_id": r.rule_id,
        "rule_number": r.rule_number,
        "rule_name": r.rule_name or r.rule_id or f"Rule #{r.rule_number}",
        "section": r.section,
        "sources": r.sources or [],
        "destinations": r.destinations or [],
        "services": r.services or [],
        "applications": r.applications or [],
        "action": r.action,
        "enabled": r.enabled,
        "logging_enabled": r.logging_enabled,
        "hit_count": r.hit_count,
        "last_hit": r.last_hit,
        "first_hit": r.first_hit,
        "comments": r.comments,
        "source_any": _any_highlight(r.sources),
        "destination_any": _any_highlight(r.destinations),
        "service_any": _any_highlight(r.services),
    }


def _finding_dict(f: Finding, rule_map: dict | None = None) -> dict:
    affected_ids = f.affected_rules or []
    affected_rules_data = []
    if rule_map:
        for rid in affected_ids:
            if rid in rule_map:
                affected_rules_data.append(rule_map[rid])

    d = {
        "id": f.id,
        "policy_id": f.policy_id,
        "analysis_run_id": f.analysis_run_id,
        "vendor": f.vendor,
        "finding_type": f.finding_type,
        "severity": f.severity,
        "confidence": f.confidence,
        "priority": f.priority or "Standard",
        "title": f.title,
        "description": f.description,
        "affected_rules": affected_ids,
        "affected_rules_data": affected_rules_data,
        "affected_objects": f.affected_objects or [],
        "recommendation": f.recommendation,
        "status": f.status,
        "engineer_comment": f.engineer_comment,
        "assigned_to": f.assigned_to,
        "due_date": f.due_date,
        "risk_score": f.risk_score,
        "created_at": f.created_at.isoformat() if f.created_at else None,
        "updated_at": f.updated_at.isoformat() if f.updated_at else None,
        "risk_acceptance": None,
    }
    if f.risk_acceptance_reason or f.risk_acceptance_expiry or f.risk_acceptance_ref:
        d["risk_acceptance"] = {
            "reason": f.risk_acceptance_reason,
            "expiry": f.risk_acceptance_expiry,
            "ref": f.risk_acceptance_ref,
            "accepted_by": f.risk_accepted_by,
        }
    return d


def _finding_detail(f: Finding, db: Session) -> dict:
    comments = (
        db.query(FindingComment)
        .filter(FindingComment.finding_id == f.id)
        .order_by(FindingComment.created_at)
        .all()
    )
    affected_ids = f.affected_rules or []
    rule_map: dict = {}
    if affected_ids:
        rules = db.query(FirewallRule).filter(FirewallRule.id.in_(affected_ids)).all()
        rule_map = {r.id: _rule_dict(r) for r in rules}

    return {
        **_finding_dict(f, rule_map),
        "evidence": f.evidence or {},
        "risk_acceptance": {
            "reason": f.risk_acceptance_reason,
            "expiry": f.risk_acceptance_expiry,
            "ref": f.risk_acceptance_ref,
            "accepted_by": f.risk_accepted_by,
        },
        "comments": [
            {
                "id": c.id,
                "author": c.author,
                "comment": c.comment,
                "old_status": c.old_status,
                "new_status": c.new_status,
                "created_at": c.created_at.isoformat() if c.created_at else None,
            }
            for c in comments
        ],
    }
