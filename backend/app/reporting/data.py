"""Build the shared ReportData model once from existing analysis data.

Every exporter (HTML/PDF/DOCX/XLSX/CSV/JSON) consumes this same structure, so
output stays consistent across formats. Read-only: assembled purely from
already-stored policy/finding/rule/object rows.
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.models.policy import FirewallPolicy, FirewallRule, FirewallObject, AnalysisRun
from app.models.finding import Finding
from app.reporting import placeholders, sections as S

_SEVS = ["Critical", "High", "Medium", "Low", "Informational"]
_FINDING_LABEL = dict(S.FINDING_CATEGORIES)


@dataclass
class ReportData:
    meta: Dict[str, Any] = field(default_factory=dict)
    branding: Dict[str, Any] = field(default_factory=dict)
    texts: Dict[str, str] = field(default_factory=dict)
    sections: List[Dict[str, Any]] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    severity_counts: Dict[str, int] = field(default_factory=dict)
    category_counts: Dict[str, int] = field(default_factory=dict)
    rules: List[Dict[str, Any]] = field(default_factory=list)
    objects: List[Dict[str, Any]] = field(default_factory=list)


def _evidence_summary(ev: Any) -> str:
    if not isinstance(ev, dict) or not ev:
        return ""
    parts = []
    for k, v in list(ev.items())[:4]:
        if isinstance(v, (list, dict)):
            v = (", ".join(map(str, v)) if isinstance(v, list) else "…")
        parts.append(f"{k}: {v}")
    return "; ".join(parts)


def _finding_dict(f: Finding, firewall_name: str) -> Dict[str, Any]:
    return {
        "id": f.id,
        "severity": f.severity,
        "confidence": f.confidence,
        "finding_type": f.finding_type,
        "finding_type_label": _FINDING_LABEL.get(f.finding_type, f.finding_type),
        "title": f.title,
        "description": f.description or "",
        "recommendation": f.recommendation or "",
        "risk_score": f.risk_score or 0,
        "affected_rule_count": len(f.affected_rules or []),
        "affected_object_count": len(f.affected_objects or []),
        "evidence_summary": _evidence_summary(f.evidence),
        "firewall_name": firewall_name,
        "status": f.status,
    }


def _rule_dict(r: FirewallRule) -> Dict[str, Any]:
    def _join(v):
        return ", ".join(v) if isinstance(v, list) else (v or "")
    return {
        "rule_number": r.rule_number,
        "rule_name": r.rule_name or "",
        "sources": _join(r.sources),
        "destinations": _join(r.destinations),
        "services": _join(r.services),
        "action": r.action or "",
        "logging": "Yes" if r.logging_enabled else "No",
        "hit_count": r.hit_count if r.hit_count is not None else "",
        "last_hit": r.last_hit or "",
        "risk_score": r.risk_score or 0,
        "enabled": r.enabled,
    }


def _object_dict(o: FirewallObject) -> Dict[str, Any]:
    return {
        "object_name": o.object_name,
        "object_type": o.object_type,
        "value": o.value or "",
        "members": ", ".join(o.members or []) if o.members else "",
        "member_count": len(o.members or []),
    }


def build_report_data(
    db: Session,
    policy: FirewallPolicy,
    *,
    section_keys: List[str],
    finding_categories: Optional[List[str]] = None,
    filters: Optional[Dict[str, Any]] = None,
    branding: Optional[Dict[str, Any]] = None,
    texts: Optional[Dict[str, str]] = None,
    custom_sections: Optional[Dict[str, str]] = None,
    generated_by: str = "",
) -> ReportData:
    filters = filters or {}
    branding = dict(branding or {})
    texts = dict(texts or {})
    custom_sections = custom_sections or {}

    customer_name = policy.customer.name if policy.customer else ""
    firewall_name = policy.firewall_name or ""

    latest_run = (
        db.query(AnalysisRun)
        .filter(AnalysisRun.policy_id == policy.id, AnalysisRun.status == "completed")
        .order_by(AnalysisRun.completed_at.desc())
        .first()
    )
    analysis_date = ""
    if latest_run and latest_run.completed_at:
        analysis_date = latest_run.completed_at.strftime("%Y-%m-%d")
    elif policy.upload_date:
        analysis_date = policy.upload_date.strftime("%Y-%m-%d")

    # ── Findings (apply finding-level filters) ────────────────────────────────
    fq = db.query(Finding).filter(Finding.policy_id == policy.id)
    sev_filter = filters.get("severities")
    if sev_filter:
        fq = fq.filter(Finding.severity.in_(sev_filter))
    if filters.get("confidence"):
        fq = fq.filter(Finding.confidence.in_(filters["confidence"]))
    if finding_categories:
        fq = fq.filter(Finding.finding_type.in_(finding_categories))
    all_findings = fq.all()
    findings = [_finding_dict(f, firewall_name) for f in all_findings]

    severity_counts = {s: 0 for s in _SEVS}
    category_counts: Dict[str, int] = {}
    for f in all_findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        category_counts[f.finding_type] = category_counts.get(f.finding_type, 0) + 1

    meta = {
        "customer_name": customer_name,
        "firewall_name": firewall_name,
        "vendor": policy.vendor or "",
        "policy_name": policy.firewall_name or "",
        "policy_id": policy.id,
        "analysis_date": analysis_date,
        "generated_date": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "generated_by": generated_by,
        "total_rules": policy.rule_count or 0,
        "total_objects": policy.object_count or 0,
        "total_findings": len(all_findings),
        "critical_findings": severity_counts.get("Critical", 0),
        "high_findings": severity_counts.get("High", 0),
        "medium_findings": severity_counts.get("Medium", 0),
        "low_findings": severity_counts.get("Low", 0),
        "info_findings": severity_counts.get("Informational", 0),
        "policy_score": int(policy.health_score) if policy.health_score is not None else "",
        "health_score": policy.health_score,
        "complexity_score": policy.complexity_score,
        "cleanup_readiness": policy.cleanup_readiness_score,
    }

    ph = placeholders.build_map(meta)

    # ── Branding defaults ─────────────────────────────────────────────────────
    branding.setdefault("company_name", "")
    branding.setdefault("customer_name", customer_name)
    branding.setdefault("accent_color", "#1e3a5f")
    branding.setdefault("secondary_color", "#2e7d62")
    branding.setdefault("confidentiality", "Confidential")
    branding.setdefault("report_title", f"Firewall Policy Review — {firewall_name}")
    branding.setdefault("footer_text", texts.get("footer_text", ""))
    # Resolve placeholders in branding text fields.
    for k in ("report_title", "header_text", "footer_text", "cover_subtitle", "prepared_by", "cover_custom_text"):
        if branding.get(k):
            branding[k] = placeholders.apply(str(branding[k]), ph)
    # Embed logos: keep the on-disk path (for DOCX) and a data URI (for HTML/PDF).
    from app.reporting import logos
    for k in ("company_logo", "customer_logo"):
        ref = branding.get(k)
        if ref:
            branding[k + "_path"] = logos.abs_path(ref)
            branding[k] = logos.data_uri(ref) or ""

    # ── Resolve narrative text (with placeholders) ────────────────────────────
    resolved_texts = {}
    for tk in ("introduction_text", "scope_text", "methodology_text",
               "disclaimer_text", "scoring_methodology_text", "footer_text"):
        resolved_texts[tk] = placeholders.apply(texts.get(tk, ""), ph)
    if not resolved_texts.get("disclaimer_text"):
        resolved_texts["disclaimer_text"] = S.READ_ONLY_DISCLAIMER

    # ── Rules / objects (only loaded if a section needs them) ─────────────────
    need_rules = any(k in section_keys for k in ("full_rulebase",))
    need_objects = any(k in section_keys for k in ("full_object_inventory",))
    rules_out: List[Dict[str, Any]] = []
    objects_out: List[Dict[str, Any]] = []
    if need_rules:
        rows = (db.query(FirewallRule).filter(FirewallRule.policy_id == policy.id)
                .order_by(FirewallRule.rule_number).all())
        rules_out = [_rule_dict(r) for r in rows]
    if need_objects:
        rows = db.query(FirewallObject).filter(FirewallObject.policy_id == policy.id).all()
        objects_out = [_object_dict(o) for o in rows]

    # ── Assemble ordered, enabled sections ────────────────────────────────────
    by_type = {f["finding_type"]: True for f in findings}  # noqa: F841 (clarity)
    out_sections: List[Dict[str, Any]] = []
    for key in section_keys:
        spec = S.SECTION_BY_KEY.get(key)
        if not spec:
            # Custom free-text section: key like "custom:<id>"
            if key.startswith("custom"):
                out_sections.append({
                    "key": key, "name": custom_sections.get(key + "_name", "Custom Section"),
                    "type": S.T_TEXT, "text": placeholders.apply(custom_sections.get(key, ""), ph),
                })
            continue
        sec = {"key": key, "name": spec["name"], "type": spec["type"]}
        if spec["type"] == S.T_TEXT:
            tkey = spec.get("text_key")
            sec["text"] = resolved_texts.get(tkey, "")
        elif spec["type"] == S.T_FINDINGS:
            ftypes = spec.get("finding_types")
            sevs = spec.get("severities")
            sel = findings
            if ftypes:
                sel = [f for f in sel if f["finding_type"] in ftypes]
            if sevs:
                sel = [f for f in sel if f["severity"] in sevs]
            sec["findings"] = sorted(sel, key=lambda f: (-_sev_rank(f["severity"]), -f["risk_score"]))
        out_sections.append(sec)

    top_high = sorted(
        [f for f in findings if f["severity"] in ("Critical", "High")],
        key=lambda f: (-_sev_rank(f["severity"]), -f["risk_score"]),
    )[:15]

    return ReportData(
        meta={**meta, "placeholders": ph, "top_high_risk": top_high},
        branding=branding,
        texts=resolved_texts,
        sections=out_sections,
        findings=findings,
        severity_counts=severity_counts,
        category_counts={_FINDING_LABEL.get(k, k): v for k, v in sorted(category_counts.items(), key=lambda kv: -kv[1])},
        rules=rules_out,
        objects=objects_out,
    )


def _sev_rank(sev: str) -> int:
    return {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Informational": 1}.get(sev, 0)
