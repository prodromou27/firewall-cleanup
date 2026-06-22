"""Modular reporting API — template management, generation, preview, download.

Read-only: generates documents from existing analysis data. No approvals,
engineer notes, workflow, or change execution.
"""
import os
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session
from sqlalchemy import or_

from app.database import get_db
from app.config import settings
from app.models.policy import FirewallPolicy, AnalysisRun
from app.models.report import ReportTemplate, ReportTemplateSection, GeneratedReport
from app.models.user import User
from app.security.identity import (
    get_current_user, require_capability, accessible_customer_ids, require_customer_access,
)
from app.security.rbac import CAP_VIEW, CAP_GENERATE_REPORT, CAP_DOWNLOAD_REPORT
from app.security.audit import audit_log
from app.reporting import sections as S
from app.reporting.data import build_report_data
from app.reporting.exporters import export, filename_for, SUPPORTED_FORMATS, normalize_format
from app.reporting.export_safety import attachment_headers, safe_filename

templates_router = APIRouter(prefix="/api/report-templates", tags=["reporting"])
reports_router = APIRouter(prefix="/api/reports", tags=["reporting"])
meta_router = APIRouter(tags=["reporting"])

_REPORTS_DIR = os.path.join(settings.upload_dir, "reports")


# ── Schemas ──────────────────────────────────────────────────────────────────
class SectionIn(BaseModel):
    section_key: str
    section_name: Optional[str] = None
    section_type: str = "builtin"
    enabled: bool = True
    display_order: int = 0
    custom_text: Optional[str] = None
    config: Dict[str, Any] = Field(default_factory=dict)


class TemplateIn(BaseModel):
    name: str
    description: Optional[str] = None
    template_type: str = "technical"
    audience: str = "internal"
    is_customer_facing: bool = False
    default_export_format: str = "pdf"
    default_detail_level: str = "standard"
    branding_config: Dict[str, Any] = Field(default_factory=dict)
    cover_page_config: Dict[str, Any] = Field(default_factory=dict)
    introduction_text: Optional[str] = None
    methodology_text: Optional[str] = None
    disclaimer_text: Optional[str] = None
    footer_text: Optional[str] = None
    default_finding_categories: List[str] = Field(default_factory=list)
    customer_id: Optional[str] = None
    sections: List[SectionIn] = Field(default_factory=list)

    @field_validator("default_export_format")
    @classmethod
    def validate_export_format(cls, v: str) -> str:
        fmt = normalize_format(v)
        if fmt not in SUPPORTED_FORMATS:
            raise ValueError(f"default_export_format must be one of: {', '.join(SUPPORTED_FORMATS)}")
        return fmt

    @field_validator("default_finding_categories")
    @classmethod
    def validate_default_finding_categories(cls, v: List[str]) -> List[str]:
        invalid = [c for c in v if c not in S.FINDING_CATEGORY_KEYS]
        if invalid:
            raise ValueError(f"Unknown finding categories: {', '.join(invalid)}")
        return v


class GenerateIn(BaseModel):
    policy_id: str
    template_id: Optional[str] = None
    export_format: str = "pdf"
    report_type: Optional[str] = None
    analysis_run_id: Optional[str] = None
    sections: Optional[List[str]] = None
    finding_categories: Optional[List[str]] = None
    filters: Dict[str, Any] = Field(default_factory=dict)
    branding: Dict[str, Any] = Field(default_factory=dict)
    texts: Dict[str, str] = Field(default_factory=dict)
    custom_sections: Dict[str, str] = Field(default_factory=dict)

    @field_validator("export_format")
    @classmethod
    def validate_export_format(cls, v: str) -> str:
        fmt = normalize_format(v)
        if fmt not in SUPPORTED_FORMATS:
            raise ValueError(f"export_format must be one of: {', '.join(SUPPORTED_FORMATS)}")
        return fmt

    @field_validator("sections")
    @classmethod
    def validate_sections(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        if not v:
            return v
        invalid = [s for s in v if s not in S.SECTION_BY_KEY and not s.startswith("custom")]
        if invalid:
            raise ValueError(f"Unknown report sections: {', '.join(invalid)}")
        return v

    @field_validator("finding_categories")
    @classmethod
    def validate_finding_categories(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        if not v:
            return v
        invalid = [c for c in v if c not in S.FINDING_CATEGORY_KEYS]
        if invalid:
            raise ValueError(f"Unknown finding categories: {', '.join(invalid)}")
        return v


# ── Helpers ──────────────────────────────────────────────────────────────────
def _template_dict(t: ReportTemplate) -> dict:
    return {
        "id": t.id, "name": t.name, "description": t.description,
        "template_type": t.template_type, "audience": t.audience,
        "is_customer_facing": t.is_customer_facing,
        "default_export_format": t.default_export_format,
        "default_detail_level": t.default_detail_level,
        "branding_config": t.branding_config or {}, "cover_page_config": t.cover_page_config or {},
        "introduction_text": t.introduction_text, "methodology_text": t.methodology_text,
        "disclaimer_text": t.disclaimer_text, "footer_text": t.footer_text,
        "default_finding_categories": t.default_finding_categories or [],
        "customer_id": t.customer_id, "is_default": t.is_default,
        "created_at": t.created_at.isoformat() if t.created_at else None,
        "sections": [
            {"id": s.id, "section_key": s.section_key, "section_name": s.section_name,
             "section_type": s.section_type, "enabled": s.enabled,
             "display_order": s.display_order, "custom_text": s.custom_text, "config": s.config or {}}
            for s in sorted(t.sections, key=lambda x: x.display_order)
        ],
    }


def _accessible_template_q(db: Session, user: User):
    allowed = accessible_customer_ids(db, user)
    q = db.query(ReportTemplate)
    if allowed is not None:
        q = q.filter(or_(ReportTemplate.customer_id.is_(None), ReportTemplate.customer_id.in_(allowed or ["__none__"])))
    return q


def _authz_template(db: Session, user: User, tid: str) -> ReportTemplate:
    t = db.query(ReportTemplate).filter(ReportTemplate.id == tid).first()
    if not t:
        raise HTTPException(status_code=404, detail="Template not found")
    if t.customer_id:
        require_customer_access(db, user, t.customer_id)
    return t


def _authz_template_write(db: Session, user: User, tid: str) -> ReportTemplate:
    """Authorize template mutation without letting tenant users alter global state."""
    t = _authz_template(db, user, tid)
    if t.customer_id is None and accessible_customer_ids(db, user) is not None:
        raise HTTPException(
            status_code=403,
            detail="Global report templates can only be modified by global administrators.",
        )
    return t


def _authz_policy(db: Session, user: User, policy_id: str) -> FirewallPolicy:
    p = db.query(FirewallPolicy).filter(FirewallPolicy.id == policy_id).first()
    if not p:
        raise HTTPException(status_code=404, detail="Policy not found")
    require_customer_access(db, user, p.customer_id)
    return p


def _report_customer_id(db: Session, report: GeneratedReport) -> Optional[str]:
    if report.customer_id:
        return report.customer_id
    if report.policy_id:
        policy = db.query(FirewallPolicy.customer_id).filter(FirewallPolicy.id == report.policy_id).first()
        if policy:
            return policy[0]
    return None


def _safe_report_path(path: str) -> bool:
    base = os.path.abspath(_REPORTS_DIR)
    p = os.path.abspath(path or "")
    return p.startswith(base + os.sep)


def _set_sections(db: Session, template: ReportTemplate, sections: List[SectionIn]):
    template.sections.clear()
    db.flush()
    for i, s in enumerate(sections):
        spec = S.SECTION_BY_KEY.get(s.section_key, {})
        db.add(ReportTemplateSection(
            template_id=template.id, section_key=s.section_key,
            section_name=s.section_name or spec.get("name", s.section_key),
            section_type=s.section_type or spec.get("type", "builtin"),
            enabled=s.enabled, display_order=s.display_order if s.display_order else i,
            custom_text=s.custom_text, config=s.config or {},
        ))


# ── Metadata endpoints ────────────────────────────────────────────────────────
@meta_router.get("/api/report-sections/catalog")
def section_catalog(user: User = Depends(get_current_user)):
    return {"sections": S.SECTION_CATALOG, "default_sections": S.DEFAULT_SECTION_KEYS}


@meta_router.get("/api/report-placeholders")
def placeholders(user: User = Depends(get_current_user)):
    return {"placeholders": S.PLACEHOLDERS}


@meta_router.get("/api/report-finding-categories")
def finding_categories(user: User = Depends(get_current_user)):
    return {"categories": [{"key": k, "label": v} for k, v in S.FINDING_CATEGORIES]}


# ── Template CRUD ─────────────────────────────────────────────────────────────
@templates_router.post("/logo")
async def upload_logo(file: UploadFile = File(...),
                      user: User = Depends(require_capability(CAP_GENERATE_REPORT))):
    """Upload a branding logo (company or customer). Returns a storage ref + data URI."""
    from app.reporting import logos
    content = await file.read()
    if len(content) > 2 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="Logo too large (max 2 MB).")
    try:
        ref = logos.save_logo(content, file.filename or "logo.png")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"logo_ref": ref, "data_uri": logos.data_uri(ref)}


@templates_router.get("")
def list_templates(db: Session = Depends(get_db), user: User = Depends(require_capability(CAP_VIEW))):
    rows = _accessible_template_q(db, user).order_by(ReportTemplate.created_at.desc()).all()
    return {"templates": [_template_dict(t) for t in rows]}


@templates_router.post("")
def create_template(body: TemplateIn, db: Session = Depends(get_db),
                    user: User = Depends(require_capability(CAP_GENERATE_REPORT))):
    if body.customer_id:
        require_customer_access(db, user, body.customer_id)
    elif accessible_customer_ids(db, user) is not None:
        raise HTTPException(
            status_code=403,
            detail="Tenant users must create report templates for an authorized customer.",
        )
    data = body.dict(exclude={"sections"})
    t = ReportTemplate(created_by=user.email, **data)
    db.add(t); db.flush()
    secs = body.sections or [SectionIn(section_key=k, display_order=i) for i, k in enumerate(S.DEFAULT_SECTION_KEYS)]
    _set_sections(db, t, secs)
    db.commit(); db.refresh(t)
    audit_log("report.template_create", user_id=user.id, email=user.email, template_id=t.id, name=t.name)
    return _template_dict(t)


@templates_router.get("/{tid}")
def get_template(tid: str, db: Session = Depends(get_db), user: User = Depends(require_capability(CAP_VIEW))):
    return _template_dict(_authz_template(db, user, tid))


@templates_router.put("/{tid}")
def update_template(tid: str, body: TemplateIn, db: Session = Depends(get_db),
                    user: User = Depends(require_capability(CAP_GENERATE_REPORT))):
    t = _authz_template_write(db, user, tid)
    if body.customer_id != t.customer_id:
        raise HTTPException(status_code=400, detail="Template customer_id cannot be changed.")
    for k, v in body.dict(exclude={"sections", "customer_id"}).items():
        setattr(t, k, v)
    _set_sections(db, t, body.sections)
    db.commit(); db.refresh(t)
    audit_log("report.template_update", user_id=user.id, email=user.email, template_id=t.id)
    return _template_dict(t)


@templates_router.delete("/{tid}")
def delete_template(tid: str, db: Session = Depends(get_db),
                    user: User = Depends(require_capability(CAP_GENERATE_REPORT))):
    t = _authz_template_write(db, user, tid)
    db.delete(t); db.commit()
    audit_log("report.template_delete", user_id=user.id, email=user.email, template_id=tid)
    return {"deleted": tid}


@templates_router.post("/{tid}/clone")
def clone_template(tid: str, db: Session = Depends(get_db),
                   user: User = Depends(require_capability(CAP_GENERATE_REPORT))):
    t = _authz_template_write(db, user, tid)
    clone = ReportTemplate(
        name=f"{t.name} (copy)", description=t.description, template_type=t.template_type,
        audience=t.audience, is_customer_facing=t.is_customer_facing,
        default_export_format=t.default_export_format, default_detail_level=t.default_detail_level,
        branding_config=t.branding_config, cover_page_config=t.cover_page_config,
        introduction_text=t.introduction_text, methodology_text=t.methodology_text,
        disclaimer_text=t.disclaimer_text, footer_text=t.footer_text,
        default_finding_categories=t.default_finding_categories, customer_id=t.customer_id,
        is_default=False, created_by=user.email,
    )
    db.add(clone); db.flush()
    for s in t.sections:
        db.add(ReportTemplateSection(
            template_id=clone.id, section_key=s.section_key, section_name=s.section_name,
            section_type=s.section_type, enabled=s.enabled, display_order=s.display_order,
            custom_text=s.custom_text, config=s.config))
    db.commit(); db.refresh(clone)
    audit_log("report.template_clone", user_id=user.id, email=user.email, source=tid, template_id=clone.id)
    return _template_dict(clone)


@templates_router.post("/{tid}/default")
def set_default(tid: str, db: Session = Depends(get_db),
                user: User = Depends(require_capability(CAP_GENERATE_REPORT))):
    t = _authz_template_write(db, user, tid)
    q = db.query(ReportTemplate).filter(ReportTemplate.audience == t.audience)
    if t.customer_id is None:
        q = q.filter(ReportTemplate.customer_id.is_(None))
    else:
        q = q.filter(ReportTemplate.customer_id == t.customer_id)
    for other in q.all():
        other.is_default = False
    t.is_default = True
    db.commit()
    return {"default": tid}


# ── Generation core (shared by generate + preview) ────────────────────────────
def _resolve_and_build(db: Session, user: User, body: GenerateIn):
    policy = _authz_policy(db, user, body.policy_id)
    template = _authz_template(db, user, body.template_id) if body.template_id else None
    if body.analysis_run_id:
        run = (
            db.query(AnalysisRun)
            .filter(AnalysisRun.id == body.analysis_run_id, AnalysisRun.policy_id == policy.id)
            .first()
        )
        if not run:
            raise HTTPException(status_code=404, detail="Analysis run not found for this policy")

    # Sections (ordered)
    if body.sections:
        section_keys = body.sections
    elif template:
        section_keys = [s.section_key for s in sorted(template.sections, key=lambda x: x.display_order) if s.enabled]
    else:
        section_keys = S.DEFAULT_SECTION_KEYS

    # Finding categories
    finding_categories = body.finding_categories
    if finding_categories is None and template:
        finding_categories = template.default_finding_categories or None

    # Branding (template defaults < request)
    branding = {}
    if template:
        branding.update(template.branding_config or {})
        branding.update(template.cover_page_config or {})
    branding.update(body.branding or {})

    # Texts (template defaults < request)
    texts = {}
    template_custom_sections: Dict[str, str] = {}
    if template:
        texts.update({
            "introduction_text": template.introduction_text or "",
            "methodology_text": template.methodology_text or "",
            "disclaimer_text": template.disclaimer_text or "",
            "footer_text": template.footer_text or "",
            "scoring_methodology_text": (template.cover_page_config or {}).get("scoring_methodology_text", ""),
        })
        # custom_text from template sections
        for s in template.sections:
            if s.custom_text:
                template_custom_sections[s.section_key] = s.custom_text
                if s.section_name:
                    template_custom_sections[f"{s.section_key}_name"] = s.section_name
    texts.update(body.texts or {})
    template_custom_sections.update(body.custom_sections or {})

    data = build_report_data(
        db, policy, section_keys=section_keys, finding_categories=finding_categories,
        analysis_run_id=body.analysis_run_id, filters=body.filters, branding=branding, texts=texts,
        custom_sections=template_custom_sections, generated_by=user.email,
    )
    return policy, template, data, section_keys, finding_categories


@reports_router.post("/preview")
def preview_report(body: GenerateIn, db: Session = Depends(get_db),
                   user: User = Depends(require_capability(CAP_GENERATE_REPORT))):
    _, _, data, _, _ = _resolve_and_build(db, user, body)
    from app.reporting.exporters.html import render as render_html
    return HTMLResponse(content=render_html(data))


@reports_router.post("/generate")
def generate_report(body: GenerateIn, db: Session = Depends(get_db),
                    user: User = Depends(require_capability(CAP_GENERATE_REPORT))):
    fmt = normalize_format(body.export_format)
    if fmt not in SUPPORTED_FORMATS:
        raise HTTPException(status_code=400, detail=f"Unsupported format. Use one of: {', '.join(SUPPORTED_FORMATS)}")
    policy, template, data, section_keys, finding_categories = _resolve_and_build(db, user, body)
    report_type = body.report_type or (template.template_type if template else "report")

    try:
        content, media, ext = export(data, fmt)
    except Exception as e:
        return JSONResponse(status_code=500, content={"detail": f"Report generation failed: {e}"})

    os.makedirs(_REPORTS_DIR, exist_ok=True)
    fname = safe_filename(filename_for(data, fmt, report_type))
    rec = GeneratedReport(
        template_id=template.id if template else None, customer_id=policy.customer_id,
        policy_id=policy.id, analysis_run_id=body.analysis_run_id, firewall_name=policy.firewall_name,
        report_type=report_type, export_format=fmt, file_name=fname,
        file_path="",  # set after we know the id
        selected_sections=section_keys, selected_finding_categories=finding_categories or [],
        filters=body.filters or {}, generated_by=user.email,
    )
    db.add(rec); db.flush()
    path = os.path.join(_REPORTS_DIR, f"{rec.id}.{ext}")
    with open(path, "wb") as f:
        f.write(content)
    rec.file_path = path
    db.commit()
    audit_log("report.generate", user_id=user.id, email=user.email, report_id=rec.id,
              policy_id=policy.id, customer_id=policy.customer_id, format=fmt, report_type=report_type)
    return {"id": rec.id, "file_name": fname, "export_format": fmt,
            "download_url": f"/api/reports/{rec.id}/download"}


@reports_router.get("/policies/{policy_id}/analysis-runs")
def list_policy_analysis_runs(
    policy_id: str,
    limit: int = Query(25, ge=1, le=100),
    db: Session = Depends(get_db),
    user: User = Depends(require_capability(CAP_VIEW)),
):
    policy = _authz_policy(db, user, policy_id)
    rows = (
        db.query(AnalysisRun)
        .filter(AnalysisRun.policy_id == policy.id)
        .order_by(AnalysisRun.completed_at.desc(), AnalysisRun.started_at.desc())
        .limit(limit)
        .all()
    )
    return {"analysis_runs": [{
        "id": r.id,
        "status": r.status,
        "started_at": r.started_at.isoformat() if r.started_at else None,
        "completed_at": r.completed_at.isoformat() if r.completed_at else None,
        "findings_created": r.findings_created,
        "run_by": r.run_by,
    } for r in rows]}


@reports_router.get("")
def list_reports(
    customer_id: Optional[str] = None,
    search: Optional[str] = None,
    export_format: Optional[str] = None,
    sort_by: Optional[str] = None,
    sort_dir: Optional[str] = None,
    page: int = 1,
    page_size: int = 50,
    limit: Optional[int] = Query(None, ge=1, le=500),
    db: Session = Depends(get_db),
    user: User = Depends(require_capability(CAP_VIEW)),
):
    allowed = accessible_customer_ids(db, user)
    q = db.query(GeneratedReport)
    if allowed is not None:
        if not allowed:
            return {"total": 0, "page": page, "page_size": page_size, "reports": []}
        q = q.filter(GeneratedReport.customer_id.in_(allowed))
    if customer_id:
        require_customer_access(db, user, customer_id)
        q = q.filter(GeneratedReport.customer_id == customer_id)
    if search:
        like = f"%{search.strip()}%"
        q = q.filter(or_(
            GeneratedReport.firewall_name.ilike(like),
            GeneratedReport.file_name.ilike(like),
            GeneratedReport.report_type.ilike(like),
            GeneratedReport.generated_by.ilike(like),
        ))
    if export_format:
        q = q.filter(GeneratedReport.export_format == export_format)

    sort_map = {
        "generated_at": GeneratedReport.generated_at,
        "firewall_name": GeneratedReport.firewall_name,
        "report_type": GeneratedReport.report_type,
        "export_format": GeneratedReport.export_format,
        "generated_by": GeneratedReport.generated_by,
    }
    if page < 1:
        raise HTTPException(status_code=422, detail="page must be >= 1")
    if page_size < 1 or page_size > 250:
        raise HTTPException(status_code=422, detail="page_size must be between 1 and 250")
    if sort_by is None:
        sort_by = "generated_at"
    if sort_by not in sort_map:
        raise HTTPException(status_code=422, detail="Invalid sort_by")
    if sort_dir is None:
        sort_dir = "desc"
    if sort_dir not in ("asc", "desc"):
        raise HTTPException(status_code=422, detail="Invalid sort_dir")
    sort_col = sort_map[sort_by]
    if sort_dir == "desc":
        sort_col = sort_col.desc()

    total = q.count()
    effective_page_size = limit or page_size
    rows = q.order_by(sort_col).offset((page - 1) * effective_page_size).limit(effective_page_size).all()
    return {"total": total, "page": page, "page_size": effective_page_size, "reports": [{
        "id": r.id, "report_type": r.report_type, "export_format": r.export_format,
        "customer_id": r.customer_id, "firewall_name": r.firewall_name, "file_name": r.file_name,
        "generated_by": r.generated_by,
        "generated_at": r.generated_at.isoformat() if r.generated_at else None,
        "selected_sections": r.selected_sections or [], "template_id": r.template_id,
        "policy_id": r.policy_id, "analysis_run_id": r.analysis_run_id,
    } for r in rows]}


@reports_router.get("/{report_id}/download")
def download_report(report_id: str, db: Session = Depends(get_db),
                    user: User = Depends(require_capability(CAP_DOWNLOAD_REPORT))):
    r = db.query(GeneratedReport).filter(GeneratedReport.id == report_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Report not found")
    require_customer_access(db, user, _report_customer_id(db, r))
    if not r.file_path or not _safe_report_path(r.file_path) or not os.path.exists(r.file_path):
        raise HTTPException(status_code=410, detail="Report file no longer available; regenerate it.")
    from app.reporting.exporters import _MEDIA
    media = _MEDIA.get(r.export_format, ("application/octet-stream", ""))[0]
    fname = safe_filename(r.file_name)
    return FileResponse(r.file_path, media_type=media, filename=fname,
                        headers=attachment_headers(fname))


@reports_router.get("/{report_id}")
def get_report(report_id: str, db: Session = Depends(get_db),
               user: User = Depends(require_capability(CAP_VIEW))):
    r = db.query(GeneratedReport).filter(GeneratedReport.id == report_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Report not found")
    require_customer_access(db, user, _report_customer_id(db, r))
    return {"id": r.id, "report_type": r.report_type, "export_format": r.export_format,
            "customer_id": r.customer_id, "firewall_name": r.firewall_name, "file_name": r.file_name,
            "generated_at": r.generated_at.isoformat() if r.generated_at else None,
            "selected_sections": r.selected_sections or [],
            "selected_finding_categories": r.selected_finding_categories or [],
            "filters": r.filters or {}, "template_id": r.template_id,
            "policy_id": r.policy_id, "analysis_run_id": r.analysis_run_id}
