"""File upload and policy import API."""
import os
import re
import uuid
from fastapi import APIRouter, UploadFile, File, Form, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from typing import Optional
from app.database import get_db
from app.models.customer import Customer
from app.models.policy import FirewallPolicy, FirewallRule, FirewallObject
from app.parsers import get_parser
from app.analysis.engine import run_analysis
from app.config import settings
from app.security.audit import audit_log
from app.models.user import User
from app.security.identity import require_capability, require_customer_access
from app.security.rbac import CAP_UPLOAD
import logging

router = APIRouter(prefix="/api/upload", tags=["upload"])
logger = logging.getLogger(__name__)

# Allowed file extensions for uploaded policy files (union across all vendors).
_ALLOWED_EXTENSIONS = {".conf", ".txt", ".json", ".csv", ".log", ".cfg", ".xml"}

# Per-vendor extension allow-list.
_VENDOR_EXTENSIONS = {
    "CheckPoint": {".json", ".txt"},
    "FortiGate":  {".conf", ".txt", ".json", ".cfg"},
    "PaloAlto":   {".xml", ".json", ".conf"},
    "CiscoASA":   {".txt", ".conf", ".cfg"},
    "HuaweiUSG":  {".txt", ".cfg", ".conf"},
}

# Max filename length
_MAX_FILENAME_LEN = 255

# Read uploads in 1 MiB chunks so an oversized file is rejected mid-stream
# rather than fully buffered into memory.
_READ_CHUNK = 1024 * 1024

# Allowed vendor values (must match parsers)
_ALLOWED_VENDORS = {"FortiGate", "CheckPoint", "PaloAlto", "CiscoASA", "HuaweiUSG"}


def _file_extension(filename: str) -> str:
    """Return the lowercased file extension (empty string if none)."""
    _, ext = os.path.splitext(filename)
    return ext.lower()


def _sanitize_filename(filename: str) -> str:
    """Strip path components and dangerous characters from an uploaded filename."""
    # Take only the basename (prevent path traversal)
    filename = os.path.basename(filename)
    # Remove null bytes and control characters
    filename = re.sub(r"[\x00-\x1f\x7f]", "", filename)
    # Truncate
    if len(filename) > _MAX_FILENAME_LEN:
        filename = filename[:_MAX_FILENAME_LEN]
    return filename or "upload"


@router.post("")
async def upload_policy(
    background_tasks: BackgroundTasks,
    customer_id: str = Form(...),
    vendor: str = Form(...),
    firewall_name: str = Form(...),
    policy_package: Optional[str] = Form(None),
    notes: Optional[str] = Form(None),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: User = Depends(require_capability(CAP_UPLOAD)),
):
    """Upload a firewall policy file under a specific customer tenant."""
    # ── Input validation ──────────────────────────────────────────────────────
    # Tenant isolation: the user must be authorized for the target customer.
    require_customer_access(db, user, customer_id)
    customer = db.query(Customer).filter(Customer.id == customer_id).first()
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")

    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")

    if vendor not in _ALLOWED_VENDORS:
        raise HTTPException(status_code=400, detail=f"Unsupported vendor: {vendor!r}. Allowed: {', '.join(sorted(_ALLOWED_VENDORS))}")

    try:
        get_parser(vendor)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"No parser available for vendor: {vendor}")

    safe_filename = _sanitize_filename(file.filename)
    ext = _file_extension(safe_filename)

    # Validate extension against the vendor's allow-list.
    allowed_exts = _VENDOR_EXTENSIONS.get(vendor, _ALLOWED_EXTENSIONS)
    if ext not in allowed_exts:
        raise HTTPException(
            status_code=400,
            detail=f"File extension {ext!r} is not valid for {vendor}. "
                   f"Allowed: {', '.join(sorted(allowed_exts))}",
        )

    # ── Read content with a streaming size cap ────────────────────────────────
    # Reject early if the client-declared size already exceeds the limit, then
    # read in chunks so an oversized stream is aborted without being fully
    # buffered into memory.
    max_bytes = settings.max_upload_size_mb * 1024 * 1024
    declared = getattr(file, "size", None)
    if declared is not None and declared > max_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"File too large ({declared // (1024*1024)} MB). Max allowed: {settings.max_upload_size_mb} MB",
        )

    chunks = []
    total = 0
    while True:
        chunk = await file.read(_READ_CHUNK)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise HTTPException(
                status_code=413,
                detail=f"File too large (> {settings.max_upload_size_mb} MB). Upload aborted.",
            )
        chunks.append(chunk)
    content = b"".join(chunks)

    if len(content) == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")

    # ── Binary-content guard ──────────────────────────────────────────────────
    # Policy exports are text (conf/csv/xml/json). A NUL byte in the leading
    # bytes indicates a binary/garbage upload, not a config file.
    if b"\x00" in content[:8192]:
        raise HTTPException(
            status_code=400,
            detail="Uploaded file appears to be binary. Expected a text-based policy export.",
        )

    # ── Save file with UUID name (no user-controlled filename on disk) ─────────
    os.makedirs(settings.upload_dir, exist_ok=True)
    file_id = str(uuid.uuid4())
    file_path = os.path.join(settings.upload_dir, f"{file_id}{ext}")

    with open(file_path, "wb") as f:
        f.write(content)

    # ── Parse ─────────────────────────────────────────────────────────────────
    try:
        parser = get_parser(vendor)
        text_content = content.decode("utf-8", errors="replace")
        rules, objects, warnings = parser.parse(text_content)
    except Exception as e:
        try:
            os.remove(file_path)
        except Exception:
            pass
        raise HTTPException(status_code=422, detail=f"Failed to parse file: {str(e)}")

    # ── Persist ───────────────────────────────────────────────────────────────
    policy = FirewallPolicy(
        id=str(uuid.uuid4()),
        customer_id=customer_id,
        firewall_name=firewall_name,
        vendor=vendor,
        policy_package=policy_package or "",
        original_filename=safe_filename,   # store sanitised name, not raw user input
        file_path=file_path,
        analysis_status="parsing",
        rule_count=len(rules),
        object_count=len(objects),
        notes=notes or "",
    )
    db.add(policy)
    db.flush()

    for rule in rules:
        rule_orm = FirewallRule(
            id=str(uuid.uuid4()),
            policy_id=policy.id,
            vendor=vendor,
            firewall_name=firewall_name,
            policy_package=policy_package or "",
            rule_id=str(rule.get("rule_id", "")),
            rule_uid=rule.get("rule_uid", ""),
            rule_number=rule.get("rule_number", 0),
            rule_name=rule.get("rule_name", ""),
            section=rule.get("section", ""),
            source_interfaces=rule.get("source_interfaces", []),
            destination_interfaces=rule.get("destination_interfaces", []),
            sources=rule.get("sources", []),
            destinations=rule.get("destinations", []),
            services=rule.get("services", []),
            applications=rule.get("applications", []),
            users=rule.get("users", []),
            vpn=rule.get("vpn", []),
            action=rule.get("action", ""),
            schedule=rule.get("schedule", ""),
            enabled=rule.get("enabled", True),
            logging_enabled=rule.get("logging_enabled", True),
            nat_enabled=rule.get("nat_enabled", False),
            comments=rule.get("comments", ""),
            hit_count=rule.get("hit_count"),
            last_hit=str(rule.get("last_hit")) if rule.get("last_hit") else None,
            first_hit=str(rule.get("first_hit")) if rule.get("first_hit") else None,
            install_on=rule.get("install_on", []),
            raw_data=rule.get("raw_data", {}),
        )
        db.add(rule_orm)

    for obj in objects:
        obj_orm = FirewallObject(
            id=str(uuid.uuid4()),
            policy_id=policy.id,
            vendor=vendor,
            object_uid=obj.get("object_uid", ""),
            object_name=obj.get("object_name", ""),
            object_type=obj.get("object_type", "host"),
            value=obj.get("value", ""),
            protocol=obj.get("protocol"),
            port_start=obj.get("port_start"),
            port_end=obj.get("port_end"),
            members=obj.get("members", []),
            comment=obj.get("comment", ""),
            raw_data=obj.get("raw_data", {}),
        )
        db.add(obj_orm)

    policy.analysis_status = "pending"
    db.commit()

    audit_log(
        "policy.upload",
        user_id=user.id,
        policy_id=policy.id,
        customer_id=customer_id,
        vendor=vendor,
        firewall_name=firewall_name,
        rule_count=len(rules),
        file_size_bytes=len(content),
    )

    background_tasks.add_task(_run_analysis_task, policy.id, customer_id)

    # ── Import quality scoring ────────────────────────────────────────────────
    quality = _import_quality(rules, objects, warnings)

    return {
        "policy_id": policy.id,
        "customer_id": customer_id,
        "vendor": vendor,
        "firewall_name": firewall_name,
        "rules_parsed": len(rules),
        "objects_parsed": len(objects),
        "warnings": warnings,
        "import_quality": quality,
        "message": "File uploaded and analysis started.",
    }


def _import_quality(rules: list, objects: list, warnings: list) -> dict:
    """Compute an import quality and data completeness score."""
    total = len(rules)
    if total == 0:
        return {
            "quality_score": 0,
            "completeness_score": 0,
            "has_hit_counts": False,
            "has_last_hit": False,
            "has_comments": False,
            "rules_with_hit_count": 0,
            "rules_with_last_hit": 0,
            "rules_with_comments": 0,
            "warning_count": len(warnings),
            "data_gaps": ["No rules found — verify the file format and vendor selection."],
        }

    rules_with_hit = sum(1 for r in rules if r.get("hit_count") is not None)
    rules_with_last_hit = sum(1 for r in rules if r.get("last_hit"))
    rules_with_comments = sum(1 for r in rules if (r.get("comments") or "").strip())
    rules_enabled = sum(1 for r in rules if r.get("enabled", True))

    has_hit_counts = rules_with_hit > 0
    has_last_hit = rules_with_last_hit > 0
    has_comments = rules_with_comments > 0

    # Completeness: % of enabled rules with hit count data (most important)
    hit_completeness = (rules_with_hit / total * 100) if total else 0
    comment_completeness = (rules_with_comments / total * 100) if total else 0

    # Quality score: base 100, deductions for missing data
    quality_score = 100
    data_gaps = []

    if not has_hit_counts:
        quality_score -= 30
        data_gaps.append("No hit count data — zero-hit and low-usage detection will be limited.")
    elif hit_completeness < 50:
        quality_score -= 15
        data_gaps.append(f"Only {hit_completeness:.0f}% of rules have hit count data — usage analysis may be incomplete.")

    if not has_last_hit:
        quality_score -= 15
        data_gaps.append("No last-hit timestamps — age-based usage detection unavailable.")

    if not objects:
        quality_score -= 10
        data_gaps.append("No objects/groups imported — object analysis unavailable.")

    if len(warnings) > 5:
        quality_score -= min(15, len(warnings))
        data_gaps.append(f"{len(warnings)} parse warnings — review for unsupported fields.")
    elif warnings:
        quality_score -= 5

    quality_score = max(0, quality_score)
    completeness_score = round((hit_completeness * 0.5 + comment_completeness * 0.3 + (30 if objects else 0)) * 0.7)
    completeness_score = min(100, completeness_score)

    confidence_note = None
    if quality_score < 50:
        confidence_note = "Analysis confidence is REDUCED due to missing data. Findings will be generated but accuracy may be limited."
    elif quality_score < 80:
        confidence_note = "Analysis confidence is MODERATE. Some detections may have lower accuracy due to missing data."

    return {
        "quality_score": quality_score,
        "completeness_score": completeness_score,
        "has_hit_counts": has_hit_counts,
        "has_last_hit": has_last_hit,
        "has_comments": has_comments,
        "rules_with_hit_count": rules_with_hit,
        "rules_with_last_hit": rules_with_last_hit,
        "rules_with_comments": rules_with_comments,
        "warning_count": len(warnings),
        "data_gaps": data_gaps,
        "confidence_note": confidence_note,
    }


def _run_analysis_task(policy_id: str, customer_id: str):
    from app.database import SessionLocal
    db = SessionLocal()
    try:
        run_analysis(policy_id, db)
        _refresh_customer_counters(customer_id, db)
    except Exception as e:
        logger.error(f"Background analysis failed: {e}", exc_info=True)
    finally:
        db.close()


def _refresh_customer_counters(customer_id: str, db):
    from sqlalchemy import func
    from app.models.policy import FirewallPolicy, FirewallRule
    from app.models.finding import Finding

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
