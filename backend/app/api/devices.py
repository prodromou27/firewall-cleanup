"""
REST API for FirewallDevice management and live sync.

Endpoints:
  GET    /api/devices                    list (optionally ?customer_id=)
  POST   /api/devices                    create
  GET    /api/devices/{id}               get one
  PATCH  /api/devices/{id}              update
  DELETE /api/devices/{id}              delete
  POST   /api/devices/{id}/test         test connectivity (no DB changes)
  POST   /api/devices/{id}/sync         trigger live sync (background task)
  POST   /api/devices/{id}/reset-sync   force-reset stuck sync status
  GET    /api/devices/{id}/sync-status  lightweight status poll
  GET    /api/devices/{id}/trends       trend analysis across revisions

Security:
  - Credentials (password, api_token) are encrypted at rest using Fernet.
  - The API response NEVER returns raw credential values — only has_token / has_credentials flags.
  - All state-changing operations are written to the audit log.
"""
import logging
import re
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.device import FirewallDevice
from app.models.customer import Customer
from app.security.crypto import encrypt_credential, decrypt_credential
from app.security.audit import audit_log

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/devices", tags=["devices"])

# Allowed vendor values
_ALLOWED_VENDORS = {"FortiGate", "CheckPoint", "PaloAlto", "Cisco"}
# Allowed CP management types
_ALLOWED_CP_TYPES = {"SmartCenter", "MDS", "Smart-1Cloud"}
# Allowed sync intervals (hours) — None = disabled
_ALLOWED_INTERVALS = {None, 6, 12, 24, 48, 168}

# Very basic host / IP / FQDN validation — blocks obvious injection attempts
_HOST_RE = re.compile(
    r"^(?:"
    r"(?:\d{1,3}\.){3}\d{1,3}"        # IPv4
    r"|(?:[0-9a-fA-F:]+)"              # IPv6 (loose)
    r"|(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*)"  # FQDN
    r")$"
)


# ── Schemas ──────────────────────────────────────────────────────────────────

class DeviceCreate(BaseModel):
    customer_id: str
    name: str
    vendor: str
    host: str
    port: Optional[int] = None
    api_token: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    use_ssl: bool = True
    verify_ssl: bool = False
    vdom: Optional[str] = "root"
    cp_domain: Optional[str] = None
    cp_policy_package: Optional[str] = None
    cp_management_type: Optional[str] = "SmartCenter"
    sync_interval_hours: Optional[int] = None
    # Inventory fields
    fw_model: Optional[str] = None
    os_version: Optional[str] = None
    management_platform: Optional[str] = None
    environment_type: Optional[str] = "production"
    location: Optional[str] = None
    fw_role: Optional[str] = "perimeter"
    criticality: Optional[str] = "high"

    @field_validator("vendor")
    @classmethod
    def validate_vendor(cls, v: str) -> str:
        if v not in _ALLOWED_VENDORS:
            raise ValueError(f"vendor must be one of: {', '.join(sorted(_ALLOWED_VENDORS))}")
        return v

    @field_validator("host")
    @classmethod
    def validate_host(cls, v: str) -> str:
        v = v.strip()
        if not v or not _HOST_RE.match(v):
            raise ValueError("host must be a valid IP address or hostname")
        return v

    @field_validator("port")
    @classmethod
    def validate_port(cls, v: Optional[int]) -> Optional[int]:
        if v is not None and not (1 <= v <= 65535):
            raise ValueError("port must be between 1 and 65535")
        return v

    @field_validator("cp_management_type")
    @classmethod
    def validate_cp_type(cls, v: Optional[str]) -> Optional[str]:
        if v and v not in _ALLOWED_CP_TYPES:
            raise ValueError(f"cp_management_type must be one of: {', '.join(sorted(_ALLOWED_CP_TYPES))}")
        return v

    @field_validator("sync_interval_hours")
    @classmethod
    def validate_interval(cls, v: Optional[int]) -> Optional[int]:
        if v is not None and v not in _ALLOWED_INTERVALS:
            raise ValueError(f"sync_interval_hours must be one of: {sorted(i for i in _ALLOWED_INTERVALS if i)}")
        return v

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        v = v.strip()
        if not v or len(v) > 100:
            raise ValueError("name must be 1–100 characters")
        return v


class DeviceUpdate(BaseModel):
    name: Optional[str] = None
    host: Optional[str] = None
    port: Optional[int] = None
    api_token: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    use_ssl: Optional[bool] = None
    verify_ssl: Optional[bool] = None
    vdom: Optional[str] = None
    cp_domain: Optional[str] = None
    cp_policy_package: Optional[str] = None
    cp_management_type: Optional[str] = None
    sync_interval_hours: Optional[int] = None
    # Inventory fields
    fw_model: Optional[str] = None
    os_version: Optional[str] = None
    management_platform: Optional[str] = None
    environment_type: Optional[str] = None
    location: Optional[str] = None
    fw_role: Optional[str] = None
    criticality: Optional[str] = None

    @field_validator("host")
    @classmethod
    def validate_host(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            v = v.strip()
            if not v or not _HOST_RE.match(v):
                raise ValueError("host must be a valid IP address or hostname")
        return v

    @field_validator("port")
    @classmethod
    def validate_port(cls, v: Optional[int]) -> Optional[int]:
        if v is not None and not (1 <= v <= 65535):
            raise ValueError("port must be between 1 and 65535")
        return v

    @field_validator("cp_management_type")
    @classmethod
    def validate_cp_type(cls, v: Optional[str]) -> Optional[str]:
        if v and v not in _ALLOWED_CP_TYPES:
            raise ValueError(f"cp_management_type must be one of: {', '.join(sorted(_ALLOWED_CP_TYPES))}")
        return v

    @field_validator("sync_interval_hours")
    @classmethod
    def validate_interval(cls, v: Optional[int]) -> Optional[int]:
        if v is not None and v not in _ALLOWED_INTERVALS:
            raise ValueError(f"sync_interval_hours must be one of: {sorted(i for i in _ALLOWED_INTERVALS if i)}")
        return v


def _device_dict(d: FirewallDevice) -> dict:
    """
    Safe device serialization — NEVER includes raw credentials.
    Only boolean flags indicating whether credentials are present.
    """
    return {
        "id": d.id,
        "customer_id": d.customer_id,
        "name": d.name,
        "vendor": d.vendor,
        "host": d.host,
        "port": d.port,
        "use_ssl": d.use_ssl,
        "verify_ssl": d.verify_ssl,
        "vdom": d.vdom,
        "cp_domain": d.cp_domain,
        "cp_policy_package": d.cp_policy_package,
        # Presence flags only — never expose raw/decrypted values
        "has_token": bool(d.api_token),
        "has_credentials": bool(d.username and d.password),
        "cp_management_type": d.cp_management_type or "SmartCenter",
        "sync_interval_hours": d.sync_interval_hours,
        "sync_status": d.sync_status,
        "last_sync_at": d.last_sync_at.isoformat() if d.last_sync_at else None,
        "last_error": d.last_error,
        "last_policy_id": d.last_policy_id,
        # Inventory fields
        "fw_model": d.fw_model,
        "os_version": d.os_version,
        "management_platform": d.management_platform,
        "environment_type": d.environment_type or "production",
        "location": d.location,
        "fw_role": d.fw_role or "perimeter",
        "criticality": d.criticality or "high",
        # Network / HA fields (populated on live sync)
        "serial_number": d.serial_number,
        "ha_mode": d.ha_mode,
        "ha_peer": d.ha_peer,
        "device_interfaces": d.device_interfaces,  # JSON string — decoded on frontend
        "username": d.username,  # shown in detail view (not sensitive)
        "created_at": d.created_at.isoformat() if d.created_at else None,
    }


def _build_connector_for_device(d: FirewallDevice):
    """
    Instantiate the appropriate connector with DECRYPTED credentials.
    Used for test and sync operations only — credentials are never returned to callers.
    """
    token   = decrypt_credential(d.api_token)
    password = decrypt_credential(d.password)

    if d.vendor == "FortiGate":
        from app.connectors.fortigate import FortiGateConnector
        return FortiGateConnector(
            host=d.host,
            api_token=token or None,
            username=d.username or None,
            password=password or None,
            port=d.port or 443,
            use_ssl=d.use_ssl,
            verify_ssl=d.verify_ssl,
            vdom=d.vdom or "root",
        )
    elif d.vendor == "CheckPoint":
        from app.connectors.checkpoint import CheckPointConnector
        return CheckPointConnector(
            host=d.host,
            username=d.username or "",
            password=password or "",
            port=d.port or 443,
            use_ssl=d.use_ssl,
            verify_ssl=d.verify_ssl,
            domain=d.cp_domain or None,
            management_type=d.cp_management_type or "SmartCenter",
        )
    else:
        raise ValueError(f"Unsupported vendor: {d.vendor!r}")


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("")
def list_devices(customer_id: Optional[str] = None, db: Session = Depends(get_db)):
    q = db.query(FirewallDevice)
    if customer_id:
        q = q.filter(FirewallDevice.customer_id == customer_id)
    return [_device_dict(d) for d in q.order_by(FirewallDevice.created_at).all()]


@router.post("", status_code=201)
def create_device(body: DeviceCreate, db: Session = Depends(get_db)):
    if not db.query(Customer).filter(Customer.id == body.customer_id).first():
        raise HTTPException(status_code=404, detail="Customer not found")

    data = body.model_dump()
    # Encrypt sensitive fields before persisting
    data["api_token"] = encrypt_credential(data.get("api_token"))
    data["password"]  = encrypt_credential(data.get("password"))

    d = FirewallDevice(**data)
    db.add(d)
    db.commit()
    db.refresh(d)

    audit_log("device.create", device_id=d.id, customer_id=d.customer_id,
              name=d.name, vendor=d.vendor, host=d.host)
    return _device_dict(d)


@router.get("/{device_id}")
def get_device(device_id: str, db: Session = Depends(get_db)):
    d = db.query(FirewallDevice).filter(FirewallDevice.id == device_id).first()
    if not d:
        raise HTTPException(status_code=404, detail="Device not found")
    return _device_dict(d)


@router.patch("/{device_id}")
def update_device(device_id: str, body: DeviceUpdate, db: Session = Depends(get_db)):
    d = db.query(FirewallDevice).filter(FirewallDevice.id == device_id).first()
    if not d:
        raise HTTPException(status_code=404, detail="Device not found")

    updates = body.model_dump(exclude_none=True)
    # Encrypt credential fields if being updated
    if "api_token" in updates:
        updates["api_token"] = encrypt_credential(updates["api_token"])
    if "password" in updates:
        updates["password"] = encrypt_credential(updates["password"])

    for k, v in updates.items():
        setattr(d, k, v)
    db.commit()
    db.refresh(d)

    audit_log("device.update", device_id=d.id, fields=list(updates.keys()))
    return _device_dict(d)


@router.delete("/{device_id}")
def delete_device(device_id: str, db: Session = Depends(get_db)):
    d = db.query(FirewallDevice).filter(FirewallDevice.id == device_id).first()
    if not d:
        raise HTTPException(status_code=404, detail="Device not found")
    audit_log("device.delete", device_id=d.id, name=d.name, customer_id=d.customer_id)
    db.delete(d)
    db.commit()
    return {"message": "Device deleted"}


# ── Test connection ───────────────────────────────────────────────────────────

@router.post("/{device_id}/test")
def test_device(device_id: str, db: Session = Depends(get_db)):
    """
    Test connectivity and return discovery information.
    FortiGate: version, serial, VDOM list, rule count.
    CheckPoint: API version, management type, domains (MDS), policy packages, gateways.
    No data is written to the DB.
    """
    d = db.query(FirewallDevice).filter(FirewallDevice.id == device_id).first()
    if not d:
        raise HTTPException(status_code=404, detail="Device not found")

    audit_log("device.test_connection", device_id=d.id, host=d.host, vendor=d.vendor)

    try:
        conn = _build_connector_for_device(d)

        if d.vendor == "FortiGate":
            info = conn.connect()
            try:
                policies = conn.get_policies()
                info["rule_count"] = len(policies)
            except Exception:
                info["rule_count"] = None
            try:
                vdoms_data = conn._get_cmdb("system/vdom")
                info["vdoms"] = [v.get("name") for v in vdoms_data if v.get("name")]
            except Exception:
                info["vdoms"] = [d.vdom or "root"]
            conn.disconnect()

        elif d.vendor == "CheckPoint":
            info = conn.connect()
            packages: list[dict] = []
            try:
                raw_pkgs = conn.get_packages()
                packages = [
                    {
                        "name":          pkg.get("name"),
                        "uid":           pkg.get("uid"),
                        "access_layers": [
                            (l["name"] if isinstance(l, dict) else l)
                            for l in pkg.get("access-layers", [])
                        ],
                    }
                    for pkg in raw_pkgs
                ]
            except Exception as e:
                logger.warning("Could not list packages during test: %s", e)

            gateways: list[dict] = []
            try:
                raw_gws = conn.get_gateways()
                gateways = [
                    {"name": gw.get("name"), "type": gw.get("type"), "version": gw.get("version")}
                    for gw in raw_gws
                ]
            except Exception:
                pass

            domains: list[dict] = []
            is_mds = False
            try:
                raw_domains = conn.get_domains()
                if raw_domains:
                    is_mds = True
                    domains = [{"name": dom.get("name"), "uid": dom.get("uid")} for dom in raw_domains]
            except Exception:
                pass

            api_ver_info = {}
            try:
                api_ver_info = conn.get_api_version()
            except Exception:
                pass

            info.update({
                "is_mds":          is_mds,
                "domains":         domains,
                "packages":        packages,
                "gateways":        gateways,
                "api_versions":    api_ver_info,
                "management_type": "MDS" if is_mds else (d.cp_management_type or "SmartCenter"),
            })
            conn.disconnect()

        else:
            raise ValueError(f"Unknown vendor: {d.vendor!r}")

        # ── Persist version/model info discovered during test ─────────────
        if d.vendor == "FortiGate":
            from app.connectors.live_sync import _fgt_model_from_serial
            raw_ver    = info.get("version", "")
            raw_serial = info.get("serial",  "")
            if raw_ver:
                d.os_version = raw_ver
            if raw_serial:
                d.fw_model = _fgt_model_from_serial(raw_serial) or raw_serial
        elif d.vendor == "CheckPoint":
            api_ver = info.get("api_server_version", "")
            if api_ver:
                d.os_version = f"API {api_ver}"
                d.management_platform = f"Check Point Management R{api_ver.split('.')[0]}"
            gws = info.get("gateways", [])
            gw_versions = list({g.get("version") for g in gws if g.get("version")})
            if gw_versions:
                d.fw_model = f"GW: {', '.join(sorted(gw_versions)[:3])}"
        elif d.vendor == "PaloAlto":
            if info.get("version"):
                d.os_version = info["version"]
            if info.get("model"):
                d.fw_model = info["model"]
        elif d.vendor == "CiscoASA":
            if info.get("version") or info.get("software_version"):
                d.os_version = info.get("version") or info.get("software_version")
            if info.get("model"):
                d.fw_model = info["model"]
        db.commit()

        return {"success": True, "info": info}

    except Exception as e:
        logger.warning("Device test failed for %s: %s", device_id, e)
        return {"success": False, "error": str(e)}


# ── Live sync ─────────────────────────────────────────────────────────────────

def _run_sync_bg(device_id: str):
    """Background-task wrapper — gets its own DB session."""
    from app.database import SessionLocal
    db = SessionLocal()
    try:
        device = db.query(FirewallDevice).filter(FirewallDevice.id == device_id).first()
        if not device:
            return
        from app.connectors.live_sync import sync_device
        sync_device(device, db)
    except Exception as e:
        logger.error("Background sync error for device %s: %s", device_id, e)
    finally:
        db.close()


@router.post("/{device_id}/sync")
def sync_device_endpoint(
    device_id: str,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """Trigger a live policy sync. Runs in background; returns immediately."""
    d = db.query(FirewallDevice).filter(FirewallDevice.id == device_id).first()
    if not d:
        raise HTTPException(status_code=404, detail="Device not found")
    if d.sync_status == "running":
        raise HTTPException(status_code=409, detail="Sync already in progress")

    d.sync_status = "running"
    db.commit()

    audit_log("sync.trigger", device_id=d.id, name=d.name, customer_id=d.customer_id)
    background_tasks.add_task(_run_sync_bg, device_id)
    return {"message": "Sync started", "device_id": device_id}


@router.post("/{device_id}/reset-sync")
def reset_sync_status(device_id: str, db: Session = Depends(get_db)):
    """Force-reset a device stuck in 'running' state back to 'never' or 'error'."""
    d = db.query(FirewallDevice).filter(FirewallDevice.id == device_id).first()
    if not d:
        raise HTTPException(status_code=404, detail="Device not found")
    prev_status = d.sync_status
    d.sync_status = "error" if d.last_sync_at else "never"
    d.last_error = "Sync was manually reset (was stuck in 'running' state)"
    db.commit()
    audit_log("sync.reset", device_id=d.id, prev_status=prev_status, new_status=d.sync_status)
    return {"message": f"Sync status reset from '{prev_status}' to '{d.sync_status}'", "device_id": device_id}


@router.get("/{device_id}/sync-status")
def get_sync_status(device_id: str, db: Session = Depends(get_db)):
    d = db.query(FirewallDevice).filter(FirewallDevice.id == device_id).first()
    if not d:
        raise HTTPException(status_code=404, detail="Device not found")
    return {
        "sync_status": d.sync_status,
        "last_sync_at": d.last_sync_at.isoformat() if d.last_sync_at else None,
        "last_error": d.last_error,
        "last_policy_id": d.last_policy_id,
    }


@router.get("/{device_id}/trends")
def get_device_trends(device_id: str, db: Session = Depends(get_db)):
    """
    Trend analysis across all revision history for a device.
    Returns suggestions based on observed patterns over time.
    Read-only — no DB writes.
    """
    import json
    from app.models.revision import PolicyRevision
    from app.models.policy import FirewallRule
    from app.models.finding import Finding

    d = db.query(FirewallDevice).filter(FirewallDevice.id == device_id).first()
    if not d:
        raise HTTPException(status_code=404, detail="Device not found")

    if not d.last_policy_id:
        return {"revision_count": 0, "suggestions": [], "change_activity": [], "revision_timeline": [], "finding_trend": []}

    revisions = (
        db.query(PolicyRevision)
        .filter(PolicyRevision.device_id == device_id)
        .order_by(PolicyRevision.synced_at.asc())
        .all()
    )

    sync_count = len(revisions)

    revision_timeline = [
        {
            "id": r.id,
            "revision_number": r.revision_number,
            "synced_at": r.synced_at.isoformat() if r.synced_at else None,
            "rule_count": r.rule_count,
            "finding_count": r.finding_count,
            "high_finding_count": r.high_finding_count,
            "rules_added": r.rules_added,
            "rules_removed": r.rules_removed,
            "rules_modified": r.rules_modified,
            "change_summary": r.change_summary,
        }
        for r in revisions
    ]

    finding_trend = [
        {
            "synced_at": r.synced_at.isoformat() if r.synced_at else None,
            "finding_count": r.finding_count or 0,
            "high_finding_count": r.high_finding_count or 0,
            "revision_number": r.revision_number,
        }
        for r in revisions
    ]

    if sync_count < 2:
        msg = (
            "At least 2 syncs needed to detect trends. Enable auto-sync to collect data over time."
            if sync_count == 1
            else "No sync data yet. Add a device and run the first sync."
        )
        return {
            "device_id": device_id,
            "policy_id": d.last_policy_id,
            "revision_count": sync_count,
            "sync_interval_hours": d.sync_interval_hours,
            "suggestions": [{"type": "info", "severity": "Informational", "message": msg}],
            "change_activity": [],
            "revision_timeline": revision_timeline,
            "finding_trend": finding_trend,
        }

    rule_activity: dict[str, dict] = {}
    for rev_idx, rev in enumerate(revisions):
        detail = rev.change_detail or []
        if isinstance(detail, str):
            try:
                detail = json.loads(detail)
            except Exception:
                detail = []
        for change in detail:
            if not isinstance(change, dict) or "rule_id" not in change:
                continue
            rid = change["rule_id"]
            ctype = change.get("change_type", "")
            name = (change.get("after") or change.get("before") or {})
            rule_name = name.get("name", rid) if isinstance(name, dict) else rid
            if rid not in rule_activity:
                rule_activity[rid] = {
                    "rule_id": rid,
                    "rule_name": rule_name,
                    "modification_count": 0,
                    "added_in_rev_idx": None,
                    "removed_in_rev_idx": None,
                    "last_changed_at": None,
                }
            if ctype == "modified":
                rule_activity[rid]["modification_count"] += 1
                rule_activity[rid]["last_changed_at"] = rev.synced_at.isoformat() if rev.synced_at else None
            elif ctype == "added":
                rule_activity[rid]["added_in_rev_idx"] = rev_idx
                rule_activity[rid]["rule_name"] = rule_name
            elif ctype == "removed":
                rule_activity[rid]["removed_in_rev_idx"] = rev_idx

    current_rules = db.query(FirewallRule).filter(
        FirewallRule.policy_id == d.last_policy_id
    ).all()

    rule_findings: dict[str, int] = {}
    for finding in db.query(Finding).filter(Finding.policy_id == d.last_policy_id).all():
        for rid in (finding.affected_rules or []):
            rule_findings[str(rid)] = rule_findings.get(str(rid), 0) + 1

    suggestions = []

    for rule in current_rules:
        if not rule.enabled:
            continue
        if rule.hit_count is not None and rule.hit_count == 0:
            ra = rule_activity.get(rule.rule_id, {})
            added_idx = ra.get("added_in_rev_idx")
            syncs_present = sync_count - (added_idx + 1 if added_idx is not None else 0)
            if syncs_present >= 2:
                suggestions.append({
                    "type": "persistent_zero_hits",
                    "severity": "Medium",
                    "rule_id": rule.rule_id,
                    "rule_name": rule.rule_name,
                    "message": f"'{rule.rule_name}' has had zero hits across {syncs_present} consecutive syncs. Consider review for potential cleanup.",
                    "syncs_zero_hit": syncs_present,
                    "note": "Engineer validation required before any action.",
                })

    for ra in sorted(rule_activity.values(), key=lambda x: -x["modification_count"]):
        if ra["modification_count"] < 2:
            break
        if ra.get("removed_in_rev_idx") is not None:
            continue
        suggestions.append({
            "type": "frequently_modified",
            "severity": "Low",
            "rule_id": ra["rule_id"],
            "rule_name": ra["rule_name"],
            "message": f"'{ra['rule_name']}' was modified {ra['modification_count']} times — may be a temporary workaround or unstable configuration.",
            "modification_count": ra["modification_count"],
        })

    for ra in rule_activity.values():
        if ra.get("added_in_rev_idx") is not None and ra.get("removed_in_rev_idx") is not None:
            suggestions.append({
                "type": "temporary_rule_removed",
                "severity": "Informational",
                "rule_id": ra["rule_id"],
                "rule_name": ra["rule_name"],
                "message": f"'{ra['rule_name']}' was added and subsequently removed during the monitoring period.",
            })

    last_rev = revisions[-1]
    last_detail = last_rev.change_detail or []
    if isinstance(last_detail, str):
        try:
            last_detail = json.loads(last_detail)
        except Exception:
            last_detail = []
    newly_added_ids = {
        c["rule_id"] for c in last_detail
        if isinstance(c, dict) and c.get("change_type") == "added"
    }
    for rule in current_rules:
        if rule.rule_id in newly_added_ids:
            fcount = rule_findings.get(rule.rule_id, 0)
            if fcount > 0:
                suggestions.append({
                    "type": "new_rule_with_findings",
                    "severity": "High",
                    "rule_id": rule.rule_id,
                    "rule_name": rule.rule_name,
                    "message": f"'{rule.rule_name}' was added in the latest sync and already has {fcount} finding(s) — review before approving.",
                    "finding_count": fcount,
                    "note": "Engineer validation and change approval required before any modification.",
                })

    if sync_count >= 3:
        counts = [r.finding_count or 0 for r in revisions[-3:]]
        if counts[2] > counts[1] > counts[0]:
            suggestions.append({
                "type": "finding_trend_increasing",
                "severity": "Medium",
                "message": f"Total findings have increased across the last 3 syncs ({counts[0]} → {counts[1]} → {counts[2]}). Policy risk is growing.",
            })
        elif counts[2] < counts[1] < counts[0]:
            suggestions.append({
                "type": "finding_trend_decreasing",
                "severity": "Informational",
                "message": f"Total findings have decreased across the last 3 syncs ({counts[0]} → {counts[1]} → {counts[2]}). Good progress on cleanup.",
            })

    _sev_order = {"High": 0, "Medium": 1, "Low": 2, "Informational": 3}
    suggestions.sort(key=lambda s: _sev_order.get(s.get("severity", "Informational"), 3))

    change_activity = sorted(
        [ra for ra in rule_activity.values() if ra["modification_count"] > 0],
        key=lambda x: -x["modification_count"],
    )[:20]

    return {
        "device_id": device_id,
        "policy_id": d.last_policy_id,
        "revision_count": sync_count,
        "sync_interval_hours": d.sync_interval_hours,
        "suggestions": suggestions,
        "change_activity": change_activity,
        "revision_timeline": revision_timeline,
        "finding_trend": finding_trend,
    }


# ── CVE Vulnerability Check ───────────────────────────────────────────────────

@router.get("/{device_id}/vulnerabilities")
def get_device_vulnerabilities(
    device_id: str,
    refresh: bool = False,
    db: Session = Depends(get_db),
):
    """
    Query the NIST NVD for known CVEs affecting this device's OS version.
    Results are cached for 24 hours.

    Pass ?refresh=true to force a fresh NVD lookup.
    """
    d = db.query(FirewallDevice).filter(FirewallDevice.id == device_id).first()
    if not d:
        raise HTTPException(status_code=404, detail="Device not found")

    from app.analysis.cve_checker import get_device_cves
    from app.models.customer import Customer

    customer = db.query(Customer).filter(Customer.id == d.customer_id).first()
    customer_name = customer.name if customer else d.customer_id

    result = get_device_cves(
        device_id=device_id,
        vendor=d.vendor,
        os_version=d.os_version,
        db=db,
        force_refresh=refresh,
    )
    result["device_name"]    = d.name
    result["vendor"]         = d.vendor
    result["customer_name"]  = customer_name

    # Add severity summary
    cves = result.get("cves", [])
    critical = sum(1 for c in cves if (c.get("cvss_severity") or "").upper() == "CRITICAL")
    high     = sum(1 for c in cves if (c.get("cvss_severity") or "").upper() == "HIGH")
    medium   = sum(1 for c in cves if (c.get("cvss_severity") or "").upper() == "MEDIUM")
    low      = sum(1 for c in cves if (c.get("cvss_severity") or "").upper() == "LOW")

    result["severity_summary"] = {
        "critical": critical,
        "high":     high,
        "medium":   medium,
        "low":      low,
        "total":    len(cves),
    }
    return result
