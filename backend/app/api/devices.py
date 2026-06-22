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
import json
import logging
import ipaddress
import re
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query
from pydantic import BaseModel, field_validator
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.device import FirewallDevice
from app.models.customer import Customer
from app.models.policy import FirewallPolicy
from app.models.revision import PolicyRevision
from app.security.crypto import encrypt_credential, decrypt_credential
from app.security.audit import audit_log
from app.config import settings
from app.models.user import User
from app.security.identity import (
    get_current_user, require_capability, require_customer_access, accessible_customer_ids,
)
from app.security.rbac import (
    CAP_MANAGE_DEVICES, CAP_STORE_CREDENTIALS, CAP_RUN_SYNC, CAP_DELETE_DATA,
)
from app.security.redaction import redact_secrets

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/devices", tags=["devices"])


def _diag(value: object) -> str:
    return redact_secrets(value)


def _get_device_authz(device_id: str, db: Session, user: User) -> FirewallDevice:
    """Fetch a device and enforce that the user may access its customer (tenant)."""
    d = db.query(FirewallDevice).filter(FirewallDevice.id == device_id).first()
    if not d:
        raise HTTPException(status_code=404, detail="Device not found")
    require_customer_access(db, user, d.customer_id)
    return d

# Allowed vendor values
_ALLOWED_VENDORS = {"FortiGate", "CheckPoint", "PaloAlto", "CiscoASA", "HuaweiUSG"}
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

_BLOCKED_DEVICE_IPS = {
    ipaddress.ip_address("169.254.169.254"),  # cloud instance metadata
}


def _is_unsafe_device_host(host: str) -> bool:
    h = (host or "").strip().lower().rstrip(".")
    if h in {"localhost", "ip6-localhost"}:
        return True
    try:
        ip = ipaddress.ip_address(h.strip("[]"))
    except ValueError:
        return False
    return (
        ip in _BLOCKED_DEVICE_IPS
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
    )


def _validate_safe_device_host(v: str) -> str:
    v = v.strip()
    if not v or not _HOST_RE.match(v):
        raise ValueError("host must be a valid IP address or hostname")
    if _is_unsafe_device_host(v) and not settings.allow_unsafe_device_hosts:
        raise ValueError("host targets a local/link-local/metadata address and is blocked")
    return v


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
        return _validate_safe_device_host(v)

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
            v = _validate_safe_device_host(v)
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


def _mask_username(username: Optional[str]) -> Optional[str]:
    """Return a masked version of the username for display (e.g. 'ad***' for 'admin').
    Never returns the full plaintext username in API responses."""
    if not username:
        return None
    if len(username) <= 2:
        return "*" * len(username)
    return username[:2] + "***"


def _cp_interfaces(raw: list) -> list:
    """Normalize Check Point gateway 'interfaces' (full topology) to the common
    {name, ip, mask, type, status} shape the device detail panel renders.

    Check Point full-detail interfaces look like:
      {"name": "eth0", "ipv4-address": "10.0.0.1", "ipv4-mask-length": 24,
       "topology": "external", ...}
    Missing/odd shapes are tolerated — only interfaces with a name are kept.
    """
    out = []
    for itf in raw or []:
        if not isinstance(itf, dict):
            continue
        name = itf.get("name") or itf.get("interface-name")
        if not name:
            continue
        ip = itf.get("ipv4-address") or itf.get("ipv4_address") or itf.get("ip-address") or ""
        mask_len = itf.get("ipv4-mask-length")
        mask = (
            f"/{mask_len}" if isinstance(mask_len, int) or (isinstance(mask_len, str) and mask_len.isdigit())
            else (itf.get("ipv4-network-mask") or itf.get("subnet-mask") or "")
        )
        out.append({
            "name": name,
            "ip": ip,
            "mask": mask,
            "type": itf.get("topology") or "",
            # Topology lists configured interfaces; treat as up so they render active.
            "status": "up",
        })
    return out


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
        # Credential presence flags — NEVER expose raw values
        "has_token":       bool(d.api_token),
        "has_credentials": bool(d.username and d.password),
        # Username is returned masked (first 2 chars + ***) so the UI can confirm
        # which account is configured without exposing the full value.
        "username_hint":   _mask_username(d.username),
        "cp_management_type": d.cp_management_type or "SmartCenter",
        "sync_interval_hours": d.sync_interval_hours,
        "sync_status": d.sync_status,
        "last_sync_at": d.last_sync_at.isoformat() if d.last_sync_at else None,
        "last_error": _diag(d.last_error) if d.last_error else None,
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
        "created_at": d.created_at.isoformat() if d.created_at else None,
    }


def _build_connector_for_device(d: FirewallDevice):
    """
    Instantiate the appropriate connector with DECRYPTED credentials.
    Used for test and sync operations only — credentials are never returned to callers.
    """
    token    = decrypt_credential(d.api_token)
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
    elif d.vendor == "PaloAlto":
        from app.connectors.paloalto import PaloAltoConnector
        return PaloAltoConnector(
            host=d.host,
            api_key=token or None,
            username=d.username or None,
            password=password or None,
            port=d.port or 443,
            use_ssl=d.use_ssl,
            verify_ssl=d.verify_ssl,
            vsys=d.vdom or "vsys1",
        )
    elif d.vendor == "CiscoASA":
        from app.connectors.cisco_asa import CiscoASAConnector
        return CiscoASAConnector(
            host=d.host,
            username=d.username or "",
            password=password or "",
            port=d.port or 443,
            use_ssl=d.use_ssl,
            verify_ssl=d.verify_ssl,
        )
    elif d.vendor == "HuaweiUSG":
        _hw_port = d.port or 22
        if _hw_port == 22:
            from app.connectors.huawei_ssh import HuaweiSSHConnector
            return HuaweiSSHConnector(
                host=d.host,
                username=d.username or "",
                password=password or "",
                port=_hw_port,
            )
        else:
            from app.connectors.huawei_usg import HuaweiUSGConnector
            return HuaweiUSGConnector(
                host=d.host,
                username=d.username or "",
                password=password or "",
                port=_hw_port,
                use_ssl=d.use_ssl,
                verify_ssl=d.verify_ssl,
            )
    else:
        raise ValueError(f"Unsupported vendor: {d.vendor!r}")


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("")
def list_devices(
    customer_id: Optional[str] = None,
    search: Optional[str] = None,
    vendor: Optional[str] = None,
    sync_status: Optional[str] = None,
    sort_by: Optional[str] = None,
    sort_dir: Optional[str] = None,
    page: Optional[int] = None,
    page_size: int = 50,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    q = db.query(FirewallDevice)
    if customer_id:
        require_customer_access(db, user, customer_id)
        q = q.filter(FirewallDevice.customer_id == customer_id)
    else:
        # No explicit customer filter — restrict to the user's accessible tenants.
        allowed = accessible_customer_ids(db, user)
        if allowed is not None:
            q = q.filter(FirewallDevice.customer_id.in_(allowed)) if allowed else q.filter(False)
    if search:
        like = f"%{search.strip()}%"
        q = q.filter(or_(
            FirewallDevice.name.ilike(like),
            FirewallDevice.host.ilike(like),
            FirewallDevice.fw_model.ilike(like),
            FirewallDevice.location.ilike(like),
        ))
    if vendor:
        q = q.filter(FirewallDevice.vendor == vendor)
    if sync_status:
        q = q.filter(FirewallDevice.sync_status == sync_status)

    sort_map = {
        "created_at": FirewallDevice.created_at,
        "name": FirewallDevice.name,
        "vendor": FirewallDevice.vendor,
        "host": FirewallDevice.host,
        "sync_status": FirewallDevice.sync_status,
        "last_sync_at": FirewallDevice.last_sync_at,
        "criticality": FirewallDevice.criticality,
    }
    if page is not None and page < 1:
        raise HTTPException(status_code=422, detail="page must be >= 1")
    if page_size < 1 or page_size > 250:
        raise HTTPException(status_code=422, detail="page_size must be between 1 and 250")
    if sort_by is None:
        sort_by = "created_at"
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
    if page is not None:
        rows = q.order_by(sort_col).offset((page - 1) * page_size).limit(page_size).all()
        return {"total": total, "page": page, "page_size": page_size, "devices": [_device_dict(d) for d in rows]}
    return [_device_dict(d) for d in q.order_by(sort_col).all()]


@router.post("", status_code=201)
def create_device(
    body: DeviceCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_capability(CAP_MANAGE_DEVICES)),
):
    require_customer_access(db, user, body.customer_id)
    if not db.query(Customer).filter(Customer.id == body.customer_id).first():
        raise HTTPException(status_code=404, detail="Customer not found")

    # Storing device credentials requires a dedicated capability.
    from app.security.rbac import has_capability
    if (body.password or body.api_token) and not has_capability(user.role, CAP_STORE_CREDENTIALS):
        raise HTTPException(
            status_code=403,
            detail="Your role is not permitted to store device credentials.",
        )

    data = body.model_dump()
    # Encrypt sensitive fields before persisting
    data["api_token"] = encrypt_credential(data.get("api_token"))
    data["password"]  = encrypt_credential(data.get("password"))

    d = FirewallDevice(**data)
    db.add(d)
    db.commit()
    db.refresh(d)

    audit_log("device.create", user_id=user.id, device_id=d.id, customer_id=d.customer_id,
              name=d.name, vendor=d.vendor, host=d.host)
    return _device_dict(d)


@router.get("/{device_id}")
def get_device(
    device_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    d = _get_device_authz(device_id, db, user)
    return _device_dict(d)


@router.patch("/{device_id}")
def update_device(
    device_id: str,
    body: DeviceUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(require_capability(CAP_MANAGE_DEVICES)),
):
    d = _get_device_authz(device_id, db, user)

    updates = body.model_dump(exclude_none=True)
    # Encrypt credential fields if being updated — gated by capability.
    from app.security.rbac import has_capability
    if ("api_token" in updates or "password" in updates) and not has_capability(user.role, CAP_STORE_CREDENTIALS):
        raise HTTPException(
            status_code=403,
            detail="Your role is not permitted to store device credentials.",
        )
    if "api_token" in updates:
        updates["api_token"] = encrypt_credential(updates["api_token"])
    if "password" in updates:
        updates["password"] = encrypt_credential(updates["password"])

    for k, v in updates.items():
        setattr(d, k, v)
    db.commit()
    db.refresh(d)

    audit_log("device.update", user_id=user.id, device_id=d.id, fields=list(updates.keys()))
    return _device_dict(d)


@router.delete("/{device_id}")
def delete_device(
    device_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_capability(CAP_DELETE_DATA)),
):
    d = _get_device_authz(device_id, db, user)

    audit_log("device.delete", user_id=user.id, device_id=d.id, name=d.name, customer_id=d.customer_id)

    # ── Cascade-delete all policies created by this device ───────────────────
    # This covers rules, objects, findings, finding comments, analysis runs,
    # and policy revisions — all via ORM or DB-level CASCADE.
    #
    # Strategy: find policies either stamped with device_id (new FK) OR
    # referenced by last_policy_id (legacy, before device_id column existed).
    policy_ids_to_delete: set[str] = set()

    # 1. All policies stamped with this device_id
    stamped = (
        db.query(FirewallPolicy.id)
        .filter(FirewallPolicy.device_id == d.id)
        .all()
    )
    policy_ids_to_delete.update(row[0] for row in stamped)

    # 2. The last synced policy (covers legacy rows without device_id stamped)
    if d.last_policy_id:
        policy_ids_to_delete.add(d.last_policy_id)

    deleted_policy_count = 0
    for pid in policy_ids_to_delete:
        policy = db.query(FirewallPolicy).filter(FirewallPolicy.id == pid).first()
        if policy:
            db.delete(policy)   # ORM cascade: rules, objects, findings, comments, analysis_runs
            deleted_policy_count += 1

    if deleted_policy_count:
        db.flush()  # apply policy deletes before device delete to respect FK order

    # ── Orphan revisions: device_id is a plain string (no FK) ─────────────────
    # Policy-cascade deletes most revisions via policy_id FK, but any revision
    # whose policy was already deleted separately will remain. Clean them up.
    db.query(PolicyRevision).filter(
        PolicyRevision.device_id == d.id
    ).delete(synchronize_session=False)

    # ── Delete the device (DeviceCVE deleted by DB-level CASCADE) ─────────────
    db.delete(d)
    db.commit()

    logger.info(
        "Device %s (%s) deleted — %d associated polic%s cleaned up.",
        d.id, d.name, deleted_policy_count, "ies" if deleted_policy_count != 1 else "y",
    )
    return {"message": "Device deleted", "policies_removed": deleted_policy_count}


# ── Staged connectivity diagnostics ──────────────────────────────────────────

def _tcp_reachable(host: str, port: int, timeout: int = 5) -> tuple[bool, str]:
    """Check raw TCP connectivity. Returns (ok, latency_or_error)."""
    import socket, time
    try:
        t0 = time.monotonic()
        with socket.create_connection((host, port), timeout=timeout):
            pass
        ms = round((time.monotonic() - t0) * 1000)
        return True, f"{ms} ms"
    except OSError as e:
        return False, _diag(e)


def _tls_reachable(host: str, port: int, verify_ssl: bool, timeout: int = 8) -> tuple[bool, str]:
    """Check TLS handshake. Returns (ok, info_or_error)."""
    import ssl, socket, time
    try:
        ctx = ssl.create_default_context()
        if not verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        t0 = time.monotonic()
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                cert = tls.getpeercert()
                ms = round((time.monotonic() - t0) * 1000)
                cn = ""
                for field in cert.get("subject", []):
                    for k, v in field:
                        if k == "commonName":
                            cn = v
                return True, f"TLS OK ({ms} ms){' CN=' + cn if cn else ''}"
    except ssl.SSLError as e:
        return False, f"TLS error: {e}"
    except OSError as e:
        return False, _diag(e)


# ── Test connection ───────────────────────────────────────────────────────────

@router.post("/{device_id}/test")
def test_device(
    device_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_capability(CAP_RUN_SYNC)),
):
    """
    Staged connectivity test — returns per-phase diagnostics + vendor discovery info.

    Phases:
      1. TCP reachability  (socket connect)
      2. TLS handshake     (HTTPS only)
      3. Authentication    (vendor login)
      4. API discovery     (version, rules, packages/domains, …)

    No policy data is written to the DB. Device model/version fields are updated on success.
    """
    d = db.query(FirewallDevice).filter(FirewallDevice.id == device_id).first()
    if not d:
        raise HTTPException(status_code=404, detail="Device not found")
    require_customer_access(db, user, d.customer_id)

    audit_log("device.test_connection", user_id=user.id, device_id=d.id, host=d.host, vendor=d.vendor)

    # Determine effective port and whether this is an SSH-based connection
    port = d.port or (22 if d.vendor == "HuaweiUSG" else 443)
    _is_ssh = (d.vendor == "HuaweiUSG" and port == 22)

    phases: list[dict] = []

    def phase(name: str, ok: bool, detail: str):
        phases.append({"phase": name, "ok": ok, "detail": detail})

    # ── Phase 1: TCP ──────────────────────────────────────────────────────────
    tcp_ok, tcp_detail = _tcp_reachable(d.host, port)
    phase("TCP Reachability", tcp_ok, tcp_detail)
    if not tcp_ok:
        proto = "SSH (port 22)" if _is_ssh else f"management API port {port}"
        hint = (
            f"Cannot reach {d.host}:{port} — check that the {proto} is reachable "
            "from this server and that any firewall/ACL allows the connection."
        )
        return {"success": False, "phases": phases,
                "error": f"TCP connection failed: {tcp_detail}", "hint": hint}

    # ── Phase 2: TLS (HTTPS only — skipped for SSH) ───────────────────────────
    if not _is_ssh and d.use_ssl:
        tls_ok, tls_detail = _tls_reachable(d.host, port, d.verify_ssl)
        phase("TLS Handshake", tls_ok, tls_detail)
        if not tls_ok and d.verify_ssl:
            # Retry without verification to give a better hint
            tls_noverify_ok, _ = _tls_reachable(d.host, port, verify_ssl=False)
            hint = (
                "TLS handshake failed with certificate verification enabled. "
                "If using a self-signed certificate, disable 'Verify SSL cert' in device settings. "
                + (f"Connection works without verification ({_}). " if tls_noverify_ok else "")
            )
            return {"success": False, "phases": phases,
                    "error": f"TLS error: {tls_detail}", "hint": hint}
        elif not tls_ok:
            return {"success": False, "phases": phases,
                    "error": f"TLS error: {tls_detail}",
                    "hint": "TLS handshake failed. Ensure the management port is correct and the server is reachable over HTTPS."}

    # ── Phases 3+4: Auth + Discovery (vendor-specific) ────────────────────────
    try:
        conn = _build_connector_for_device(d)
        info: dict = {}

        # ── FortiGate ─────────────────────────────────────────────────────────
        if d.vendor == "FortiGate":
            try:
                info = conn.connect()
                phase("Authentication", True, f"Logged in — version {info.get('version', '?')}")
            except Exception as e:
                err = _diag(e)
                phase("Authentication", False, err)
                hint = (
                    "FortiGate authentication failed. Ensure the API token is correct and the trusted host list "
                    "includes this server's IP. Or provide a username/password if not using API tokens."
                )
                conn.disconnect()
                return {"success": False, "phases": phases, "error": err, "hint": hint}

            # Discovery
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
            try:
                ifaces = conn.get_interfaces()
                info["interface_count"] = len(ifaces)
            except Exception:
                info["interface_count"] = None
            try:
                zones = conn.get_zones()
                info["zone_count"] = len(zones)
            except Exception:
                info["zone_count"] = None
            conn.disconnect()

            disc_parts = []
            if info.get("rule_count") is not None:
                disc_parts.append(f"{info['rule_count']} rules")
            if info.get("interface_count"):
                disc_parts.append(f"{info['interface_count']} interfaces")
            if info.get("zone_count"):
                disc_parts.append(f"{info['zone_count']} zones")
            if info.get("vdoms") and len(info["vdoms"]) > 1:
                disc_parts.append(f"{len(info['vdoms'])} VDOMs")
            phase("API Discovery", True, ", ".join(disc_parts) if disc_parts else "Discovery complete")

        # ── Check Point ───────────────────────────────────────────────────────
        elif d.vendor == "CheckPoint":
            try:
                info = conn.connect()
                phase("Authentication", True, f"Logged in — API {info.get('api_server_version', '?')}")
            except Exception as e:
                err = _diag(e)
                phase("Authentication", False, err)
                hint = (
                    "Check Point authentication failed. Ensure:\n"
                    "• The management server has API access enabled (SmartConsole → Management API)\n"
                    "• The user has read-only permission profile\n"
                    "• For MDS, specify the correct domain in device settings\n"
                    "• For Smart-1 Cloud, use the API key in the 'API Token' field"
                )
                return {"success": False, "phases": phases, "error": err, "hint": hint}

            packages: list[dict] = []
            try:
                raw_pkgs = conn.get_packages()
                packages = [
                    {
                        "name": pkg.get("name"),
                        "uid":  pkg.get("uid"),
                        "access_layers": [
                            (l["name"] if isinstance(l, dict) else l)
                            for l in pkg.get("access-layers", [])
                        ],
                    }
                    for pkg in raw_pkgs
                ]
            except Exception as e:
                logger.warning("Could not list packages during test: %s", _diag(e))

            gateways: list[dict] = []
            try:
                raw_gws = conn.get_gateways()
                gateways = [
                    {
                        "name": gw.get("name"), "type": gw.get("type"), "version": gw.get("version"),
                        "hardware": gw.get("hardware"),
                        "ipv4-address": gw.get("ipv4-address") or gw.get("ip-address"),
                        "interfaces": gw.get("interfaces") or [],
                    }
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

            disc_parts = []
            if packages:
                disc_parts.append(f"{len(packages)} policy package(s)")
            if gateways:
                disc_parts.append(f"{len(gateways)} gateway(s)")
            if is_mds and domains:
                disc_parts.append(f"{len(domains)} domain(s)")
            phase("API Discovery", True, ", ".join(disc_parts) if disc_parts else "Discovery complete")

        # ── Palo Alto ─────────────────────────────────────────────────────────
        elif d.vendor == "PaloAlto":
            try:
                info = conn.connect()
                version = info.get("version", info.get("sw-version", "?"))
                model   = info.get("model", "")
                phase("Authentication", True, f"Logged in — PAN-OS {version}{' ' + model if model else ''}")
            except Exception as e:
                err = _diag(e)
                phase("Authentication", False, err)
                hint = (
                    "Palo Alto authentication failed. Ensure:\n"
                    "• The API key is correct (generate with GET /api/?type=keygen)\n"
                    "• Or provide username + password — the connector will auto-generate the key\n"
                    "• The management interface is accessible and the REST API is enabled\n"
                    "• The vsys name is correct (default: vsys1)"
                )
                return {"success": False, "phases": phases, "error": err, "hint": hint}

            # Fetch security rules
            try:
                raw = conn.get_all()
                rules = raw.get("rules", [])
                info["rule_count"] = len(rules)
                info["object_count"] = (
                    len(raw.get("addresses", [])) +
                    len(raw.get("address_groups", [])) +
                    len(raw.get("services", [])) +
                    len(raw.get("service_groups", []))
                )
                info["app_count"] = len(raw.get("applications", []))
                # Collect vsys list if Panorama
                vsys_list = list({r.get("vsys") for r in rules if r.get("vsys")})
                if vsys_list:
                    info["vsys_list"] = vsys_list
            except Exception as e:
                logger.warning("PaloAlto discovery partial failure: %s", _diag(e))
                info.setdefault("rule_count", None)

            disc_parts = []
            if info.get("rule_count") is not None:
                disc_parts.append(f"{info['rule_count']} security rules")
            if info.get("object_count"):
                disc_parts.append(f"{info['object_count']} objects")
            if info.get("app_count"):
                disc_parts.append(f"{info['app_count']} application definitions")
            phase("API Discovery", True, ", ".join(disc_parts) if disc_parts else "Discovery complete")

        # ── Cisco ASA ─────────────────────────────────────────────────────────
        elif d.vendor == "CiscoASA":
            try:
                info = conn.connect()
                version = info.get("version", info.get("software_version", "?"))
                model   = info.get("model", "")
                phase("Authentication", True, f"Logged in — ASA {version}{' ' + model if model else ''}")
            except Exception as e:
                err = _diag(e)
                phase("Authentication", False, err)
                hint = (
                    "Cisco ASA authentication failed. Ensure:\n"
                    "• Username and password are correct (privilege level 5+)\n"
                    "• The REST API agent is running: 'rest-api agent'\n"
                    "• The management interface allows HTTPS connections\n"
                    "• Port 443 is used for REST API (not 80 or ASDM)"
                )
                return {"success": False, "phases": phases, "error": err, "hint": hint}

            # Fetch rules across all interfaces
            try:
                # Get interface list first (lightweight)
                ifaces = conn.get_interfaces()
                info["interface_count"] = len(ifaces)
                info["interfaces"] = [
                    {"name": i.get("name") or i.get("nameif", ""),
                     "ip":   i.get("ipAddress", {}).get("ip", {}).get("value", ""),
                     "mask": i.get("ipAddress", {}).get("netMask", {}).get("value", ""),
                     "type": "physical", "status": "up"}
                    for i in ifaces if i.get("name") or i.get("nameif")
                ][:20]  # limit to 20 for display
            except Exception as e:
                logger.warning("CiscoASA interface fetch failed: %s", _diag(e))
                info["interface_count"] = None

            try:
                raw = conn.get_all()
                rules = raw.get("rules", [])
                info["rule_count"] = len(rules)
                info["object_count"] = (
                    len(raw.get("network_objects", [])) +
                    len(raw.get("network_groups", []))
                )
            except Exception as e:
                logger.warning("CiscoASA discovery partial failure: %s", _diag(e))
                info.setdefault("rule_count", None)

            conn.disconnect()

            disc_parts = []
            if info.get("rule_count") is not None:
                disc_parts.append(f"{info['rule_count']} ACL rules")
            if info.get("interface_count"):
                disc_parts.append(f"{info['interface_count']} interfaces")
            if info.get("object_count"):
                disc_parts.append(f"{info['object_count']} network objects")
            phase("API Discovery", True, ", ".join(disc_parts) if disc_parts else "Discovery complete")

        # ── Huawei USG (SSH or REST) ──────────────────────────────────────────
        elif d.vendor == "HuaweiUSG":
            _hw_port = d.port or 22
            _hw_ssh  = (_hw_port == 22)

            try:
                info = conn.connect()
                version  = info.get("version", "?")
                model    = info.get("model", "")
                sysname  = info.get("sysname", "")
                proto    = "SSH" if _hw_ssh else "REST"
                detail   = f"Connected via {proto} — VRP {version}"
                if model:
                    detail += f" ({model})"
                if sysname and sysname != d.host:
                    detail += f" sysname={sysname}"
                phase("Authentication", True, detail)
            except Exception as e:
                err = _diag(e)
                phase("Authentication", False, err)
                if _hw_ssh:
                    hint = (
                        "Huawei USG SSH authentication failed. Ensure:\n"
                        "• Username and password are correct\n"
                        "• SSH service is enabled: 'ssh server enable' in system view\n"
                        "• The user has at minimum operator (read-only) role\n"
                        "• Management ACL allows SSH (TCP/22) from this server's IP\n"
                        "• If the device has 'aaa' authentication configured, the user "
                        "must match the SSH user-interface authentication scheme"
                    )
                else:
                    hint = (
                        "Huawei USG REST API authentication failed. Ensure:\n"
                        "• Username and password are correct (admin or read-only operator)\n"
                        "• The web API is enabled: 'web-manager security enable' in system view\n"
                        "• HTTPS management is enabled on the management interface\n"
                        "• Default port is 443 (or 8443 on USG6000E/F — check your deployment)"
                    )
                return {"success": False, "phases": phases, "error": err, "hint": hint}

            try:
                raw = conn.get_all()
                rules = raw.get("rules", [])
                info["rule_count"] = len(rules)
                info["object_count"] = (
                    len(raw.get("addresses", [])) +
                    len(raw.get("address_groups", []))
                )
                info["zone_count"] = len(raw.get("zones", []))
                if raw.get("warnings"):
                    info["warnings"] = raw["warnings"]
            except Exception as e:
                logger.warning("HuaweiUSG discovery partial failure: %s", _diag(e))
                info.setdefault("rule_count", None)

            conn.disconnect()

            disc_parts = []
            if info.get("rule_count") is not None:
                disc_parts.append(f"{info['rule_count']} security rules")
            if info.get("zone_count"):
                disc_parts.append(f"{info['zone_count']} zones")
            if info.get("object_count"):
                disc_parts.append(f"{info['object_count']} address objects")
            phase("API Discovery", True, ", ".join(disc_parts) if disc_parts else "Discovery complete")

        else:
            raise ValueError(f"Unknown vendor: {d.vendor!r}")

        # ── Persist version/model info discovered during test ─────────────────
        if d.vendor == "FortiGate":
            from app.connectors.live_sync import _fgt_model_from_serial
            raw_ver    = info.get("version", "")
            raw_serial = info.get("serial",  "")
            if raw_ver:
                d.os_version = raw_ver
            if raw_serial:
                d.fw_model = _fgt_model_from_serial(raw_serial) or raw_serial
                d.serial_number = raw_serial
        elif d.vendor == "CheckPoint":
            api_ver = info.get("api_server_version", "")
            if api_ver:
                d.management_platform = f"Check Point Management R{api_ver.split('.')[0]}"
            gws = info.get("gateways", [])
            gw_versions = list({g.get("version") for g in gws if g.get("version")})
            if gw_versions:
                d.fw_model = f"GW: {', '.join(sorted(gw_versions)[:3])}"
                # Store the gateway OS version (e.g. "R81.20") for CVE mapping;
                # fall back to the management API version string if no GW versions
                d.os_version = sorted(gw_versions)[0]
            elif api_ver:
                # No gateway versions available — store API version as fallback
                # (CVE checker will skip "API x.y" strings gracefully)
                d.os_version = f"API {api_ver}"
            # Populate the inventory (interfaces, HA, hardware) from the primary
            # gateway's full topology so the device detail panel is meaningful.
            try:
                primary = next((g for g in gws if g.get("interfaces")), gws[0] if gws else None)
                if primary:
                    ifaces = _cp_interfaces(primary.get("interfaces") or [])
                    if ifaces:
                        d.device_interfaces = json.dumps(ifaces)
                    if primary.get("hardware"):
                        d.fw_model = f"{primary['hardware']} ({d.fw_model})" if d.fw_model else primary["hardware"]
                    if "cluster" in (primary.get("type") or "").lower():
                        d.ha_mode = d.ha_mode or "cluster"
            except Exception as _cp_inv_exc:
                logger.warning("Could not populate Check Point inventory: %s", _cp_inv_exc)
        elif d.vendor == "PaloAlto":
            if info.get("version") or info.get("sw-version"):
                d.os_version = info.get("version") or info.get("sw-version")
            if info.get("model"):
                d.fw_model = info["model"]
            if info.get("serial"):
                d.serial_number = info["serial"]
        elif d.vendor == "CiscoASA":
            if info.get("version") or info.get("software_version"):
                d.os_version = info.get("version") or info.get("software_version")
            if info.get("model"):
                d.fw_model = info["model"]
        elif d.vendor == "HuaweiUSG":
            if info.get("version"):
                d.os_version = info["version"]
            if info.get("model"):
                d.fw_model = info["model"]
            if info.get("serial"):
                d.serial_number = info["serial"]
        db.commit()

        return {"success": True, "phases": phases, "info": info}

    except Exception as e:
        err = _diag(e)
        logger.warning("Device test failed for %s (%s): %s", device_id, d.vendor, err)
        phase("API Discovery", False, err)
        hint = _vendor_error_hint(d.vendor, err)
        return {"success": False, "phases": phases, "error": err, "hint": hint}


def _vendor_error_hint(vendor: str, error: str) -> str:
    """Return a human-readable troubleshooting hint based on vendor + error text."""
    err = error.lower()

    # Common patterns
    if "401" in err or "unauthorized" in err or "invalid credential" in err or "login failed" in err:
        hints = {
            "FortiGate":  "API token is invalid or expired. Check trusted host list and API profile permissions.",
            "CheckPoint": "Invalid credentials or the user lacks API access. Check SmartConsole → Manage & Settings → API.",
            "PaloAlto":   "Invalid API key. Regenerate it with GET /api/?type=keygen&user=U&password=P.",
            "CiscoASA":   "Invalid credentials. Ensure the user has privilege level 5+.",
            "HuaweiUSG":  "Invalid credentials. Check the username/password. For SSH: ensure 'ssh server enable' and the user has operator role. For REST: ensure 'web-manager security enable'.",
        }
        return hints.get(vendor, "Authentication failed — check credentials.")

    if "403" in err or "forbidden" in err or "permission" in err:
        return f"Access denied. The {vendor} user may lack the required read-only permissions."

    if "404" in err or "not found" in err:
        hints = {
            "FortiGate":  "API endpoint not found — check the VDOM name and FortiOS version (6.2+ required).",
            "CheckPoint": "API endpoint not found — ensure Management API is running and the port is correct.",
            "PaloAlto":   "REST API endpoint not found — PAN-OS 9.0+ required for REST API.",
            "CiscoASA":   "REST API not available — ensure the REST API agent is running ('rest-api agent').",
        }
        return hints.get(vendor, "API endpoint not found.")

    if "timeout" in err or "timed out" in err:
        return f"Connection timed out reaching {vendor} management interface. Check network routing and firewall ACLs."

    if "ssl" in err or "certificate" in err or "cert" in err:
        return "SSL/TLS error — try disabling 'Verify SSL cert' in device settings if using a self-signed certificate."

    if "connection refused" in err:
        return f"Connection refused on the configured port. Ensure the {vendor} management API is enabled and listening on the correct port."

    return f"Unexpected error connecting to {vendor}. Check logs for details."


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
        logger.error("Background sync error for device %s: %s", device_id, _diag(e))
    finally:
        db.close()


@router.post("/{device_id}/sync")
def sync_device_endpoint(
    device_id: str,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    user: User = Depends(require_capability(CAP_RUN_SYNC)),
):
    """Trigger a live policy sync. Runs in background; returns immediately."""
    d = _get_device_authz(device_id, db, user)
    if d.sync_status == "running":
        raise HTTPException(status_code=409, detail="Sync already in progress")

    d.sync_status = "running"
    db.commit()

    audit_log("sync.trigger", user_id=user.id, device_id=d.id, name=d.name, customer_id=d.customer_id)
    background_tasks.add_task(_run_sync_bg, device_id)
    return {"message": "Sync started", "device_id": device_id}


@router.post("/{device_id}/reset-sync")
def reset_sync_status(
    device_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_capability(CAP_RUN_SYNC)),
):
    """Force-reset a device stuck in 'running' state back to 'never' or 'error'."""
    d = _get_device_authz(device_id, db, user)
    prev_status = d.sync_status
    d.sync_status = "error" if d.last_sync_at else "never"
    d.last_error = "Sync was manually reset (was stuck in 'running' state)"
    db.commit()
    audit_log("sync.reset", user_id=user.id, device_id=d.id, prev_status=prev_status, new_status=d.sync_status)
    return {"message": f"Sync status reset from '{prev_status}' to '{d.sync_status}'", "device_id": device_id}


@router.get("/{device_id}/sync-status")
def get_sync_status(
    device_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    d = _get_device_authz(device_id, db, user)
    return {
        "sync_status": d.sync_status,
        "last_sync_at": d.last_sync_at.isoformat() if d.last_sync_at else None,
        "last_error": _diag(d.last_error) if d.last_error else None,
        "last_policy_id": d.last_policy_id,
    }


@router.get("/{device_id}/trends")
def get_device_trends(
    device_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Trend analysis across all revision history for a device.
    Returns suggestions based on observed patterns over time.
    Read-only — no DB writes.
    """
    import json
    from app.models.revision import PolicyRevision
    from app.models.policy import FirewallRule
    from app.models.finding import Finding

    d = _get_device_authz(device_id, db, user)

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


# ── Version Intelligence ──────────────────────────────────────────────────────

@router.get("/{device_id}/version-intelligence")
def get_device_version_intelligence(
    device_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Advisory version assessment against the manually-managed Version Catalog.

    Read-only: never changes firmware. When the catalog has no matching entry,
    only an Informational finding is returned.
    """
    from app.analysis import version_intel
    from app.models.version_catalog import VersionCatalogEntry

    d = _get_device_authz(device_id, db, user)
    catalog = [
        {"vendor": e.vendor, "release_train": e.release_train,
         "recommended_version": e.recommended_version, "support_status": e.support_status,
         "eol_versions": e.eol_versions or [], "advisory_url": e.advisory_url}
        for e in db.query(VersionCatalogEntry).all()
    ]
    result = version_intel.analyze_device(d, catalog)
    result["device_name"] = d.name
    result["vendor"] = d.vendor
    return result


# ── CVE Vulnerability Check ───────────────────────────────────────────────────

@router.get("/{device_id}/vulnerabilities")
def get_device_vulnerabilities(
    device_id: str,
    refresh: bool = False,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Query the NIST NVD for known CVEs affecting this device's OS version.
    Results are cached for 24 hours.

    Pass ?refresh=true to force a fresh NVD lookup.
    """
    d = _get_device_authz(device_id, db, user)

    from app.analysis.cve_checker import get_device_cves
    from app.models.customer import Customer

    customer = db.query(Customer).filter(Customer.id == d.customer_id).first()
    customer_name = customer.name if customer else d.customer_id

    # For CheckPoint the sync may have stored the API version ("API 2.0.1") rather
    # than the gateway OS version. Fall back to fw_model ("GW: R81.20") so the CPE
    # can still be built.
    from app.analysis.cve_checker import build_cpe_string
    os_ver = d.os_version
    if d.vendor == "CheckPoint" and not build_cpe_string(d.vendor, os_ver or ""):
        # Try to extract a version from fw_model e.g. "GW: R81.20" → "R81.20"
        import re as _re
        if d.fw_model:
            m = _re.search(r"[Rr]\d+(?:\.\d+)?", d.fw_model)
            if m:
                os_ver = m.group(0)

    result = get_device_cves(
        device_id=device_id,
        vendor=d.vendor,
        os_version=os_ver,
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
