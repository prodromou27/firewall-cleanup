"""Firewall interface + public-IP inventory analysis (read-only).

Operates on whatever normalized interface data exists for a device
(device.device_interfaces) plus the policy's NAT rules and address objects. It
never changes interfaces or device configuration.

Interface shape consumed (best-effort, fields optional):
  {name, ip, mask, type|zone, status, alias, security_level, ipv6,
   role, admin_status, link_status, mgmt|management}
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from app.analysis.ip_utils import is_routable_public, classify_ip

# Name/zone hints that indicate an internet/WAN-facing interface.
_WAN_HINTS = ("wan", "internet", "external", "outside", "untrust", "public")


def classify_interface(iface: dict) -> Dict[str, Any]:
    ip = str(iface.get("ip") or iface.get("ipv4") or "")
    name = str(iface.get("name") or "").lower()
    zone = str(iface.get("zone") or iface.get("type") or "").lower()
    role = str(iface.get("role") or "").lower()
    has_public = is_routable_public(ip)
    wan = has_public or any(h in name or h in zone or h in role for h in _WAN_HINTS)
    return {
        "name": iface.get("name"),
        "alias": iface.get("alias") or iface.get("description"),
        "zone": iface.get("zone") or iface.get("type"),
        "security_level": iface.get("security_level"),
        "ip": ip or None,
        "mask": iface.get("mask"),
        "ipv6": iface.get("ipv6"),
        "role": iface.get("role"),
        "admin_status": iface.get("admin_status") or iface.get("status"),
        "link_status": iface.get("link_status") or iface.get("status"),
        "mgmt_access": bool(iface.get("mgmt") or iface.get("management") or iface.get("mgmt_access")),
        "has_public_ip": has_public,
        "wan_facing": wan,
    }


def _obj_public_ips(objects: dict) -> List[tuple]:
    """Return (name, value) for address objects whose value is public."""
    out = []
    for name, obj in (objects or {}).items():
        val = obj.get("value") if isinstance(obj, dict) else None
        if val and is_routable_public(str(val)):
            out.append((name, str(val)))
    return out


def build_public_ip_inventory(interfaces: List[dict], nat_rules: Optional[list],
                              objects: Optional[dict], firewall: str = "") -> List[dict]:
    """Normalized public-IP inventory across interface / NAT / object sources."""
    inv: List[dict] = []
    seen = set()

    def add(public_ip, source_type, ref, mapped_internal, service, confidence, notes):
        key = (public_ip, source_type, ref)
        if not public_ip or key in seen:
            return
        seen.add(key)
        inv.append({
            "public_ip": public_ip, "source_type": source_type, "firewall": firewall,
            "reference": ref, "mapped_internal": mapped_internal, "exposed_service": service,
            "confidence": confidence, "notes": notes,
        })

    # Interfaces
    for raw in interfaces or []:
        c = classify_interface(raw)
        if c["has_public_ip"]:
            add(c["ip"], "interface", c["name"], None, None, "High",
                "WAN/Internet-facing interface" if c["wan_facing"] else "Public IP on interface")

    # NAT (public original destination → internal translated destination)
    for n in nat_rules or []:
        if not isinstance(n, dict):
            continue
        for odst in n.get("original_dst") or []:
            if is_routable_public(str(odst)):
                add(str(odst), "nat", f"NAT {n.get('rule_number', '?')}",
                    ", ".join(n.get("translated_dst") or []) or None,
                    ", ".join(n.get("translated_service") or n.get("original_service") or []) or None,
                    "Medium", "Public IP published via NAT")

    # Address objects
    for name, val in _obj_public_ips(objects or {}):
        add(val, "object", name, None, None, "Medium", "Public IP defined in an address object")

    return inv


def analyze(interfaces: List[dict], nat_rules: Optional[list], objects: Optional[dict],
            firewall: str = "") -> Dict[str, Any]:
    """Return interface classification + public-IP inventory + advisory findings."""
    classified = [classify_interface(i) for i in (interfaces or [])]
    public_interfaces = [c for c in classified if c["has_public_ip"] or c["wan_facing"]]
    inventory = build_public_ip_inventory(interfaces, nat_rules, objects, firewall)

    findings: List[dict] = []
    for c in public_interfaces:
        if c["mgmt_access"] and c["has_public_ip"]:
            findings.append({
                "finding_type": "mgmt_on_public_interface",
                "severity": "Critical", "confidence": "High",
                "title": f"Management access enabled on public interface {c['name']}",
                "description": (
                    f"Interface {c['name']} has a public IP and management access enabled. "
                    "Device management must not be reachable from the internet."
                ),
                "affected_rules": [],
                "evidence": {"interface": c["name"], "ip": c["ip"], "mgmt_access": True},
                "recommendation": (
                    "Read-only observation. Restrict management access to trusted networks "
                    "through the approved change-management process, outside this tool."
                ),
            })

    return {
        "interfaces_available": bool(interfaces),
        "interfaces": classified,
        "public_interfaces": public_interfaces,
        "public_ip_inventory": inventory,
        "findings": findings,
    }
