"""Normalize firewall objects/rules for comparison. Expands groups recursively."""
import re
from typing import Dict, List, Set

from app.analysis.ip_utils import is_any
from app.analysis.service_utils import service_is_any


def _ref_name(ref) -> str:
    """Return the best object identifier from vendor reference shapes."""
    if isinstance(ref, dict):
        return str(ref.get("name") or ref.get("object_name") or ref.get("uid") or "").strip()
    return str(ref or "").strip()


def _object_aliases(obj: dict) -> List[str]:
    raw = obj.get("raw_data") or {}
    aliases = [
        obj.get("object_name"),
        obj.get("object_uid"),
        obj.get("uid"),
        raw.get("uid") if isinstance(raw, dict) else None,
        raw.get("name") if isinstance(raw, dict) else None,
    ]
    return [str(a).strip() for a in aliases if str(a or "").strip()]


def build_object_map(objects: List[dict]) -> Dict[str, dict]:
    """Build object alias -> object dict from firewall objects.

    Check Point APIs frequently return group members as UID references while
    rules use names. Mapping both names and UIDs prevents false "unused object"
    and "empty group" findings when membership is present but represented
    differently by the vendor API.
    """
    obj_map: Dict[str, dict] = {}
    for obj in objects:
        for alias in _object_aliases(obj):
            obj_map[alias] = obj
    return obj_map


def expand_address_object(
    name: str,
    obj_map: Dict[str, dict],
    visited: Set[str] = None,
) -> List[dict]:
    """
    Recursively expand an address object name to a list of resolved objects.
    Each resolved object has: {type, value, name}
    """
    if visited is None:
        visited = set()

    name_lower = name.strip().lower()
    if name_lower in ("any", "all", "any4", "any6"):
        return [{"type": "any", "value": "0.0.0.0/0", "name": name}]

    if name in visited:
        return []
    visited = visited | {name}

    obj = obj_map.get(name)
    if obj is None:
        return [{"type": "unknown", "value": name, "name": name}]

    obj_type = (obj.get("object_type") or "").lower()
    if "group" in obj_type:
        results = []
        for member in obj.get("members", []):
            results.extend(expand_address_object(_ref_name(member), obj_map, visited))
        return results or [{"type": "empty_group", "value": "", "name": name}]

    return [{"type": obj_type, "value": obj.get("value", ""), "name": name}]


_SERVICE_ALIASES = {
    "aol": ("tcp", 5190),
    "bgp": ("tcp", 179),
    "bootpc": ("udp", 68),
    "bootps": ("udp", 67),
    "cifs": ("tcp", 445),
    "citrix": ("tcp", 1494),
    "citrix-ica": ("tcp", 1494),
    "cvspserver": ("tcp", 2401),
    "dhcp": ("udp", 67),
    "dhcp-relay": ("udp", 67),
    "ssh": ("tcp", 22),
    "telnet": ("tcp", 23),
    "ftp": ("tcp", 21),
    "ftp-data": ("tcp", 20),
    "smtp": ("tcp", 25),
    "dns": ("udp", 53),
    "domain": ("udp", 53),
    "finger": ("tcp", 79),
    "gopher": ("tcp", 70),
    "gre": ("gre", 0),
    "gtp": ("udp", 2123),
    "h323": ("tcp", 1720),
    "http": ("tcp", 80),
    "http-alt": ("tcp", 8080),
    "http-mgmt": ("tcp", 280),
    "imap4": ("tcp", 143),
    "pop3": ("tcp", 110),
    "imap": ("tcp", 143),
    "ldap": ("tcp", 389),
    "ldaps": ("tcp", 636),
    "https": ("tcp", 443),
    "service-http": ("tcp", 80),
    "service-https": ("tcp", 443),
    "smb": ("tcp", 445),
    "microsoft-ds": ("tcp", 445),
    "netbios-ssn": ("tcp", 139),
    "mssql": ("tcp", 1433),
    "ms-sql": ("tcp", 1433),
    "ms-sql-s": ("tcp", 1433),
    "nfs": ("tcp", 2049),
    "ntp": ("udp", 123),
    "oracle": ("tcp", 1521),
    "oracle-sqlnet": ("tcp", 1521),
    "mysql": ("tcp", 3306),
    "pcanywhere": ("tcp", 5631),
    "postgres": ("tcp", 5432),
    "postgresql": ("tcp", 5432),
    "rdp": ("tcp", 3389),
    "ms-rdp": ("tcp", 3389),
    "sip": ("udp", 5060),
    "snmp": ("udp", 161),
    "snmptrap": ("udp", 162),
    "sqlnet": ("tcp", 1521),
    "syslog": ("udp", 514),
    "tftp": ("udp", 69),
    "vnc": ("tcp", 5900),
    "www": ("tcp", 80),
    "winrm": ("tcp", 5985),
    "winrm-https": ("tcp", 5986),
}

_OPAQUE_PREDEFINED_SERVICES = {
    "application-default",
    "app-default",
    "application-defaults",
    "default",
    "icmp",
    "icmp6",
    "ip",
    "ipsec",
    "ipsec-esp",
    "ipsec-ah",
    "ping",
    "traceroute",
    "all_icmp",
    "all_icmp6",
    "all_tcp",
    "all_udp",
}


def _inline_service(name: str) -> dict | None:
    """Resolve common inline/built-in vendor service names to structured ports."""
    raw = (name or "").strip()
    lower = raw.lower()
    if lower in _SERVICE_ALIASES:
        proto, port = _SERVICE_ALIASES[lower]
        return {"protocol": proto, "port_start": port, "port_end": port, "name": name}

    if lower in _OPAQUE_PREDEFINED_SERVICES:
        return {"protocol": lower, "port_start": None, "port_end": None, "name": name, "opaque": True}

    if re.fullmatch(r"\d{1,5}(?:-\d{1,5})?", lower):
        start_s, _, end_s = lower.partition("-")
        start = int(start_s)
        end = int(end_s or start_s)
        if start <= end <= 65535:
            return {"protocol": "tcp", "port_start": start, "port_end": end, "name": name}

    m = re.fullmatch(r"(tcp|udp|icmp|gre|ip|any)[/_:-]?(\d{1,5})(?:-(\d{1,5}))?", lower)
    if not m:
        m = re.fullmatch(r"(?:service[-_])?(tcp|udp)[-_](\d{1,5})(?:-(\d{1,5}))?", lower)
    if not m:
        return None

    proto = "any" if m.group(1) in ("ip", "any") else m.group(1)
    start = int(m.group(2))
    end = int(m.group(3) or start)
    if start > end or end > 65535:
        return None
    return {"protocol": proto, "port_start": start, "port_end": end, "name": name}


def expand_service_object(
    name: str,
    obj_map: Dict[str, dict],
    visited: Set[str] = None,
) -> List[dict]:
    """Recursively expand a service object to normalized service dicts."""
    if visited is None:
        visited = set()

    name_lower = name.lower()
    if name_lower in ("any", "all"):
        return [{"protocol": "any", "port_start": 0, "port_end": 65535, "name": name}]

    if name in visited:
        return []
    visited = visited | {name}

    obj = obj_map.get(name)
    if obj is None:
        inline = _inline_service(name)
        if inline:
            return [inline]
        return [{"protocol": "unknown", "port_start": None, "port_end": None, "name": name, "unknown": True}]

    obj_type = (obj.get("object_type") or "").lower()
    if "group" in obj_type:
        results = []
        for member in obj.get("members", []):
            results.extend(expand_service_object(_ref_name(member), obj_map, visited))
        return results

    return [{
        "protocol": obj.get("protocol", "any"),
        "port_start": obj.get("port_start", 0),
        "port_end": obj.get("port_end", 65535),
        "name": name,
    }]


def expand_rule_sources(rule: dict, obj_map: Dict[str, dict]) -> List[dict]:
    results = []
    for src in rule.get("sources", []):
        results.extend(expand_address_object(src, obj_map))
    return results or [{"type": "any", "value": "0.0.0.0/0", "name": "any"}]


def expand_rule_destinations(rule: dict, obj_map: Dict[str, dict]) -> List[dict]:
    results = []
    for dst in rule.get("destinations", []):
        results.extend(expand_address_object(dst, obj_map))
    return results or [{"type": "any", "value": "0.0.0.0/0", "name": "any"}]


def expand_rule_services(rule: dict, obj_map: Dict[str, dict]) -> List[dict]:
    results = []
    for svc in rule.get("services", []):
        results.extend(expand_service_object(svc, obj_map))
    return results or [{"protocol": "any", "port_start": 0, "port_end": 65535, "name": "any"}]


def has_any_source(rule: dict, obj_map: Dict[str, dict]) -> bool:
    sources = expand_rule_sources(rule, obj_map)
    return any(s.get("type") == "any" or is_any(s.get("value", "")) for s in sources)


def has_any_destination(rule: dict, obj_map: Dict[str, dict]) -> bool:
    dests = expand_rule_destinations(rule, obj_map)
    return any(d.get("type") == "any" or is_any(d.get("value", "")) for d in dests)


def has_any_service(rule: dict, obj_map: Dict[str, dict]) -> bool:
    services = expand_rule_services(rule, obj_map)
    return any(service_is_any(s) for s in services)
