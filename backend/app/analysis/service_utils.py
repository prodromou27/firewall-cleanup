"""Service/port utility functions for firewall rule comparison."""
from typing import Optional


def normalize_service(svc: dict) -> dict:
    """Normalize a service dict to {protocol, port_start, port_end}."""
    if svc.get("opaque"):
        return {
            "protocol": (svc.get("protocol") or "opaque").lower(),
            "port_start": None,
            "port_end": None,
            "name": svc.get("name", ""),
            "opaque": True,
        }
    return {
        "protocol": (svc.get("protocol") or "any").lower(),
        "port_start": int(svc.get("port_start") if svc.get("port_start") is not None else 0),
        "port_end": int(svc.get("port_end") if svc.get("port_end") is not None else 65535),
    }


def service_is_any(svc: dict) -> bool:
    # Unknown/opaque services are never treated as any.
    if svc.get("unknown") or svc.get("opaque"):
        return False
    proto = (svc.get("protocol") or "").lower()
    ps = int(svc.get("port_start") if svc.get("port_start") is not None else 0)
    pe = int(svc.get("port_end") if svc.get("port_end") is not None else 65535)
    return proto in ("any", "") and ps == 0 and pe == 65535


def service_contains(outer: dict, inner: dict) -> bool:
    """True if outer service range contains inner service range."""
    if outer.get("opaque") or inner.get("opaque"):
        return services_equal(outer, inner)

    outer = normalize_service(outer)
    inner = normalize_service(inner)

    if service_is_any(outer):
        return True

    proto_match = (
        outer["protocol"] == "any"
        or inner["protocol"] == "any"
        or outer["protocol"] == inner["protocol"]
    )
    if not proto_match:
        return False

    return outer["port_start"] <= inner["port_start"] and outer["port_end"] >= inner["port_end"]


def services_overlap(a: dict, b: dict) -> bool:
    """True if two service ranges overlap."""
    if a.get("opaque") or b.get("opaque"):
        return services_equal(a, b)

    a = normalize_service(a)
    b = normalize_service(b)

    if service_is_any(a) or service_is_any(b):
        return True

    proto_match = (
        a["protocol"] == "any"
        or b["protocol"] == "any"
        or a["protocol"] == b["protocol"]
    )
    if not proto_match:
        return False

    return a["port_start"] <= b["port_end"] and b["port_start"] <= a["port_end"]


def services_equal(a: dict, b: dict) -> bool:
    if a.get("opaque") or b.get("opaque"):
        return (
            bool(a.get("opaque")) == bool(b.get("opaque"))
            and (a.get("name") or "").lower() == (b.get("name") or "").lower()
        )
    a = normalize_service(a)
    b = normalize_service(b)
    return (
        a["protocol"] == b["protocol"]
        and a["port_start"] == b["port_start"]
        and a["port_end"] == b["port_end"]
    )


def is_wide_port_range(svc: dict, threshold: int = 1024) -> bool:
    """True if service covers a wide port range."""
    if svc.get("opaque"):
        return False
    svc = normalize_service(svc)
    return (svc["port_end"] - svc["port_start"]) >= threshold


RISKY_PORT_MAP = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    389: "LDAP",
    445: "SMB",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    5985: "WinRM",
    5986: "WinRM-HTTPS",
}

RISKY_UDP_PORT_MAP = {
    161: "SNMP",
    1812: "RADIUS",
    1813: "RADIUS-Acct",
}


def identify_risky_service(svc: dict) -> Optional[str]:
    """Return a risky service label if the service is considered risky."""
    if svc.get("opaque"):
        return None
    svc = normalize_service(svc)
    if service_is_any(svc):
        return "Any"
    proto = svc["protocol"]
    ps = svc["port_start"]
    pe = svc["port_end"]

    if proto in ("tcp", "any"):
        for port, name in RISKY_PORT_MAP.items():
            if ps <= port <= pe:
                return name
    if proto in ("udp", "any"):
        for port, name in RISKY_UDP_PORT_MAP.items():
            if ps <= port <= pe:
                return name

    if is_wide_port_range(svc):
        return f"Wide port range ({ps}-{pe})"

    return None
