"""Normalize firewall objects/rules for comparison. Expands groups recursively."""
from typing import Dict, List, Any, Set
from app.analysis.ip_utils import parse_ip_network, is_any
from app.analysis.service_utils import normalize_service, service_is_any


def build_object_map(objects: List[dict]) -> Dict[str, dict]:
    """Build name -> object dict from list of firewall objects."""
    return {obj["object_name"]: obj for obj in objects}


def expand_address_object(
    name: str,
    obj_map: Dict[str, dict],
    visited: Set[str] = None
) -> List[dict]:
    """
    Recursively expand an address object name to a list of resolved objects.
    Each resolved object has: {type, value, name}
    """
    if visited is None:
        visited = set()

    name_lower = name.lower()
    if name_lower in ("any", "all"):
        return [{"type": "any", "value": "0.0.0.0/0", "name": name}]

    if name in visited:
        return []  # circular reference guard
    visited = visited | {name}

    obj = obj_map.get(name)
    if obj is None:
        # Unknown object — treat as opaque
        return [{"type": "unknown", "value": name, "name": name}]

    obj_type = obj.get("object_type", "")
    if obj_type == "group":
        results = []
        for member in obj.get("members", []):
            results.extend(expand_address_object(member, obj_map, visited))
        return results or [{"type": "empty_group", "value": "", "name": name}]

    return [{"type": obj_type, "value": obj.get("value", ""), "name": name}]


def expand_service_object(
    name: str,
    obj_map: Dict[str, dict],
    visited: Set[str] = None
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
        return [{"protocol": "any", "port_start": 0, "port_end": 65535, "name": name, "unknown": True}]

    obj_type = obj.get("object_type", "")
    if "group" in obj_type:
        results = []
        for member in obj.get("members", []):
            results.extend(expand_service_object(member, obj_map, visited))
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
