"""Conservative comparison guards shared by policy-order detectors.

Only fields represented in the normalized rule can be compared. A mismatch in
one of these fields means matching addresses and ports do not prove redundancy.
"""
from __future__ import annotations

import json


def _stable(value):
    if isinstance(value, (list, tuple, set)):
        return sorted((_stable(item) for item in value), key=repr)
    if isinstance(value, dict):
        return {str(key): _stable(item) for key, item in sorted(value.items())}
    return value


def rule_semantics_key(rule: dict) -> str:
    """Stable comparison key, computed once per rule by indexed detectors."""
    return json.dumps(_stable({field: rule.get(field) for field in (
        "applications", "users", "vpn", "schedule", "nat_enabled",
        "logging_enabled", "security_profiles",
    )}), sort_keys=True, default=str)


def comparable_rule_semantics(first: dict, second: dict) -> bool:
    """Require equivalent known match and inspection behavior before comparison."""
    return rule_semantics_key(first) == rule_semantics_key(second)


def expansion_complete(entry: dict) -> bool:
    """Unknown and empty groups cannot prove a traffic-set relationship."""
    from app.analysis.ip_utils import parse_ip_network
    if entry["rule"].get("negated") or entry["rule"].get("negate_fields"):
        return False
    if (entry["rule"].get("action") or "").lower() not in (
            "accept", "allow", "permit", "deny", "drop", "reject", "block"):
        return False  # Jump/continue/inspection actions do not prove first-match termination.
    if any(not entry["rule"].get(field) for field in ("sources", "destinations", "services")):
        return False  # Missing match fields are not evidence of an explicit wildcard.
    for field in ("sources", "destinations"):
        if not entry[field] or any(
                item.get("type") in {"unknown", "empty_group"} for item in entry[field]):
            return False
        if any(item.get("type") != "any" and parse_ip_network(item.get("value", "")) is None
               for item in entry[field]):
            return False  # Dynamic names, ranges and unsupported types need typed semantics.
        # The current normalizer maps any4 and any6 to the same IPv4 wildcard,
        # while IPv6 network containment is not implemented. Suppress definitive
        # comparisons until address families have a typed canonical model.
        if any(
                ":" in str(item.get("value") or "")
                or str(item.get("name") or "").strip().lower() in {"any4", "any6"}
                for item in entry[field]):
            return False
        if any(
                ":" in str(ref) or str(ref).strip().lower() in {"any4", "any6"}
                for ref in entry["rule"].get(field, []) or []):
            return False
    if not entry["services"]:
        return False
    for item in entry["services"]:
        if item.get("unknown") or item.get("empty_group"):
            return False
        if item.get("opaque"):
            continue
        if (item.get("protocol") or "").lower() not in ("any", "tcp", "udp"):
            return False
        start, end = item.get("port_start"), item.get("port_end")
        if type(start) is not int or type(end) is not int or not 0 <= start <= end <= 65535:
            return False
    return True
