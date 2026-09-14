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


def comparable_rule_semantics(first: dict, second: dict) -> bool:
    """Require equivalent known match and inspection behavior before comparison."""
    for field in ("applications", "users", "vpn", "schedule", "nat_enabled",
                  "logging_enabled", "security_profiles"):
        left = first.get(field)
        right = second.get(field)
        if json.dumps(_stable(left), sort_keys=True, default=str) != json.dumps(
                _stable(right), sort_keys=True, default=str):
            return False
    return True


def expansion_complete(entry: dict) -> bool:
    """Unknown and empty groups cannot prove a traffic-set relationship."""
    for field in ("sources", "destinations"):
        if not entry[field] or any(
                item.get("type") in {"unknown", "empty_group"} for item in entry[field]):
            return False
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
    return bool(entry["services"]) and not any(
        item.get("unknown") or item.get("empty_group") for item in entry["services"]
    )
