"""Detect duplicate firewall rules using expanded normalized objects."""
from typing import List, Dict, Tuple, Any
from app.analysis.normalizer import (
    expand_rule_sources, expand_rule_destinations, expand_rule_services
)
from app.analysis.ip_utils import networks_equal, is_any
from app.analysis.service_utils import services_equal, service_is_any


def _addr_sets_equal(a: List[dict], b: List[dict]) -> bool:
    """True if two expanded address lists are semantically equal."""
    # If either side has unresolvable objects, we cannot confirm equality
    if any(s.get("type") == "unknown" for s in a) or any(s.get("type") == "unknown" for s in b):
        return False

    # Check if either is 'any'
    a_any = any(s.get("type") == "any" or is_any(s.get("value", "")) for s in a)
    b_any = any(s.get("type") == "any" or is_any(s.get("value", "")) for s in b)
    if a_any and b_any:
        return True
    if a_any != b_any:
        return False

    # Compare by expanded IP values
    a_values = sorted(s.get("value", "") for s in a)
    b_values = sorted(s.get("value", "") for s in b)

    if len(a_values) != len(b_values):
        return False

    return all(networks_equal(av, bv) for av, bv in zip(a_values, b_values))


def _svc_sets_equal(a: List[dict], b: List[dict]) -> bool:
    """True if two expanded service lists are semantically equal."""
    # If either side has unresolvable objects, we cannot confirm equality
    if any(s.get("unknown") for s in a) or any(s.get("unknown") for s in b):
        return False

    a_any = any(service_is_any(s) for s in a)
    b_any = any(service_is_any(s) for s in b)
    if a_any and b_any:
        return True
    if a_any != b_any:
        return False

    a_sorted = sorted(a, key=lambda s: (s.get("protocol", ""), s.get("port_start", 0)))
    b_sorted = sorted(b, key=lambda s: (s.get("protocol", ""), s.get("port_start", 0)))

    if len(a_sorted) != len(b_sorted):
        return False

    return all(services_equal(av, bv) for av, bv in zip(a_sorted, b_sorted))


def detect_duplicates(
    rules: List[dict],
    obj_map: Dict[str, dict]
) -> List[Dict]:
    """
    Detect duplicate rules. Returns list of finding dicts.
    Each finding describes a pair of duplicate rules.
    """
    findings = []
    checked = set()

    # Pre-expand all rules
    expanded = []
    for rule in rules:
        expanded.append({
            "rule": rule,
            "sources": expand_rule_sources(rule, obj_map),
            "destinations": expand_rule_destinations(rule, obj_map),
            "services": expand_rule_services(rule, obj_map),
        })

    for i in range(len(expanded)):
        for j in range(i + 1, len(expanded)):
            pair_key = (i, j)
            if pair_key in checked:
                continue
            checked.add(pair_key)

            r1 = expanded[i]
            r2 = expanded[j]

            rule1 = r1["rule"]
            rule2 = r2["rule"]

            # Skip if actions differ (not a true duplicate)
            action1 = (rule1.get("action") or "").lower()
            action2 = (rule2.get("action") or "").lower()
            if action1 != action2:
                continue

            src_eq = _addr_sets_equal(r1["sources"], r2["sources"])
            dst_eq = _addr_sets_equal(r1["destinations"], r2["destinations"])
            svc_eq = _svc_sets_equal(r1["services"], r2["services"])

            if src_eq and dst_eq and svc_eq:
                rule1_id = rule1.get("rule_id") or rule1.get("rule_number", "?")
                rule2_id = rule2.get("rule_id") or rule2.get("rule_number", "?")
                rule1_name = rule1.get("rule_name") or f"Rule {rule1_id}"
                rule2_name = rule2.get("rule_name") or f"Rule {rule2_id}"

                findings.append({
                    "finding_type": "duplicate_rule",
                    "severity": "Medium",
                    "confidence": "High",
                    "title": f"Rule {rule2_id} appears to duplicate Rule {rule1_id}",
                    "description": (
                        f"{rule2_name} matches the same traffic as {rule1_name}. "
                        "Both rules allow the same source, destination, and service using "
                        "equivalent expanded objects. Maintaining duplicate rules increases "
                        "policy complexity and may cause confusion during troubleshooting or "
                        "future firewall changes."
                    ),
                    "affected_rules": [
                        rule1.get("id"), rule2.get("id")
                    ],
                    "evidence": {
                        "original_rule": f"Rule {rule1_id} ({rule1_name})",
                        "duplicate_rule": f"Rule {rule2_id} ({rule2_name})",
                        "source": f"Both match: {[s.get('value') for s in r1['sources']]}",
                        "destination": f"Both match: {[d.get('value') for d in r1['destinations']]}",
                        "service": "Both match: " + str([{"protocol": s.get("protocol"), "ports": f"{s.get('port_start')}-{s.get('port_end')}"} for s in r1["services"]]),
                        "action": f"Both {action1}",
                    },
                    "recommendation": (
                        f"We recommend reviewing {rule2_name} and confirming whether it has a "
                        "valid business requirement. If no separate requirement exists, consider "
                        "removing or consolidating the duplicate rule through the formal change "
                        "management process."
                    ),
                    "rule1_db_id": rule1.get("id"),
                    "rule2_db_id": rule2.get("id"),
                    "rule1_number": rule1.get("rule_number"),
                    "rule2_number": rule2.get("rule_number"),
                })

    return findings
