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


def _expansion_complete(entry: dict) -> bool:
    """True if the rule expanded with no unresolved (unknown) objects."""
    if any(s.get("type") == "unknown" for s in entry["sources"]):
        return False
    if any(d.get("type") == "unknown" for d in entry["destinations"]):
        return False
    if any(s.get("unknown") for s in entry["services"]):
        return False
    return True


def detect_duplicates(
    rules: List[dict],
    obj_map: Dict[str, dict],
    vendor: str = "",
) -> List[Dict]:
    """
    Detect duplicate rules. Returns list of finding dicts.

    Rules that share identical effective (expanded) source, destination,
    service and action AND the same vendor evaluation context (layer / zone /
    interface binding) are grouped together. Rules in different contexts are
    never compared. A group of 3+ duplicates produces a single finding.
    """
    from app.analysis.vendor_semantics import context_key
    findings = []

    # Pre-expand all rules
    expanded = []
    for rule in rules:
        if not rule.get("enabled", True):
            continue
        expanded.append({
            "rule": rule,
            "context": context_key(rule, vendor),
            "sources": expand_rule_sources(rule, obj_map),
            "destinations": expand_rule_destinations(rule, obj_map),
            "services": expand_rule_services(rule, obj_map),
        })

    # Group rules into equivalence sets via transitive matching.
    n = len(expanded)
    group_of = [-1] * n  # index -> group id
    groups: List[List[int]] = []

    for i in range(n):
        if group_of[i] != -1:
            continue
        # Start a new group with rule i
        gid = len(groups)
        groups.append([i])
        group_of[i] = gid

        for j in range(i + 1, n):
            if group_of[j] != -1:
                continue
            r1 = expanded[i]
            r2 = expanded[j]
            # Only compare rules in the same vendor evaluation context.
            if r1["context"] != r2["context"]:
                continue
            action1 = (r1["rule"].get("action") or "").lower()
            action2 = (r2["rule"].get("action") or "").lower()
            if action1 != action2:
                continue
            if (_addr_sets_equal(r1["sources"], r2["sources"])
                    and _addr_sets_equal(r1["destinations"], r2["destinations"])
                    and _svc_sets_equal(r1["services"], r2["services"])):
                groups[gid].append(j)
                group_of[j] = gid

    for member_idxs in groups:
        if len(member_idxs) < 2:
            continue  # not a duplicate set

        members = [expanded[k] for k in member_idxs]
        first = members[0]
        first_rule = first["rule"]
        action = (first_rule.get("action") or "").lower()

        # Confidence reflects how completely objects expanded across the set.
        all_complete = all(_expansion_complete(m) for m in members)
        confidence = "High" if all_complete else "Medium"

        def _label(entry):
            r = entry["rule"]
            rid = r.get("rule_id") or r.get("rule_number", "?")
            name = r.get("rule_name") or f"Rule {rid}"
            return rid, name

        first_id, first_name = _label(first)
        dup_labels = [f"Rule {_label(m)[0]} ({_label(m)[1]})" for m in members[1:]]
        dup_ids = [_label(m)[0] for m in members[1:]]

        affected_rule_db_ids = [m["rule"].get("id") for m in members]

        if len(members) == 2:
            title = f"Rule {dup_ids[0]} appears to duplicate Rule {first_id}"
            description = (
                f"Rule {dup_ids[0]} matches the same traffic as Rule {first_id}. "
                "Both rules permit the same source, destination, and service using "
                "equivalent expanded objects. Maintaining duplicate rules increases "
                "policy complexity and may cause confusion during troubleshooting or "
                "future firewall changes."
            )
        else:
            title = f"{len(members)} rules share identical effective traffic (duplicate group)"
            description = (
                f"Rule {first_id} and {len(members) - 1} other rule(s) "
                f"({', '.join(f'Rule {i}' for i in dup_ids)}) all match the same "
                "source, destination, service, and action using equivalent expanded "
                "objects. Consolidating duplicate rules reduces policy complexity and "
                "the risk of inconsistent future changes."
            )
        if not all_complete:
            description += (
                " Note: some referenced objects could not be fully expanded, so this "
                "match is reported with reduced confidence and should be validated "
                "against the effective object definitions."
            )

        findings.append({
            "finding_type": "duplicate_rule",
            "severity": "Medium",
            "confidence": confidence,
            "title": title,
            "description": description,
            "affected_rules": affected_rule_db_ids,
            "evidence": {
                "matching_fields": "source, destination, service, action",
                "rules_in_group": [f"Rule {first_id} ({first_name})"] + dup_labels,
                "expanded_source": [s.get("value") for s in first["sources"]],
                "expanded_destination": [d.get("value") for d in first["destinations"]],
                "expanded_service": [
                    {"protocol": s.get("protocol"),
                     "ports": f"{s.get('port_start')}-{s.get('port_end')}"}
                    for s in first["services"]
                ],
                "action": f"All {action}",
                "expansion_complete": all_complete,
            },
            "recommendation": (
                f"Review these rules and confirm whether each is still required. "
                "If no valid business requirement exists for the redundant rule(s), "
                "they may be considered for manual consolidation through the approved "
                "change management process."
            ),
            "rule1_db_id": first_rule.get("id"),
            "rule2_db_id": members[1]["rule"].get("id"),
            "rule1_number": first_rule.get("rule_number"),
            "rule2_number": members[1]["rule"].get("rule_number"),
        })

    return findings
