"""Detect duplicate firewall rules using expanded normalized objects."""
from typing import List, Dict
from app.analysis.normalizer import (
    expand_rule_sources, expand_rule_destinations, expand_rule_services
)
from app.analysis.ip_utils import is_any, parse_ip_network
from app.analysis.service_utils import service_is_any
from app.analysis.rule_semantics import rule_semantics_key, expansion_complete


def _address_key(items: List[dict]) -> tuple:
    if any(item.get("type") == "any" or is_any(item.get("value", "")) for item in items):
        return ("any",)
    return tuple(sorted({str(parse_ip_network(item["value"])) for item in items}))


def _service_key(items: List[dict]) -> tuple:
    if any(service_is_any(item) for item in items):
        return (("any", 0, 65535),)
    return tuple(sorted({
        ("opaque", (item.get("name") or "").lower()) if item.get("opaque")
        else (item["protocol"].lower(), item["port_start"], item["port_end"])
        for item in items
    }, key=repr))


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
        # Negated cells invert set semantics — exclude from duplicate comparison.
        if rule.get("negated"):
            continue
        expanded.append({
            "rule": rule,
            "context": context_key(rule, vendor),
            "sources": expand_rule_sources(rule, obj_map),
            "destinations": expand_rule_destinations(rule, obj_map),
            "services": expand_rule_services(rule, obj_map),
        })

    # Hash complete traffic signatures instead of comparing every rule pair.
    # Restriction/context keys are part of the signature, never a post-filter.
    buckets = {}
    for index, entry in enumerate(expanded):
        if not expansion_complete(entry):
            continue
        action = (entry["rule"].get("action") or "").lower()
        if not action:
            continue
        key = (entry["context"], action, rule_semantics_key(entry["rule"]),
               _address_key(entry["sources"]), _address_key(entry["destinations"]), _service_key(entry["services"]))
        buckets.setdefault(key, []).append(index)
    groups = buckets.values()

    for member_idxs in groups:
        if len(member_idxs) < 2:
            continue  # not a duplicate set

        members = [expanded[k] for k in member_idxs]
        first = members[0]
        first_rule = first["rule"]
        action = (first_rule.get("action") or "").lower()

        all_complete = True  # Incomplete expansions never enter the index.

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
                "Both rules match the same source, destination, and service using "
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
        findings.append({
            "finding_type": "duplicate_rule",
            "severity": "Medium",
            "confidence": "High",
            "title": title,
            "description": description,
            "affected_rules": affected_rule_db_ids,
            "evidence": {
                "matching_fields": "source, destination, service, application, user, VPN, schedule, action, logging, NAT and security profiles",
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
