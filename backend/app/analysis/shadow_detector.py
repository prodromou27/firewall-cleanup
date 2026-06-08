"""Detect shadowed firewall rules (full and partial)."""
from typing import List, Dict, Any, Tuple
from app.analysis.normalizer import (
    expand_rule_sources, expand_rule_destinations, expand_rule_services
)
from app.analysis.ip_utils import network_contains, is_any
from app.analysis.service_utils import service_contains, service_is_any


def _sources_contained(earlier_srcs: List[dict], later_srcs: List[dict]) -> Tuple[bool, str]:
    """
    Check if earlier sources contain all of later sources.
    Returns (contained, relationship_description)
    """
    if any(s.get("type") == "any" or is_any(s.get("value", "")) for s in earlier_srcs):
        return True, "Earlier rule source 'Any' contains all sources"

    for ls in later_srcs:
        lv = ls.get("value", "")
        contained = any(
            network_contains(es.get("value", ""), lv)
            for es in earlier_srcs
            if not (es.get("type") == "unknown")
        )
        if not contained:
            return False, "Later source not fully contained"

    return True, "Earlier rule source contains later rule source"


def _destinations_contained(earlier_dsts: List[dict], later_dsts: List[dict]) -> Tuple[bool, str]:
    if any(d.get("type") == "any" or is_any(d.get("value", "")) for d in earlier_dsts):
        return True, "Earlier rule destination 'Any' contains all destinations"

    for ld in later_dsts:
        lv = ld.get("value", "")
        contained = any(
            network_contains(ed.get("value", ""), lv)
            for ed in earlier_dsts
            if not (ed.get("type") == "unknown")
        )
        if not contained:
            return False, "Later destination not fully contained"

    return True, "Earlier rule destination contains later rule destination"


def _services_contained(earlier_svcs: List[dict], later_svcs: List[dict]) -> Tuple[bool, str]:
    if any(service_is_any(s) for s in earlier_svcs):
        return True, "Earlier rule service 'Any' contains all services"

    for ls in later_svcs:
        contained = any(service_contains(es, ls) for es in earlier_svcs)
        if not contained:
            return False, "Later service not fully contained"

    return True, "Earlier rule service contains later rule service"



def detect_shadows(
    rules: List[dict],
    obj_map: Dict[str, dict]
) -> List[Dict]:
    """
    Detect shadowed rules in policy order.
    Rules must be sorted by rule_number ascending.
    """
    findings = []

    # Pre-expand
    expanded = []
    for rule in rules:
        expanded.append({
            "rule": rule,
            "sources": expand_rule_sources(rule, obj_map),
            "destinations": expand_rule_destinations(rule, obj_map),
            "services": expand_rule_services(rule, obj_map),
        })

    for j in range(1, len(expanded)):
        later = expanded[j]
        later_rule = later["rule"]

        # Skip disabled rules — they can't be shadowed in practice
        if not later_rule.get("enabled", True):
            continue

        for i in range(j):
            earlier = expanded[i]
            earlier_rule = earlier["rule"]

            if not earlier_rule.get("enabled", True):
                continue

            src_ok, src_rel = _sources_contained(earlier["sources"], later["sources"])
            dst_ok, dst_rel = _destinations_contained(earlier["destinations"], later["destinations"])
            svc_ok, svc_rel = _services_contained(earlier["services"], later["services"])

            if src_ok and dst_ok and svc_ok:
                # Full shadow
                earlier_id = earlier_rule.get("rule_id") or earlier_rule.get("rule_number", "?")
                later_id = later_rule.get("rule_id") or later_rule.get("rule_number", "?")
                earlier_name = earlier_rule.get("rule_name") or f"Rule {earlier_id}"
                later_name = later_rule.get("rule_name") or f"Rule {later_id}"

                e_action = (earlier_rule.get("action") or "").lower()
                l_action = (later_rule.get("action") or "").lower()
                actions_differ = e_action != l_action

                severity = "High" if not actions_differ else "Medium"
                finding_type = "shadowed_rule"

                desc = (
                    f"{later_name} will never be matched because {earlier_name} "
                    f"(Rule {earlier_id}) already handles all of the same traffic. "
                )
                if actions_differ:
                    desc += (
                        f"Note: the earlier rule has action '{e_action}' while the later rule has "
                        f"action '{l_action}'. This may represent a policy logic conflict."
                    )

                findings.append({
                    "finding_type": finding_type,
                    "severity": severity,
                    "confidence": "High",
                    "title": f"Rule {later_id} is fully shadowed by Rule {earlier_id}",
                    "description": desc,
                    "affected_rules": [later_rule.get("id"), earlier_rule.get("id")],
                    "evidence": {
                        "shadowed_rule": f"Rule {later_id} ({later_name})",
                        "shadowing_rule": f"Rule {earlier_id} ({earlier_name})",
                        "source_relation": src_rel,
                        "destination_relation": dst_rel,
                        "service_relation": svc_rel,
                        "action_relation": (
                            f"Both {e_action}" if not actions_differ
                            else f"Earlier: {e_action}, Later: {l_action} — CONFLICT"
                        ),
                        "result": f"Rule {later_id} is fully shadowed",
                    },
                    "recommendation": (
                        f"Rule {later_id} ({later_name}) will never be evaluated because "
                        f"Rule {earlier_id} ({earlier_name}) matches the same traffic first. "
                        "Review whether this rule has a valid purpose. If not, consider removing "
                        "it through the formal change management process."
                    ),
                    "rule1_db_id": later_rule.get("id"),
                    "rule2_db_id": earlier_rule.get("id"),
                })
                break  # Only report the first (most relevant) shadowing rule

    return findings
