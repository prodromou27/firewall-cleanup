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



def _has_unknown(entry: dict) -> bool:
    """True if the rule references objects that could not be expanded."""
    if any(s.get("type") == "unknown" for s in entry["sources"]):
        return True
    if any(d.get("type") == "unknown" for d in entry["destinations"]):
        return True
    if any(s.get("unknown") for s in entry["services"]):
        return True
    return False


def detect_shadows(
    rules: List[dict],
    obj_map: Dict[str, dict]
) -> List[Dict]:
    """
    Detect shadowed rules in policy order.
    Rules must be sorted by rule_number ascending.

    Reports both full shadows (every dimension contained) and partial
    shadows (two of three dimensions contained), and reduces confidence
    when referenced objects could not be fully expanded.
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

        reported = False
        for i in range(j):
            if reported:
                break
            earlier = expanded[i]
            earlier_rule = earlier["rule"]

            if not earlier_rule.get("enabled", True):
                continue

            src_ok, src_rel = _sources_contained(earlier["sources"], later["sources"])
            dst_ok, dst_rel = _destinations_contained(earlier["destinations"], later["destinations"])
            svc_ok, svc_rel = _services_contained(earlier["services"], later["services"])

            contained_count = sum([src_ok, dst_ok, svc_ok])
            # Full shadow needs all 3; partial shadow needs exactly 2.
            if contained_count < 2:
                continue

            full = contained_count == 3

            earlier_id = earlier_rule.get("rule_id") or earlier_rule.get("rule_number", "?")
            later_id = later_rule.get("rule_id") or later_rule.get("rule_number", "?")
            earlier_name = earlier_rule.get("rule_name") or f"Rule {earlier_id}"
            later_name = later_rule.get("rule_name") or f"Rule {later_id}"

            e_action = (earlier_rule.get("action") or "").lower()
            l_action = (later_rule.get("action") or "").lower()
            actions_differ = e_action != l_action

            # Confidence reduced when expansion incomplete on either rule.
            incomplete = _has_unknown(earlier) or _has_unknown(later)
            if full:
                confidence = "Medium" if incomplete else "High"
                conflict_type = "different-action" if actions_differ else "same-action"
                severity = "High" if not actions_differ else "Medium"
                title = f"Rule {later_id} is fully shadowed by Rule {earlier_id}"
                desc = (
                    f"{later_name} will never be matched because {earlier_name} "
                    f"(Rule {earlier_id}) already handles all of the same traffic. "
                )
                result = f"Rule {later_id} is fully shadowed"
            else:
                # Partial shadow — lower severity/confidence by nature.
                confidence = "Low" if incomplete else "Medium"
                conflict_type = "partial"
                severity = "Medium" if not actions_differ else "Low"
                covered = []
                if src_ok:
                    covered.append("source")
                if dst_ok:
                    covered.append("destination")
                if svc_ok:
                    covered.append("service")
                title = f"Rule {later_id} is partially shadowed by Rule {earlier_id}"
                desc = (
                    f"{later_name} overlaps with {earlier_name} (Rule {earlier_id}) on "
                    f"{' and '.join(covered)}, so part of its traffic may already be "
                    "handled by the earlier rule. The rules are not fully redundant. "
                )
                result = f"Rule {later_id} is partially shadowed ({', '.join(covered)} overlap)"

            if actions_differ:
                desc += (
                    f"Note: the earlier rule has action '{e_action}' while the later rule "
                    f"has action '{l_action}'. This may represent a policy logic conflict."
                )
            if incomplete:
                desc += (
                    " Some referenced objects could not be fully expanded, so this "
                    "finding is reported with reduced confidence and should be validated "
                    "against the effective object definitions."
                )

            findings.append({
                "finding_type": "shadowed_rule",
                "severity": severity,
                "confidence": confidence,
                "title": title,
                "description": desc,
                "affected_rules": [later_rule.get("id"), earlier_rule.get("id")],
                "evidence": {
                    "shadowed_rule": f"Rule {later_id} ({later_name})",
                    "shadowing_rule": f"Rule {earlier_id} ({earlier_name})",
                    "conflict_type": conflict_type,
                    "source_relation": src_rel,
                    "destination_relation": dst_rel,
                    "service_relation": svc_rel,
                    "action_relation": (
                        f"Both {e_action}" if not actions_differ
                        else f"Earlier: {e_action}, Later: {l_action} — CONFLICT"
                    ),
                    "expansion_complete": not incomplete,
                    "result": result,
                },
                "recommendation": (
                    f"Review Rule {later_id} ({later_name}) and confirm whether it is still "
                    "required given its overlap with "
                    f"Rule {earlier_id} ({earlier_name}). If no valid business requirement "
                    "exists, it may be considered for manual cleanup through the approved "
                    "change management process."
                ),
                "rule1_db_id": later_rule.get("id"),
                "rule2_db_id": earlier_rule.get("id"),
            })
            reported = True  # Only report the first (most relevant) shadowing rule

    return findings
