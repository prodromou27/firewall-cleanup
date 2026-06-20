"""Risk scoring for firewall rules."""
from typing import Dict, List, Tuple
from datetime import datetime, timedelta
from app.analysis.normalizer import (
    expand_rule_sources, expand_rule_destinations, expand_rule_services,
    has_any_source, has_any_destination, has_any_service
)
from app.analysis.service_utils import identify_risky_service
from app.analysis.ip_utils import is_any, is_broad_network
from app.config import settings


def score_rule(rule: dict, obj_map: Dict[str, dict]) -> Tuple[int, Dict[str, int]]:
    """
    Calculate risk score for a rule.
    Returns (total_score, {factor: points})
    """
    factors = {}
    total = 0

    def add(key: str, points: int, reason: str = ""):
        nonlocal total
        factors[key] = {"points": points, "reason": reason}
        total += points

    # Any source
    if has_any_source(rule, obj_map):
        add("any_source", settings.risk_any_source, "Rule allows traffic from any source")

    # Any destination
    if has_any_destination(rule, obj_map):
        add("any_destination", settings.risk_any_destination, "Rule allows traffic to any destination")

    # Any service
    if has_any_service(rule, obj_map):
        add("any_service", settings.risk_any_service, "Rule allows any service/port")

    # Compound exposure. The additive weights alone can understate any-to-any
    # policy behavior, so align the numeric score with explicit Critical findings.
    any_src = "any_source" in factors
    any_dst = "any_destination" in factors
    any_svc = "any_service" in factors
    if any_src and any_dst:
        add("any_to_any", 50, "Rule allows traffic from any source to any destination")
    elif (any_src or any_dst) and any_svc:
        add("broad_any_service", 15, "Rule combines broad scope with any service")

    # Risky services
    services = expand_rule_services(rule, obj_map)
    risky_found = set()
    for svc in services:
        label = identify_risky_service(svc)
        if label and label != "Any":
            risky_found.add(label)
    if risky_found:
        add("risky_service", settings.risk_risky_service,
            f"Rule uses risky services: {', '.join(risky_found)}")

    # No logging on allow rule
    action = (rule.get("action") or "").lower()
    if action in ("accept", "allow", "permit") and not rule.get("logging_enabled", True):
        add("no_logging", settings.risk_no_logging, "Allow rule has no logging enabled")

    # Disabled rule
    if not rule.get("enabled", True):
        add("disabled", settings.risk_disabled, "Rule is disabled")

    # No hits in 180 days
    last_hit = rule.get("last_hit")
    if last_hit:
        try:
            if isinstance(last_hit, str):
                last_hit_dt = datetime.fromisoformat(last_hit.replace("Z", "+00:00"))
            else:
                last_hit_dt = last_hit
            if datetime.now(last_hit_dt.tzinfo) - last_hit_dt > timedelta(days=180):
                add("no_hits_180d", settings.risk_no_hits_180d,
                    "Rule has not been used in over 180 days")
        except (ValueError, TypeError):
            pass
    elif rule.get("hit_count") == 0:
        add("zero_hits", settings.risk_no_hits_180d, "Rule has zero hit count")

    # Temporary keywords in name/comment
    name = (rule.get("rule_name") or "").lower()
    comment = (rule.get("comments") or "").lower()
    for keyword in settings.temp_keywords:
        if keyword in name or keyword in comment:
            add("temp_keyword", settings.risk_temp_keyword,
                f"Rule name/comment contains temporary keyword: '{keyword}'")
            break

    # Broad sources (large networks)
    sources = expand_rule_sources(rule, obj_map)
    for src in sources:
        val = src.get("value", "")
        if val and is_broad_network(val, threshold=12):
            add("broad_source", 5, f"Rule source includes very broad network: {val}")
            break

    total = min(total, 100)
    return total, factors


def score_to_severity(score: int) -> str:
    if score >= settings.severity_critical_threshold:
        return "Critical"
    elif score >= settings.severity_high_threshold:
        return "High"
    elif score >= settings.severity_medium_threshold:
        return "Medium"
    elif score >= settings.severity_low_threshold:
        return "Low"
    return "Informational"
