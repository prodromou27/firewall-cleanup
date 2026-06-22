"""Main analysis engine — orchestrates all analyzers."""
from typing import List, Dict, Any
from datetime import datetime, timedelta
from sqlalchemy.orm import Session

from app.models.policy import FirewallPolicy, FirewallRule, FirewallObject, AnalysisRun
from app.models.finding import Finding, FindingComment
from app.analysis.normalizer import (
    build_object_map, expand_rule_sources, expand_rule_destinations,
    expand_rule_services, has_any_source, has_any_destination, has_any_service
)
from app.analysis.duplicate_detector import detect_duplicates
from app.analysis.shadow_detector import detect_shadows
from app.analysis.risk_scorer import score_rule, score_to_severity
from app.analysis.service_utils import identify_risky_service, normalize_service
from app.analysis.ip_utils import is_public_network, is_broad_network
from app.analysis import recommendation_library as _RL
from app.config import settings
from app.security.redaction import redact_secrets
import uuid
import json
import logging

logger = logging.getLogger(__name__)


def run_analysis(policy_id: str, db: Session) -> str:
    """Run full analysis on a policy. Returns analysis run ID."""
    run = AnalysisRun(
        id=str(uuid.uuid4()),
        policy_id=policy_id,
        status="running",
        run_by="engineer",
    )
    db.add(run)
    db.commit()

    try:
        policy = db.query(FirewallPolicy).filter(FirewallPolicy.id == policy_id).first()
        if not policy:
            raise ValueError(f"Policy {policy_id} not found")

        # Clear previous findings (delete child comments first to satisfy FK)
        finding_ids = [row[0] for row in db.query(Finding.id).filter(Finding.policy_id == policy_id).all()]
        if finding_ids:
            db.query(FindingComment).filter(FindingComment.finding_id.in_(finding_ids)).delete(synchronize_session=False)
        db.query(Finding).filter(Finding.policy_id == policy_id).delete(synchronize_session=False)
        db.commit()

        # Load rules and objects
        rules_orm = (
            db.query(FirewallRule)
            .filter(FirewallRule.policy_id == policy_id)
            .order_by(FirewallRule.rule_number)
            .all()
        )
        objects_orm = (
            db.query(FirewallObject)
            .filter(FirewallObject.policy_id == policy_id)
            .all()
        )

        rules = [_rule_to_dict(r) for r in rules_orm]
        objects = [_obj_to_dict(o) for o in objects_orm]

        obj_map = build_object_map(objects)

        # Score all rules and save
        for rule_orm, rule in zip(rules_orm, rules):
            score, factors = score_rule(rule, obj_map)
            rule_orm.risk_score = score
            rule_orm.risk_factors = factors
            rule["risk_score"] = score
            rule["risk_factors"] = factors
        db.commit()

        findings = []

        # 1. Disabled rules
        findings.extend(_analyze_disabled(rules, obj_map))

        # 2. Zero/low hit rules
        findings.extend(_analyze_usage(rules, obj_map))

        # 3. Any source/dest/service
        findings.extend(_analyze_permissive(rules, obj_map))

        # 4. Risky services
        findings.extend(_analyze_risky_services(rules, obj_map))

        # 4b. Sensitive services exposed to untrusted (any / public) sources
        findings.extend(_analyze_exposed_services(rules, obj_map))

        # 4c. Cleartext / unencrypted protocols
        findings.extend(_analyze_cleartext_services(rules, obj_map))

        # 4d. Lateral-movement risk (broad internal segment -> broad internal segment)
        findings.extend(_analyze_lateral_movement(rules, obj_map))

        # 4e. Direct inbound exposure (untrusted source -> internal destination)
        findings.extend(_analyze_inbound_exposure(rules, obj_map))

        # 5. Duplicate rules
        findings.extend(detect_duplicates(rules, obj_map))

        # 6. Shadowed rules
        findings.extend(detect_shadows(rules, obj_map))

        # 6b. Consolidation candidates (same src/dst/action, differing services)
        findings.extend(_analyze_mergeable_rules(rules))

        # 6c. Missing explicit logged cleanup (deny-all) rule (policy-level)
        findings.extend(_analyze_cleanup_rule(rules, obj_map))

        # 6d. Rule-order optimization (busy rules sitting below unused ones)
        findings.extend(_analyze_rule_order(rules))

        # 6e. Oversized rule sections (maintainability)
        findings.extend(_analyze_section_size(rules))

        # 7. No logging
        findings.extend(_analyze_no_logging(rules, obj_map))

        # 8. Temporary rules
        findings.extend(_analyze_temp_rules(rules, obj_map))

        # 9. Unused objects
        findings.extend(_analyze_unused_objects(rules, objects, obj_map))

        # 10. Duplicate objects
        findings.extend(_analyze_duplicate_objects(objects))

        # 11. Rules without documentation (no comments, no owner reference)
        findings.extend(_analyze_no_documentation(rules))

        # 12. Naming quality
        findings.extend(_analyze_naming_quality(rules))

        # 13. Expired / scheduled rules
        findings.extend(_analyze_expired_rules(rules))

        # 14. NAT rule complexity
        findings.extend(_analyze_nat_rules(rules))

        # 15. Broad VPN access
        findings.extend(_analyze_vpn_rules(rules, obj_map))

        # 16. Negated objects
        findings.extend(_analyze_negated_objects(rules))

        # 17. Empty groups
        findings.extend(_analyze_empty_groups(objects))

        # 18. Large groups
        findings.extend(_analyze_large_groups(objects))

        # 19. Broad network objects
        findings.extend(_analyze_broad_networks(objects))

        # 20. Service objects with large port ranges
        findings.extend(_analyze_service_ranges(objects))

        # 21. Import quality summary (parse completeness, hit-data availability)
        findings.extend(_analyze_import_quality(rules, objects, policy))

        # Save findings
        finding_count = 0
        high_count = 0
        for f in findings:
            finding_orm = Finding(
                id=str(uuid.uuid4()),
                policy_id=policy_id,
                analysis_run_id=run.id,
                vendor=policy.vendor,
                finding_type=f["finding_type"],
                severity=f.get("severity", "Informational"),
                confidence=f.get("confidence", "Medium"),
                title=f["title"],
                description=f["description"],
                affected_rules=f.get("affected_rules", []),
                affected_objects=f.get("affected_objects", []),
                evidence=f.get("evidence", {}),
                recommendation=f.get("recommendation", ""),
                status="Review Required",
                risk_score=f.get("risk_score", 0),
            )
            db.add(finding_orm)
            finding_count += 1
            if f.get("severity") in ("High", "Critical"):
                high_count += 1

        policy.finding_count = finding_count
        policy.high_finding_count = high_count
        policy.analysis_status = "completed"
        policy.analysis_error = None

        # --- Compute extended scores ---
        from collections import Counter
        enabled_rules = [r for r in rules if r.get("enabled", True)]
        total_rules = len(rules)

        # ── 12-Factor Rulebase Complexity Index ───────────────────────────────
        # Each factor contributes 0–N raw points; we normalise to 0–100.
        # Higher score = more complex / harder to maintain.
        perm_count     = sum(1 for f in findings if f["finding_type"] == "overly_permissive")
        shadow_count   = sum(1 for f in findings if f["finding_type"] == "shadowed_rule")
        dup_count      = sum(1 for f in findings if f["finding_type"] == "duplicate_rule")
        disabled_count = sum(1 for r in rules if not r.get("enabled", True))
        unused_obj_cnt = sum(1 for f in findings if f["finding_type"] == "unused_object")
        broad_net_cnt  = sum(1 for f in findings if f["finding_type"] == "broad_network")
        large_svc_cnt  = sum(1 for f in findings if f["finding_type"] == "service_range")
        doc_miss       = sum(1 for f in findings if f["finding_type"] == "no_documentation")

        # Factor 3: number of groups and nested groups
        group_objects  = [o for o in objects if "group" in o.get("object_type", "")]
        nested_groups  = sum(
            1 for o in group_objects
            if any(
                "group" in (obj_map.get(m, {}).get("object_type", "")) for m in o.get("members", [])
            )
        )

        # Factor 12: rules older than 2 years (by rule_id containing old year patterns)
        import re as _re_age
        _OLD_YEARS = {str(y) for y in range(2015, 2023)}
        old_rules = sum(
            1 for r in rules
            if any(yr in (r.get("rule_name") or "") or yr in (r.get("comments") or "")
                   for yr in _OLD_YEARS)
        )

        # Weighted raw score (max theoretical = 10+10+8+8+8+8+6+6+6+6+4+4 = 84 pts → norm to 100)
        raw_complexity = (
            min(10, total_rules / 10)       +   # F1: rule count
            min(10, len(objects) / 30)      +   # F2: object count
            min(8,  len(group_objects) / 5) +   # F3: group count
            min(8,  nested_groups * 2)      +   # F4: nested groups
            min(8,  perm_count * 2)         +   # F5: any rules
            min(8,  shadow_count * 2)       +   # F6: shadowed rules
            min(6,  dup_count * 2)          +   # F7: duplicate rules
            min(6,  disabled_count)         +   # F8: disabled rules
            min(6,  unused_obj_cnt / 3)     +   # F9: unused objects
            min(6,  broad_net_cnt * 1.5)    +   # F10: broad networks
            min(4,  large_svc_cnt * 1.5)    +   # F11: large service groups
            min(4,  old_rules)                  # F12: rule age
        )
        complexity_score = min(100, int(raw_complexity / 84 * 100))

        # Store breakdown for UI drill-down
        complexity_breakdown = {
            "rule_count":       {"value": total_rules,          "label": "Total Rules",          "points": round(min(10, total_rules / 10), 1)},
            "object_count":     {"value": len(objects),         "label": "Total Objects",        "points": round(min(10, len(objects) / 30), 1)},
            "group_count":      {"value": len(group_objects),   "label": "Object Groups",        "points": round(min(8, len(group_objects) / 5), 1)},
            "nested_groups":    {"value": nested_groups,        "label": "Nested Groups",        "points": round(min(8, nested_groups * 2), 1)},
            "any_rules":        {"value": perm_count,           "label": "Any-Source/Dest Rules","points": round(min(8, perm_count * 2), 1)},
            "shadowed_rules":   {"value": shadow_count,         "label": "Shadowed Rules",       "points": round(min(8, shadow_count * 2), 1)},
            "duplicate_rules":  {"value": dup_count,            "label": "Duplicate Rules",      "points": round(min(6, dup_count * 2), 1)},
            "disabled_rules":   {"value": disabled_count,       "label": "Disabled Rules",       "points": round(min(6, disabled_count), 1)},
            "unused_objects":   {"value": unused_obj_cnt,       "label": "Unused Objects",       "points": round(min(6, unused_obj_cnt / 3), 1)},
            "broad_networks":   {"value": broad_net_cnt,        "label": "Broad Networks",       "points": round(min(6, broad_net_cnt * 1.5), 1)},
            "large_svc_groups": {"value": large_svc_cnt,        "label": "Large Service Ranges", "points": round(min(4, large_svc_cnt * 1.5), 1)},
            "rule_age":         {"value": old_rules,            "label": "Aged Rules (pre-2023)","points": round(min(4, old_rules), 1)},
        }

        # ── Cleanup readiness ──────────────────────────────────────────────────
        rules_with_hits = sum(1 for r in rules if r.get("hit_count") is not None)
        readiness_score = int(100 * rules_with_hits / max(1, total_rules))

        # ── Health score: inverse risk proxy ─────────────────────────────────
        sev_weights = {"Critical": 18, "High": 10, "Medium": 5, "Low": 2, "Informational": 0}
        total_sev = sum(sev_weights.get(f.get("severity", "Informational"), 0) for f in findings)
        health_score = max(0, 100 - min(100, total_sev))

        # ── Top risk drivers ──────────────────────────────────────────────────
        driver_counts = Counter(f["finding_type"] for f in findings)
        top_risk_drivers = [{"type": t, "count": c} for t, c in driver_counts.most_common(5)]

        policy.complexity_score = complexity_score
        policy.complexity_breakdown = complexity_breakdown
        policy.cleanup_readiness_score = readiness_score
        policy.health_score = health_score
        policy.top_risk_drivers = top_risk_drivers

        run.status = "completed"
        run.completed_at = datetime.utcnow()
        run.findings_created = finding_count
        # Severity snapshot for trend charting (counts at this run's completion).
        _sev_snapshot = Counter(f.get("severity", "Informational") for f in findings)
        run.severity_snapshot = json.dumps(dict(_sev_snapshot))
        _type_snapshot = Counter(f.get("finding_type", "unknown") for f in findings)
        run.finding_type_snapshot = json.dumps(dict(_type_snapshot))

        db.commit()
        logger.info(f"Analysis complete for policy {policy_id}: {finding_count} findings")
        return run.id

    except Exception as e:
        safe_error = redact_secrets(e)
        logger.error("Analysis failed for policy %s: %s", policy_id, safe_error, exc_info=True)
        run.status = "failed"
        run.error = safe_error
        if 'policy' in dir():
            policy.analysis_status = "failed"
            policy.analysis_error = safe_error
        db.commit()
        raise


def _rule_to_dict(r: FirewallRule) -> dict:
    return {
        "id": r.id,
        "rule_id": r.rule_id,
        "rule_uid": r.rule_uid,
        "rule_number": r.rule_number,
        "rule_name": r.rule_name,
        "section": r.section,
        "source_interfaces": r.source_interfaces or [],
        "destination_interfaces": r.destination_interfaces or [],
        "sources": r.sources or [],
        "destinations": r.destinations or [],
        "services": r.services or [],
        "applications": r.applications or [],
        "action": r.action,
        "schedule": r.schedule,
        "enabled": r.enabled,
        "logging_enabled": r.logging_enabled,
        "nat_enabled": r.nat_enabled,
        "comments": r.comments,
        "hit_count": r.hit_count,
        "last_hit": r.last_hit,
        "first_hit": r.first_hit,
    }


def _obj_to_dict(o: FirewallObject) -> dict:
    return {
        "id": o.id,
        "vendor": o.vendor,
        "object_name": o.object_name,
        "object_type": o.object_type,
        "value": o.value,
        "protocol": o.protocol,
        "port_start": o.port_start,
        "port_end": o.port_end,
        "members": o.members or [],
        "raw_data": o.raw_data or {},
    }



def _analyze_disabled(rules: List[dict], obj_map: dict) -> List[dict]:
    findings = []
    for rule in rules:
        if not rule.get("enabled", True):
            rule_id = rule.get("rule_id") or rule.get("rule_number", "?")
            rule_name = rule.get("rule_name") or f"Rule {rule_id}"
            last_hit = rule.get("last_hit")
            last_hit_str = f" Last hit: {last_hit}." if last_hit else " No hit count data available."
            findings.append({
                "finding_type": "disabled_rule",
                "severity": "Low",
                "confidence": "High",
                "title": f"Rule {rule_id} is disabled",
                "description": (
                    f"{rule_name} is currently disabled and will not process any traffic."
                    + last_hit_str +
                    " Disabled rules add complexity to the policy without providing security value."
                ),
                "affected_rules": [rule.get("id")],
                "evidence": {
                    "rule_id": rule_id,
                    "rule_name": rule_name,
                    "enabled": False,
                    "last_hit": last_hit,
                },
                "recommendation": _RL.get("disabled_rule"),
            })
    return findings


def _analyze_usage(rules: List[dict], obj_map: dict) -> List[dict]:
    findings = []
    now = datetime.utcnow()

    for rule in rules:
        if not rule.get("enabled", True):
            continue

        hit_count = rule.get("hit_count")
        last_hit = rule.get("last_hit")
        rule_id = rule.get("rule_id") or rule.get("rule_number", "?")
        rule_name = rule.get("rule_name") or f"Rule {rule_id}"

        if hit_count == 0:
            findings.append({
                "finding_type": "zero_hit_rule",
                "severity": "Medium",
                "confidence": "High",
                "title": f"Rule {rule_id} has zero hits",
                "description": (
                    f"{rule_name} has a recorded hit count of zero. This rule has never "
                    "matched any traffic, which may indicate it is redundant or incorrectly configured."
                ),
                "affected_rules": [rule.get("id")],
                "evidence": {"rule_id": rule_id, "hit_count": 0},
                "recommendation": _RL.get("zero_hit_rule"),
            })
        elif last_hit:
            try:
                lh = datetime.fromisoformat(str(last_hit).replace("Z", ""))
                days_inactive = (now - lh).days
                threshold = None
                if days_inactive >= settings.inactivity_threshold_high:
                    threshold = settings.inactivity_threshold_high
                    severity = "Medium"
                elif days_inactive >= settings.inactivity_threshold_medium:
                    threshold = settings.inactivity_threshold_medium
                    severity = "Low"
                elif days_inactive >= settings.inactivity_threshold_low:
                    threshold = settings.inactivity_threshold_low
                    severity = "Low"

                if threshold:
                    findings.append({
                        "finding_type": "low_usage_rule",
                        "severity": severity,
                        "confidence": "High",
                        "title": f"Rule {rule_id} has not been used in {days_inactive} days",
                        "description": (
                            f"{rule_name} has not matched any traffic in {days_inactive} days "
                            f"(last hit: {last_hit}). Rules with low usage may be candidates "
                            "for review or removal."
                        ),
                        "affected_rules": [rule.get("id")],
                        "evidence": {
                            "rule_id": rule_id,
                            "last_hit": str(last_hit),
                            "days_inactive": days_inactive,
                            "hit_count": hit_count,
                        },
                        "recommendation": _RL.get("low_usage_rule"),
                    })
            except (ValueError, TypeError):
                pass

    return findings


def _analyze_permissive(rules: List[dict], obj_map: dict) -> List[dict]:
    findings = []
    for rule in rules:
        if not rule.get("enabled", True):
            continue
        action = (rule.get("action") or "").lower()
        if action not in ("accept", "allow", "permit"):
            continue

        rule_id = rule.get("rule_id") or rule.get("rule_number", "?")
        rule_name = rule.get("rule_name") or f"Rule {rule_id}"

        any_src = has_any_source(rule, obj_map)
        any_dst = has_any_destination(rule, obj_map)
        any_svc = has_any_service(rule, obj_map)

        issues = []
        if any_src:
            issues.append("any source")
        if any_dst:
            issues.append("any destination")
        if any_svc:
            issues.append("any service")

        if issues:
            # Severity reflects how much access the rule actually grants:
            #  - Any source AND Any destination AND Any service = allow-everything → Critical
            #  - Any source AND Any destination (any-to-any) → Critical
            #  - Any source/dest combined with Any service → High
            #  - Any source OR Any destination alone → High
            #  - Any service only (with specific src/dst) → Medium
            if any_src and any_dst:
                severity = "Critical"
            elif (any_src or any_dst) and any_svc:
                severity = "High"
            elif any_src or any_dst:
                severity = "High"
            else:
                severity = "Medium"

            sev_phrase = {
                "Critical": (
                    "This is effectively an any-to-any allow rule, which grants the "
                    "broadest possible access and represents a significant security risk."
                ),
                "High": (
                    "Overly broad rules significantly increase the attack surface and "
                    "make the policy harder to audit and maintain."
                ),
                "Medium": (
                    "Overly broad services increase the attack surface and should be "
                    "restricted to the minimum required ports."
                ),
            }[severity]

            findings.append({
                "finding_type": "overly_permissive",
                "severity": severity,
                "confidence": "High",
                "title": f"Rule {rule_id} is overly permissive ({', '.join(issues)})",
                "description": (
                    f"{rule_name} uses {', '.join(issues)}. " + sev_phrase
                ),
                "affected_rules": [rule.get("id")],
                "evidence": {
                    "rule_id": rule_id,
                    "any_source": any_src,
                    "any_destination": any_dst,
                    "any_service": any_svc,
                    "action": rule.get("action"),
                },
                "recommendation": _RL.get("overly_permissive"),
            })

    return findings


def _analyze_risky_services(rules: List[dict], obj_map: dict) -> List[dict]:
    findings = []
    for rule in rules:
        if not rule.get("enabled", True):
            continue
        action = (rule.get("action") or "").lower()
        if action not in ("accept", "allow", "permit"):
            continue

        services = expand_rule_services(rule, obj_map)
        risky = {}
        for svc in services:
            label = identify_risky_service(svc)
            if label and label != "Any":
                risky[label] = svc

        if not risky:
            continue

        rule_id = rule.get("rule_id") or rule.get("rule_number", "?")
        rule_name = rule.get("rule_name") or f"Rule {rule_id}"

        # Broadly exposed risky service (any source or any destination) is High;
        # a risky service from/to a restricted scope is Medium.
        broadly_exposed = has_any_source(rule, obj_map) or has_any_destination(rule, obj_map)
        severity = "High" if broadly_exposed else "Medium"
        exposure_note = (
            " This rule exposes the risky service broadly (any source or any "
            "destination), which substantially increases the risk."
            if broadly_exposed else ""
        )

        findings.append({
            "finding_type": "risky_service",
            "severity": severity,
            "confidence": "High",
            "title": f"Rule {rule_id} uses risky service(s): {', '.join(risky.keys())}",
            "description": (
                f"{rule_name} allows traffic on services considered risky: "
                f"{', '.join(risky.keys())}. These services may expose sensitive "
                "systems to attack if access is not properly restricted." + exposure_note
            ),
            "affected_rules": [rule.get("id")],
            "evidence": {
                "rule_id": rule_id,
                "risky_services": list(risky.keys()),
                "action": rule.get("action"),
                "sources": rule.get("sources", []),
                "destinations": rule.get("destinations", []),
            },
            "recommendation": _RL.get("risky_service"),
        })

    return findings


# Sensitive TCP services that should never be reachable from untrusted networks,
# mapped to the finding type used for their curated recommendation.
_EXPOSED_PORTS = {
    3389: ("RDP", "rdp_exposed"),
    22:   ("SSH", "ssh_exposed"),
    1433: ("Microsoft SQL Server", "database_exposed"),
    1521: ("Oracle DB", "database_exposed"),
    3306: ("MySQL", "database_exposed"),
    5432: ("PostgreSQL", "database_exposed"),
}


def _untrusted_source(rule: dict, obj_map: dict):
    """Classify a rule's source exposure.

    Returns a tuple (exposure, public_sources):
      exposure == "any"    → source is any/0.0.0.0/0 (the entire internet)
      exposure == "public" → source resolves to specific public network(s)
      exposure is None     → source is internal/private only
    """
    if has_any_source(rule, obj_map):
        return "any", []
    public = [
        s.get("value")
        for s in expand_rule_sources(rule, obj_map)
        if s.get("value") and is_public_network(s.get("value"))
    ]
    if public:
        return "public", public
    return None, []


def _analyze_exposed_services(rules: List[dict], obj_map: dict) -> List[dict]:
    """Detect allow rules that expose RDP/SSH/database services to untrusted sources."""
    findings = []
    for rule in rules:
        action = (rule.get("action") or "").lower()
        if action not in ("accept", "allow", "permit"):
            continue
        if not rule.get("enabled", True):
            continue

        exposure, public_srcs = _untrusted_source(rule, obj_map)
        if exposure is None:
            continue

        # Group matched service labels by finding type (one finding per type per rule).
        matched: Dict[str, set] = {}
        for svc in expand_rule_services(rule, obj_map):
            n = normalize_service(svc)
            if n["protocol"] not in ("tcp", "any"):
                continue
            for port, (label, ftype) in _EXPOSED_PORTS.items():
                if n["port_start"] <= port <= n["port_end"]:
                    matched.setdefault(ftype, set()).add(label)
        if not matched:
            continue

        rule_id = rule.get("rule_id") or rule.get("rule_number", "?")
        rule_name = rule.get("rule_name") or f"Rule {rule_id}"
        src_desc = (
            "any source (the entire internet)"
            if exposure == "any"
            else f"public source network(s): {', '.join(public_srcs)}"
        )

        for ftype, labels in matched.items():
            svc_list = ", ".join(sorted(labels))
            # SSH is at least encrypted; RDP/database exposure is more severe.
            if ftype == "ssh_exposed":
                severity = "High"
            else:
                severity = "Critical" if exposure == "any" else "High"
            findings.append({
                "finding_type": ftype,
                "severity": severity,
                "confidence": "High",
                "title": f"Rule {rule_id} exposes {svc_list} to an untrusted source",
                "description": (
                    f"{rule_name} permits {svc_list} from {src_desc}. Exposing "
                    "administrative or database services to untrusted networks significantly "
                    "increases the attack surface and is a common initial-access vector."
                ),
                "affected_rules": [rule.get("id")],
                "evidence": {
                    "rule_id": rule_id,
                    "exposed_services": sorted(labels),
                    "exposure": exposure,
                    "sources": rule.get("sources", []),
                    "destinations": rule.get("destinations", []),
                    "services": rule.get("services", []),
                },
                "recommendation": _RL.get(ftype),
            })
    return findings


# Cleartext protocols that transmit data/credentials without encryption, mapped
# to (protocol, display name, encrypted alternative).
_CLEARTEXT_PORTS = {
    21:  ("tcp", "FTP", "SFTP or FTPS"),
    23:  ("tcp", "Telnet", "SSH"),
    69:  ("udp", "TFTP", "SCP/SFTP"),
    110: ("tcp", "POP3", "POP3S (TLS)"),
    143: ("tcp", "IMAP", "IMAPS (TLS)"),
    161: ("udp", "SNMP v1/v2", "SNMPv3"),
    389: ("tcp", "LDAP", "LDAPS (TLS)"),
    512: ("tcp", "rexec", "SSH"),
    513: ("tcp", "rlogin", "SSH"),
    514: ("tcp", "rsh", "SSH"),
}


def _analyze_cleartext_services(rules: List[dict], obj_map: dict) -> List[dict]:
    """Detect allow rules permitting unencrypted (cleartext) protocols."""
    findings = []
    for rule in rules:
        action = (rule.get("action") or "").lower()
        if action not in ("accept", "allow", "permit"):
            continue
        if not rule.get("enabled", True):
            continue

        matched = {}  # name -> alternative
        for svc in expand_rule_services(rule, obj_map):
            n = normalize_service(svc)
            proto = n["protocol"]
            for port, (p_proto, name, alt) in _CLEARTEXT_PORTS.items():
                if proto not in (p_proto, "any"):
                    continue
                if n["port_start"] <= port <= n["port_end"]:
                    matched[name] = alt
        if not matched:
            continue

        # Broad exposure raises the stakes for an unencrypted protocol.
        broad = has_any_source(rule, obj_map)
        severity = "High" if broad else "Medium"
        rule_id = rule.get("rule_id") or rule.get("rule_number", "?")
        rule_name = rule.get("rule_name") or f"Rule {rule_id}"
        svc_list = ", ".join(sorted(matched.keys()))
        alts = ", ".join(sorted(set(matched.values())))

        findings.append({
            "finding_type": "cleartext_service",
            "severity": severity,
            "confidence": "High",
            "title": f"Rule {rule_id} permits cleartext protocol(s): {svc_list}",
            "description": (
                f"{rule_name} allows {svc_list}, which transmit data and credentials "
                "without encryption and can be intercepted on the network path."
                + (" The rule also uses an any source, broadening the exposure." if broad else "")
                + f" Consider migrating to an encrypted equivalent ({alts})."
            ),
            "affected_rules": [rule.get("id")],
            "evidence": {
                "rule_id": rule_id,
                "cleartext_services": sorted(matched.keys()),
                "any_source": broad,
                "services": rule.get("services", []),
            },
            "recommendation": _RL.get("cleartext_service"),
        })
    return findings


_DENY_ACTIONS = {"deny", "drop", "reject", "block"}

# Prefix length at or below which an internal network is considered "broad"
# (e.g. /16 covers 65k hosts). Tunable.
_BROAD_INTERNAL_PREFIX = 16


def _broad_internal_addrs(expanded: List[dict]) -> List[str]:
    """Return the values among expanded addresses that are broad PRIVATE
    networks (large internal supernets). Public ranges and 'any' are excluded —
    'any' is handled by the overly-permissive detector.
    """
    out = []
    for a in expanded:
        if a.get("type") in ("any", "unknown", "empty_group"):
            continue
        v = a.get("value", "")
        if not v or is_public_network(v):
            continue
        if is_broad_network(v, _BROAD_INTERNAL_PREFIX):
            out.append(v)
    return out


def _analyze_lateral_movement(rules: List[dict], obj_map: dict) -> List[dict]:
    """Detect allow rules permitting traffic between two broad internal segments
    (east-west), which enables lateral movement if a source host is compromised.
    """
    findings = []
    for rule in rules:
        action = (rule.get("action") or "").lower()
        if action not in ("accept", "allow", "permit"):
            continue
        if not rule.get("enabled", True):
            continue

        broad_src = _broad_internal_addrs(expand_rule_sources(rule, obj_map))
        broad_dst = _broad_internal_addrs(expand_rule_destinations(rule, obj_map))
        if not broad_src or not broad_dst:
            continue

        any_svc = has_any_service(rule, obj_map)
        severity = "High" if any_svc else "Medium"
        rule_id = rule.get("rule_id") or rule.get("rule_number", "?")
        rule_name = rule.get("rule_name") or f"Rule {rule_id}"
        svc_note = (
            " The rule also permits any service, so all ports are reachable across these "
            "segments." if any_svc else ""
        )
        findings.append({
            "finding_type": "lateral_movement_risk",
            "severity": severity,
            "confidence": "Medium",
            "title": f"Rule {rule_id} permits broad east-west traffic between internal segments",
            "description": (
                f"{rule_name} allows traffic from broad internal network(s) "
                f"({', '.join(broad_src)}) to broad internal network(s) "
                f"({', '.join(broad_dst)}). Wide internal-to-internal access lets an "
                "attacker move laterally across the environment after compromising any "
                "host in the source range." + svc_note
            ),
            "affected_rules": [rule.get("id")],
            "evidence": {
                "rule_id": rule_id,
                "broad_sources": broad_src,
                "broad_destinations": broad_dst,
                "any_service": any_svc,
            },
            "recommendation": _RL.get("lateral_movement_risk"),
        })
    return findings


# Rule-order optimization thresholds (tunable).
_BUSY_HIT_THRESHOLD = 1000      # a rule is "busy" at/above this hit count
_ZERO_ABOVE_THRESHOLD = 10      # flag if this many zero-hit rules sit above it
_MAX_REORDER_FINDINGS = 10      # cap per policy to avoid flooding

# Maintainability threshold for a single policy section (Tufin guidance).
_MAX_SECTION_RULES = 20


def _analyze_rule_order(rules: List[dict]) -> List[dict]:
    """Performance optimization: flag busy rules positioned below many zero-hit
    rules. Read-only — recommends manual reordering. Skips entirely when hit
    data is not available.
    """
    enabled = [r for r in rules if r.get("enabled", True) and r.get("hit_count") is not None]
    if len(enabled) < 5:
        return []  # too little hit data to draw a conclusion

    ordered = sorted(enabled, key=lambda r: (r.get("rule_number") or 0))
    findings = []
    zero_above = 0
    for r in ordered:
        hits = r.get("hit_count") or 0
        if hits >= _BUSY_HIT_THRESHOLD and zero_above >= _ZERO_ABOVE_THRESHOLD:
            rule_id = r.get("rule_id") or r.get("rule_number", "?")
            rule_name = r.get("rule_name") or f"Rule {rule_id}"
            findings.append({
                "finding_type": "rule_order_optimization",
                "severity": "Low",
                "confidence": "Medium",
                "title": f"Rule {rule_id} is heavily used but sits below {zero_above} unused rules",
                "description": (
                    f"{rule_name} has {hits:,} hits but is positioned below {zero_above} "
                    "enabled rules that currently receive no traffic. Because firewalls "
                    "evaluate rules top-to-bottom, promoting frequently-matched rules above "
                    "unused ones reduces per-packet evaluation overhead."
                ),
                "affected_rules": [r.get("id")],
                "evidence": {
                    "rule_id": rule_id,
                    "hit_count": hits,
                    "zero_hit_rules_above": zero_above,
                },
                "recommendation": _RL.get("rule_order_optimization"),
            })
        if hits == 0:
            zero_above += 1
    # Report the most impactful reorder candidates first.
    findings.sort(key=lambda f: -f["evidence"]["hit_count"])
    return findings[:_MAX_REORDER_FINDINGS]


def _analyze_section_size(rules: List[dict]) -> List[dict]:
    """Maintainability: flag policy sections that exceed the recommended size."""
    counts: Dict[str, int] = {}
    for r in rules:
        section = (r.get("section") or "").strip()
        if not section:
            continue
        counts[section] = counts.get(section, 0) + 1

    findings = []
    for section, count in counts.items():
        if count <= _MAX_SECTION_RULES:
            continue
        findings.append({
            "finding_type": "large_rule_section",
            "severity": "Informational",
            "confidence": "High",
            "title": f"Section '{section}' has {count} rules (recommended ≤ {_MAX_SECTION_RULES})",
            "description": (
                f"The '{section}' section contains {count} rules. Large sections are harder "
                "to read, audit, and troubleshoot; industry guidance recommends keeping "
                f"sections to roughly {_MAX_SECTION_RULES} rules or fewer."
            ),
            "affected_rules": [],
            "evidence": {"section": section, "rule_count": count, "recommended_max": _MAX_SECTION_RULES},
            "recommendation": _RL.get("large_rule_section"),
        })
    return findings


def _analyze_mergeable_rules(rules: List[dict]) -> List[dict]:
    """Detect consolidation candidates: enabled rules that share action, source
    set, and destination set but differ in services (mergeable via a service
    group). Exact duplicates (identical services too) are left to the duplicate
    detector — a group only qualifies here if its services actually vary.
    """
    findings = []
    groups: Dict[tuple, List[dict]] = {}
    for rule in rules:
        if not rule.get("enabled", True):
            continue
        action = (rule.get("action") or "").lower()
        src_key = tuple(sorted(rule.get("sources", []) or []))
        dst_key = tuple(sorted(rule.get("destinations", []) or []))
        # Skip rules with no addressing info to avoid grouping empties together.
        if not src_key and not dst_key:
            continue
        groups.setdefault((action, src_key, dst_key), []).append(rule)

    for (action, src_key, dst_key), members in groups.items():
        if len(members) < 2:
            continue
        # Require genuine service variety (otherwise it's a pure duplicate set).
        svc_sets = {tuple(sorted(m.get("services", []) or [])) for m in members}
        if len(svc_sets) < 2:
            continue

        rule_ids = [m.get("rule_id") or m.get("rule_number", "?") for m in members]
        all_services = sorted({s for m in members for s in (m.get("services", []) or [])})
        findings.append({
            "finding_type": "mergeable_rules",
            "severity": "Low",
            "confidence": "High",
            "title": f"{len(members)} rules can likely be consolidated (Rules {', '.join(str(r) for r in rule_ids)})",
            "description": (
                f"Rules {', '.join(str(r) for r in rule_ids)} share the same action "
                f"('{action or 'n/a'}'), source, and destination but use different "
                "services. They can typically be merged into a single rule using a "
                "service group, reducing policy size and maintenance overhead."
            ),
            "affected_rules": [m.get("id") for m in members],
            "evidence": {
                "rule_ids": [str(r) for r in rule_ids],
                "action": action,
                "shared_sources": list(src_key),
                "shared_destinations": list(dst_key),
                "combined_services": all_services,
            },
            "recommendation": _RL.get("mergeable_rules"),
        })
    return findings


def _analyze_cleanup_rule(rules: List[dict], obj_map: dict) -> List[dict]:
    """Policy-level: flag when there is no explicit, logged final deny-all rule.

    A 'cleanup rule' is an explicit deny/drop of any→any (all services). Without
    one, denied traffic falls through to the implicit default-deny and is not
    logged — a monitoring blind spot.
    """
    enabled = [r for r in rules if r.get("enabled", True)]
    if not enabled:
        return []

    def _is_deny_all(rule: dict) -> bool:
        action = (rule.get("action") or "").lower()
        if action not in _DENY_ACTIONS:
            return False
        return (
            has_any_source(rule, obj_map)
            and has_any_destination(rule, obj_map)
            and has_any_service(rule, obj_map)
        )

    cleanup_rules = [r for r in enabled if _is_deny_all(r)]
    if cleanup_rules:
        # An explicit cleanup rule exists. If none of them log, recommend logging.
        if any(r.get("logging_enabled", False) for r in cleanup_rules):
            return []
        cr = cleanup_rules[-1]
        rid = cr.get("rule_id") or cr.get("rule_number", "?")
        return [{
            "finding_type": "no_cleanup_rule",
            "severity": "Low",
            "confidence": "High",
            "title": "Cleanup (deny-all) rule does not log dropped traffic",
            "description": (
                f"The policy has an explicit deny-all rule (Rule {rid}) but it does not "
                "have logging enabled, so dropped connections are not recorded. This "
                "creates a visibility gap for security monitoring and incident response."
            ),
            "affected_rules": [cr.get("id")],
            "evidence": {"cleanup_rule_id": str(rid), "logging_enabled": False},
            "recommendation": _RL.get("no_cleanup_rule"),
        }]

    return [{
        "finding_type": "no_cleanup_rule",
        "severity": "Medium",
        "confidence": "High",
        "title": "Policy has no explicit cleanup (deny-all) rule",
        "description": (
            "This policy contains no explicit final deny-all rule. Denied traffic relies "
            "on the implicit default-deny, which on most platforms is not logged — leaving "
            "no record of blocked connection attempts for security monitoring or incident "
            "response."
        ),
        "affected_rules": [],
        "evidence": {"enabled_rule_count": len(enabled), "explicit_cleanup_rule": False},
        "recommendation": _RL.get("no_cleanup_rule"),
    }]


def _internal_dest_addrs(expanded: List[dict]) -> List[str]:
    """Return concrete internal (private, non-'any') destination values."""
    out = []
    for a in expanded:
        if a.get("type") in ("any", "unknown", "empty_group"):
            continue
        v = a.get("value", "")
        if not v or is_public_network(v):
            continue
        out.append(v)
    return out


def _analyze_inbound_exposure(rules: List[dict], obj_map: dict) -> List[dict]:
    """Detect allow rules permitting traffic from an untrusted source (internet /
    public) directly to an internal destination — the core NIST SP 800-41 / PCI
    DSS inbound-exposure concern. Distinct from exposed_services (specific
    sensitive ports) and overly_permissive (any/any).
    """
    findings = []
    for rule in rules:
        action = (rule.get("action") or "").lower()
        if action not in ("accept", "allow", "permit"):
            continue
        if not rule.get("enabled", True):
            continue

        exposure, public_srcs = _untrusted_source(rule, obj_map)
        if exposure is None:
            continue
        internal_dsts = _internal_dest_addrs(expand_rule_destinations(rule, obj_map))
        if not internal_dsts:
            continue

        any_svc = has_any_service(rule, obj_map)
        severity = "Critical" if any_svc else "High"
        rule_id = rule.get("rule_id") or rule.get("rule_number", "?")
        rule_name = rule.get("rule_name") or f"Rule {rule_id}"
        src_desc = (
            "any source (the entire internet)" if exposure == "any"
            else f"public source(s) {', '.join(public_srcs)}"
        )
        svc_note = (
            " The rule permits any service, so every port on the internal target is "
            "reachable from the internet." if any_svc else ""
        )
        findings.append({
            "finding_type": "inbound_from_internet",
            "severity": severity,
            "confidence": "Medium",
            "title": f"Rule {rule_id} allows direct inbound access from the internet to an internal host",
            "description": (
                f"{rule_name} permits inbound traffic from {src_desc} directly to internal "
                f"destination(s) ({', '.join(internal_dsts)}). Direct internet-to-internal "
                "access is a primary attack surface; standards require it to be justified, "
                "minimal, and ideally terminated in a DMZ." + svc_note
            ),
            "affected_rules": [rule.get("id")],
            "evidence": {
                "rule_id": rule_id,
                "exposure": exposure,
                "public_sources": public_srcs,
                "internal_destinations": internal_dsts,
                "any_service": any_svc,
            },
            "recommendation": _RL.get("inbound_from_internet"),
        })
    return findings


def _analyze_no_logging(rules: List[dict], obj_map: dict) -> List[dict]:
    findings = []
    for rule in rules:
        action = (rule.get("action") or "").lower()
        if action not in ("accept", "allow", "permit"):
            continue
        if not rule.get("logging_enabled", True):
            rule_id = rule.get("rule_id") or rule.get("rule_number", "?")
            rule_name = rule.get("rule_name") or f"Rule {rule_id}"
            findings.append({
                "finding_type": "no_logging",
                "severity": "Low",
                "confidence": "High",
                "title": f"Rule {rule_id} has logging disabled",
                "description": (
                    f"{rule_name} is an allow rule with logging disabled. "
                    "Without logging, traffic allowed by this rule will not be visible "
                    "for troubleshooting, auditing, or security monitoring."
                ),
                "affected_rules": [rule.get("id")],
                "evidence": {"rule_id": rule_id, "logging_enabled": False},
                "recommendation": _RL.get("no_logging"),
            })
    return findings


def _analyze_temp_rules(rules: List[dict], obj_map: dict) -> List[dict]:
    findings = []
    for rule in rules:
        name = (rule.get("rule_name") or "").lower()
        comment = (rule.get("comments") or "").lower()
        matched_keyword = None
        for kw in settings.temp_keywords:
            if kw in name or kw in comment:
                matched_keyword = kw
                break
        if matched_keyword:
            rule_id = rule.get("rule_id") or rule.get("rule_number", "?")
            rule_name = rule.get("rule_name") or f"Rule {rule_id}"
            findings.append({
                "finding_type": "temporary_rule",
                "severity": "Medium",
                "confidence": "Medium",
                "title": f"Rule {rule_id} appears to be a temporary rule",
                "description": (
                    f"{rule_name} contains the keyword '{matched_keyword}' in its name or "
                    "comment, suggesting it may have been created as a temporary rule. "
                    "Temporary rules that remain active can increase policy complexity and risk."
                ),
                "affected_rules": [rule.get("id")],
                "evidence": {
                    "rule_id": rule_id,
                    "rule_name": rule.get("rule_name"),
                    "matched_keyword": matched_keyword,
                    "comments": rule.get("comments"),
                },
                "recommendation": _RL.get("temporary_rule"),
            })
    return findings


def _analyze_unused_objects(
    rules: List[dict], objects: List[dict], obj_map: dict
) -> List[dict]:
    findings = []

    # Collect all object names referenced by rules
    used_names = set()
    reference_fields = (
        "sources", "destinations", "services", "applications", "users", "vpn",
        "source_interfaces", "destination_interfaces", "install_on",
    )
    for rule in rules:
        for field in reference_fields:
            for ref in rule.get(field, []) or []:
                if isinstance(ref, str):
                    used_names.add(ref)

    # Also include members of used groups
    def collect_members(name: str, visited: set):
        if name in visited:
            return
        visited.add(name)
        obj = obj_map.get(name)
        if obj and _is_group_object(obj):
            for m in obj.get("members", []):
                used_names.add(m)
                collect_members(m, visited)

    for name in list(used_names):
        collect_members(name, set())

    for obj in objects:
        name = obj.get("object_name", "")
        if name.lower() in ("any", "all"):
            continue
        # Skip all service/port objects — type-based, vendor-agnostic filter.
        if _is_service_object(obj):
            continue
        # Skip vendor built-in / predefined objects; customers cannot remove them.
        if _is_vendor_builtin_object(obj):
            continue
        if name not in used_names:
            findings.append({
                "finding_type": "unused_object",
                "severity": "Informational",
                "confidence": "Medium",
                "title": f"Object '{name}' appears unused",
                "description": (
                    f"The object '{name}' ({obj.get('object_type', 'unknown')}: "
                    f"{obj.get('value', 'N/A')}) is not referenced by any firewall rule "
                    "in this policy. Unused objects add clutter to the object database."
                ),
                "affected_rules": [],
                "affected_objects": [obj.get("id")],
                "evidence": {
                    "object_name": name,
                    "object_type": obj.get("object_type"),
                    "value": obj.get("value"),
                    "members": obj.get("members"),
                },
                "recommendation": _RL.get("unused_object"),
            })

    return findings


def _analyze_duplicate_objects(objects: List[dict]) -> List[dict]:
    findings = []
    # Group non-group objects by normalized value
    value_map: Dict[str, List[dict]] = {}
    for obj in objects:
        if _is_group_object(obj):
            continue
        if _is_vendor_builtin_object(obj):
            continue
        val = (obj.get("value") or "").strip().lower()
        if not val or val in ("any", "all"):
            continue
        if val not in value_map:
            value_map[val] = []
        value_map[val].append(obj)

    for val, objs in value_map.items():
        if len(objs) < 2:
            continue
        names = [o.get("object_name") for o in objs]
        findings.append({
            "finding_type": "duplicate_object",
            "severity": "Low",
            "confidence": "High",
            "title": f"Duplicate objects with value '{val}': {', '.join(names)}",
            "description": (
                f"The following objects share the same value ({val}) but have different names: "
                f"{', '.join(names)}. Duplicate objects increase policy complexity and can "
                "cause inconsistencies."
            ),
            "affected_rules": [],
            "affected_objects": [o.get("id") for o in objs],
            "evidence": {
                "value": val,
                "object_names": names,
                "object_types": [o.get("object_type") for o in objs],
            },
            "recommendation": _RL.get("duplicate_object"),
        })

    return findings


def _analyze_no_documentation(rules: List[dict]) -> List[dict]:
    """Find enabled allow rules with no comments or documentation."""
    _TEMP_KEYWORDS = {
        "temp", "temporary", "test", "migration", "old", "legacy",
        "workaround", "vendor", "emergency", "troubleshoot", "to be removed",
        "tbd", "todo", "fixme",
    }
    findings = []
    for rule in rules:
        if not rule.get("enabled", True):
            continue
        action = (rule.get("action") or "").lower()
        if action not in ("accept", "allow", "permit"):
            continue

        comments = (rule.get("comments") or "").strip()
        rule_id = rule.get("rule_id") or rule.get("rule_number", "?")
        rule_name = rule.get("rule_name") or f"Rule {rule_id}"

        # Skip rules that have some form of documentation
        if len(comments) >= 10:
            # Check if it looks like a real comment (not just numbers/whitespace)
            if any(c.isalpha() for c in comments):
                continue

        findings.append({
            "finding_type": "no_documentation",
            "severity": "Informational",
            "confidence": "High",
            "title": f"Rule {rule_id} has no documentation",
            "description": (
                f"{rule_name} is an enabled allow rule with no comment, owner reference, "
                "or business justification. Undocumented rules make it difficult to determine "
                "whether access is still required or approved."
            ),
            "affected_rules": [rule.get("id")],
            "evidence": {
                "rule_id": rule_id,
                "rule_name": rule_name,
                "comments": comments or None,
                "action": rule.get("action"),
            },
            "recommendation": _RL.get("no_documentation"),
        })
    return findings


# ─── New analyzers (12-20) ───────────────────────────────────────────────────

_VAGUE_NAME_KEYWORDS = {
    "test", "allow", "old", "vendor", "rule", "new rule", "new", "temp",
    "policy", "access", "permit", "any", "default", "unnamed", "noname",
    "tbd", "todo", "fixme", "legacy", "migration", "change", "cr", "ticket",
}


def _analyze_naming_quality(rules: List[dict]) -> List[dict]:
    """Detect rules with vague, generic, or missing names."""
    findings = []
    for rule in rules:
        rule_id = rule.get("rule_id") or rule.get("rule_number", "?")
        name = (rule.get("rule_name") or "").strip()

        if not name:
            findings.append({
                "finding_type": "naming_quality",
                "severity": "Informational",
                "confidence": "High",
                "title": f"Rule {rule_id} has no name",
                "description": (
                    f"Rule {rule_id} has no descriptive name. Unnamed rules are difficult "
                    "to identify during audits and change reviews."
                ),
                "affected_rules": [rule.get("id")],
                "evidence": {"rule_id": rule_id, "rule_name": None},
                "recommendation": _RL.get("naming_quality"),
            })
        elif name.lower() in _VAGUE_NAME_KEYWORDS or len(name) < 4:
            findings.append({
                "finding_type": "naming_quality",
                "severity": "Informational",
                "confidence": "Medium",
                "title": f"Rule {rule_id} has a vague name: '{name}'",
                "description": (
                    f"Rule {rule_id} has a generic or vague name ('{name}'). "
                    "Non-descriptive names make policy review and audit significantly harder."
                ),
                "affected_rules": [rule.get("id")],
                "evidence": {"rule_id": rule_id, "rule_name": name},
                "recommendation": _RL.get("naming_quality"),
            })
    return findings


_SCHEDULE_EXPIRED_KEYWORDS = {
    "expired", "expire", "end", "past", "old", "archive", "2020", "2021",
    "2022", "2019", "2018", "2017",
}


def _analyze_expired_rules(rules: List[dict]) -> List[dict]:
    """Detect rules with schedules that appear expired or time-limited."""
    findings = []
    for rule in rules:
        schedule = (rule.get("schedule") or "").strip()
        if not schedule:
            continue
        schedule_lower = schedule.lower()
        matched = next(
            (kw for kw in _SCHEDULE_EXPIRED_KEYWORDS if kw in schedule_lower), None
        )
        if matched:
            rule_id = rule.get("rule_id") or rule.get("rule_number", "?")
            rule_name = rule.get("rule_name") or f"Rule {rule_id}"
            findings.append({
                "finding_type": "expired_rule",
                "severity": "Medium",
                "confidence": "Medium",
                "title": f"Rule {rule_id} may have an expired schedule",
                "description": (
                    f"{rule_name} references a schedule ('{schedule}') that may be expired "
                    "or time-limited. Scheduled rules that remain enabled past their intended "
                    "period can allow unintended access."
                ),
                "affected_rules": [rule.get("id")],
                "evidence": {
                    "rule_id": rule_id,
                    "schedule": schedule,
                    "matched_keyword": matched,
                },
                "recommendation": _RL.get("expired_rule"),
            })
    return findings


def _analyze_nat_rules(rules: List[dict]) -> List[dict]:
    """Identify rules with NAT enabled for review."""
    findings = []
    nat_rules = [r for r in rules if r.get("nat_enabled") and r.get("enabled", True)]
    if not nat_rules:
        return findings
    for rule in nat_rules:
        rule_id = rule.get("rule_id") or rule.get("rule_number", "?")
        rule_name = rule.get("rule_name") or f"Rule {rule_id}"
        findings.append({
            "finding_type": "nat_complexity",
            "severity": "Informational",
            "confidence": "High",
            "title": f"Rule {rule_id} uses NAT",
            "description": (
                f"{rule_name} has NAT enabled. NAT rules introduce address translation "
                "complexity and should be periodically reviewed to confirm they reflect "
                "current network topology."
            ),
            "affected_rules": [rule.get("id")],
            "evidence": {
                "rule_id": rule_id,
                "nat_enabled": True,
                "sources": rule.get("sources", []),
                "destinations": rule.get("destinations", []),
            },
            "recommendation": _RL.get("nat_complexity"),
        })
    return findings


def _analyze_vpn_rules(rules: List[dict], obj_map: dict) -> List[dict]:
    """Detect VPN rules with overly broad access."""
    findings = []
    for rule in rules:
        vpn = rule.get("vpn") or []
        if not vpn:
            continue
        action = (rule.get("action") or "").lower()
        if action not in ("accept", "allow", "permit"):
            continue
        any_src = has_any_source(rule, obj_map)
        any_dst = has_any_destination(rule, obj_map)
        any_svc = has_any_service(rule, obj_map)
        if not (any_src or any_dst or any_svc):
            continue

        rule_id = rule.get("rule_id") or rule.get("rule_number", "?")
        rule_name = rule.get("rule_name") or f"Rule {rule_id}"
        broad = []
        if any_src:
            broad.append("any source")
        if any_dst:
            broad.append("any destination")
        if any_svc:
            broad.append("any service")

        findings.append({
            "finding_type": "vpn_access",
            "severity": "Critical" if (any_src and any_dst) else "High",
            "confidence": "High",
            "title": f"Rule {rule_id} grants broad VPN access ({', '.join(broad)})",
            "description": (
                f"{rule_name} is a VPN rule that uses {', '.join(broad)}. "
                "Overly permissive VPN rules can allow remote users to reach unintended "
                "internal resources."
            ),
            "affected_rules": [rule.get("id")],
            "evidence": {
                "rule_id": rule_id,
                "vpn": vpn,
                "any_source": any_src,
                "any_destination": any_dst,
                "any_service": any_svc,
            },
            "recommendation": _RL.get("vpn_access"),
        })
    return findings


def _analyze_negated_objects(rules: List[dict]) -> List[dict]:
    """Detect rules that reference negated (NOT) source or destination objects."""
    findings = []
    for rule in rules:
        sources = rule.get("sources", []) or []
        destinations = rule.get("destinations", []) or []
        neg_srcs = [s for s in sources if str(s).startswith("!") or str(s).startswith("NOT ")]
        neg_dsts = [d for d in destinations if str(d).startswith("!") or str(d).startswith("NOT ")]
        if not neg_srcs and not neg_dsts:
            continue
        rule_id = rule.get("rule_id") or rule.get("rule_number", "?")
        rule_name = rule.get("rule_name") or f"Rule {rule_id}"
        findings.append({
            "finding_type": "negated_object",
            "severity": "Low",
            "confidence": "Medium",
            "title": f"Rule {rule_id} uses negated objects",
            "description": (
                f"{rule_name} uses negated source or destination objects "
                f"({', '.join(neg_srcs + neg_dsts)}). Negated objects define "
                "what is excluded, which can be harder to review and may produce "
                "unintended traffic matches."
            ),
            "affected_rules": [rule.get("id")],
            "evidence": {
                "rule_id": rule_id,
                "negated_sources": neg_srcs,
                "negated_destinations": neg_dsts,
            },
            "recommendation": _RL.get("negated_object"),
        })
    return findings


# CheckPoint ships hundreds of predefined service-group objects that are
# intentionally empty (they serve as placeholders or are populated on-device
# by the OS).  Flagging them as findings produces noise with no actionable
# value, so we suppress them by name.  The list covers the most common ones
# visible in CheckPoint R80/R81/R82 default object databases.
_CHECKPOINT_PREDEFINED_GROUPS: frozenset = frozenset({
    # ── P2P / file-sharing (CP predefined) ──────────────────────────────────
    "AOL", "AOL_Messenger", "Gnutella", "GNUtella", "irc", "Kazaa2",
    "Napster", "eDonkey", "Direct_Connect", "Hotline", "FreeTel-outgoing",
    "P2P_File_Sharing_Applications", "RealPlayer",
    # ── Microsoft services ────────────────────────────────────────────────
    "MS-SQL", "MS_SQL", "MSExchange", "MSExchange-2000", "MSExchange-2003",
    "MSExchange-2007", "MSExchange-2010", "MSExchange-RemoteAdmin",
    "MSExchange-SiteConnector", "MSExchange_2007",
    "Microsoft-DS", "NetBIOS-dgm", "NetBIOS-ns", "NetBIOS-ssn",
    "NetMeeting", "sqlnet2",
    # ── Messaging ─────────────────────────────────────────────────────────
    "Messenger_Applications", "MSN_Messenger", "Yahoo_Messenger",
    "ICQ", "Jabber", "XMPP", "Skype",
    # ── Auth / directory ──────────────────────────────────────────────────
    "kerberos", "Kerberos", "LDAP", "RADIUS", "TACACS", "TACACS+",
    "SecurID", "securid", "NIS", "Entrust-CA",
    # ── CP-specific product groups ────────────────────────────────────────
    "FW1_clntauth",           # Check Point FireWall-1 client auth
    "Integrity_Server",       # Check Point Integrity product
    "RainWall-Control",       # StoneGate/Forcepoint OEM
    "StoneBeat",              # Stonesoft HA
    "DAIP_Control_services",  # Dynamic Address IP (CP)
    "Trojan_Services",        # CP predefined malware group
    "OAS",                    # Oracle Application Server (CP predefined)
    "Orbix",                  # IONA Orbix (CP predefined)
    "Citrix_metaFrame",       # Citrix (CP predefined)
    "pcANYWHERE", "PC_Anywhere", "pcTELECOMMUTE",
    # ── Well-known protocols as CP predefined service groups ──────────────
    "NBT", "PPTP", "PPTP_Encryption", "PPTP_Tunnel", "IPSEC",
    "IKE", "IKEv2", "IPsec", "ESP", "AH", "GRE", "L2TP",
    "VNC", "icmp-requests",
    # ── Network / routing protocol groups ────────────────────────────────
    "IGMP", "OSPF", "RIP", "BGP", "IS-IS", "PIM-SM", "PIM-DM",
    "EIGRP", "VRRP", "HSRP", "CDP", "STP", "RSTP", "MSTP", "LACP", "LLDP",
    # ── Standard service groups that CP pre-populates ─────────────────────
    "dns", "ntp", "time", "daytime", "discard", "echo",
    "SNMP", "SNMP_ALL", "Syslog", "NTP", "TFTP",
    "H323_all", "SIP_all", "MGCP", "SCCP", "RTP", "RTSP", "MMS",
    "SMB_all", "CIFS", "NFS", "LPR", "CUPS",
    # ── IPv6 / miscellaneous CP predefined ───────────────────────────────
    "IPv6_group", "IPv6_Link_Local_Hosts",
    # ── CP time / schedule objects ────────────────────────────────────────
    "Weekend", "Every_Day", "Weekdays", "Off_Work",
    # ── CP network / host objects ─────────────────────────────────────────
    "LocalMachine_Loopback", "MyIntranet",
    # ── CP service / protocol groups ─────────────────────────────────────
    "AD_Dcerpc_services", "HTTPS default services",
    # ── CP user / auth groups ─────────────────────────────────────────────
    "Authenticated", "All Users", "All Blocked",
})

# Additional heuristic: CP predefined groups often follow these naming patterns
import re as _re
_CP_PREDEFINED_PATTERNS = (
    _re.compile(r'^MSExchange', _re.IGNORECASE),
    _re.compile(r'^MS-', _re.IGNORECASE),
    _re.compile(r'^Microsoft-', _re.IGNORECASE),
    _re.compile(r'^H323_', _re.IGNORECASE),
    _re.compile(r'^SIP_', _re.IGNORECASE),
    _re.compile(r'^SMB_', _re.IGNORECASE),
    _re.compile(r'^SNMP', _re.IGNORECASE),
)


def _is_checkpoint_predefined(name: str) -> bool:
    """Return True if the group name matches a known CheckPoint predefined object."""
    if name in _CHECKPOINT_PREDEFINED_GROUPS:
        return True
    return any(p.match(name) for p in _CP_PREDEFINED_PATTERNS)


def _object_type(obj: dict) -> str:
    return (obj.get("object_type") or "").strip().lower().replace("-", "_")


def _is_group_object(obj: dict) -> bool:
    return "group" in _object_type(obj)


def _is_service_object(obj: dict) -> bool:
    return "service" in _object_type(obj)


def _truthy_metadata(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value == 1
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "enabled"}
    return False


def _is_vendor_builtin_object(obj: dict) -> bool:
    """Return True for vendor-managed/predefined objects that customers should not clean up."""
    name = obj.get("object_name", "")
    if _is_cp_predefined(name) or _is_checkpoint_predefined(name):
        return True

    obj_type = _object_type(obj)
    if "predefined" in obj_type or "builtin" in obj_type or "built_in" in obj_type:
        return True

    raw = obj.get("raw_data") or {}
    if isinstance(raw, dict):
        for key in (
            "predefined", "is_predefined", "builtin", "built_in", "built-in",
            "read_only", "read-only", "vendor_managed", "vendor-managed",
            "system_object",
        ):
            if _truthy_metadata(raw.get(key)):
                return True

        domain = raw.get("domain")
        if isinstance(domain, dict) and (domain.get("name") or "").lower() == "check point data":
            return True
        if isinstance(domain, str) and domain.lower() == "check point data":
            return True

    return False


def _analyze_empty_groups(objects: List[dict]) -> List[dict]:
    """Detect group objects with no members.

    CheckPoint predefined service groups are intentionally empty and are
    suppressed to avoid false-positive noise.
    """
    findings = []
    for obj in objects:
        if not _is_group_object(obj):
            continue
        members = obj.get("members") or []
        if len(members) == 0:
            # Suppress known vendor predefined empty groups.
            if _is_vendor_builtin_object(obj):
                continue
            findings.append({
                "finding_type": "empty_group",
                "severity": "Low",
                "confidence": "High",
                "title": f"Group '{obj['object_name']}' is empty",
                "description": (
                    f"The group object '{obj['object_name']}' has no members. "
                    "Empty groups referenced in rules may behave unexpectedly and "
                    "add unnecessary clutter to the object database."
                ),
                "affected_rules": [],
                "affected_objects": [obj.get("id")],
                "evidence": {
                    "object_name": obj["object_name"],
                    "object_type": obj["object_type"],
                    "member_count": 0,
                },
                "recommendation": _RL.get("empty_group"),
            })
    return findings


_LARGE_GROUP_THRESHOLD = 20


def _analyze_large_groups(objects: List[dict]) -> List[dict]:
    """Detect group objects with an excessive number of members."""
    findings = []
    for obj in objects:
        if not _is_group_object(obj):
            continue
        if _is_vendor_builtin_object(obj):
            continue
        members = obj.get("members") or []
        if len(members) >= _LARGE_GROUP_THRESHOLD:
            findings.append({
                "finding_type": "large_group",
                "severity": "Informational",
                "confidence": "High",
                "title": f"Group '{obj['object_name']}' has {len(members)} members",
                "description": (
                    f"The group object '{obj['object_name']}' contains {len(members)} members. "
                    "Very large groups are difficult to audit and may include obsolete members."
                ),
                "affected_rules": [],
                "affected_objects": [obj.get("id")],
                "evidence": {
                    "object_name": obj["object_name"],
                    "object_type": obj["object_type"],
                    "member_count": len(members),
                    "members": members[:10],
                },
                "recommendation": _RL.get("large_group"),
            })
    return findings


import ipaddress


def _analyze_broad_networks(objects: List[dict]) -> List[dict]:
    """Detect network objects with very large address spaces (/8, /12, /16)."""
    findings = []
    _BROAD_PREFIXES = {8, 12, 16}
    for obj in objects:
        if _object_type(obj) not in ("network", "host"):
            continue
        if _is_vendor_builtin_object(obj):
            continue
        value = (obj.get("value") or "").strip()
        if not value or "/" not in value:
            continue
        try:
            net = ipaddress.ip_network(value, strict=False)
            if net.prefixlen in _BROAD_PREFIXES or net.prefixlen < 16:
                findings.append({
                    "finding_type": "broad_network",
                    "severity": "Medium",
                    "confidence": "High",
                    "title": f"Network object '{obj['object_name']}' is very broad ({value})",
                    "description": (
                        f"The object '{obj['object_name']}' covers {net.num_addresses:,} "
                        f"addresses ({value}). Overly broad network objects can inadvertently "
                        "grant access to unintended hosts."
                    ),
                    "affected_rules": [],
                    "affected_objects": [obj.get("id")],
                    "evidence": {
                        "object_name": obj["object_name"],
                        "value": value,
                        "prefix_length": net.prefixlen,
                        "num_addresses": net.num_addresses,
                    },
                    "recommendation": _RL.get("broad_network"),
                })
        except ValueError:
            pass
    return findings


_LARGE_PORT_RANGE = 100

# ── CheckPoint built-in / predefined object names ─────────────────────────
# These are vendor-shipped objects present in every CP installation.
# They must not be flagged for large port ranges, unused status, or any other
# hygiene finding — they are not customer-managed and cannot be removed.
_CP_PREDEFINED_NAMES: set = {
    # Broad protocol catch-alls
    "tcp-high-ports", "udp-high-ports",
    "unknown_protocol_tcp", "unknown_protocol_udp",
    "unknown_protocol_other",
    # Secure Internal Communication (SIC)
    "SIC-TCP", "SIC-UDP", "CPD", "CPD_amon", "CP_redundant",
    "FW1_ike", "FW1_key", "FW1_omi", "FW1_omi-sic", "FW1_sam",
    "FW1_clntauth_telnet", "FW1_clntauth_http", "FW1_mgmt",
    "FW1_log", "FW1_snmp", "FW1_topo", "FW1_ela", "FW1_cvp",
    "FW1_ufp", "FW1_snauth", "FW1_sds", "FW1_amon",
    # Common CP predefined services
    "AOL", "AOL_Messenger", "AH", "AP-Defender", "AT-Defender",
    "BGP", "BFD-Single_hop", "BFD-Multihop", "Backage",
    "Authenticated", "Accept",
    # Catch-all / legacy
    "Any", "any", "All", "all",
}

# Objects whose names start with these prefixes are also CheckPoint internals
_CP_PREDEFINED_PREFIXES = ("FW1_", "CP_", "cpd_", "SIC-", "CPMI_", "Cpty_")


def _is_cp_predefined(name: str) -> bool:
    """Return True if this object name is a CheckPoint built-in."""
    if name in _CP_PREDEFINED_NAMES:
        return True
    for prefix in _CP_PREDEFINED_PREFIXES:
        if name.startswith(prefix):
            return True
    return False


def _analyze_service_ranges(objects: List[dict]) -> List[dict]:
    """Detect service objects that span large port ranges."""
    findings = []
    for obj in objects:
        if not _is_service_object(obj):
            continue
        # Skip vendor built-in services; customers cannot modify them.
        if _is_vendor_builtin_object(obj):
            continue
        start = obj.get("port_start")
        end = obj.get("port_end")
        if start is None or end is None:
            continue
        span = int(end) - int(start)
        if span >= _LARGE_PORT_RANGE:
            findings.append({
                "finding_type": "service_range",
                "severity": "Medium",
                "confidence": "High",
                "title": (
                    f"Service '{obj['object_name']}' covers a large port range "
                    f"({start}–{end}, {span} ports)"
                ),
                "description": (
                    f"The service object '{obj['object_name']}' spans {span} ports "
                    f"({start}–{end}). Large service ranges may inadvertently permit "
                    "traffic on unintended ports."
                ),
                "affected_rules": [],
                "affected_objects": [obj.get("id")],
                "evidence": {
                    "object_name": obj["object_name"],
                    "protocol": obj.get("protocol"),
                    "port_start": start,
                    "port_end": end,
                    "port_span": span,
                },
                "recommendation": _RL.get("service_range"),
            })
    return findings


def _analyze_import_quality(
    rules: List[dict], objects: List[dict], policy
) -> List[dict]:
    """Produce a single informational finding summarising parse completeness.

    This explains why some findings (zero-hit, NAT, etc.) may be unavailable or
    reported with reduced confidence, per spec 4.7 / 4.14. It is purely a
    review aid and contains no remediation action.
    """
    total_rules = len(rules)
    total_objects = len(objects)
    service_objs = sum(1 for o in objects if o.get("object_type") in ("service", "service-group"))
    group_objs = sum(1 for o in objects if "group" in (o.get("object_type") or ""))
    nat_rules = sum(1 for r in rules if r.get("nat_enabled"))

    rules_with_hits = sum(1 for r in rules if r.get("hit_count") is not None)
    rules_with_last_hit = sum(1 for r in rules if r.get("last_hit"))
    hit_data_available = rules_with_hits > 0
    last_hit_available = rules_with_last_hit > 0

    notes = []
    confidence_impact = []
    if not hit_data_available:
        notes.append(
            "No hit-count data was found in the imported configuration. "
            "Zero-hit and low-usage findings cannot be generated for this policy."
        )
        confidence_impact.append("Usage-based findings unavailable (no hit counts).")
    elif rules_with_hits < total_rules:
        notes.append(
            f"Hit-count data is available for {rules_with_hits} of {total_rules} rules. "
            "Usage findings are limited to rules with recorded hit data."
        )
        confidence_impact.append("Partial hit-count coverage reduces usage-finding completeness.")
    if not last_hit_available:
        notes.append(
            "No last-hit timestamps were found, so time-based inactivity findings "
            "(90/180/365 days) cannot be generated."
        )
    if nat_rules == 0:
        notes.append(
            "No NAT data was detected. NAT-specific findings are not generated for this policy."
        )
    vendor_hints = _vendor_collection_hints(policy.vendor or "")

    description = (
        f"Parsed {total_rules} rule(s), {total_objects} object(s) "
        f"({service_objs} service object(s), {group_objs} group(s)), and "
        f"{nat_rules} NAT-enabled rule(s) from this {policy.vendor or 'firewall'} "
        "configuration. "
    )
    if notes:
        description += "Import notes: " + " ".join(notes)
    else:
        description += (
            "Hit-count, last-hit, NAT, and object data were all available, so the full "
            "set of findings could be generated at standard confidence."
        )

    return [{
        "finding_type": "import_quality",
        "severity": "Informational",
        "confidence": "High",
        "title": "Import quality and data availability summary",
        "description": description,
        "affected_rules": [],
        "affected_objects": [],
        "evidence": {
            "rules_parsed": total_rules,
            "objects_parsed": total_objects,
            "service_objects_parsed": service_objs,
            "groups_parsed": group_objs,
            "nat_rules_parsed": nat_rules,
            "hit_count_available": hit_data_available,
            "rules_with_hit_count": rules_with_hits,
            "last_hit_available": last_hit_available,
            "rules_with_last_hit": rules_with_last_hit,
            "recommended_collection": vendor_hints,
            "confidence_impact": confidence_impact or ["None - full data available."],
        },
        "recommendation": _RL.get("import_quality"),
    }]


def _vendor_collection_hints(vendor: str) -> List[str]:
    """Return vendor-specific data that improves analysis completeness."""
    v = (vendor or "").lower()
    if "huawei" in v:
        return [
            "Include display security-policy all or current-configuration security-policy output.",
            "Include display security-policy statistics output so hit_count, first_hit, and last_hit can be populated.",
            "Include display ip address-set, display service-set, display zone, and display nat-policy output when using file import.",
        ]
    if "fortigate" in v:
        return [
            "Prefer API/JSON export or backup output that includes hitc, first-used, and last-used fields.",
            "Include config firewall address, addrgrp, service custom, service group, policy, and NAT/VIP sections.",
        ]
    if "palo" in v:
        return [
            "Use XML configuration exports that include address, address-group, service, service-group, application, and security rulebase nodes.",
            "When available, enrich imports with rule hit-count and last-hit data from operational rule usage APIs or reports.",
        ]
    if "cisco" in v or "asa" in v:
        return [
            "Include show running-config and show access-list output so ACE hitcnt values can be parsed.",
            "Include object, object-group network, object-group service, access-group, and NAT sections.",
        ]
    if "checkpoint" in v or "check point" in v:
        return [
            "Include exported access rulebase, network objects, service objects, service groups, and install-on/package details.",
            "When available, enrich imports with rule hit-count and last-hit data from management API usage/statistics views.",
        ]
    return [
        "Include rule hit counts, last-hit timestamps, address/service objects, groups, NAT, logging, and zone/interface metadata when available.",
    ]
