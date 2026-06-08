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
from app.analysis.service_utils import identify_risky_service
from app.config import settings
import uuid
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

        # 5. Duplicate rules
        findings.extend(detect_duplicates(rules, obj_map))

        # 6. Shadowed rules
        findings.extend(detect_shadows(rules, obj_map))

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

        # Save findings
        finding_count = 0
        high_count = 0
        for f in findings:
            finding_orm = Finding(
                id=str(uuid.uuid4()),
                policy_id=policy_id,
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
            if f.get("severity") == "High":
                high_count += 1

        policy.finding_count = finding_count
        policy.high_finding_count = high_count
        policy.analysis_status = "completed"

        # --- Compute extended scores ---
        enabled_rules = [r for r in rules if r.get("enabled", True)]
        total_rules = len(rules)

        # Complexity score: penalise large rule count, low documentation, high permissiveness
        perm_count = sum(1 for f in findings if f["finding_type"] == "overly_permissive")
        doc_miss = sum(1 for f in findings if f["finding_type"] == "no_documentation")
        complexity_score = min(100, int(
            min(30, total_rules / 5) +
            min(30, len(objects) / 20) +
            min(20, perm_count * 4) +
            min(20, doc_miss * 2)
        ))

        # Cleanup readiness: how much useful data do we have?
        rules_with_hits = sum(1 for r in rules if r.get("hit_count") is not None)
        readiness_score = int(100 * rules_with_hits / max(1, total_rules))

        # Health score: inverse risk proxy
        sev_weights = {"High": 10, "Medium": 5, "Low": 2, "Informational": 0}
        total_sev = sum(sev_weights.get(f.get("severity", "Informational"), 0) for f in findings)
        health_score = max(0, 100 - min(100, total_sev))

        # Top risk drivers
        from collections import Counter
        driver_counts = Counter(f["finding_type"] for f in findings)
        top_risk_drivers = [{"type": t, "count": c} for t, c in driver_counts.most_common(5)]

        policy.complexity_score = complexity_score
        policy.cleanup_readiness_score = readiness_score
        policy.health_score = health_score
        policy.top_risk_drivers = top_risk_drivers

        run.status = "completed"
        run.completed_at = datetime.utcnow()
        run.findings_created = finding_count

        db.commit()
        logger.info(f"Analysis complete for policy {policy_id}: {finding_count} findings")
        return run.id

    except Exception as e:
        logger.error(f"Analysis failed for policy {policy_id}: {e}", exc_info=True)
        run.status = "failed"
        run.error = str(e)
        if 'policy' in dir():
            policy.analysis_status = "failed"
            policy.analysis_error = str(e)
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
        "object_name": o.object_name,
        "object_type": o.object_type,
        "value": o.value,
        "protocol": o.protocol,
        "port_start": o.port_start,
        "port_end": o.port_end,
        "members": o.members or [],
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
                "recommendation": (
                    f"This rule is currently disabled. If it has remained disabled for a long "
                    "period and there is no business requirement, consider removing it after "
                    "change approval."
                ),
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
                "recommendation": (
                    "Review whether this rule has a valid business requirement. If it has never "
                    "been used and no future use is expected, consider removing it after "
                    "change approval."
                ),
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
                        "recommendation": (
                            f"This rule has not been used in {days_inactive} days. Review whether "
                            "it has an active business requirement. If no requirement exists, "
                            "consider removing it through the change management process."
                        ),
                    })
            except (ValueError, TypeError):
                pass

    return findings


def _analyze_permissive(rules: List[dict], obj_map: dict) -> List[dict]:
    findings = []
    for rule in rules:
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
            if any_src and any_dst:
                severity = "High"
            elif any_src or any_dst:
                severity = "High"
            else:
                severity = "Medium"

            findings.append({
                "finding_type": "overly_permissive",
                "severity": severity,
                "confidence": "High",
                "title": f"Rule {rule_id} is overly permissive ({', '.join(issues)})",
                "description": (
                    f"{rule_name} uses {', '.join(issues)}. "
                    "Overly broad rules increase the attack surface and make the policy "
                    "harder to audit and maintain."
                ),
                "affected_rules": [rule.get("id")],
                "evidence": {
                    "rule_id": rule_id,
                    "any_source": any_src,
                    "any_destination": any_dst,
                    "any_service": any_svc,
                    "action": rule.get("action"),
                },
                "recommendation": (
                    "Review the business requirement and restrict the source, destination, and "
                    "service to the minimum required scope. Apply the principle of least privilege."
                ),
            })

    return findings


def _analyze_risky_services(rules: List[dict], obj_map: dict) -> List[dict]:
    findings = []
    for rule in rules:
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

        findings.append({
            "finding_type": "risky_service",
            "severity": "Medium",
            "confidence": "High",
            "title": f"Rule {rule_id} uses risky service(s): {', '.join(risky.keys())}",
            "description": (
                f"{rule_name} allows traffic on services considered risky: "
                f"{', '.join(risky.keys())}. These services may expose sensitive "
                "systems to attack if access is not properly restricted."
            ),
            "affected_rules": [rule.get("id")],
            "evidence": {
                "rule_id": rule_id,
                "risky_services": list(risky.keys()),
                "action": rule.get("action"),
                "sources": rule.get("sources", []),
                "destinations": rule.get("destinations", []),
            },
            "recommendation": (
                "Review whether the identified risky services are required. Restrict access "
                "to specific, known source and destination addresses. Consider using "
                "encrypted alternatives where available (e.g., HTTPS instead of HTTP, "
                "SSH instead of Telnet)."
            ),
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
                "recommendation": (
                    "Consider enabling logging on this rule if visibility is required "
                    "for troubleshooting, auditing, or security monitoring purposes."
                ),
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
                "recommendation": (
                    "Review whether this rule is still required. If it was created for a "
                    "temporary purpose that has since expired, remove it through the formal "
                    "change management process."
                ),
            })
    return findings


def _analyze_unused_objects(
    rules: List[dict], objects: List[dict], obj_map: dict
) -> List[dict]:
    findings = []

    # Collect all object names referenced by rules
    used_names = set()
    for rule in rules:
        for src in rule.get("sources", []):
            used_names.add(src)
        for dst in rule.get("destinations", []):
            used_names.add(dst)
        for svc in rule.get("services", []):
            used_names.add(svc)

    # Also include members of used groups
    def collect_members(name: str, visited: set):
        if name in visited:
            return
        visited.add(name)
        obj = obj_map.get(name)
        if obj and obj.get("object_type") == "group":
            for m in obj.get("members", []):
                used_names.add(m)
                collect_members(m, visited)

    for name in list(used_names):
        collect_members(name, set())

    # Service/port object types are excluded from unused-object analysis.
    # Port objects (TCP, UDP, ICMP services and service groups) may be referenced
    # in other policy packages, NAT rules, or used by vendor management processes.
    # Flagging them as unused within a single policy is not actionable.
    _SERVICE_TYPES = {"service", "service-group"}

    for obj in objects:
        name = obj.get("object_name", "")
        if name.lower() in ("any", "all"):
            continue
        # Skip all service/port objects — type-based, vendor-agnostic filter.
        if obj.get("object_type") in _SERVICE_TYPES:
            continue
        # Skip CheckPoint built-in / predefined objects — vendor-managed, cannot be removed.
        if _is_cp_predefined(name):
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
                "recommendation": (
                    f"Review whether the object '{name}' is referenced in other policies "
                    "or has a future use. If unused, consider removing it to reduce "
                    "policy complexity."
                ),
            })

    return findings


def _analyze_duplicate_objects(objects: List[dict]) -> List[dict]:
    findings = []
    # Group non-group objects by normalized value
    value_map: Dict[str, List[dict]] = {}
    for obj in objects:
        if obj.get("object_type") in ("group", "service-group"):
            continue
        val = (obj.get("value") or "").strip().lower()
        if not val or val in ("any", "all"):
            continue
        if val not in value_map:
            value_map[val] = []
        value_map[val].append(obj)

    for val, objs in value_map.items():
        # Filter out CP predefined objects from duplicate detection
        objs = [o for o in objs if not _is_cp_predefined(o.get("object_name", ""))]
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
            "recommendation": (
                "Consider consolidating these objects into a single standard object after "
                "validating all rule references. Update all rules to use the consolidated object."
            ),
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
            "recommendation": (
                "Add a comment to this rule identifying the business owner, ticket reference, "
                "and purpose of the access. Rules without documented justification should be "
                "reviewed to confirm they are still required."
            ),
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
                "recommendation": (
                    "Assign a meaningful name that reflects the rule's purpose, the owning "
                    "team, and the relevant change ticket."
                ),
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
                "recommendation": (
                    "Rename this rule to clearly describe its purpose, traffic type, and "
                    "business owner."
                ),
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
                "recommendation": (
                    "Verify the schedule object and confirm whether this rule is still "
                    "within its intended active period. If the schedule has expired, "
                    "disable or remove the rule through the change management process."
                ),
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
            "recommendation": (
                "Review this NAT rule to confirm the translation is still accurate, "
                "necessary, and documented. Verify the associated security rule permits "
                "only the intended traffic."
            ),
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
            "severity": "High",
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
            "recommendation": (
                "Restrict VPN access to the minimum required source groups, destination "
                "segments, and services. Apply role-based segmentation for different "
                "user populations."
            ),
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
            "recommendation": (
                "Review negated objects to confirm the exclusion logic is intentional "
                "and correctly scoped. Where possible, convert to explicit positive "
                "object definitions."
            ),
        })
    return findings


def _analyze_empty_groups(objects: List[dict]) -> List[dict]:
    """Detect group objects with no members."""
    findings = []
    for obj in objects:
        if obj.get("object_type") not in ("group", "service-group"):
            continue
        members = obj.get("members") or []
        if len(members) == 0:
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
                "recommendation": (
                    "Either populate the group with appropriate members or remove it "
                    "if it is no longer needed. Verify no rules reference this empty group."
                ),
            })
    return findings


_LARGE_GROUP_THRESHOLD = 20


def _analyze_large_groups(objects: List[dict]) -> List[dict]:
    """Detect group objects with an excessive number of members."""
    findings = []
    for obj in objects:
        if obj.get("object_type") not in ("group", "service-group"):
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
                "recommendation": (
                    "Review group membership to identify obsolete or overly broad entries. "
                    "Consider splitting into smaller, purpose-specific groups."
                ),
            })
    return findings


import ipaddress


def _analyze_broad_networks(objects: List[dict]) -> List[dict]:
    """Detect network objects with very large address spaces (/8, /12, /16)."""
    findings = []
    _BROAD_PREFIXES = {8, 12, 16}
    for obj in objects:
        if obj.get("object_type") not in ("network", "host"):
            continue
        if _is_cp_predefined(obj.get("object_name", "")):
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
                    "recommendation": (
                        "Verify that the broad scope is intentional. Where possible, "
                        "restrict the object to the specific subnet or host range required."
                    ),
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
        if obj.get("object_type") not in ("service", "service-group"):
            continue
        # Skip CheckPoint built-in services — they cannot be modified by customers
        if _is_cp_predefined(obj.get("object_name", "")):
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
                "recommendation": (
                    "Review whether the full port range is required. Restrict service "
                    "objects to the specific ports needed by the application."
                ),
            })
    return findings
