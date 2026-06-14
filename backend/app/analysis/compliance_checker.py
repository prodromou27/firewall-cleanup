"""
Compliance Framework Checker
=============================
Maps policy findings and rule data to industry compliance frameworks:
  - PCI-DSS v4.0 (Payment Card Industry Data Security Standard)
  - CIS Controls v8 (Center for Internet Security)
  - NIST CSF 2.0 (Cybersecurity Framework)
  - ISO 27001:2022 (Information Security Management)

SAFETY: Read-only analysis. No policy is modified.

Architecture:
  - Works on already-analyzed findings stored in the DB (fast, no re-analysis)
  - Supplements with direct rule/object checks where needed
  - Each check returns: status (pass/warn/fail/info/na), severity, detail, evidence
"""
from __future__ import annotations
import json
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session

from app.models.policy import FirewallPolicy, FirewallRule, FirewallObject
from app.models.finding import Finding

PASS    = "pass"
WARN    = "warn"
FAIL    = "fail"
INFO    = "info"
NA      = "na"

# Severity levels for compliance checks
SEV_CRITICAL = "Critical"
SEV_HIGH     = "High"
SEV_MEDIUM   = "Medium"
SEV_LOW      = "Low"
SEV_INFO     = "Informational"


def _check(
    check_id: str,
    control_ref: str,
    title: str,
    status: str,
    severity: str,
    detail: str,
    recommendation: str = "",
    evidence: Optional[dict] = None,
    category: str = "",
) -> dict:
    return {
        "check_id":     check_id,
        "control_ref":  control_ref,
        "category":     category,
        "title":        title,
        "status":       status,
        "severity":     severity,
        "detail":       detail,
        "recommendation": recommendation,
        "evidence":     evidence or {},
    }


# ── Helpers ────────────────────────────────────────────────────────────────────

def _findings_by_type(findings: list, *types: str) -> list:
    return [f for f in findings if f.finding_type in types]

def _count_by_type(findings: list, *types: str) -> int:
    return len(_findings_by_type(findings, *types))

def _high_findings(findings: list) -> list:
    return [f for f in findings if f.severity in ("High", "Critical")]

def _last_rule(rules: list) -> Optional[FirewallRule]:
    """Return the last enabled rule (should be a deny-all)."""
    enabled = [r for r in rules if r.enabled]
    return enabled[-1] if enabled else None

def _is_deny(action: str) -> bool:
    return (action or "").lower() in ("deny", "drop", "reject", "block")

def _is_any(value: str) -> bool:
    v = (value or "").lower().strip()
    return v in ("any", "all", "", "0.0.0.0/0", "::/0", "0.0.0.0")

def _has_any_source(rule: FirewallRule) -> bool:
    srcs = json.loads(rule.sources or "[]")
    return not srcs or any(_is_any(str(s)) for s in srcs)

def _has_any_dest(rule: FirewallRule) -> bool:
    dsts = json.loads(rule.destinations or "[]")
    return not dsts or any(_is_any(str(d)) for d in dsts)

def _has_any_service(rule: FirewallRule) -> bool:
    svcs = json.loads(rule.services or "[]")
    return not svcs or any(_is_any(str(s)) for s in svcs)

# High-risk service names / ports that should never be open to the internet
_RISKY_HIGH_PORTS = {21, 22, 23, 80, 135, 137, 138, 139, 445, 1433, 1434, 3306, 3389, 5432, 5900, 5901, 8080}
_RISKY_SERVICES   = {"ftp","ssh","telnet","rdp","smb","mssql","mysql","vnc","http","oracle","postgres"}


# ════════════════════════════════════════════════════════════════════════════
# PCI-DSS v4.0 checks
# ════════════════════════════════════════════════════════════════════════════

def _pci_dss_checks(
    policy: FirewallPolicy,
    rules: list[FirewallRule],
    findings: list[Finding],
) -> list[dict]:
    checks = []
    enabled_rules = [r for r in rules if r.enabled]
    allow_rules   = [r for r in enabled_rules if not _is_deny(r.action)]

    # ── 1.2.1 — Restrict inbound/outbound to business necessity (no ANY/ANY) ──
    perm = _count_by_type(findings, "overly_permissive")
    checks.append(_check(
        check_id="PCI-1.2.1",
        control_ref="PCI-DSS v4 Req 1.2.1",
        category="Network Security Controls",
        title="Restrict inbound/outbound traffic to business necessity",
        status=FAIL if perm > 0 else PASS,
        severity=SEV_HIGH if perm > 0 else SEV_INFO,
        detail=(
            f"{perm} rule(s) allow traffic to/from Any source, Any destination, or Any service "
            "without documented business justification. PCI-DSS requires all traffic to be restricted "
            "to only what is necessary for authorised business needs."
            if perm > 0 else
            "No overly-permissive rules detected. All traffic appears restricted to defined sources/destinations/services."
        ),
        recommendation=(
            "Review each flagged rule. Replace 'Any' with specific, documented IP ranges, "
            "network objects, and service definitions. Obtain written business justification before approval."
        ) if perm > 0 else "",
        evidence={"overly_permissive_count": perm},
    ))

    # ── 1.2.2 — Implicit deny: last rule must be DENY ────────────────────────
    last = _last_rule(rules)
    last_is_deny = last and _is_deny(last.action)
    checks.append(_check(
        check_id="PCI-1.2.2",
        control_ref="PCI-DSS v4 Req 1.2.2",
        category="Network Security Controls",
        title="Implicit deny: last rule must deny all unmatched traffic",
        status=PASS if last_is_deny else FAIL,
        severity=SEV_CRITICAL if not last_is_deny else SEV_INFO,
        detail=(
            f"Last rule is '{last.rule_name}' with action '{last.action}'. "
            "An explicit deny-all rule at the end of the policy is required by PCI-DSS to "
            "prevent unmatched traffic from passing."
            if last and not last_is_deny else
            "Policy ends with an explicit deny-all rule — compliant."
            if last_is_deny else
            "No enabled rules found in this policy."
        ),
        recommendation="Add a deny-all rule as the final entry in the policy (Rule 9999 or equivalent)." if not last_is_deny else "",
        evidence={"last_rule_name": last.rule_name if last else None, "last_rule_action": last.action if last else None},
    ))

    # ── 1.3.1 — Block high-risk services to/from internet ────────────────────
    risky = _count_by_type(findings, "risky_service")
    checks.append(_check(
        check_id="PCI-1.3.1",
        control_ref="PCI-DSS v4 Req 1.3.1",
        category="Prohibited Services",
        title="Block insecure management protocols (RDP, Telnet, FTP, SMB) to/from internet",
        status=FAIL if risky > 0 else PASS,
        severity=SEV_HIGH if risky > 0 else SEV_INFO,
        detail=(
            f"{risky} rule(s) permit high-risk services (RDP/3389, Telnet/23, FTP/21, SMB/445, SSH/22, etc.) "
            "that are prohibited by PCI-DSS for internet-accessible network segments."
            if risky > 0 else
            "No rules permitting prohibited high-risk services detected."
        ),
        recommendation=(
            "Remove or restrict rules allowing Telnet, FTP, RDP, or SMB. "
            "Use encrypted alternatives (SSH, SFTP, VPN) with MFA enforced."
        ) if risky > 0 else "",
        evidence={"risky_service_rule_count": risky},
    ))

    # ── 1.3.2 — No direct internet connectivity without inspection ────────────
    checks.append(_check(
        check_id="PCI-1.3.2",
        control_ref="PCI-DSS v4 Req 1.3.2",
        category="Network Security Controls",
        title="Restrict outbound traffic from CDE to explicitly authorised addresses",
        status=WARN if perm > 0 else PASS,
        severity=SEV_MEDIUM if perm > 0 else SEV_INFO,
        detail=(
            f"Found {perm} rules with unrestricted source/destination. "
            "Without explicit destination restrictions, CDE systems may communicate with arbitrary internet hosts."
            if perm > 0 else
            "Outbound traffic appears restricted to defined destinations."
        ),
        recommendation="Define explicit destination groups for each outbound rule. Remove 'Any Destination' entries." if perm > 0 else "",
        evidence={"permissive_rule_count": perm},
    ))

    # ── 1.4.1 — Logging on all firewall rules ────────────────────────────────
    no_log = _count_by_type(findings, "no_logging")
    checks.append(_check(
        check_id="PCI-1.4.1",
        control_ref="PCI-DSS v4 Req 10.2.1 / Req 1.4.1",
        category="Logging & Audit",
        title="All rules must have logging enabled",
        status=FAIL if no_log > 0 else PASS,
        severity=SEV_HIGH if no_log > 0 else SEV_INFO,
        detail=(
            f"{no_log} rule(s) have logging disabled. PCI-DSS requires logging of all traffic "
            "entering and leaving the CDE to support audit trails and incident response."
            if no_log > 0 else
            "All rules have logging enabled — compliant."
        ),
        recommendation="Enable logging on all rules. Store logs for a minimum of 12 months (3 months immediately available)." if no_log > 0 else "",
        evidence={"rules_without_logging": no_log},
    ))

    # ── 1.4.2 — Rule documentation ──────────────────────────────────────────
    no_doc = _count_by_type(findings, "no_documentation")
    checks.append(_check(
        check_id="PCI-1.4.2",
        control_ref="PCI-DSS v4 Req 1.2.1 (documentation)",
        category="Change Management",
        title="All rules must have documented business justification",
        status=FAIL if no_doc > 0 else PASS,
        severity=SEV_MEDIUM if no_doc > 0 else SEV_INFO,
        detail=(
            f"{no_doc} rule(s) lack comments/documentation. PCI-DSS requires documented "
            "business justification for each active rule."
            if no_doc > 0 else
            "All rules have documented justification — compliant."
        ),
        recommendation="Add a comment to each rule stating: owner, business purpose, approved ticket/CR number, and review date." if no_doc > 0 else "",
        evidence={"undocumented_rules": no_doc},
    ))

    # ── 1.4.3 — Shadow/duplicate rules ──────────────────────────────────────
    shadow = _count_by_type(findings, "shadowed_rule")
    dup    = _count_by_type(findings, "duplicate_rule")
    checks.append(_check(
        check_id="PCI-1.4.3",
        control_ref="PCI-DSS v4 Req 1.2.7",
        category="Rule Quality",
        title="No shadowed or duplicate rules (policy review hygiene)",
        status=FAIL if (shadow + dup) > 0 else PASS,
        severity=SEV_MEDIUM if (shadow + dup) > 0 else SEV_INFO,
        detail=(
            f"{shadow} shadowed rule(s) and {dup} duplicate rule(s) detected. "
            "Shadowed/duplicate rules indicate lack of regular policy review and may "
            "mask security misconfigurations."
            if (shadow + dup) > 0 else
            "No shadowed or duplicate rules detected."
        ),
        recommendation="Remove shadowed and duplicate rules through the formal change management process. Implement quarterly rule review." if (shadow + dup) > 0 else "",
        evidence={"shadowed_rules": shadow, "duplicate_rules": dup},
    ))

    # ── 1.4.4 — Unused / zero-hit rules ────────────────────────────────────
    zero_hit = _count_by_type(findings, "zero_hit_rule")
    checks.append(_check(
        check_id="PCI-1.4.4",
        control_ref="PCI-DSS v4 Req 1.2.7 (review & validity)",
        category="Rule Quality",
        title="Remove or document unused rules (zero traffic hit count)",
        status=WARN if zero_hit > 0 else PASS,
        severity=SEV_LOW if zero_hit > 0 else SEV_INFO,
        detail=(
            f"{zero_hit} rule(s) have never matched any traffic. "
            "Unused rules expand attack surface and violate the principle of least privilege."
            if zero_hit > 0 else
            "No zero-hit rules detected (or hit count data not available)."
        ),
        recommendation="Review zero-hit rules: disable or remove those without documented business justification. Treat 'zero-hit' rules older than 90 days as candidates for removal." if zero_hit > 0 else "",
        evidence={"zero_hit_rules": zero_hit},
    ))

    # ── 6.4 — Change management: temporary rules ────────────────────────────
    temp = _count_by_type(findings, "temporary_rule")
    checks.append(_check(
        check_id="PCI-6.4",
        control_ref="PCI-DSS v4 Req 6.4.6",
        category="Change Management",
        title="Temporary rules must have an expiry date and not remain permanently",
        status=WARN if temp > 0 else PASS,
        severity=SEV_MEDIUM if temp > 0 else SEV_INFO,
        detail=(
            f"{temp} rule(s) appear to be temporary (contain temp/test/temp keywords) "
            "but may not have proper expiry controls. Temporary rules must be removed after need expires."
            if temp > 0 else
            "No suspected temporary rules without expiry detected."
        ),
        recommendation="Ensure all temporary rules have: expiry date, ticket reference, and owner. Use the firewall schedule feature to enforce auto-expiry." if temp > 0 else "",
        evidence={"temp_rules": temp},
    ))

    # ── Summary ─────────────────────────────────────────────────────────────
    total  = len(checks)
    passed = sum(1 for c in checks if c["status"] == PASS)
    failed = sum(1 for c in checks if c["status"] == FAIL)
    warned = sum(1 for c in checks if c["status"] == WARN)
    score  = int(passed / total * 100) if total else 0
    grade  = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 50 else "F"

    return {
        "framework": "pci-dss",
        "framework_name": "PCI-DSS v4.0",
        "policy_id": policy.id,
        "firewall_name": policy.firewall_name,
        "vendor": policy.vendor,
        "score": score,
        "grade": grade,
        "summary": {"total": total, "passed": passed, "failed": failed, "warned": warned},
        "checks": checks,
    }


# ════════════════════════════════════════════════════════════════════════════
# CIS Controls v8 checks
# ════════════════════════════════════════════════════════════════════════════

def _cis_checks(
    policy: FirewallPolicy,
    rules: list[FirewallRule],
    findings: list[Finding],
) -> list[dict]:
    checks = []
    enabled_rules = [r for r in rules if r.enabled]

    # ── CIS 4.1 — No shadow rules ────────────────────────────────────────────
    shadow = _count_by_type(findings, "shadowed_rule")
    checks.append(_check(
        check_id="CIS-4.1",
        control_ref="CIS Control 4.4",
        category="Secure Configuration",
        title="No shadowed rules (unreachable rules due to ordering)",
        status=FAIL if shadow > 0 else PASS,
        severity=SEV_HIGH if shadow > 0 else SEV_INFO,
        detail=(
            f"{shadow} rule(s) are completely shadowed by earlier rules and will never be evaluated. "
            "Shadowed rules often indicate policy drift or manual error."
            if shadow > 0 else
            "No shadowed rules detected."
        ),
        recommendation="Remove or reorder shadowed rules. Use the shadow findings to identify the specific rule pairs." if shadow > 0 else "",
        evidence={"shadowed_rules": shadow},
    ))

    # ── CIS 4.2 — Minimal access (no ANY/ANY/ANY) ────────────────────────────
    perm = _count_by_type(findings, "overly_permissive")
    checks.append(_check(
        check_id="CIS-4.2",
        control_ref="CIS Control 4.1 / 12.2",
        category="Secure Configuration",
        title="Apply principle of least access — no unrestricted rules",
        status=FAIL if perm > 0 else PASS,
        severity=SEV_HIGH if perm > 0 else SEV_INFO,
        detail=(
            f"{perm} rule(s) grant unrestricted access (Any Source, Any Destination, or Any Service). "
            "CIS requires traffic to be restricted to defined, documented needs only."
            if perm > 0 else
            "No unrestricted rules detected."
        ),
        recommendation="Replace Any/Any with specific source/destination/service objects." if perm > 0 else "",
        evidence={"permissive_rules": perm},
    ))

    # ── CIS 4.3 — High-risk services blocked ─────────────────────────────────
    risky = _count_by_type(findings, "risky_service")
    checks.append(_check(
        check_id="CIS-4.3",
        control_ref="CIS Control 4.5",
        category="Service Restriction",
        title="Block or restrict high-risk services (RDP, Telnet, FTP, SMB, SQL)",
        status=FAIL if risky > 0 else PASS,
        severity=SEV_HIGH if risky > 0 else SEV_INFO,
        detail=(
            f"{risky} rule(s) permit known high-risk services. CIS recommends that "
            "services like Telnet, FTP, RDP, and SMB be blocked unless explicitly required and MFA-protected."
            if risky > 0 else
            "No rules permitting uncontrolled high-risk services detected."
        ),
        recommendation="Replace legacy protocols with secure alternatives. If required, restrict to specific source IPs and require MFA." if risky > 0 else "",
        evidence={"risky_service_rules": risky},
    ))

    # ── CIS 4.4 — All rules logged ───────────────────────────────────────────
    no_log = _count_by_type(findings, "no_logging")
    checks.append(_check(
        check_id="CIS-4.4",
        control_ref="CIS Control 8.2",
        category="Audit & Logging",
        title="All firewall rules must generate audit logs",
        status=FAIL if no_log > 0 else PASS,
        severity=SEV_HIGH if no_log > 0 else SEV_INFO,
        detail=(
            f"{no_log} rule(s) have logging disabled. CIS requires all allowed and denied "
            "traffic to be logged for incident detection and forensics."
            if no_log > 0 else
            "All rules have logging enabled."
        ),
        recommendation="Enable logging on all rules. At minimum, log all deny and all internet-bound traffic." if no_log > 0 else "",
        evidence={"unlogged_rules": no_log},
    ))

    # ── CIS 4.5 — Remove unused rules ────────────────────────────────────────
    zero_hit = _count_by_type(findings, "zero_hit_rule", "low_usage_rule")
    checks.append(_check(
        check_id="CIS-4.5",
        control_ref="CIS Control 4.7",
        category="Attack Surface Reduction",
        title="Remove unused or low-activity rules to reduce attack surface",
        status=WARN if zero_hit > 0 else PASS,
        severity=SEV_MEDIUM if zero_hit > 0 else SEV_INFO,
        detail=(
            f"{zero_hit} rule(s) show zero or low hit counts. "
            "CIS recommends removing rules that no longer serve an active business function."
            if zero_hit > 0 else
            "No unused rules detected."
        ),
        recommendation="Disable rules with zero hits for 90+ days, obtain business confirmation, then remove." if zero_hit > 0 else "",
        evidence={"unused_rules": zero_hit},
    ))

    # ── CIS 4.6 — Rule documentation ─────────────────────────────────────────
    no_doc = _count_by_type(findings, "no_documentation")
    checks.append(_check(
        check_id="CIS-4.6",
        control_ref="CIS Control 4.2",
        category="Change Management",
        title="Document all active rules with owner and purpose",
        status=FAIL if no_doc > 0 else PASS,
        severity=SEV_MEDIUM if no_doc > 0 else SEV_INFO,
        detail=(
            f"{no_doc} rule(s) lack documentation. CIS requires each rule to have "
            "documented owner, business purpose, and change approval reference."
            if no_doc > 0 else
            "All rules are documented."
        ),
        recommendation="Add rule comments with: owner name, business justification, ticket reference, and review date." if no_doc > 0 else "",
        evidence={"undocumented_rules": no_doc},
    ))

    # ── CIS 4.7 — Clean objects: no unused objects ───────────────────────────
    unused_obj = _count_by_type(findings, "unused_object")
    empty_grp  = _count_by_type(findings, "empty_group")
    checks.append(_check(
        check_id="CIS-4.7",
        control_ref="CIS Control 4.3",
        category="Object Hygiene",
        title="Remove unused network objects and empty groups",
        status=WARN if (unused_obj + empty_grp) > 0 else PASS,
        severity=SEV_LOW if (unused_obj + empty_grp) > 0 else SEV_INFO,
        detail=(
            f"{unused_obj} unused object(s) and {empty_grp} empty group(s) found. "
            "Stale objects increase management complexity and can be repurposed maliciously."
            if (unused_obj + empty_grp) > 0 else
            "No unused objects or empty groups found."
        ),
        recommendation="Periodically clean up unused objects. Archive before deletion to maintain audit trail." if (unused_obj + empty_grp) > 0 else "",
        evidence={"unused_objects": unused_obj, "empty_groups": empty_grp},
    ))

    # ── CIS 4.8 — No duplicate objects ──────────────────────────────────────
    dup_obj = _count_by_type(findings, "duplicate_object")
    checks.append(_check(
        check_id="CIS-4.8",
        control_ref="CIS Control 4.3",
        category="Object Hygiene",
        title="Eliminate duplicate network objects",
        status=WARN if dup_obj > 0 else PASS,
        severity=SEV_LOW if dup_obj > 0 else SEV_INFO,
        detail=(
            f"{dup_obj} duplicate object(s) found. Duplicate objects cause inconsistency "
            "when updating access rules — changes to one copy may not propagate to others."
            if dup_obj > 0 else
            "No duplicate objects found."
        ),
        recommendation="Consolidate duplicate objects into single canonical definitions. Update all rule references." if dup_obj > 0 else "",
        evidence={"duplicate_objects": dup_obj},
    ))

    # ── CIS 4.9 — No broad network objects (/8, /16) ────────────────────────
    broad = _count_by_type(findings, "broad_network")
    checks.append(_check(
        check_id="CIS-4.9",
        control_ref="CIS Control 12.2",
        category="Network Segmentation",
        title="Avoid overly broad network objects (/8, /16 CIDR ranges)",
        status=FAIL if broad > 0 else PASS,
        severity=SEV_MEDIUM if broad > 0 else SEV_INFO,
        detail=(
            f"{broad} network object(s) with overly broad CIDR masks detected (/8, /12, /16). "
            "These can inadvertently allow access to large swaths of IP space."
            if broad > 0 else
            "All network objects use appropriately scoped CIDR ranges."
        ),
        recommendation="Replace broad network objects with more specific ranges. Document why a broad range is necessary if legitimately required." if broad > 0 else "",
        evidence={"broad_network_objects": broad},
    ))

    # ── CIS 4.10 — Implicit deny ─────────────────────────────────────────────
    last = _last_rule(rules)
    last_is_deny = last and _is_deny(last.action)
    checks.append(_check(
        check_id="CIS-4.10",
        control_ref="CIS Control 12.4",
        category="Secure Configuration",
        title="Implicit deny-all: last rule must deny all unmatched traffic",
        status=PASS if last_is_deny else FAIL,
        severity=SEV_HIGH if not last_is_deny else SEV_INFO,
        detail=(
            "Policy ends with an explicit deny-all rule — compliant with CIS implicit deny requirement."
            if last_is_deny else
            f"Last rule '{last.rule_name if last else 'N/A'}' action='{last.action if last else 'N/A'}' is NOT a deny. "
            "All unmatched traffic should be denied by default."
        ),
        recommendation="Add an explicit deny-all rule as the final rule in the policy." if not last_is_deny else "",
        evidence={"last_rule_action": last.action if last else None},
    ))

    total  = len(checks)
    passed = sum(1 for c in checks if c["status"] == PASS)
    failed = sum(1 for c in checks if c["status"] == FAIL)
    warned = sum(1 for c in checks if c["status"] == WARN)
    score  = int(passed / total * 100) if total else 0
    grade  = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 50 else "F"

    return {
        "framework": "cis",
        "framework_name": "CIS Controls v8",
        "policy_id": policy.id,
        "firewall_name": policy.firewall_name,
        "vendor": policy.vendor,
        "score": score,
        "grade": grade,
        "summary": {"total": total, "passed": passed, "failed": failed, "warned": warned},
        "checks": checks,
    }


# ════════════════════════════════════════════════════════════════════════════
# NIST CSF 2.0 checks
# ════════════════════════════════════════════════════════════════════════════

def _nist_checks(
    policy: FirewallPolicy,
    rules: list[FirewallRule],
    findings: list[Finding],
) -> list[dict]:
    checks = []

    # GOVERN — Policy documentation
    no_doc = _count_by_type(findings, "no_documentation")
    checks.append(_check(
        check_id="NIST-GV.PO-01",
        control_ref="NIST CSF 2.0 GV.PO-01",
        category="Govern",
        title="Firewall rules have organisational policy documentation",
        status=FAIL if no_doc > 0 else PASS,
        severity=SEV_MEDIUM if no_doc > 0 else SEV_INFO,
        detail=(
            f"{no_doc} rule(s) lack documented justification. NIST requires cybersecurity policies "
            "to be documented, approved, and communicated."
            if no_doc > 0 else "All rules are documented."
        ),
        recommendation="Implement a rule documentation policy: each rule must reference a change ticket and owner." if no_doc > 0 else "",
    ))

    # IDENTIFY — Asset inventory
    total_rules = len([r for r in rules if r.enabled])
    checks.append(_check(
        check_id="NIST-ID.AM-03",
        control_ref="NIST CSF 2.0 ID.AM-03",
        category="Identify",
        title="Network communication flows are documented and inventoried",
        status=WARN if total_rules > 200 else PASS,
        severity=SEV_LOW if total_rules > 200 else SEV_INFO,
        detail=(
            f"{total_rules} active rules found. Large rule sets increase risk of undocumented flows. "
            "Regular review helps ensure the inventory remains accurate."
            if total_rules > 200 else
            f"{total_rules} active rules — manageable rule set size."
        ),
        recommendation="Perform a semi-annual review of all rules. Use the findings workflow to track review status." if total_rules > 200 else "",
        evidence={"active_rules": total_rules},
    ))

    # PROTECT — Access control
    perm = _count_by_type(findings, "overly_permissive")
    checks.append(_check(
        check_id="NIST-PR.AC-05",
        control_ref="NIST CSF 2.0 PR.AC-05",
        category="Protect",
        title="Network integrity protected through least-privilege access controls",
        status=FAIL if perm > 0 else PASS,
        severity=SEV_HIGH if perm > 0 else SEV_INFO,
        detail=(
            f"{perm} overly permissive rule(s) detected. Least-privilege access requires "
            "traffic to be restricted to the minimum required."
            if perm > 0 else "All rules follow least-privilege principles."
        ),
        recommendation="Restrict all rules to specific source/destination/service combinations." if perm > 0 else "",
    ))

    # PROTECT — Protective technology
    risky = _count_by_type(findings, "risky_service")
    no_log = _count_by_type(findings, "no_logging")
    checks.append(_check(
        check_id="NIST-PR.PT-04",
        control_ref="NIST CSF 2.0 PR.PT-04",
        category="Protect",
        title="Communications and control networks protected (no high-risk uncontrolled services)",
        status=FAIL if risky > 0 or no_log > 0 else PASS,
        severity=SEV_HIGH if risky > 0 else (SEV_MEDIUM if no_log > 0 else SEV_INFO),
        detail=(
            f"Issues: {risky} high-risk service rule(s), {no_log} unlogged rule(s). "
            "NIST requires communications networks to be protected and monitored."
            if risky > 0 or no_log > 0 else
            "No high-risk services or unlogged rules detected."
        ),
        recommendation="Block high-risk services and ensure all rules generate log entries." if risky > 0 or no_log > 0 else "",
    ))

    # DETECT — Anomaly detection (proxy: logging coverage)
    checks.append(_check(
        check_id="NIST-DE.CM-01",
        control_ref="NIST CSF 2.0 DE.CM-01",
        category="Detect",
        title="Networks monitored to detect potential cybersecurity events",
        status=FAIL if no_log > 0 else PASS,
        severity=SEV_HIGH if no_log > 0 else SEV_INFO,
        detail=(
            f"{no_log} rule(s) with logging disabled. Without logs, anomalous traffic cannot be detected."
            if no_log > 0 else
            "All traffic rules generate logs — network monitoring baseline met."
        ),
        recommendation="Enable logging on all rules and forward to SIEM for correlation." if no_log > 0 else "",
        evidence={"unlogged_rules": no_log},
    ))

    # RESPOND — Baseline / change tracking
    shadow = _count_by_type(findings, "shadowed_rule")
    dup    = _count_by_type(findings, "duplicate_rule")
    checks.append(_check(
        check_id="NIST-RS.MA-01",
        control_ref="NIST CSF 2.0 RS.MA-01",
        category="Respond",
        title="Policy anomalies (shadowed/duplicate rules) addressed to support incident response",
        status=WARN if (shadow + dup) > 0 else PASS,
        severity=SEV_MEDIUM if (shadow + dup) > 0 else SEV_INFO,
        detail=(
            f"{shadow + dup} policy anomalies (shadowed/duplicate rules) may complicate incident response "
            "by obscuring effective rule intent."
            if (shadow + dup) > 0 else
            "No policy anomalies detected."
        ),
        recommendation="Resolve shadowed and duplicate rules to ensure policy intent is clear during incident response." if (shadow + dup) > 0 else "",
    ))

    # RECOVER — Clean policy state
    temp = _count_by_type(findings, "temporary_rule")
    checks.append(_check(
        check_id="NIST-RC.RP-01",
        control_ref="NIST CSF 2.0 RC.RP-01",
        category="Recover",
        title="Temporary emergency rules removed after incident recovery",
        status=WARN if temp > 0 else PASS,
        severity=SEV_LOW if temp > 0 else SEV_INFO,
        detail=(
            f"{temp} suspected temporary rule(s) detected. Rules created during incidents "
            "must be removed or regularised after recovery is complete."
            if temp > 0 else
            "No suspected temporary rules detected."
        ),
        recommendation="Review all temporary rules. Remove or formally document those that have been promoted to permanent." if temp > 0 else "",
    ))

    total  = len(checks)
    passed = sum(1 for c in checks if c["status"] == PASS)
    failed = sum(1 for c in checks if c["status"] == FAIL)
    warned = sum(1 for c in checks if c["status"] == WARN)
    score  = int(passed / total * 100) if total else 0
    grade  = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 50 else "F"

    return {
        "framework": "nist",
        "framework_name": "NIST CSF 2.0",
        "policy_id": policy.id,
        "firewall_name": policy.firewall_name,
        "vendor": policy.vendor,
        "score": score,
        "grade": grade,
        "summary": {"total": total, "passed": passed, "failed": failed, "warned": warned},
        "checks": checks,
    }


# ════════════════════════════════════════════════════════════════════════════
# ISO 27001:2022 checks
# ════════════════════════════════════════════════════════════════════════════

def _iso27001_checks(
    policy: FirewallPolicy,
    rules: list[FirewallRule],
    findings: list[Finding],
) -> list[dict]:
    checks = []

    perm    = _count_by_type(findings, "overly_permissive")
    no_log  = _count_by_type(findings, "no_logging")
    no_doc  = _count_by_type(findings, "no_documentation")
    risky   = _count_by_type(findings, "risky_service")
    shadow  = _count_by_type(findings, "shadowed_rule")
    dup     = _count_by_type(findings, "duplicate_rule")
    zero_hit= _count_by_type(findings, "zero_hit_rule")
    last    = _last_rule(rules)
    last_deny = last and _is_deny(last.action)

    checks.append(_check(
        check_id="ISO-A.8.20",
        control_ref="ISO 27001:2022 A.8.20",
        category="Network Security",
        title="Network controls: firewall rules restrict traffic to business need",
        status=FAIL if perm > 0 else PASS,
        severity=SEV_HIGH if perm > 0 else SEV_INFO,
        detail=f"{perm} overly permissive rule(s) violate network security controls." if perm > 0 else "Network controls in place.",
        recommendation="Restrict all rules to documented business necessity." if perm > 0 else "",
    ))

    checks.append(_check(
        check_id="ISO-A.8.22",
        control_ref="ISO 27001:2022 A.8.22",
        category="Network Segregation",
        title="Networks segregated based on information classification",
        status=WARN if perm > 0 else PASS,
        severity=SEV_MEDIUM if perm > 0 else SEV_INFO,
        detail=f"{perm} broad access rule(s) may violate network segregation." if perm > 0 else "Network segregation appears in place.",
        recommendation="Apply zone-based firewall policies aligned to data classification tiers." if perm > 0 else "",
    ))

    checks.append(_check(
        check_id="ISO-A.8.15",
        control_ref="ISO 27001:2022 A.8.15",
        category="Logging",
        title="Logging enabled for all firewall traffic",
        status=FAIL if no_log > 0 else PASS,
        severity=SEV_HIGH if no_log > 0 else SEV_INFO,
        detail=f"{no_log} rule(s) without logging violate ISO logging requirements." if no_log > 0 else "All rules generate logs.",
        recommendation="Enable logging on all rules." if no_log > 0 else "",
    ))

    checks.append(_check(
        check_id="ISO-A.5.37",
        control_ref="ISO 27001:2022 A.5.37",
        category="Change Management",
        title="Operating procedures documented (rule justification and change history)",
        status=FAIL if no_doc > 0 else PASS,
        severity=SEV_MEDIUM if no_doc > 0 else SEV_INFO,
        detail=f"{no_doc} undocumented rule(s)." if no_doc > 0 else "All rules documented.",
        recommendation="Document business justification and change approver for each rule." if no_doc > 0 else "",
    ))

    checks.append(_check(
        check_id="ISO-A.8.6",
        control_ref="ISO 27001:2022 A.8.6",
        category="Capacity Management",
        title="Policy complexity managed — no redundant or shadow rules",
        status=WARN if (shadow + dup) > 0 else PASS,
        severity=SEV_MEDIUM if (shadow + dup) > 0 else SEV_INFO,
        detail=f"{shadow + dup} redundant rule(s) increase policy complexity unnecessarily." if (shadow + dup) > 0 else "No redundant rules.",
        recommendation="Remove shadowed and duplicate rules through change management." if (shadow + dup) > 0 else "",
    ))

    checks.append(_check(
        check_id="ISO-A.8.3",
        control_ref="ISO 27001:2022 A.8.3",
        category="Information Access Restriction",
        title="High-risk services blocked or explicitly authorised",
        status=FAIL if risky > 0 else PASS,
        severity=SEV_HIGH if risky > 0 else SEV_INFO,
        detail=f"{risky} rule(s) permit high-risk services without adequate controls." if risky > 0 else "High-risk services appropriately controlled.",
        recommendation="Replace insecure protocols with secure alternatives. Add explicit approval for any required exceptions." if risky > 0 else "",
    ))

    checks.append(_check(
        check_id="ISO-A.8.20-DENY",
        control_ref="ISO 27001:2022 A.8.20 (default deny)",
        category="Network Security",
        title="Default-deny: all unmatched traffic denied",
        status=PASS if last_deny else FAIL,
        severity=SEV_HIGH if not last_deny else SEV_INFO,
        detail="Implicit deny-all present." if last_deny else "No deny-all rule at end of policy.",
        recommendation="Add explicit deny-all as the last rule." if not last_deny else "",
    ))

    total  = len(checks)
    passed = sum(1 for c in checks if c["status"] == PASS)
    failed = sum(1 for c in checks if c["status"] == FAIL)
    warned = sum(1 for c in checks if c["status"] == WARN)
    score  = int(passed / total * 100) if total else 0
    grade  = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 50 else "F"

    return {
        "framework": "iso27001",
        "framework_name": "ISO 27001:2022",
        "policy_id": policy.id,
        "firewall_name": policy.firewall_name,
        "vendor": policy.vendor,
        "score": score,
        "grade": grade,
        "summary": {"total": total, "passed": passed, "failed": failed, "warned": warned},
        "checks": checks,
    }


# ════════════════════════════════════════════════════════════════════════════
# GDPR Article 32 checks
# ════════════════════════════════════════════════════════════════════════════

def _gdpr_checks(
    policy: FirewallPolicy,
    rules: list[FirewallRule],
    findings: list[Finding],
) -> list[dict]:
    """
    GDPR Article 32 — Security of Processing (Regulation (EU) 2016/679)
    Maps firewall controls to the technical and organisational measures
    required to ensure a level of security appropriate to the risk of
    processing personal data.

    Key articles covered:
      Art. 32(1)(a) — Pseudonymisation and encryption of personal data
      Art. 32(1)(b) — Ongoing confidentiality, integrity, availability
      Art. 32(1)(c) — Ability to restore availability and access
      Art. 32(1)(d) — Regular testing, assessing, and evaluating
      Art. 5(1)(f)  — Integrity and confidentiality principle
      Art. 25       — Data protection by design and by default
    """
    checks = []
    enabled_rules = [r for r in rules if r.enabled]
    allow_rules   = [r for r in enabled_rules if not _is_deny(r.action)]

    # ── Art. 32(1)(a) — Encryption: prohibit cleartext protocols ─────────────
    risky_rules = _findings_by_type(findings, "risky_service")
    risky = len(risky_rules)
    unencrypted_protos = [
        f.description for f in risky_rules
        if any(svc in (f.description or "").lower() for svc in ("telnet", "ftp", "http", "rsh", "rlogin"))
    ]
    checks.append(_check(
        check_id="GDPR-32-1",
        control_ref="Art. 32(1)(a) Encryption of personal data",
        category="Encryption & Pseudonymisation",
        title="Prohibit cleartext protocols that expose personal data in transit",
        status=FAIL if unencrypted_protos else (WARN if risky > 0 else PASS),
        severity=SEV_HIGH if unencrypted_protos else (SEV_MEDIUM if risky > 0 else SEV_INFO),
        detail=(
            f"{len(unencrypted_protos)} cleartext protocol rule(s) detected "
            f"(Telnet, plain FTP, HTTP). These protocols transmit data in the clear and "
            "must not be used to access or transport personal data under GDPR Art. 32(1)(a)."
            if unencrypted_protos else
            f"No cleartext protocol rules detected. {risky} risky-service finding(s) present for review."
            if risky > 0 else
            "No cleartext protocol rules detected."
        ),
        recommendation=(
            "Remove Telnet, plain FTP, and HTTP permit rules immediately. "
            "Replace with SSH (22), SFTP/FTPS, and HTTPS (443). Enforce TLS 1.2+ minimum for all "
            "flows that may carry personal data."
        ) if unencrypted_protos else "",
        evidence={"cleartext_protocol_findings": len(unencrypted_protos), "risky_service_total": risky},
    ))

    # ── Art. 32(1)(b) + Art. 5(1)(f) — Confidentiality: restrict access ─────
    perm = _count_by_type(findings, "overly_permissive")
    broad = _count_by_type(findings, "broad_network")
    access_issues = perm + broad
    checks.append(_check(
        check_id="GDPR-32-2",
        control_ref="Art. 32(1)(b) + Art. 5(1)(f) Confidentiality",
        category="Access Control",
        title="Ensure ongoing confidentiality — restrict access to personal data systems",
        status=FAIL if access_issues > 0 else PASS,
        severity=SEV_HIGH if access_issues > 0 else SEV_INFO,
        detail=(
            f"{access_issues} rule(s) allow overly broad network access "
            f"(overly permissive: {perm}, broad CIDR objects: {broad}). "
            "GDPR's integrity and confidentiality principle requires access to systems "
            "processing personal data to be limited to authorised parties only."
            if access_issues > 0 else
            "Access control rules appear appropriately restricted. No overly-broad rules detected."
        ),
        recommendation=(
            "Replace Any-source or /8–/16 CIDR objects with specific named hosts or subnets. "
            "Apply the principle of least privilege: each rule should permit only the minimum "
            "access required for the documented business purpose."
        ) if access_issues > 0 else "",
        evidence={"overly_permissive": perm, "broad_network": broad},
    ))

    # ── Art. 32(1)(b) — Integrity: eliminate policy inconsistencies ──────────
    shadow = _count_by_type(findings, "shadowed_rule")
    dup    = _count_by_type(findings, "duplicate_rule")
    integrity_issues = shadow + dup
    checks.append(_check(
        check_id="GDPR-32-3",
        control_ref="Art. 32(1)(b) Integrity of processing",
        category="Policy Integrity",
        title="Eliminate shadowed and duplicate rules that undermine policy integrity",
        status=FAIL if integrity_issues > 0 else PASS,
        severity=SEV_MEDIUM if integrity_issues > 0 else SEV_INFO,
        detail=(
            f"{shadow} shadowed rule(s) and {dup} duplicate rule(s) found. "
            "Policy inconsistencies undermine integrity, make audits unreliable, and may "
            "conceal unintended access paths to personal data — contrary to Art. 32(1)(b)."
            if integrity_issues > 0 else
            "No shadowed or duplicate rules detected. Policy integrity appears sound."
        ),
        recommendation=(
            "Remove or consolidate shadowed/duplicate rules in the next change-management cycle. "
            "Maintain a rule-ownership register linking each rule to its approved change ticket."
        ) if integrity_issues > 0 else "",
        evidence={"shadowed_rules": shadow, "duplicate_rules": dup},
    ))

    # ── Art. 32(1)(b) — Availability: default-deny and VPN controls ──────────
    last = _last_rule(rules)
    has_default_deny = last is not None and _is_deny(last.action)
    vpn = _count_by_type(findings, "vpn_access")
    checks.append(_check(
        check_id="GDPR-32-4",
        control_ref="Art. 32(1)(b)+(c) Availability & resilience",
        category="Network Security",
        title="Enforce default-deny policy to protect availability of personal data systems",
        status=(WARN if vpn > 0 else PASS) if has_default_deny else FAIL,
        severity=SEV_HIGH if not has_default_deny else (SEV_MEDIUM if vpn > 0 else SEV_INFO),
        detail=(
            "No implicit-deny rule at the end of the policy. Unrestricted traffic may reach "
            "personal-data systems — a direct breach of Art. 32 confidentiality and availability obligations."
            if not has_default_deny else
            f"Default-deny rule present. {vpn} broad VPN access rule(s) detected — "
            "overly broad remote-access policies increase exposure of personal-data systems."
            if vpn > 0 else
            "Default-deny rule in place. No broad VPN access issues detected."
        ),
        recommendation=(
            "Add an explicit deny-all rule as the last entry in every policy. "
            "Restrict VPN tunnel access to named subnets that genuinely require it; "
            "avoid split-tunnel configurations that grant access to all internal ranges."
        ) if not has_default_deny or vpn > 0 else "",
        evidence={"has_default_deny": has_default_deny, "broad_vpn_rules": vpn},
    ))

    # ── Art. 32(1)(d) — Regular testing: logging and audit trail ─────────────
    no_log = _count_by_type(findings, "no_logging")
    total_allow = len(allow_rules)
    log_pct = int((1 - no_log / max(total_allow, 1)) * 100)
    checks.append(_check(
        check_id="GDPR-32-5",
        control_ref="Art. 32(1)(d) Regular testing and evaluation",
        category="Audit & Logging",
        title="Enable logging on all rules to support ongoing security evaluation",
        status=FAIL if no_log > 0 else PASS,
        severity=SEV_HIGH if no_log > (total_allow * 0.25) else (SEV_MEDIUM if no_log > 0 else SEV_INFO),
        detail=(
            f"{no_log} of {total_allow} allow rule(s) ({100 - log_pct}%) have logging disabled. "
            "GDPR Art. 32(1)(d) requires organisations to regularly test and evaluate the "
            "effectiveness of security measures — impossible without complete audit logs."
            if no_log > 0 else
            "All permit rules appear to have logging enabled. Audit trail is intact."
        ),
        recommendation=(
            "Enable logging on every permit rule. Forward firewall logs to a centralised SIEM. "
            "Under GDPR Art. 30(1) and recital 85, retain logs sufficient to demonstrate compliance "
            "and support breach notification within 72 hours (Art. 33)."
        ) if no_log > 0 else "",
        evidence={"rules_without_logging": no_log, "total_allow_rules": total_allow, "log_coverage_pct": log_pct},
    ))

    # ── Art. 25 — Data protection by design: remove stale access grants ──────
    zero_hit = _count_by_type(findings, "zero_hit_rule")
    checks.append(_check(
        check_id="GDPR-25-1",
        control_ref="Art. 25 Data protection by design and by default",
        category="Access Control",
        title="Remove zero-hit rules — enforce data-minimisation by default",
        status=WARN if zero_hit > 0 else PASS,
        severity=SEV_MEDIUM if zero_hit > 0 else SEV_INFO,
        detail=(
            f"{zero_hit} rule(s) with zero recorded hits. Under GDPR's data-minimisation "
            "and privacy-by-default principles (Art. 25), access that is never used should be revoked. "
            "These rules may represent orphaned grants from former staff, vendors, or decommissioned systems."
            if zero_hit > 0 else
            "No zero-hit rules detected. Access grants appear to reflect active usage."
        ),
        recommendation=(
            "Review each zero-hit rule with the rule owner. If the access is no longer needed, "
            "disable and schedule removal after a change-management review. "
            "Conduct a formal access-recertification exercise at least annually."
        ) if zero_hit > 0 else "",
        evidence={"zero_hit_rules": zero_hit},
    ))

    # ── Art. 32 + Art. 33 — Risk management: temporary / expired exceptions ──
    temp = _count_by_type(findings, "temporary_rule")
    expired = _count_by_type(findings, "expired_rule")
    exception_issues = temp + expired
    checks.append(_check(
        check_id="GDPR-32-6",
        control_ref="Art. 32 + Art. 33 Risk management",
        category="Risk Management",
        title="Control temporary access exceptions to prevent unreviewed exposure",
        status=FAIL if expired > 0 else (WARN if temp > 0 else PASS),
        severity=SEV_HIGH if expired > 0 else (SEV_MEDIUM if temp > 0 else SEV_INFO),
        detail=(
            f"{expired} expired schedule(s) and {temp} temporary rule(s) detected. "
            "Unreviewed or expired exceptions represent ongoing uncontrolled access risk. "
            "A security incident through such a gap may trigger GDPR Art. 33 breach notification."
            if exception_issues > 0 else
            "No expired or uncontrolled temporary rules detected."
        ),
        recommendation=(
            "Expire or remove stale temporary rules immediately. Every exception must carry a "
            "ticket reference, approved end-date, and named owner. Review quarterly and document "
            "risk-acceptance decisions in your Art. 30 Records of Processing Activities."
        ) if exception_issues > 0 else "",
        evidence={"temporary_rules": temp, "expired_rules": expired},
    ))

    # Score
    total  = len(checks)
    passed = sum(1 for c in checks if c["status"] == PASS)
    failed = sum(1 for c in checks if c["status"] == FAIL)
    warned = sum(1 for c in checks if c["status"] == WARN)
    score  = int(passed / total * 100) if total else 0
    grade  = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 50 else "F"

    return {
        "framework": "gdpr",
        "framework_name": "GDPR Article 32",
        "policy_id": policy.id,
        "firewall_name": policy.firewall_name,
        "vendor": policy.vendor,
        "score": score,
        "grade": grade,
        "summary": {"total": total, "passed": passed, "failed": failed, "warned": warned},
        "checks": checks,
    }


# ════════════════════════════════════════════════════════════════════════════
# Main entry point
# ════════════════════════════════════════════════════════════════════════════

SUPPORTED_FRAMEWORKS = {
    "pci-dss":  ("PCI-DSS v4.0",    _pci_dss_checks),
    "cis":      ("CIS Controls v8", _cis_checks),
    "nist":     ("NIST CSF 2.0",    _nist_checks),
    "iso27001": ("ISO 27001:2022",  _iso27001_checks),
    "gdpr":     ("GDPR Art. 32",    _gdpr_checks),
}


def run_compliance(policy_id: str, framework: str, db: Session) -> dict:
    """
    Run a compliance framework check against a policy.

    Args:
        policy_id:  UUID of the FirewallPolicy
        framework:  one of 'pci-dss', 'cis', 'nist', 'iso27001'
        db:         SQLAlchemy session

    Returns:
        Compliance result dict with score, grade, and per-check results.
    """
    framework = framework.lower()
    if framework not in SUPPORTED_FRAMEWORKS:
        raise ValueError(f"Unknown framework '{framework}'. Supported: {list(SUPPORTED_FRAMEWORKS)}")

    policy = db.query(FirewallPolicy).filter(FirewallPolicy.id == policy_id).first()
    if not policy:
        raise ValueError(f"Policy {policy_id} not found")

    rules    = (
        db.query(FirewallRule)
        .filter(FirewallRule.policy_id == policy_id)
        .order_by(FirewallRule.rule_number)
        .all()
    )
    findings = (
        db.query(Finding)
        .filter(Finding.policy_id == policy_id)
        .all()
    )

    _, check_fn = SUPPORTED_FRAMEWORKS[framework]
    return check_fn(policy, rules, findings)


def run_all_frameworks(policy_id: str, db: Session) -> dict:
    """Run all compliance frameworks and return an aggregate summary."""
    results = {}
    for fw_key in SUPPORTED_FRAMEWORKS:
        try:
            results[fw_key] = run_compliance(policy_id, fw_key, db)
        except Exception as exc:
            results[fw_key] = {"error": str(exc), "framework": fw_key}
    return results
