"""Per-vendor remediation guidance for findings.

Findings carry a generic, change-management-phrased recommendation (see
recommendation_library). This module adds vendor-specific *where to look and
what to change* guidance for FortiGate, Check Point, Palo Alto (PAN-OS),
Cisco ASA, and Huawei USG.

SAFETY: every entry is review/validation guidance only. The tool never pushes a
change; all modifications must go through the approved change-management
process. The "change" text describes what an engineer would request/perform
manually, not an action the tool takes.
"""
from typing import Optional

READ_ONLY_NOTE = (
    "Review-only guidance. PolicyInsight does not modify firewall configuration — "
    "validate findings and implement any change through your approved change-management process."
)

# ── Finding type → remediation category ──────────────────────────────────────
CATEGORY_OF = {
    # Review & remove/consolidate a rule
    "disabled_rule": "review_remove", "zero_hit_rule": "review_remove",
    "low_usage_rule": "review_remove", "duplicate_rule": "review_remove",
    "shadowed_rule": "review_remove", "temporary_rule": "review_remove",
    "expired_rule": "review_remove", "mergeable_rules": "review_remove",
    # Tighten source/destination scope
    "overly_permissive": "restrict_access", "inbound_from_internet": "restrict_access",
    "lateral_movement_risk": "restrict_access", "vpn_access": "restrict_access",
    "broad_network": "restrict_access",
    # Restrict / replace a service or exposed port
    "risky_service": "restrict_service", "rdp_exposed": "restrict_service",
    "ssh_exposed": "restrict_service", "database_exposed": "restrict_service",
    "cleartext_service": "restrict_service", "service_range": "restrict_service",
    # Enable logging
    "no_logging": "enable_logging", "no_cleanup_rule": "enable_logging",
    # Object cleanup
    "unused_object": "remove_object", "duplicate_object": "remove_object",
    "empty_group": "remove_object", "large_group": "remove_object",
    # Documentation / naming
    "no_documentation": "documentation", "naming_quality": "documentation",
    # Ordering / structure
    "rule_order_optimization": "reorder", "large_rule_section": "reorder",
}

CATEGORY_LABEL = {
    "review_remove": "Review & remove/consolidate the rule",
    "restrict_access": "Restrict source/destination scope",
    "restrict_service": "Restrict or replace the service",
    "enable_logging": "Enable logging",
    "remove_object": "Clean up the object",
    "documentation": "Document / rename the rule",
    "reorder": "Reorder / restructure the rule base",
}

# ── Vendor guidance per category ─────────────────────────────────────────────
# Each entry: how to verify (read-only) + what change to request.
TEMPLATES = {
    "FortiGate": {
        "review_remove": "Verify: `show firewall policy <id>` and check the hit count in GUI under Policy & Objects → Firewall Policy (Sessions/Bytes columns), or `diagnose firewall iprope show`. Change request: disable then, after a soak period, delete the policy via Policy & Objects → Firewall Policy.",
        "restrict_access": "Verify: open the policy in Policy & Objects → Firewall Policy and review Source/Destination (avoid `all`). Change request: replace `all`/broad address objects with specific address objects or groups under Policy & Objects → Addresses.",
        "restrict_service": "Verify: review the Service column and `config firewall service custom`. Change request: replace ALL/broad services with specific service objects; for risky/cleartext protocols (Telnet/FTP) move to encrypted equivalents and restrict source to management hosts.",
        "enable_logging": "Verify: edit the policy and check `Log Allowed Traffic`. Change request: set Log Allowed Traffic to `All Sessions` (`set logtraffic all`) so denied/allowed traffic is recorded.",
        "remove_object": "Verify: Policy & Objects → Addresses/Services; use `Where Used` to confirm the object/group is unreferenced. Change request: remove the unused object or consolidate duplicates after updating references.",
        "documentation": "Verify: check the policy `Comments` field. Change request: add a comment with owner, ticket reference and purpose; rename per the naming standard.",
        "reorder": "Verify: review policy order in Policy & Objects → Firewall Policy (sequence matters, top-down). Change request: move high-hit policies above unused ones, and split oversized sections using Section/Global labels.",
    },
    "CheckPoint": {
        "review_remove": "Verify: in SmartConsole open the policy, right-click the rule → Hit Count, and check logs in Logs & Monitor. Change request: disable the rule, then remove it via the Access Control policy and Install Policy.",
        "restrict_access": "Verify: review the Source/Destination cells (avoid `Any`). Change request: replace `Any` with specific Host/Network/Group objects, then Install Policy.",
        "restrict_service": "Verify: review the Services & Applications cell. Change request: replace `Any`/broad services with specific service objects; restrict risky/cleartext services to authorized sources and prefer encrypted equivalents.",
        "enable_logging": "Verify: check the Track column. Change request: set Track to `Log` (or `Detailed Log`) so the rule's traffic is recorded.",
        "remove_object": "Verify: select the object → `Where Used` (object References). Change request: delete the unused object or merge duplicates after repointing references; Install Policy.",
        "documentation": "Verify: check the rule Name and Comments columns. Change request: add a name, comment with owner/ticket, and follow the naming convention.",
        "reorder": "Verify: rule order is top-down; review section structure. Change request: reorder rules and split large sections into logical Sections for readability.",
    },
    "PaloAlto": {
        "review_remove": "Verify: Policies → Security; enable the Hit Count / Rule Usage columns (PAN-OS 8.1+) or check Monitor → Traffic. Change request: disable, then delete the rule and Commit (and push from Panorama if managed).",
        "restrict_access": "Verify: review Source/Destination zones and addresses (avoid `any`). Change request: replace `any` with specific address objects/groups and tighten zones; Commit.",
        "restrict_service": "Verify: review Service/Application columns; prefer App-ID over port-based `service-http`. Change request: restrict to specific applications/services, replace cleartext protocols, limit source for management ports; Commit.",
        "enable_logging": "Verify: open the rule → Actions tab → check `Log at Session End`. Change request: enable `Log at Session End` and assign a Log Forwarding profile.",
        "remove_object": "Verify: Objects → Addresses/Address Groups; right-click → `Where Used`. Change request: delete unused objects or consolidate duplicates after repointing references; Commit.",
        "documentation": "Verify: review the rule Description and Tag columns. Change request: add a Description with owner/ticket and apply tags per standard.",
        "reorder": "Verify: rules are evaluated top-down; review order and rule count. Change request: move frequently-matched rules up and split large rulebases; consider Panorama device groups.",
    },
    "CiscoASA": {
        "review_remove": "Verify: `show access-list <name>` shows per-ACE hit counts; `show running-config access-list`. Change request: remove the unused/duplicate/shadowed ACE line (or the object-group entry) via change control.",
        "restrict_access": "Verify: inspect the ACE source/destination (avoid `any`). Change request: replace `any` with specific hosts/network objects or object-groups to scope the ACE.",
        "restrict_service": "Verify: review the ACE service/port and any `object-group service`. Change request: restrict to specific ports, replace cleartext services, and limit management access (SSH/Telnet) to specific sources; disable Telnet in favor of SSH.",
        "enable_logging": "Verify: check whether the ACE has a `log` keyword. Change request: append `log` to the ACE so matches are recorded to syslog.",
        "remove_object": "Verify: `show running-config object` / `object-group`; confirm it is unreferenced. Change request: remove the unused `object`/`object-group` or consolidate duplicates after updating ACL references.",
        "documentation": "Verify: check for `remark` lines above the ACE. Change request: add a `remark` documenting owner/ticket/purpose; adopt a consistent naming scheme.",
        "reorder": "Verify: ACEs are evaluated top-down within an ACL. Change request: reorder ACEs so frequently-matched lines precede unused ones; split very long ACLs logically.",
    },
    "HuaweiUSG": {
        "review_remove": "Verify: `display security-policy rule <name>` and `display firewall session table` / policy hit statistics. Change request: `undo` (disable) the rule, then remove it from the security-policy after the soak period via change control.",
        "restrict_access": "Verify: review `source-address` / `destination-address` (avoid `any`/`address-set` that is too broad). Change request: bind specific address-sets and source/destination zones to scope the rule.",
        "restrict_service": "Verify: review the `service` / `ip service-set` referenced by the rule. Change request: restrict to specific service-sets, replace cleartext protocols, and limit management services to authorized hosts.",
        "enable_logging": "Verify: check for `action permit` with session logging enabled. Change request: enable policy/session logging on the rule so traffic is recorded.",
        "remove_object": "Verify: `display object-group` / `ip address-set`; confirm the set is unreferenced. Change request: remove the unused address-set/service-set or consolidate duplicates after updating references.",
        "documentation": "Verify: review the rule `description`. Change request: add a `description` with owner/ticket/purpose and follow the naming convention.",
        "reorder": "Verify: security-policy rules are matched top-down by order. Change request: move high-traffic rules above unused ones and split large policy sets logically.",
    },
}

_GENERIC = (
    "Locate the affected rule/object in the firewall's management interface, confirm "
    "the finding against the live configuration and traffic logs, and request any change "
    "through your approved change-management process."
)

# Normalize vendor strings coming from parsers / DB to template keys.
_VENDOR_ALIASES = {
    "fortigate": "FortiGate", "forti": "FortiGate",
    "checkpoint": "CheckPoint", "check point": "CheckPoint", "cp": "CheckPoint",
    "paloalto": "PaloAlto", "palo alto": "PaloAlto", "panos": "PaloAlto", "pan-os": "PaloAlto",
    "ciscoasa": "CiscoASA", "cisco asa": "CiscoASA", "cisco": "CiscoASA", "asa": "CiscoASA",
    "huaweiusg": "HuaweiUSG", "huawei": "HuaweiUSG", "huawei usg": "HuaweiUSG",
}


def _vendor_key(vendor: Optional[str]) -> Optional[str]:
    if not vendor:
        return None
    return _VENDOR_ALIASES.get(vendor.strip().lower(), vendor if vendor in TEMPLATES else None)


def get(vendor: Optional[str], finding_type: str) -> dict:
    """Resolve vendor-specific remediation guidance for a finding type."""
    vk = _vendor_key(vendor)
    category = CATEGORY_OF.get(finding_type)
    label = CATEGORY_LABEL.get(category, "Review the finding")
    guidance = None
    if vk and category:
        guidance = TEMPLATES.get(vk, {}).get(category)
    return {
        "vendor": vk or (vendor or "Unknown"),
        "finding_type": finding_type,
        "category": category,
        "category_label": label,
        "guidance": guidance or _GENERIC,
        "vendor_specific": bool(guidance),
        "read_only_note": READ_ONLY_NOTE,
    }
