"""
Centralised recommendation library for PolicyInsight findings.

Every finding_type has an approved, consistent recommendation that is used
across analysis outputs and exported reports. This ensures all engineers see
identical guidance regardless of who ran the analysis.

SAFETY NOTE: All recommendations explicitly require engineer validation and
formal change approval. The tool operates in read-only mode only.
"""
from typing import Optional

# ── Standard recommendation text per finding_type ────────────────────────────

LIBRARY: dict[str, str] = {

    # ── Rule hygiene ──────────────────────────────────────────────────────────
    "disabled_rule": (
        "Review whether this disabled rule still has an active business requirement. "
        "If no requirement exists, raise a change request to remove it — retaining "
        "disabled rules increases policy complexity and creates confusion during audits."
    ),
    "zero_hit_rule": (
        "Confirm the business requirement for this rule before taking any action. "
        "A zero hit count may indicate the rule is unreachable, misconfigured, or no "
        "longer needed. If no valid requirement can be confirmed, raise a change request "
        "for removal through the formal change management process."
    ),
    "low_usage_rule": (
        "Verify whether the access this rule provides is still required. Low usage over "
        "an extended period may indicate the rule is no longer needed. If the business "
        "requirement cannot be confirmed, raise a change request for removal."
    ),
    "overly_permissive": (
        "Review and restrict overly broad fields (source, destination, service) to the "
        "minimum required for business operations. Replace 'Any' with specific IP objects, "
        "subnets, or named groups where possible. All changes require engineer validation "
        "and formal change approval before implementation."
    ),
    "risky_service": (
        "Validate the business requirement for this service. Restrict the source to the "
        "minimum set of authorised hosts and verify that destination systems are hardened. "
        "Consider whether the service can be replaced with a more secure alternative "
        "(e.g. SSH instead of Telnet, SFTP instead of FTP)."
    ),
    "no_logging": (
        "Enable logging on this rule to support security monitoring, incident response, "
        "and compliance requirements. Allow rules without logging create visibility gaps. "
        "All logging changes require change approval before implementation."
    ),
    "temporary_rule": (
        "Confirm whether the temporary or test access this rule provides is still required. "
        "If access is ongoing, rename the rule to reflect its purpose and assign an owner. "
        "If access is no longer needed, raise a change request for removal. Temporary rules "
        "without an expiry date are a common source of policy bloat."
    ),
    "no_documentation": (
        "Add a comment to this rule identifying the business owner, the relevant change "
        "ticket or reference, and the purpose of the access. Rules without documented "
        "justification are difficult to audit and should be reviewed to confirm they remain "
        "required."
    ),
    "naming_quality": (
        "Rename this rule to clearly describe its purpose, the traffic it permits, and the "
        "owning team or application. A good naming convention includes: application name, "
        "source zone/segment, destination zone/segment, and ticket reference."
    ),
    "expired_rule": (
        "Verify the schedule object and confirm whether this rule is still within its "
        "intended active period. If the schedule has expired or no longer reflects the "
        "business requirement, raise a change request to disable or remove the rule."
    ),
    "inoperative_rule": (
        "This rule references an empty group on its source or destination, so it can never "
        "match traffic. Confirm whether the group should be populated (a missed change) or "
        "the rule removed, then raise the appropriate change request."
    ),
    "nat_complexity": (
        "Review this NAT rule to confirm the address translation is accurate, necessary, "
        "and documented. Verify the associated security rule permits only the intended "
        "translated traffic. All NAT changes require engineer validation and change approval."
    ),
    "vpn_access": (
        "Restrict VPN access rules to the minimum required source and destination. "
        "Replace broad network objects with specific host or subnet objects. Ensure VPN "
        "access is reviewed periodically as part of access recertification."
    ),
    "negated_object": (
        "Review rules using negated objects to confirm the intended traffic match is correct. "
        "Negated objects are counterintuitive and may produce unexpected permit/deny decisions. "
        "Consider rewriting the rule using explicit positive objects where possible."
    ),

    # ── Object hygiene ────────────────────────────────────────────────────────
    "unused_object": (
        "Verify that this object is not referenced in policies outside the current view. "
        "If the object is confirmed unused, raise a change request to remove it from the "
        "object database to reduce policy complexity."
    ),
    "unattached_object": (
        "These objects are referenced by no rule or NAT rule and are not members of any "
        "used group. Verify against any policies outside the current view, then raise a "
        "change request to remove confirmed-unattached objects to reduce clutter."
    ),
    "object_usage_unknown": (
        "Object usage could not be determined because the object import is incomplete or "
        "contains a circular reference. Re-import / re-sync the object database (and review "
        "any circular groups) before relying on unattached-object cleanup."
    ),
    "overlapping_object": (
        "Review the overlapping network objects: confirm whether the narrower object is "
        "still required, or whether rules should reference the broader object. Consolidate "
        "to remove ambiguity, via change management."
    ),
    "duplicate_object": (
        "Consolidate duplicate objects to a single canonical definition. Update any rules "
        "that reference the redundant object to use the canonical one, then remove the "
        "duplicate through the change management process."
    ),
    "empty_group": (
        "Investigate why this group has no members. An empty group used in a rule will "
        "match no traffic — effectively making the rule non-functional. Either populate "
        "the group with the correct objects or remove it if it is no longer needed."
    ),
    "large_group": (
        "Review whether this group requires all its current members. Large groups with "
        "many members are harder to audit and may contain objects that are no longer "
        "relevant. Consider splitting into smaller, purpose-specific groups."
    ),
    "broad_network": (
        "Assess whether this broad network object can be replaced with a more specific "
        "subnet or host object. Rules referencing broad networks may unintentionally permit "
        "traffic to or from unintended hosts. All object changes require change approval."
    ),
    "service_range": (
        "Review whether the full port range defined in this service object is required. "
        "Large port ranges may inadvertently permit traffic on unintended ports. Replace "
        "with specific port definitions where possible."
    ),

    # ── Structural / policy-level ─────────────────────────────────────────────
    "duplicate_rule": (
        "Review the duplicate rule and confirm whether it has a separate business "
        "requirement. If no independent requirement exists, raise a change request to "
        "remove or consolidate the duplicate through the formal change management process. "
        "Maintaining duplicate rules increases policy complexity without security benefit."
    ),
    "rule_order_optimization": (
        "This frequently-matched rule is positioned below a number of rules that receive "
        "no traffic. Firewalls evaluate rules top-to-bottom, so placing high-traffic rules "
        "above unused ones reduces per-packet evaluation overhead and improves performance. "
        "Review the rule order and, if no dependency requires the current position, consider "
        "promoting this rule. Reordering must be performed manually through the approved "
        "change management process — this tool does not modify rule order."
    ),
    "large_rule_section": (
        "This policy section contains a large number of rules, which makes the rule base "
        "harder to read, audit, and troubleshoot. Industry guidance recommends keeping "
        "sections to roughly 20 rules or fewer. Review whether the section can be divided "
        "into smaller, purpose-specific sections through the approved change management "
        "process."
    ),
    "inbound_from_internet": (
        "This rule permits inbound traffic from an untrusted source (the internet or a "
        "public network) directly to an internal system. NIST SP 800-41 and PCI DSS require "
        "every inbound allow rule to carry a documented business justification and to be as "
        "specific as possible. Review the rule: confirm the business need, restrict the "
        "source to the minimum required external addresses, limit the service to specific "
        "ports, ensure logging is enabled, and where possible terminate the connection in a "
        "DMZ rather than allowing direct access to the internal network. All changes require "
        "engineer validation and approved change management."
    ),
    "lateral_movement_risk": (
        "This rule permits traffic between two broad internal network segments, which "
        "enables lateral (east-west) movement across the environment if any host in the "
        "source range is compromised. Review whether such wide internal access is required; "
        "if not, restrict the source and destination to the specific hosts or subnets that "
        "need to communicate, and segment the network through the approved change management "
        "process."
    ),
    "mergeable_rules": (
        "These rules share the same source, destination, and action but use different "
        "services. They can typically be consolidated into a single rule using a service "
        "group, reducing rule count and simplifying the policy. Review the rules and "
        "confirm none has a separate business or change-tracking reason to remain "
        "distinct; if not, consolidation may be performed through the approved change "
        "management process."
    ),
    "no_cleanup_rule": (
        "This policy has no explicit final deny-all (cleanup) rule that logs dropped "
        "traffic. Relying on the implicit default-deny means denied connections are not "
        "logged, creating a visibility gap for security monitoring and incident response. "
        "Review whether an explicit, logged 'deny any/any' rule should be added at the end "
        "of the rule base through the approved change management process."
    ),
    "shadowed_rule": (
        "Review the rule order and confirm whether the shadowed rule is intended to be "
        "unreachable. If the rule should match traffic, adjust the rule order after "
        "engineer review and change approval. If the rule is redundant, raise a change "
        "request for removal."
    ),

    # ── NAT / exposure ────────────────────────────────────────────────────────
    "nat_any_service": (
        "Restrict the NAT rule service to specific protocols and ports. A NAT rule with "
        "any-service translates all traffic matching the source/destination regardless of "
        "port, which may expose unintended services. Specify the minimum required services."
    ),
    "nat_no_security_policy": (
        "Verify that a corresponding security policy rule exists to control traffic for "
        "this NAT translation. NAT rules that have no matching security policy may allow "
        "traffic to pass without inspection or logging."
    ),
    "nat_overlapping": (
        "Review overlapping NAT rules to confirm which translation should take precedence. "
        "Overlapping NAT entries can cause inconsistent translation behaviour depending on "
        "rule order. Consolidate or reorder to make intent explicit."
    ),
    "rdp_exposed": (
        "RDP (port 3389) directly exposed to untrusted networks is a critical risk. "
        "Review this rule urgently and confirm whether the exposure is genuinely required. "
        "If no valid business requirement exists, raise a high-priority change request to "
        "restrict the source to authorised management hosts or move access behind a VPN or "
        "jump host. All changes require engineer validation and formal change approval."
    ),
    "ssh_exposed": (
        "SSH exposure to untrusted networks should be restricted to known source IPs. "
        "Verify the business requirement and restrict the source to specific authorised "
        "management hosts or implement VPN-gated access."
    ),
    "database_exposed": (
        "Database ports should never be directly exposed to untrusted networks. "
        "Review this rule urgently and confirm whether the exposure is genuinely required. "
        "If no valid business requirement exists, raise a high-priority change request to "
        "restrict access or route it through an application tier or VPN. All changes require "
        "engineer validation and formal change approval."
    ),

    "cleartext_service": (
        "This rule permits a cleartext protocol that transmits credentials and data "
        "without encryption, exposing them to interception on the path. Confirm the "
        "business requirement and plan migration to the encrypted equivalent (e.g. SSH "
        "instead of Telnet, SFTP/FTPS instead of FTP, LDAPS instead of LDAP, SNMPv3 "
        "instead of SNMP v1/v2). All changes require engineer validation and formal "
        "change approval before implementation."
    ),

    # ── Import / data quality ───────────────────────────────────────────────────
    "import_quality": (
        "Review the import quality summary to understand which findings are available for "
        "this policy. Where hit-count, last-hit, or NAT data is missing, consider exporting "
        "the configuration with usage statistics included so a more complete review can be "
        "performed."
    ),
}


def get(finding_type: str, fallback: Optional[str] = None) -> str:
    """Return the standard recommendation for a finding type.

    Args:
        finding_type: The finding type identifier.
        fallback:     Text to return if finding_type is not in the library.
                      If None, a generic recommendation is returned.
    """
    if finding_type in LIBRARY:
        return LIBRARY[finding_type]
    if fallback:
        return fallback
    return (
        "Review this finding and confirm whether any remediation is required. "
        "All changes must be validated by the responsible engineer and implemented "
        "through the formal change management process."
    )


def all_types() -> list[dict]:
    """Return the full library as a list of {finding_type, recommendation} dicts."""
    return [{"finding_type": k, "recommendation": v} for k, v in LIBRARY.items()]
