"""Report section catalog, finding-category catalog, and shared constants.

This is the single source of truth for what sections and finding categories a
report can contain — consumed by the API metadata endpoints, the template
defaults, and every exporter.
"""

# Default disclaimer every formal report includes (editable per template).
READ_ONLY_DISCLAIMER = (
    "This report was generated using read-only firewall policy data available to "
    "the analysis platform at the time of analysis. The platform does not perform firewall "
    "changes and does not delete, disable, modify, reorder, or install firewall "
    "policies or objects. The findings and recommendations in this report are intended "
    "to support review and planning activities only. Any firewall changes must be "
    "validated by the responsible technical teams, approved through the appropriate "
    "change management process, and implemented outside the platform."
)

# Section types
T_COVER = "cover"
T_TEXT = "text"            # free / template text (intro, methodology, scope, disclaimer, custom)
T_METRICS = "metrics"      # summary / score blocks
T_FINDINGS = "findings"    # a finding table, optionally filtered to a category
T_APPENDIX = "appendix"    # full rulebase / object inventory tables
T_DOCCTRL = "doc_control"

# Section catalog. `finding_types` (when present) filters the findings shown in
# that section. `text_key` (when present) names the template text field used.
SECTION_CATALOG = [
    {"key": "cover_page",        "name": "Cover Page",            "type": T_COVER,    "group": "Front matter",  "default": True},
    {"key": "document_control",  "name": "Document Control",      "type": T_DOCCTRL,  "group": "Front matter",  "default": True},
    {"key": "introduction",      "name": "Introduction",          "type": T_TEXT,     "group": "Narrative",     "default": True,  "text_key": "introduction_text"},
    {"key": "scope",             "name": "Scope",                 "type": T_TEXT,     "group": "Narrative",     "default": True,  "text_key": "scope_text"},
    {"key": "methodology",       "name": "Methodology",           "type": T_TEXT,     "group": "Narrative",     "default": True,  "text_key": "methodology_text"},
    {"key": "executive_summary", "name": "Executive Summary",     "type": T_METRICS,  "group": "Summary",       "default": True},
    {"key": "policy_overview",   "name": "Policy Overview",       "type": T_METRICS,  "group": "Summary",       "default": True},
    {"key": "firewall_inventory","name": "Firewall Inventory",    "type": T_METRICS,  "group": "Summary",       "default": False},
    {"key": "security_posture",  "name": "Security Posture Score","type": T_METRICS,  "group": "Summary",       "default": True},
    {"key": "findings_summary",  "name": "Findings Summary",      "type": T_METRICS,  "group": "Summary",       "default": True},
    {"key": "findings_by_severity","name": "Findings by Severity","type": T_METRICS, "group": "Summary",       "default": True},
    {"key": "findings_by_category","name": "Findings by Category","type": T_METRICS, "group": "Summary",       "default": True},
    {"key": "top_high_risk",     "name": "Top High-Risk Findings","type": T_FINDINGS, "group": "Findings",      "default": True, "severities": ["Critical", "High"]},
    {"key": "any_to_any_rules",  "name": "Any-to-Any Allow Rules","type": T_FINDINGS, "group": "Findings",      "default": True, "finding_types": ["any_to_any_allow"]},
    {"key": "overly_permissive_rules","name": "Overly Permissive Rules","type": T_FINDINGS,"group": "Findings","default": True, "finding_types": ["overly_permissive"]},
    {"key": "disabled_rules",    "name": "Disabled Rules",        "type": T_FINDINGS, "group": "Findings",      "default": False,"finding_types": ["disabled_rule"]},
    {"key": "zero_hit_rules",    "name": "Zero-Hit Rules",        "type": T_FINDINGS, "group": "Findings",      "default": False,"finding_types": ["zero_hit_rule"]},
    {"key": "low_hit_rules",     "name": "Low-Hit Rules",         "type": T_FINDINGS, "group": "Findings",      "default": False,"finding_types": ["low_usage_rule"]},
    {"key": "duplicate_rules",   "name": "Duplicate Rules",       "type": T_FINDINGS, "group": "Findings",      "default": False,"finding_types": ["duplicate_rule"]},
    {"key": "shadowed_rules",    "name": "Shadowed Rules",        "type": T_FINDINGS, "group": "Findings",      "default": False,"finding_types": ["shadowed_rule", "same_action_shadowed_rule", "conflicting_shadowed_rule", "partial_shadowed_rule"]},
    {"key": "risky_services",    "name": "Risky Services",        "type": T_FINDINGS, "group": "Findings",      "default": True, "finding_types": ["risky_service", "cleartext_service"]},
    {"key": "rules_without_logging","name": "Rules Without Logging","type": T_FINDINGS,"group": "Findings",     "default": False,"finding_types": ["no_logging"]},
    {"key": "temporary_rules",   "name": "Temporary Rules",       "type": T_FINDINGS, "group": "Findings",      "default": False,"finding_types": ["temporary_rule", "expired_rule"]},
    {"key": "public_exposure",   "name": "Public Exposure Findings","type": T_FINDINGS,"group": "Findings",     "default": True, "finding_types": ["rdp_exposed", "ssh_exposed", "database_exposed", "inbound_from_internet", "rdp_public_exposure", "ssh_public_exposure", "telnet_public_exposure", "smb_public_exposure", "winrm_public_exposure", "vnc_public_exposure", "database_public_exposure", "any_service_public_exposure", "sensitive_destination_exposure", "public_exposure_no_logging"]},
    {"key": "nat_findings",      "name": "NAT Findings",          "type": T_FINDINGS, "group": "Findings",      "default": False,"finding_types": ["nat_complexity", "nat_static", "nat_source", "nat_duplicate", "nat_overlap"]},
    {"key": "nat_public_exposure","name": "NAT & Public Exposure Review","type": T_FINDINGS,"group": "Findings","default": False,"finding_types": ["nat_public_to_internal", "nat_without_policy", "policy_without_nat", "rdp_public_exposure", "ssh_public_exposure", "telnet_public_exposure", "smb_public_exposure", "winrm_public_exposure", "vnc_public_exposure", "database_public_exposure", "any_service_public_exposure", "sensitive_destination_exposure", "public_exposure_no_logging"]},
    {"key": "version_intelligence","name": "Firewall Version Intelligence","type": T_FINDINGS,"group": "Findings","default": False,"finding_types": ["version_outdated", "version_end_of_support", "version_ha_mismatch", "version_unknown", "version_catalog_unavailable"]},
    {"key": "unused_objects",    "name": "Unused Objects",        "type": T_FINDINGS, "group": "Objects",       "default": False,"finding_types": ["unused_object"]},
    {"key": "duplicate_objects", "name": "Duplicate Objects",     "type": T_FINDINGS, "group": "Objects",       "default": False,"finding_types": ["duplicate_object"]},
    {"key": "overlapping_objects","name": "Overlapping Objects",  "type": T_FINDINGS, "group": "Objects",       "default": False,"finding_types": ["broad_network", "large_group", "empty_group", "service_range"]},
    {"key": "full_rulebase",     "name": "Full Rulebase Appendix","type": T_APPENDIX, "group": "Appendices",    "default": False},
    {"key": "full_object_inventory","name": "Full Object Inventory Appendix","type": T_APPENDIX,"group": "Appendices","default": False},
    {"key": "scoring_methodology","name": "Scoring Methodology",  "type": T_TEXT,     "group": "Appendices",    "default": False,"text_key": "scoring_methodology_text"},
    {"key": "read_only_disclaimer","name": "Read-Only Disclaimer","type": T_TEXT,     "group": "Back matter",   "default": True, "text_key": "disclaimer_text"},
]

SECTION_BY_KEY = {s["key"]: s for s in SECTION_CATALOG}
DEFAULT_SECTION_KEYS = [s["key"] for s in SECTION_CATALOG if s.get("default")]

# Finding categories selectable in the builder (canonical finding types the
# engine produces). label is display text.
FINDING_CATEGORIES = [
    ("overly_permissive", "Overly Permissive Rules"),
    ("disabled_rule", "Disabled Rules"),
    ("zero_hit_rule", "Zero-Hit Rules"),
    ("low_usage_rule", "Low-Usage Rules"),
    ("duplicate_rule", "Duplicate Rules"),
    ("shadowed_rule", "Shadowed Rules"),
    ("same_action_shadowed_rule", "Redundant (Same-Action) Shadowed Rules"),
    ("conflicting_shadowed_rule", "Conflicting Shadowed Rules"),
    ("partial_shadowed_rule", "Partially Shadowed Rules"),
    ("shadowing_not_evaluated", "Shadowing Not Evaluated"),
    ("risky_service", "Risky Services"),
    ("cleartext_service", "Cleartext Protocols"),
    ("no_logging", "Rules Without Logging"),
    ("temporary_rule", "Temporary Rules"),
    ("expired_rule", "Expired Rules"),
    ("no_documentation", "Undocumented Rules"),
    ("naming_quality", "Poorly Named Rules"),
    ("vpn_access", "Broad VPN Access"),
    ("rdp_exposed", "RDP Exposed"),
    ("ssh_exposed", "SSH Exposed"),
    ("database_exposed", "Database Exposed"),
    ("inbound_from_internet", "Inbound From Internet"),
    ("lateral_movement_risk", "Lateral Movement Risk"),
    ("nat_complexity", "NAT Findings"),
    ("negated_object", "Negated Objects"),
    ("mergeable_rules", "Consolidation Candidates"),
    ("rule_order_optimization", "Rule Order Optimization"),
    ("large_rule_section", "Oversized Sections"),
    ("unused_object", "Unused Objects"),
    ("duplicate_object", "Duplicate Objects"),
    ("empty_group", "Empty Groups"),
    ("large_group", "Large Groups"),
    ("broad_network", "Broad Network Objects"),
    ("service_range", "Wide Service Objects"),
    ("any_to_any_allow", "Any-to-Any Allow Rules"),
    ("import_quality", "Import Quality Notes"),
    ("analysis_configuration", "Analysis Configuration Notes"),
    # Version intelligence
    ("version_outdated", "Outdated Firewall Versions"),
    ("version_end_of_support", "End-of-Support Versions"),
    ("version_ha_mismatch", "HA Version Mismatch"),
    ("version_unknown", "Unknown Firewall Versions"),
    ("version_catalog_unavailable", "Version Catalog Unavailable"),
    # NAT & Public Exposure
    ("nat_public_to_internal", "Public IP Mapped to Internal System"),
    ("nat_static", "Static NAT Mappings"),
    ("nat_source", "Source / Hide NAT"),
    ("nat_duplicate", "Duplicate NAT Rules"),
    ("nat_overlap", "Overlapping NAT Rules"),
    ("nat_without_policy", "NAT Without Security Policy"),
    ("policy_without_nat", "Security Rule Without NAT Relationship"),
    ("any_service_public_exposure", "Public Exposure of Any Service"),
    ("rdp_public_exposure", "Public Exposure of RDP"),
    ("ssh_public_exposure", "Public Exposure of SSH"),
    ("telnet_public_exposure", "Public Exposure of Telnet"),
    ("smb_public_exposure", "Public Exposure of SMB"),
    ("winrm_public_exposure", "Public Exposure of WinRM"),
    ("vnc_public_exposure", "Public Exposure of VNC"),
    ("database_public_exposure", "Public Exposure of Database Ports"),
    ("sensitive_destination_exposure", "Public Exposure to Sensitive Destinations"),
    ("public_exposure_no_logging", "Public Exposure Without Logging"),
    ("mgmt_on_public_interface", "Management on Public Interface"),
]
FINDING_CATEGORY_KEYS = [k for k, _ in FINDING_CATEGORIES]

# Placeholder catalog (shown in the editor).
PLACEHOLDERS = [
    "customer_name", "firewall_name", "vendor", "policy_name", "analysis_date",
    "total_rules", "total_objects", "total_findings", "critical_findings",
    "high_findings", "medium_findings", "low_findings", "info_findings",
    "policy_score", "generated_date",
]
