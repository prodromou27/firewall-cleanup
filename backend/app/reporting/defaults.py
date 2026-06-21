"""Default report templates (customer-facing + internal) seeded on first run."""
from app.reporting import sections as S

_CUSTOMER_SECTIONS = [
    "cover_page", "document_control", "introduction", "scope", "methodology",
    "executive_summary", "security_posture", "findings_summary",
    "findings_by_severity", "top_high_risk", "public_exposure",
    "overly_permissive_rules", "risky_services", "read_only_disclaimer",
]
_INTERNAL_SECTIONS = [
    "cover_page", "document_control", "executive_summary", "policy_overview",
    "findings_summary", "findings_by_severity", "findings_by_category",
    "top_high_risk", "overly_permissive_rules", "disabled_rules", "zero_hit_rules",
    "duplicate_rules", "shadowed_rules", "risky_services", "rules_without_logging",
    "public_exposure", "unused_objects", "full_rulebase", "full_object_inventory",
    "scoring_methodology", "read_only_disclaimer",
]

_INTRO = (
    "This report summarizes the results of a read-only firewall policy review of "
    "{{firewall_name}} ({{vendor}}) for {{customer_name}}, based on analysis performed "
    "on {{analysis_date}}. It identifies {{total_findings}} findings across "
    "{{total_rules}} rules and {{total_objects}} objects."
)
_METHODOLOGY = (
    "The analysis engine ingests the exported firewall configuration and evaluates it against "
    "a library of rule- and object-level checks (permissiveness, exposure, shadowing, "
    "duplication, usage, logging, documentation and hygiene). Findings are scored by "
    "severity and confidence using available hit-count and object-expansion data. No "
    "changes are made to the firewall during analysis."
)
_SCORING = (
    "Each finding is assigned a severity (Critical/High/Medium/Low/Informational) and a "
    "confidence level reflecting the completeness of the underlying data (e.g. hit-count "
    "availability and object-expansion success). The policy health score is an inverse "
    "risk proxy derived from the weighted severity of all findings."
)


def default_template_specs():
    """Return (template_dict, ordered_section_keys) tuples to seed."""
    common_branding = {"company_name": "", "accent_color": "#1e3a5f",
                       "secondary_color": "#2e7d62", "confidentiality": "Confidential"}
    return [
        ({
            "name": "Customer-Facing Firewall Review",
            "description": "Polished, customer-ready summary report.",
            "template_type": "executive", "audience": "customer", "is_customer_facing": True,
            "default_export_format": "pdf", "default_detail_level": "summary",
            "branding_config": common_branding,
            "cover_page_config": {"cover_subtitle": "Firewall Policy Review", "prepared_by": ""},
            "introduction_text": _INTRO, "methodology_text": _METHODOLOGY,
            "disclaimer_text": S.READ_ONLY_DISCLAIMER, "footer_text": "",
            "default_finding_categories": [], "is_default": True,
        }, _CUSTOMER_SECTIONS),
        ({
            "name": "Internal Technical Findings",
            "description": "Detailed technical report with appendices for engineers.",
            "template_type": "technical", "audience": "internal", "is_customer_facing": False,
            "default_export_format": "xlsx", "default_detail_level": "detailed",
            "branding_config": common_branding,
            "cover_page_config": {"cover_subtitle": "Internal Technical Findings", "prepared_by": ""},
            "introduction_text": _INTRO, "methodology_text": _METHODOLOGY,
            "disclaimer_text": S.READ_ONLY_DISCLAIMER,
            "scoring_methodology_text": _SCORING, "footer_text": "",
            "default_finding_categories": [], "is_default": False,
        }, _INTERNAL_SECTIONS),
    ]


# Product-named text that early seeds stored; used to detect un-edited rows so
# the de-branding fix-up never clobbers a user's own edits.
_OLD_METHODOLOGY = (
    "PolicyInsight ingests the exported firewall configuration and evaluates it against "
    "a library of rule- and object-level checks (permissiveness, exposure, shadowing, "
    "duplication, usage, logging, documentation and hygiene). Findings are scored by "
    "severity and confidence using available hit-count and object-expansion data. No "
    "changes are made to the firewall during analysis."
)
_OLD_DISCLAIMER = (
    "This report was generated using read-only firewall policy data available to "
    "PolicyInsight at the time of analysis. PolicyInsight does not perform firewall "
    "changes and does not delete, disable, modify, reorder, or install firewall "
    "policies or objects. The findings and recommendations in this report are intended "
    "to support review and planning activities only. Any firewall changes must be "
    "validated by the responsible technical teams, approved through the appropriate "
    "change management process, and implemented outside PolicyInsight."
)


def debrand_seeded_templates(db) -> int:
    """Strip the product name from system-seeded global templates already in the DB.

    Idempotent and conservative: only touches rows created_by 'system' with no
    customer, and only replaces values still equal to the old hardcoded seeds
    (so user edits are never overwritten). Returns the number of rows changed.
    """
    from app.models.report import ReportTemplate
    changed = 0
    rows = (db.query(ReportTemplate)
            .filter(ReportTemplate.customer_id.is_(None),
                    ReportTemplate.created_by == "system")
            .all())
    for t in rows:
        touched = False
        bc = dict(t.branding_config or {})
        if bc.get("company_name") == "PolicyInsight":
            bc["company_name"] = ""
            t.branding_config = bc
            touched = True
        if t.methodology_text == _OLD_METHODOLOGY:
            t.methodology_text = _METHODOLOGY
            touched = True
        if t.disclaimer_text == _OLD_DISCLAIMER:
            t.disclaimer_text = S.READ_ONLY_DISCLAIMER
            touched = True
        if touched:
            changed += 1
    if changed:
        db.commit()
    return changed


def ensure_default_templates(db) -> int:
    """Create the global default templates if none exist. Returns count created."""
    from app.models.report import ReportTemplate, ReportTemplateSection
    if db.query(ReportTemplate).count() > 0:
        debrand_seeded_templates(db)
        return 0
    created = 0
    for tmpl_dict, section_keys in default_template_specs():
        scoring = tmpl_dict.pop("scoring_methodology_text", None)
        t = ReportTemplate(customer_id=None, created_by="system", **tmpl_dict)
        if scoring:
            cfg = dict(t.cover_page_config or {})
            cfg["scoring_methodology_text"] = scoring
            t.cover_page_config = cfg
        db.add(t)
        db.flush()
        for order, key in enumerate(section_keys):
            spec = S.SECTION_BY_KEY.get(key, {})
            db.add(ReportTemplateSection(
                template_id=t.id, section_key=key, section_name=spec.get("name", key),
                section_type=spec.get("type", "builtin"), enabled=True, display_order=order,
            ))
        created += 1
    db.commit()
    return created
