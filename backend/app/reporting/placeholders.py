"""Dynamic placeholder substitution for report text blocks.

Placeholders use the form {{name}} and resolve from the report's metadata
(customer, firewall, counts, score, dates). Unknown placeholders are left
intact so authors notice typos rather than silently losing content.
"""
import re

_PATTERN = re.compile(r"\{\{\s*([a-z_]+)\s*\}\}")


def build_map(meta: dict) -> dict:
    """Build the placeholder→value map from report metadata."""
    return {
        "customer_name": meta.get("customer_name", ""),
        "firewall_name": meta.get("firewall_name", ""),
        "vendor": meta.get("vendor", ""),
        "policy_name": meta.get("policy_name", "") or meta.get("firewall_name", ""),
        "analysis_date": meta.get("analysis_date", ""),
        "generated_date": meta.get("generated_date", ""),
        "total_rules": str(meta.get("total_rules", 0)),
        "total_objects": str(meta.get("total_objects", 0)),
        "total_findings": str(meta.get("total_findings", 0)),
        "critical_findings": str(meta.get("critical_findings", 0)),
        "high_findings": str(meta.get("high_findings", 0)),
        "medium_findings": str(meta.get("medium_findings", 0)),
        "low_findings": str(meta.get("low_findings", 0)),
        "info_findings": str(meta.get("info_findings", 0)),
        "policy_score": str(meta.get("policy_score", "")),
    }


def apply(text: str, mapping: dict) -> str:
    """Replace {{placeholder}} tokens in text using mapping (unknown left as-is)."""
    if not text:
        return ""
    return _PATTERN.sub(lambda m: mapping.get(m.group(1), m.group(0)), text)
