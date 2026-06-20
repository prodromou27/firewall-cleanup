"""Unit tests for the reporting layer: placeholders, catalog, exporters."""
import json

import pytest

from app.reporting import placeholders, sections as S
from app.reporting.data import ReportData
from app.reporting.exporters import export, filename_for, SUPPORTED_FORMATS


# ── Placeholders ──────────────────────────────────────────────────────────────
def test_placeholder_substitution_and_unknown_left_intact():
    m = placeholders.build_map({"customer_name": "ACME", "firewall_name": "FW1", "total_findings": 7})
    out = placeholders.apply("{{customer_name}} / {{firewall_name}} has {{total_findings}} ({{nope}})", m)
    assert out == "ACME / FW1 has 7 ({{nope}})"


def test_placeholder_empty_text():
    assert placeholders.apply("", {}) == ""


# ── Catalog integrity ─────────────────────────────────────────────────────────
def test_default_sections_exist_in_catalog():
    for k in S.DEFAULT_SECTION_KEYS:
        assert k in S.SECTION_BY_KEY


def test_disclaimer_is_default_section():
    assert "read_only_disclaimer" in S.DEFAULT_SECTION_KEYS


def test_finding_category_keys_unique():
    assert len(S.FINDING_CATEGORY_KEYS) == len(set(S.FINDING_CATEGORY_KEYS))


# ── Exporters (synthetic ReportData, no DB) ──────────────────────────────────
def _sample() -> ReportData:
    findings = [{
        "id": "f1", "severity": "High", "confidence": "High", "finding_type": "overly_permissive",
        "finding_type_label": "Overly Permissive Rules", "title": "Rule 1 is overly permissive",
        "description": "any/any", "recommendation": "Restrict scope.", "risk_score": 80,
        "affected_rule_count": 1, "affected_object_count": 0, "evidence_summary": "any_source: True",
        "firewall_name": "FW1", "status": "Review Required",
    }]
    return ReportData(
        meta={"customer_name": "ACME", "firewall_name": "FW1", "vendor": "FortiGate",
              "analysis_date": "2026-06-20", "generated_date": "2026-06-20 12:00",
              "total_rules": 10, "total_objects": 5, "total_findings": 1,
              "critical_findings": 0, "high_findings": 1, "medium_findings": 0,
              "low_findings": 0, "info_findings": 0, "policy_score": 72},
        branding={"company_name": "PolicyInsight", "accent_color": "#1e3a5f",
                  "confidentiality": "Confidential", "report_title": "Review — FW1"},
        texts={"introduction_text": "Intro", "disclaimer_text": S.READ_ONLY_DISCLAIMER},
        sections=[
            {"key": "cover_page", "name": "Cover Page", "type": S.T_COVER},
            {"key": "introduction", "name": "Introduction", "type": S.T_TEXT, "text": "Intro"},
            {"key": "findings_by_severity", "name": "Findings by Severity", "type": S.T_METRICS},
            {"key": "overly_permissive_rules", "name": "Overly Permissive Rules", "type": S.T_FINDINGS, "findings": findings},
            {"key": "read_only_disclaimer", "name": "Read-Only Disclaimer", "type": S.T_TEXT, "text": S.READ_ONLY_DISCLAIMER},
        ],
        findings=findings,
        severity_counts={"Critical": 0, "High": 1, "Medium": 0, "Low": 0, "Informational": 0},
        category_counts={"Overly Permissive Rules": 1},
        rules=[], objects=[],
    )


@pytest.mark.parametrize("fmt", ["html", "docx", "xlsx", "csv", "json"])
def test_exporter_produces_nonempty_output(fmt):
    content, media, ext = export(_sample(), fmt)
    assert isinstance(content, (bytes,)) and len(content) > 50
    assert ext == ("html" if fmt == "html" else fmt)


def test_json_export_schema():
    content, _, _ = export(_sample(), "json")
    payload = json.loads(content)
    assert payload["schema_version"] == "1.0"
    assert payload["meta"]["customer_name"] == "ACME"
    assert payload["findings"][0]["finding_type"] == "overly_permissive"


def test_html_escapes_finding_text():
    data = _sample()
    data.sections[3]["findings"][0]["title"] = "<script>alert(1)</script>"
    content, _, _ = export(data, "html")
    html = content.decode()
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_html_includes_disclaimer():
    content, _, _ = export(_sample(), "html")
    assert "read-only firewall policy data" in content.decode()


def test_filename_format():
    fn = filename_for(_sample(), "docx", "Technical-Findings")
    assert fn.startswith("PolicyInsight_ACME_FW1_Technical-Findings_") and fn.endswith(".docx")


def test_pdf_when_available():
    try:
        import weasyprint  # noqa: F401
    except Exception:
        pytest.skip("WeasyPrint not available in this environment (works in the Docker image)")
    content, media, ext = export(_sample(), "pdf")
    assert content[:4] == b"%PDF" and media == "application/pdf"
