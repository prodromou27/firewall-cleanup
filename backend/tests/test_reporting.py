"""Unit tests for the reporting layer: placeholders, catalog, exporters."""
import json

import pytest

from app.reporting import placeholders, sections as S
from app.reporting.data import ReportData
from app.reporting.exporters import export, filename_for, SUPPORTED_FORMATS
from app.reporting.export_safety import attachment_headers, safe_filename, spreadsheet_cell


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
        "firewall_name": "FW1",
    }]
    return ReportData(
        meta={"customer_name": "ACME", "firewall_name": "FW1", "vendor": "FortiGate",
              "analysis_date": "2026-06-20", "generated_date": "2026-06-20 12:00",
              "total_rules": 10, "total_objects": 5, "total_findings": 1,
              "critical_findings": 0, "high_findings": 1, "medium_findings": 0,
              "low_findings": 0, "info_findings": 0, "policy_score": 72},
        branding={"company_name": "", "accent_color": "#1e3a5f",
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


def test_html_respects_selected_sections_without_cover_page():
    data = _sample()
    data.sections = [s for s in data.sections if s["key"] != "cover_page"]
    content, _, _ = export(data, "html")
    assert 'class="cover"' not in content.decode()


def test_filename_format():
    fn = filename_for(_sample(), "docx", "Technical-Findings")
    assert fn.startswith("Firewall-Report_ACME_FW1_Technical-Findings_") and fn.endswith(".docx")
    assert "PolicyInsight" not in fn


def test_format_aliases_are_supported():
    content, media, ext = export(_sample(), "word")
    assert content[:2] == b"PK"
    assert ext == "docx"
    assert "wordprocessingml.document" in media
    assert filename_for(_sample(), "excel").endswith(".xlsx")


def test_csv_export_guards_against_formula_injection():
    data = _sample()
    data.findings[0]["title"] = '=HYPERLINK("https://evil.example")'
    content, _, _ = export(data, "csv")
    assert "'=HYPERLINK" in content.decode()


@pytest.mark.parametrize("prefix", ["=", "+", "-", "@", "\t", "\r", "\n"])
def test_spreadsheet_cell_guards_all_formula_prefixes(prefix):
    assert spreadsheet_cell(prefix + "payload").startswith("'")


def test_safe_filename_and_attachment_header_strip_unsafe_content():
    filename = safe_filename('../ACME "Q2"/report?.csv')
    assert "/" not in filename and "\\" not in filename and '"' not in filename
    header = attachment_headers(filename)["Content-Disposition"]
    assert "attachment;" in header
    assert "filename*=" in header


def test_json_export_does_not_include_local_logo_paths_or_workflow_status():
    data = _sample()
    data.branding["company_logo_path"] = "C:/secret/internal/path/logo.png"
    content, _, _ = export(data, "json")
    payload = json.loads(content)
    assert "company_logo_path" not in payload["branding"]
    assert "status" not in payload["findings"][0]


def test_json_export_records_selected_sections_categories_and_filters():
    data = _sample()
    data.meta["selected_sections"] = ["cover_page", "overly_permissive_rules"]
    data.meta["selected_finding_categories"] = ["overly_permissive", "zero_hit_rule"]
    data.meta["filters_applied"] = {"severities": ["High"], "statuses": ["Review Required"]}
    content, _, _ = export(data, "json")
    payload = json.loads(content)
    assert payload["meta"]["selected_sections"] == ["cover_page", "overly_permissive_rules"]
    assert payload["meta"]["selected_finding_categories"] == ["overly_permissive", "zero_hit_rule"]
    assert payload["meta"]["filters_applied"]["severities"] == ["High"]


def test_pdf_when_available():
    try:
        import weasyprint  # noqa: F401
    except Exception:
        pytest.skip("WeasyPrint not available in this environment (works in the Docker image)")
    content, media, ext = export(_sample(), "pdf")
    assert content[:4] == b"%PDF" and media == "application/pdf"


# ── Logos ─────────────────────────────────────────────────────────────────────
def test_logo_save_resolve_datauri(tmp_path, monkeypatch):
    from app.config import settings
    from app.reporting import logos
    monkeypatch.setattr(settings, "upload_dir", str(tmp_path))
    # 1x1 transparent PNG
    png = bytes.fromhex(
        "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4"
        "890000000a49444154789c6360000002000154a24f9c0000000049454e44ae426082")
    ref = logos.save_logo(png, "logo.png")
    assert ref.startswith("branding/") and ref.endswith(".png")
    assert logos.abs_path(ref) is not None
    uri = logos.data_uri(ref)
    assert uri.startswith("data:image/png;base64,")


def test_logo_rejects_bad_type(tmp_path, monkeypatch):
    from app.config import settings
    from app.reporting import logos
    monkeypatch.setattr(settings, "upload_dir", str(tmp_path))
    with pytest.raises(ValueError):
        logos.save_logo(b"x", "evil.exe")


def test_logo_path_traversal_blocked(tmp_path, monkeypatch):
    from app.config import settings
    from app.reporting import logos
    monkeypatch.setattr(settings, "upload_dir", str(tmp_path))
    assert logos.abs_path("../../etc/passwd") is None


def test_html_embeds_logo_data_uri():
    data = _sample()
    data.branding["company_logo"] = "data:image/png;base64,AAAA"
    content, _, _ = export(data, "html")
    assert 'src="data:image/png;base64,AAAA"' in content.decode()
