"""DOCX renderer — editable Word document via python-docx, sharing ReportData.

Produces a professional title page, headings per ordered section, editable
paragraphs and tables, finding tables, appendices, page breaks, and a
header/footer with page numbers. Respects selected sections + order.
"""
import io

from docx import Document
from docx.shared import Pt, RGBColor, Inches
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml.ns import qn
from docx.oxml import OxmlElement

from app.reporting.data import ReportData

_SEV_RGB = {
    "Critical": RGBColor(0xB9, 0x1C, 0x1C), "High": RGBColor(0xDC, 0x26, 0x26),
    "Medium": RGBColor(0xD9, 0x77, 0x06), "Low": RGBColor(0x25, 0x63, 0xEB),
    "Informational": RGBColor(0x6B, 0x72, 0x80),
}


def _hex_rgb(h: str) -> RGBColor:
    h = (h or "#1e3a5f").lstrip("#")
    try:
        return RGBColor(int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16))
    except Exception:
        return RGBColor(0x1e, 0x3a, 0x5f)


def _add_page_number_field(paragraph):
    run = paragraph.add_run()
    fld = OxmlElement("w:fldSimple"); fld.set(qn("w:instr"), "PAGE")
    run._r.addnext(fld)


def render(data: ReportData) -> bytes:
    b, m = data.branding, data.meta
    accent = _hex_rgb(b.get("accent_color"))
    doc = Document()

    # Base style
    normal = doc.styles["Normal"]
    normal.font.name = "Calibri"; normal.font.size = Pt(10.5)

    # Footer with confidentiality + page number
    footer = doc.sections[0].footer
    fp = footer.paragraphs[0]; fp.alignment = WD_ALIGN_PARAGRAPH.CENTER
    fp.add_run(f"{b.get('confidentiality','Confidential')} — page ").font.size = Pt(8)
    _add_page_number_field(fp)

    # ── Title page ────────────────────────────────────────────────────────────
    for logo_key in ("company_logo_path", "customer_logo_path"):
        lp = b.get(logo_key)
        if lp:
            try:
                pic = doc.add_paragraph(); pic.alignment = WD_ALIGN_PARAGRAPH.CENTER
                pic.add_run().add_picture(lp, width=Inches(2.2))
            except Exception:
                pass  # unsupported/corrupt image — skip rather than fail the report
    for _ in range(2):
        doc.add_paragraph()
    t = doc.add_paragraph(); t.alignment = WD_ALIGN_PARAGRAPH.CENTER
    tr = t.add_run(b.get("report_title", "Firewall Policy Review")); tr.bold = True
    tr.font.size = Pt(26); tr.font.color.rgb = accent
    if b.get("cover_subtitle"):
        sp = doc.add_paragraph(); sp.alignment = WD_ALIGN_PARAGRAPH.CENTER
        sr = sp.add_run(b["cover_subtitle"]); sr.font.size = Pt(13); sr.font.color.rgb = RGBColor(0x6b, 0x72, 0x80)
    doc.add_paragraph()
    for label, val in [("Customer", m.get("customer_name")), ("Firewall", m.get("firewall_name")),
                       ("Vendor", m.get("vendor")), ("Analysis date", m.get("analysis_date")),
                       ("Generated", m.get("generated_date")), ("Prepared by", b.get("prepared_by"))]:
        if not val:
            continue
        p = doc.add_paragraph(); p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p.add_run(f"{label}: ").bold = True; p.add_run(str(val))
    cp = doc.add_paragraph(); cp.alignment = WD_ALIGN_PARAGRAPH.CENTER
    cr = cp.add_run(b.get("confidentiality", "Confidential")); cr.bold = True; cr.font.color.rgb = accent
    if b.get("cover_custom_text"):
        ct = doc.add_paragraph(b["cover_custom_text"]); ct.alignment = WD_ALIGN_PARAGRAPH.CENTER
    doc.add_page_break()

    def heading(text):
        h = doc.add_heading(text, level=1)
        for r in h.runs:
            r.font.color.rgb = accent

    def finding_table(findings):
        if not findings:
            doc.add_paragraph("No findings in this category.")
            return
        tbl = doc.add_table(rows=1, cols=5); tbl.style = "Light Grid Accent 1"
        hdr = tbl.rows[0].cells
        for i, h in enumerate(["Severity", "Type", "Title", "Recommendation", "Conf."]):
            hdr[i].paragraphs[0].add_run(h).bold = True
        for f in findings:
            c = tbl.add_row().cells
            sev_run = c[0].paragraphs[0].add_run(f["severity"])
            sev_run.bold = True; sev_run.font.color.rgb = _SEV_RGB.get(f["severity"], _SEV_RGB["Informational"])
            c[1].text = f["finding_type_label"]; c[2].text = f["title"]
            c[3].text = f["recommendation"]; c[4].text = f["confidence"]

    # ── Sections (ordered) ────────────────────────────────────────────────────
    for s in data.sections:
        if s["key"] == "cover_page":
            continue
        stype = s["type"]
        if stype == "doc_control":
            heading("Document Control")
            tbl = doc.add_table(rows=0, cols=2); tbl.style = "Light List Accent 1"
            for k, v in [("Report title", b.get("report_title")), ("Customer", m.get("customer_name")),
                         ("Firewall", m.get("firewall_name")), ("Vendor", m.get("vendor")),
                         ("Analysis date", m.get("analysis_date")), ("Generated", m.get("generated_date")),
                         ("Classification", b.get("confidentiality"))]:
                row = tbl.add_row().cells; row[0].paragraphs[0].add_run(str(k)).bold = True; row[1].text = str(v or "")
        elif stype == "text":
            if s.get("text"):
                heading(s["name"])
                for para in str(s["text"]).split("\n"):
                    doc.add_paragraph(para)
        elif stype == "metrics":
            heading(s["name"])
            tbl = doc.add_table(rows=0, cols=2); tbl.style = "Light List Accent 1"
            for k, v in [("Total findings", m.get("total_findings")), ("Critical", m.get("critical_findings")),
                         ("High", m.get("high_findings")), ("Medium", m.get("medium_findings")),
                         ("Total rules", m.get("total_rules")), ("Total objects", m.get("total_objects")),
                         ("Health score", m.get("policy_score"))]:
                row = tbl.add_row().cells; row[0].paragraphs[0].add_run(str(k)).bold = True; row[1].text = str(v)
            if s["key"] == "findings_by_category":
                doc.add_paragraph()
                ct = doc.add_table(rows=1, cols=2); ct.style = "Light Grid Accent 1"
                ct.rows[0].cells[0].paragraphs[0].add_run("Category").bold = True
                ct.rows[0].cells[1].paragraphs[0].add_run("Count").bold = True
                for cat, n in data.category_counts.items():
                    r = ct.add_row().cells; r[0].text = cat; r[1].text = str(n)
        elif stype == "findings":
            heading(s["name"]); finding_table(s.get("findings", []))
        elif stype == "appendix" and s["key"] == "full_rulebase":
            heading(s["name"])
            tbl = doc.add_table(rows=1, cols=6); tbl.style = "Light Grid Accent 1"
            for i, h in enumerate(["#", "Name", "Source", "Dest", "Service", "Action"]):
                tbl.rows[0].cells[i].paragraphs[0].add_run(h).bold = True
            for r in data.rules:
                c = tbl.add_row().cells
                c[0].text = str(r["rule_number"]); c[1].text = r["rule_name"]; c[2].text = r["sources"]
                c[3].text = r["destinations"]; c[4].text = r["services"]; c[5].text = r["action"]
        elif stype == "appendix" and s["key"] == "full_object_inventory":
            heading(s["name"])
            tbl = doc.add_table(rows=1, cols=4); tbl.style = "Light Grid Accent 1"
            for i, h in enumerate(["Name", "Type", "Value", "Members"]):
                tbl.rows[0].cells[i].paragraphs[0].add_run(h).bold = True
            for o in data.objects:
                c = tbl.add_row().cells
                c[0].text = o["object_name"]; c[1].text = o["object_type"]; c[2].text = o["value"]; c[3].text = o["members"]
        doc.add_paragraph()

    buf = io.BytesIO(); doc.save(buf)
    return buf.getvalue()
