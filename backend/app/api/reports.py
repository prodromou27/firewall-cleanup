"""Report generation API — HTML, PDF, Excel, CSV, JSON.

All export endpoints accept optional filter query parameters:
  severities   — comma-separated list, e.g. "High,Medium"
  finding_types — comma-separated list, e.g. "shadowed_rule,zero_hit_rule"
  statuses     — comma-separated list, e.g. "Open,Accepted"
  finding_ids  — comma-separated list of specific finding UUIDs to include
  include_rules — whether to append the full rulebase (default: true)
"""
import io
import json
import csv
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse, HTMLResponse
from sqlalchemy.orm import Session
from typing import Optional, List
from app.database import get_db
from app.models.policy import FirewallPolicy, FirewallRule
from app.models.finding import Finding
from app.api.tenant import assert_policy_customer

router = APIRouter(prefix="/api/reports", tags=["reports"])

DISCLAIMER = (
    "The findings and recommendations in this report are based on the policy data available "
    "at the time of analysis. Firewall policy cleanup should only be performed after validation "
    "of business requirements, risk assessment, and formal change approval. "
    "This platform operates in read-only mode and does not modify any firewall configuration."
)


# ── Filter helpers ─────────────────────────────────────────────────────────────

def _parse_csv_param(value: Optional[str]) -> Optional[List[str]]:
    """Split a comma-separated query param into a list, or return None if empty."""
    if not value:
        return None
    items = [v.strip() for v in value.split(",") if v.strip()]
    return items if items else None


def _apply_finding_filters(
    q,
    severities: Optional[str],
    finding_types: Optional[str],
    statuses: Optional[str],
    finding_ids: Optional[str],
):
    sevs = _parse_csv_param(severities)
    ftypes = _parse_csv_param(finding_types)
    stats = _parse_csv_param(statuses)
    fids = _parse_csv_param(finding_ids)

    if sevs:
        q = q.filter(Finding.severity.in_(sevs))
    if ftypes:
        q = q.filter(Finding.finding_type.in_(ftypes))
    if stats:
        q = q.filter(Finding.status.in_(stats))
    if fids:
        q = q.filter(Finding.id.in_(fids))
    return q


# ── Routes ─────────────────────────────────────────────────────────────────────

@router.get("/{policy_id}/html")
def generate_html_report(
    policy_id: str,
    severities: Optional[str] = None,
    finding_types: Optional[str] = None,
    statuses: Optional[str] = None,
    finding_ids: Optional[str] = None,
    include_rules: bool = True,
    customer_id: Optional[str] = None,
    db: Session = Depends(get_db),
):
    policy, rules, findings = _load_report_data(
        policy_id, db, severities, finding_types, statuses, finding_ids, customer_id
    )
    rules_data = rules if include_rules else []
    html = _build_html_report(policy, rules_data, findings)
    return HTMLResponse(content=html)


@router.get("/{policy_id}/excel")
def generate_excel_report(
    policy_id: str,
    severities: Optional[str] = None,
    finding_types: Optional[str] = None,
    statuses: Optional[str] = None,
    finding_ids: Optional[str] = None,
    include_rules: bool = True,
    customer_id: Optional[str] = None,
    db: Session = Depends(get_db),
):
    try:
        import openpyxl
        from openpyxl.styles import Font, PatternFill, Alignment
    except ImportError:
        raise HTTPException(status_code=500, detail="openpyxl not installed")

    policy, rules, findings = _load_report_data(
        policy_id, db, severities, finding_types, statuses, finding_ids, customer_id
    )

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Summary"
    _write_summary_sheet(ws, policy, findings)

    wf = wb.create_sheet("Findings")
    _write_findings_sheet(wf, findings)

    if include_rules:
        wr = wb.create_sheet("Rulebase")
        _write_rules_sheet(wr, rules)

    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)

    filename = f"firewall_report_{policy.firewall_name}_{datetime.now().strftime('%Y%m%d')}.xlsx"
    return StreamingResponse(
        buf,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{policy_id}/csv")
def generate_csv_report(
    policy_id: str,
    severities: Optional[str] = None,
    finding_types: Optional[str] = None,
    statuses: Optional[str] = None,
    finding_ids: Optional[str] = None,
    customer_id: Optional[str] = None,
    db: Session = Depends(get_db),
):
    policy, rules, findings = _load_report_data(
        policy_id, db, severities, finding_types, statuses, finding_ids, customer_id
    )

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Severity", "Confidence", "Finding Type", "Title",
        "Description", "Recommendation", "Status", "Engineer Comment",
        "Affected Rules", "Risk Score", "Created At"
    ])
    for f in findings:
        writer.writerow([
            f.severity, f.confidence, f.finding_type, f.title,
            f.description, f.recommendation, f.status, f.engineer_comment or "",
            ", ".join(str(r) for r in (f.affected_rules or [])),
            f"{f.risk_score or 0:.0f}",
            f.created_at.isoformat() if f.created_at else "",
        ])

    output.seek(0)
    filename = f"findings_{policy.firewall_name}_{datetime.now().strftime('%Y%m%d')}.csv"
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode()),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{policy_id}/json")
def generate_json_report(
    policy_id: str,
    severities: Optional[str] = None,
    finding_types: Optional[str] = None,
    statuses: Optional[str] = None,
    finding_ids: Optional[str] = None,
    include_rules: bool = True,
    customer_id: Optional[str] = None,
    db: Session = Depends(get_db),
):
    policy, rules, findings = _load_report_data(
        policy_id, db, severities, finding_types, statuses, finding_ids, customer_id
    )

    data = {
        "report_generated": datetime.now().isoformat(),
        "disclaimer": DISCLAIMER,
        "filters_applied": {
            "severities": _parse_csv_param(severities),
            "finding_types": _parse_csv_param(finding_types),
            "statuses": _parse_csv_param(statuses),
            "finding_ids_count": len(_parse_csv_param(finding_ids) or []) or None,
        },
        "policy": {
            "id": policy.id,
            "customer_name": (policy.customer.name if policy.customer else policy.customer_id),
            "firewall_name": policy.firewall_name,
            "vendor": policy.vendor,
            "policy_package": policy.policy_package,
            "rule_count": policy.rule_count,
            "object_count": policy.object_count,
            "upload_date": policy.upload_date.isoformat() if policy.upload_date else None,
        },
        "summary": {
            "total_findings": len(findings),
            "high": sum(1 for f in findings if f.severity == "High"),
            "medium": sum(1 for f in findings if f.severity == "Medium"),
            "low": sum(1 for f in findings if f.severity == "Low"),
            "informational": sum(1 for f in findings if f.severity == "Informational"),
        },
        "findings": [
            {
                "id": f.id,
                "finding_type": f.finding_type,
                "severity": f.severity,
                "confidence": f.confidence,
                "title": f.title,
                "description": f.description,
                "evidence": f.evidence,
                "recommendation": f.recommendation,
                "status": f.status,
                "engineer_comment": f.engineer_comment,
                "risk_score": f.risk_score,
            }
            for f in findings
        ],
    }

    if include_rules:
        data["rulebase"] = [
            {
                "rule_number": r.rule_number,
                "rule_id": r.rule_id,
                "rule_name": r.rule_name,
                "sources": r.sources,
                "destinations": r.destinations,
                "services": r.services,
                "action": r.action,
                "enabled": r.enabled,
                "hit_count": r.hit_count,
                "risk_score": r.risk_score,
            }
            for r in rules
        ]

    buf = io.BytesIO(json.dumps(data, indent=2, default=str).encode())
    filename = f"report_{policy.firewall_name}_{datetime.now().strftime('%Y%m%d')}.json"
    return StreamingResponse(
        buf,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ── Data loader ────────────────────────────────────────────────────────────────

def _load_report_data(
    policy_id: str,
    db: Session,
    severities: Optional[str] = None,
    finding_types: Optional[str] = None,
    statuses: Optional[str] = None,
    finding_ids: Optional[str] = None,
    customer_id: Optional[str] = None,
):
    policy = db.query(FirewallPolicy).filter(FirewallPolicy.id == policy_id).first()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    if customer_id:
        assert_policy_customer(policy_id, customer_id, db)

    rules = (
        db.query(FirewallRule)
        .filter(FirewallRule.policy_id == policy_id)
        .order_by(FirewallRule.rule_number)
        .all()
    )

    findings_q = (
        db.query(Finding)
        .filter(Finding.policy_id == policy_id)
    )
    findings_q = _apply_finding_filters(findings_q, severities, finding_types, statuses, finding_ids)
    findings = (
        findings_q
        .order_by(Finding.severity, Finding.created_at)
        .all()
    )
    return policy, rules, findings


# ── Customer-level summary report ─────────────────────────────────────────────

@router.get("/customer/{customer_id}/summary")
def generate_customer_summary_report(
    customer_id: str,
    format: str = Query("json", regex="^(json|excel)$"),
    severities: Optional[str] = None,
    finding_types: Optional[str] = None,
    statuses: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """
    Multi-policy summary report for an entire customer.
    Includes all policies, aggregate findings counts, per-policy risk scores,
    and a findings breakdown — exported as JSON or Excel.
    """
    from app.models.customer import Customer
    from app.models.policy import FirewallRule
    from sqlalchemy import func

    customer = db.query(Customer).filter(Customer.id == customer_id).first()
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")

    policies = (
        db.query(FirewallPolicy)
        .filter(FirewallPolicy.customer_id == customer_id)
        .order_by(FirewallPolicy.upload_date.desc())
        .all()
    )

    policy_summaries = []
    for p in policies:
        fq = db.query(Finding).filter(Finding.policy_id == p.id)
        fq = _apply_finding_filters(fq, severities, finding_types, statuses, None)
        findings = fq.all()

        sev_counts = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}
        for f in findings:
            if f.severity in sev_counts:
                sev_counts[f.severity] += 1

        type_breakdown: dict = {}
        for f in findings:
            type_breakdown[f.finding_type] = type_breakdown.get(f.finding_type, 0) + 1

        status_breakdown: dict = {}
        for f in findings:
            status_breakdown[f.status] = status_breakdown.get(f.status, 0) + 1

        policy_summaries.append({
            "policy_id":       p.id,
            "firewall_name":   p.firewall_name,
            "vendor":          p.vendor,
            "policy_package":  p.policy_package,
            "rule_count":      p.rule_count,
            "object_count":    p.object_count,
            "analysis_status": p.analysis_status,
            "upload_date":     p.upload_date.isoformat() if p.upload_date else None,
            "health_score":    p.health_score,
            "complexity_score": p.complexity_score,
            "total_findings":  len(findings),
            "severity_counts": sev_counts,
            "type_breakdown":  type_breakdown,
            "status_breakdown": status_breakdown,
        })

    # Aggregate totals
    total_findings   = sum(s["total_findings"]           for s in policy_summaries)
    total_high       = sum(s["severity_counts"]["High"]  for s in policy_summaries)
    total_medium     = sum(s["severity_counts"]["Medium"] for s in policy_summaries)
    total_low        = sum(s["severity_counts"]["Low"]   for s in policy_summaries)
    total_info       = sum(s["severity_counts"]["Informational"] for s in policy_summaries)

    agg_types: dict = {}
    for s in policy_summaries:
        for k, v in s["type_breakdown"].items():
            agg_types[k] = agg_types.get(k, 0) + v

    now_str = datetime.now().strftime('%Y%m%d_%H%M%S')
    safe_name = customer.name.replace(" ", "_").replace("/", "-")

    data = {
        "report_generated": datetime.now().isoformat(),
        "report_type":      "customer_summary",
        "disclaimer":       DISCLAIMER,
        "customer": {
            "id":   customer.id,
            "name": customer.name,
        },
        "filters_applied": {
            "severities":    _parse_csv_param(severities),
            "finding_types": _parse_csv_param(finding_types),
            "statuses":      _parse_csv_param(statuses),
        },
        "summary": {
            "total_policies":    len(policies),
            "total_findings":    total_findings,
            "high":              total_high,
            "medium":            total_medium,
            "low":               total_low,
            "informational":     total_info,
            "findings_by_type":  agg_types,
        },
        "policies": policy_summaries,
    }

    if format == "json":
        buf = io.BytesIO(json.dumps(data, indent=2, default=str).encode())
        filename = f"customer_summary_{safe_name}_{now_str}.json"
        return StreamingResponse(buf, media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'})

    # Excel format
    try:
        import openpyxl
        from openpyxl.styles import Font, PatternFill, Alignment
    except ImportError:
        raise HTTPException(status_code=500, detail="openpyxl not installed")

    wb = openpyxl.Workbook()

    # Summary sheet
    ws = wb.active
    ws.title = "Summary"
    hdr_fill = PatternFill(fill_type="solid", fgColor="1e3a5f")
    hdr_font = Font(bold=True, color="FFFFFF")

    ws.append(["Customer Summary Report"])
    ws["A1"].font = Font(bold=True, size=14)
    ws.append([f"Customer: {customer.name}"])
    ws.append([f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}"])
    ws.append([])
    ws.append(["Total Policies", "Total Findings", "High", "Medium", "Low", "Informational"])
    for cell in ws[5]:
        cell.fill = hdr_fill
        cell.font = hdr_font
    ws.append([len(policies), total_findings, total_high, total_medium, total_low, total_info])
    ws.append([])

    # Policies sheet
    wp = wb.create_sheet("Policies")
    pol_headers = ["Firewall Name", "Vendor", "Package", "Rules", "Objects",
                   "Analysis", "Total Findings", "High", "Medium", "Low", "Upload Date"]
    wp.append(pol_headers)
    for cell in wp[1]:
        cell.fill = hdr_fill
        cell.font = hdr_font
    for s in policy_summaries:
        wp.append([
            s["firewall_name"], s["vendor"], s["policy_package"] or "", s["rule_count"], s["object_count"],
            s["analysis_status"], s["total_findings"],
            s["severity_counts"]["High"], s["severity_counts"]["Medium"], s["severity_counts"]["Low"],
            s["upload_date"] or "",
        ])

    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)
    filename = f"customer_summary_{safe_name}_{now_str}.xlsx"
    return StreamingResponse(buf,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'})


# ── HTML builder ───────────────────────────────────────────────────────────────

SEVERITY_COLORS = {
    "High": "#dc2626",
    "Medium": "#d97706",
    "Low": "#2563eb",
    "Informational": "#6b7280",
}

SEVERITY_BG = {
    "High": "#fee2e2",
    "Medium": "#fef3c7",
    "Low": "#dbeafe",
    "Informational": "#f3f4f6",
}


def _build_html_report(policy, rules, findings) -> str:
    now = datetime.now().strftime("%Y-%m-%d %H:%M UTC")
    high   = [f for f in findings if f.severity == "High"]
    medium = [f for f in findings if f.severity == "Medium"]
    low    = [f for f in findings if f.severity == "Low"]
    info   = [f for f in findings if f.severity == "Informational"]

    type_counts: dict = {}
    for f in findings:
        type_counts[f.finding_type] = type_counts.get(f.finding_type, 0) + 1

    # Findings grouped by severity
    findings_rows = ""
    for f in findings:
        color = SEVERITY_COLORS.get(f.severity, "#6b7280")
        bg = SEVERITY_BG.get(f.severity, "#f9fafb")
        evidence_html = ""
        if f.evidence and isinstance(f.evidence, dict):
            ev_items = "".join(
                f"<li><strong>{k.replace('_',' ').title()}:</strong> {v}</li>"
                for k, v in list(f.evidence.items())[:5]
            )
            evidence_html = f"<ul style='margin:4px 0 0 16px;font-size:11px;color:#6b7280'>{ev_items}</ul>"
        findings_rows += f"""
        <tr style="background:{bg}20">
          <td><span class="sev-badge" style="background:{color}">{f.severity}</span></td>
          <td style="font-size:11px;color:#6b7280">{f.confidence}</td>
          <td style="font-size:12px">{f.finding_type.replace('_',' ').title()}</td>
          <td style="font-weight:600">{f.title}{evidence_html}</td>
          <td style="font-size:11px;max-width:280px;color:#374151">{f.recommendation or ''}</td>
          <td><span class="status-badge status-{f.status.lower().replace(' ','_')}">{f.status}</span></td>
          <td style="font-size:11px;color:#6b7280">{f.engineer_comment or ''}</td>
        </tr>"""

    rules_rows = ""
    for r in rules:
        status_color = "#15803d" if r.enabled else "#dc2626"
        rules_rows += f"""
        <tr>
          <td style="font-size:11px;font-weight:600;color:#374151">{r.rule_number}</td>
          <td style="font-size:11px;color:#6b7280;font-family:monospace">{r.rule_id}</td>
          <td style="font-size:11px;font-weight:500">{r.rule_name or ''}</td>
          <td style="font-size:11px">{', '.join((r.sources or [])[:3])}{'…' if len(r.sources or []) > 3 else ''}</td>
          <td style="font-size:11px">{', '.join((r.destinations or [])[:3])}{'…' if len(r.destinations or []) > 3 else ''}</td>
          <td style="font-size:11px">{', '.join((r.services or [])[:3])}{'…' if len(r.services or []) > 3 else ''}</td>
          <td><span style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.5px;color:{'#15803d' if r.action=='allow' else '#dc2626'}">{r.action or ''}</span></td>
          <td style="font-size:11px;color:{status_color}">{'✓' if r.enabled else '✗'}</td>
          <td style="font-size:11px;text-align:right">{r.hit_count if r.hit_count is not None else '—'}</td>
          <td style="font-size:11px;text-align:right;font-weight:600;color:{'#dc2626' if (r.risk_score or 0) >= 70 else '#d97706' if (r.risk_score or 0) >= 40 else '#374151'}">{r.risk_score or 0:.0f}</td>
        </tr>"""

    type_rows = "".join(
        f"<tr><td>{t.replace('_',' ').title()}</td><td style='text-align:right;font-weight:600'>{c}</td></tr>"
        for t, c in sorted(type_counts.items(), key=lambda x: -x[1])
    )

    # Risk level bar
    total = len(findings) or 1
    high_pct   = len(high)   * 100 // total
    medium_pct = len(medium) * 100 // total
    low_pct    = len(low)    * 100 // total
    info_pct   = len(info)   * 100 // total

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Firewall Audit Report — {policy.firewall_name}</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
    font-size: 13px; color: #111827; background: #f9fafb; line-height: 1.5;
  }}
  .page {{ max-width: 1100px; margin: 0 auto; padding: 40px 24px; }}
  /* Header */
  .report-header {{
    background: #111827; color: white; border-radius: 12px;
    padding: 32px 36px; margin-bottom: 28px; position: relative; overflow: hidden;
  }}
  .report-header::after {{
    content: 'CONFIDENTIAL';
    position: absolute; top: 18px; right: 28px;
    font-size: 10px; font-weight: 700; letter-spacing: 2px;
    color: rgba(255,255,255,.25); border: 1px solid rgba(255,255,255,.15);
    padding: 2px 8px; border-radius: 4px;
  }}
  .report-header h1 {{ font-size: 22px; font-weight: 700; letter-spacing: -.5px; margin-bottom: 8px; }}
  .report-header .meta {{ display: flex; flex-wrap: wrap; gap: 20px; margin-top: 16px; }}
  .report-header .meta-item {{ font-size: 12px; color: rgba(255,255,255,.7); }}
  .report-header .meta-item strong {{ color: white; display: block; font-size: 13px; }}
  /* Disclaimer */
  .disclaimer {{
    background: #fffbeb; border: 1px solid #fde68a; border-left: 4px solid #f59e0b;
    border-radius: 8px; padding: 14px 18px; margin-bottom: 24px;
    font-size: 12px; color: #92400e; line-height: 1.6;
  }}
  /* Summary cards */
  .summary-grid {{ display: grid; grid-template-columns: repeat(4,1fr); gap: 14px; margin-bottom: 28px; }}
  .summary-card {{
    background: white; border: 1px solid #e5e7eb; border-radius: 10px;
    padding: 18px; text-align: center;
  }}
  .summary-card .num {{ font-size: 32px; font-weight: 800; line-height: 1; }}
  .summary-card .lbl {{ font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: .8px; color: #9ca3af; margin-top: 4px; }}
  .c-high   {{ color: #dc2626; }}
  .c-medium {{ color: #d97706; }}
  .c-low    {{ color: #2563eb; }}
  .c-info   {{ color: #6b7280; }}
  /* Risk bar */
  .risk-bar {{ display: flex; height: 8px; border-radius: 4px; overflow: hidden; margin: 16px 0 4px; gap: 2px; }}
  .risk-bar span {{ border-radius: 2px; }}
  /* Section */
  .section {{ background: white; border: 1px solid #e5e7eb; border-radius: 10px; margin-bottom: 24px; overflow: hidden; }}
  .section-header {{
    padding: 16px 20px; border-bottom: 1px solid #f3f4f6;
    display: flex; align-items: center; justify-content: space-between;
  }}
  .section-header h2 {{ font-size: 14px; font-weight: 700; color: #111827; }}
  .section-header .count {{ font-size: 12px; color: #9ca3af; font-weight: 500; }}
  /* Table */
  table {{ width: 100%; border-collapse: collapse; }}
  thead th {{
    background: #f9fafb; padding: 10px 14px; text-align: left;
    font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: .7px; color: #6b7280;
    border-bottom: 1px solid #e5e7eb;
  }}
  tbody td {{ padding: 10px 14px; border-bottom: 1px solid #f3f4f6; vertical-align: top; }}
  tbody tr:last-child td {{ border-bottom: none; }}
  tbody tr:hover {{ background: #f9fafb; }}
  /* Badges */
  .sev-badge {{
    display: inline-block; color: white; padding: 2px 8px; border-radius: 4px;
    font-size: 11px; font-weight: 700; white-space: nowrap; letter-spacing: .3px;
  }}
  .status-badge {{
    display: inline-block; padding: 2px 8px; border-radius: 4px;
    font-size: 11px; font-weight: 600; white-space: nowrap;
  }}
  .status-open {{ background:#fee2e2; color:#dc2626; }}
  .status-accepted {{ background:#d1fae5; color:#065f46; }}
  .status-suppressed {{ background:#f3f4f6; color:#6b7280; }}
  .status-in_progress {{ background:#dbeafe; color:#1d4ed8; }}
  /* Type table */
  .type-table td:first-child {{ color: #374151; font-weight: 500; }}
  .type-table td:last-child {{ text-align: right; width: 60px; }}
  /* Footer */
  .footer {{ text-align: center; font-size: 11px; color: #9ca3af; margin-top: 36px; padding-top: 20px; border-top: 1px solid #e5e7eb; }}
  @media print {{
    body {{ background: white; }}
    .page {{ padding: 20px; }}
    .section {{ break-inside: avoid; }}
  }}
</style>
</head>
<body>
<div class="page">

  <!-- Header -->
  <div class="report-header">
    <div style="font-size:11px;color:rgba(255,255,255,.5);text-transform:uppercase;letter-spacing:1.5px;margin-bottom:6px">Firewall Audit Report</div>
    <h1>{policy.firewall_name}</h1>
    <div class="meta">
      <div class="meta-item"><strong>{(policy.customer.name if policy.customer else policy.customer_id) or '—'}</strong>Customer</div>
      <div class="meta-item"><strong>{policy.vendor}</strong>Vendor</div>
      <div class="meta-item"><strong>{policy.policy_package or 'Default'}</strong>Policy Package</div>
      <div class="meta-item"><strong>{policy.rule_count}</strong>Rules Analyzed</div>
      <div class="meta-item"><strong>{policy.object_count or 0}</strong>Objects</div>
      <div class="meta-item"><strong>{now}</strong>Generated</div>
    </div>
  </div>

  <!-- Disclaimer -->
  <div class="disclaimer">
    <strong>⚠ Read-Only Report — No Changes Made:</strong> {DISCLAIMER}
  </div>

  <!-- Summary -->
  <div class="summary-grid">
    <div class="summary-card"><div class="num c-high">{len(high)}</div><div class="lbl">High Risk</div></div>
    <div class="summary-card"><div class="num c-medium">{len(medium)}</div><div class="lbl">Medium Risk</div></div>
    <div class="summary-card"><div class="num c-low">{len(low)}</div><div class="lbl">Low Risk</div></div>
    <div class="summary-card"><div class="num c-info">{len(info)}</div><div class="lbl">Informational</div></div>
  </div>

  <!-- Risk distribution bar -->
  <div style="background:white;border:1px solid #e5e7eb;border-radius:10px;padding:18px 20px;margin-bottom:24px">
    <div style="font-size:12px;font-weight:600;color:#374151;margin-bottom:8px">Risk Distribution</div>
    <div class="risk-bar">
      {'<span style="flex:'+str(len(high))+';background:#dc2626" title="High"></span>' if high else ''}
      {'<span style="flex:'+str(len(medium))+';background:#d97706" title="Medium"></span>' if medium else ''}
      {'<span style="flex:'+str(len(low))+';background:#3b82f6" title="Low"></span>' if low else ''}
      {'<span style="flex:'+str(len(info))+';background:#d1d5db" title="Informational"></span>' if info else ''}
    </div>
    <div style="display:flex;gap:16px;font-size:11px;color:#6b7280">
      <span><span style="color:#dc2626;font-weight:700">{len(high)}</span> High ({high_pct}%)</span>
      <span><span style="color:#d97706;font-weight:700">{len(medium)}</span> Medium ({medium_pct}%)</span>
      <span><span style="color:#3b82f6;font-weight:700">{len(low)}</span> Low ({low_pct}%)</span>
      <span><span style="color:#9ca3af;font-weight:700">{len(info)}</span> Informational ({info_pct}%)</span>
    </div>
  </div>

  <!-- Findings by type -->
  <div class="section">
    <div class="section-header">
      <h2>Findings by Category</h2>
      <span class="count">{len(type_counts)} categories</span>
    </div>
    <table class="type-table">
      <thead><tr><th>Category</th><th style="text-align:right">Count</th></tr></thead>
      <tbody>{type_rows}</tbody>
    </table>
  </div>

  <!-- All findings -->
  <div class="section">
    <div class="section-header">
      <h2>Findings Detail</h2>
      <span class="count">{len(findings)} findings</span>
    </div>
    <table>
      <thead>
        <tr>
          <th style="width:80px">Severity</th>
          <th style="width:70px">Confidence</th>
          <th style="width:130px">Category</th>
          <th>Finding</th>
          <th style="width:220px">Recommendation</th>
          <th style="width:90px">Status</th>
          <th style="width:130px">Notes</th>
        </tr>
      </thead>
      <tbody>{findings_rows if findings_rows else '<tr><td colspan="7" style="text-align:center;color:#9ca3af;padding:24px">No findings match the selected filters.</td></tr>'}</tbody>
    </table>
  </div>

  {'<!-- Rulebase --><div class="section"><div class="section-header"><h2>Rulebase Appendix</h2><span class="count">' + str(len(rules)) + ' rules</span></div><table><thead><tr><th style="width:40px">#</th><th style="width:90px">Rule ID</th><th style="width:120px">Name</th><th>Source</th><th>Destination</th><th>Service</th><th style="width:60px">Action</th><th style="width:35px">On</th><th style="width:55px;text-align:right">Hits</th><th style="width:45px;text-align:right">Risk</th></tr></thead><tbody>' + rules_rows + '</tbody></table></div>' if rules else ''}

  <div class="footer">
    PolicyInsight — Read-Only Firewall Audit Platform &nbsp;·&nbsp; Generated {now} &nbsp;·&nbsp;
    All recommendations require engineer validation and formal change approval before implementation.
  </div>

</div>
</body>
</html>"""


def _write_summary_sheet(ws, policy, findings):
    from openpyxl.styles import Font, PatternFill, Alignment
    ws["A1"] = "Firewall Audit Report"
    ws["A1"].font = Font(bold=True, size=16, color="111827")
    ws["A2"] = f"Customer: {(policy.customer.name if policy.customer else policy.customer_id)}"
    ws["A3"] = f"Firewall: {policy.firewall_name} ({policy.vendor})"
    ws["A4"] = f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}"
    ws["A6"] = "Summary"; ws["A6"].font = Font(bold=True)
    ws["A7"] = "Total Findings"; ws["B7"] = len(findings)
    ws["A8"] = "High";          ws["B8"] = sum(1 for f in findings if f.severity == "High")
    ws["A9"] = "Medium";        ws["B9"] = sum(1 for f in findings if f.severity == "Medium")
    ws["A10"] = "Low";          ws["B10"] = sum(1 for f in findings if f.severity == "Low")
    ws["A11"] = "Informational";ws["B11"] = sum(1 for f in findings if f.severity == "Informational")
    ws["A13"] = "Disclaimer"; ws["A13"].font = Font(bold=True)
    ws["A14"] = DISCLAIMER; ws["A14"].alignment = Alignment(wrap_text=True)
    ws.column_dimensions["A"].width = 30
    ws.column_dimensions["B"].width = 15


def _write_findings_sheet(ws, findings):
    from openpyxl.styles import Font, PatternFill
    headers = [
        "Severity", "Confidence", "Finding Type", "Title", "Description",
        "Recommendation", "Status", "Engineer Comment", "Risk Score", "Created"
    ]
    ws.append(headers)
    for cell in ws[1]:
        cell.font = Font(bold=True, color="FFFFFF")
        cell.fill = PatternFill(fill_type="solid", fgColor="111827")

    FILL_MAP = {"High": "fee2e2", "Medium": "fef3c7", "Low": "dbeafe", "Informational": "f3f4f6"}

    for f in findings:
        ws.append([
            f.severity, f.confidence, f.finding_type.replace("_", " ").title(),
            f.title, f.description, f.recommendation or "",
            f.status, f.engineer_comment or "", f.risk_score or 0,
            f.created_at.strftime("%Y-%m-%d") if f.created_at else "",
        ])
        fill_color = FILL_MAP.get(f.severity, "ffffff")
        row_num = ws.max_row
        for col in range(1, len(headers) + 1):
            ws.cell(row=row_num, column=col).fill = PatternFill(fill_type="solid", fgColor=fill_color)

    for col_letter, width in zip("ABCDEFGHIJ", [12, 12, 22, 40, 60, 50, 22, 30, 10, 12]):
        ws.column_dimensions[col_letter].width = width


def _write_rules_sheet(ws, rules):
    from openpyxl.styles import Font, PatternFill
    headers = [
        "#", "Rule ID", "Rule Name", "Source", "Destination", "Service",
        "Action", "Enabled", "Hit Count", "Last Hit", "Logging", "Risk Score", "Comments"
    ]
    ws.append(headers)
    for cell in ws[1]:
        cell.font = Font(bold=True, color="FFFFFF")
        cell.fill = PatternFill(fill_type="solid", fgColor="111827")

    for r in rules:
        ws.append([
            r.rule_number, r.rule_id, r.rule_name or "",
            ", ".join(r.sources or []), ", ".join(r.destinations or []),
            ", ".join(r.services or []), r.action or "",
            "Yes" if r.enabled else "No",
            r.hit_count if r.hit_count is not None else "N/A",
            r.last_hit or "", "Yes" if r.logging_enabled else "No",
            f"{r.risk_score or 0:.0f}", r.comments or "",
        ])

    for col_letter, width in zip("ABCDEFGHIJKLM", [5, 10, 25, 30, 30, 25, 10, 8, 10, 12, 8, 8, 30]):
        ws.column_dimensions[col_letter].width = width


# ═══════════════════════════════════════════════════════════════════════════════
# ── Report Builder v2 ─────────────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════

from pydantic import BaseModel as _BaseModel

FULL_DISCLAIMER = (
    "This report was generated using read-only firewall policy data available to PolicyInsight "
    "at the time of analysis. PolicyInsight does not perform firewall changes and does not delete, "
    "disable, modify, reorder, or install firewall policies or objects.\n\n"
    "The findings and recommendations in this report are intended to support review and planning "
    "activities only. Any firewall changes must be validated by the responsible technical teams, "
    "approved through the appropriate change management process, and implemented outside PolicyInsight."
)

CATEGORY_META: dict = {
    "overly_permissive":  "Overly Permissive Rules",
    "disabled_rule":      "Disabled Rules",
    "zero_hit_rule":      "Zero-Hit Rules",
    "low_usage_rule":     "Low-Usage Rules",
    "duplicate_rule":     "Duplicate Rules",
    "shadowed_rule":      "Shadowed Rules",
    "risky_service":      "Risky Service Rules",
    "no_logging":         "Rules Without Logging",
    "temporary_rule":     "Temporary Rules",
    "expired_rule":       "Expired Schedule Rules",
    "no_documentation":   "Undocumented Rules",
    "naming_quality":     "Naming Quality",
    "nat_complexity":     "NAT Rule Findings",
    "vpn_access":         "Broad VPN Access",
    "negated_object":     "Negated Object Rules",
    "unused_object":      "Unused Objects",
    "duplicate_object":   "Duplicate Objects",
    "empty_group":        "Empty Groups",
    "large_group":        "Large Groups",
    "broad_network":      "Broad Network Objects",
    "service_range":      "Wide Service Ranges",
}

REPORT_TYPE_TITLES: dict = {
    "executive":   "Executive Firewall Audit Report",
    "technical":   "Firewall Policy Technical Review",
    "internal":    "Internal Engineering Export",
    "cleanup":     "Cleanup Candidate Report",
    "posture":     "Security Posture Assessment",
    "comparison":  "Policy Comparison Report",
    "compliance":  "Compliance Mapping Report",
}


class ReportBranding(_BaseModel):
    company_name: str = "PolicyInsight"
    customer_name: Optional[str] = None
    confidentiality: str = "Confidential"
    prepared_by: str = ""
    accent_color: str = "#1e3a5f"
    report_title: Optional[str] = None


class ReportBuildConfig(_BaseModel):
    report_type: str = "technical"
    detail_level: str = "standard"          # summary | standard | detailed
    sections: List[str] = []               # exec_summary, scope, findings_summary, findings_detail, posture
    finding_categories: List[str] = []     # which finding_type values to include
    severities: List[str] = ["High", "Medium", "Low", "Informational"]
    statuses: Optional[List[str]] = None
    finding_ids: Optional[List[str]] = None
    include_rules: bool = True
    appendices: List[str] = []             # appendix_rulebase, appendix_objects
    branding: ReportBranding = ReportBranding()


@router.post("/{policy_id}/build")
def build_report_v2(
    policy_id: str,
    config: ReportBuildConfig,
    format: str = Query("html", regex="^(html|excel|csv|json)$"),
    customer_id: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """Build a fully customisable report from the given configuration."""
    policy = db.query(FirewallPolicy).filter(FirewallPolicy.id == policy_id).first()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    if customer_id:
        assert_policy_customer(policy_id, customer_id, db)

    need_rules = config.include_rules or "appendix_rulebase" in config.appendices
    rules = (
        db.query(FirewallRule)
        .filter(FirewallRule.policy_id == policy_id)
        .order_by(FirewallRule.rule_number)
        .all()
    ) if need_rules else []

    fq = db.query(Finding).filter(Finding.policy_id == policy_id)
    if config.severities:
        fq = fq.filter(Finding.severity.in_(config.severities))
    if config.statuses:
        fq = fq.filter(Finding.status.in_(config.statuses))
    if config.finding_categories:
        fq = fq.filter(Finding.finding_type.in_(config.finding_categories))
    if config.finding_ids:
        fq = fq.filter(Finding.id.in_(config.finding_ids))
    findings = fq.order_by(Finding.severity, Finding.finding_type, Finding.created_at).all()

    branding = config.branding
    customer_name = branding.customer_name or (policy.customer.name if policy.customer else "") or ""
    now_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_fw = "".join(c if c.isalnum() or c in "-_" else "_" for c in policy.firewall_name)

    if format == "html":
        html = _build_html_full(policy, rules, findings, config, customer_name)
        return HTMLResponse(content=html)

    if format == "excel":
        try:
            import openpyxl
        except ImportError:
            raise HTTPException(status_code=500, detail="openpyxl not installed")
        wb = _build_excel_full(policy, rules, findings, config, customer_name)
        buf = io.BytesIO()
        wb.save(buf)
        buf.seek(0)
        filename = f"report_{safe_fw}_{now_str}.xlsx"
        return StreamingResponse(
            buf,
            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    if format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Severity", "Confidence", "Finding Type", "Title",
                         "Description", "Recommendation", "Status"])
        for f in findings:
            writer.writerow([f.severity, f.confidence,
                             CATEGORY_META.get(f.finding_type, f.finding_type),
                             f.title, f.description, f.recommendation or "", f.status])
        output.seek(0)
        filename = f"findings_{safe_fw}_{now_str}.csv"
        return StreamingResponse(
            io.BytesIO(output.getvalue().encode()),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    # JSON
    data = {
        "report_generated": datetime.now().isoformat(),
        "report_type":  config.report_type,
        "detail_level": config.detail_level,
        "disclaimer":   FULL_DISCLAIMER,
        "branding":     branding.dict(),
        "policy": {
            "id":               policy.id,
            "firewall_name":    policy.firewall_name,
            "vendor":           policy.vendor,
            "policy_package":   policy.policy_package,
            "rule_count":       policy.rule_count,
            "object_count":     policy.object_count,
            "health_score":     policy.health_score,
            "complexity_score": policy.complexity_score,
            "upload_date":      policy.upload_date.isoformat() if policy.upload_date else None,
        },
        "customer": customer_name,
        "summary": {
            "total_findings": len(findings),
            "by_severity": {sev: sum(1 for f in findings if f.severity == sev)
                            for sev in ["High", "Medium", "Low", "Informational"]},
            "by_category": {ftype: sum(1 for f in findings if f.finding_type == ftype)
                            for ftype in set(f.finding_type for f in findings)},
        },
        "findings": [{
            "finding_type":   f.finding_type,
            "severity":       f.severity,
            "confidence":     f.confidence,
            "title":          f.title,
            "description":    f.description,
            "recommendation": f.recommendation,
            "evidence":       f.evidence,
            "status":         f.status,
            "risk_score":     f.risk_score,
        } for f in findings],
    }
    if rules and config.include_rules:
        data["rulebase"] = [{
            "rule_number": r.rule_number,
            "rule_name":   r.rule_name,
            "sources":     r.sources,
            "destinations": r.destinations,
            "services":    r.services,
            "action":      r.action,
            "enabled":     r.enabled,
            "hit_count":   r.hit_count,
            "risk_score":  r.risk_score,
        } for r in rules]
    filename = f"report_{safe_fw}_{now_str}.json"
    return StreamingResponse(
        io.BytesIO(json.dumps(data, indent=2, default=str).encode()),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ── HTML builder (full) ────────────────────────────────────────────────────────

def _build_html_full(policy, rules, findings, config: ReportBuildConfig, customer_name: str) -> str:
    now = datetime.now()
    now_str = now.strftime("%Y-%m-%d %H:%M UTC")
    date_str = now.strftime("%B %d, %Y")
    b = config.branding
    accent = b.accent_color or "#1e3a5f"
    title = b.report_title or REPORT_TYPE_TITLES.get(config.report_type, "Firewall Policy Report")

    # Group findings by type
    by_type: dict = {}
    for f in findings:
        by_type.setdefault(f.finding_type, []).append(f)

    sev_counts = {s: sum(1 for f in findings if f.severity == s)
                  for s in ("High", "Medium", "Low", "Informational")}
    total = len(findings)

    # Helpers
    def _sev_color(sev): return {"High":"#dc2626","Medium":"#d97706","Low":"#3b82f6","Informational":"#6b7280"}.get(sev,"#6b7280")
    def _sev_bg(sev):    return {"High":"#fee2e2","Medium":"#fef3c7","Low":"#dbeafe","Informational":"#f3f4f6"}.get(sev,"#f9fafb")

    def score_ring(score: int, color: str, label: str) -> str:
        r, cx, cy = 38, 48, 48
        circ = 2 * 3.14159 * r
        offset = circ - (max(0, min(100, score)) / 100) * circ
        return (f'<div class="ring-wrap">'
                f'<svg width="96" height="96" viewBox="0 0 96 96">'
                f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="#e5e7eb" stroke-width="8"/>'
                f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{color}" stroke-width="8"'
                f' stroke-linecap="round" stroke-dasharray="{circ:.1f}" stroke-dashoffset="{offset:.1f}"'
                f' transform="rotate(-90 {cx} {cy})"/>'
                f'<text x="{cx}" y="{cy+7}" text-anchor="middle" font-size="17" font-weight="800" fill="{color}">{score}</text>'
                f'</svg>'
                f'<div class="ring-label">{label}</div></div>')

    def sev_bar(counts: dict, tot: int) -> str:
        if not tot:
            return '<div class="sev-bar-empty">No findings</div>'
        segs = ""
        for sev, clr in (("High","#dc2626"),("Medium","#d97706"),("Low","#3b82f6"),("Informational","#9ca3af")):
            n = counts.get(sev, 0)
            if n:
                segs += f'<span style="flex:{n};background:{clr};border-radius:2px" title="{sev}: {n}"></span>'
        legend = " &nbsp; ".join(
            f'<span><b style="color:{c}">{counts.get(s,0)}</b> {s}</span>'
            for s, c in (("High","#dc2626"),("Medium","#d97706"),("Low","#3b82f6"),("Informational","#9ca3af"))
        )
        return f'<div class="sev-bar">{segs}</div><div class="sev-legend">{legend}</div>'

    # Section: Executive Summary
    def exec_summary_html() -> str:
        health = int(policy.health_score or 0)
        complexity = int(policy.complexity_score or 0)
        h_clr = "#10b981" if health >= 70 else "#f59e0b" if health >= 40 else "#ef4444"
        c_clr = "#ef4444" if complexity >= 70 else "#f59e0b" if complexity >= 40 else "#10b981"

        obs = []
        if sev_counts["High"] > 0:
            obs.append(f'<li><span style="color:#dc2626;font-weight:600">⚠ {sev_counts["High"]} high-severity finding{"s" if sev_counts["High"]!=1 else ""}</span> require prompt review.</li>')
        if sev_counts["Medium"] > 0:
            obs.append(f'<li>{sev_counts["Medium"]} medium-severity finding{"s" if sev_counts["Medium"]!=1 else ""} identified.</li>')
        top3 = sorted(by_type.items(), key=lambda x: -len(x[1]))[:3]
        for ftype, fl in top3:
            lbl = CATEGORY_META.get(ftype, ftype.replace("_"," ").title())
            obs.append(f'<li>{len(fl)} {lbl.lower()} finding{"s" if len(fl)!=1 else ""}.</li>')
        if not obs:
            obs.append("<li>No significant findings in the selected categories.</li>")

        return f'''
        <div class="report-section">
          <div class="section-header"><h2>Executive Summary</h2></div>
          <div class="exec-body">
            <div class="score-row">
              {score_ring(health, h_clr, "Health Score")}
              {score_ring(complexity, c_clr, "Complexity")}
              <div class="exec-right">
                <div class="stat-grid">
                  <div class="stat-card"><div class="stat-n">{total}</div><div class="stat-l">Total</div></div>
                  <div class="stat-card high"><div class="stat-n">{sev_counts["High"]}</div><div class="stat-l">High</div></div>
                  <div class="stat-card med"><div class="stat-n">{sev_counts["Medium"]}</div><div class="stat-l">Medium</div></div>
                  <div class="stat-card low"><div class="stat-n">{sev_counts["Low"]}</div><div class="stat-l">Low</div></div>
                </div>
                {sev_bar(sev_counts, total)}
              </div>
            </div>
            <div class="obs-box">
              <div class="obs-title">Key Observations</div>
              <ul>{"".join(obs)}</ul>
            </div>
          </div>
        </div>'''

    # Section: Findings Summary Table
    def findings_summary_html() -> str:
        if not by_type:
            return ''
        rows = "".join(
            f'<tr><td>{CATEGORY_META.get(ft,ft.replace("_"," ").title())}</td>'
            f'<td class="tc high-clr">{sum(1 for f in fl if f.severity=="High") or ""}</td>'
            f'<td class="tc med-clr">{sum(1 for f in fl if f.severity=="Medium") or ""}</td>'
            f'<td class="tc low-clr">{sum(1 for f in fl if f.severity=="Low") or ""}</td>'
            f'<td class="tc info-clr">{sum(1 for f in fl if f.severity=="Informational") or ""}</td>'
            f'<td class="tc bold">{len(fl)}</td></tr>'
            for ft, fl in sorted(by_type.items(), key=lambda x: -len(x[1]))
        )
        return f'''
        <div class="report-section">
          <div class="section-header"><h2>Findings Summary</h2><span class="badge">{total} total</span></div>
          <table><thead><tr>
            <th>Category</th>
            <th class="tc" style="width:55px">High</th>
            <th class="tc" style="width:55px">Med</th>
            <th class="tc" style="width:55px">Low</th>
            <th class="tc" style="width:55px">Info</th>
            <th class="tc" style="width:55px">Total</th>
          </tr></thead><tbody>{rows}</tbody></table>
        </div>'''

    # Section: Per-category findings detail
    def category_section_html(ftype: str, flist: list) -> str:
        label = CATEGORY_META.get(ftype, ftype.replace("_"," ").title())
        rows = ""
        for f in flist:
            clr = _sev_color(f.severity)
            desc = ""
            if config.detail_level in ("standard", "detailed"):
                d = f.description or ""
                if config.detail_level == "standard" and len(d) > 260:
                    d = d[:260] + "…"
                if d:
                    desc = f'<div class="f-desc">{d}</div>'
            evid = ""
            if config.detail_level == "detailed" and f.evidence and isinstance(f.evidence, dict):
                chips = "".join(
                    f'<span class="ev-chip"><b>{k.replace("_"," ").title()}:</b> {v}</span>'
                    for k, v in list(f.evidence.items())[:6]
                )
                evid = f'<div class="ev-row">{chips}</div>'
            rec = f'<div class="rec-box">{f.recommendation}</div>' if f.recommendation else ""
            rows += (
                f'<tr><td class="sev-col"><span class="sev-badge" style="background:{clr}">{f.severity}</span></td>'
                f'<td><div class="f-title">{f.title}</div>{desc}{evid}{rec}</td>'
                f'<td class="stat-col">{f.status or ""}</td></tr>'
            )
        return f'''
        <div class="report-section">
          <div class="section-header"><h2>{label}</h2><span class="badge">{len(flist)}</span></div>
          <table><thead><tr>
            <th style="width:75px">Severity</th><th>Finding / Recommendation</th>
            <th style="width:110px">Status</th>
          </tr></thead><tbody>{rows}</tbody></table>
        </div>'''

    # Section: Scope & Methodology
    def scope_html() -> str:
        return f'''
        <div class="report-section">
          <div class="section-header"><h2>Scope &amp; Methodology</h2></div>
          <div class="prose">
            <p>This report covers the firewall policy analysis for <strong>{policy.firewall_name}</strong>
            (Vendor: {policy.vendor}, Policy Package: {policy.policy_package or "Default"}).
            The analysis was performed using PolicyInsight's read-only analysis engine, which examines
            rule structure, object usage, security posture, and policy hygiene without accessing live
            traffic data or making any changes to the firewall configuration.</p>
            <p>A total of <strong>{policy.rule_count}</strong> rules and
            <strong>{policy.object_count or 0}</strong> objects were analysed. The findings presented
            represent areas that may benefit from review by the responsible technical team.</p>
            <p><strong>Analysis methodology:</strong> Rules are analysed for permissiveness, usage
            patterns, documentation, naming conventions, and structural issues such as shadowing and
            duplication. Objects are analysed for unused status, duplication, and scope breadth.
            All recommendations require validation and formal change approval before any implementation.</p>
          </div>
        </div>'''

    # Section: Posture
    def posture_html() -> str:
        health = int(policy.health_score or 0)
        complexity = int(policy.complexity_score or 0)
        cleanup = int(policy.cleanup_readiness_score or 0)
        rows = (
            f'<tr><td>Health Score</td><td style="font-weight:700;color:{"#10b981" if health>=70 else "#f59e0b" if health>=40 else "#ef4444"}">{health}/100</td></tr>'
            f'<tr><td>Complexity Index</td><td style="font-weight:700;color:{"#ef4444" if complexity>=70 else "#f59e0b" if complexity>=40 else "#10b981"}">{complexity}/100</td></tr>'
            f'<tr><td>Cleanup Readiness</td><td>{cleanup}%</td></tr>'
            f'<tr><td>Total Rules</td><td>{policy.rule_count}</td></tr>'
            f'<tr><td>Total Objects</td><td>{policy.object_count or 0}</td></tr>'
            f'<tr><td>Total Findings</td><td>{total}</td></tr>'
            f'<tr><td>High Findings</td><td style="color:#dc2626;font-weight:700">{sev_counts["High"]}</td></tr>'
        )
        return f'''
        <div class="report-section">
          <div class="section-header"><h2>Security Posture</h2></div>
          <table style="max-width:400px"><thead><tr><th>Metric</th><th>Value</th></tr></thead>
          <tbody>{rows}</tbody></table>
        </div>'''

    # Rulebase appendix
    def rulebase_appendix_html() -> str:
        if not rules:
            return ''
        display = rules[:600]
        row_html = "".join(
            f'<tr>'
            f'<td>{r.rule_number}</td>'
            f'<td class="mono">{r.rule_id or ""}</td>'
            f'<td>{r.rule_name or ""}</td>'
            f'<td>{", ".join((r.sources or [])[:3])}{"…" if len(r.sources or [])>3 else ""}</td>'
            f'<td>{", ".join((r.destinations or [])[:3])}{"…" if len(r.destinations or [])>3 else ""}</td>'
            f'<td>{", ".join((r.services or [])[:2])}{"…" if len(r.services or [])>2 else ""}</td>'
            f'<td style="font-weight:700;color:{"#15803d" if (r.action or "").lower() in ("allow","accept","permit") else "#dc2626"}">{r.action or ""}</td>'
            f'<td>{"✓" if r.enabled else "✗"}</td>'
            f'<td style="text-align:right">{r.hit_count if r.hit_count is not None else "—"}</td>'
            f'<td style="text-align:right;font-weight:600">{r.risk_score or 0:.0f}</td>'
            f'</tr>'
            for r in display
        )
        trunc = f'<div class="trunc">Showing {len(display)} of {len(rules)} rules</div>' if len(rules) > len(display) else ""
        return f'''
        <div class="report-section">
          <div class="section-header"><h2>Appendix: Full Rulebase</h2><span class="badge">{len(rules)} rules</span></div>
          <div class="app-table"><table><thead><tr>
            <th style="width:30px">#</th><th style="width:80px">Rule ID</th>
            <th style="width:120px">Name</th><th>Source</th><th>Destination</th>
            <th>Service</th><th style="width:60px">Action</th>
            <th style="width:30px">On</th><th style="width:45px;text-align:right">Hits</th>
            <th style="width:40px;text-align:right">Risk</th>
          </tr></thead><tbody>{row_html}</tbody></table>{trunc}</div>
        </div>'''

    # Compose sections
    selected = set(config.sections)
    use_all_sections = not selected

    parts = []
    if use_all_sections or "exec_summary" in selected:
        parts.append(exec_summary_html())
    if "scope" in selected:
        parts.append(scope_html())
    if use_all_sections or "findings_summary" in selected:
        parts.append(findings_summary_html())
    if use_all_sections or "posture" in selected:
        parts.append(posture_html())
    if use_all_sections or "findings_detail" in selected:
        cats = config.finding_categories or list(by_type.keys())
        for ft in cats:
            fl = by_type.get(ft, [])
            if fl:
                parts.append(category_section_html(ft, fl))
    if "appendix_rulebase" in config.appendices:
        parts.append(rulebase_appendix_html())

    sections_html = "\n".join(parts)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} — {policy.firewall_name}</title>
<style>
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
:root{{--acc:{accent};--acc22:{accent}22}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial,sans-serif;font-size:13px;color:#111827;background:#f3f4f6;line-height:1.5}}
.wrap{{max-width:1100px;margin:0 auto;padding:28px 20px}}
/* Cover */
.cover{{background:white;border-radius:12px;overflow:hidden;margin-bottom:28px;box-shadow:0 1px 4px rgba(0,0,0,.08)}}
.cover-bar{{height:7px;background:var(--acc)}}
.cover-inner{{padding:48px 56px}}
.cover-logo{{font-size:12px;font-weight:800;letter-spacing:1.5px;text-transform:uppercase;color:var(--acc);margin-bottom:64px}}
.cover-title{{font-size:30px;font-weight:800;color:#111827;letter-spacing:-.5px;margin-bottom:6px}}
.cover-sub{{font-size:17px;color:#6b7280;margin-bottom:48px}}
.cover-grid{{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:48px}}
.cm .lbl{{font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#9ca3af;margin-bottom:3px}}
.cm .val{{font-size:15px;font-weight:600;color:#111827}}
.cover-ft{{display:flex;justify-content:space-between;align-items:center;border-top:1px solid #e5e7eb;padding-top:24px}}
.confidentiality{{display:inline-block;border:1.5px solid var(--acc);color:var(--acc);font-size:10px;font-weight:800;letter-spacing:1.5px;text-transform:uppercase;padding:4px 12px;border-radius:4px}}
/* Disclaimer */
.disclaimer{{background:#fffbeb;border:1px solid #fde68a;border-left:4px solid #f59e0b;border-radius:8px;padding:14px 18px;margin-bottom:24px;font-size:12px;color:#78350f;line-height:1.6}}
/* Sections */
.report-section{{background:white;border:1px solid #e5e7eb;border-radius:10px;margin-bottom:20px;overflow:hidden}}
.section-header{{padding:14px 18px;border-bottom:1px solid #f3f4f6;display:flex;align-items:center;gap:10px}}
.section-header h2{{font-size:14px;font-weight:700;color:#111827}}
.badge{{font-size:11px;font-weight:600;background:#f3f4f6;color:#6b7280;padding:2px 8px;border-radius:999px;margin-left:auto}}
/* Exec summary */
.exec-body{{padding:18px 20px}}
.score-row{{display:flex;align-items:flex-start;gap:20px;margin-bottom:16px}}
.ring-wrap{{text-align:center;flex-shrink:0}}
.ring-label{{font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.7px;color:#9ca3af;margin-top:2px}}
.exec-right{{flex:1}}
.stat-grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-bottom:10px}}
.stat-card{{text-align:center;border:1px solid #e5e7eb;border-radius:8px;padding:10px 6px;background:#f9fafb}}
.stat-card.high{{background:#fee2e2;border-color:#fca5a5}}.stat-card.med{{background:#fef3c7;border-color:#fcd34d}}.stat-card.low{{background:#dbeafe;border-color:#93c5fd}}
.stat-n{{font-size:22px;font-weight:800;color:#111827}}.stat-l{{font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.5px;color:#9ca3af}}
.stat-card.high .stat-n{{color:#dc2626}}.stat-card.med .stat-n{{color:#d97706}}.stat-card.low .stat-n{{color:#2563eb}}
.sev-bar{{display:flex;height:7px;border-radius:4px;overflow:hidden;gap:2px;margin-bottom:4px}}
.sev-bar-empty{{font-size:12px;color:#9ca3af}}
.sev-legend{{font-size:11px;color:#6b7280;display:flex;gap:12px}}
.obs-box{{padding:12px 14px;background:#f9fafb;border-radius:8px;margin-top:12px}}
.obs-title{{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.6px;color:#6b7280;margin-bottom:6px}}
.obs-box li{{font-size:13px;padding:3px 0;list-style:none}}
/* Prose */
.prose{{padding:18px 20px}}.prose p{{margin-bottom:10px;color:#374151;line-height:1.7}}
/* Tables */
table{{width:100%;border-collapse:collapse}}
thead th{{background:#f9fafb;padding:9px 12px;text-align:left;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.6px;color:#6b7280;border-bottom:1px solid #e5e7eb}}
tbody td{{padding:9px 12px;border-bottom:1px solid #f3f4f6;vertical-align:top}}
tbody tr:last-child td{{border-bottom:none}}
.tc{{text-align:center}}.bold{{font-weight:700}}.mono{{font-family:monospace;font-size:10px}}
.high-clr{{color:#dc2626;font-weight:700}}.med-clr{{color:#d97706;font-weight:700}}.low-clr{{color:#2563eb;font-weight:700}}.info-clr{{color:#9ca3af}}
/* Finding rows */
.sev-col{{width:75px;vertical-align:top}}.stat-col{{width:110px;vertical-align:top;font-size:11px;color:#6b7280}}
.sev-badge{{display:inline-block;color:white;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700}}
.f-title{{font-weight:600;font-size:13px;margin-bottom:3px}}
.f-desc{{font-size:12px;color:#4b5563;margin:4px 0;line-height:1.5}}
.ev-row{{display:flex;flex-wrap:wrap;gap:4px;margin:4px 0}}
.ev-chip{{font-size:10px;background:#f3f4f6;border-radius:3px;padding:2px 5px;color:#4b5563}}
.rec-box{{font-size:12px;color:#1d4ed8;background:#eff6ff;border-left:3px solid #93c5fd;padding:6px 10px;margin-top:5px;border-radius:0 4px 4px 0;line-height:1.5}}
/* App table */
.app-table{{overflow-x:auto}}
.app-table th,.app-table td{{font-size:11px;padding:6px 8px}}
.trunc{{font-size:11px;color:#9ca3af;text-align:center;padding:8px;border-top:1px solid #f3f4f6}}
/* Footer */
.report-footer{{text-align:center;font-size:11px;color:#9ca3af;margin-top:28px;padding-top:14px;border-top:1px solid #e5e7eb}}
@media print{{
  body{{background:white}}
  .wrap{{padding:0;max-width:none}}
  .cover{{box-shadow:none;page-break-after:always}}
  .report-section{{page-break-inside:avoid;box-shadow:none}}
  @page{{margin:15mm;size:A4}}
}}
</style>
</head>
<body>
<div class="wrap">

<!-- Cover Page -->
<div class="cover">
  <div class="cover-bar"></div>
  <div class="cover-inner">
    <div class="cover-logo">{b.company_name}</div>
    <div class="cover-title">{title}</div>
    <div class="cover-sub">{policy.firewall_name}</div>
    <div class="cover-grid">
      <div class="cm"><div class="lbl">Customer</div><div class="val">{customer_name or "—"}</div></div>
      <div class="cm"><div class="lbl">Vendor</div><div class="val">{policy.vendor}</div></div>
      <div class="cm"><div class="lbl">Policy Package</div><div class="val">{policy.policy_package or "Default"}</div></div>
      <div class="cm"><div class="lbl">Rules Analysed</div><div class="val">{policy.rule_count}</div></div>
      <div class="cm"><div class="lbl">Assessment Date</div><div class="val">{date_str}</div></div>
      <div class="cm"><div class="lbl">Total Findings</div><div class="val" style="color:{"#dc2626" if sev_counts["High"] else "#111827"}">{total}</div></div>
    </div>
    <div class="cover-ft">
      <div>
        {"<div style='font-size:12px;color:#6b7280'>Prepared by: <strong style=color:#111827>" + b.prepared_by + "</strong></div>" if b.prepared_by else ""}
        <div style="font-size:11px;color:#9ca3af;margin-top:3px">Generated: {now_str}</div>
      </div>
      <span class="confidentiality">{b.confidentiality}</span>
    </div>
  </div>
</div>

<!-- Disclaimer -->
<div class="disclaimer">
  <strong>⚠ Read-Only Analysis — No Firewall Changes Were Made:</strong> This report was generated using read-only firewall policy data.
  PolicyInsight does not delete, disable, modify, reorder, or install firewall policies or objects.
  All recommendations require engineer validation and formal change approval before any implementation.
</div>

{sections_html}

<div class="report-footer">
  PolicyInsight &nbsp;·&nbsp; {title} &nbsp;·&nbsp; {policy.firewall_name} &nbsp;·&nbsp; {now_str} &nbsp;·&nbsp; {b.confidentiality}
</div>
</div>
</body>
</html>"""


# ── Excel builder (full) ───────────────────────────────────────────────────────

CATEGORY_SHEET_NAMES: dict = {
    "overly_permissive":  "Permissive Rules",
    "disabled_rule":      "Disabled Rules",
    "zero_hit_rule":      "Zero-Hit Rules",
    "low_usage_rule":     "Low-Usage Rules",
    "duplicate_rule":     "Duplicate Rules",
    "shadowed_rule":      "Shadowed Rules",
    "risky_service":      "Risky Services",
    "no_logging":         "No Logging",
    "temporary_rule":     "Temp Rules",
    "expired_rule":       "Expired Rules",
    "no_documentation":   "Undocumented",
    "naming_quality":     "Naming Quality",
    "nat_complexity":     "NAT Findings",
    "vpn_access":         "VPN Access",
    "negated_object":     "Negated Objects",
    "unused_object":      "Unused Objects",
    "duplicate_object":   "Duplicate Objects",
    "empty_group":        "Empty Groups",
    "large_group":        "Large Groups",
    "broad_network":      "Broad Networks",
    "service_range":      "Service Ranges",
}

CLEANUP_TYPES = {"disabled_rule","zero_hit_rule","low_usage_rule","duplicate_rule","shadowed_rule","temporary_rule"}


def _build_excel_full(policy, rules, findings, config: ReportBuildConfig, customer_name: str):
    """Build a multi-sheet Excel workbook with per-category worksheets."""
    import openpyxl
    from openpyxl.styles import Font, PatternFill, Alignment

    DARK  = PatternFill(fill_type="solid", fgColor="111827")
    ACCF  = PatternFill(fill_type="solid", fgColor="1e3a5f")
    H_RED = PatternFill(fill_type="solid", fgColor="fee2e2")
    H_AMB = PatternFill(fill_type="solid", fgColor="fef3c7")
    H_BLU = PatternFill(fill_type="solid", fgColor="dbeafe")
    H_GRY = PatternFill(fill_type="solid", fgColor="f3f4f6")
    SEV_FILL = {"High": H_RED, "Medium": H_AMB, "Low": H_BLU, "Informational": H_GRY}
    H_FONT = Font(bold=True, color="FFFFFF")

    def hdr(ws, cols):
        ws.append(cols)
        for cell in ws[1]:
            cell.font = H_FONT
            cell.fill = DARK
            cell.alignment = Alignment(wrap_text=False)

    def style_sev_row(ws, row_idx, sev):
        fill = SEV_FILL.get(sev, H_GRY)
        for col in range(1, ws.max_column + 1):
            ws.cell(row=row_idx, column=col).fill = fill

    wb = openpyxl.Workbook()

    # 1. Summary
    ws = wb.active
    ws.title = "Summary"
    b = config.branding
    ws["A1"] = b.report_title or REPORT_TYPE_TITLES.get(config.report_type, "Firewall Policy Report")
    ws["A1"].font = Font(bold=True, size=14, color="111827")
    ws.append([])
    ws.append(["Customer", customer_name])
    ws.append(["Firewall", policy.firewall_name])
    ws.append(["Vendor", policy.vendor])
    ws.append(["Policy Package", policy.policy_package or "Default"])
    ws.append(["Rules Analysed", policy.rule_count])
    ws.append(["Objects", policy.object_count or 0])
    ws.append(["Generated", datetime.now().strftime("%Y-%m-%d %H:%M")])
    ws.append(["Prepared by", b.prepared_by])
    ws.append(["Confidentiality", b.confidentiality])
    ws.append([])
    ws.append(["FINDINGS SUMMARY"])
    ws[f"A{ws.max_row}"].font = Font(bold=True)
    ws.append(["Total Findings", len(findings)])
    for sev in ("High", "Medium", "Low", "Informational"):
        n = sum(1 for f in findings if f.severity == sev)
        ws.append([sev, n])
    ws.append([])
    ws.append(["FINDINGS BY CATEGORY"])
    ws[f"A{ws.max_row}"].font = Font(bold=True)
    by_type: dict = {}
    for f in findings:
        by_type.setdefault(f.finding_type, []).append(f)
    for ftype, fl in sorted(by_type.items(), key=lambda x: -len(x[1])):
        ws.append([CATEGORY_META.get(ftype, ftype), len(fl)])
    ws.append([])
    ws.append(["DISCLAIMER"])
    ws[f"A{ws.max_row}"].font = Font(bold=True)
    disc_row = ws.max_row + 1
    ws.append([FULL_DISCLAIMER])
    ws.cell(row=disc_row, column=1).alignment = Alignment(wrap_text=True)
    ws.row_dimensions[disc_row].height = 90
    ws.column_dimensions["A"].width = 28
    ws.column_dimensions["B"].width = 45

    # 2. All Findings
    wa = wb.create_sheet("All Findings")
    hdr(wa, ["Severity", "Confidence", "Category", "Title", "Description", "Recommendation", "Status", "Risk Score"])
    for f in findings:
        wa.append([f.severity, f.confidence,
                   CATEGORY_META.get(f.finding_type, f.finding_type),
                   f.title, f.description or "", f.recommendation or "",
                   f.status, f.risk_score or 0])
        style_sev_row(wa, wa.max_row, f.severity)
    for cl, w in zip("ABCDEFGH", [10, 10, 26, 48, 70, 60, 24, 8]):
        wa.column_dimensions[cl].width = w
    wa.freeze_panes = "A2"
    wa.auto_filter.ref = f"A1:H{wa.max_row}"

    # 3. Per-category sheets
    for ftype, flist in sorted(by_type.items(), key=lambda x: -len(x[1])):
        sheet_name = CATEGORY_SHEET_NAMES.get(ftype, ftype[:31])
        wc = wb.create_sheet(sheet_name)
        hdr(wc, ["Severity", "Title", "Description", "Recommendation", "Status", "Risk Score"])
        for f in flist:
            wc.append([f.severity, f.title, f.description or "", f.recommendation or "", f.status, f.risk_score or 0])
            style_sev_row(wc, wc.max_row, f.severity)
        for cl, w in zip("ABCDEF", [10, 48, 70, 60, 24, 8]):
            wc.column_dimensions[cl].width = w
        wc.freeze_panes = "A2"

    # 4. Cleanup Candidates
    cleanup = [f for f in findings if f.finding_type in CLEANUP_TYPES]
    if cleanup:
        wk = wb.create_sheet("Cleanup Candidates")
        hdr(wk, ["Severity", "Category", "Title", "Description", "Recommendation", "Status"])
        for f in cleanup:
            wk.append([f.severity, CATEGORY_META.get(f.finding_type, f.finding_type),
                       f.title, f.description or "", f.recommendation or "", f.status])
            style_sev_row(wk, wk.max_row, f.severity)
        for cl, w in zip("ABCDEF", [10, 26, 48, 70, 60, 24]):
            wk.column_dimensions[cl].width = w
        wk.freeze_panes = "A2"

    # 5. Rulebase
    if config.include_rules and rules:
        wr = wb.create_sheet("Rulebase")
        _write_rules_sheet(wr, rules)

    return wb
