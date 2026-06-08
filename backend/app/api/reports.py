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
    db: Session = Depends(get_db),
):
    policy, rules, findings = _load_report_data(
        policy_id, db, severities, finding_types, statuses, finding_ids
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
    db: Session = Depends(get_db),
):
    try:
        import openpyxl
        from openpyxl.styles import Font, PatternFill, Alignment
    except ImportError:
        raise HTTPException(status_code=500, detail="openpyxl not installed")

    policy, rules, findings = _load_report_data(
        policy_id, db, severities, finding_types, statuses, finding_ids
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
    db: Session = Depends(get_db),
):
    policy, rules, findings = _load_report_data(
        policy_id, db, severities, finding_types, statuses, finding_ids
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
    db: Session = Depends(get_db),
):
    policy, rules, findings = _load_report_data(
        policy_id, db, severities, finding_types, statuses, finding_ids
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
):
    policy = db.query(FirewallPolicy).filter(FirewallPolicy.id == policy_id).first()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")

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
    PolicyLens — Read-Only Firewall Audit Platform &nbsp;·&nbsp; Generated {now} &nbsp;·&nbsp;
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
