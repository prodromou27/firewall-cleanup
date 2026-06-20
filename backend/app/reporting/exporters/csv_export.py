"""CSV renderer — flat export of the selected findings (with key columns)."""
import csv
import io

from app.reporting.data import ReportData


def render(data: ReportData) -> str:
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["Severity", "Confidence", "Finding Type", "Title", "Firewall",
                "Risk Score", "Affected Rules", "Affected Objects", "Status", "Recommendation"])
    for f in data.findings:
        w.writerow([f["severity"], f["confidence"], f["finding_type_label"], f["title"],
                    f["firewall_name"], f["risk_score"], f["affected_rule_count"],
                    f["affected_object_count"], f["status"], f["recommendation"]])
    return out.getvalue()
