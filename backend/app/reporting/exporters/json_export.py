"""JSON renderer — structured, versioned export of the shared ReportData."""
import json

from app.reporting.data import ReportData

SCHEMA_VERSION = "1.0"


def render(data: ReportData) -> str:
    meta = {k: v for k, v in data.meta.items() if k != "placeholders"}
    branding = {
        k: v for k, v in data.branding.items()
        if not k.endswith("_path")
    }
    payload = {
        "schema_version": SCHEMA_VERSION,
        "meta": meta,
        "branding": branding,
        "texts": data.texts,
        "sections": [
            {"key": s["key"], "name": s["name"], "type": s["type"],
             "finding_count": len(s.get("findings", [])) if s["type"] == "findings" else None}
            for s in data.sections
        ],
        "severity_counts": data.severity_counts,
        "category_counts": data.category_counts,
        "findings": data.findings,
        "rules": data.rules,
        "objects": data.objects,
    }
    return json.dumps(payload, indent=2, default=str)
