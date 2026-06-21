"""Export dispatch — one entry point that renders ReportData to any format."""
import re
from datetime import datetime
from typing import Tuple

from app.reporting.data import ReportData

_MEDIA = {
    "html": ("text/html", "html"),
    "pdf": ("application/pdf", "pdf"),
    "docx": ("application/vnd.openxmlformats-officedocument.wordprocessingml.document", "docx"),
    "xlsx": ("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "xlsx"),
    "csv": ("text/csv", "csv"),
    "json": ("application/json", "json"),
}
_ALIASES = {"word": "docx", "excel": "xlsx"}

SUPPORTED_FORMATS = list(_MEDIA.keys())


def _slug(s: str) -> str:
    s = re.sub(r"[^A-Za-z0-9._-]+", "-", (s or "").strip()) or "report"
    return s.strip("-")[:60]


def filename_for(data: ReportData, fmt: str, report_type: str = "Report") -> str:
    fmt = normalize_format(fmt)
    ext = _MEDIA[fmt][1]
    parts = [
        "Firewall-Report",
        _slug(data.meta.get("customer_name") or "Customer"),
        _slug(data.meta.get("firewall_name") or "Firewall"),
        _slug(report_type),
        datetime.now().strftime("%Y-%m-%d"),
    ]
    return "_".join(parts) + f".{ext}"


def normalize_format(fmt: str) -> str:
    fmt = (fmt or "").strip().lower()
    return _ALIASES.get(fmt, fmt)


def export(data: ReportData, fmt: str) -> Tuple[bytes, str, str]:
    """Render the report. Returns (bytes, media_type, file_extension)."""
    fmt = normalize_format(fmt)
    if fmt not in _MEDIA:
        raise ValueError(f"Unsupported export format: {fmt}")
    media, ext = _MEDIA[fmt]
    if fmt == "html":
        from app.reporting.exporters.html import render
        return render(data).encode("utf-8"), media, ext
    if fmt == "pdf":
        from app.reporting.exporters.pdf import render
        return render(data), media, ext
    if fmt == "docx":
        from app.reporting.exporters.docx_export import render
        return render(data), media, ext
    if fmt == "xlsx":
        from app.reporting.exporters.xlsx import render
        return render(data), media, ext
    if fmt == "csv":
        from app.reporting.exporters.csv_export import render
        return render(data).encode("utf-8"), media, ext
    if fmt == "json":
        from app.reporting.exporters.json_export import render
        return render(data).encode("utf-8"), media, ext
    raise ValueError(fmt)  # pragma: no cover
