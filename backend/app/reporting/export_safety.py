"""Small output-safety helpers shared by report exporters."""
from __future__ import annotations

import re
from urllib.parse import quote
from typing import Any

_DANGEROUS_SPREADSHEET_PREFIXES = ("=", "+", "-", "@", "\t", "\r", "\n")
_HEX_COLOR_RE = re.compile(r"^#[0-9A-Fa-f]{6}$")
_SAFE_FILENAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


def spreadsheet_cell(value: Any) -> Any:
    """Return a value safe for CSV/XLSX cells.

    Spreadsheet apps can execute values beginning with =, +, -, @ and a few
    control characters as formulas. Prefix only strings that need protection.
    """
    if not isinstance(value, str):
        return value
    return "'" + value if value.startswith(_DANGEROUS_SPREADSHEET_PREFIXES) else value


def spreadsheet_row(values: list[Any]) -> list[Any]:
    """Apply spreadsheet formula-injection protection to every cell in a row."""
    return [spreadsheet_cell(v) for v in values]


def safe_filename(name: Any, fallback: str = "report", max_len: int = 120) -> str:
    """Return a conservative filename safe for Content-Disposition and disk metadata."""
    stem = str(name or "").strip().replace("\\", "-").replace("/", "-")
    stem = _SAFE_FILENAME_RE.sub("-", stem).strip(".-_")
    if not stem:
        stem = fallback
    return stem[:max_len].rstrip(".-_") or fallback


def attachment_headers(filename: str) -> dict[str, str]:
    """Build a safe attachment header with ASCII fallback and RFC 5987 filename."""
    safe = safe_filename(filename)
    encoded = quote(safe, safe="")
    return {"Content-Disposition": f"attachment; filename=\"{safe}\"; filename*=UTF-8''{encoded}"}


def css_hex_color(value: Any, fallback: str = "#1e3a5f") -> str:
    """Accept only simple #RRGGBB colors before inserting into CSS."""
    s = str(value or "").strip()
    return s if _HEX_COLOR_RE.match(s) else fallback
