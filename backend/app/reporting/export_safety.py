"""Small output-safety helpers shared by report exporters."""
from __future__ import annotations

import re
from typing import Any

_DANGEROUS_SPREADSHEET_PREFIXES = ("=", "+", "-", "@", "\t", "\r", "\n")
_HEX_COLOR_RE = re.compile(r"^#[0-9A-Fa-f]{6}$")


def spreadsheet_cell(value: Any) -> Any:
    """Return a value safe for CSV/XLSX cells.

    Spreadsheet apps can execute values beginning with =, +, -, @ and a few
    control characters as formulas. Prefix only strings that need protection.
    """
    if not isinstance(value, str):
        return value
    return "'" + value if value.startswith(_DANGEROUS_SPREADSHEET_PREFIXES) else value


def css_hex_color(value: Any, fallback: str = "#1e3a5f") -> str:
    """Accept only simple #RRGGBB colors before inserting into CSS."""
    s = str(value or "").strip()
    return s if _HEX_COLOR_RE.match(s) else fallback
