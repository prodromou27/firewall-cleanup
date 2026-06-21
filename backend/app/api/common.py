"""Shared API validation helpers."""
from typing import Optional, Sequence

from fastapi import HTTPException


def validate_choice(value: Optional[str], allowed: Sequence[str], field: str) -> Optional[str]:
    if value is None:
        return value
    if value not in allowed:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid {field}: {value}. Allowed: {', '.join(allowed)}",
        )
    return value


def validate_csv_choices(value: Optional[str], allowed: Sequence[str], field: str) -> list[str]:
    if not value:
        return []
    values = [v.strip() for v in value.split(",") if v.strip()]
    invalid = [v for v in values if v not in allowed]
    if invalid:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid {field}: {', '.join(invalid)}. Allowed: {', '.join(allowed)}",
        )
    return values


def validate_sort(sort_by: Optional[str], sort_dir: Optional[str], allowed: Sequence[str], default: str) -> tuple[str, str]:
    field = sort_by or default
    if field not in allowed:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid sort_by: {field}. Allowed: {', '.join(allowed)}",
        )
    direction = (sort_dir or "asc").lower()
    if direction not in ("asc", "desc"):
        raise HTTPException(status_code=400, detail="Invalid sort_dir: must be 'asc' or 'desc'.")
    return field, direction
