"""Helpers for keeping credentials out of diagnostics and API responses."""
from __future__ import annotations

import re

_MAX_DIAGNOSTIC_LEN = 500

_KEY_VALUE_RE = re.compile(
    r"(?i)\b("
    r"password|passwd|pass|secret|secret_key|secretkey|api[_-]?key|api[_-]?token|"
    r"token|access[_-]?token|refresh[_-]?token|authorization|x-auth-token|sid|session"
    r")(\s*[=:]\s*)([^&\s,;}\]\)]+)"
)
_QUERY_RE = re.compile(
    r"(?i)([?&]("
    r"password|passwd|pass|secret|secret_key|secretkey|api[_-]?key|api[_-]?token|"
    r"token|access[_-]?token|refresh[_-]?token|authorization|x-auth-token|sid|session"
    r")=)([^&#\s]+)"
)
_BEARER_RE = re.compile(r"(?i)\b(Bearer\s+)[A-Za-z0-9._~+/=-]+")
_BASIC_RE = re.compile(r"(?i)\b(Basic\s+)[A-Za-z0-9+/=-]+")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def redact_secrets(value: object, max_len: int = _MAX_DIAGNOSTIC_LEN) -> str:
    """Return a short diagnostic string with common secret patterns redacted."""
    text = "" if value is None else str(value)
    text = _CONTROL_RE.sub(" ", text)
    text = _QUERY_RE.sub(r"\1[REDACTED]", text)
    text = _BEARER_RE.sub(r"\1[REDACTED]", text)
    text = _BASIC_RE.sub(r"\1[REDACTED]", text)
    text = _KEY_VALUE_RE.sub(r"\1\2[REDACTED]", text)
    if max_len and len(text) > max_len:
        return text[: max_len - 3].rstrip() + "..."
    return text
