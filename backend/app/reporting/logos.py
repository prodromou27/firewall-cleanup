"""Branding logo storage + embedding helpers.

Logos are stored under <upload_dir>/branding and referenced from a template's
branding_config as a relative ref ("branding/<uuid>.<ext>"). At render time they
are embedded as data URIs (HTML/PDF) or read from disk (DOCX), so output is
self-contained and works regardless of how the server is reached.
"""
import base64
import os
import uuid

from app.config import settings

_LOGO_SUBDIR = "branding"
_ALLOWED_EXT = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp"}
_MIME = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
         ".gif": "image/gif", ".svg": "image/svg+xml", ".webp": "image/webp"}


def _logo_dir() -> str:
    return os.path.join(settings.upload_dir, _LOGO_SUBDIR)


def save_logo(content: bytes, original_name: str) -> str:
    """Persist an uploaded logo; return its storage ref. Raises ValueError on bad type."""
    ext = os.path.splitext(original_name or "")[1].lower()
    if ext not in _ALLOWED_EXT:
        raise ValueError(f"Unsupported image type {ext or '(none)'}. Allowed: {', '.join(sorted(_ALLOWED_EXT))}")
    os.makedirs(_logo_dir(), exist_ok=True)
    name = f"{uuid.uuid4().hex}{ext}"
    with open(os.path.join(_logo_dir(), name), "wb") as f:
        f.write(content)
    return f"{_LOGO_SUBDIR}/{name}"


def abs_path(ref: str) -> str | None:
    """Resolve a stored ref to an absolute path inside the upload dir (path-traversal safe)."""
    if not ref:
        return None
    base = os.path.abspath(settings.upload_dir)
    p = os.path.abspath(os.path.join(base, ref))
    if not p.startswith(base + os.sep):
        return None
    return p if os.path.exists(p) else None


def data_uri(ref: str) -> str | None:
    """Return a data: URI for the stored logo, or None if missing/already a URI/URL."""
    if not ref:
        return None
    if ref.startswith(("data:", "http://", "https://")):
        return ref  # already embeddable
    p = abs_path(ref)
    if not p:
        return None
    ext = os.path.splitext(p)[1].lower()
    with open(p, "rb") as f:
        b64 = base64.b64encode(f.read()).decode("ascii")
    return f"data:{_MIME.get(ext, 'application/octet-stream')};base64,{b64}"
