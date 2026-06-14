"""Password hashing using bcrypt.

Plaintext passwords are never stored, returned, or logged. bcrypt has a hard
72-byte input limit, so we pre-hash longer inputs with SHA-256 to avoid silent
truncation while keeping a fixed, safe input length.
"""
import base64
import hashlib

import bcrypt

_BCRYPT_MAX_BYTES = 72


def _normalize(password: str) -> bytes:
    raw = password.encode("utf-8")
    if len(raw) > _BCRYPT_MAX_BYTES:
        # Pre-hash to collapse to 44 base64 bytes, well under the 72-byte limit,
        # without losing entropy from long passphrases.
        raw = base64.b64encode(hashlib.sha256(raw).digest())
    return raw


def hash_password(password: str) -> str:
    return bcrypt.hashpw(_normalize(password), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    if not password_hash:
        return False
    try:
        return bcrypt.checkpw(_normalize(password), password_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False
