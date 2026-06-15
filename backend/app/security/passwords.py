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


MIN_PASSWORD_LEN = 12

# Weak base words: a password is rejected if it contains any of these as a
# substring (so "Password123!", "welcome2024", etc. are all caught).
_WEAK_BASE_WORDS = (
    "password", "passw0rd", "qwerty", "letmein", "welcome", "changeme",
    "iloveyou", "monkey", "admin", "12345678",
)


def validate_password_policy(password: str) -> None:
    """Enforce the password policy. Raises ValueError with a user-facing message
    if the password is unacceptable. Framework-agnostic — callers translate the
    ValueError into an HTTP 400 (or other) response.
    """
    pw = password or ""
    if len(pw) < MIN_PASSWORD_LEN:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LEN} characters.")
    classes = sum([
        any(c.islower() for c in pw),
        any(c.isupper() for c in pw),
        any(c.isdigit() for c in pw),
        any(not c.isalnum() for c in pw),
    ])
    if classes < 3:
        raise ValueError(
            "Password must include at least three of: lowercase, uppercase, "
            "digit, and symbol."
        )
    lowered = pw.lower()
    if any(word in lowered for word in _WEAK_BASE_WORDS):
        raise ValueError(
            "Password contains a common, easily-guessed word; choose something "
            "less predictable."
        )


def hash_password(password: str) -> str:
    return bcrypt.hashpw(_normalize(password), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    if not password_hash:
        return False
    try:
        return bcrypt.checkpw(_normalize(password), password_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False
