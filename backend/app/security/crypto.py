"""
Credential encryption at rest.

Uses Fernet symmetric encryption (AES-128-CBC + HMAC-SHA256).
The key is derived from SECRET_KEY in config.  If SECRET_KEY is not set
(dev mode) we use a stable machine-scoped fallback key stored in the DB
directory — this ensures credentials survive restarts even without .env.

Usage:
    from app.security.crypto import encrypt_credential, decrypt_credential

    stored   = encrypt_credential("plain-text-secret")
    original = decrypt_credential(stored)   # → "plain-text-secret"

    # Already-plaintext values (from pre-encryption installs) are returned as-is
    # once they fail to base64-decode as a Fernet token — migration is automatic
    # on next save.
"""
import base64
import hashlib
import logging
import os

from cryptography.fernet import Fernet, InvalidToken

from app.config import settings

logger = logging.getLogger(__name__)

_fernet: Fernet | None = None

# Marker prefix so we can tell encrypted values from legacy plain values
_PREFIX = "enc:"


def _get_fernet() -> Fernet:
    global _fernet
    if _fernet is not None:
        return _fernet

    raw_key = settings.secret_key.strip()

    if raw_key:
        # Derive a 32-byte Fernet key from the configured secret
        digest = hashlib.sha256(raw_key.encode()).digest()
        key = base64.urlsafe_b64encode(digest)
    else:
        if settings.is_production:
            raise RuntimeError("SECRET_KEY must be set in production to encrypt/decrypt device credentials.")
        # Dev fallback: persist a stable key on disk so credentials survive
        # restarts even without SECRET_KEY. Use the uploads directory — it is a
        # mounted/persistent volume in the Docker stack — rather than deriving a
        # path from DATABASE_URL (which is wrong for non-SQLite URLs like
        # postgresql://… and left the key non-persistent, regenerating it every
        # restart and losing stored device passwords).
        key_dir = (getattr(settings, "upload_dir", "") or "").strip() or os.getcwd()
        try:
            os.makedirs(key_dir, exist_ok=True)
        except Exception:
            key_dir = os.getcwd()
        key_file = os.path.join(key_dir, ".dev_key")
        if os.path.exists(key_file):
            with open(key_file, "rb") as f:
                key = f.read().strip()
        else:
            key = Fernet.generate_key()
            try:
                os.makedirs(os.path.dirname(key_file), exist_ok=True)
                with open(key_file, "wb") as f:
                    f.write(key)
                # Restrict permissions on Unix
                try:
                    os.chmod(key_file, 0o600)
                except Exception:
                    pass
            except Exception:
                pass
            logger.warning(
                "SECRET_KEY not set — using ephemeral dev key. "
                "Set SECRET_KEY in .env for production deployments."
            )

    _fernet = Fernet(key)
    return _fernet


def encrypt_credential(plain: str | None) -> str | None:
    """Encrypt a credential string. Returns None if input is None/empty."""
    if not plain:
        return plain
    # Already encrypted (idempotent)
    if plain.startswith(_PREFIX):
        return plain
    token = _get_fernet().encrypt(plain.encode()).decode()
    return f"{_PREFIX}{token}"


def decrypt_credential(stored: str | None) -> str | None:
    """
    Decrypt a credential.  Handles:
      - None / empty → None
      - Fernet-encrypted (enc: prefix) → decrypted string
      - Legacy plaintext (no prefix, pre-encryption install) → returned as-is
        with a warning so it gets re-encrypted on next save
    """
    if not stored:
        return stored
    if not stored.startswith(_PREFIX):
        # Legacy plaintext — return as-is (will be re-encrypted on next update)
        logger.debug("Credential appears to be legacy plaintext — will be re-encrypted on next save")
        return stored
    token = stored[len(_PREFIX):]
    try:
        return _get_fernet().decrypt(token.encode()).decode()
    except InvalidToken:
        logger.error("Failed to decrypt credential — key may have changed")
        return None
