"""
Credential Encryption Migration
================================
One-shot utility that scans every FirewallDevice row in the database and
re-encrypts any api_token or password that is still stored in plaintext
(i.e. lacks the "enc:" prefix added by encrypt_credential).

Safe to run multiple times — already-encrypted values are left untouched
(encrypt_credential is idempotent on enc:-prefixed values).

Run manually:
    python -m app.security.migrate_credentials

Or import and call:
    from app.security.migrate_credentials import migrate_device_credentials
    migrate_device_credentials(db)

This is called automatically on application startup via app/main.py.
"""
from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger(__name__)

_PREFIX = "enc:"


def _needs_encryption(value: Optional[str]) -> bool:
    """Return True if value is non-empty and not already encrypted."""
    return bool(value) and not value.startswith(_PREFIX)


def migrate_device_credentials(db) -> int:
    """
    Encrypt any plaintext api_token / password values for all FirewallDevice rows.
    Returns the number of rows updated.
    """
    from app.models.device import FirewallDevice
    from app.security.crypto import encrypt_credential

    devices = db.query(FirewallDevice).all()
    updated = 0

    for device in devices:
        changed = False

        if _needs_encryption(device.api_token):
            logger.warning(
                "Encrypting plaintext api_token for device %s (%s)",
                device.id, device.name,
            )
            device.api_token = encrypt_credential(device.api_token)
            changed = True

        if _needs_encryption(device.password):
            logger.warning(
                "Encrypting plaintext password for device %s (%s)",
                device.id, device.name,
            )
            device.password = encrypt_credential(device.password)
            changed = True

        if changed:
            updated += 1

    if updated:
        db.commit()
        logger.info("Credential migration: encrypted %d device record(s)", updated)
    else:
        logger.debug("Credential migration: all device credentials already encrypted")

    return updated


def run_migration():
    """Entry point for standalone execution."""
    from app.database import SessionLocal
    db = SessionLocal()
    try:
        count = migrate_device_credentials(db)
        print(f"Migration complete — {count} record(s) updated")
    finally:
        db.close()


if __name__ == "__main__":
    import os, sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
    logging.basicConfig(level=logging.INFO)
    run_migration()
