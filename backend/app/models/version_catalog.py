"""Manually-managed firewall version catalog.

Reference data for version intelligence: which OS versions are recommended,
end-of-support, etc. Populated by manual import/edit (no live internet for MVP).
PolicyInsight only reads device versions; it never changes device firmware.
"""
from sqlalchemy import Column, String, Text, DateTime, JSON
from sqlalchemy.sql import func
from app.database import Base
import uuid


def _uuid():
    return str(uuid.uuid4())


class VersionCatalogEntry(Base):
    __tablename__ = "version_catalog"

    id = Column(String, primary_key=True, default=_uuid)
    vendor = Column(String, nullable=False)            # FortiGate | CheckPoint | PaloAlto | CiscoASA | HuaweiUSG
    product = Column(String, nullable=True)            # e.g. FortiOS, PAN-OS, Gaia
    model_family = Column(String, nullable=True)       # optional
    os_name = Column(String, nullable=True)
    release_train = Column(String, nullable=True)      # e.g. "7.2", "R81", "10.1"
    latest_known_version = Column(String, nullable=True)
    recommended_version = Column(String, nullable=True)
    minimum_supported_version = Column(String, nullable=True)
    eol_versions = Column(JSON, nullable=True)          # list of end-of-support version strings/prefixes
    release_date = Column(String, nullable=True)        # ISO date
    support_status = Column(String, nullable=True)      # supported | extended | end-of-support
    advisory_url = Column(String, nullable=True)
    notes = Column(Text, nullable=True)
    last_updated = Column(DateTime, server_default=func.now(), onupdate=func.now())
    created_at = Column(DateTime, server_default=func.now())
