"""DeviceCVECache model — caches NVD CVE results per device to avoid rate limiting."""
from sqlalchemy import Column, String, Text, DateTime, ForeignKey
from sqlalchemy.sql import func
import uuid

from app.database import Base


def _uuid():
    return str(uuid.uuid4())


class DeviceCVECache(Base):
    __tablename__ = "device_cve_cache"

    id           = Column(String, primary_key=True, default=_uuid)
    device_id    = Column(String, ForeignKey("firewall_devices.id", ondelete="CASCADE"), nullable=False, unique=True)
    cpe_string   = Column(String, nullable=True)   # CPE used for the last query
    cve_data     = Column(Text, nullable=True)      # JSON array of CVE dicts
    last_checked = Column(DateTime, server_default=func.now())
    created_at   = Column(DateTime, server_default=func.now())
