"""FirewallDevice model — stores live firewall connection credentials (encrypted at rest)."""
from sqlalchemy import Column, String, Integer, Boolean, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import uuid

from app.database import Base


def _uuid():
    return str(uuid.uuid4())


class FirewallDevice(Base):
    __tablename__ = "firewall_devices"

    id = Column(String, primary_key=True, default=_uuid)
    customer_id = Column(String, ForeignKey("customers.id", ondelete="CASCADE"), nullable=False)

    # Identity
    name = Column(String, nullable=False)           # friendly label, e.g. "HQ Firewall"
    vendor = Column(String, nullable=False)         # "FortiGate" | "CheckPoint"
    host = Column(String, nullable=False)           # IP or FQDN
    port = Column(Integer, nullable=True)           # API port (443 default)

    # Auth — stored encrypted at rest (see app.security.crypto).
    api_token = Column(String, nullable=True)       # FortiGate API token (encrypted)
    username = Column(String, nullable=True)        # username (NOT encrypted)
    password = Column(String, nullable=True)        # password (encrypted)

    # Connection options
    use_ssl = Column(Boolean, default=True)
    verify_ssl = Column(Boolean, default=False)     # False = accept self-signed certs
    vdom = Column(String, nullable=True)            # FortiGate VDOM ("root" default)

    # Check Point specific
    cp_domain = Column(String, nullable=True)
    cp_policy_package = Column(String, nullable=True)
    cp_management_type = Column(String, nullable=True)  # "SmartCenter"|"MDS"|"Smart-1Cloud"

    # ── Firewall Inventory Fields ─────────────────────────────────────────────
    fw_model = Column(String, nullable=True)        # e.g. "FortiGate-600F"
    os_version = Column(String, nullable=True)      # e.g. "7.2.5", "R81.20"
    management_platform = Column(String, nullable=True)  # e.g. "FortiManager", "SmartCenter"
    environment_type = Column(String, default="production")  # production/staging/development/dr
    location = Column(String, nullable=True)        # e.g. "HQ DataCenter", "London DC"
    fw_role = Column(String, default="perimeter")   # perimeter/datacenter/internal/branch/dr/vpn/cloud
    criticality = Column(String, default="high")    # critical/high/medium/low

    # Network interfaces discovered during last sync (JSON list of {name, ip, mask, type, status})
    device_interfaces = Column(Text, nullable=True)    # JSON-encoded list
    # Serial / HA info
    serial_number = Column(String, nullable=True)
    ha_mode = Column(String, nullable=True)            # standalone|active-passive|active-active|cluster
    ha_peer = Column(String, nullable=True)            # peer hostname / IP if in HA

    # Auto-sync schedule (None = disabled, >0 = interval in hours)
    sync_interval_hours = Column(Integer, nullable=True)

    # Status tracking
    last_sync_at = Column(DateTime, nullable=True)
    sync_status = Column(String, default="never")   # "never"|"running"|"ok"|"error"
    last_error = Column(Text, nullable=True)
    last_policy_id = Column(String, nullable=True)

    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    # Relationship
    customer = relationship("Customer", back_populates="devices")
