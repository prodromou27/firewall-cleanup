"""
PolicyRevision — stores a snapshot hash of each policy sync so we can
detect changes between syncs (Tufin-style change tracking).
"""
from sqlalchemy import Column, String, Integer, DateTime, Text, JSON, ForeignKey, Index
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import uuid

from app.database import Base


def _uuid():
    return str(uuid.uuid4())


class PolicyRevision(Base):
    __tablename__ = "policy_revisions"
    __table_args__ = (
        Index("ix_policy_revisions_policy_revision", "policy_id", "revision_number"),
        Index("ix_policy_revisions_policy_synced", "policy_id", "synced_at"),
        Index("ix_policy_revisions_device_synced", "device_id", "synced_at"),
    )

    id = Column(String, primary_key=True, default=_uuid)
    policy_id = Column(String, ForeignKey("firewall_policies.id", ondelete="CASCADE"), nullable=False)
    device_id = Column(String, ForeignKey("firewall_devices.id", ondelete="SET NULL"), nullable=True)

    revision_number = Column(Integer, nullable=False)    # 1, 2, 3 …
    synced_at = Column(DateTime, server_default=func.now())
    sync_source = Column(String, nullable=False, default="upload")   # "upload" | "live_sync"

    rule_count = Column(Integer, nullable=False, default=0)
    object_count = Column(Integer, nullable=False, default=0)
    finding_count = Column(Integer, nullable=False, default=0)
    high_finding_count = Column(Integer, nullable=False, default=0)

    # Diff vs previous revision
    rules_added = Column(Integer, nullable=False, default=0)
    rules_removed = Column(Integer, nullable=False, default=0)
    rules_modified = Column(Integer, nullable=False, default=0)

    # SHA-256 of sorted rule IDs + action + src/dst/svc — change detection
    policy_hash = Column(String, nullable=True)

    # Human-readable change summary
    change_summary = Column(Text, nullable=True)
    # Detailed diff (JSON list of {rule_id, change_type, before, after})
    change_detail = Column(JSON, nullable=True)

    notes = Column(Text, nullable=True)

    policy = relationship("FirewallPolicy", back_populates="revisions")
    device = relationship("FirewallDevice", back_populates="revisions")
