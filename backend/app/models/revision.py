"""
PolicyRevision — stores a snapshot hash of each policy sync so we can
detect changes between syncs (Tufin-style change tracking).
"""
from sqlalchemy import Column, String, Integer, DateTime, Text, JSON, ForeignKey
from sqlalchemy.sql import func
import uuid

from app.database import Base


def _uuid():
    return str(uuid.uuid4())


class PolicyRevision(Base):
    __tablename__ = "policy_revisions"

    id = Column(String, primary_key=True, default=_uuid)
    policy_id = Column(String, ForeignKey("firewall_policies.id", ondelete="CASCADE"), nullable=False)
    device_id = Column(String, nullable=True)        # FirewallDevice.id if from live sync

    revision_number = Column(Integer, nullable=False)    # 1, 2, 3 …
    synced_at = Column(DateTime, server_default=func.now())
    sync_source = Column(String, default="upload")   # "upload" | "live_sync"

    rule_count = Column(Integer, default=0)
    object_count = Column(Integer, default=0)
    finding_count = Column(Integer, default=0)
    high_finding_count = Column(Integer, default=0)

    # Diff vs previous revision
    rules_added = Column(Integer, default=0)
    rules_removed = Column(Integer, default=0)
    rules_modified = Column(Integer, default=0)

    # SHA-256 of sorted rule IDs + action + src/dst/svc — change detection
    policy_hash = Column(String, nullable=True)

    # Human-readable change summary
    change_summary = Column(Text, nullable=True)
    # Detailed diff (JSON list of {rule_id, change_type, before, after})
    change_detail = Column(JSON, nullable=True)

    notes = Column(Text, nullable=True)
