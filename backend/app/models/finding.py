from sqlalchemy import Column, String, Integer, DateTime, Text, JSON, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.database import Base
import uuid


def gen_uuid():
    return str(uuid.uuid4())


class Finding(Base):
    __tablename__ = "findings"

    id = Column(String, primary_key=True, default=gen_uuid)
    policy_id = Column(String, ForeignKey("firewall_policies.id"), nullable=False)
    vendor = Column(String, nullable=True)
    finding_type = Column(String, nullable=False)
    severity = Column(String, nullable=False)       # High/Medium/Low/Informational
    confidence = Column(String, nullable=False)     # High/Medium/Low
    priority = Column(String, default="Standard")   # Immediate/High/Standard/Low/Monitor
    title = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    affected_rules = Column(JSON, default=list)
    affected_objects = Column(JSON, default=list)
    evidence = Column(JSON, default=dict)
    recommendation = Column(Text, nullable=True)
    status = Column(String, default="Review Required")
    engineer_comment = Column(Text, nullable=True)
    risk_score = Column(Integer, default=0)

    # Workflow fields
    assigned_to = Column(String, nullable=True)     # assigned engineer name/email
    due_date = Column(String, nullable=True)        # ISO date string YYYY-MM-DD

    # Risk acceptance
    risk_acceptance_reason = Column(Text, nullable=True)
    risk_acceptance_expiry = Column(String, nullable=True)  # ISO date YYYY-MM-DD
    risk_acceptance_ref = Column(String, nullable=True)     # ticket / approval ref
    risk_accepted_by = Column(String, nullable=True)

    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    policy = relationship("FirewallPolicy", back_populates="findings")
    comments = relationship("FindingComment", back_populates="finding", cascade="all, delete-orphan")


class FindingComment(Base):
    __tablename__ = "finding_comments"

    id = Column(String, primary_key=True, default=gen_uuid)
    finding_id = Column(String, ForeignKey("findings.id"), nullable=False)
    author = Column(String, default="engineer")
    comment = Column(Text, nullable=False)
    old_status = Column(String, nullable=True)
    new_status = Column(String, nullable=True)
    created_at = Column(DateTime, server_default=func.now())

    finding = relationship("Finding", back_populates="comments")
