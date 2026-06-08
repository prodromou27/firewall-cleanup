from sqlalchemy import Column, String, Integer, Boolean, DateTime, Text, Float, ForeignKey, JSON
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.database import Base
import uuid


def gen_uuid():
    return str(uuid.uuid4())


class FirewallPolicy(Base):
    __tablename__ = "firewall_policies"

    id = Column(String, primary_key=True, default=gen_uuid)

    # Tenant link
    customer_id = Column(String, ForeignKey("customers.id"), nullable=False)

    firewall_name = Column(String, nullable=False)
    vendor = Column(String, nullable=False)          # FortiGate | CheckPoint
    policy_package = Column(String, nullable=True)
    uploaded_by = Column(String, default="engineer")
    upload_date = Column(DateTime, server_default=func.now())
    original_filename = Column(String, nullable=True)
    file_path = Column(String, nullable=True)
    analysis_status = Column(String, default="pending")  # pending|running|completed|failed
    analysis_error = Column(Text, nullable=True)
    rule_count = Column(Integer, default=0)
    object_count = Column(Integer, default=0)
    finding_count = Column(Integer, default=0)
    high_finding_count = Column(Integer, default=0)
    notes = Column(Text, nullable=True)
    complexity_score = Column(Float, nullable=True)
    cleanup_readiness_score = Column(Float, nullable=True)
    health_score = Column(Float, nullable=True)
    top_risk_drivers = Column(JSON, nullable=True)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    customer = relationship("Customer", back_populates="policies")
    rules = relationship("FirewallRule", back_populates="policy", cascade="all, delete-orphan")
    objects = relationship("FirewallObject", back_populates="policy", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="policy", cascade="all, delete-orphan")
    analysis_runs = relationship("AnalysisRun", back_populates="policy", cascade="all, delete-orphan")


class FirewallRule(Base):
    __tablename__ = "firewall_rules"

    id = Column(String, primary_key=True, default=gen_uuid)
    policy_id = Column(String, ForeignKey("firewall_policies.id"), nullable=False)
    vendor = Column(String, nullable=False)
    firewall_name = Column(String, nullable=True)
    policy_package = Column(String, nullable=True)
    rule_id = Column(String, nullable=True)
    rule_uid = Column(String, nullable=True)
    rule_number = Column(Integer, nullable=True)
    rule_name = Column(String, nullable=True)
    section = Column(String, nullable=True)
    source_interfaces = Column(JSON, default=list)
    destination_interfaces = Column(JSON, default=list)
    sources = Column(JSON, default=list)
    destinations = Column(JSON, default=list)
    services = Column(JSON, default=list)
    applications = Column(JSON, default=list)
    users = Column(JSON, default=list)
    vpn = Column(JSON, default=list)
    action = Column(String, nullable=True)
    schedule = Column(String, nullable=True)
    enabled = Column(Boolean, default=True)
    logging_enabled = Column(Boolean, default=True)
    nat_enabled = Column(Boolean, default=False)
    comments = Column(Text, nullable=True)
    hit_count = Column(Integer, nullable=True)
    last_hit = Column(String, nullable=True)
    first_hit = Column(String, nullable=True)
    install_on = Column(JSON, default=list)
    risk_score = Column(Float, default=0)
    risk_factors = Column(JSON, default=dict)
    raw_data = Column(JSON, default=dict)
    created_at = Column(DateTime, server_default=func.now())

    policy = relationship("FirewallPolicy", back_populates="rules")


class FirewallObject(Base):
    __tablename__ = "firewall_objects"

    id = Column(String, primary_key=True, default=gen_uuid)
    policy_id = Column(String, ForeignKey("firewall_policies.id"), nullable=False)
    vendor = Column(String, nullable=False)
    object_uid = Column(String, nullable=True)
    object_name = Column(String, nullable=False)
    object_type = Column(String, nullable=False)
    value = Column(String, nullable=True)
    protocol = Column(String, nullable=True)
    port_start = Column(Integer, nullable=True)
    port_end = Column(Integer, nullable=True)
    members = Column(JSON, default=list)
    used_by_rules = Column(JSON, default=list)
    comment = Column(Text, nullable=True)
    raw_data = Column(JSON, default=dict)
    created_at = Column(DateTime, server_default=func.now())

    policy = relationship("FirewallPolicy", back_populates="objects")
    member_entries = relationship(
        "ObjectMember", foreign_keys="ObjectMember.parent_id", cascade="all, delete-orphan"
    )


class ObjectMember(Base):
    __tablename__ = "object_members"

    id = Column(String, primary_key=True, default=gen_uuid)
    parent_id = Column(String, ForeignKey("firewall_objects.id"), nullable=False)
    member_name = Column(String, nullable=False)
    member_id = Column(String, ForeignKey("firewall_objects.id"), nullable=True)


class AnalysisRun(Base):
    __tablename__ = "analysis_runs"

    id = Column(String, primary_key=True, default=gen_uuid)
    policy_id = Column(String, ForeignKey("firewall_policies.id"), nullable=False)
    started_at = Column(DateTime, server_default=func.now())
    completed_at = Column(DateTime, nullable=True)
    status = Column(String, default="running")
    findings_created = Column(Integer, default=0)
    error = Column(Text, nullable=True)
    run_by = Column(String, default="engineer")

    policy = relationship("FirewallPolicy", back_populates="analysis_runs")
