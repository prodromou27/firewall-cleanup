from sqlalchemy import Column, String, DateTime, Text, Integer
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.database import Base
import uuid


def gen_uuid():
    return str(uuid.uuid4())


class Customer(Base):
    __tablename__ = "customers"

    id = Column(String, primary_key=True, default=gen_uuid)
    name = Column(String, nullable=False, unique=True)
    description = Column(Text, nullable=True)
    contact_name = Column(String, nullable=True)
    contact_email = Column(String, nullable=True)
    industry = Column(String, nullable=True)
    status = Column(String, default="active")   # active | archived
    tags = Column(String, nullable=True)         # comma-separated
    notes = Column(Text, nullable=True)

    # Denormalised counters updated after each analysis
    total_policies = Column(Integer, default=0)
    total_rules = Column(Integer, default=0)
    total_findings = Column(Integer, default=0)
    high_findings = Column(Integer, default=0)

    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    policies = relationship(
        "FirewallPolicy", back_populates="customer", cascade="all, delete-orphan"
    )
    devices = relationship(
        "FirewallDevice", back_populates="customer", cascade="all, delete-orphan"
    )
