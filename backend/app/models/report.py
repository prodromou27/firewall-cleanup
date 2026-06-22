"""Reporting models — reusable report templates and a record of generated reports.

Read-only product: these store report *configuration* and generation metadata
only. Nothing here pushes, approves, or executes firewall changes.
"""
from sqlalchemy import Column, String, Integer, Boolean, DateTime, Text, JSON, ForeignKey, Index
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import uuid

from app.database import Base


def _uuid():
    return str(uuid.uuid4())


class ReportTemplate(Base):
    __tablename__ = "report_templates"
    __table_args__ = (
        Index("ix_report_templates_customer_audience", "customer_id", "audience"),
        Index("ix_report_templates_default", "is_default"),
    )

    id = Column(String, primary_key=True, default=_uuid)
    name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    template_type = Column(String, default="technical")     # technical|executive|cleanup|exposure|custom
    audience = Column(String, default="internal")           # customer|internal
    is_customer_facing = Column(Boolean, default=False)
    default_export_format = Column(String, default="pdf")   # html|pdf|docx|xlsx|csv|json
    default_detail_level = Column(String, default="standard")  # summary|standard|detailed

    branding_config = Column(JSON, default=dict)            # logos, colors, header/footer text, confidentiality
    cover_page_config = Column(JSON, default=dict)          # title, subtitle, prepared_by, custom text
    introduction_text = Column(Text, nullable=True)
    methodology_text = Column(Text, nullable=True)
    disclaimer_text = Column(Text, nullable=True)
    footer_text = Column(Text, nullable=True)
    default_finding_categories = Column(JSON, default=list)

    # NULL customer_id => global template available to all tenants.
    customer_id = Column(String, ForeignKey("customers.id", ondelete="CASCADE"), nullable=True)
    is_default = Column(Boolean, default=False)
    created_by = Column(String, nullable=True)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    sections = relationship(
        "ReportTemplateSection",
        back_populates="template",
        cascade="all, delete-orphan",
        order_by="ReportTemplateSection.display_order",
    )
    customer = relationship("Customer")
    generated_reports = relationship("GeneratedReport", back_populates="template", passive_deletes=True)


class ReportTemplateSection(Base):
    __tablename__ = "report_template_sections"
    __table_args__ = (
        Index("ix_report_template_sections_template_order", "template_id", "display_order"),
        Index("ix_report_template_sections_template_key", "template_id", "section_key"),
    )

    id = Column(String, primary_key=True, default=_uuid)
    template_id = Column(String, ForeignKey("report_templates.id", ondelete="CASCADE"), nullable=False)
    section_key = Column(String, nullable=False)        # matches the section catalog
    section_name = Column(String, nullable=True)        # display override
    section_type = Column(String, default="builtin")    # builtin|custom_text|appendix
    enabled = Column(Boolean, default=True)
    display_order = Column(Integer, default=0)
    custom_text = Column(Text, nullable=True)           # for custom_text sections / overrides
    config = Column(JSON, default=dict)                 # per-section options (finding filter, chart, etc.)

    template = relationship("ReportTemplate", back_populates="sections")


class GeneratedReport(Base):
    __tablename__ = "generated_reports"
    __table_args__ = (
        Index("ix_generated_reports_customer_generated", "customer_id", "generated_at"),
        Index("ix_generated_reports_customer_format", "customer_id", "export_format"),
        Index("ix_generated_reports_template_id", "template_id"),
        Index("ix_generated_reports_analysis_run_id", "analysis_run_id"),
    )

    id = Column(String, primary_key=True, default=_uuid)
    template_id = Column(String, ForeignKey("report_templates.id", ondelete="SET NULL"), nullable=True)
    customer_id = Column(String, ForeignKey("customers.id", ondelete="CASCADE"), nullable=True, index=True)
    policy_id = Column(String, ForeignKey("firewall_policies.id", ondelete="SET NULL"), nullable=True, index=True)
    analysis_run_id = Column(String, ForeignKey("analysis_runs.id", ondelete="SET NULL"), nullable=True)
    firewall_name = Column(String, nullable=True)
    report_type = Column(String, nullable=True)
    export_format = Column(String, nullable=False)      # html|pdf|docx|xlsx|csv|json
    file_name = Column(String, nullable=False)
    file_path = Column(String, nullable=False)
    selected_sections = Column(JSON, default=list)
    selected_finding_categories = Column(JSON, default=list)
    filters = Column(JSON, default=dict)
    generated_by = Column(String, nullable=True)
    generated_at = Column(DateTime, server_default=func.now(), index=True)

    template = relationship("ReportTemplate", back_populates="generated_reports")
    customer = relationship("Customer")
    policy = relationship("FirewallPolicy")
    analysis_run = relationship("AnalysisRun")
