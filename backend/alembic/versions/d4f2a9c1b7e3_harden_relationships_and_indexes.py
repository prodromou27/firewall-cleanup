"""harden relationships and indexes

Revision ID: d4f2a9c1b7e3
Revises: b679ae30d172
Create Date: 2026-06-22 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "d4f2a9c1b7e3"
down_revision: Union[str, None] = "b679ae30d172"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _create_indexes(table: str, indexes: list[tuple[str, list[str]]]) -> None:
    with op.batch_alter_table(table, schema=None) as batch_op:
        for name, columns in indexes:
            batch_op.create_index(name, columns, unique=False)


def _drop_indexes(table: str, names: list[str]) -> None:
    with op.batch_alter_table(table, schema=None) as batch_op:
        for name in names:
            batch_op.drop_index(name)


def upgrade() -> None:
    bind = op.get_bind()

    # Backfill application defaults before tightening nullable workflow fields.
    bind.execute(sa.text("UPDATE customers SET status = 'active' WHERE status IS NULL"))
    for col in ("total_policies", "total_rules", "total_findings", "high_findings"):
        bind.execute(sa.text(f"UPDATE customers SET {col} = 0 WHERE {col} IS NULL"))

    bind.execute(sa.text("UPDATE firewall_devices SET use_ssl = 1 WHERE use_ssl IS NULL"))
    bind.execute(sa.text("UPDATE firewall_devices SET verify_ssl = 0 WHERE verify_ssl IS NULL"))
    bind.execute(sa.text("UPDATE firewall_devices SET environment_type = 'production' WHERE environment_type IS NULL"))
    bind.execute(sa.text("UPDATE firewall_devices SET fw_role = 'perimeter' WHERE fw_role IS NULL"))
    bind.execute(sa.text("UPDATE firewall_devices SET criticality = 'high' WHERE criticality IS NULL"))
    bind.execute(sa.text("UPDATE firewall_devices SET sync_status = 'never' WHERE sync_status IS NULL"))

    bind.execute(sa.text("UPDATE firewall_policies SET uploaded_by = 'engineer' WHERE uploaded_by IS NULL"))
    bind.execute(sa.text("UPDATE firewall_policies SET analysis_status = 'pending' WHERE analysis_status IS NULL"))
    for col in ("rule_count", "object_count", "finding_count", "high_finding_count"):
        bind.execute(sa.text(f"UPDATE firewall_policies SET {col} = 0 WHERE {col} IS NULL"))

    bind.execute(sa.text("UPDATE firewall_rules SET enabled = 1 WHERE enabled IS NULL"))
    bind.execute(sa.text("UPDATE firewall_rules SET logging_enabled = 1 WHERE logging_enabled IS NULL"))
    bind.execute(sa.text("UPDATE firewall_rules SET nat_enabled = 0 WHERE nat_enabled IS NULL"))
    bind.execute(sa.text("UPDATE firewall_rules SET risk_score = 0 WHERE risk_score IS NULL"))

    bind.execute(sa.text("UPDATE analysis_runs SET status = 'running' WHERE status IS NULL"))
    bind.execute(sa.text("UPDATE analysis_runs SET findings_created = 0 WHERE findings_created IS NULL"))
    bind.execute(sa.text("UPDATE analysis_runs SET run_by = 'engineer' WHERE run_by IS NULL"))

    bind.execute(sa.text("UPDATE findings SET priority = 'Standard' WHERE priority IS NULL"))
    bind.execute(sa.text("UPDATE findings SET status = 'Review Required' WHERE status IS NULL"))
    bind.execute(sa.text("UPDATE findings SET risk_score = 0 WHERE risk_score IS NULL"))
    bind.execute(sa.text("UPDATE finding_comments SET author = 'engineer' WHERE author IS NULL"))

    bind.execute(sa.text("UPDATE policy_revisions SET sync_source = 'upload' WHERE sync_source IS NULL"))
    for col in (
        "rule_count",
        "object_count",
        "finding_count",
        "high_finding_count",
        "rules_added",
        "rules_removed",
        "rules_modified",
    ):
        bind.execute(sa.text(f"UPDATE policy_revisions SET {col} = 0 WHERE {col} IS NULL"))

    # Avoid FK failures on legacy orphan references before adding constraints.
    bind.execute(sa.text(
        "UPDATE findings SET analysis_run_id = NULL "
        "WHERE analysis_run_id IS NOT NULL "
        "AND analysis_run_id NOT IN (SELECT id FROM analysis_runs)"
    ))
    bind.execute(sa.text(
        "UPDATE policy_revisions SET device_id = NULL "
        "WHERE device_id IS NOT NULL "
        "AND device_id NOT IN (SELECT id FROM firewall_devices)"
    ))
    bind.execute(sa.text(
        "UPDATE generated_reports SET template_id = NULL "
        "WHERE template_id IS NOT NULL "
        "AND template_id NOT IN (SELECT id FROM report_templates)"
    ))
    bind.execute(sa.text(
        "UPDATE generated_reports SET customer_id = NULL "
        "WHERE customer_id IS NOT NULL "
        "AND customer_id NOT IN (SELECT id FROM customers)"
    ))
    bind.execute(sa.text(
        "UPDATE generated_reports SET policy_id = NULL "
        "WHERE policy_id IS NOT NULL "
        "AND policy_id NOT IN (SELECT id FROM firewall_policies)"
    ))
    bind.execute(sa.text(
        "UPDATE generated_reports SET analysis_run_id = NULL "
        "WHERE analysis_run_id IS NOT NULL "
        "AND analysis_run_id NOT IN (SELECT id FROM analysis_runs)"
    ))

    with op.batch_alter_table("customers", schema=None) as batch_op:
        batch_op.alter_column("status", existing_type=sa.String(), nullable=False)
        for col in ("total_policies", "total_rules", "total_findings", "high_findings"):
            batch_op.alter_column(col, existing_type=sa.Integer(), nullable=False)

    with op.batch_alter_table("firewall_devices", schema=None) as batch_op:
        batch_op.alter_column("use_ssl", existing_type=sa.Boolean(), nullable=False)
        batch_op.alter_column("verify_ssl", existing_type=sa.Boolean(), nullable=False)
        batch_op.alter_column("environment_type", existing_type=sa.String(), nullable=False)
        batch_op.alter_column("fw_role", existing_type=sa.String(), nullable=False)
        batch_op.alter_column("criticality", existing_type=sa.String(), nullable=False)
        batch_op.alter_column("sync_status", existing_type=sa.String(), nullable=False)

    with op.batch_alter_table("firewall_policies", schema=None) as batch_op:
        batch_op.alter_column("uploaded_by", existing_type=sa.String(), nullable=False)
        batch_op.alter_column("analysis_status", existing_type=sa.String(), nullable=False)
        for col in ("rule_count", "object_count", "finding_count", "high_finding_count"):
            batch_op.alter_column(col, existing_type=sa.Integer(), nullable=False)

    with op.batch_alter_table("firewall_rules", schema=None) as batch_op:
        batch_op.alter_column("enabled", existing_type=sa.Boolean(), nullable=False)
        batch_op.alter_column("logging_enabled", existing_type=sa.Boolean(), nullable=False)
        batch_op.alter_column("nat_enabled", existing_type=sa.Boolean(), nullable=False)
        batch_op.alter_column("risk_score", existing_type=sa.Float(), nullable=False)

    with op.batch_alter_table("analysis_runs", schema=None) as batch_op:
        batch_op.alter_column("status", existing_type=sa.String(), nullable=False)
        batch_op.alter_column("findings_created", existing_type=sa.Integer(), nullable=False)
        batch_op.alter_column("run_by", existing_type=sa.String(), nullable=False)

    with op.batch_alter_table("findings", schema=None) as batch_op:
        batch_op.alter_column("priority", existing_type=sa.String(), nullable=False)
        batch_op.alter_column("status", existing_type=sa.String(), nullable=False)
        batch_op.alter_column("risk_score", existing_type=sa.Integer(), nullable=False)
        batch_op.create_foreign_key(
            "fk_findings_analysis_run_id_analysis_runs",
            "analysis_runs",
            ["analysis_run_id"],
            ["id"],
            ondelete="SET NULL",
        )

    with op.batch_alter_table("finding_comments", schema=None) as batch_op:
        batch_op.alter_column("author", existing_type=sa.String(), nullable=False)

    with op.batch_alter_table("policy_revisions", schema=None) as batch_op:
        batch_op.alter_column("sync_source", existing_type=sa.String(), nullable=False)
        for col in (
            "rule_count",
            "object_count",
            "finding_count",
            "high_finding_count",
            "rules_added",
            "rules_removed",
            "rules_modified",
        ):
            batch_op.alter_column(col, existing_type=sa.Integer(), nullable=False)
        batch_op.create_foreign_key(
            "fk_policy_revisions_device_id_firewall_devices",
            "firewall_devices",
            ["device_id"],
            ["id"],
            ondelete="SET NULL",
        )

    with op.batch_alter_table("generated_reports", schema=None) as batch_op:
        batch_op.create_foreign_key(
            "fk_generated_reports_template_id_report_templates",
            "report_templates",
            ["template_id"],
            ["id"],
            ondelete="SET NULL",
        )
        batch_op.create_foreign_key(
            "fk_generated_reports_customer_id_customers",
            "customers",
            ["customer_id"],
            ["id"],
            ondelete="CASCADE",
        )
        batch_op.create_foreign_key(
            "fk_generated_reports_policy_id_firewall_policies",
            "firewall_policies",
            ["policy_id"],
            ["id"],
            ondelete="SET NULL",
        )
        batch_op.create_foreign_key(
            "fk_generated_reports_analysis_run_id_analysis_runs",
            "analysis_runs",
            ["analysis_run_id"],
            ["id"],
            ondelete="SET NULL",
        )

    _create_indexes("customers", [
        ("ix_customers_status_name", ["status", "name"]),
    ])
    _create_indexes("firewall_devices", [
        ("ix_firewall_devices_customer_vendor", ["customer_id", "vendor"]),
        ("ix_firewall_devices_customer_sync_status", ["customer_id", "sync_status"]),
        ("ix_firewall_devices_host", ["host"]),
        ("ix_firewall_devices_last_policy_id", ["last_policy_id"]),
    ])
    _create_indexes("firewall_policies", [
        ("ix_firewall_policies_customer_upload_date", ["customer_id", "upload_date"]),
        ("ix_firewall_policies_customer_status", ["customer_id", "analysis_status"]),
        ("ix_firewall_policies_customer_vendor", ["customer_id", "vendor"]),
        ("ix_firewall_policies_device_upload_date", ["device_id", "upload_date"]),
    ])
    _create_indexes("firewall_rules", [
        ("ix_firewall_rules_policy_rule_number", ["policy_id", "rule_number"]),
        ("ix_firewall_rules_policy_enabled", ["policy_id", "enabled"]),
        ("ix_firewall_rules_policy_action", ["policy_id", "action"]),
        ("ix_firewall_rules_policy_hit_count", ["policy_id", "hit_count"]),
        ("ix_firewall_rules_policy_risk_score", ["policy_id", "risk_score"]),
        ("ix_firewall_rules_policy_rule_uid", ["policy_id", "rule_uid"]),
    ])
    _create_indexes("firewall_objects", [
        ("ix_firewall_objects_policy_type", ["policy_id", "object_type"]),
        ("ix_firewall_objects_policy_name", ["policy_id", "object_name"]),
        ("ix_firewall_objects_policy_uid", ["policy_id", "object_uid"]),
    ])
    _create_indexes("object_members", [
        ("ix_object_members_parent_name", ["parent_id", "member_name"]),
        ("ix_object_members_member_id", ["member_id"]),
    ])
    _create_indexes("analysis_runs", [
        ("ix_analysis_runs_policy_status_completed", ["policy_id", "status", "completed_at"]),
        ("ix_analysis_runs_policy_started", ["policy_id", "started_at"]),
    ])
    _create_indexes("findings", [
        ("ix_findings_policy_type", ["policy_id", "finding_type"]),
        ("ix_findings_policy_severity", ["policy_id", "severity"]),
        ("ix_findings_policy_status", ["policy_id", "status"]),
        ("ix_findings_policy_priority", ["policy_id", "priority"]),
        ("ix_findings_policy_created", ["policy_id", "created_at"]),
        ("ix_findings_policy_assigned", ["policy_id", "assigned_to"]),
        ("ix_findings_analysis_run", ["analysis_run_id"]),
        ("ix_findings_vendor", ["vendor"]),
    ])
    _create_indexes("finding_comments", [
        ("ix_finding_comments_finding_created", ["finding_id", "created_at"]),
    ])
    _create_indexes("policy_revisions", [
        ("ix_policy_revisions_policy_revision", ["policy_id", "revision_number"]),
        ("ix_policy_revisions_policy_synced", ["policy_id", "synced_at"]),
        ("ix_policy_revisions_device_synced", ["device_id", "synced_at"]),
    ])
    _create_indexes("report_templates", [
        ("ix_report_templates_customer_audience", ["customer_id", "audience"]),
        ("ix_report_templates_default", ["is_default"]),
    ])
    _create_indexes("report_template_sections", [
        ("ix_report_template_sections_template_order", ["template_id", "display_order"]),
        ("ix_report_template_sections_template_key", ["template_id", "section_key"]),
    ])
    _create_indexes("generated_reports", [
        ("ix_generated_reports_customer_generated", ["customer_id", "generated_at"]),
        ("ix_generated_reports_customer_format", ["customer_id", "export_format"]),
        ("ix_generated_reports_template_id", ["template_id"]),
        ("ix_generated_reports_analysis_run_id", ["analysis_run_id"]),
    ])


def downgrade() -> None:
    _drop_indexes("generated_reports", [
        "ix_generated_reports_analysis_run_id",
        "ix_generated_reports_template_id",
        "ix_generated_reports_customer_format",
        "ix_generated_reports_customer_generated",
    ])
    _drop_indexes("report_template_sections", [
        "ix_report_template_sections_template_key",
        "ix_report_template_sections_template_order",
    ])
    _drop_indexes("report_templates", [
        "ix_report_templates_default",
        "ix_report_templates_customer_audience",
    ])
    _drop_indexes("policy_revisions", [
        "ix_policy_revisions_device_synced",
        "ix_policy_revisions_policy_synced",
        "ix_policy_revisions_policy_revision",
    ])
    _drop_indexes("finding_comments", ["ix_finding_comments_finding_created"])
    _drop_indexes("findings", [
        "ix_findings_vendor",
        "ix_findings_analysis_run",
        "ix_findings_policy_assigned",
        "ix_findings_policy_created",
        "ix_findings_policy_priority",
        "ix_findings_policy_status",
        "ix_findings_policy_severity",
        "ix_findings_policy_type",
    ])
    _drop_indexes("analysis_runs", [
        "ix_analysis_runs_policy_started",
        "ix_analysis_runs_policy_status_completed",
    ])
    _drop_indexes("object_members", [
        "ix_object_members_member_id",
        "ix_object_members_parent_name",
    ])
    _drop_indexes("firewall_objects", [
        "ix_firewall_objects_policy_uid",
        "ix_firewall_objects_policy_name",
        "ix_firewall_objects_policy_type",
    ])
    _drop_indexes("firewall_rules", [
        "ix_firewall_rules_policy_rule_uid",
        "ix_firewall_rules_policy_risk_score",
        "ix_firewall_rules_policy_hit_count",
        "ix_firewall_rules_policy_action",
        "ix_firewall_rules_policy_enabled",
        "ix_firewall_rules_policy_rule_number",
    ])
    _drop_indexes("firewall_policies", [
        "ix_firewall_policies_device_upload_date",
        "ix_firewall_policies_customer_vendor",
        "ix_firewall_policies_customer_status",
        "ix_firewall_policies_customer_upload_date",
    ])
    _drop_indexes("firewall_devices", [
        "ix_firewall_devices_last_policy_id",
        "ix_firewall_devices_host",
        "ix_firewall_devices_customer_sync_status",
        "ix_firewall_devices_customer_vendor",
    ])
    _drop_indexes("customers", ["ix_customers_status_name"])

    with op.batch_alter_table("generated_reports", schema=None) as batch_op:
        batch_op.drop_constraint("fk_generated_reports_analysis_run_id_analysis_runs", type_="foreignkey")
        batch_op.drop_constraint("fk_generated_reports_policy_id_firewall_policies", type_="foreignkey")
        batch_op.drop_constraint("fk_generated_reports_customer_id_customers", type_="foreignkey")
        batch_op.drop_constraint("fk_generated_reports_template_id_report_templates", type_="foreignkey")

    with op.batch_alter_table("policy_revisions", schema=None) as batch_op:
        batch_op.drop_constraint("fk_policy_revisions_device_id_firewall_devices", type_="foreignkey")
        for col in (
            "rules_modified",
            "rules_removed",
            "rules_added",
            "high_finding_count",
            "finding_count",
            "object_count",
            "rule_count",
        ):
            batch_op.alter_column(col, existing_type=sa.Integer(), nullable=True)
        batch_op.alter_column("sync_source", existing_type=sa.String(), nullable=True)

    with op.batch_alter_table("finding_comments", schema=None) as batch_op:
        batch_op.alter_column("author", existing_type=sa.String(), nullable=True)

    with op.batch_alter_table("findings", schema=None) as batch_op:
        batch_op.drop_constraint("fk_findings_analysis_run_id_analysis_runs", type_="foreignkey")
        batch_op.alter_column("risk_score", existing_type=sa.Integer(), nullable=True)
        batch_op.alter_column("status", existing_type=sa.String(), nullable=True)
        batch_op.alter_column("priority", existing_type=sa.String(), nullable=True)

    with op.batch_alter_table("analysis_runs", schema=None) as batch_op:
        batch_op.alter_column("run_by", existing_type=sa.String(), nullable=True)
        batch_op.alter_column("findings_created", existing_type=sa.Integer(), nullable=True)
        batch_op.alter_column("status", existing_type=sa.String(), nullable=True)

    with op.batch_alter_table("firewall_rules", schema=None) as batch_op:
        batch_op.alter_column("risk_score", existing_type=sa.Float(), nullable=True)
        batch_op.alter_column("nat_enabled", existing_type=sa.Boolean(), nullable=True)
        batch_op.alter_column("logging_enabled", existing_type=sa.Boolean(), nullable=True)
        batch_op.alter_column("enabled", existing_type=sa.Boolean(), nullable=True)

    with op.batch_alter_table("firewall_policies", schema=None) as batch_op:
        for col in ("high_finding_count", "finding_count", "object_count", "rule_count"):
            batch_op.alter_column(col, existing_type=sa.Integer(), nullable=True)
        batch_op.alter_column("analysis_status", existing_type=sa.String(), nullable=True)
        batch_op.alter_column("uploaded_by", existing_type=sa.String(), nullable=True)

    with op.batch_alter_table("firewall_devices", schema=None) as batch_op:
        batch_op.alter_column("sync_status", existing_type=sa.String(), nullable=True)
        batch_op.alter_column("criticality", existing_type=sa.String(), nullable=True)
        batch_op.alter_column("fw_role", existing_type=sa.String(), nullable=True)
        batch_op.alter_column("environment_type", existing_type=sa.String(), nullable=True)
        batch_op.alter_column("verify_ssl", existing_type=sa.Boolean(), nullable=True)
        batch_op.alter_column("use_ssl", existing_type=sa.Boolean(), nullable=True)

    with op.batch_alter_table("customers", schema=None) as batch_op:
        for col in ("high_findings", "total_findings", "total_rules", "total_policies"):
            batch_op.alter_column(col, existing_type=sa.Integer(), nullable=True)
        batch_op.alter_column("status", existing_type=sa.String(), nullable=True)
