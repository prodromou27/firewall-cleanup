"""add version_catalog table

Additive table for the manually-managed firewall version catalog. No FKs, no
backfill — safe on a populated database.

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-06-22
"""
from alembic import op
import sqlalchemy as sa


revision = "b2c3d4e5f6a7"
down_revision = "a1b2c3d4e5f6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "version_catalog",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("vendor", sa.String(), nullable=False),
        sa.Column("product", sa.String(), nullable=True),
        sa.Column("model_family", sa.String(), nullable=True),
        sa.Column("os_name", sa.String(), nullable=True),
        sa.Column("release_train", sa.String(), nullable=True),
        sa.Column("latest_known_version", sa.String(), nullable=True),
        sa.Column("recommended_version", sa.String(), nullable=True),
        sa.Column("minimum_supported_version", sa.String(), nullable=True),
        sa.Column("eol_versions", sa.JSON(), nullable=True),
        sa.Column("release_date", sa.String(), nullable=True),
        sa.Column("support_status", sa.String(), nullable=True),
        sa.Column("advisory_url", sa.String(), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("last_updated", sa.DateTime(), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_version_catalog_vendor_train", "version_catalog", ["vendor", "release_train"])


def downgrade() -> None:
    op.drop_index("ix_version_catalog_vendor_train", table_name="version_catalog")
    op.drop_table("version_catalog")
