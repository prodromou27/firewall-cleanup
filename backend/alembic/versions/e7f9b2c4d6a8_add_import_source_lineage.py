"""Add upload checksum and parser diagnostics without altering existing data.

Revision ID: e7f9b2c4d6a8
Revises: c3d4e5f6a7b8
"""
from alembic import op
import sqlalchemy as sa


revision = "e7f9b2c4d6a8"
down_revision = "c3d4e5f6a7b8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("firewall_policies", sa.Column("source_sha256", sa.String(64), nullable=True))
    op.add_column("firewall_policies", sa.Column("parse_warnings", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("firewall_policies", "parse_warnings")
    op.drop_column("firewall_policies", "source_sha256")
