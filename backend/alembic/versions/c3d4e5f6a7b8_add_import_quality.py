"""add import-quality score/breakdown columns

Additive, nullable columns recording how complete the imported data was for a
policy (0-100 score + capability breakdown), persisted on both the policy and the
analysis run. No constraints, no backfill — safe on a populated database.

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
Create Date: 2026-06-25
"""
from alembic import op
import sqlalchemy as sa


revision = "c3d4e5f6a7b8"
down_revision = "b2c3d4e5f6a7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("firewall_policies", sa.Column("import_quality_score", sa.Float(), nullable=True))
    op.add_column("firewall_policies", sa.Column("import_quality", sa.JSON(), nullable=True))
    op.add_column("analysis_runs", sa.Column("import_quality", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("analysis_runs", "import_quality")
    op.drop_column("firewall_policies", "import_quality")
    op.drop_column("firewall_policies", "import_quality_score")
