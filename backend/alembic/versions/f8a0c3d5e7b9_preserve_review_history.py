"""Preserve findings and review history across successful reanalysis.

Revision ID: f8a0c3d5e7b9
Revises: e7f9b2c4d6a8
"""
from alembic import op
import sqlalchemy as sa

revision = "f8a0c3d5e7b9"
down_revision = "e7f9b2c4d6a8"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("analysis_runs", sa.Column("replaced_findings", sa.JSON(), nullable=True))


def downgrade():
    op.drop_column("analysis_runs", "replaced_findings")
