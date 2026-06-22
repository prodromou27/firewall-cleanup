"""add firewall_policies.nat_rules JSON column

Additive, nullable column to persist normalized NAT rules for the NAT & Public
Exposure analysis. No constraints, no backfill — safe on a populated database.

Revision ID: a1b2c3d4e5f6
Revises: d4f2a9c1b7e3
Create Date: 2026-06-22
"""
from alembic import op
import sqlalchemy as sa


revision = "a1b2c3d4e5f6"
down_revision = "d4f2a9c1b7e3"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("firewall_policies", sa.Column("nat_rules", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("firewall_policies", "nat_rules")
