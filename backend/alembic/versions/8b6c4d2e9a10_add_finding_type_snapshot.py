"""add finding type snapshot

Revision ID: 8b6c4d2e9a10
Revises: 4e9c017023c2
Create Date: 2026-06-20 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "8b6c4d2e9a10"
down_revision: Union[str, None] = "4e9c017023c2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("analysis_runs", sa.Column("finding_type_snapshot", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("analysis_runs", "finding_type_snapshot")
