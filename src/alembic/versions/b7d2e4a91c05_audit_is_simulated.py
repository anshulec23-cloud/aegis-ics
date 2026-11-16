"""Add audit_logs.is_simulated (separates red-team drill entries from real events).

Revision ID: b7d2e4a91c05
Revises: f1a4571c083c
Create Date: 2026-11-14
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "b7d2e4a91c05"
down_revision: Union[str, None] = "f1a4571c083c"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "audit_logs",
        sa.Column("is_simulated", sa.Boolean(), nullable=False, server_default=sa.false()),
    )


def downgrade() -> None:
    op.drop_column("audit_logs", "is_simulated")
