"""Add per-device financial profile columns to devices.

Revision ID: c3f1aa20d5e4
Revises: b7d2e4a91c05
Create Date: 2026-11-15
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "c3f1aa20d5e4"
down_revision: Union[str, None] = "b7d2e4a91c05"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_COLUMNS = [
    ("role", sa.String(32)),
    ("criticality", sa.String(20)),
    ("zone", sa.String(80)),
    ("equipment_value", sa.Float()),
    ("downtime_rate_per_hour", sa.Float()),
    ("cleanup_cost", sa.Float()),
    ("regulatory_exposure", sa.Float()),
]


def upgrade() -> None:
    for name, col_type in _COLUMNS:
        op.add_column("devices", sa.Column(name, col_type, nullable=True))


def downgrade() -> None:
    for name, _ in reversed(_COLUMNS):
        op.drop_column("devices", name)
