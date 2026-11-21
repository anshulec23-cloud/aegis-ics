"""Split the operator financial profile out of devices into device_financials.

Keeps `devices` purely identity + crypto state so the costing model can change without
touching the table enrollment and replay protection depend on.

Revision ID: d4e8b2c91f07
Revises: c3f1aa20d5e4
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "d4e8b2c91f07"
down_revision: Union[str, None] = "c3f1aa20d5e4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

MONEY = (
    "role",
    "criticality",
    "zone",
    "equipment_value",
    "downtime_rate_per_hour",
    "cleanup_cost",
    "regulatory_exposure",
)


def _device_columns(conn) -> set:
    return {c["name"] for c in sa.inspect(conn).get_columns("devices")}


def upgrade() -> None:
    conn = op.get_bind()
    op.create_table(
        "device_financials",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "device_id",
            sa.String(length=50),
            sa.ForeignKey("devices.device_id"),
            nullable=False,
            unique=True,
        ),
        sa.Column("role", sa.String(length=32), nullable=True),
        sa.Column("criticality", sa.String(length=20), nullable=True),
        sa.Column("zone", sa.String(length=80), nullable=True),
        sa.Column("equipment_value", sa.Float(), nullable=True),
        sa.Column("downtime_rate_per_hour", sa.Float(), nullable=True),
        sa.Column("cleanup_cost", sa.Float(), nullable=True),
        sa.Column("regulatory_exposure", sa.Float(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
    )
    op.create_index(
        "ix_device_financials_device_id", "device_financials", ["device_id"], unique=True
    )

    present = [c for c in MONEY if c in _device_columns(conn)]
    if present:
        cols = ", ".join(present)
        not_null = " OR ".join(f"{c} IS NOT NULL" for c in present)
        conn.execute(
            sa.text(
                f"INSERT INTO device_financials (device_id, {cols}) "
                f"SELECT device_id, {cols} FROM devices WHERE {not_null}"
            )
        )
        with op.batch_alter_table("devices") as batch:
            for col in present:
                batch.drop_column(col)


def downgrade() -> None:
    conn = op.get_bind()
    existing = _device_columns(conn)
    with op.batch_alter_table("devices") as batch:
        for col, type_ in (
            ("role", sa.String(length=32)),
            ("criticality", sa.String(length=20)),
            ("zone", sa.String(length=80)),
            ("equipment_value", sa.Float()),
            ("downtime_rate_per_hour", sa.Float()),
            ("cleanup_cost", sa.Float()),
            ("regulatory_exposure", sa.Float()),
        ):
            if col not in existing:
                batch.add_column(sa.Column(col, type_, nullable=True))

    sets = ", ".join(
        f"{c} = (SELECT f.{c} FROM device_financials f WHERE f.device_id = devices.device_id)"
        for c in MONEY
    )
    conn.execute(
        sa.text(
            f"UPDATE devices SET {sets} WHERE device_id IN (SELECT device_id FROM device_financials)"
        )
    )
    op.drop_index("ix_device_financials_device_id", table_name="device_financials")
    op.drop_table("device_financials")
