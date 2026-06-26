"""similarity columns: src_ip / dest_ip on investigations

Revision ID: 0003
Revises: 0002
Create Date: 2026-06-12
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("investigations") as batch_op:
        batch_op.add_column(sa.Column("src_ip", sa.String(64), nullable=True))
        batch_op.add_column(sa.Column("dest_ip", sa.String(64), nullable=True))
    op.create_index(
        "ix_investigations_similarity",
        "investigations",
        ["rule_name", "src_ip", "dest_ip"],
    )


def downgrade() -> None:
    op.drop_index("ix_investigations_similarity", table_name="investigations")
    with op.batch_alter_table("investigations") as batch_op:
        batch_op.drop_column("dest_ip")
        batch_op.drop_column("src_ip")
