"""alert_assignments table: persisted owner assignment per detection rule

Revision ID: 0006
Revises: 0005
Create Date: 2026-06-22
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "alert_assignments",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("rule_name", sa.String(512), nullable=False),
        sa.Column("owner", sa.String(128), nullable=False),
        sa.Column("assigned_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    op.create_index(
        "ix_alert_assignments_rule_name", "alert_assignments", ["rule_name"], unique=True
    )


def downgrade() -> None:
    op.drop_index("ix_alert_assignments_rule_name", table_name="alert_assignments")
    op.drop_table("alert_assignments")
