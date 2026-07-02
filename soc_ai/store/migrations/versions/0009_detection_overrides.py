"""detection_override table: operator soft-mutes for noisy detection rules

Revision ID: 0009
Revises: 0008
Create Date: 2026-06-30
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "detection_override",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("rule_name", sa.String(512), nullable=False),
        sa.Column("action", sa.String(16), nullable=False, server_default="mute"),
        sa.Column("reason", sa.String(512), nullable=True),
        sa.Column("created_by", sa.String(128), nullable=False, server_default="anonymous"),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
    )
    op.create_index(
        "ix_detection_override_rule_name", "detection_override", ["rule_name"]
    )


def downgrade() -> None:
    op.drop_index("ix_detection_override_rule_name", table_name="detection_override")
    op.drop_table("detection_override")
