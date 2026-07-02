"""hunts + hunt_events tables: multi-alert threat hunts (findings + narrative)

Revision ID: 0010
Revises: 0009
Create Date: 2026-07-01
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "hunts",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("objective", sa.Text(), nullable=False),
        sa.Column("kind", sa.String(16), nullable=False, server_default="chat"),
        sa.Column("status", sa.String(16), nullable=False, server_default="running"),
        sa.Column("narrative", sa.Text(), nullable=True),
        sa.Column("report", sa.JSON(), nullable=True),
        sa.Column("started_by", sa.String(64), nullable=False, server_default="anonymous"),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
    )
    op.create_table(
        "hunt_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("hunt_id", sa.String(32), sa.ForeignKey("hunts.id"), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(40), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
    )
    op.create_index("ix_hunt_events_hunt_id", "hunt_events", ["hunt_id"])


def downgrade() -> None:
    op.drop_index("ix_hunt_events_hunt_id", table_name="hunt_events")
    op.drop_table("hunt_events")
    op.drop_table("hunts")
