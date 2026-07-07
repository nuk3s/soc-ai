"""hunt_schedules table: per-hunt recurring schedules fired by a background loop

Each row is one recurring hunt: an ``objective`` re-run every ``interval_minutes``
by the in-process ``_hunt_schedule_loop`` (see :mod:`soc_ai.main`). A due schedule
spawns a normal hunt tagged ``kind="scheduled"`` and stamps ``last_run_at`` — the
interval clock. Small self-contained table (no template_id yet — E3.2 adds
templates); mirrors the runbook table shape (op.create_table).

Revision ID: 0014
Revises: 0013
Create Date: 2026-07-07
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "hunt_schedules",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("objective", sa.Text(), nullable=False),
        sa.Column("interval_minutes", sa.Integer(), nullable=False, server_default="60"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        # NULL until the first run — a fresh schedule is immediately due.
        sa.Column("last_run_at", sa.DateTime(), nullable=True),
        sa.Column("created_by", sa.String(128), nullable=False, server_default="anonymous"),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("hunt_schedules")
