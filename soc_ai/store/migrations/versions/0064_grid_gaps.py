"""grid_gaps table: the hours soc-ai could not read the grid

A pure CREATE TABLE. Nothing existing is touched.

The range sensor was down from 2026-10-15 13:36Z to 2026-10-19 10:15Z. soc-ai
saw Elasticsearch fail and kept the fact in process memory only. After the
recovery every windowed surface read the hole as a quiet grid, and the profile
sweep wrote departures for hours the grid held no data for.

One row is one gap.

* ``source`` says who saw it. ``probe``: the health probe found the grid
  unreadable. ``sweep``: the grid answered, and the profile sweep found the
  documents of one plane stopped on most hosts at once.
* ``plane`` names the dimension of a sweep gap. NULL for a probe gap, which
  covers every plane.
* ``started_at`` is the first failed probe or the first dark hour.
* ``ended_at`` is the first good probe or the end of the last dark hour. NULL
  while the gap is open. An open row survives a restart, and the first good
  probe after the start closes it.

Revision ID: 0064
Revises: 0063
Create Date: 2026-10-19
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0064"
down_revision = "0063"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "grid_gaps",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("source", sa.String(length=16), nullable=False),
        sa.Column("plane", sa.String(length=64), nullable=True),
        sa.Column("started_at", sa.DateTime(), nullable=False),
        sa.Column("ended_at", sa.DateTime(), nullable=True),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_grid_gaps_window", "grid_gaps", ["started_at", "ended_at"])


def downgrade() -> None:
    op.drop_index("ix_grid_gaps_window", table_name="grid_gaps")
    op.drop_table("grid_gaps")
