"""quality_snapshots: the detail a snapshot could not hold

One nullable JSON column on ``quality_snapshots``. Nothing existing is touched.

A snapshot held numbers and one model name. Three facts had no column, and the
production review of 2026-11-13 found each of them missing from the trend:

- **Which model served the runs.** ``analyst_model`` is the configured route.
  The gateway moved that route to another engine, and a fallback route served
  54 runs, and the snapshots of those days kept the one configured name.
- **What became of the planted true positive.** The nightly now plants a known
  positive in each batch. A miss is an alarm and is in ``alarm_reasons``. A
  catch, and a plant that could not be measured, had nowhere to go.
- **Which runs the grader never graded, and why.** Three nights lost every
  grade to the Oracle quota and were recorded as ``error_rate 1.00``. Those runs
  now count as completed runs, and the lost grades need a place of their own.

``detail`` holds all three as one object
(:func:`soc_ai.eval.quality.snapshot_detail`). One JSON column and not six
typed ones, because the reader is one API route and the table is capped at 90
rows: nothing here is ever filtered or joined on.

NULL and no backfill, for the reason 0026, 0027 and 0041 gave before it. A row
written before this revision recorded none of these facts, and its batch
artifacts are the only place they could be recovered from. An invented value
would say a model was recorded as served when nothing was recorded.

SQLite ADD COLUMN is metadata-only for a nullable column with no default.

Revision ID: 0066
Revises: 0065
Create Date: 2026-11-13
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0066"
down_revision = "0065"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("quality_snapshots", sa.Column("detail", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("quality_snapshots", "detail")
