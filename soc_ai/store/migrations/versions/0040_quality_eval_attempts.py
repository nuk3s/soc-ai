"""quality_eval_attempts: the nightly ran, even on the nights it wrote nothing

A nightly quality eval that finds no eligible alerts exits 2, and one that
fails exits 5. Neither writes a ``quality_snapshots`` row, and that is on
purpose: a zero row would plot as quality zero, count toward the regression
detector's trailing history, and push a real point out of the 90-row prune. So
on exactly the nights an operator most needs to know what happened, the trend
table is silent by design.

The stand-in was ``_QualityEvalStatus`` on ``app.state`` — ``last_run``,
``last_exit_code``, ``last_detail``. Process memory. Null until this process
had attempted a run and gone at the next restart, which on a container is a
routine event. Both surfaces that read it test the timestamp for truthiness and
render nothing when it is null, so "the nightly has never run here" and "it ran
last night, exited 2, and I have forgotten" produced the same silence. The
Quality card then showed an empty trend with no explanation beside it, which is
the shape of every other defect in this tracker: an absence read as an
all-clear.

The same field was also the scheduler's once-per-day guard. ``_eval_nightly_due``
compensates with a durable read of the newest snapshot's date — but a snapshot
is precisely what an exit-2 or exit-5 night does not write, so on those nights
the only guard was the one a restart cleared. This table is durable for that
too.

One row per finished attempt, pruned like the trend it accompanies. Not merged
into ``quality_snapshots``: that table is the trend, every reader of it plots
its rows, and a row that is not a measurement does not belong in it.

Revision ID: 0040
Revises: 0039
Create Date: 2026-09-10
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0040"
down_revision = "0039"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "quality_eval_attempts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("attempted_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        # Server defaults on every non-identity column, matching the sweep
        # trail: a row written by an older writer, or a raw insert naming only
        # the timestamp, must never trip a NOT NULL.
        sa.Column("trigger", sa.String(16), nullable=False, server_default="schedule"),
        sa.Column("exit_code", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("detail", sa.Text(), nullable=False, server_default=""),
    )
    # The only read is "the newest attempt", and the prune orders by the same
    # column. One index serves both.
    op.create_index(
        "ix_quality_eval_attempts_attempted_at", "quality_eval_attempts", ["attempted_at"]
    )


def downgrade() -> None:
    op.drop_index("ix_quality_eval_attempts_attempted_at", table_name="quality_eval_attempts")
    op.drop_table("quality_eval_attempts")
