"""quality_snapshots: the nightly micro-eval trend table (I4 — measured always)

``soc-ai eval-nightly`` runs a tiny batch of real investigations on a schedule
and lands ONE row per run here, so verdict quality is a local trend the
dashboard can plot (and alarm on) instead of a one-off validation that rots
the day the operator swaps inference engines.

Design notes:

* One plain table, no FKs — a snapshot summarizes a whole batch, whose
  per-alert artifacts live on disk (``batch_dir``), not in the store. Nothing
  references a snapshot and a snapshot references nothing, so pruning (the
  store keeps only the newest 90 rows) is a bare DELETE.
* ``agreement_rate`` / ``fallback_rate`` are NULLABLE by contract: local-mode
  (zero-egress) runs have no oracle and therefore no agreement signal, and a
  run where nothing succeeded has no fallback denominator. NULL is the honest
  "not measured" — storing 0.0 would fake a catastrophic reading.
* ``alarmed`` + ``alarm_reasons`` persist the regression-detector outcome at
  write time (vs the trailing same-mode history), so the read-model never has
  to re-derive the alarm rule against rows that may since have been pruned.
* No index beyond the PK: the table is capped at 90 rows and every query is
  "newest N by id" — the integer PK already serves that.

Revision ID: 0019
Revises: 0018
Create Date: 2026-07-10
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0019"
down_revision = "0018"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "quality_snapshots",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        # "local" (no oracle, zero-egress) | "graded" (oracle-critiqued).
        sa.Column("mode", sa.String(8), nullable=False),
        sa.Column("n_ok", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("n_error", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("agreement_rate", sa.Float(), nullable=True),
        sa.Column("fallback_rate", sa.Float(), nullable=True),
        sa.Column("error_rate", sa.Float(), nullable=False, server_default="0"),
        sa.Column("verdict_counts", sa.JSON(), nullable=False),
        sa.Column("latency_p50_ms", sa.Integer(), nullable=True),
        sa.Column("batch_dir", sa.String(512), nullable=True),
        sa.Column("alarmed", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("alarm_reasons", sa.JSON(), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("quality_snapshots")
