"""(status, created_at) indexes + denormalized is_fallback / findings_count

Two composite indexes and two denormalized columns, serving the app's hottest
query path — the always-mounted Topbar polls ``GET /notifications`` every 15s
from every open tab.

**The indexes.** Neither ``investigations`` nor ``hunts`` indexed ``status`` or
``created_at``, so every ``list_recent(status=?, ORDER BY created_at DESC)`` —
the bell's three per-poll queries — scanned the whole filtered table and top-k
sorted it. ``(status, created_at)`` turns that into an index range scan. The
same index serves ``query_page``'s ORDER BY and ``reap_stale_running``'s
``status == 'running'`` filter.

**The denormalized columns.** The bell and the investigations-list aggregate
each reopened the ``report`` JSON blob for one scalar:

- ``hunts.findings_count`` = ``len(report["findings"])`` — the bell showed
  "Hunt finished — N findings" by deserializing every completed hunt's report.
- ``investigations.is_fallback`` = ``is_pipeline_fallback(report)`` — ``query_page``
  ran ``json_extract(report, '$.resolution.provenance')`` over EVERY row of the
  filter set on each 10s poll to compute the true-positive / pipeline-error
  counts. Now the flag is stamped once at finalize/resolve and the aggregate
  reads the column.

**Backfill, not lazy.** Both columns are backfilled from the report JSON already
on disk so the reads cover every row, not just ones finalized after this
migration — the aggregate would otherwise miscount legacy fallbacks and the bell
would show 0 findings for old hunts. Both tables are small (bounded by triage /
hunt history; no retention prune yet, a few thousand rows at most on the
measured install), so a single set-based ``UPDATE`` per table is cheap and runs
once. The ``json_extract`` used for ``is_fallback`` is the same expression the
prior ``query_page`` filter used, proven equivalent to ``is_pipeline_fallback``
by the differential test — so the backfill inherits that equivalence.

The columns are nullable with no default, so the ``ADD COLUMN`` itself is a
metadata-only O(1) operation in SQLite; the cost is the one-time backfill scan.

Revision ID: 0028
Revises: 0027
Create Date: 2026-08-10
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0028"
down_revision = "0027"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index("ix_investigations_status_created", "investigations", ["status", "created_at"])
    op.create_index("ix_hunts_status_created", "hunts", ["status", "created_at"])

    op.add_column("investigations", sa.Column("is_fallback", sa.Boolean(), nullable=True))
    op.add_column("hunts", sa.Column("findings_count", sa.Integer(), nullable=True))

    bind = op.get_bind()
    # is_fallback mirrors is_pipeline_fallback(report): resolution.provenance ==
    # 'pipeline_fallback'. json_extract returns NULL for any unresolvable path
    # (report NULL, scalar, or non-object), so CASE folds every non-fallback —
    # report IS NULL included — to 0 rather than leaving it NULL.
    bind.execute(
        sa.text(
            "UPDATE investigations SET is_fallback = "
            "CASE WHEN json_extract(report, '$.resolution.provenance') = 'pipeline_fallback' "
            "THEN 1 ELSE 0 END"
        )
    )
    # findings_count mirrors len(report['findings']): json_array_length returns
    # the array length, 0 for a non-array at the path, and NULL when the path is
    # absent — COALESCE folds absent / NULL report to 0.
    bind.execute(
        sa.text(
            "UPDATE hunts SET findings_count = COALESCE(json_array_length(report, '$.findings'), 0)"
        )
    )


def downgrade() -> None:
    op.drop_column("hunts", "findings_count")
    op.drop_column("investigations", "is_fallback")
    op.drop_index("ix_hunts_status_created", table_name="hunts")
    op.drop_index("ix_investigations_status_created", table_name="investigations")
