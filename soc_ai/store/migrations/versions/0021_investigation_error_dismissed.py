"""investigations.error_dismissed_at: operator ack of a pipeline-error run

A pipeline-error run (``report['resolution']['provenance'] ==
"pipeline_fallback"`` — model truncation, gateway 5xx) is counted in the
Dashboard's "N pipeline errors" KPI. This column records the operator's
acknowledgement: ``POST /investigations/{id}/dismiss-error`` stamps it, and the
KPI counts only rows where the marker is present AND this is NULL. The run's
``fallback`` flag itself is untouched — it remains a historical fact, visible
under the Investigations "Pipeline error" filter; only the dashboard nag is
silenced.

Design notes:

* Nullable ``DateTime``, no default: NULL means "not acknowledged", which is
  the correct state for every pre-existing row — no backfill needed, and
  SQLite handles a plain nullable ADD COLUMN natively (no batch mode).
* A timestamp (not a bool) so the ack moment is auditable for free.
* No index: the flag is read off rows the list endpoint already fetched.

Revision ID: 0021
Revises: 0020
Create Date: 2026-07-14
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0021"
down_revision = "0020"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "investigations",
        sa.Column("error_dismissed_at", sa.DateTime(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("investigations", "error_dismissed_at")
