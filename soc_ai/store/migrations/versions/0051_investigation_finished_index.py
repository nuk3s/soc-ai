"""Indexes for the bell's finished_since window and the unread shadow-hit count.

Three indexes, all serving queries the always-mounted shell polls from every
open tab: ``GET /notifications`` every 15s, the sidebar's needs-you ledger
every 60s.

**(status, finished_at) on investigations and hunts.** The completed half of
the bell bounds and orders on ``finished_at`` (the clock it renders), while the
only index either table had was 0028's ``(status, created_at)``. SQLite used
that index for the status equality and then sorted every completed row in a
temp B-tree to satisfy the ORDER BY, on each poll, three queries per poll.
With ``(status, finished_at)`` the window is a range seek on the index and the
rows come out in order; only the id tiebreak is left to sort.

**(shadow, read_at, spec_id) on entity_observations.** The unread-hit clause
(``shadow IS TRUE AND read_at IS NULL AND spec_id NOT IN (retired)``) is read
by five surfaces and had no index it could use, so every count was a full scan
of a table whose unique key is per (entity, spec, fingerprint) and which grows
with every distinct signal. The index covers the whole clause, so the count is
answered from the index alone.

Index creation is a single pass over each table; both are small (see 0028) and
this runs once.

Revision ID: 0051
Revises: 0050
Create Date: 2026-09-28
"""

from __future__ import annotations

from alembic import op

revision = "0051"
down_revision = "0050"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index(
        "ix_investigations_status_finished", "investigations", ["status", "finished_at"]
    )
    op.create_index("ix_hunts_status_finished", "hunts", ["status", "finished_at"])
    op.create_index(
        "ix_entity_observation_unread", "entity_observations", ["shadow", "read_at", "spec_id"]
    )


def downgrade() -> None:
    op.drop_index("ix_entity_observation_unread", table_name="entity_observations")
    op.drop_index("ix_hunts_status_finished", table_name="hunts")
    op.drop_index("ix_investigations_status_finished", table_name="investigations")
