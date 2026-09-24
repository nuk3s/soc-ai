"""hunt_spec_state.retired_at — a way for a handled condition to stop being handled

The gate is deliberately terminal: a condition that persists fires once, ever,
because on a one-analyst SOC the problem is never the first notification but
the ninetieth. Terminal with no exit is a different thing, and it is the bug
this table has now grown four times in four disguises. A backfill marked
history as fired; shadow mode did the same; the budget cap starved new
low-count scopes; a fired row committed before its hunt existed made a crash
permanent. Every one of them ended with a real condition suppressed forever and
nobody told.

The fifth is the visibility gap. ``sweep.py`` records a blind or errored run as
a synthetic candidate on the ``visibility-gap`` scope so the gap reports once
rather than on every sweep, and its own comment says the gap re-reports on
transition — blind, then seeing, then blind again. Nothing retired the row, so
it did not. The first coverage gap a spec recorded was the last one it could
record, which matters most on the deployment that logged a gap the spec was
later fixed not to produce: the report it will need the day that plane really
dies has already been spent.

``retired_at`` is when a live sweep last saw the spec's plane again. It is
nullable with no default, so the ADD COLUMN is metadata-only on SQLite and no
existing row needs rewriting: a null means the row still speaks for itself,
which is what every row written before this migration meant.

It is read only for gap rows, and only by the gate. Retiring an ordinary
finding on absence would be wrong for a reason the gap does not share: a
finding's evidence leaves the rolling window on a fixed schedule whatever the
network is doing, so absence there is a clock and not a state change. Widening
this to findings is a separate decision with its own reasoning.

Revision ID: 0035
Revises: 0034
Create Date: 2026-09-05
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0035"
down_revision = "0034"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("hunt_spec_state", sa.Column("retired_at", sa.DateTime(), nullable=True))


def downgrade() -> None:
    op.drop_column("hunt_spec_state", "retired_at")
