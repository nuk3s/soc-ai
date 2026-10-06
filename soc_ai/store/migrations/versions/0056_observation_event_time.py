"""An observation keeps the time of the event it cites.

``entity_observations.born_at`` is the time soc-ai wrote the row. The time of
the event the row cites was lost, so an observation decayed from the sweep
that recorded it. A lead on the range joined an event of 2026-09-04 with a
silence of 2026-09-28 as two fresh observations.

``observed_at`` is the newest document timestamp the observation cites. The
prior sweep writes it from the documents of the recent read. The catalog
sweep writes it from the newest document of the hit. ``born_at`` stays the
record time. The decay and the lead page read ``observed_at`` when a row has
one, and ``born_at`` when it has none.

The column is nullable with no default. A row written before this upgrade has
no event time on record, so it keeps the record time as its clock.

Revision ID: 0056
Revises: 0055
Create Date: 2026-10-04
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0056"
down_revision = "0055"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("entity_observations", sa.Column("observed_at", sa.DateTime(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("entity_observations") as batch:
        batch.drop_column("observed_at")
