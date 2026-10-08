"""entity_observations: the dismissal an analyst gives one observation

Four nullable columns. Nothing existing is touched.

A live analytic hit offered only "Hunt this entity". Five hits of "A
workstation runs remote-execution tooling" were Windows updates, and the
analyst had no way to say so on the hit itself. "Mark benign" records the
reason on the observation, in the shape a lead dismissal takes: a reason from
the fixed list, an optional note, the hand and the time.

A dismissed observation counts toward no lead. A repeat of the same content
refreshes the same row, so the dismissal holds for the repeats.

Revision ID: 0062
Revises: 0061
Create Date: 2026-10-06
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0062"
down_revision = "0061"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("entity_observations") as batch:
        batch.add_column(sa.Column("dismissed_reason", sa.String(32), nullable=True))
        batch.add_column(sa.Column("dismissed_note", sa.Text(), nullable=True))
        batch.add_column(sa.Column("dismissed_by", sa.String(80), nullable=True))
        batch.add_column(sa.Column("dismissed_at", sa.DateTime(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("entity_observations") as batch:
        batch.drop_column("dismissed_at")
        batch.drop_column("dismissed_by")
        batch.drop_column("dismissed_note")
        batch.drop_column("dismissed_reason")
