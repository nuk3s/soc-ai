"""Hunt starters and lead status.

A hunt names the class that started it: an analyst, a schedule, a lead, or the
catalog sweep before merge 1. A lead-started hunt links to its lead. A lead
records why it was dismissed and which investigation promoted it.

Revision ID: 0047
Revises: 0046
Create Date: 2026-09-18
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0047"
down_revision = "0046"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("hunts") as batch:
        batch.add_column(
            sa.Column("starter", sa.String(16), nullable=False, server_default="analyst")
        )
        batch.add_column(sa.Column("lead_id", sa.Integer(), nullable=True))
    op.create_index("ix_hunts_lead_id", "hunts", ["lead_id"])
    # Existing rows: the class follows the kind the row was written with.
    op.execute("UPDATE hunts SET starter = 'catalog' WHERE kind = 'triggered'")
    op.execute("UPDATE hunts SET starter = 'schedule' WHERE kind = 'scheduled'")
    with op.batch_alter_table("leads") as batch:
        batch.add_column(sa.Column("dismissed_reason", sa.String(32), nullable=True))
        batch.add_column(sa.Column("dismissed_note", sa.Text(), nullable=True))
        batch.add_column(sa.Column("dismissed_by", sa.String(80), nullable=True))
        batch.add_column(sa.Column("dismissed_at", sa.DateTime(), nullable=True))
        batch.add_column(sa.Column("investigation_id", sa.String(32), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("leads") as batch:
        for name in (
            "investigation_id",
            "dismissed_at",
            "dismissed_by",
            "dismissed_note",
            "dismissed_reason",
        ):
            batch.drop_column(name)
    op.drop_index("ix_hunts_lead_id", table_name="hunts")
    with op.batch_alter_table("hunts") as batch:
        batch.drop_column("lead_id")
        batch.drop_column("starter")
