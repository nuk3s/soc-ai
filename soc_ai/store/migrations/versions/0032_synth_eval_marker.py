"""Synthetic-evaluation marker on hunts + investigations

The quality spine plants synthetic attack scenarios into the grid so verdict
quality can be measured. Tasks 1-3 let an EVAL-MODE run see those scenarios
(``include_synth``); this closes the containment story on the store side: a
hunt recorded from an eval context, and any investigation promoted from such a
hunt, is permanently marked ``is_synth_eval`` — otherwise a planted attack
could later be read back as a real finding (in the UI, in a report, or by a
future measurement).

``server_default="0"`` (not just an ORM default) backfills every pre-existing
row as NOT synthetic — which is true by construction: before this column, no
recorded hunt could opt in to synth visibility. Plain ``add_column`` (no batch
mode), same as 0031 on these same tables: SQLite handles ADD COLUMN with a
constant default natively. No index — nothing filters on the flag today; it is
provenance read row-by-row.

The flag is set only from an explicit eval context
(``InvestigationContext.include_synth`` at hunt-record time) or inherited from
a marked hunt by the finding-promotion route. No API request model carries it.

Revision ID: 0032
Revises: 0031
Create Date: 2026-08-26
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0032"
down_revision = "0031"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "hunts",
        sa.Column("is_synth_eval", sa.Boolean(), nullable=False, server_default="0"),
    )
    op.add_column(
        "investigations",
        sa.Column("is_synth_eval", sa.Boolean(), nullable=False, server_default="0"),
    )


def downgrade() -> None:
    op.drop_column("investigations", "is_synth_eval")
    op.drop_column("hunts", "is_synth_eval")
