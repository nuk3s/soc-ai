"""dossier_run.notes — a channel for advisory notes, kept apart from errors

The nightly dossier sweep had one operator-facing channel, ``dossier_run.errors``.
Truncation notes (a hit terms-agg cap) and the cadence-ceiling advisory were
folded into it, so a fully healthy sweep — every host built, zero conflicts —
persisted a nonzero ``errors`` count every night. A run-row count that is always
on stops being read, and a genuine census or collection failure then hides among
the permanent notes: the level-triggered-noise class the alarm work already
fixed elsewhere.

This adds a second JSON column so the two channels are separate at rest:
``errors`` carries only things that actually broke, ``notes`` carries the
healthy-but-capped advisories. ``_close_run`` writes each from its own list on
:class:`~soc_ai.enrichment.host_dossier.DossierSummary`.

Nullable with no default, so the ``ADD COLUMN`` is a metadata-only O(1)
operation in SQLite; nothing needs backfilling — a note is derived fresh each
sweep, and a legacy run simply has no notes.

Revision ID: 0029
Revises: 0028
Create Date: 2026-08-11
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0029"
down_revision = "0028"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("dossier_run", sa.Column("notes", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("dossier_run", "notes")
