"""runbook.draft: the promoted-from-history draft flag (suggestion, never auto-applied)

The runbook-promotion feature distills a rule's investigation history into a
runbook the operator reviews in the Runbooks page. Those machine-authored rows
land with ``draft=1`` and are EXCLUDED from every agent retrieval path
(rule-link / FTS / legacy scorer / semantic) until the operator explicitly
approves them — the same "suggestions, never auto-applied" contract detection
tuning follows. Approval flips the flag to 0; nothing else reads it.

Design notes:

* ``server_default='0'`` (not just an ORM default) so every PRE-EXISTING
  operator-authored runbook stays retrievable through the upgrade — a NULL or
  missing default here would silently drop the whole corpus out of the agent's
  ``lookup_runbook`` tool.
* Plain ``add_column`` (no batch mode): SQLite handles ADD COLUMN with a
  constant default natively, and the 0017 FTS triggers name their columns
  explicitly so they are unaffected.
* No index: retrieval scans are already bounded (≤500 rows) and the corpus is
  a few hundred operator documents at most.

Revision ID: 0020
Revises: 0019
Create Date: 2026-07-10
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0020"
down_revision = "0019"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "runbook",
        sa.Column("draft", sa.Boolean(), nullable=False, server_default=sa.false()),
    )


def downgrade() -> None:
    op.drop_column("runbook", "draft")
