"""campaign decisions: the decision of a campaign, and the changes of each campaign

Eight ADD COLUMN statements on ``campaigns`` and one new table,
``campaign_changes``. No existing value changes.

The analyst decides once on a campaign. A rebuild deletes and writes the
member and party rows again, so the decision lives on the ``campaigns`` row:

* ``decision`` is null, or one of ``closed``, ``authorized`` and ``case``.
  This release writes ``closed`` only.
* ``decided_at`` and ``decided_by`` state when and who.
* ``decision_note`` is the optional note of the analyst.
* ``close_reason`` is ``handled_outside``, ``accepted_risk`` or ``test_over``.
* ``decision_basis`` holds what the decision covered: the last event time,
  the stage and the machine keys of the parties. A later rebuild opens the
  campaign again when it goes past that basis.
* ``authorization_id`` and ``case_id`` are for two later decisions. This
  release writes neither.

``campaign_changes`` holds one row for each change of a campaign: ``formed``,
``stage``, ``party``, ``decided``, ``reopened`` and ``acknowledged``. The bell
and the campaign page read it. The index on ``campaign_id`` serves the page.

No backfill. The first rebuild after the upgrade compares each campaign with
its stored row, and an unchanged campaign gets no change row.

SQLite ADD COLUMN is metadata-only for a nullable column with no default.

Revision ID: 0070
Revises: 0069
Create Date: 2026-11-14
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0070"
down_revision = "0069"
branch_labels = None
depends_on = None

_COLUMNS = (
    ("decision", sa.String(length=16)),
    ("decided_at", sa.DateTime()),
    ("decided_by", sa.String(length=128)),
    ("decision_note", sa.Text()),
    ("close_reason", sa.String(length=32)),
    ("decision_basis", sa.JSON()),
    ("authorization_id", sa.Integer()),
    ("case_id", sa.String(length=64)),
)


def upgrade() -> None:
    for name, type_ in _COLUMNS:
        op.add_column("campaigns", sa.Column(name, type_, nullable=True))
    op.create_table(
        "campaign_changes",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("campaign_id", sa.Integer(), nullable=False),
        sa.Column("type", sa.String(length=24), nullable=False),
        sa.Column("detail", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_campaign_changes_campaign", "campaign_changes", ["campaign_id"])
    op.create_index("ix_campaign_changes_created", "campaign_changes", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_campaign_changes_created", table_name="campaign_changes")
    op.drop_index("ix_campaign_changes_campaign", table_name="campaign_changes")
    op.drop_table("campaign_changes")
    with op.batch_alter_table("campaigns") as batch:
        for name, _type in reversed(_COLUMNS):
            batch.drop_column(name)
