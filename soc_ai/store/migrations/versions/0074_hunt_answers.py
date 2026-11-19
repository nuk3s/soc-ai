"""hunt answers: what a hunt found for each campaign and each lead that it read

One new table, ``hunt_answers``. No existing value changes.

The round "decide once" (2026-11-17): the scheduled hunt of 2026-11-16 read
campaign 2 and lead 73 and found no new event, and neither page showed it.
When a hunt ends complete and not degraded, soc-ai records one answer for
each campaign whose block the hunt read and for each open lead that the hunt
read (:mod:`soc_ai.hunting.hunt_answers`).

* ``hunt_id`` names the hunt. It has no foreign key, like
  ``campaign_members.run_id``.
* ``subject_type`` is ``campaign`` or ``lead``, and ``subject_id`` is the id
  of the campaign or of the lead.
* ``outcome`` is ``new_activity``, ``continues`` or ``no_new_event``. It
  comes from stored facts, never from model text.
* ``finding_ordinal`` names the finding that gave ``new_activity`` or
  ``continues``. It is null for ``no_new_event``.
* ``answered_at`` is the time that the hunt ended.

The unique index holds one answer for one hunt and one subject. The second
index serves the campaign page and the lead page.

No fill here. The start step of the application fills the answers of the
stored hunts of the last 30 days: the rule reads the report of each hunt.

Revision ID: 0074
Revises: 0073
Create Date: 2026-11-17
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0074"
down_revision = "0073"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "hunt_answers",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("hunt_id", sa.String(length=32), nullable=False),
        sa.Column("subject_type", sa.String(length=16), nullable=False),
        sa.Column("subject_id", sa.Integer(), nullable=False),
        sa.Column("outcome", sa.String(length=16), nullable=False),
        sa.Column("finding_ordinal", sa.Integer(), nullable=True),
        sa.Column("answered_at", sa.DateTime(), nullable=False),
    )
    op.create_index(
        "ux_hunt_answers_hunt_subject",
        "hunt_answers",
        ["hunt_id", "subject_type", "subject_id"],
        unique=True,
    )
    op.create_index("ix_hunt_answers_subject", "hunt_answers", ["subject_type", "subject_id"])


def downgrade() -> None:
    op.drop_index("ix_hunt_answers_subject", table_name="hunt_answers")
    op.drop_index("ux_hunt_answers_hunt_subject", table_name="hunt_answers")
    op.drop_table("hunt_answers")
