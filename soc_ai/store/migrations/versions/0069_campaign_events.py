"""campaign events: three columns of ``campaigns`` hold the events of the last grid read

Three ADD COLUMN statements on ``campaigns``. No existing value changes.

A member of a campaign is one investigation of soc-ai. The campaign page
counted the member investigations as the size of the attack, and one arrow
read "33 runs" where the grid held 1,072 alert events between the two
machines. The page now counts events: an event is one record of the grid, and
an alert is an event of a detection rule.

* ``events`` holds the events of the last grid read: the alert events of each
  pair of machines by rule, the records between the two machines, and the
  timeline of the alerts of the confirmed rules.
* ``events_at`` is the time of that read.
* ``events_basis`` is a hash of what the read covered: the pairs, their
  addresses, their confirmed rules and the window. A new basis needs a new
  read.

The detail route reads the grid. A rebuild never reads it, and it leaves the
three columns as they are. NULL means that no grid read stored events. The
page then counts the alert documents that the investigations hold. No
backfill: the grid forgets old records, and a read during the upgrade would
hold up the start of the app.

SQLite ADD COLUMN is metadata-only for a nullable column with no default.

Revision ID: 0069
Revises: 0068
Create Date: 2026-11-14
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0069"
down_revision = "0068"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("campaigns", sa.Column("events", sa.JSON(), nullable=True))
    op.add_column("campaigns", sa.Column("events_at", sa.DateTime(), nullable=True))
    op.add_column("campaigns", sa.Column("events_basis", sa.String(length=64), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("campaigns") as batch:
        batch.drop_column("events_basis")
        batch.drop_column("events_at")
        batch.drop_column("events")
