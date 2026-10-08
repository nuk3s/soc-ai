"""hunts: the investigations a hunt opens for its findings

Three columns on ``hunts``. Nothing existing is touched.

The owner's decision of 2026-10-07: a hunt investigates its subject findings
as part of the hunt. While the investigations run the hunt reads
``investigating``, and it reads ``complete`` when the last one ends.

* ``findings_total``: how many findings of the report are subjects.
* ``findings_investigated``: how many of those have an ended investigation.
  A failed investigation counts as ended.
* ``finding_investigations``: one entry per subject finding, keyed by its
  ordinal. Each entry names the investigation and its state on the hunt:
  queued, investigating, ended, over the cap, failed or cancelled. A reused
  investigation of another hunt is named here, because its own row names
  the other hunt.

A row written before this upgrade reads 0 and 0 and NULL. It investigated
nothing by itself, which is the truth.

Revision ID: 0063
Revises: 0062
Create Date: 2026-10-07
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0063"
down_revision = "0062"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("hunts") as batch:
        batch.add_column(
            sa.Column("findings_total", sa.Integer(), nullable=False, server_default="0")
        )
        batch.add_column(
            sa.Column("findings_investigated", sa.Integer(), nullable=False, server_default="0")
        )
        batch.add_column(sa.Column("finding_investigations", sa.JSON(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("hunts") as batch:
        batch.drop_column("finding_investigations")
        batch.drop_column("findings_investigated")
        batch.drop_column("findings_total")
