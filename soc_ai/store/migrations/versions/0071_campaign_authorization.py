"""campaign authorization: an authorization on a campaign, and the overrides of an analyst

Two ADD COLUMN statements on ``authorized_activity``, one index and one new
table, ``campaign_run_overrides``. No existing value changes.

An authorization can name a campaign. Such a record lists machines and no
rules:

* ``campaign_id`` is the campaign that the record covers, or null for a
  record of the rule-list form. The index serves the campaign page.
* ``parties`` is null for a record of the rule-list form. A campaign record
  holds the listed machines of the campaign:
  ``[{"machine_key", "role", "name", "addresses"}]``. ``role`` is ``actor``
  or ``target``. A campaign record stores ``rule_names`` as ``[]``, and
  ``target_address`` and ``rule_class`` as empty text.

``campaign_run_overrides`` holds one row for each investigation that an
analyst excluded from a campaign or included in one. ``type`` is
``excluded`` or ``included``. ``campaign_id`` is the campaign at that time,
and ``anchor_run_id`` is the seed of that campaign for an inclusion. The
unique index on ``run_id`` keeps one override for each investigation. A
rebuild reads the table and gives both lists to the engine.

No backfill. A record of the rule-list form keeps its scope and its marks.

SQLite ADD COLUMN is metadata-only for a nullable column with no default.

Revision ID: 0071
Revises: 0070
Create Date: 2026-11-15
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0071"
down_revision = "0070"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("authorized_activity", sa.Column("campaign_id", sa.Integer(), nullable=True))
    op.add_column("authorized_activity", sa.Column("parties", sa.JSON(), nullable=True))
    op.create_index("ix_authorized_activity_campaign", "authorized_activity", ["campaign_id"])
    op.create_table(
        "campaign_run_overrides",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("run_id", sa.String(length=32), nullable=False),
        sa.Column("type", sa.String(length=16), nullable=False),
        sa.Column("campaign_id", sa.Integer(), nullable=False),
        sa.Column("anchor_run_id", sa.String(length=32), nullable=True),
        sa.Column("by", sa.String(length=128), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index(
        "ux_campaign_run_overrides_run", "campaign_run_overrides", ["run_id"], unique=True
    )
    op.create_index("ix_campaign_run_overrides_campaign", "campaign_run_overrides", ["campaign_id"])


def downgrade() -> None:
    op.drop_index("ix_campaign_run_overrides_campaign", table_name="campaign_run_overrides")
    op.drop_index("ux_campaign_run_overrides_run", table_name="campaign_run_overrides")
    op.drop_table("campaign_run_overrides")
    op.drop_index("ix_authorized_activity_campaign", table_name="authorized_activity")
    with op.batch_alter_table("authorized_activity") as batch:
        batch.drop_column("parties")
        batch.drop_column("campaign_id")
