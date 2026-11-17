"""the campaign of a lead and of a hunt

Two ADD COLUMN, each with one index: ``leads.campaign_id`` and
``hunts.campaign_id``. Both are Integer and nullable, with no foreign key,
like ``campaign_members.run_id``.

The owner, 2026-11-16: one test caused 6 leads, 20 hunts and 48 finding
investigations beside its campaign. The leads and the lead hunts of a
campaign fold into the campaign.

``leads.campaign_id`` names the campaign that holds every live observation of
the lead. The step after a rebuild sets it and removes it
(:mod:`soc_ai.campaigns.lead_tags`). ``hunts.campaign_id`` names the campaign
that a hunt is for: a lead hunt of such a lead, a hunt that the campaign
started (starter ``campaign``), and a hunt whose finding investigations one
campaign holds. The limit of one hunt for one campaign in 24 hours reads it.

No fill: no row belongs to a campaign before the first step after a rebuild.

SQLite ADD COLUMN is metadata-only for a nullable column with no default.

Revision ID: 0073
Revises: 0072
Create Date: 2026-11-16
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0073"
down_revision = "0072"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("leads", sa.Column("campaign_id", sa.Integer(), nullable=True))
    op.create_index("ix_leads_campaign_id", "leads", ["campaign_id"])
    op.add_column("hunts", sa.Column("campaign_id", sa.Integer(), nullable=True))
    op.create_index("ix_hunts_campaign_id", "hunts", ["campaign_id"])


def downgrade() -> None:
    op.drop_index("ix_hunts_campaign_id", table_name="hunts")
    op.drop_column("hunts", "campaign_id")
    op.drop_index("ix_leads_campaign_id", table_name="leads")
    op.drop_column("leads", "campaign_id")
