"""Observations from every source, and shadow leads.

The observations table held profile departures only. A catalog hit was a hunt
row and a triaged alert was an alert. Three tables cannot form one lead. Two
columns say where an observation came from and whether the analytic that wrote
it is live. One column on leads marks a lead that one repeated kind formed.

Revision ID: 0046
Revises: 0045
Create Date: 2026-09-18
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0046"
down_revision = "0045"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("entity_observations") as batch:
        batch.add_column(
            sa.Column("source", sa.String(16), nullable=False, server_default="profile")
        )
        batch.add_column(sa.Column("shadow", sa.Boolean(), nullable=False, server_default="0"))
    with op.batch_alter_table("leads") as batch:
        batch.add_column(
            sa.Column("single_signal", sa.Boolean(), nullable=False, server_default="0")
        )


def downgrade() -> None:
    with op.batch_alter_table("leads") as batch:
        batch.drop_column("single_signal")
    with op.batch_alter_table("entity_observations") as batch:
        batch.drop_column("shadow")
        batch.drop_column("source")
