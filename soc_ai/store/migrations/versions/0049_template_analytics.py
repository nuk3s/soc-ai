"""A hunt template names the analytics to run first.

analytics_json holds the analytic ids a starter runs before the investigation.
The start path renders them into the objective, so the hunt agent runs them
with t_run_analytic before it writes its own query.

Revision ID: 0049
Revises: 0048
Create Date: 2026-09-18
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0049"
down_revision = "0048"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("hunt_templates") as batch:
        batch.add_column(sa.Column("analytics_json", sa.JSON(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("hunt_templates") as batch:
        batch.drop_column("analytics_json")
