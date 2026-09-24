"""A trail for the prior sweep, so Operate can show coverage instead of nothing.

The catalog sweep writes hunt_spec_sweeps on every run. The prior sweep wrote
nothing, so the twelve profile specs on the Operate panel could only say "not
swept here" while the shadow log printed blind=285 and "could not be scored
against any entity" in a single line. The log was more honest than the product.

Revision ID: 0045
Revises: 0044
Create Date: 2026-09-16
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0045"
down_revision = "0044"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "prior_spec_runs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column("spec_id", sa.String(80), nullable=False),
        sa.Column("shadow", sa.Boolean(), nullable=False, server_default="1"),
        sa.Column("measured", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("learning", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("blind", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("not_applicable", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("fired", sa.Integer(), nullable=False, server_default="0"),
    )
    op.create_index("ix_prior_spec_runs_spec_created", "prior_spec_runs", ["spec_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_prior_spec_runs_spec_created", table_name="prior_spec_runs")
    op.drop_table("prior_spec_runs")
