"""The local analytics tier, the version trail, sweep cost, and read marks.

analytic_state holds every analytic that is not shipped and live: a local
analytic with its spec text and status, or a shipped analytic that an analyst
retired. analytic_versions holds every transition with the spec text before and
after. duration_ms on the sweep trail is the cost half of the ledger. read_at
on an observation marks a shadow hit that an analyst opened.

Revision ID: 0048
Revises: 0047
Create Date: 2026-09-18
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0048"
down_revision = "0047"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "analytic_state",
        sa.Column("analytic_id", sa.String(64), primary_key=True),
        # shipped | local
        sa.Column("tier", sa.String(8), nullable=False),
        # candidate | shadow | live | retired
        sa.Column("status", sa.String(16), nullable=False),
        # Local analytics only. A shipped analytic keeps its file on disk.
        sa.Column("spec_text", sa.Text(), nullable=True),
        sa.Column("created_by", sa.String(80), nullable=False, server_default="analyst"),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        # The reason of the latest transition.
        sa.Column("reason", sa.Text(), nullable=True),
    )
    op.create_table(
        "analytic_versions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("analytic_id", sa.String(64), nullable=False),
        sa.Column("from_status", sa.String(16), nullable=True),
        sa.Column("to_status", sa.String(16), nullable=False),
        sa.Column("who", sa.String(80), nullable=False),
        sa.Column("at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column("why", sa.Text(), nullable=True),
        sa.Column("spec_before", sa.Text(), nullable=True),
        sa.Column("spec_after", sa.Text(), nullable=True),
        # The receipts an analyst read before an approval to live.
        sa.Column("receipts_json", sa.JSON(), nullable=True),
    )
    op.create_index("ix_analytic_versions_analytic", "analytic_versions", ["analytic_id", "at"])
    with op.batch_alter_table("hunt_spec_sweeps") as batch:
        batch.add_column(sa.Column("duration_ms", sa.Integer(), nullable=False, server_default="0"))
    with op.batch_alter_table("entity_observations") as batch:
        batch.add_column(sa.Column("read_at", sa.DateTime(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("entity_observations") as batch:
        batch.drop_column("read_at")
    with op.batch_alter_table("hunt_spec_sweeps") as batch:
        batch.drop_column("duration_ms")
    op.drop_index("ix_analytic_versions_analytic", table_name="analytic_versions")
    op.drop_table("analytic_versions")
    op.drop_table("analytic_state")
