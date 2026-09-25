"""Why a dimension could not be measured, and how fresh the baselines were.

``entity_profiles.coverage_reason`` carries the Elasticsearch reason when a
dimension ends in ``unmeasurable``. Without it the two shaped dimensions on a
700M-document grid failed with a 400, wrote no row, and every surface read
"blind" for 215 hosts with no way to say why.

``prior_spec_runs.profiles_*`` records what the prior sweep knew about its
baselines when it ran: when the newest was built, whether the sweep judged
them stale, and the reason when a dimension could not be measured. The
Analytics panel reads them next to the coverage counts, which otherwise imply
the state of the grid now.

Revision ID: 0051
Revises: 0050
Create Date: 2026-09-25
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0051"
down_revision = "0050"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("entity_profiles") as batch:
        batch.add_column(sa.Column("coverage_reason", sa.String(255), nullable=True))
    with op.batch_alter_table("prior_spec_runs") as batch:
        batch.add_column(sa.Column("profiles_built_at", sa.DateTime(), nullable=True))
        batch.add_column(
            sa.Column("profiles_stale", sa.Boolean(), nullable=False, server_default="0")
        )
        batch.add_column(sa.Column("profiles_reason", sa.String(255), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("prior_spec_runs") as batch:
        batch.drop_column("profiles_reason")
        batch.drop_column("profiles_stale")
        batch.drop_column("profiles_built_at")
    with op.batch_alter_table("entity_profiles") as batch:
        batch.drop_column("coverage_reason")
