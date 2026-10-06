"""An observation carries the statistic, the documents and a query to re-run.

A profile observation kept its numbers in the summary sentence. The lead
hunt read them as prose, and the hunt sent to confirm a departure searched
the grid for it again. An observation now records:

* ``statistic``: the name of the statistic that departed, for example
  ``residual_z`` or ``estate_hosts``;
* ``statistic_value``: its value;
* ``baseline_value``: the value of the baseline it departed from;
* ``document_ids``: up to 10 document ids the observation cites;
* ``rerun_query``: an OQL query the agent can run again.

Every column is nullable with no default. A row written before this upgrade
has none of them, and the readers state that the row carries no statistic.

The table ``member_prevalence`` holds how many hosts in the estate hold each
member of each set dimension. Novelty fired on first sight against a host's
own set, and a member that forty hosts held weighed the same as a member no
host held. The prior sweep fills the table from the stored host profiles
after each build. It starts empty, and the first sweep after the upgrade
fills it.

Revision ID: 0057
Revises: 0056
Create Date: 2026-10-04
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0057"
down_revision = "0056"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("entity_observations", sa.Column("statistic", sa.String(32), nullable=True))
    op.add_column("entity_observations", sa.Column("statistic_value", sa.Float(), nullable=True))
    op.add_column("entity_observations", sa.Column("baseline_value", sa.Float(), nullable=True))
    op.add_column(
        "entity_observations",
        sa.Column("document_ids", sa.JSON(none_as_null=True), nullable=True),
    )
    op.add_column("entity_observations", sa.Column("rerun_query", sa.Text(), nullable=True))
    op.create_table(
        "member_prevalence",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("dimension", sa.String(64), nullable=False),
        sa.Column("member", sa.String(255), nullable=False),
        sa.Column("hosts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("built_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("dimension", "member", name="uq_member_prevalence_member"),
    )


def downgrade() -> None:
    op.drop_table("member_prevalence")
    with op.batch_alter_table("entity_observations") as batch:
        batch.drop_column("rerun_query")
        batch.drop_column("document_ids")
        batch.drop_column("baseline_value")
        batch.drop_column("statistic_value")
        batch.drop_column("statistic")
