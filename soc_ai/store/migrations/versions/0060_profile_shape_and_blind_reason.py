"""A profile row records its shape version. A prior run records why it was blind.

``entity_profiles.shape_version`` is the version of the stored profile shape
that the build wrote. The code holds the current version as
``soc_ai.dossier.profile.PROFILE_SHAPE``. A row with no version was built
before the column existed. soc-ai reads it as shape 1. When no host row holds
the current shape, a profile build is due at once. The profile build also
rebuilds each host whose rows hold an older shape, whatever their age. Before
this column, a release that changed the stored shape left the analytics that
read the new shape blind until the next daily build.

``prior_spec_runs.blind_reason`` is the reason the prior sweep gave for the
blind entities of one analytic, when they share one reason. When they do not,
it holds the reason of the most entities and their count. The Analytics API
and the analytic ledger show it beside the blind count.

Both columns are nullable with no default. A row written before this upgrade
has none.

Revision ID: 0060
Revises: 0059
Create Date: 2026-10-05
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0060"
down_revision = "0059"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("entity_profiles", sa.Column("shape_version", sa.Integer(), nullable=True))
    op.add_column("prior_spec_runs", sa.Column("blind_reason", sa.String(255), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("prior_spec_runs") as batch:
        batch.drop_column("blind_reason")
    with op.batch_alter_table("entity_profiles") as batch:
        batch.drop_column("shape_version")
