"""An investigation records what it investigated.

subject_json holds the subject of the run. An alert run leaves it NULL: the
alert is named by alert_es_id and the run reads one document. A hunt run holds
the hunt id, the objective, the finding ordinals, the lead id, the cited
document ids and the lead's observation ids, so the page can say what the run
was about and the pipeline can rebuild the context.

Revision ID: 0050
Revises: 0049
Create Date: 2026-09-22
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0050"
down_revision = "0049"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("investigations") as batch:
        batch.add_column(sa.Column("subject_json", sa.JSON(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("investigations") as batch:
        batch.drop_column("subject_json")
