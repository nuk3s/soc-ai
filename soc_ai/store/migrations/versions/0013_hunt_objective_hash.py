"""hunts.objective_hash: content hash of the normalized objective for re-run diffing

A hunt re-run of the same objective links to its prior run via a stable hash of
the NORMALIZED objective (lowercase, whitespace-collapsed). Nullable + no server
default: existing rows stay NULL (they simply won't diff); the value is computed
on write in :func:`soc_ai.store.hunts.create`.

Revision ID: 0013
Revises: 0012
Create Date: 2026-07-07
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "hunts",
        sa.Column("objective_hash", sa.String(64), nullable=True),
    )
    op.create_index("ix_hunts_objective_hash", "hunts", ["objective_hash"])


def downgrade() -> None:
    op.drop_index("ix_hunts_objective_hash", table_name="hunts")
    op.drop_column("hunts", "objective_hash")
