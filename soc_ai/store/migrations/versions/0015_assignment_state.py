"""alert_assignments.state: human triage state on an ownership assignment

An assignment now carries a workflow ``state`` alongside its ``owner``:
``owned`` (the default on assign) → ``in_review`` → ``done``. The fourth state,
``unassigned``, is the ABSENCE of a row — so this column is never that value.
Server default ``'owned'`` backfills existing rows (they were all plain owners),
and a fresh assign lands ``owned`` without the caller having to name it.

Revision ID: 0015
Revises: 0014
Create Date: 2026-07-07
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "alert_assignments",
        sa.Column("state", sa.String(16), nullable=False, server_default="owned"),
    )


def downgrade() -> None:
    op.drop_column("alert_assignments", "state")
