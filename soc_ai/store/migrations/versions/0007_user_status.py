"""users.status: editable per-user status string

Revision ID: 0007
Revises: 0006
Create Date: 2026-06-23
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("status", sa.String(64), nullable=False, server_default=""),
    )


def downgrade() -> None:
    op.drop_column("users", "status")
