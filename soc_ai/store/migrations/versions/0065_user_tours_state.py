"""users: the tour state of each user

One column on ``users``. Nothing existing is touched.

The console has a tutorial mode. A welcome tour runs at the first sign-in,
and each page runs its own tour at the first visit. ``tours_state`` keeps,
per user, the global opt-out and the version of each tour the user saw:
``{"off": bool, "seen": {"<tour-id>": <version>}}``. The column lives on the
user row, so the first sign-in holds across browsers.

A row written before this upgrade reads ``{}``: the user saw no tour. The
store reads ``{}`` as tours on and nothing seen.

Revision ID: 0065
Revises: 0064
Create Date: 2026-10-21
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0065"
down_revision = "0064"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("users") as batch:
        batch.add_column(sa.Column("tours_state", sa.Text(), nullable=False, server_default="{}"))


def downgrade() -> None:
    with op.batch_alter_table("users") as batch:
        batch.drop_column("tours_state")
