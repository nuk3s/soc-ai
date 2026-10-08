"""dashboard_layout table: one user's arrangement of the Dashboard panels

A pure CREATE TABLE; nothing existing is touched.

The console draws the Dashboard on a grid of 12 columns, and an operator can
move and resize its panels. The arrangement belongs to a person, so it is a
row per user, keyed by ``user_id``, the way a saved view is. A layout kept in
``localStorage`` would stay behind in one browser profile. The console still
uses ``localStorage`` when authentication is off, because then no user row
exists to own a layout.

``panels_json`` is a list of slots, ``{id, x, y, w, h}``. The store checks the
panel ids and the grid bounds on write and drops what the console cannot place
on read, so a panel that a later release removes does not break an old row.

No row means the shipped layout, so Reset layout is a DELETE.

Revision ID: 0061
Revises: 0060
Create Date: 2026-10-06
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0061"
down_revision = "0060"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "dashboard_layout",
        # CASCADE: a layout has no meaning without its user, and PRAGMA
        # foreign_keys is ON for every connection (store/db.py).
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("panels_json", sa.JSON(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("dashboard_layout")
