"""saved_view table — one analyst's named filter sets for the list screens

A pure CREATE TABLE; nothing existing is touched.

The alternative was ``localStorage``, which needs no migration at all. The owner
ruled against it: a saved view that lives in one browser profile is a view the
analyst loses every time they move to the other workstation, and half the point
of naming a filter set is that it is waiting for you when you get there. So the
views are rows, and they are scoped by ``user_id`` — every read and every delete
carries that predicate, which is what makes another analyst's view invisible
rather than merely forbidden.

``query_json`` is deliberately opaque. The four list screens disagree about what
a filter is — a verdict multi-select, a host role string, a deep-linked OQL
clause — and a column per facet would drag a migration behind every new control
on any of them. The screen that writes a view is the screen that reads it.

``uq_saved_view_name`` over ``(user_id, screen, name)`` makes re-saving a name an
update rather than a duplicate chip; ``ix_saved_view_user_screen`` serves the one
query the API makes (this user's views, optionally for one screen).

Revision ID: 0030
Revises: 0029
Create Date: 2026-08-12
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0030"
down_revision = "0029"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "saved_view",
        sa.Column("id", sa.Integer(), primary_key=True),
        # CASCADE: a filter set has no meaning without the analyst who named it,
        # and PRAGMA foreign_keys is ON for every connection (store/db.py), so
        # this actually fires rather than leaving orphans.
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("screen", sa.String(32), nullable=False),
        sa.Column("name", sa.String(64), nullable=False),
        sa.Column("query_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("user_id", "screen", "name", name="uq_saved_view_name"),
    )
    op.create_index("ix_saved_view_user_screen", "saved_view", ["user_id", "screen"])


def downgrade() -> None:
    op.drop_index("ix_saved_view_user_screen", table_name="saved_view")
    op.drop_table("saved_view")
