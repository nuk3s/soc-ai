"""general_chat_messages table: the dashboard's rolling per-analyst chat thread

A pure CREATE TABLE. Nothing existing is altered, which is the whole design
decision worth recording here.

**Why a new table instead of making ``chat_messages.investigation_id``
nullable.** That column is ``NOT NULL`` *with a foreign key*, and SQLite cannot
alter a column's nullability or drop a constraint in place — Alembic emulates it
by rebuilding the table (``batch_alter_table``: create shadow, copy every row,
drop, rename). That is a full rebuild of live analyst chat history, on a
customer's box, at upgrade time, to gain nothing the new table does not give.
It would also leave ``chat_messages`` with two columns whose meanings depend on
each other — ``investigation_id`` NULL implies "read ``thread_key`` instead" —
so every existing query, the delete-cascade, and the ``chat_memory`` projection
(whose ``thread_id`` is NOT NULL) would each need a null-safety review. Keeping
the tables apart avoids all of that by construction.

The column set is deliberately ``chat_messages`` minus ``investigation_id`` plus
``thread_key``, so both tables serialize through the same API shape.

A generic ``chat_threads`` parent is the right eventual target, but it only pays
off if it also absorbs hunt chat (today: ``hunt_events`` JSON rows), which is a
refactor project — not a prerequisite for shipping this.

Revision ID: 0025
Revises: 0024
Create Date: 2026-08-06
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0025"
down_revision = "0024"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "general_chat_messages",
        sa.Column("id", sa.Integer(), primary_key=True),
        # The caller string from identify_caller ("alice", "token:ci",
        # "anonymous") — one rolling thread per analyst. No FK: the thread must
        # survive the account being renamed or removed, and an actor string is
        # not a row anywhere.
        sa.Column("thread_key", sa.String(64), nullable=False),
        sa.Column("role", sa.String(16), nullable=False),
        sa.Column("content", sa.Text(), nullable=False, server_default=""),
        sa.Column("status", sa.String(16), nullable=False, server_default="done"),
        sa.Column("meta", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    # Every read is thread-scoped (list, history, trim), so this index carries
    # all of them.
    op.create_index(
        "ix_general_chat_messages_thread_key",
        "general_chat_messages",
        ["thread_key"],
    )


def downgrade() -> None:
    op.drop_index("ix_general_chat_messages_thread_key", table_name="general_chat_messages")
    op.drop_table("general_chat_messages")
