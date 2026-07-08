"""chat_fts: the chat_memory projection + FTS5 BM25 index over past chat transcripts

Chat-transcript memory ("prior discussion excerpts") needs ONE searchable place
for both chat sources, whose shapes are incompatible:

- investigation follow-up chats — real columns on ``chat_messages``
  (role/content/status), keyed by ``investigation_id``;
- hunt follow-up chats — ``hunt_events`` rows with kind
  ``chat_user``/``chat_assistant`` whose role/content/status live INSIDE the
  JSON ``payload`` (FTS5 external-content tables cannot index a JSON field).

So this migration lands:

1. ``chat_memory`` — a plain projection table (source, thread_id, role,
   content, created_at) holding one row per COMPLETED chat message from either
   source. Created unconditionally (an ordinary table, no FTS dependency).
   Kept in sync at write time by the store layer
   (:func:`soc_ai.store.chat_memory.record_message` — application-level
   dual-write; SQL triggers on the source tables would need JSON extraction
   for the hunt side, and the app-level helper is clearer and testable).
   Delete paths (:func:`soc_ai.store.investigations.delete`,
   :func:`soc_ai.store.hunts.delete`) remove their projection rows.

2. A one-shot **backfill** from both sources, so chats that pre-date this
   migration are searchable immediately. Only ``status='done'`` rows with
   non-empty content matter (a pending/errored turn carries no knowledge).
   The hunt side extracts role/content/status via ``json_extract`` (SQLite
   ≥ 3.38 — well below anything this app runs on). ``hunt_events`` has no
   timestamp column, so the parent hunt's ``created_at`` stands in — close
   enough for the "how long ago" phrase the retrieval renders.

3. ``chat_memory_fts`` — an external-content FTS5 table over
   ``chat_memory.content`` + the standard sync triggers (mirroring migration
   0017's ``runbook_fts``), giving
   :func:`soc_ai.store.chat_memory.relevant_chat_snippets` a real BM25 ranker.
   Triggers fire on the PROJECTION table, so the app-level dual-write above is
   the only sync the store layer owes.

**FTS5-availability guard (same contract as 0017):** an FTS5-less SQLite
raises ``OperationalError: no such module: fts5`` on the CREATE VIRTUAL TABLE.
That case completes cleanly WITHOUT the virtual table or triggers — the
projection table (cheap) still exists and stays in sync, and retrieval detects
the missing index at query time and returns no snippets (memory is advisory
context; there is no legacy scorer to fall back to here).

Revision ID: 0018
Revises: 0017
Create Date: 2026-07-08
"""

from __future__ import annotations

import logging

import sqlalchemy as sa
from alembic import op
from sqlalchemy.exc import OperationalError

revision = "0018"
down_revision = "0017"
branch_labels = None
depends_on = None

_LOGGER = logging.getLogger(__name__)

# Only `content` is indexed — source/thread_id/role/created_at are filter
# columns, applied against the projection table AFTER the BM25 candidate pass.
_CREATE_FTS = """
CREATE VIRTUAL TABLE chat_memory_fts USING fts5(
    content,
    content='chat_memory', content_rowid='id'
)
"""

# Standard FTS5 external-content sync triggers (the 0017 pattern): an insert
# indexes the new row; a delete issues the special 'delete' command with the
# OLD values (required — external-content FTS5 needs them to remove the index
# entries); an update is delete-old + insert-new. The projection is written
# append-only by the store layer, but the update trigger keeps the index
# correct if anything ever mutates a row directly.
_CREATE_TRIGGERS = (
    """
    CREATE TRIGGER chat_memory_fts_ai AFTER INSERT ON chat_memory BEGIN
        INSERT INTO chat_memory_fts(rowid, content)
        VALUES (new.id, new.content);
    END
    """,
    """
    CREATE TRIGGER chat_memory_fts_ad AFTER DELETE ON chat_memory BEGIN
        INSERT INTO chat_memory_fts(chat_memory_fts, rowid, content)
        VALUES ('delete', old.id, old.content);
    END
    """,
    """
    CREATE TRIGGER chat_memory_fts_au AFTER UPDATE ON chat_memory BEGIN
        INSERT INTO chat_memory_fts(chat_memory_fts, rowid, content)
        VALUES ('delete', old.id, old.content);
        INSERT INTO chat_memory_fts(rowid, content)
        VALUES (new.id, new.content);
    END
    """,
)

# Investigation chats: columns map 1:1. Complete turns only — a pending
# assistant row is empty, an errored one is an apology string, neither is
# institutional knowledge.
_BACKFILL_INVESTIGATION_CHATS = """
INSERT INTO chat_memory (source, thread_id, role, content, created_at)
SELECT 'investigation', investigation_id, role, content, created_at
FROM chat_messages
WHERE status = 'done' AND content != ''
"""

# Hunt chats: role/content/status live inside the JSON payload. The event kind
# encodes the role; the hunt's created_at stands in for the (timestamp-less)
# event row. COALESCE guards a NULL json content so the non-empty check can't
# trip on NULL semantics.
_BACKFILL_HUNT_CHATS = """
INSERT INTO chat_memory (source, thread_id, role, content, created_at)
SELECT 'hunt', he.hunt_id,
       CASE he.kind WHEN 'chat_user' THEN 'user' ELSE 'assistant' END,
       json_extract(he.payload, '$.content'),
       COALESCE(h.created_at, CURRENT_TIMESTAMP)
FROM hunt_events AS he
LEFT JOIN hunts AS h ON h.id = he.hunt_id
WHERE he.kind IN ('chat_user', 'chat_assistant')
  AND json_extract(he.payload, '$.status') = 'done'
  AND COALESCE(json_extract(he.payload, '$.content'), '') != ''
"""

_BACKFILL_FTS = """
INSERT INTO chat_memory_fts(rowid, content)
SELECT id, content FROM chat_memory
"""


def upgrade() -> None:
    # Projection table + thread index — unconditional (plain table, no FTS
    # dependency; the index serves the delete-cascade and exclude-thread paths).
    op.create_table(
        "chat_memory",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("source", sa.String(16), nullable=False),
        sa.Column("thread_id", sa.String(32), nullable=False),
        sa.Column("role", sa.String(16), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_chat_memory_thread_id", "chat_memory", ["thread_id"])

    # Backfill BEFORE creating the FTS objects, then index everything in one
    # explicit pass (the 0017 shape) — clearer than relying on the insert
    # trigger to observe the backfill, and identical in outcome.
    op.execute(sa.text(_BACKFILL_INVESTIGATION_CHATS))
    op.execute(sa.text(_BACKFILL_HUNT_CHATS))

    # FTS index + sync triggers — guarded: an FTS5-less SQLite must complete
    # the migration cleanly with nothing FTS created (retrieval returns no
    # snippets at query time). The guard probes the CREATE itself; triggers +
    # backfill only run when it succeeded, so a partial state is impossible.
    try:
        op.execute(sa.text(_CREATE_FTS))
    except OperationalError:
        # "no such module: fts5" — this install keeps the projection only.
        _LOGGER.warning("SQLite lacks FTS5 — skipping chat_memory_fts (chat memory disabled)")
    else:
        for ddl in _CREATE_TRIGGERS:
            op.execute(sa.text(ddl))
        op.execute(sa.text(_BACKFILL_FTS))


def downgrade() -> None:
    # IF EXISTS: the upgrade may have skipped the FTS objects on an FTS5-less
    # SQLite, and DROP TRIGGER/TABLE IF EXISTS is safe either way.
    op.execute(sa.text("DROP TRIGGER IF EXISTS chat_memory_fts_au"))
    op.execute(sa.text("DROP TRIGGER IF EXISTS chat_memory_fts_ad"))
    op.execute(sa.text("DROP TRIGGER IF EXISTS chat_memory_fts_ai"))
    op.execute(sa.text("DROP TABLE IF EXISTS chat_memory_fts"))
    op.drop_index("ix_chat_memory_thread_id", table_name="chat_memory")
    op.drop_table("chat_memory")
