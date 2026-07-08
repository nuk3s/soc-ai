"""runbook_fts: FTS5 BM25 index over runbooks + the runbook_embedding side table (E4.1)

Two retrieval upgrades for the ``lookup_runbook`` tool land here:

1. ``runbook_fts`` — an **external-content FTS5** virtual table over the existing
   ``runbook`` table (``content='runbook'``), giving :func:`soc_ai.store.runbooks.search`
   a real BM25 ranker instead of the in-process token scorer. Three AFTER
   INSERT/UPDATE/DELETE triggers keep the index in sync with every write path
   (ORM or raw SQL), using the standard FTS5 external-content ``'delete'``
   command pattern; a one-shot backfill indexes the rows that already exist.
   ``runbook.id`` is an ``INTEGER PRIMARY KEY`` (a rowid alias), so it is used
   directly as ``content_rowid`` — unambiguous in triggers, identical to rowid.

2. ``runbook_embedding`` — a plain side table for the OPT-IN semantic tier
   (one float32 vector per runbook, produced by the operator's gateway
   ``/v1/embeddings`` model; see :mod:`soc_ai.rag.runbook_embeddings`). Created
   unconditionally: it's an ordinary table with no FTS dependency, and it stays
   empty until ``rag_embed_model`` is configured.

**FTS5-availability guard:** FTS5 ships in virtually every modern SQLite build,
but it IS a compile-time option — an FTS5-less SQLite raises ``OperationalError:
no such module: fts5`` on the CREATE VIRTUAL TABLE. This migration must never
brick such an install: the FTS block is wrapped so that case completes cleanly
WITHOUT creating the virtual table or triggers, and ``search()`` detects the
missing table at query time and falls back to the legacy in-process scorer.
(Everything else — the embedding table — is still created.)

Revision ID: 0017
Revises: 0016
Create Date: 2026-07-07
"""

from __future__ import annotations

import logging

import sqlalchemy as sa
from alembic import op
from sqlalchemy.exc import OperationalError

revision = "0017"
down_revision = "0016"
branch_labels = None
depends_on = None

_LOGGER = logging.getLogger(__name__)

# Columns are indexed in this order — the bm25() per-column weights in
# soc_ai.store.runbooks address them positionally (title, content, tags).
_CREATE_FTS = """
CREATE VIRTUAL TABLE runbook_fts USING fts5(
    title, content, tags,
    content='runbook', content_rowid='id'
)
"""

# Standard FTS5 external-content sync triggers: an insert indexes the new row;
# a delete issues the special 'delete' command with the OLD values (required —
# external-content FTS5 needs them to remove the index entries); an update is
# delete-old + insert-new.
_CREATE_TRIGGERS = (
    """
    CREATE TRIGGER runbook_fts_ai AFTER INSERT ON runbook BEGIN
        INSERT INTO runbook_fts(rowid, title, content, tags)
        VALUES (new.id, new.title, new.content, new.tags);
    END
    """,
    """
    CREATE TRIGGER runbook_fts_ad AFTER DELETE ON runbook BEGIN
        INSERT INTO runbook_fts(runbook_fts, rowid, title, content, tags)
        VALUES ('delete', old.id, old.title, old.content, old.tags);
    END
    """,
    """
    CREATE TRIGGER runbook_fts_au AFTER UPDATE ON runbook BEGIN
        INSERT INTO runbook_fts(runbook_fts, rowid, title, content, tags)
        VALUES ('delete', old.id, old.title, old.content, old.tags);
        INSERT INTO runbook_fts(rowid, title, content, tags)
        VALUES (new.id, new.title, new.content, new.tags);
    END
    """,
)

_BACKFILL = """
INSERT INTO runbook_fts(rowid, title, content, tags)
SELECT id, title, content, tags FROM runbook
"""


def upgrade() -> None:
    # FTS index + sync triggers — guarded: an FTS5-less SQLite must complete the
    # migration cleanly with nothing FTS created (search() falls back to the
    # legacy scorer at query time). The guard probes the CREATE itself; triggers
    # + backfill only run when it succeeded, so a partial state is impossible.
    try:
        op.execute(sa.text(_CREATE_FTS))
    except OperationalError:
        # "no such module: fts5" — leave this install on the legacy scorer.
        _LOGGER.warning("SQLite lacks FTS5 — skipping runbook_fts (legacy scorer stays)")
    else:
        for ddl in _CREATE_TRIGGERS:
            op.execute(sa.text(ddl))
        op.execute(sa.text(_BACKFILL))

    # Semantic-tier side table (opt-in gateway embeddings). Unconditional: plain
    # table, no FTS dependency. One row per runbook; `model` records WHICH
    # embedding model produced the vector so a model change marks rows stale
    # (skipped at query time, refreshed by the re-embed endpoint). `vector` is
    # float32 little-endian bytes (dim * 4 bytes) — decoded in pure Python.
    op.create_table(
        "runbook_embedding",
        sa.Column(
            "runbook_id",
            sa.Integer(),
            sa.ForeignKey("runbook.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("model", sa.String(128), nullable=False),
        sa.Column("dim", sa.Integer(), nullable=False),
        sa.Column("vector", sa.LargeBinary(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("runbook_embedding")
    # IF EXISTS: the upgrade may have skipped the FTS objects on an FTS5-less
    # SQLite, and DROP TRIGGER/TABLE IF EXISTS is safe either way.
    op.execute(sa.text("DROP TRIGGER IF EXISTS runbook_fts_au"))
    op.execute(sa.text("DROP TRIGGER IF EXISTS runbook_fts_ad"))
    op.execute(sa.text("DROP TRIGGER IF EXISTS runbook_fts_ai"))
    op.execute(sa.text("DROP TABLE IF EXISTS runbook_fts"))
