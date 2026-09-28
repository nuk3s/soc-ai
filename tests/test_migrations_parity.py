"""The ORM metadata and the migration chain describe the same schema.

Every model change ships with a revision and every revision is mirrored in
``models.py``; the ORM is what the app queries through and the chain is what
the store actually holds, and the two drift silently until a query hits a
column that exists on one side only, or ``alembic revision --autogenerate``
proposes dropping an index it cannot see in the model. Until now only three
tables were compared, by column name. This compares every table, including
types, indexes, uniques and foreign keys.

The FTS5 tables are the one intended difference: 0017 / 0018 create them with
raw DDL (with their shadow tables) and no model declares them, since SQLAlchemy
has no virtual-table construct and the app reads them through raw SQL.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from soc_ai.config import Settings
from soc_ai.store.db import _migration_config, make_engine, run_migrations
from soc_ai.store.models import Base
from sqlalchemy import Connection

_FTS_TABLES = ("runbook_fts", "chat_memory_fts")


def _schema_diffs(connection: Connection) -> list[Any]:
    ctx = MigrationContext.configure(
        connection, opts={"render_as_batch": True, "compare_type": True}
    )
    flat: list[Any] = []
    for diff in compare_metadata(ctx, Base.metadata):
        # A modify_* entry arrives as a list of tuples; everything else is a tuple.
        flat.extend(diff if isinstance(diff, list) else [diff])
    return [
        d for d in flat if not (d[0] == "remove_table" and str(d[1].name).startswith(_FTS_TABLES))
    ]


async def test_models_match_migrated_schema(settings_kratos: Settings) -> None:
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    async with engine.connect() as conn:
        diffs = await conn.run_sync(_schema_diffs)
    await engine.dispose()
    assert diffs == [], "\n".join(str(d) for d in diffs)


def test_chain_has_one_head_and_each_file_is_named_after_its_revision() -> None:
    script = ScriptDirectory.from_config(_migration_config())
    assert len(script.get_heads()) == 1
    for rev in script.walk_revisions():
        assert Path(rev.path).name.startswith(f"{rev.revision}_"), rev.path


def test_version_headers_match_code() -> None:
    """The ``Revision ID`` / ``Revises`` lines are what a reader traces the chain by."""
    mismatched: list[tuple[str, str, str]] = []
    for rev in ScriptDirectory.from_config(_migration_config()).walk_revisions():
        src = Path(rev.path).read_text(encoding="utf-8")
        # [ \t]* rather than \s*: 0001 has a bare "Revises:" line and \s* would
        # run over the newline and capture the first word of the next line.
        head = re.search(r"^Revision ID:[ \t]*(\S*)$", src, re.M)
        parent = re.search(r"^Revises:[ \t]*(\S*)$", src, re.M)
        assert head is not None and parent is not None, rev.path
        if head.group(1) != rev.revision or parent.group(1) != (rev.down_revision or ""):
            mismatched.append((rev.revision, head.group(1), parent.group(1)))
    assert mismatched == []
