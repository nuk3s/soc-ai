"""Copy every table of one store into another store, in foreign key order.

``soc-ai store migrate --to <url>`` uses this to move a SQLite store to
PostgreSQL. The copy works in either direction between the two dialects.

The steps:

1. The source must be at the migration head of this build. soc-ai migrates a
   store at start, so a source behind the head has not run on this build yet.
2. The target must be empty. The copy brings it to head with the same chain
   the app runs, then writes every table in one transaction. A failure rolls
   the rows back and leaves an empty store at head, so a second run can start
   again.
3. Checks on the source come first. A PostgreSQL target refuses a text value
   longer than its column, a text value with a NUL character, an integer
   outside 32 bits and a row whose parent is missing. SQLite accepts all four.
   The copy counts each one and refuses before it writes a row.
4. Every table is counted on both sides after the copy. The result reports
   the counts that the target holds, so a short copy cannot pass as complete.

JSON columns move as their stored text. A Python round trip would turn a JSON
``null`` into SQL NULL, or the reverse, depending on the column type.
Integer primary keys keep their values, and each PostgreSQL sequence moves
past the highest copied key.

A dry run reads both stores and writes nothing.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import (
    JSON,
    Integer,
    String,
    Table,
    Text,
    bindparam,
    case,
    cast,
    func,
    insert,
    inspect,
    or_,
    select,
    text,
    type_coerce,
)
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from soc_ai.store import db as store_db
from soc_ai.store.models import Base

# PostgreSQL INTEGER is 32 bits. SQLite INTEGER is 64 bits.
_INT32_MAX = 2_147_483_647
_INT32_MIN = -2_147_483_648


class StoreCopyRefused(RuntimeError):
    """The copy would not be faithful, or the stores are not in a state to copy."""


@dataclass
class TableCount:
    name: str
    source_rows: int
    target_rows: int | None = None


@dataclass
class SourceProblem:
    """A count of source values that the target cannot hold."""

    table: str
    column: str
    problem: str
    rows: int


@dataclass
class CopyResult:
    source_head: str | None
    target_head: str | None
    dry_run: bool
    tables: list[TableCount] = field(default_factory=list)
    problems: list[SourceProblem] = field(default_factory=list)

    @property
    def source_rows(self) -> int:
        return sum(t.source_rows for t in self.tables)

    @property
    def target_rows(self) -> int:
        return sum(t.target_rows or 0 for t in self.tables)


def _tables() -> Sequence[Table]:
    # sorted_tables puts every parent before its children.
    return Base.metadata.sorted_tables


async def _revision(conn: AsyncConnection) -> str | None:
    tables = await conn.run_sync(lambda c: set(inspect(c).get_table_names()))
    if "alembic_version" not in tables:
        return None
    return await conn.run_sync(store_db._current_revision)


async def _counts(conn: AsyncConnection, *, missing_ok: bool) -> dict[str, int]:
    present = await conn.run_sync(lambda c: set(inspect(c).get_table_names()))
    out: dict[str, int] = {}
    for table in _tables():
        if table.name not in present:
            if not missing_ok:
                raise StoreCopyRefused(f"The store has no table {table.name}.")
            out[table.name] = 0
            continue
        out[table.name] = int(await conn.scalar(select(func.count()).select_from(table)) or 0)
    return out


def _checks(table: Table) -> list[tuple[str, str, Any]]:
    """``(column, problem, condition)`` for each value a PostgreSQL column refuses."""
    checks: list[tuple[str, str, Any]] = []
    for col in table.columns:
        kind = col.type
        if isinstance(kind, JSON):
            continue  # json.dumps escapes a NUL, and PostgreSQL json takes the escape
        if isinstance(kind, String):
            # Text is a String without a length. PostgreSQL text holds no NUL.
            checks.append((col.name, "a NUL character", func.instr(col, func.char(0)) > 0))
            if kind.length is not None:
                checks.append(
                    (
                        col.name,
                        f"text longer than {kind.length} characters",
                        func.length(col) > kind.length,
                    )
                )
        elif isinstance(kind, Integer):
            checks.append(
                (col.name, "an integer outside 32 bits", or_(col > _INT32_MAX, col < _INT32_MIN))
            )
    return checks


async def _source_problems(conn: AsyncConnection) -> list[SourceProblem]:
    """What a PostgreSQL target refuses that a SQLite source holds.

    One scan per table: every check of the table is a SUM in one SELECT.
    """
    problems: list[SourceProblem] = []
    for table in _tables():
        checks = _checks(table)
        if not checks:
            continue
        sums = [func.coalesce(func.sum(case((cond, 1), else_=0)), 0) for _c, _p, cond in checks]
        row = (await conn.execute(select(*sums).select_from(table))).one()
        for (column, problem, _cond), rows in zip(checks, row, strict=True):
            if rows:
                problems.append(SourceProblem(table.name, column, problem, int(rows)))
    orphans = (await conn.exec_driver_sql("PRAGMA foreign_key_check")).all()
    by_table: dict[str, int] = {}
    for row in orphans:
        by_table[str(row[0])] = by_table.get(str(row[0]), 0) + 1
    for name, rows in sorted(by_table.items()):
        problems.append(SourceProblem(name, "", "a reference to a missing parent row", rows))
    return problems


def _select_raw(table: Table) -> Any:
    """Every column of ``table``, with each JSON column as its stored text."""
    columns = [
        type_coerce(col, Text).label(col.name) if isinstance(col.type, JSON) else col
        for col in table.columns
    ]
    return select(*columns).order_by(*table.primary_key.columns)


# SQLAlchemy reserves a column's own name for the automatic VALUES bind, so the
# JSON text binds under a name of its own.
_JSON_BIND = "{}__json_text"


def _json_columns(table: Table) -> list[str]:
    return [col.name for col in table.columns if isinstance(col.type, JSON)]


def _insert_raw(table: Table, dialect: str) -> Any:
    """An INSERT that writes each JSON column from its stored text.

    PostgreSQL casts the text to ``json``. SQLite stores the text as it is,
    because a CAST to the type name JSON there applies numeric affinity.
    """
    values: dict[str, Any] = {}
    for name in _json_columns(table):
        param = bindparam(_JSON_BIND.format(name), type_=Text)
        values[name] = cast(param, JSON) if dialect == "postgresql" else param
    return insert(table).values(values) if values else insert(table)


async def _copy_table(
    source: AsyncConnection, target: AsyncConnection, table: Table, batch_size: int
) -> None:
    stmt = _insert_raw(table, target.dialect.name)
    json_columns = _json_columns(table)
    result = await source.stream(_select_raw(table))
    async for batch in result.mappings().partitions(batch_size):
        rows = []
        for row in batch:
            values = dict(row)
            for name in json_columns:
                values[_JSON_BIND.format(name)] = values.pop(name)
            rows.append(values)
        await target.execute(stmt, rows)


async def _reset_sequences(target: AsyncConnection) -> None:
    """Move each PostgreSQL sequence past the highest key the copy wrote."""
    quote = target.dialect.identifier_preparer.quote
    for table in _tables():
        pks = list(table.primary_key.columns)
        if len(pks) != 1 or not isinstance(pks[0].type, Integer):
            continue
        sequence = await target.scalar(
            text("SELECT pg_get_serial_sequence(:table, :column)"),
            {"table": table.name, "column": pks[0].name},
        )
        if sequence is None:
            continue
        # The names come from the model and pass through the dialect's quoting.
        top = f"SELECT COALESCE(MAX({quote(pks[0].name)}), 0) + 1 FROM {quote(table.name)}"  # noqa: S608
        await target.execute(
            text(f"SELECT setval(CAST(:sequence AS regclass), ({top}), false)"),
            {"sequence": sequence},
        )


async def copy_store(
    source: AsyncEngine,
    target: AsyncEngine,
    *,
    dry_run: bool = False,
    batch_size: int = 1000,
) -> CopyResult:
    """Copy every table of ``source`` into the empty ``target``.

    Raises :class:`StoreCopyRefused` before it writes a row when the copy
    would not be faithful. A dry run reads both stores and writes nothing.
    """
    if source.url == target.url:
        raise StoreCopyRefused("The source and the target are the same store.")
    head = store_db._script_head()
    async with source.connect() as src:
        source_head = await _revision(src)
        if source_head != head:
            raise StoreCopyRefused(
                f"The source store is at migration {source_head or 'none'}. This build "
                f"expects {head}. Start soc-ai once on the source store, then copy again."
            )
        source_counts = await _counts(src, missing_ok=False)
        problems = (
            await _source_problems(src)
            if src.dialect.name == "sqlite" and target.dialect.name != "sqlite"
            else []
        )
    async with target.connect() as dst:
        target_head = await _revision(dst)
        target_counts = await _counts(dst, missing_ok=True)
    result = CopyResult(
        source_head=source_head,
        target_head=target_head,
        dry_run=dry_run,
        tables=[TableCount(name, rows) for name, rows in source_counts.items()],
        problems=problems,
    )
    occupied = sorted(name for name, rows in target_counts.items() if rows)
    if occupied:
        raise StoreCopyRefused(
            f"The target store holds rows in {', '.join(occupied)}. soc-ai copies into "
            "an empty store only. Create a new, empty database, then copy again."
        )
    if target_head not in (None, head):
        raise StoreCopyRefused(
            f"The target store is at migration {target_head}. This build expects {head}."
        )
    if dry_run:
        return result
    if problems:
        raise StoreCopyRefused(
            f"The source holds {sum(p.rows for p in problems)} value(s) that the target "
            "cannot hold. Run the copy with --dry-run to list them."
        )

    await store_db.run_migrations(target)
    async with source.connect() as src, target.connect() as dst:
        # One read transaction on the source gives one consistent snapshot.
        await src.begin()
        async with dst.begin():
            for table in _tables():
                await _copy_table(src, dst, table, batch_size)
            if dst.dialect.name == "postgresql":
                await _reset_sequences(dst)
            copied = await _counts(dst, missing_ok=False)
            short = [name for name, rows in source_counts.items() if copied.get(name, 0) != rows]
            if short:
                raise StoreCopyRefused(
                    f"The target count differs from the source in {', '.join(short)}. "
                    "soc-ai rolled the copy back."
                )
        await src.rollback()
    result.target_head = head
    for entry in result.tables:
        entry.target_rows = copied[entry.name]
    return result
