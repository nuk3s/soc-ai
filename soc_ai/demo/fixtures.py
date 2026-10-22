"""Load the demo fixture set and seed it into the store.

Schema (version 2), built by ``scripts/demo/build_story.py``:

* ``anchor``: the instant the file's timestamps are written against. Every
  ISO-8601 datetime string in the file, at any depth, moves by
  ``now - anchor`` when the demo starts (:func:`rebase_document`). The anchor
  lands at the seed instant, so "the last 24 hours" holds data on every boot,
  and the gaps between rows in different sections stay as written. The mock
  grid (``scripts/demo/mock_es.py``) moves its documents the same way.
* ``investigations[]`` and ``hunts[]``: store rows, each with its ordered
  ``events[]`` (``{kind, sequence, payload}``), the rows that
  :class:`~soc_ai.store.models.InvestigationEvent` and
  :class:`~soc_ai.store.models.HuntEvent` hold.
* ``backtests[]``, ``hunt_schedules[]``, ``quality_snapshots[]``: store rows.
* ``tables``: ``{table name: [row, ...]}`` for every other store table the
  demo fills (hosts, profiles, observations, leads, grid gaps, analytic
  history, escalations, runbooks and more). Only the tables in
  :data:`SEEDED_TABLES` are accepted, in that order. A row names every
  primary key, so a restart skips the rows it already holds.
* ``autotriage``: the last Auto-Investigate batch, set on ``app.state`` at
  startup (the panel reads process memory, not the store).
* ``alerts[]``, ``documents[]``, ``traffic``: the mock grid's documents and
  host traffic. The seeder ignores them.
* ``replays[]`` and ``chats[]``: request-time content for
  :mod:`soc_ai.demo.replay` and :mod:`soc_ai.demo.chat`. The seeder ignores
  them.

Seeding is idempotent per row: a row whose primary key is already present is
skipped. A missing or invalid file is the caller's fail-soft concern (see the
demo hook in :func:`soc_ai.main._init_store`).
"""

from __future__ import annotations

import copy
import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import DateTime, Table, insert, select, tuple_
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.types import TypeDecorator

from soc_ai.store.models import (
    Backtest,
    Base,
    Hunt,
    HuntEvent,
    HuntSchedule,
    Investigation,
    InvestigationEvent,
    QualitySnapshot,
)

DEFAULT_FIXTURES = Path(__file__).parent / "fixtures.json"

FIXTURES_VERSION = 2

# The store tables a fixture file may fill through ``tables``, in insert order:
# a parent table comes before the table that holds a key to it. The list is
# also the allowlist. A fixture can never write users, sessions, tokens or
# config overrides.
SEEDED_TABLES: tuple[str, ...] = (
    "host_machine",
    "host_dossier",
    "host_dossier_field",
    "dossier_run",
    "entity_profiles",
    "member_prevalence",
    "leads",
    "entity_observations",
    "grid_gaps",
    "analytic_state",
    "analytic_versions",
    "hunt_spec_sweeps",
    "prior_spec_runs",
    "alert_assignments",
    "alert_escalations",
    "detection_override",
    "runbook",
    "internal_identifier",
    "rule_prior_decisions",
)

# A full ISO-8601 datetime, the only string shape the rebase moves. A date
# alone, a version string or an id never matches.
_ISO_DATETIME = re.compile(
    r"^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})(\.\d{1,6})?(Z|[+-]\d{2}:\d{2})?$"
)


def load_fixtures(path: Path = DEFAULT_FIXTURES) -> dict[str, Any]:
    """Parse and check the fixture file.

    Returns the whole document as written, timestamps still against the
    anchor. Call :func:`rebase_document` for the copy that reads as current.
    ``chats[]`` entries are shape-checked (see :func:`_validate_chats`), so a
    malformed canned-chat entry fails here and not at chat time.
    """
    data: dict[str, Any] = json.loads(path.read_text())
    if data.get("version") != FIXTURES_VERSION:
        raise ValueError(f"unsupported fixtures version: {data.get('version')!r}")
    anchor = data.get("anchor")
    if not isinstance(anchor, str) or _ISO_DATETIME.match(anchor) is None:
        raise ValueError(f"fixtures anchor must be an ISO-8601 datetime, got {anchor!r}")
    tables = data.get("tables") or {}
    unknown = sorted(set(tables) - set(SEEDED_TABLES))
    if unknown:
        raise ValueError(f"fixtures name tables the demo does not seed: {unknown}")
    _validate_chats(data.get("chats", []))
    return data


def _validate_chats(chats: list[Any]) -> None:
    """Fail loud on a malformed ``chats[]`` entry.

    This is a loader-side guard, not a schema framework: each entry must name
    a ``target`` (``"investigation"`` or ``"hunt"``), a non-empty ``id``, and
    a ``messages`` list — the exact shape :func:`soc_ai.demo.chat.canned_reply`
    indexes by. A bad entry would otherwise surface only as a silent fallback
    reply at chat time, with no clue which fixture row was wrong.
    """
    for i, entry in enumerate(chats):
        if not isinstance(entry, dict):
            raise ValueError(f"chats[{i}]: expected an object, got {type(entry).__name__}")
        target = entry.get("target")
        if target not in ("investigation", "hunt"):
            raise ValueError(
                f"chats[{i}]: target must be 'investigation' or 'hunt', got {target!r}"
            )
        entry_id = entry.get("id")
        if not isinstance(entry_id, str) or not entry_id:
            raise ValueError(f"chats[{i}]: id must be a non-empty string, got {entry_id!r}")
        if not isinstance(entry.get("messages"), list):
            messages = entry.get("messages")
            raise ValueError(f"chats[{i}]: messages must be a list, got {type(messages).__name__}")


def _parse_naive_utc(value: str) -> datetime:
    """Parse an ISO-8601 string to a naive-UTC datetime, the store's form."""
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(UTC).replace(tzinfo=None)
    return parsed


def shift_iso(value: str, delta: timedelta) -> str:
    """Move one ISO-8601 datetime string by ``delta`` and keep its format.

    The suffix stays as written (``Z``, an offset, or none for a naive UTC
    value), and so does the number of fraction digits. A string that is not a
    full datetime comes back unchanged.
    """
    match = _ISO_DATETIME.match(value)
    if match is None:
        return value
    _date, _time, fraction, suffix = match.groups()
    moved = _parse_naive_utc(value) + delta
    out = moved.strftime("%Y-%m-%dT%H:%M:%S")
    if fraction:
        digits = len(fraction) - 1
        out += "." + f"{moved.microsecond:06d}"[:digits]
    if suffix == "Z":
        out += "Z"
    elif suffix:
        out += "+00:00"
    return out


def shift_tree(node: Any, delta: timedelta) -> Any:
    """A copy of ``node`` with every datetime string value moved by ``delta``.

    Dict keys never move. Only a whole string value that is a full datetime
    moves; a datetime inside prose stays as written.
    """
    if isinstance(node, str):
        return shift_iso(node, delta)
    if isinstance(node, dict):
        return {key: shift_tree(value, delta) for key, value in node.items()}
    if isinstance(node, list):
        return [shift_tree(item, delta) for item in node]
    return node


def rebase_document(data: dict[str, Any], now: datetime | None = None) -> dict[str, Any]:
    """A copy of the fixture document with every timestamp moved to read as current.

    The anchor lands at ``now`` (the seed instant, naive or aware UTC), and
    every other datetime string keeps its distance from the anchor. The
    input is never changed, so one loaded document can be rebased again.
    """
    anchor = _parse_naive_utc(str(data["anchor"]))
    current = now or datetime.now(UTC)
    if current.tzinfo is not None:
        current = current.astimezone(UTC).replace(tzinfo=None)
    rebased: dict[str, Any] = shift_tree(data, current - anchor)
    rebased["anchor"] = current.isoformat() + "+00:00"
    return rebased


def _table(name: str) -> Table:
    table = Base.metadata.tables.get(name)
    if table is None:
        raise ValueError(f"no store table {name!r}")
    return table


def _store_row(table: Table, raw: dict[str, Any]) -> dict[str, Any]:
    """One fixture row as the column values the store takes.

    A DateTime column gets a naive-UTC datetime. An unknown key fails loud:
    a builder mistake must not seed a row with a silently missing value.
    """
    columns = table.columns
    unknown = sorted(set(raw) - set(columns.keys()))
    if unknown:
        raise ValueError(f"{table.name}: unknown column(s) {unknown}")
    row = dict(raw)
    for name, value in raw.items():
        if isinstance(value, str) and _is_datetime(columns[name].type):
            row[name] = _parse_naive_utc(value)
    return row


def _is_datetime(column_type: Any) -> bool:
    """Whether a column holds a datetime. The store's type wraps ``DateTime``."""
    if isinstance(column_type, TypeDecorator):
        column_type = column_type.impl
    return isinstance(column_type, DateTime)


async def _seed_table(db: AsyncSession, table_name: str, rows: list[dict[str, Any]]) -> int:
    """Insert the rows of one table whose primary key the store does not hold."""
    if not rows:
        return 0
    table = _table(table_name)
    pk_cols = list(table.primary_key.columns)
    names = [col.name for col in pk_cols]
    for i, row in enumerate(rows):
        missing = [name for name in names if row.get(name) is None]
        if missing:
            raise ValueError(f"{table_name}[{i}]: the primary key {missing} is missing")
    keys = [tuple(row[name] for name in names) for row in rows]
    have: set[tuple[Any, ...]] = set()
    if len(names) == 1:
        found = await db.scalars(select(pk_cols[0]).where(pk_cols[0].in_([k[0] for k in keys])))
        have = {(value,) for value in found}
    else:
        result = await db.execute(select(*pk_cols).where(tuple_(*pk_cols).in_(keys)))
        have = {tuple(r) for r in result}
    fresh = [_store_row(table, row) for row, key in zip(rows, keys, strict=True) if key not in have]
    # One executemany per set of keys: a row that leaves a column out takes the
    # column default, and a row that names it None stores NULL.
    groups: dict[tuple[str, ...], list[dict[str, Any]]] = {}
    for row in fresh:
        groups.setdefault(tuple(sorted(row)), []).append(row)
    for group in groups.values():
        await db.execute(insert(table), group)
    return len(fresh)


async def seed_fixtures(
    sessionmaker: async_sessionmaker[AsyncSession],
    data: dict[str, Any],
    *,
    now: datetime | None = None,
) -> int:
    """Insert the fixture rows; skip any primary key that already exists.

    Rebases a copy of ``data`` to ``now`` first (:func:`rebase_document`), so
    the caller's document is never changed and can be seeded again. Returns
    the number of rows added: the parent rows of the named sections plus the
    rows of ``tables``. Child events ride along uncounted.
    """
    doc = rebase_document(data, now)
    added = 0
    async with sessionmaker() as db:
        for raw in doc.get("investigations", []):
            inv = copy.deepcopy(raw)
            events = inv.pop("events", [])
            if await db.get(Investigation, inv["id"]) is not None:
                continue
            db.add(Investigation(**_store_row(_table("investigations"), inv)))
            # Parent before children: no ORM relationships are declared, so
            # flush the parent row before its FK event rows.
            await db.flush()
            for ev in events:
                db.add(InvestigationEvent(investigation_id=inv["id"], **ev))
            added += 1
        for raw in doc.get("hunts", []):
            hunt = copy.deepcopy(raw)
            events = hunt.pop("events", [])
            if await db.get(Hunt, hunt["id"]) is not None:
                continue
            db.add(Hunt(**_store_row(_table("hunts"), hunt)))
            await db.flush()
            for ev in events:
                db.add(HuntEvent(hunt_id=hunt["id"], **ev))
            added += 1
        for section, model in (
            ("backtests", Backtest),
            ("hunt_schedules", HuntSchedule),
            ("quality_snapshots", QualitySnapshot),
        ):
            for raw in doc.get(section, []):
                if await db.get(model, raw["id"]) is None:
                    db.add(model(**_store_row(_table(model.__tablename__), raw)))
                    added += 1
        await db.flush()
        tables = doc.get("tables") or {}
        for table_name in SEEDED_TABLES:
            added += await _seed_table(db, table_name, tables.get(table_name) or [])
        await db.commit()
    return added
