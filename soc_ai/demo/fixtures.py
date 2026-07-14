"""Load the sanitized demo fixture set and seed it into the store.

Schema (version 1): ``{version, investigations[], hunts[], backtests[],
alerts[] (mock-ES documents, consumed by scripts/demo/mock_es.py),
replays[] ({alert_es_id, investigation{...}, events[]} — replayed live by
soc_ai/demo/replay.py, NOT seeded at startup), chats[] ({target
("investigation"|"hunt"), id, messages[]} — canned assistant replies looked
up by soc_ai/demo/chat.py at request time, NOT seeded at startup)}``. Each
investigation/hunt carries its ordered ``events[]`` (``{kind, sequence,
payload}``) — the same rows :class:`~soc_ai.store.models.InvestigationEvent` /
:class:`~soc_ai.store.models.HuntEvent` store.

Seeding is idempotent PER ROW (skip any primary key already present), so a
restart — or a store that was only partially seeded — completes without
duplicating anything. The fixture file itself ships separately (built +
owner-reviewed by the demo pipeline); a missing/invalid file is the caller's
fail-soft concern (see the demo hook in :func:`soc_ai.main._init_store`).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from soc_ai.store.models import Backtest, Hunt, HuntEvent, Investigation, InvestigationEvent

DEFAULT_FIXTURES = Path(__file__).parent / "fixtures.json"

# Row keys holding ISO-8601 strings in the fixture file; the store's DateTime
# columns want naive-UTC datetime objects (see soc_ai/store/models.py docstring).
_TIME_KEYS = ("created_at", "finished_at")


def load_fixtures(path: Path = DEFAULT_FIXTURES) -> dict[str, Any]:
    """Parse + version-check the fixture file.

    Returns the whole document — including the ``alerts[]``/``replays[]``/
    ``chats[]`` pass-through sections consumed by the mock ES, the replay
    runner, and the demo chat lookup, all of which :func:`seed_fixtures`
    deliberately ignores. ``chats[]`` entries are shape-checked (see
    :func:`_validate_chats`) so a malformed canned-chat entry fails loud here
    rather than silently producing no reply at request time.
    """
    data: dict[str, Any] = json.loads(path.read_text())
    if data.get("version") != 1:
        raise ValueError(f"unsupported fixtures version: {data.get('version')!r}")
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
    """Parse an ISO-8601 string to a naive-UTC datetime (same normalization as
    :func:`_coerce_times`), so mixed tz-aware/naive fixture rows stay comparable.
    """
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(UTC).replace(tzinfo=None)
    return parsed


def _rebase_rows_to_now(rows: list[dict[str, Any]]) -> None:
    """Shift one section's created_at+finished_at forward so its newest row lands
    at 'now', preserving ordering and gaps within the section. Mutates in place;
    a no-op when the section carries no parseable timestamp.
    """
    times: list[datetime] = []
    for row in rows:
        for key in _TIME_KEYS:
            value = row.get(key)
            if isinstance(value, str):
                times.append(_parse_naive_utc(value))
    if not times:
        return
    delta = datetime.now(UTC).replace(tzinfo=None) - max(times)
    for row in rows:
        for key in _TIME_KEYS:
            value = row.get(key)
            if isinstance(value, str):
                row[key] = (_parse_naive_utc(value) + delta).isoformat()


def _rebase_to_now(data: dict[str, Any]) -> None:
    """Rebase each section (investigations/hunts/backtests) independently so its
    OWN newest row lands at 'now', preserving ordering and gaps within the
    section.

    Per-section, not one global delta: in the committed fixtures the backtest is
    ~2 days newer than the newest investigation, so a single global anchor would
    drag every investigation ~46h into the past and out of the default window.
    Cross-section time relationships don't matter for the demo — only that each
    surface reads as current. Mutates ``data`` in place (the ISO-string timestamp
    fields only); the committed fixtures mix tz-aware and naive rows, so
    everything is normalized to naive-UTC first.
    """
    for section in ("investigations", "hunts", "backtests"):
        _rebase_rows_to_now(data.get(section, []))


def _coerce_times(row: dict[str, Any]) -> dict[str, Any]:
    """Convert ISO-8601 timestamp strings to the store's naive-UTC datetimes."""
    for key in _TIME_KEYS:
        value = row.get(key)
        if isinstance(value, str):
            parsed = datetime.fromisoformat(value)
            if parsed.tzinfo is not None:
                parsed = parsed.astimezone(UTC).replace(tzinfo=None)
            row[key] = parsed
    return row


async def seed_fixtures(
    sessionmaker: async_sessionmaker[AsyncSession], data: dict[str, Any]
) -> int:
    """Insert fixture rows; skip any id that already exists (idempotent).

    Rebases every row's timestamps to 'now' first (in place, see
    :func:`_rebase_to_now`) so seeded content always reads as recent. Each row
    is then copied before the ``events`` pop / time coercion, so seeding never
    drops events and one loaded document can be seeded repeatedly.
    Returns the number of parent rows (investigations + hunts + backtests)
    added; their child events ride along uncounted.
    """
    _rebase_to_now(data)
    added = 0
    async with sessionmaker() as db:
        for raw in data.get("investigations", []):
            inv = _coerce_times(dict(raw))
            events = inv.pop("events", [])
            if await db.get(Investigation, inv["id"]) is not None:
                continue
            db.add(Investigation(**inv))
            # Parent before children: no ORM relationships are declared (same
            # constraint scripts/demo/seed_demo.py works around), so flush the
            # parent row before its FK event rows.
            await db.flush()
            for ev in events:
                db.add(InvestigationEvent(investigation_id=inv["id"], **ev))
            added += 1
        for raw in data.get("hunts", []):
            hunt = _coerce_times(dict(raw))
            events = hunt.pop("events", [])
            if await db.get(Hunt, hunt["id"]) is not None:
                continue
            db.add(Hunt(**hunt))
            await db.flush()
            for ev in events:
                db.add(HuntEvent(hunt_id=hunt["id"], **ev))
            added += 1
        for raw in data.get("backtests", []):
            bt = _coerce_times(dict(raw))
            if await db.get(Backtest, bt["id"]) is None:
                db.add(Backtest(**bt))
                added += 1
        await db.commit()
    return added
