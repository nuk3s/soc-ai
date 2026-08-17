"""Per-user saved list views — CRUD for :class:`~soc_ai.store.models.SavedView`.

Every function here takes ``user_id`` and puts it in the WHERE clause. That is
the whole security model: a view belonging to someone else is not forbidden, it
simply is not there, so a caller probing ids learns nothing about another
analyst's rows.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, cast

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

if TYPE_CHECKING:  # pragma: no cover - typing only
    from sqlalchemy.engine import CursorResult

from soc_ai.store.models import SavedView

# The list screens that can hold a view. A screen not on this list is a typo or
# a stale client, and either way saving against it would create a row nothing
# will ever read back.
SAVED_VIEW_SCREENS: tuple[str, ...] = ("alerts", "investigations", "hunts", "hosts")

# Per user, across all screens. The chip row stops being readable long before
# this, so the cap is really about not leaving a one-click INSERT unbounded.
MAX_VIEWS_PER_USER = 30

NAME_MAX = 64

# Serialised size of one view's query.
#
# Measured against what the four screens actually produce with EVERY facet set
# and the search box at its own cap: hunts 95 B, alerts 248 B, hosts 276 B,
# investigations 485 B. 4 KiB is ~8x the worst real payload — room for several
# more facets per screen — while keeping a row a row. Unbounded, this column was
# a write-what-you-like store: any signed-in analyst could script 30 rows of
# arbitrary size into the appliance's SQLite.
MAX_QUERY_BYTES = 4096

# Serialised length alone does not cover nesting: ~2,000 nested arrays fit
# inside 4 KiB and exhaust Python's recursion limit when the value is walked for
# storage, turning a request into a 500. Nothing any screen saves is deeper than
# 2 (``{custom: {from, to}}``), so 8 is already generous.
MAX_QUERY_DEPTH = 8


class TooManyViewsError(RuntimeError):
    """This user is already at :data:`MAX_VIEWS_PER_USER`."""


class QueryTooLargeError(ValueError):
    """The query blob is over :data:`MAX_QUERY_BYTES` or :data:`MAX_QUERY_DEPTH`."""

    def __init__(self, reason: str, hint: str) -> None:
        super().__init__(hint)
        self.reason = reason
        self.hint = hint


def _depth(value: Any, limit: int) -> int:
    """Nesting depth of a JSON-ish value, giving up once past ``limit``.

    Bounded on the way DOWN rather than measured and then compared: measuring a
    hostile value first is the same recursion the limit exists to prevent.
    """
    if limit < 0:
        return 0
    if isinstance(value, dict):
        return 1 + max((_depth(v, limit - 1) for v in value.values()), default=0)
    if isinstance(value, list):
        return 1 + max((_depth(v, limit - 1) for v in value), default=0)
    return 0


def validate_query(query: dict[str, Any]) -> None:
    """Refuse a query blob that is too big or too deep to be a filter set.

    Raises :class:`QueryTooLargeError`; the route turns it into the house 400.
    """
    if _depth(query, MAX_QUERY_DEPTH) > MAX_QUERY_DEPTH:
        raise QueryTooLargeError(
            "query_too_deep",
            f"A saved view's filters may nest at most {MAX_QUERY_DEPTH} levels.",
        )
    size = len(json.dumps(query, separators=(",", ":"), default=str).encode())
    if size > MAX_QUERY_BYTES:
        raise QueryTooLargeError(
            "query_too_large",
            f"A saved view's filters may be at most {MAX_QUERY_BYTES} bytes; that one is {size}.",
        )


async def list_views(
    db: AsyncSession, user_id: int, *, screen: str | None = None
) -> list[SavedView]:
    """This user's views, oldest first — the one order that never reshuffles."""
    stmt = select(SavedView).where(SavedView.user_id == user_id)
    if screen:
        stmt = stmt.where(SavedView.screen == screen)
    stmt = stmt.order_by(SavedView.id.asc())
    return list((await db.scalars(stmt)).all())


async def upsert_view(
    db: AsyncSession,
    user_id: int,
    *,
    screen: str,
    name: str,
    query: dict[str, Any],
) -> SavedView:
    """Save a filter set under a name, replacing any same-named one.

    Re-saving is an update, not a second chip: an operator refining "Beacons"
    and clicking Save again means "this is what Beacons is now", and the unique
    constraint says the same thing at the schema level.
    """
    row = await db.scalar(
        select(SavedView).where(
            SavedView.user_id == user_id,
            SavedView.screen == screen,
            SavedView.name == name,
        )
    )
    if row is not None:
        # An UPDATE, so the cap does not apply: an operator sitting at the limit
        # must still be able to edit the very views that filled it.
        row.query_json = query
        await db.commit()
        await db.refresh(row)
        return row

    # Only the CREATE path can grow the table, and the count has to be taken
    # while holding the write lock — counting first and inserting after is a
    # check-then-act race (eight concurrent saves at 29 rows landed 31).
    #
    # The flush below is what takes SQLite's RESERVED lock, and SQLite
    # serialises writers: any concurrent saver blocks here until this
    # transaction commits or rolls back, and then counts a table that already
    # includes this row. So insert first, count second, and undo if the count
    # says this row was one too many.
    row = SavedView(user_id=user_id, screen=screen, name=name, query_json=query)
    db.add(row)
    await db.flush()
    total = await db.scalar(
        select(func.count()).select_from(SavedView).where(SavedView.user_id == user_id)
    )
    if int(total or 0) > MAX_VIEWS_PER_USER:
        await db.rollback()
        raise TooManyViewsError(f"at most {MAX_VIEWS_PER_USER} saved views per user")
    await db.commit()
    await db.refresh(row)
    return row


async def delete_view(db: AsyncSession, user_id: int, view_id: int) -> bool:
    """Delete one of this user's views. False when it is not theirs, or gone."""
    result = await db.execute(
        delete(SavedView).where(SavedView.id == view_id, SavedView.user_id == user_id)
    )
    await db.commit()
    return bool(cast("CursorResult[Any]", result).rowcount)
