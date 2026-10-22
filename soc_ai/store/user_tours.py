"""Per-user tour state: the console's tutorial mode.

The console runs a welcome tour at the first sign-in and a page tour at the
first visit to each page. It keeps one small object per user on the user row
(``users.tours_state``, migration 0065)::

    {"off": bool, "seen": {"<tour-id>": <version>}}

``off`` is the global opt-out. ``seen`` maps a tour id to the version of that
tour the user saw. A tour starts again on a first visit only when its version
is higher than the stored one.

Every function takes ``user_id`` and puts it in the WHERE clause, the same
model as :mod:`soc_ai.store.dashboard_layout`: another user's state is not
forbidden, it is not there.

:func:`validate_state` checks a write and refuses it whole. :func:`sanitize_state`
reads a stored value and never raises: a value it cannot read reads as the
default, and a bad entry drops on its own.
"""

from __future__ import annotations

import json
import re
from typing import Any, TypedDict

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.store.models import User

# A tour id: lowercase letters, digits and hyphens, 48 characters at most. The
# console's ids are page names, such as "welcome" and "alerts".
TOUR_ID = re.compile(r"^[a-z][a-z0-9-]{0,47}$")
# The console ships 16 tours. The cap leaves room for growth and keeps the
# stored value small.
MAX_TOURS = 64
MAX_VERSION = 10_000
# The largest PUT body the route reads (main._ROUTE_BODY_CAPS). A full state
# of MAX_TOURS ids at their longest is under 4 KiB as compact JSON. The cap
# leaves room for a client that indents its JSON.
MAX_BYTES = 8 * 1024


class ToursState(TypedDict):
    off: bool
    seen: dict[str, int]


class ToursStateInvalidError(ValueError):
    """A write that is not a tour state. ``hint`` names the fault."""

    reason = "invalid_tours_state"

    def __init__(self, hint: str) -> None:
        super().__init__(hint)
        self.hint = hint


def default_state() -> ToursState:
    return {"off": False, "seen": {}}


def _version_ok(value: object) -> bool:
    # bool is an int in Python. A stored true is no version.
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= MAX_VERSION


def validate_state(raw: Any) -> ToursState:
    """The state of a write, or :class:`ToursStateInvalidError`.

    The route's model already checked the types. This checks the values: each
    tour id, each version and the number of tours.
    """
    if not isinstance(raw, dict) or set(raw) != {"off", "seen"}:
        raise ToursStateInvalidError('A tour state is an object with the keys "off" and "seen".')
    off = raw["off"]
    seen = raw["seen"]
    if not isinstance(off, bool):
        raise ToursStateInvalidError('"off" is true or false.')
    if not isinstance(seen, dict):
        raise ToursStateInvalidError('"seen" is an object that maps a tour id to a version.')
    if len(seen) > MAX_TOURS:
        raise ToursStateInvalidError(f'"seen" holds {len(seen)} tours. The limit is {MAX_TOURS}.')
    out: dict[str, int] = {}
    for tour_id, version in seen.items():
        if not isinstance(tour_id, str) or not TOUR_ID.match(tour_id):
            raise ToursStateInvalidError(
                f"The tour id {tour_id!r} is not valid. A tour id uses lowercase letters, "
                "digits and hyphens, and starts with a letter. The limit is 48 characters."
            )
        if not _version_ok(version):
            raise ToursStateInvalidError(
                f"The version of {tour_id!r} is not valid. "
                f"A version is a whole number from 0 to {MAX_VERSION}."
            )
        out[tour_id] = int(version)
    return {"off": off, "seen": out}


def sanitize_state(raw: str | None) -> ToursState:
    """Read a stored value. Never raises.

    A value that is not JSON, or not an object, reads as the default. A bad
    ``off`` reads as tours on. A bad entry in ``seen`` drops, and the good
    entries stay, up to :data:`MAX_TOURS`.
    """
    if not raw:
        return default_state()
    try:
        data = json.loads(raw)
    except (TypeError, ValueError):
        return default_state()
    if not isinstance(data, dict):
        return default_state()
    off = data.get("off")
    seen = data.get("seen")
    out: dict[str, int] = {}
    if isinstance(seen, dict):
        for tour_id, version in seen.items():
            if len(out) >= MAX_TOURS:
                break
            if isinstance(tour_id, str) and TOUR_ID.match(tour_id) and _version_ok(version):
                out[tour_id] = int(version)
    return {"off": off if isinstance(off, bool) else False, "seen": out}


async def get_state(db: AsyncSession, user_id: int) -> ToursState:
    """This user's tour state. A missing user reads as the default."""
    raw = await db.scalar(select(User.tours_state).where(User.id == user_id))
    return sanitize_state(raw)


async def put_state(db: AsyncSession, user_id: int, state: ToursState) -> ToursState:
    """Replace this user's tour state whole. ``state`` comes from :func:`validate_state`."""
    clean = validate_state(state)
    text = json.dumps(clean, separators=(",", ":"), sort_keys=True)
    await db.execute(update(User).where(User.id == user_id).values(tours_state=text))
    await db.commit()
    return clean
