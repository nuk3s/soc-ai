"""The probe source of the grid-gap ledger.

The health probe already tracks when Elasticsearch flips down
(``routes_meta._note_dep_transitions``), in process memory. This module turns
the same probe results into a stored gap, so the fact outlives the recovery
and a restart.

The rule:

* A probe leg is UNREADABLE when the grid refused the connection or did not
  answer in the budget. A slow answer, a partial read, a grid that sheds load
  and a missing index pattern are answers, so none of them opens a gap.
* A gap opens when the probe has read the grid as unreadable for
  :data:`CONFIRM` without a break. One failed probe opens nothing. The gap
  starts at the first unreadable probe of the run.
* The first probe that is not unreadable closes the open gap. The gap ends
  at that probe.
* An open row survives a restart. The first probe after the start reads it
  from the store, and the first good probe closes it.

Never raises. A store that cannot be written costs the record, never the
health answer.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any

from soc_ai.demo.guard import is_demo
from soc_ai.store import grid_gaps
from soc_ai.store.auth import utcnow
from soc_ai.webui.probes import KIND_REFUSED, KIND_TIMEOUT

__all__ = ["CONFIRM", "is_unreadable", "note_probe"]

_LOGGER = logging.getLogger(__name__)

# How long the grid must stay unreadable before a gap opens. The scheduled
# probe wakes every minute, so this is about three probes in a row.
CONFIRM = timedelta(minutes=3)

# The sentinel for "the open row was not read from the store yet".
_UNREAD = object()


def is_unreadable(result: dict[str, Any]) -> bool:
    """Whether one ES probe result means soc-ai could not read the grid at all."""
    if result.get("ok"):
        return False
    return str(result.get("kind") or "") in {KIND_REFUSED, KIND_TIMEOUT}


async def note_probe(
    state: Any, probed: dict[str, dict[str, Any]], *, now: datetime | None = None
) -> None:
    """Open or close the probe gap from one set of probe results. Never raises."""
    sessionmaker = getattr(state, "db_sessionmaker", None)
    es = probed.get("es")
    if sessionmaker is None or not isinstance(es, dict):
        return
    # The public demo has no grid behind it. A gap there would be a fact
    # about the demo host, never about a grid.
    if is_demo(getattr(state, "settings", None)):
        return
    at = now or utcnow()
    try:
        await _note(state, sessionmaker, es, at)
    except Exception:
        _LOGGER.warning("grid gap: the probe result could not be recorded", exc_info=True)


async def _note(state: Any, sessionmaker: Any, es: dict[str, Any], at: datetime) -> None:
    open_id = getattr(state, "_grid_gap_open_id", _UNREAD)
    if open_id is _UNREAD:
        async with sessionmaker() as db:
            rows = await grid_gaps.open_probe_gaps(db)
        open_id = rows[0].id if rows else None
        state._grid_gap_open_id = open_id

    if not is_unreadable(es):
        state._grid_unreadable_since = None
        if open_id is not None:
            async with sessionmaker() as db:
                await grid_gaps.close_probe_gaps(db, ended_at=at)
            state._grid_gap_open_id = None
            _LOGGER.info("grid gap: the grid answers again. The gap closed at %s.", at)
        return

    since = getattr(state, "_grid_unreadable_since", None)
    if since is None:
        since = at
        state._grid_unreadable_since = since
    if open_id is not None or at - since < CONFIRM:
        return
    detail = str(es.get("detail") or "The grid did not answer the health probe.")
    async with sessionmaker() as db:
        row = await grid_gaps.open_probe_gap(db, started_at=since, detail=detail)
    state._grid_gap_open_id = row.id
    _LOGGER.warning("grid gap: the grid is unreadable since %s. A gap is open.", since)
