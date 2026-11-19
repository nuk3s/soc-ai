"""The trigger of a campaign rebuild after a change of the store (S1).

The campaign engine ran only when a person opened a campaign page, so no
other page could name the campaign of an investigation. A campaign changes
when an investigation ends with a verdict, or when an analyst changes a
verdict or a resolution. The store then calls :func:`request_refresh`.

:func:`refresh_loop` is one background task of the app
(``soc_ai.main.lifespan``). It waits for a request or for :data:`IDLE_S`,
then waits :data:`JOIN_S` more, so a burst of verdicts causes one rebuild.
It then opens its own session and calls
:func:`soc_ai.campaigns.service.ensure_fresh`. That call rebuilds only when
the basis of the store changed, and it never raises. The two campaign GET
routes keep their own call.

:func:`request_refresh` is cheap, never raises and is safe from any task or
thread. With no loop, as in the test suite and in a CLI process, it does
nothing. This module imports nothing of the store, so the store can call it.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

_LOGGER = logging.getLogger(__name__)


def _naive_now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


# The longest wait for a request. A change that no request names, such as a
# write of another process, reaches the campaigns at the next timer.
IDLE_S = 300.0
# The wait after a request, so the verdicts of a burst join one rebuild.
JOIN_S = 2.0

_LOOP_LINE = (
    "campaigns: the refresh loop could not rebuild the campaigns. The next request or "
    "the next timer tries again."
)
_COUNTS_LINE = (
    "campaigns: the refresh loop could not read the grid for the alert counts. The pages "
    "show the stored counts with the time of their read. The next wake tries again."
)


@dataclass(frozen=True)
class _Listener:
    event: asyncio.Event
    loop: asyncio.AbstractEventLoop


# The event of the running refresh loop, or None when no loop runs.
_LISTENER: _Listener | None = None


def request_refresh() -> None:
    """Ask the refresh loop for a rebuild. Cheap, never raises, safe from any task or thread."""
    try:
        held = _LISTENER
        if held is None or held.loop.is_closed():
            return
        try:
            running: asyncio.AbstractEventLoop | None = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is held.loop:
            held.event.set()
        else:
            held.loop.call_soon_threadsafe(held.event.set)
    except Exception:
        _LOGGER.debug("campaigns: a refresh request was lost", exc_info=True)


def is_listening() -> bool:
    """True while a refresh loop waits for requests."""
    return _LISTENER is not None


@contextlib.contextmanager
def _listen() -> Iterator[asyncio.Event]:
    global _LISTENER  # noqa: PLW0603 - one loop for each process
    held = _Listener(asyncio.Event(), asyncio.get_running_loop())
    _LISTENER = held
    try:
        yield held.event
    finally:
        if _LISTENER is held:
            _LISTENER = None


async def _refresh_counts(app: Any, service: Any) -> None:
    """Read the grid for the campaigns whose stored alert count is behind (SD5).

    A rebuild that adds an investigation changes the pairs of a campaign,
    and every surface reads the stored count. The demo has no grid, and an
    app with no grid client or settings reads nothing. The step has a time
    budget, so a grid that does not answer holds the next rebuild back by at
    most :data:`soc_ai.campaigns.service.EVENTS_REFRESH_BUDGET_S`.

    The step first opens each closed campaign again whose activity goes on
    (G4, :func:`soc_ai.campaigns.service.reopen_on_activity`). Its reads and
    the reads of the counts share the one limit of reads of a wake. The end
    check of each ended campaign (E2, :func:`soc_ai.campaigns.service.check_end`)
    comes last, inside the same limit.
    """
    state = getattr(app, "state", None)
    elastic = getattr(state, "elastic", None)
    settings = getattr(state, "settings", None)
    if elastic is None or settings is None or getattr(settings, "soc_ai_demo", False):
        return
    try:
        async with asyncio.timeout(service.EVENTS_REFRESH_BUDGET_S):
            async with app.state.db_sessionmaker() as db:
                at = _naive_now()
                asked = await service.reopen_on_activity(db, elastic, settings, now=at)
                await service.refresh_behind(
                    db,
                    elastic,
                    settings,
                    now=at,
                    limit=max(0, service.EVENTS_REFRESH_MAX - asked),
                )
    except TimeoutError:
        _LOGGER.warning(_COUNTS_LINE)
    except Exception:
        _LOGGER.warning(_COUNTS_LINE, exc_info=True)


async def refresh_loop(app: Any, *, idle_s: float = IDLE_S, join_s: float = JOIN_S) -> None:
    """Rebuild the campaigns after each request, and at least once every ``idle_s``.

    Runs until cancelled at shutdown. A failed wake is logged, and the next
    request or timer tries again. The rebuild shares the lock of
    :func:`soc_ai.campaigns.service.ensure_fresh` with the campaign routes,
    so a page read and the loop never rebuild at the same time.
    """
    from soc_ai.campaigns import (  # noqa: PLC0415 - they import the store
        case_comments,
        lead_tags,
        service,
    )

    with _listen() as event:
        while True:
            with contextlib.suppress(TimeoutError):
                async with asyncio.timeout(idle_s):
                    await event.wait()
            await asyncio.sleep(join_s)
            # A request after this line causes the next rebuild.
            event.clear()
            try:
                async with app.state.db_sessionmaker() as db:
                    await service.ensure_fresh(db, audit=getattr(app.state, "audit", None))
                    # The step runs on each wake too. A sweep of another
                    # process can attach an observation to a lead, and no
                    # rebuild follows such a write.
                    await lead_tags.after_rebuild(db, now=_naive_now())
                    # A change that a rebuild of another process wrote waits
                    # on its comment until this step.
                    await case_comments.after_rebuild(db, state=app.state)
            except Exception:
                _LOGGER.warning(_LOOP_LINE, exc_info=True)
            await _refresh_counts(app, service)


__all__ = ["IDLE_S", "JOIN_S", "is_listening", "refresh_loop", "request_refresh"]
