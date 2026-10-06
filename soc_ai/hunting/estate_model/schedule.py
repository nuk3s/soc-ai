"""The daily estate model loop, beside the profile build.

The profile build runs inside the dossier sweep and the prior sweep. The
estate model reads what the build wrote, once a day, in a loop of its own:

* it wakes every 5 minutes and reads the settings each wake, so a console
  toggle applies without a restart;
* it does nothing while ``estate_model_enabled`` is off, and nothing in a
  demo;
* a run is due when the newest fit in the store is 24 hours old or more. The
  stamp is durable: a restart does not refit;
* the run takes the dossier's single-flight slot, the slot the profile build
  takes. A fit never runs beside a dossier sweep or a profile rebuild. When
  the slot is held the run waits for the next wake;
* the fit itself runs in a worker thread, so the event loop keeps serving.

A run that fails is logged and the loop continues. A run with the extra
absent logs its one line and counts as a run, so the line comes once a day.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from soc_ai.hunting.estate_model.job import run_estate_model
from soc_ai.store import estate_model as store

__all__ = ["FIT_INTERVAL", "WAKE_SECONDS", "estate_model_due", "estate_model_loop"]

_LOGGER = logging.getLogger(__name__)

WAKE_SECONDS = 300
FIT_INTERVAL = timedelta(hours=24)


def _utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def estate_model_due(last: datetime | None, now: datetime) -> bool:
    """Never fitted, 24 hours old or more, or stamped in the future."""
    if last is None:
        return True
    return last > now or (now - last) >= FIT_INTERVAL


async def _last_fit(app: Any) -> datetime | None:
    stamp = getattr(app.state, "estate_model_last_run", None)
    if isinstance(stamp, datetime):
        return stamp
    async with app.state.db_sessionmaker() as db:
        fit = await store.latest_fit(db)
    return fit.fitted_at if fit is not None else None


async def estate_model_wake(app: Any, *, now: datetime | None = None) -> Any:
    """One wake of the loop. Returns the run, or None when nothing was due."""
    from soc_ai.api.webui import _get_dossier_status  # noqa: PLC0415 - avoids a cycle

    settings = app.state.settings
    if not getattr(settings, "estate_model_enabled", False):
        return None
    if getattr(settings, "soc_ai_demo", False):
        return None
    at = now or _utcnow()
    if not estate_model_due(await _last_fit(app), at):
        return None
    status = _get_dossier_status(app.state)
    if status.running:
        _LOGGER.info("estate model: a dossier sweep holds the slot. The fit waits.")
        return None
    status.running = True
    try:
        run = await run_estate_model(
            db_sessionmaker=app.state.db_sessionmaker,
            settings=settings,
            elastic=getattr(app.state, "elastic", None),
            audit=getattr(app.state, "audit", None),
            now=at,
        )
    finally:
        status.running = False
    app.state.estate_model_last_run = at
    return run


async def estate_model_loop(app: Any) -> None:
    """Run :func:`estate_model_wake` every 5 minutes until cancelled."""
    app.state.estate_model_last_run = None
    while True:
        await asyncio.sleep(WAKE_SECONDS)
        try:
            await estate_model_wake(app)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            _LOGGER.warning("estate model loop: %s: %s", type(exc).__name__, exc)
