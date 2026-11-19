"""The event time of the investigation behind a lead observation.

An alert observation and a promoted hunt finding observation are written with
no document time. The lead page read "Recorded 2026-11-11 18:51 UTC. No
document time is on record." for an observation whose investigation holds the
time of its event (dogfood 2026-11-17, AB2). The page reads the time here.

* An alert observation (spec ``alert``) keys on the alert id. The time is the
  ``event_at`` of an investigation of that alert.
* A hunt finding observation (spec ``hunt``) holds the hunt id and the finding
  ordinal in its evidence. The time is the ``event_at`` of the finding
  investigation.

``event_at`` holds the creation time when the run had no event time (see
:mod:`soc_ai.store.event_at`). Such a row holds no event time, so it gives
none here: the page keeps its "No document time" line. The read changes no
stored row, and the live weight of an observation does not read it.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.store.models import Investigation

ALERT_SPEC_ID = "alert"
HUNT_SPEC_ID = "hunt"

# The ids of one IN clause. SQLite allows 999 bound parameters on an old build.
_CHUNK = 500


def _chunks(values: Sequence[Any]) -> Iterable[Sequence[Any]]:
    for start in range(0, len(values), _CHUNK):
        yield values[start : start + _CHUNK]


def _held_event_time(event_at: datetime | None, created_at: datetime | None) -> datetime | None:
    """The event time of a run, or None when the row holds its creation time."""
    if event_at is None:
        return None
    if created_at is not None and event_at >= created_at:
        return None
    return event_at


def _finding_key(evidence: Any) -> tuple[str, int] | None:
    if not isinstance(evidence, Mapping):
        return None
    hunt_id = evidence.get("hunt_id")
    ordinal = evidence.get("ordinal")
    if not isinstance(hunt_id, str) or not hunt_id or isinstance(ordinal, bool):
        return None
    if not isinstance(ordinal, int):
        return None
    return hunt_id, ordinal


async def investigation_event_times(
    db: AsyncSession, observations: Sequence[Any]
) -> dict[int, datetime]:
    """The event time of each observation's investigation, by observation id.

    An observation with its own document time, or with no investigation that
    holds an event time, is not in the answer.
    """
    alerts: dict[str, list[int]] = {}
    findings: dict[tuple[str, int], list[int]] = {}
    for o in observations:
        if getattr(o, "observed_at", None) is not None:
            continue
        spec = str(getattr(o, "spec_id", "") or "")
        if spec == ALERT_SPEC_ID and getattr(o, "fingerprint", None):
            alerts.setdefault(str(o.fingerprint), []).append(int(o.id))
        elif spec == HUNT_SPEC_ID:
            key = _finding_key(getattr(o, "evidence_json", None))
            if key is not None:
                findings.setdefault(key, []).append(int(o.id))

    out: dict[int, datetime] = {}
    by_alert: dict[str, datetime] = {}
    for ids in _chunks(sorted(alerts)):
        rows = await db.execute(
            select(
                Investigation.alert_es_id, Investigation.event_at, Investigation.created_at
            ).where(Investigation.alert_es_id.in_(ids))
        )
        for alert_id, event_at, created_at in rows.all():
            held = _held_event_time(event_at, created_at)
            if held is None:
                continue
            # The runs of one alert judge one event. The newest stated time
            # wins, so the answer does not depend on the row order.
            known = by_alert.get(str(alert_id))
            by_alert[str(alert_id)] = held if known is None else max(known, held)
    for alert_id, obs_ids in alerts.items():
        if alert_id in by_alert:
            for obs_id in obs_ids:
                out[obs_id] = by_alert[alert_id]

    hunts = sorted({hunt for hunt, _ in findings})
    by_finding: dict[tuple[str, int], datetime] = {}
    for ids in _chunks(hunts):
        rows = await db.execute(
            select(
                Investigation.hunt_id,
                Investigation.finding_ordinal,
                Investigation.event_at,
                Investigation.created_at,
            ).where(Investigation.hunt_id.in_(ids), Investigation.finding_ordinal.is_not(None))
        )
        for hunt_id, ordinal, event_at, created_at in rows.all():
            held = _held_event_time(event_at, created_at)
            if held is None:
                continue
            key = (str(hunt_id), int(ordinal))
            known = by_finding.get(key)
            by_finding[key] = held if known is None else max(known, held)
    for key, obs_ids in findings.items():
        if key in by_finding:
            for obs_id in obs_ids:
                out[obs_id] = by_finding[key]
    return out
