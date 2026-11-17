"""The close time of a lead is naive UTC, the form of the stored columns.

The list of leads answered 500 when a promoted lead was on it. The close time
of a promotion comes from the history, which states its time with an offset.
Each caller compares it with an observation time, which has none. The unit
suite passed, and the browser smoke found it (2026-11-13).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any

from soc_ai.store import leads as leads_store


def _promoted(at: str, *, lead_id: int = 7) -> Any:
    return SimpleNamespace(
        id=lead_id,
        status="promoted",
        dismissed_at=None,
        dismissed_by=None,
        updated_at=datetime.now(UTC).replace(tzinfo=None),
        decisions_json=[{"action": "promoted", "at": at, "by": "analyst"}],
    )


def _obs(born_at: datetime, *, lead_id: int = 7) -> Any:
    return SimpleNamespace(lead_id=lead_id, born_at=born_at)


def test_the_close_time_of_a_promotion_has_no_offset() -> None:
    closed = leads_store.closed_at_of(_promoted("2026-11-10T12:00:00+00:00"))
    assert closed == datetime(2026, 11, 10, 12, 0, 0)
    assert closed is not None and closed.tzinfo is None


def test_an_offset_other_than_utc_is_converted() -> None:
    closed = leads_store.closed_at_of(_promoted("2026-11-10T07:00:00-05:00"))
    assert closed == datetime(2026, 11, 10, 12, 0, 0)


def test_the_repeats_of_a_promoted_lead_compare_with_naive_observation_times() -> None:
    lead = _promoted("2026-11-10T12:00:00+00:00")
    close = datetime(2026, 11, 10, 12, 0, 0)
    rows = [_obs(close - timedelta(hours=1)), _obs(close + timedelta(hours=2))]
    count, newest = leads_store.repeats_after_close(lead, rows)
    assert (count, newest) == (1, close + timedelta(hours=2))


def test_an_observation_time_with_an_offset_compares_too() -> None:
    lead = _promoted("2026-11-10T12:00:00+00:00")
    aware = datetime(2026, 11, 10, 15, 0, 0, tzinfo=timezone(timedelta(hours=1)))
    count, newest = leads_store.repeats_after_close(lead, [_obs(aware)])
    assert (count, newest) == (1, datetime(2026, 11, 10, 14, 0, 0))


def test_a_dismissal_and_an_open_lead_keep_their_answers() -> None:
    at = datetime(2026, 11, 9, 8, 0, 0)
    dismissed = SimpleNamespace(
        id=1, status="dismissed", dismissed_at=at, updated_at=at, decisions_json=[]
    )
    assert leads_store.closed_at_of(dismissed) == at
    open_lead = SimpleNamespace(
        id=2, status="open", dismissed_at=None, updated_at=at, decisions_json=[]
    )
    assert leads_store.closed_at_of(open_lead) is None
    assert leads_store.repeats_after_close(open_lead, [_obs(at, lead_id=2)]) == (0, None)
