"""The profile sweep and the grid gap: an hour the grid held no data is unknown.

The range sensor was down from 2026-10-15 13:36Z to 2026-10-19 10:15Z. Six
minutes after the recovery the sweep wrote "connection rate collapsed" on five
hosts for hours inside the outage, and the departures fed a lead (dogfood
2026-10-19, R4-D1, R3-D2). These tests pin the guard:

* the hours of a recorded gap, and a settle margin after it, are not scored;
* one sweep that finds the rate collapsed on most hosts at once records a
  sweep gap and writes no departure for those hours;
* one host that goes quiet while the others keep talking is still a
  departure. That is the negative control: it is the path the grid-dark rule
  would wrongly swallow.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

from soc_ai.config import Settings
from soc_ai.hunting.prior_sweep import _complete_hours, run_prior_sweep
from soc_ai.hunting.priors import COVERAGE_BLIND
from soc_ai.store import grid_gaps
from soc_ai.store.models import EntityObservation
from sqlalchemy import func, select

from tests.test_prior_sweep import (
    _EVERY_CELL,
    _db,
    _doc_ids,
    _FakeES,
    _prior,
    _sample_hits,
    _seed_profile,
)

_HOSTS = [f"192.0.2.{n}" for n in range(10, 16)]
_COLLAPSE = _prior(dimension="connection_rate", test="below", roles=[])


class _Settings:
    events_index_pattern = "logs-*"
    so_timezone = "UTC"
    grid_gap_settle_minutes = 60


class _RatesES(_FakeES):
    """A shaped read over several hosts: per host, a count for each hour it held documents."""

    def __init__(self, hourly: dict[str, Sequence[tuple[datetime, int]]]) -> None:
        super().__init__()
        self.hourly = hourly

    def _buckets(self) -> list[dict[str, Any]]:
        out = []
        for entity, hours in sorted(self.hourly.items()):
            rows = [
                {
                    "key_as_string": at.strftime("%Y-%m-%dT%H:00:00.000Z"),
                    "doc_count": count,
                    "samples": _sample_hits(_doc_ids(f"{entity}-{at:%H}")),
                }
                for at, count in hours
                if count > 0
            ]
            if rows:
                out.append(
                    {
                        "key": entity,
                        "doc_count": sum(r["doc_count"] for r in rows),
                        "per_hour": {"buckets": rows},
                    }
                )
        return out


def _window() -> list[datetime]:
    return _complete_hours(hours=24, now=None)


async def _seed_hosts(maker: Any, hosts: Sequence[str]) -> None:
    for host in hosts:
        await _seed_profile(
            maker,
            vector=_EVERY_CELL,
            dimension="connection_rate",
            shape="numeric",
            entity_key=host,
        )


async def _sweep(maker: Any, es: Any, *, record: bool = True) -> Any:
    async with maker() as db:
        return await run_prior_sweep(
            elastic=es, settings=_Settings(), db=db, catalog=_COLLAPSE, record=record
        )


async def _observations(maker: Any) -> int:
    async with maker() as db:
        found = await db.scalar(select(func.count(EntityObservation.id)))
    return int(found or 0)


def _busy(
    hours: Sequence[datetime], *, quiet: Sequence[datetime] = ()
) -> list[tuple[datetime, int]]:
    return [(at, 0 if at in quiet else 500) for at in hours]


async def test_without_a_gap_a_dark_grid_hour_on_one_host_is_a_departure(
    settings_kratos: Settings,
) -> None:
    """The control for the gap test below: the same hosts, no gap, departures."""
    engine, maker = await _db(settings_kratos)
    await _seed_hosts(maker, _HOSTS[:2])
    window = _window()
    es = _RatesES({_HOSTS[0]: _busy(window)})
    sweep = await _sweep(maker, es, record=False)
    silent = [r for r in sweep.results if r.entity_key == _HOSTS[1]]
    assert silent and silent[0].departures
    await engine.dispose()


async def test_the_hours_of_a_recorded_gap_are_not_scored(settings_kratos: Settings) -> None:
    """The whole window and its settle margin lie in a probe gap: nothing is scored."""
    engine, maker = await _db(settings_kratos)
    await _seed_hosts(maker, _HOSTS[:5])
    now = datetime.now(UTC)
    async with maker() as db:
        await grid_gaps.open_probe_gap(db, started_at=now - timedelta(days=4), detail="refused")
        await grid_gaps.close_probe_gaps(db, ended_at=now - timedelta(minutes=6))
    window = _window()
    # Agents back-filled a little into the hole for one host.
    es = _RatesES({_HOSTS[0]: [(window[3], 40)]})
    sweep = await _sweep(maker, es)

    assert sweep.errors == ()
    assert not any(r.departures for r in sweep.results), [r.note for r in sweep.results]
    (blind,) = sweep.results
    assert blind.coverage == COVERAGE_BLIND
    assert "grid gap" in blind.note
    assert any("lie in a grid gap" in note for note in sweep.notes), sweep.notes
    assert await _observations(maker) == 0
    await engine.dispose()


async def test_a_departure_outside_the_gap_and_its_margin_still_fires(
    settings_kratos: Settings,
) -> None:
    """A gap over the first hours: the hours after the margin are scored as before."""
    engine, maker = await _db(settings_kratos)
    await _seed_hosts(maker, _HOSTS[:5])
    window = _window()
    async with maker() as db:
        await grid_gaps.open_probe_gap(db, started_at=window[0] - timedelta(hours=3), detail="x")
        await grid_gaps.close_probe_gaps(db, ended_at=window[6])
    # Host 0 is silent the whole window. The others keep talking.
    es = _RatesES({h: _busy(window) for h in _HOSTS[1:5]})
    sweep = await _sweep(maker, es, record=False)

    (silent,) = [r for r in sweep.results if r.entity_key == _HOSTS[0]]
    assert silent.departures, silent.note
    margin_end = window[6] + timedelta(minutes=60)
    for departure in silent.departures:
        assert departure.run_start is not None
        assert departure.run_start >= margin_end
    await engine.dispose()


async def test_most_hosts_dark_at_once_is_a_sweep_gap_and_no_departure(
    settings_kratos: Settings,
) -> None:
    """The sensor died and Elasticsearch stayed up. The probe cannot see that."""
    engine, maker = await _db(settings_kratos)
    await _seed_hosts(maker, _HOSTS[:5])
    window = _window()
    dark = window[-8:]
    es = _RatesES({h: _busy(window, quiet=dark) for h in _HOSTS[:5]})
    sweep = await _sweep(maker, es)

    assert sweep.errors == ()
    assert not any(r.departures for r in sweep.results), [r.note for r in sweep.results]
    assert any("collapsed on most hosts at once" in note for note in sweep.notes), sweep.notes
    assert await _observations(maker) == 0
    async with maker() as db:
        rows = await grid_gaps.overlapping(
            db, since=window[0] - timedelta(hours=1), until=datetime.now(UTC)
        )
    (gap,) = rows
    assert gap.source == grid_gaps.SOURCE_SWEEP
    assert gap.plane == "connection_rate"
    assert gap.started_at == dark[0].replace(tzinfo=None)
    assert gap.ended_at == (dark[-1] + timedelta(hours=1)).replace(tzinfo=None)
    await engine.dispose()


async def test_a_read_only_sweep_records_no_gap(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    await _seed_hosts(maker, _HOSTS[:5])
    window = _window()
    es = _RatesES({h: _busy(window, quiet=window[-8:]) for h in _HOSTS[:5]})
    sweep = await _sweep(maker, es, record=False)
    assert not any(r.departures for r in sweep.results)
    async with maker() as db:
        rows = await grid_gaps.overlapping(
            db, since=window[0] - timedelta(hours=1), until=datetime.now(UTC)
        )
    assert rows == []
    await engine.dispose()


async def test_one_host_that_goes_quiet_while_the_others_talk_is_still_a_departure(
    settings_kratos: Settings,
) -> None:
    """The negative control: the grid-dark rule must not swallow a real collapse."""
    engine, maker = await _db(settings_kratos)
    await _seed_hosts(maker, _HOSTS[:5])
    window = _window()
    quiet = window[-8:]
    hourly = {h: _busy(window) for h in _HOSTS[1:5]}
    hourly[_HOSTS[0]] = _busy(window, quiet=quiet)
    sweep = await _sweep(maker, _RatesES(hourly))

    (host,) = [r for r in sweep.results if r.entity_key == _HOSTS[0]]
    assert host.departures, host.note
    assert not any(r.departures for r in sweep.results if r.entity_key != _HOSTS[0])
    assert not any("collapsed on most hosts" in note for note in sweep.notes)
    assert await _observations(maker) >= 1
    async with maker() as db:
        evidence = (await db.scalars(select(EntityObservation.evidence_json))).all()
    # The run the departure covers: the self-healing hold reads it.
    assert all("window" in e for e in evidence), evidence
    async with maker() as db:
        rows = await grid_gaps.overlapping(
            db, since=window[0] - timedelta(hours=1), until=datetime.now(UTC)
        )
    assert rows == []
    await engine.dispose()


async def test_two_dark_hosts_are_below_the_host_floor_and_stay_departures(
    settings_kratos: Settings,
) -> None:
    """Two of two dark hosts is a share of 1.0 and still under the floor of three."""
    engine, maker = await _db(settings_kratos)
    await _seed_hosts(maker, _HOSTS[:2])
    window = _window()
    es = _RatesES({h: _busy(window, quiet=window[-8:]) for h in _HOSTS[:2]})
    sweep = await _sweep(maker, es, record=False)
    assert sum(1 for r in sweep.results if r.departures) == 2
    await engine.dispose()


async def test_three_dark_hosts_of_six_are_under_the_share_and_stay_departures(
    settings_kratos: Settings,
) -> None:
    """Three of six is a share of 0.5, under the bar of 0.6."""
    engine, maker = await _db(settings_kratos)
    await _seed_hosts(maker, _HOSTS[:6])
    window = _window()
    quiet = window[-8:]
    hourly = {h: _busy(window, quiet=quiet) for h in _HOSTS[:3]}
    hourly.update({h: _busy(window) for h in _HOSTS[3:6]})
    sweep = await _sweep(maker, _RatesES(hourly), record=False)
    assert sum(1 for r in sweep.results if r.departures) == 3
    await engine.dispose()


# ── The rate baseline does not learn the gap hours ──────────────────────────


def _row(counts: list[Any], start: datetime) -> Any:
    from soc_ai.store.entity_profiles import ProfileRow

    return ProfileRow(
        entity_kind="host",
        entity_key=_HOSTS[0],
        dimension="connection_rate",
        shape="numeric",
        vector={"hourly": {"start": start.isoformat(), "counts": counts}},
        coverage="measured",
        coverage_reason=None,
        support_days=14,
        role=None,
        role_confidence=None,
        identity_fingerprint=None,
        window_days=30,
        first_seen=None,
        last_seen=None,
        built_at=None,
    )


def _evaluate(row: Any, recent: dict[str, Any], **kw: Any) -> Any:
    from soc_ai.hunting.priors import evaluate_prior

    return evaluate_prior(
        _COLLAPSE["prior-under-test"],
        profile=row,
        observed=recent,
        role=None,
        role_confidence=None,
        tz="UTC",
        **kw,
    )


def test_a_rate_baseline_leaves_out_the_gap_hours() -> None:
    """A week of zeros halves the expected count. Named as a gap, it is left out."""
    now = datetime.now(UTC).replace(minute=0, second=0, microsecond=0)
    start = now - timedelta(days=15)
    # One busy week, then one week the grid held nothing for.
    counts: list[Any] = [500] * (7 * 24) + [0] * (7 * 24)
    gap = (start + timedelta(days=7), start + timedelta(days=14))
    recent = {
        (now - timedelta(hours=n)).isoformat(): {"count": 100, "sample_ids": []} for n in (3, 2)
    }
    learned_zeros = _evaluate(_row(counts, start), recent)
    assert learned_zeros.departures == ()
    named = _evaluate(_row(counts, start), recent, gaps=[gap])
    assert named.departures, named.note


def test_a_null_hour_in_the_series_is_missing_and_never_a_zero() -> None:
    """The profile build writes null for an hour inside a gap."""
    now = datetime.now(UTC).replace(minute=0, second=0, microsecond=0)
    start = now - timedelta(days=15)
    counts: list[Any] = [500] * (7 * 24) + [None] * (7 * 24)
    recent = {
        (now - timedelta(hours=n)).isoformat(): {"count": 100, "sample_ids": []} for n in (3, 2)
    }
    assert _evaluate(_row(counts, start), recent).departures
