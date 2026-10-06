"""Detector 1, cross-plane telemetry silence, against a synthetic grid.

The grid is tests/replay_grid.py's PlaneGrid: a count per hour per dataset
for each machine, and the sensor's flows. The anchor is a Sunday noon. The
plant and its twins:

=====  =============================================  =================
Host   What happens on the Sunday 09:00 to 12:00 UTC   Expected
=====  =============================================  =================
A      the process events stop, the rest keeps going   fires
B      every plane stops: the machine is off           quiet, measured
C      the process events stop, as every weekend       quiet, measured
D      ships host logs only                            unmeasurable
E      two planes, born three days ago                 learning
F      nothing                                         quiet, measured
=====  =============================================  =================

Every address is from the documentation ranges.
"""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime, timedelta
from typing import Any

from soc_ai.config import Settings
from soc_ai.hunting.detectors.base import DetectorContext
from soc_ai.hunting.detectors.params import CrossPlaneSilenceParams
from soc_ai.hunting.detectors.plane_silence import detect
from soc_ai.hunting.prior_sweep import run_prior_sweep
from soc_ai.hunting.spec import CATALOG_DIR, load_catalog
from soc_ai.so_client.oql import parse_oql, validate_oql
from soc_ai.store.models import EntityObservation
from sqlalchemy import select

from tests.replay_grid import HOUR, PlaneGrid, PlaneHost
from tests.test_prior_sweep import _db

# A Sunday noon, UTC.
ANCHOR = datetime(2026, 9, 13, 12, tzinfo=UTC)
BORN = ANCHOR - timedelta(days=40)
PLANT = (ANCHOR - timedelta(hours=3), ANCHOR)
CIDRS = (ipaddress.ip_network("192.0.2.0/24"),)
SPEC_ID = "model-cross-plane-silence"


def _jitter(at: datetime) -> int:
    n = int(at.timestamp() // 3600)
    return (n * 7) % 11 - 5


def _flat(base: int, *, off: tuple[datetime, datetime] | None = None) -> Any:
    def count(at: datetime) -> int:
        if off is not None and off[0] <= at < off[1]:
            return 0
        return base + _jitter(at)

    return count


def _weekdays(base: int) -> Any:
    """A plane that stops every weekend."""
    return lambda at: 0 if at.weekday() >= 5 else base + _jitter(at)


def _estate() -> list[PlaneHost]:
    return [
        PlaneHost(
            "app-01",
            ["192.0.2.21"],
            {"system.syslog": _flat(100), "endpoint.events.process": _flat(200, off=PLANT)},
            flows=_flat(300),
            born=BORN,
        ),
        PlaneHost(
            "app-02",
            ["192.0.2.22"],
            {
                "system.syslog": _flat(100, off=PLANT),
                "endpoint.events.process": _flat(200, off=PLANT),
            },
            flows=_flat(300, off=PLANT),
            born=BORN,
        ),
        PlaneHost(
            "app-03",
            ["192.0.2.23"],
            {"system.syslog": _flat(100), "endpoint.events.process": _weekdays(200)},
            flows=_flat(300),
            born=BORN,
        ),
        PlaneHost("app-04", ["192.0.2.24"], {"system.syslog": _flat(100)}, born=BORN),
        PlaneHost(
            "app-05",
            ["192.0.2.25"],
            {"system.syslog": _flat(100), "endpoint.events.process": _flat(200)},
            born=ANCHOR - timedelta(days=3),
        ),
        PlaneHost(
            "app-06",
            ["192.0.2.26"],
            {"system.syslog": _flat(100), "endpoint.events.process": _flat(200)},
            flows=_flat(300),
            born=BORN,
        ),
    ]


class _Settings:
    events_index_pattern = "logs-*"
    so_timezone = "UTC"


def _ctx(grid: PlaneGrid, *, now: datetime = ANCHOR) -> DetectorContext:
    return DetectorContext(
        elastic=grid, settings=_Settings(), db=None, now=now, tz="UTC", cidrs=CIDRS
    )


async def _detect(hosts: list[PlaneHost], **params: Any) -> Any:
    grid = PlaneGrid(hosts=hosts, clock=ANCHOR)
    run = await detect(CrossPlaneSilenceParams(**params), _ctx(grid))
    return run, grid


def _state(run: Any, name: str) -> Any:
    return next(e for e in run.entities if e.entity_key == name)


# ---------------------------------------------------------------------------
# The plant and its twins
# ---------------------------------------------------------------------------


async def test_a_silent_plane_beside_a_live_one_fires_and_cites_both() -> None:
    run, _grid = await _detect(_estate())
    a = _state(run, "app-01")

    assert a.state == "measured"
    (hit,) = a.hits
    assert hit.fingerprint == ("cross_plane_silence", "process")
    assert hit.kind.value == "telemetry_silence"
    assert hit.statistic == "plane_documents"
    assert hit.statistic_value == 0.0
    assert hit.baseline_value is not None and hit.baseline_value > 500
    assert hit.features["silent_plane"] == "process"
    assert hit.features["silent_hours"] == 3
    # The live plane that held best: the sensor's flows at 300 an hour.
    assert hit.features["live_plane"] == "network_flows"
    # The newest process document before the silence, and a flow inside it.
    assert hit.document_ids == (
        "app-01-endpoint.events.process-2026091308",
        "app-01-zeek.conn-2026091311",
    )
    assert hit.observed_at == ANCHOR - timedelta(minutes=10)
    assert hit.rerun_query is not None
    assert '(host.name:"app-01" OR source.ip:"192.0.2.21")' in hit.rerun_query
    validate_oql(parse_oql(hit.rerun_query))
    assert hit.reason.startswith("The process events of app-01 fell to 0 documents in 3 hours.")
    assert "The network flows of app-01 held" in hit.reason


async def test_a_machine_whose_every_plane_fell_is_quiet() -> None:
    """The twin: the machine is off. No plane is live, so nothing fires."""
    run, _grid = await _detect(_estate())
    b = _state(run, "app-02")
    assert b.state == "measured"
    assert b.hits == ()


async def test_a_plane_that_always_dips_at_the_weekend_is_quiet() -> None:
    """The twin: the process plane of C stops every weekend, so its baseline
    expects nothing on a Sunday morning."""
    run, _grid = await _detect(_estate())
    c = _state(run, "app-03")
    assert c.state == "measured"
    assert c.hits == ()


async def test_the_same_dip_on_a_weekday_fires() -> None:
    """Negative control for the twin above. The guard reads the baseline of
    the hour, so the same stop on a Wednesday, when C always runs, fires."""
    wednesday = ANCHOR - timedelta(days=4)
    off = (wednesday - timedelta(hours=3), wednesday)
    host = PlaneHost(
        "app-03",
        ["192.0.2.23"],
        {"system.syslog": _flat(100), "endpoint.events.process": _flat(200, off=off)},
        flows=_flat(300),
        born=BORN,
    )
    grid = PlaneGrid(hosts=[host], clock=wednesday)
    run = await detect(CrossPlaneSilenceParams(), _ctx(grid, now=wednesday))
    (c,) = run.entities
    assert [h.features["silent_plane"] for h in c.hits] == ["process"]


async def test_a_machine_with_one_plane_is_unmeasurable() -> None:
    run, _grid = await _detect(_estate())
    d = _state(run, "app-04")
    assert d.state == "unmeasurable"
    assert "one plane" in d.note


async def test_a_machine_with_under_seven_days_of_history_is_learning() -> None:
    run, _grid = await _detect(_estate())
    e = _state(run, "app-05")
    assert e.state == "learning"
    assert e.hits == ()


async def test_a_quiet_machine_is_measured_and_says_nothing_departed() -> None:
    run, _grid = await _detect(_estate())
    f = _state(run, "app-06")
    assert (f.state, f.hits, f.note) == ("measured", (), "Nothing departed.")


async def test_a_single_silent_hour_does_not_fire() -> None:
    """Two hours in a row, by default. One hour is an agent restart."""
    off = (ANCHOR - timedelta(hours=1), ANCHOR)
    host = PlaneHost(
        "app-01",
        ["192.0.2.21"],
        {"system.syslog": _flat(100), "endpoint.events.process": _flat(200, off=off)},
        born=BORN,
    )
    run, _grid = await _detect([host])
    assert run.entities[0].hits == ()
    # The same hour fires when the spec asks for one.
    run, _grid = await _detect([host], min_silent_hours=1)
    assert len(run.entities[0].hits) == 1


# ---------------------------------------------------------------------------
# The grid condition and the join
# ---------------------------------------------------------------------------


def _fleet(n: int) -> list[PlaneHost]:
    return [
        PlaneHost(
            f"ws-{i:02d}",
            [f"192.0.2.{40 + i}"],
            {"system.syslog": _flat(100), "endpoint.events.process": _flat(200, off=PLANT)},
            born=BORN,
        )
        for i in range(n)
    ]


async def test_one_plane_silent_on_most_machines_is_held_as_a_grid_condition() -> None:
    run, _grid = await _detect(_fleet(4))
    assert {e.state for e in run.entities} == {"held"}
    assert all(e.hits == () for e in run.entities)
    assert any("fell silent on 4 of 4 machines at once" in n for n in run.notes), run.notes


async def test_two_machines_are_not_a_grid_condition() -> None:
    """Negative control: under grid_min_machines the silences are each machine's."""
    run, _grid = await _detect(_fleet(2))
    assert [len(e.hits) for e in run.entities] == [1, 1]
    assert {e.state for e in run.entities} == {"measured"}


async def test_an_address_two_machines_report_joins_neither() -> None:
    """A Docker bridge gateway sits on every Docker host. A flow from it is
    no one machine's flow."""
    hosts = _estate()
    hosts[0].ips.append("192.0.2.99")
    hosts[5].ips.append("192.0.2.99")
    _run, grid = await _detect(hosts)
    assert "192.0.2.99" not in grid.flow_sources
    assert "192.0.2.21" in grid.flow_sources
    assert "127.0.0.1" not in grid.flow_sources


async def test_a_grid_with_no_host_plane_is_blind() -> None:
    run, _grid = await _detect([])
    assert run.blind is not None
    assert run.entities == ()


# ---------------------------------------------------------------------------
# Through the sweep, with the shipped spec
# ---------------------------------------------------------------------------


def _shipped() -> dict[str, Any]:
    return {SPEC_ID: load_catalog(CATALOG_DIR)[SPEC_ID]}


async def test_the_sweep_writes_the_hit_and_notes_every_state(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    grid = PlaneGrid(hosts=_estate(), clock=ANCHOR)
    async with maker() as db:
        sweep = await run_prior_sweep(
            elastic=grid,
            settings=_Settings(),
            db=db,
            catalog=_shipped(),
            # The shipped detector declares ships_as shadow, so the effective
            # catalog hands the sweep its id here.
            shadow_ids=frozenset({"model-cross-plane-silence"}),
            record=True,
            cidrs=CIDRS,
            now=ANCHOR,
        )
        rows = (await db.execute(select(EntityObservation))).scalars().all()

    assert sweep.errors == ()
    assert (
        f"{SPEC_ID}: entity states: measured 4, learning 1, blind 0, unmeasurable 1, "
        "stale 0, drifted 0, held 0."
    ) in sweep.notes
    (row,) = rows
    assert (row.entity_key, row.source, row.shadow, row.kind) == (
        "app-01",
        "model",
        True,
        "telemetry_silence",
    )
    assert row.statistic == "plane_documents"
    assert row.statistic_value == 0.0
    assert row.baseline_value is not None
    assert row.document_ids == [
        "app-01-endpoint.events.process-2026091308",
        "app-01-zeek.conn-2026091311",
    ]
    assert row.rerun_query
    await engine.dispose()


async def test_a_replayed_weekend_fires_on_the_plant_only(settings_kratos: Settings) -> None:
    """Hour by hour from Saturday 00:00 to Monday 00:00, through the sweep."""
    engine, maker = await _db(settings_kratos)
    grid = PlaneGrid(hosts=_estate(), clock=ANCHOR)
    start = ANCHOR.replace(hour=0) - timedelta(days=1)
    fires: list[tuple[datetime, str]] = []
    errors: list[str] = []
    for step in range(48):
        now = start + step * HOUR
        grid.clock = now
        async with maker() as db:
            sweep = await run_prior_sweep(
                elastic=grid,
                settings=_Settings(),
                db=db,
                catalog=_shipped(),
                record=True,
                cidrs=CIDRS,
                now=now,
            )
        errors.extend(sweep.errors)
        fires.extend((now, r.entity_key) for r in sweep.fired)
    async with maker() as db:
        rows = (await db.execute(select(EntityObservation))).scalars().all()
    await engine.dispose()

    assert errors == []
    assert {name for _at, name in fires} == {"app-01"}
    # From the first sweep that holds two silent hours to the last one.
    assert min(at for at, _n in fires) == PLANT[0] + 2 * HOUR
    assert max(at for at, _n in fires) == PLANT[0] + 7 * HOUR
    assert len(fires) == 6
    assert [(r.entity_key, r.kind) for r in rows] == [("app-01", "telemetry_silence")]
    print(
        f"\nreplay: 48 sweeps, {grid.searches} grid searches. "
        f"Plant fires: {len(fires)}. Twin fires: 0. Observations: {len(rows)}."
    )
