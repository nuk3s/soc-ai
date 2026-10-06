"""Detector 2, the logon chain, against a synthetic grid.

The grid is tests/replay_grid.py's LogonGrid: logon documents, each an sshd
line or a Windows 4624 or 4625. The estate learns 30 days of daily sessions:

* the jump host 192.0.2.10 opens sessions on web-01, db-01 and nas-01;
* web-01 opens sessions on backup-01.

The plant, on the Wednesday at 11:20 UTC: a session from the jump host lands
on web-01, and four minutes later web-01 tries db-01, which it never reached.

The twins that must stay quiet: web-01 to backup-01, a host already in its
edge set; the same attempt to db-01 outside ``chain_minutes``; an attempt to
db-01 that web-01 made before the session; an attempt back to the host the
session came from.

Every address is from the documentation ranges.
"""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime, timedelta
from typing import Any

from soc_ai.config import Settings
from soc_ai.hunting.detectors.base import DetectorContext
from soc_ai.hunting.detectors.logon_chain import detect
from soc_ai.hunting.detectors.params import LogonChainParams
from soc_ai.hunting.prior_sweep import run_prior_sweep
from soc_ai.hunting.spec import CATALOG_DIR, load_catalog
from soc_ai.so_client.oql import parse_oql, validate_oql
from soc_ai.store.models import EntityObservation
from sqlalchemy import select

from tests.replay_grid import HOUR, Logon, LogonGrid
from tests.test_prior_sweep import _db

# A Wednesday noon, UTC.
ANCHOR = datetime(2026, 9, 9, 12, tzinfo=UTC)
CIDRS = (ipaddress.ip_network("192.0.2.0/24"),)
SPEC_ID = "model-logon-chain"

JUMP = "192.0.2.10"
WEB, DB, BACKUP = "192.0.2.12", "192.0.2.13", "192.0.2.14"
WS, SRV = "192.0.2.15", "192.0.2.16"
SESSION_AT = ANCHOR.replace(hour=11, minute=20)


def _at(hour: int, minute: int) -> datetime:
    return ANCHOR.replace(hour=hour, minute=minute)


def _history(days: int = 30) -> list[Logon]:
    """One session a day on each learned edge, at 09:00, for ``days`` days."""
    out: list[Logon] = []
    for n in range(1, days + 1):
        day = (ANCHOR - timedelta(days=n)).replace(hour=9, minute=0)
        out += [
            Logon(f"h{n}-jump-web", day, "web-01", JUMP, [WEB]),
            Logon(f"h{n}-jump-db", day, "db-01", JUMP, [DB]),
            Logon(f"h{n}-jump-nas", day, "nas-01", JUMP, []),
            Logon(f"h{n}-web-backup", day + timedelta(minutes=5), "backup-01", WEB, [BACKUP]),
            Logon(f"h{n}-jump-ws", day, "ws-01", JUMP, [WS], windows=True, logon_type="10"),
            Logon(f"h{n}-jump-srv", day, "srv-01", JUMP, [SRV], windows=True, logon_type="3"),
        ]
    return out


def _session() -> Logon:
    return Logon("p-session", SESSION_AT, "web-01", JUMP, [WEB])


def _attempt(at: datetime, *, doc_id: str = "p-attempt", target: str = "db-01") -> Logon:
    ip = {"db-01": DB, "backup-01": BACKUP}[target]
    return Logon(doc_id, at, target, WEB, [ip], outcome="invalid")


def _plant() -> list[Logon]:
    return [
        *_history(),
        _session(),
        _attempt(_at(11, 24)),
        # Twin: backup-01 is in the edge set of web-01.
        Logon("t-backup", _at(11, 25), "backup-01", WEB, [BACKUP]),
    ]


class _Settings:
    events_index_pattern = "logs-*"
    so_timezone = "UTC"


async def _detect(logons: list[Logon], *, now: datetime = ANCHOR, **params: Any) -> Any:
    grid = LogonGrid(logons=logons, clock=now)
    ctx = DetectorContext(
        elastic=grid, settings=_Settings(), db=None, now=now, tz="UTC", cidrs=CIDRS
    )
    return await detect(LogonChainParams(**params), ctx)


def _state(run: Any, name: str) -> Any:
    return next(e for e in run.entities if e.entity_key == name)


def _fired(run: Any) -> list[tuple[str, str]]:
    return [(e.entity_key, h.features["attempt_target"]) for e in run.entities for h in e.hits]


# ---------------------------------------------------------------------------
# The plant and its twins
# ---------------------------------------------------------------------------


async def test_a_session_then_a_first_attempt_to_a_new_host_fires() -> None:
    run = await _detect(_plant())
    web = _state(run, "web-01")

    assert web.state == "measured"
    (hit,) = web.hits
    assert hit.kind.value == "logon_chain"
    assert hit.fingerprint == ("logon_chain", "db-01")
    assert hit.document_ids == ("p-session", "p-attempt")
    assert hit.statistic == "chain_minutes"
    assert hit.statistic_value == 4.0
    # The edge set of web-01 held one outbound edge: backup-01.
    assert hit.baseline_value == 1.0
    assert hit.observed_at == _at(11, 24)
    assert hit.features["attempt_outcome"] == "failed"
    assert hit.features["protocol"] == "SSH"
    assert hit.rerun_query is not None
    assert f'source.ip:"{WEB}"' in hit.rerun_query
    validate_oql(parse_oql(hit.rerun_query))
    assert hit.reason == (
        "web-01 received a session from 192.0.2.10 at 11:20 UTC. 4 minutes later web-01 "
        "made its first SSH attempt to db-01, and the attempt was failed. The learned edge "
        "set of web-01 held 1 outbound edge over 30 days."
    )
    assert _fired(run) == [("web-01", "db-01")]


async def test_an_attempt_to_a_host_in_the_edge_set_is_quiet() -> None:
    """The twin: web-01 reaches backup-01 every day."""
    logons = [*_history(), _session(), Logon("t-backup", _at(11, 25), "backup-01", WEB, [BACKUP])]
    run = await _detect(logons)
    assert _fired(run) == []
    assert _state(run, "web-01").state == "measured"


async def test_a_chain_outside_chain_minutes_is_quiet() -> None:
    """The twin: the attempt comes 50 minutes after the session."""
    logons = [
        *_history(),
        Logon("t-early-session", _at(10, 30), "web-01", JUMP, [WEB]),
        _attempt(_at(11, 20)),
    ]
    run = await _detect(logons)
    assert _fired(run) == []


async def test_the_same_chain_inside_chain_minutes_fires() -> None:
    """Negative control for the twin above: the same documents ten minutes
    apart fire, so the gap is what kept the twin quiet."""
    logons = [
        *_history(),
        Logon("t-early-session", _at(10, 30), "web-01", JUMP, [WEB]),
        _attempt(_at(10, 40)),
    ]
    run = await _detect(logons)
    assert _fired(run) == [("web-01", "db-01")]
    # The same twin fires at 50 minutes when the spec allows an hour.
    late = [*_history(), Logon("s", _at(10, 30), "web-01", JUMP, [WEB]), _attempt(_at(11, 20))]
    assert _fired(await _detect(late, chain_minutes=60)) == [("web-01", "db-01")]


async def test_an_attempt_made_before_the_session_is_not_a_first_attempt() -> None:
    logons = [
        *_history(),
        _attempt(_at(10, 30), doc_id="t-before"),
        _session(),
        _attempt(_at(11, 24)),
    ]
    run = await _detect(logons)
    assert _fired(run) == []


async def test_an_attempt_back_to_the_session_source_is_not_a_third_host() -> None:
    logons = [
        *_history(),
        Logon("t-from-db", SESSION_AT, "web-01", DB, [WEB]),
        _attempt(_at(11, 24)),
    ]
    run = await _detect(logons)
    assert _fired(run) == []


async def test_a_windows_chain_fires() -> None:
    """A 4624 of type 10 on ws-01, then a 4625 on srv-01 from ws-01."""
    logons = [
        *_history(),
        Logon("w-session", SESSION_AT, "ws-01", JUMP, [WS], windows=True, logon_type="10"),
        Logon("w-attempt", _at(11, 23), "srv-01", WS, [SRV], outcome="failed", windows=True),
    ]
    run = await _detect(logons)
    ws = _state(run, "ws-01")
    (hit,) = ws.hits
    assert hit.document_ids == ("w-session", "w-attempt")
    assert hit.features["protocol"] == "Windows remote logon"
    assert hit.baseline_value == 0.0


# ---------------------------------------------------------------------------
# The states
# ---------------------------------------------------------------------------


async def test_an_edge_set_under_fourteen_days_is_learning() -> None:
    logons = [*_history(days=5), _session(), _attempt(_at(11, 24))]
    run = await _detect(logons)
    assert _fired(run) == []
    assert _state(run, "web-01").state == "learning"


async def test_a_host_with_no_known_address_is_unmeasurable() -> None:
    run = await _detect(_plant())
    nas = _state(run, "nas-01")
    assert nas.state == "unmeasurable"


async def test_a_grid_with_no_logon_plane_is_blind() -> None:
    run = await _detect([])
    assert run.blind is not None
    assert run.entities == ()


# ---------------------------------------------------------------------------
# Through the sweep, with the shipped spec
# ---------------------------------------------------------------------------


def _shipped() -> dict[str, Any]:
    return {SPEC_ID: load_catalog(CATALOG_DIR)[SPEC_ID]}


async def test_the_sweep_writes_the_chain_and_notes_every_state(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _db(settings_kratos)
    grid = LogonGrid(logons=_plant(), clock=ANCHOR)
    async with maker() as db:
        sweep = await run_prior_sweep(
            elastic=grid,
            settings=_Settings(),
            db=db,
            catalog=_shipped(),
            # The shipped detector declares ships_as shadow, so the effective
            # catalog hands the sweep its id here.
            shadow_ids=frozenset({"model-logon-chain"}),
            record=True,
            cidrs=CIDRS,
            now=ANCHOR,
        )
        rows = (await db.execute(select(EntityObservation))).scalars().all()
    await engine.dispose()

    assert sweep.errors == ()
    assert (
        f"{SPEC_ID}: entity states: measured 5, learning 0, blind 0, unmeasurable 1, "
        "stale 0, drifted 0, held 0."
    ) in sweep.notes
    (row,) = rows
    assert (row.entity_key, row.source, row.shadow, row.kind) == (
        "web-01",
        "model",
        True,
        "logon_chain",
    )
    assert (row.statistic, row.statistic_value, row.baseline_value) == ("chain_minutes", 4.0, 1.0)
    assert row.document_ids == ["p-session", "p-attempt"]
    assert row.rerun_query
    assert row.observed_at == _at(11, 24).replace(tzinfo=None)


async def test_a_replayed_day_fires_on_the_plant_only(settings_kratos: Settings) -> None:
    """Hour by hour over the Wednesday, through the sweep, with every twin planted."""
    logons = [
        *_plant(),
        # The twin outside chain_minutes, on its own pair of hosts: a session
        # on db-01, and 50 minutes later db-01 tries backup-01 for the first time.
        Logon("t-early-session", _at(6, 30), "db-01", JUMP, [DB]),
        Logon("t-late-attempt", _at(7, 20), "backup-01", DB, [BACKUP], outcome="failed"),
    ]
    engine, maker = await _db(settings_kratos)
    grid = LogonGrid(logons=logons, clock=ANCHOR)
    start = ANCHOR.replace(hour=0)
    fires: list[tuple[datetime, str, str]] = []
    errors: list[str] = []
    for step in range(24):
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
        fires.extend(
            (now, r.entity_key, h.features["attempt_target"]) for r in sweep.fired for h in r.hits
        )
    async with maker() as db:
        rows = (await db.execute(select(EntityObservation))).scalars().all()
    await engine.dispose()

    assert errors == []
    # The read covers two hours and the chain window. The sweeps at 12:00 and
    # 13:00 hold both documents of the plant.
    assert [(at.hour, b, c) for at, b, c in fires] == [
        (12, "web-01", "db-01"),
        (13, "web-01", "db-01"),
    ]
    assert [(r.entity_key, r.kind) for r in rows] == [("web-01", "logon_chain")]
    print(
        f"\nreplay: 24 sweeps, {grid.searches} grid searches. "
        f"Plant fires: {len(fires)}. Twin fires: 0. Observations: {len(rows)}."
    )
