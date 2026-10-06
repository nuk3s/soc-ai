"""A deterministic replay of tier 2: seven days, hour by hour, with planted departures.

The design asks for this before any statistic moves: a replay over seven
days with planted departures, where every plant fires and every twin stays
quiet. No model runs, so one run per hour is enough.

The grid is synthetic (tests/replay_grid.py). The build is the real profile
job, run at the start of each replayed day. The sweep is the real prior
sweep with every shipped profile analytic, run at each replayed hour through
its time anchor, recording observations and forming leads.

The estate: nine declared servers on 192.0.2.0/24, with 35 days of history
before the replay. The plants and their twins:

=====  ================================================  =======================
Plant  What happens                                       Twin that must stay quiet
=====  ================================================  =======================
P1     A, a flat host, bursts to 10 times its rate for     B bursts the same, on the
       four hours on the Wednesday afternoon               Monday morning it always
                                                           bursts on
P2     C opens outbound port 4444, which no host uses      D opens 8443, which three
                                                           other servers use daily
P3     H, at 200 flows an hour, stops for four hours       K, at 2 flows an hour,
                                                           stops for the same hours
=====  ================================================  =======================

Every other host must stay quiet on every analytic for all seven days.
"""

from __future__ import annotations

import ipaddress
from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from soc_ai.config import Settings
from soc_ai.dossier.profile_job import build_profiles
from soc_ai.hunting.prior_sweep import run_prior_sweep
from soc_ai.hunting.spec import CATALOG_DIR, load_catalog
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import EntityObservation, HostDossier, HostDossierField, Lead
from sqlalchemy import select

from tests.replay_grid import HOUR, SyntheticGrid, SyntheticHost

pytestmark = pytest.mark.asyncio

# A Monday. The replay runs from here for seven days.
START = datetime(2026, 9, 7, tzinfo=UTC)
HISTORY = START - timedelta(days=35)
CIDRS = [ipaddress.ip_network("192.0.2.0/24")]

A, B, C, D, E, F, G, H, K = (f"192.0.2.{n}" for n in range(11, 20))

# The plant windows, in the replayed week.
P1_BURST = (START + timedelta(days=2, hours=14), START + timedelta(days=2, hours=18))
P2_PORT = (START + timedelta(days=3, hours=10), START + timedelta(days=3, hours=13))
P3_SILENCE = (START + timedelta(days=4, hours=8), START + timedelta(days=4, hours=12))


def _inside(at: datetime, window: tuple[datetime, datetime]) -> bool:
    return window[0] <= at < window[1]


def _jitter(at: datetime) -> int:
    """A deterministic wobble of five flows either way."""
    n = int(at.timestamp() // 3600)
    return (n * 7) % 11 - 5


def _flat(base: int) -> Any:
    return lambda at: base + _jitter(at)


def _burst_a(at: datetime) -> int:
    return 1000 if _inside(at, P1_BURST) else 100 + _jitter(at)


def _monday_b(at: datetime) -> int:
    return 1000 if at.weekday() == 0 and 9 <= at.hour < 13 else 100 + _jitter(at)


def _silent_h(at: datetime) -> int:
    return 0 if _inside(at, P3_SILENCE) else 200 + _jitter(at)


def _silent_i(at: datetime) -> int:
    return 0 if _inside(at, P3_SILENCE) else 2


def _ports(extra: Any = None) -> Any:
    """The ports every server uses every hour, and any extra ones."""

    def ports(at: datetime) -> dict[str, int]:
        out = {"443": 4, "53": 2}
        if extra is not None:
            out.update(extra(at))
        return out

    return ports


def _estate() -> list[SyntheticHost]:
    common = _ports(lambda at: {"8443": 3})
    return [
        SyntheticHost(A, _burst_a, _ports(), HISTORY),
        SyntheticHost(B, _monday_b, _ports(), HISTORY),
        SyntheticHost(
            C, _flat(100), _ports(lambda at: {"4444": 6} if _inside(at, P2_PORT) else {}), HISTORY
        ),
        SyntheticHost(
            D, _flat(100), _ports(lambda at: {"8443": 6} if _inside(at, P2_PORT) else {}), HISTORY
        ),
        SyntheticHost(E, _flat(100), common, HISTORY),
        SyntheticHost(F, _flat(100), common, HISTORY),
        SyntheticHost(G, _flat(100), common, HISTORY),
        SyntheticHost(H, _silent_h, _ports(), HISTORY),
        SyntheticHost(K, _silent_i, _ports(), HISTORY),
    ]


class _Settings:
    events_index_pattern = "logs-*"
    so_timezone = "UTC"
    entity_profiles_enabled = True
    entity_profile_window_days = 30
    entity_profile_lag_hours = 24
    profile_estate_rare_hosts = 3
    profile_estate_common_share = 0.2


async def _declare_servers(maker: Any, keys: list[str]) -> None:
    async with maker() as db:
        for key in keys:
            host = HostDossier(host_key=key, ip=key)
            db.add(host)
            await db.flush()
            db.add(
                HostDossierField(
                    dossier_id=host.id,
                    field="role",
                    operator_value="server",
                    operator_set_at=START.replace(tzinfo=None),
                )
            )
        await db.commit()


async def _replay(settings_kratos: Settings) -> dict[str, Any]:
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    maker = make_sessionmaker(engine)
    hosts = _estate()
    await _declare_servers(maker, [h.ip for h in hosts])
    grid = SyntheticGrid(hosts=hosts, clock=START)
    settings = _Settings()
    catalog = {k: v for k, v in load_catalog(CATALOG_DIR).items() if v.evaluator == "profile"}

    fires: list[tuple[datetime, str, str, Any]] = []
    errors: list[str] = []
    builds = 0
    sweeps = 0
    for step in range(7 * 24):
        now = START + step * HOUR
        grid.clock = now
        if now.hour == 0:
            build = await build_profiles(grid, maker, settings, CIDRS)
            errors.extend(build.errors)
            builds += 1
        async with maker() as db:
            sweep = await run_prior_sweep(
                elastic=grid,
                settings=settings,
                db=db,
                catalog=catalog,
                record=True,
                cidrs=CIDRS,
                now=now,
            )
        sweeps += 1
        errors.extend(sweep.errors)
        for result in sweep.fired:
            for departure in result.departures:
                fires.append((now, result.spec_id, result.entity_key, departure))

    async with maker() as db:
        observations = (await db.execute(select(EntityObservation))).scalars().all()
        leads = (await db.execute(select(Lead))).scalars().all()
    await engine.dispose()
    return {
        "fires": fires,
        "errors": errors,
        "builds": builds,
        "sweeps": sweeps,
        "observations": observations,
        "leads": leads,
        "searches": grid.searches,
    }


_PLANTS = {
    ("profile-connection-rate-spiked", A),
    ("prior-server-internet-nonweb-novel-port", C),
    ("profile-connection-rate-collapsed", H),
}


async def test_the_planted_departures_fire_and_their_twins_do_not(
    settings_kratos: Settings,
) -> None:
    run = await _replay(settings_kratos)
    fires = run["fires"]
    assert run["errors"] == [], run["errors"][:5]
    assert (run["builds"], run["sweeps"]) == (7, 168)

    by_pair = Counter((spec, host) for _at, spec, host, _d in fires)

    # P1: the burst fires from the first sweep that holds a whole hour of it.
    # One hour at ten times the expected count is twice past the bar.
    p1 = [
        (at, d)
        for at, spec, host, d in fires
        if (spec, host) == ("profile-connection-rate-spiked", A)
    ]
    assert p1, "the four-hour burst on the flat host did not fire"
    first_p1 = min(at for at, _d in p1)
    assert first_p1 == P1_BURST[0] + HOUR
    assert {d.run_start for _at, d in p1} >= {P1_BURST[0]}
    assert all(d.statistic == "residual_z" and d.statistic_value >= 3.0 for _at, d in p1)

    # P2: the port no host uses fires, estate-rare.
    p2 = [
        d
        for _at, spec, host, d in fires
        if (spec, host) == ("prior-server-internet-nonweb-novel-port", C)
    ]
    assert p2, "the estate-rare port did not fire"
    assert {d.member for d in p2} == {"4444"}
    assert all(d.estate_rare and d.estate_hosts == 0 for d in p2)

    # P3: the busy host that stopped fires a collapse.
    p3 = [
        (at, d)
        for at, spec, host, d in fires
        if (spec, host) == ("profile-connection-rate-collapsed", H)
    ]
    assert p3, "the silence of the busy host did not fire"
    assert min(at for at, _d in p3) == P3_SILENCE[0] + HOUR

    # The twins.
    assert by_pair[("profile-connection-rate-spiked", B)] == 0, "the Monday burst fired"
    assert by_pair[("prior-server-internet-nonweb-novel-port", D)] == 0, "the common port fired"
    assert by_pair[("profile-connection-rate-collapsed", K)] == 0, "the quiet host fired"

    # Nothing else fired, on any analytic, on any host, on any day.
    stray = {pair: n for pair, n in by_pair.items() if pair not in _PLANTS}
    assert stray == {}, stray

    # The observations carry their evidence.
    rows = [o for o in run["observations"] if o.source == "profile"]
    assert {(o.kind, o.entity_key) for o in rows} == {
        ("above_baseline", A),
        ("novel_consumed_port", C),
        ("below_baseline", H),
    }
    for row in rows:
        assert row.statistic is not None and row.statistic_value is not None
        assert row.rerun_query
        assert row.observed_at is not None or row.kind == "below_baseline"
    port = next(o for o in rows if o.kind == "novel_consumed_port")
    assert port.birth_weight == 0.6

    hosts = 9
    print(
        f"\nreplay: {run['sweeps']} sweeps and {run['builds']} builds over 7 days, "
        f"{run['searches']} grid searches. "
        f"Fires per plant: P1 {len(p1)}, P2 {len(p2)}, P3 {len(p3)}. "
        f"Twins: 0. Stray fires: 0 in {hosts * 7} host-days. "
        f"Observations: {len(rows)}. Leads: {len(run['leads'])}."
    )
