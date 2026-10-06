"""The tier 2 upgrades to the prior sweep: the time anchor, the estate, the peers.

Every address here is from the documentation ranges. The fakes come from
tests/test_prior_sweep.py, so the sweep reads the same grid shapes there and
here.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from soc_ai.config import Settings
from soc_ai.hunting.prior_sweep import DEFAULT_RECENT_HOURS, run_prior_sweep
from soc_ai.store import entity_profiles as ep
from soc_ai.store.models import EntityObservation, HostDossier, HostDossierField
from sqlalchemy import select

from tests.test_prior_sweep import _db, _FakeES, _prior, _settings_like, _ShapedES

pytestmark = pytest.mark.asyncio

_SERVER = "192.0.2.10"


async def _declare(maker: Any, key: str, role: str) -> None:
    """An operator declares the role of one host."""
    async with maker() as db:
        host = HostDossier(host_key=key, ip=key)
        db.add(host)
        await db.flush()
        db.add(
            HostDossierField(
                dossier_id=host.id,
                field="role",
                operator_value=role,
                operator_set_at=datetime.now(UTC).replace(tzinfo=None),
            )
        )
        await db.commit()


async def _set(
    maker: Any,
    key: str,
    members: dict[str, Any],
    *,
    dimension: str = "served_ports",
    coverage: str = "measured",
) -> None:
    """A stored set for one host. A member maps to its entry or to a count."""
    vector = {str(m): (v if isinstance(v, dict) else {"count": int(v)}) for m, v in members.items()}
    async with maker() as db:
        await ep.upsert_profile(
            db,
            entity_kind="host",
            entity_key=key,
            dimension=dimension,
            shape="categorical",
            vector=vector,
            coverage=coverage,
            support_days=30,
        )


# ---------------------------------------------------------------------------
# The time anchor
# ---------------------------------------------------------------------------


async def test_the_recent_read_ends_at_the_time_anchor(settings_kratos: Settings) -> None:
    """A replay reads a past hour. The read had no anchor, so every replayed
    hour read the present."""
    engine, maker = await _db(settings_kratos)
    await _declare(maker, _SERVER, "network_device")
    await _set(maker, _SERVER, {"22": 40})

    anchor = datetime(2026, 9, 1, 12, tzinfo=UTC)
    es = _FakeES(recent={_SERVER: {"445": 3}})
    async with maker() as db:
        await run_prior_sweep(
            elastic=es,
            settings=_settings_like(settings_kratos),
            db=db,
            catalog=_prior(),
            now=anchor,
        )

    minutes = DEFAULT_RECENT_HOURS * 60
    assert es.windows, "the sweep made no windowed read"
    assert all(w.get("gte") == f"{anchor.isoformat()}||-{minutes}m" for w in es.windows), es.windows
    assert all(w.get("lte") == anchor.isoformat() for w in es.windows), es.windows
    await engine.dispose()


async def test_without_an_anchor_the_recent_read_is_relative_to_now(
    settings_kratos: Settings,
) -> None:
    """Negative control: the hourly loop passes no anchor and reads the present."""
    engine, maker = await _db(settings_kratos)
    await _declare(maker, _SERVER, "network_device")
    await _set(maker, _SERVER, {"22": 40})

    es = _FakeES(recent={_SERVER: {"445": 3}})
    async with maker() as db:
        await run_prior_sweep(
            elastic=es, settings=_settings_like(settings_kratos), db=db, catalog=_prior()
        )
    minutes = DEFAULT_RECENT_HOURS * 60
    assert es.windows
    assert all(w.get("gte") == f"now-{minutes}m" for w in es.windows), es.windows
    await engine.dispose()


async def test_an_anchored_sweep_records_its_observations_at_the_anchor(
    settings_kratos: Settings,
) -> None:
    """The observation and the lead read the replayed hour as their clock.
    Written at the wall clock, a replayed week decayed as one moment."""
    engine, maker = await _db(settings_kratos)
    await _declare(maker, _SERVER, "network_device")
    await _set(maker, _SERVER, {"22": 40})

    anchor = datetime(2026, 9, 1, 12, tzinfo=UTC)
    async with maker() as db:
        await run_prior_sweep(
            elastic=_FakeES(recent={_SERVER: {"445": 6}}),
            settings=_settings_like(settings_kratos),
            db=db,
            catalog=_prior(),
            record=True,
            now=anchor,
        )
        row = (await db.execute(select(EntityObservation))).scalars().one()

    assert row.born_at == anchor.replace(tzinfo=None)
    assert row.first_seen_at == anchor.replace(tzinfo=None)
    await engine.dispose()


# ---------------------------------------------------------------------------
# Estate prevalence
# ---------------------------------------------------------------------------


def _hosts(first: int, count: int) -> list[str]:
    return [f"192.0.2.{n}" for n in range(first, first + count)]


async def _sweep(
    maker: Any, settings: Settings, recent: dict[str, dict[str, int]], **kw: Any
) -> Any:
    async with maker() as db:
        return await run_prior_sweep(
            elastic=_FakeES(recent=recent),
            settings=_settings_like(settings),
            db=db,
            catalog=_prior(roles=[]),
            record=True,
            now=datetime(2026, 9, 1, 12, tzinfo=UTC),
            **kw,
        )


async def _rows(maker: Any) -> list[EntityObservation]:
    async with maker() as db:
        return list((await db.execute(select(EntityObservation))).scalars().all())


async def test_three_hosts_gaining_a_port_a_fourth_holds_read_its_prevalence(
    settings_kratos: Settings,
) -> None:
    """Three hosts gain port 4444 on the day a fourth already serves it. Each
    departure reads that one host held it, so each is estate-rare and born
    heavier. The spread is one condition on three hosts: each host gets a
    second observation that states the spread and the prevalence."""
    engine, maker = await _db(settings_kratos)
    gaining = _hosts(21, 3)
    holder = "192.0.2.24"
    for key in gaining:
        await _set(maker, key, {"22": 40})
    await _set(maker, holder, {"22": 40, "4444": 12})

    recent = {key: {"4444": 6} for key in gaining}
    recent[holder] = {"4444": 5}
    sweep = await _sweep(maker, settings_kratos, recent)

    fired = {r.entity_key: r.departures for r in sweep.fired}
    assert sorted(fired) == gaining
    for departures in fired.values():
        (d,) = departures
        assert (d.estate_hosts, d.estate_measured, d.estate_rare) == (1, 4, True)

    rows = await _rows(maker)
    novel = [r for r in rows if r.kind == "novel_served_port"]
    spread = [r for r in rows if r.kind == "scope_count"]
    assert sorted(r.entity_key for r in novel) == gaining
    assert {r.birth_weight for r in novel} == {0.6}
    assert {(r.statistic, r.statistic_value, r.baseline_value) for r in novel} == {
        ("estate_hosts", 1.0, 4.0)
    }
    assert sorted(r.entity_key for r in spread) == gaining
    assert {(r.statistic, r.statistic_value, r.baseline_value) for r in spread} == {
        ("hosts_departing", 3.0, 1.0)
    }
    assert spread[0].summary == (
        "3 hosts gained the served port 4444 in one sweep. 1 host held it before."
    )
    # The host that already served the port departs from nothing.
    assert holder not in {r.entity_key for r in rows}
    # Two types on each host form a lead. The span counts the three hosts.
    assert sweep.leads is not None
    assert len(sweep.leads.formed) == 3
    await engine.dispose()


async def test_a_port_no_other_host_holds_is_estate_rare_and_alone(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _db(settings_kratos)
    first, *others = _hosts(41, 4)
    for key in (first, *others):
        await _set(maker, key, {"22": 40})
    sweep = await _sweep(maker, settings_kratos, {first: {"31337": 6}})

    (result,) = sweep.fired
    (d,) = result.departures
    assert (d.estate_hosts, d.estate_measured, d.estate_rare) == (0, 4, True)
    assert "None of the 4 profiled hosts holds it" in result.note
    rows = await _rows(maker)
    assert [(r.kind, r.birth_weight) for r in rows] == [("novel_served_port", 0.6)]
    await engine.dispose()


async def test_a_port_most_of_the_estate_holds_forms_no_observation(
    settings_kratos: Settings,
) -> None:
    """Five of ten profiled hosts serve 8443. A sixth gains it: a trait of the
    estate, not a novelty. The note counts it, so the absence is stated."""
    engine, maker = await _db(settings_kratos)
    keys = _hosts(50, 10)
    for n, key in enumerate(keys):
        await _set(maker, key, {"22": 40, **({"8443": 9} if n < 5 else {})})
    newcomer = keys[-1]
    sweep = await _sweep(maker, settings_kratos, {newcomer: {"8443": 7}})

    assert sweep.fired == ()
    (result,) = [r for r in sweep.results if r.entity_key == newcomer]
    assert result.coverage == "measured"
    assert result.suppressed == 1
    assert "1 new member common across the estate formed no observation." in result.note
    assert await _rows(maker) == []
    await engine.dispose()


async def test_a_port_two_hosts_hold_is_still_a_departure(settings_kratos: Settings) -> None:
    """Negative control on the path the common rule would miss: two holders in
    an estate of five clear 20 % and stay below the rare bar of three hosts.
    One host is not a trait of the estate, and two are not either."""
    engine, maker = await _db(settings_kratos)
    keys = _hosts(70, 5)
    for n, key in enumerate(keys):
        await _set(maker, key, {"22": 40, **({"8443": 9} if n < 2 else {})})
    sweep = await _sweep(maker, settings_kratos, {keys[-1]: {"8443": 7}})

    (result,) = sweep.fired
    (d,) = result.departures
    assert (d.estate_hosts, d.estate_rare) == (2, True)
    assert result.suppressed == 0
    await engine.dispose()


async def test_a_set_at_the_cap_reports_no_novelty_and_says_set_full(
    settings_kratos: Settings,
) -> None:
    """A set at the cap holds the top 200 members by count. A member past the
    cut reads as new on every sweep, so the prior is blind there and says why."""
    engine, maker = await _db(settings_kratos)
    full, short = "192.0.2.80", "192.0.2.81"
    await _set(maker, full, {str(port): 3 for port in range(1000, 1200)})
    await _set(maker, short, {str(port): 3 for port in range(1000, 1199)})
    sweep = await _sweep(maker, settings_kratos, {full: {"4444": 6}, short: {"4444": 6}})

    by_key = {r.entity_key: r for r in sweep.results}
    assert by_key[full].coverage == "blind"
    assert by_key[full].departures == ()
    assert by_key[full].note == (
        "the baseline is full. It holds 200 values, the most it can hold. "
        "soc-ai cannot tell a new value from a value past that limit."
    )
    # Negative control: one member short of the cap still scores.
    assert by_key[short].coverage == "measured"
    assert [d.member for d in by_key[short].departures] == ["4444"]
    await engine.dispose()


async def test_the_prevalence_is_refreshed_only_after_a_newer_build(
    settings_kratos: Settings,
) -> None:
    from soc_ai.hunting.estate import ensure_estate, prevalence_for, refresh_estate

    engine, maker = await _db(settings_kratos)
    a, b = _hosts(90, 2)
    await _set(maker, a, {"22": 40, "445": 3})
    await _set(maker, b, {"22": 40})
    async with maker() as db:
        assert await ensure_estate(db) is not None
        assert await prevalence_for(db, "served_ports", ["22", "445", "9"]) == {"22": 2, "445": 1}
        # Nothing was built since. The second sweep reads the same table.
        assert await ensure_estate(db) is None
    await _set(maker, b, {"22": 40, "445": 3})
    async with maker() as db:
        assert await ensure_estate(db) is not None
        assert (await prevalence_for(db, "served_ports", ["445"]))["445"] == 2
        # The hook a build can call reads the same thing.
        done = await refresh_estate(db)
        assert done.hosts == 2
    await engine.dispose()


# ---------------------------------------------------------------------------
# The per-hour seasonal residual
# ---------------------------------------------------------------------------

_ANCHOR = datetime(2026, 9, 2, 22, 30, tzinfo=UTC)  # a Wednesday evening


async def _flat_rate(maker: Any, key: str, *, per_hour: int = 100) -> None:
    """Four weeks of the same count every hour, ending a day before the anchor."""
    start = (_ANCHOR - timedelta(days=29)).replace(minute=0)
    async with maker() as db:
        await ep.upsert_profile(
            db,
            entity_kind="host",
            entity_key=key,
            dimension="connection_rate",
            shape="numeric",
            vector={
                "work": {"median": float(per_hour), "dispersion": 0.0, "samples": 200},
                "hourly": {"start": start.isoformat(), "counts": [per_hour] * (28 * 24)},
            },
            coverage="measured",
            support_days=28,
        )


def _hours(counts: dict[int, int], *, usual: int = 100) -> list[tuple[str, int]]:
    """The recent hourly buckets of the anchor's day, from 00:00 UTC."""
    day = _ANCHOR.replace(hour=0, minute=0)
    return [
        ((day + timedelta(hours=h)).strftime("%Y-%m-%dT%H:00:00.000Z"), counts.get(h, usual))
        for h in range(22)
    ]


async def test_a_four_hour_burst_departs_through_the_sweep(settings_kratos: Settings) -> None:
    """The recent read returns every hour. The burst of four hours departs,
    and the observation cites the hours and queries exactly them."""
    engine, maker = await _db(settings_kratos)
    await _flat_rate(maker, _SERVER)
    es = _ShapedES(_SERVER, _hours({14: 1000, 15: 1000, 16: 1000, 17: 1000}))
    async with maker() as db:
        sweep = await run_prior_sweep(
            elastic=es,
            settings=_settings_like(settings_kratos),
            db=db,
            catalog=_prior(dimension="connection_rate", test="above", roles=[]),
            record=True,
            now=_ANCHOR,
        )
        row = (await db.execute(select(EntityObservation))).scalars().one()

    (result,) = sweep.fired
    (d,) = result.departures
    assert (d.run_hours, d.observed_value, d.baseline_median) == (4, 1000.0, 100.0)
    assert row.kind == "above_baseline"
    assert (row.statistic, row.statistic_value, row.baseline_value) == ("residual_z", 90.0, 100.0)
    assert row.rerun_query is not None
    assert '@timestamp:["2026-09-02T14:00:00Z" TO "2026-09-02T18:00:00Z"]' in row.rerun_query
    assert row.rerun_query.endswith("| groupby destination.ip")
    assert len(row.document_ids or []) == 10
    await engine.dispose()


async def test_hours_with_no_document_read_as_zero_and_a_drop_departs(
    settings_kratos: Settings,
) -> None:
    """The aggregation leaves out an hour with no document. That hour is a
    count of zero. Read as missing, a host that stopped for three hours
    looked like a host with nothing to say."""
    engine, maker = await _db(settings_kratos)
    await _flat_rate(maker, _SERVER)
    quiet = [(stamp, n) for stamp, n in _hours({}) if not stamp.startswith("2026-09-02T1")]
    assert len(quiet) == 12
    # The first complete hour of the window is the evening before.
    es = _ShapedES(_SERVER, [("2026-09-01T23:00:00.000Z", 100), *quiet])
    async with maker() as db:
        sweep = await run_prior_sweep(
            elastic=es,
            settings=_settings_like(settings_kratos),
            db=db,
            catalog=_prior(dimension="connection_rate", test="below", roles=[]),
            now=_ANCHOR,
        )
    (result,) = sweep.fired
    # One run of ten hours, 10:00 to 19:59. Its furthest hour is the first,
    # in working hours.
    assert [(d.member, d.run_hours) for d in result.departures] == [("work", 10)]
    assert result.departures[0].sample_ids == ()
    await engine.dispose()


async def test_the_recent_hours_leave_out_the_two_partial_hours() -> None:
    """The hour that holds the anchor is still filling, and the first hour of
    the window was cut by its start. Either would read as a collapse."""
    from soc_ai.hunting.prior_sweep import _complete_hours

    hours = _complete_hours(hours=24, now=_ANCHOR)
    assert hours[0] == datetime(2026, 9, 1, 23, tzinfo=UTC)
    assert hours[-1] == datetime(2026, 9, 2, 21, tzinfo=UTC)
    assert len(hours) == 23
    # On the hour, the whole window is complete.
    assert len(_complete_hours(hours=24, now=_ANCHOR.replace(minute=0))) == 24


# ---------------------------------------------------------------------------
# Baseline hygiene through the sweep
# ---------------------------------------------------------------------------

_DC = "dc-01.example.test"


async def _investigation(
    maker: Any,
    *,
    verdict: str,
    at: datetime,
    host_name: str | None = None,
    src_ip: str | None = None,
    synth: bool = False,
    fallback: bool = False,
    n: int = 1,
) -> None:
    from soc_ai.store.models import Investigation

    async with maker() as db:
        db.add(
            Investigation(
                id=f"01TIER2HYGIENE{n:018d}",
                alert_es_id=f"alert-{n}",
                verdict=verdict,
                status="complete",
                host_name=host_name,
                src_ip=src_ip,
                is_synth_eval=synth,
                is_fallback=fallback,
                created_at=at.replace(tzinfo=None),
                finished_at=(at + timedelta(minutes=5)).replace(tzinfo=None),
            )
        )
        await db.commit()


async def _logon_sweep(maker: Any, settings: Settings) -> Any:
    async with maker() as db:
        return await run_prior_sweep(
            elastic=_FakeES(recent={_DC: {"domainadmin": 4, "administrator": 40}}),
            settings=_settings_like(settings),
            db=db,
            catalog=_prior(dimension="logon_users", roles=[]),
            now=datetime(2026, 9, 1, 12, tzinfo=UTC),
        )


async def _dc_logons(maker: Any) -> None:
    await _set(
        maker,
        _DC,
        {
            "administrator": {
                "count": 900,
                "first_seen": "2026-08-01T08:00:00Z",
                "last_seen": "2026-08-30T17:00:00Z",
            },
            "domainadmin": {
                "count": 3,
                "first_seen": "2026-08-10T02:10:00Z",
                "last_seen": "2026-08-11T03:00:00Z",
            },
        },
        dimension="logon_users",
    )


async def test_a_confirmed_attack_window_stays_out_of_the_logon_baseline(
    settings_kratos: Settings,
) -> None:
    """An investigation confirmed an attack on the DC on 2026-08-10. The
    account the attack created entered the logon set that night. Its next
    logon is new: the baseline does not learn from a confirmed attack."""
    engine, maker = await _db(settings_kratos)
    await _dc_logons(maker)
    await _investigation(
        maker, verdict="true_positive", at=datetime(2026, 8, 10, 3, tzinfo=UTC), host_name="DC-01"
    )
    sweep = await _logon_sweep(maker, settings_kratos)
    assert [d.member for r in sweep.fired for d in r.departures] == ["domainadmin"]
    await engine.dispose()


@pytest.mark.parametrize(
    "case",
    [
        {"verdict": "false_positive"},
        {"verdict": "true_positive", "synth": True},
        {"verdict": "true_positive", "fallback": True},
        {"verdict": "true_positive", "host_name": "ws-07.example.test"},
        {"verdict": "true_positive", "at": datetime(2026, 7, 1, tzinfo=UTC)},
    ],
)
async def test_a_window_nothing_confirmed_stays_in_the_baseline(
    settings_kratos: Settings, case: dict[str, Any]
) -> None:
    """Negative controls: a false positive, a synthetic run, a pipeline
    fallback, another host and an old attack confirm nothing about this
    window. The account seen on two days is known."""
    engine, maker = await _db(settings_kratos)
    await _dc_logons(maker)
    await _investigation(
        maker,
        verdict=case["verdict"],
        at=case.get("at", datetime(2026, 8, 10, 3, tzinfo=UTC)),
        host_name=case.get("host_name", _DC),
        synth=case.get("synth", False),
        fallback=case.get("fallback", False),
    )
    sweep = await _logon_sweep(maker, settings_kratos)
    assert sweep.fired == ()
    await engine.dispose()


async def test_the_windows_are_keyed_by_address_and_by_folded_name(
    settings_kratos: Settings,
) -> None:
    from soc_ai.hunting.estate import confirmed_windows, windows_for

    engine, maker = await _db(settings_kratos)
    at = datetime(2026, 8, 20, 10, tzinfo=UTC)
    await _investigation(maker, verdict="true_positive", at=at, src_ip=_SERVER, n=1)
    await _investigation(maker, verdict="true_positive", at=at, host_name="WS-02.example.test", n=2)
    async with maker() as db:
        windows = await confirmed_windows(db, now=datetime(2026, 9, 1, tzinfo=UTC))
    (window,) = windows_for(windows, _SERVER)
    assert window == (at - timedelta(hours=24), at + timedelta(minutes=5, hours=24))
    assert windows_for(windows, "ws-02") == windows_for(windows, "ws-02.example.test") != []
    assert windows_for(windows, "192.0.2.99") == []
    await engine.dispose()


async def test_a_member_a_host_learnt_during_an_attack_counts_toward_no_trait(
    settings_kratos: Settings,
) -> None:
    from soc_ai.hunting.estate import prevalence_for, refresh_estate

    engine, maker = await _db(settings_kratos)
    await _dc_logons(maker)
    await _investigation(
        maker, verdict="true_positive", at=datetime(2026, 8, 10, 3, tzinfo=UTC), host_name=_DC
    )
    async with maker() as db:
        await refresh_estate(db)
        assert await prevalence_for(db, "logon_users", ["administrator", "domainadmin"]) == {
            "administrator": 1
        }
    await engine.dispose()


# ---------------------------------------------------------------------------
# Peer groups
# ---------------------------------------------------------------------------

_SERVERS = [f"192.0.2.{n}" for n in range(101, 107)]
_DESKS = [f"198.51.100.{n}" for n in range(1, 21)]


async def _infer(maker: Any, key: str, role: str, confidence: float) -> None:
    """The dossier infers a role for one host, at a confidence."""
    async with maker() as db:
        host = HostDossier(host_key=key, ip=key)
        db.add(host)
        await db.flush()
        db.add(
            HostDossierField(
                dossier_id=host.id,
                field="role",
                inferred_value=role,
                inferred_confidence=confidence,
            )
        )
        await db.commit()


async def _server_estate(maker: Any, *, holders_of_8080: int = 4) -> None:
    """Six declared servers and twenty desks. ``holders_of_8080`` of the five
    peers of the first server serve 8080. One peer serves 9999. No desk
    serves either, so neither port is common across the estate of 26."""
    for n, key in enumerate(_SERVERS):
        await _declare(maker, key, "server")
        ports: dict[str, Any] = {"22": 40, "443": 90}
        if 1 <= n <= holders_of_8080:
            ports["8080"] = 30
        if n == 5:
            ports["9999"] = 12
        await _set(maker, key, ports)
    for key in _DESKS:
        await _set(maker, key, {"22": 5})


def _server_prior(test: str = "novel_for", **profile: Any) -> dict[str, Any]:
    return _prior(roles=["server"], test=test, **profile)


async def _server_sweep(maker: Any, settings: Settings, catalog: Any, recent: Any) -> Any:
    async with maker() as db:
        return await run_prior_sweep(
            elastic=_FakeES(recent=recent),
            settings=_settings_like(settings),
            db=db,
            catalog=catalog,
            record=True,
            now=datetime(2026, 9, 1, 12, tzinfo=UTC),
        )


async def test_a_port_most_server_peers_serve_is_a_role_trait(settings_kratos: Settings) -> None:
    """Four of the five peers serve 8080. The first server starts to serve it
    too: it joined its role, it did not leave it. The note counts it. A port
    one peer serves is still a departure."""
    engine, maker = await _db(settings_kratos)
    await _server_estate(maker)
    first = _SERVERS[0]
    sweep = await _server_sweep(
        maker, settings_kratos, _server_prior(), {first: {"8080": 9, "9999": 7}}
    )
    (result,) = [r for r in sweep.results if r.entity_key == first]
    assert [d.member for d in result.departures] == ["9999"]
    assert result.role_traits == 1
    assert "1 new member that most peers in the role hold formed no observation." in result.note
    assert result.suppressed == 0
    await engine.dispose()


async def test_a_role_below_the_gate_reads_no_peer_group(settings_kratos: Settings) -> None:
    """Negative control: the same host with a role inferred at 0.5 has no
    peer group. A guessed role is not a trait, and the port departs."""
    engine, maker = await _db(settings_kratos)
    for key in _SERVERS[1:]:
        await _declare(maker, key, "server")
        await _set(maker, key, {"22": 40, "8080": 30})
    for key in _DESKS:
        await _set(maker, key, {"22": 5})
    first = _SERVERS[0]
    await _infer(maker, first, "server", 0.5)
    await _set(maker, first, {"22": 40})
    sweep = await _server_sweep(maker, settings_kratos, _prior(roles=[]), {first: {"8080": 9}})
    (result,) = [r for r in sweep.results if r.entity_key == first]
    assert [d.member for d in result.departures] == ["8080"]
    assert result.role_traits == 0
    await engine.dispose()


async def test_rare_for_peers_fires_on_a_new_port_no_peer_serves(
    settings_kratos: Settings,
) -> None:
    """The producer of rare_for_peers: a new port on a server that none of its
    five peers serves. One peer serving it is enough to keep it quiet at the
    default share of zero."""
    engine, maker = await _db(settings_kratos)
    await _server_estate(maker)
    first = _SERVERS[0]
    sweep = await _server_sweep(
        maker,
        settings_kratos,
        _server_prior("rare_for_peers"),
        {first: {"4444": 6, "9999": 6}},
    )
    (result,) = [r for r in sweep.results if r.entity_key == first]
    (d,) = result.departures
    assert d.member == "4444"
    assert (d.peer_role, d.peer_count, d.peer_holders) == ("server", 5, 0)
    assert "None of the 5 server peers holds it" in result.note
    async with maker() as db:
        row = (await db.execute(select(EntityObservation))).scalars().one()
    assert row.kind == "rare_for_peers"
    assert row.birth_weight == 0.45
    assert (row.statistic, row.statistic_value, row.baseline_value) == ("peer_share", 0.0, 5.0)
    await engine.dispose()


async def test_rare_for_peers_is_blind_below_five_peers(settings_kratos: Settings) -> None:
    """Four peers say nothing about the role. The test is blind and says why.
    It never reads a member as rare against a group too small to hold it."""
    engine, maker = await _db(settings_kratos)
    for key in _SERVERS[:5]:
        await _declare(maker, key, "server")
        await _set(maker, key, {"22": 40})
    first = _SERVERS[0]
    sweep = await _server_sweep(
        maker, settings_kratos, _server_prior("rare_for_peers"), {first: {"4444": 6}}
    )
    (result,) = [r for r in sweep.results if r.entity_key == first]
    assert result.coverage == "blind"
    assert result.departures == ()
    assert result.note == (
        "the peer group is too small. The role server has 4 peers. The test needs 5."
    )
    await engine.dispose()


async def test_the_refresh_writes_the_role_on_every_profile_row(settings_kratos: Settings) -> None:
    """The role column was empty on every production row, so profiles_for_role
    returned nothing and no peer group existed. The refresh after a build
    writes it from the dossier."""
    from soc_ai.hunting.estate import refresh_estate

    engine, maker = await _db(settings_kratos)
    await _server_estate(maker)
    await _infer(maker, _DESKS[0], "workstation", 0.5)
    async with maker() as db:
        done = await refresh_estate(db)
        servers = await ep.profiles_for_role(
            db, role="server", dimension="served_ports", min_confidence=0.9
        )
        desks = await ep.profiles_for_role(
            db, role="workstation", dimension="served_ports", min_confidence=0.9
        )
        guessed = await ep.profiles_for_role(db, role="workstation", dimension="served_ports")
    assert done.roles_stamped == 7
    assert sorted(r.entity_key for r in servers) == _SERVERS
    assert {r.role_confidence for r in servers} == {1.0}
    # A guessed role is written, and the peer group leaves it out.
    assert desks == []
    assert [(r.entity_key, r.role_confidence) for r in guessed] == [(_DESKS[0], 0.5)]
    await engine.dispose()


# ---------------------------------------------------------------------------
# The blind reason
# ---------------------------------------------------------------------------

_NO_SERIES = "the baseline holds no hourly series yet. The next profile build writes one."


async def _cells_only_rate(maker: Any, key: str) -> None:
    """A rate baseline from before the hourly series: the three cells only."""
    async with maker() as db:
        await ep.upsert_profile(
            db,
            entity_kind="host",
            entity_key=key,
            dimension="connection_rate",
            shape="numeric",
            vector={"work": {"median": 100.0, "dispersion": 4.0, "samples": 200}},
            coverage="measured",
            support_days=28,
        )


async def _rate_sweep(settings: Settings, maker: Any) -> Any:
    es = _ShapedES(_SERVER, _hours({14: 1000, 15: 1000}))
    async with maker() as db:
        sweep = await run_prior_sweep(
            elastic=es,
            settings=_settings_like(settings),
            db=db,
            catalog=_prior(dimension="connection_rate", test="above", roles=[]),
            record=True,
            now=_ANCHOR,
        )
        await db.commit()
    return sweep


async def test_a_blind_rate_analytic_states_its_reason_on_every_surface(
    settings_kratos: Settings, caplog: pytest.LogCaptureFixture
) -> None:
    """The deploy of 2026-10-04 made the rate test read an hourly series. The
    stored baselines held none, and the two rate analytics were blind on every
    host for 19 hours. The evaluator wrote the reason on each result, and the
    sweep notes, the CLI, the journal, the trail and the ledger said "blind=8"
    with no reason. Each of them now carries it."""
    from soc_ai.hunting import prior_sweep as module
    from soc_ai.hunting.ledger import analytic_ledger
    from soc_ai.hunting.prior_sweep import format_sweep
    from soc_ai.store.models import PriorSpecRun

    module._LOGGED_BLIND.clear()
    engine, maker = await _db(settings_kratos)
    await _cells_only_rate(maker, _SERVER)

    with caplog.at_level("INFO", logger="soc_ai.hunting.prior_sweep"):
        sweep = await _rate_sweep(settings_kratos, maker)
        again = await _rate_sweep(settings_kratos, maker)

    reason = f"1 of 1 blind host: {_NO_SERIES}"
    note = f"prior-under-test: {reason}"
    assert sweep.blind_reasons() == {"prior-under-test": reason}
    assert note in sweep.notes
    text = format_sweep(sweep)
    assert f"       {reason}" in text
    # The row states the reason. The note does not say it a second time.
    assert f"note: {note}" not in text
    # The journal: one line when the reason appears, none while it holds.
    logged = [r.getMessage() for r in caplog.records if "blind host" in r.getMessage()]
    assert logged == [f"prior sweep: {note}"]
    assert note in again.notes

    async with maker() as db:
        runs = (await db.execute(select(PriorSpecRun))).scalars().all()
        ledger = await analytic_ledger(db, "prior-under-test", since=_ANCHOR - timedelta(days=1))
    assert [r.blind_reason for r in runs] == [reason, reason]
    assert ledger.blind_reason == reason
    assert ledger.coverage["blind"] == 1
    await engine.dispose()


async def test_a_measured_rate_analytic_states_no_blind_reason(
    settings_kratos: Settings, caplog: pytest.LogCaptureFixture
) -> None:
    """Negative control on the same path: the baseline holds the series."""
    from soc_ai.hunting import prior_sweep as module
    from soc_ai.hunting.prior_sweep import format_sweep
    from soc_ai.store.models import PriorSpecRun

    module._LOGGED_BLIND.clear()
    engine, maker = await _db(settings_kratos)
    await _flat_rate(maker, _SERVER)
    with caplog.at_level("INFO", logger="soc_ai.hunting.prior_sweep"):
        sweep = await _rate_sweep(settings_kratos, maker)

    assert sweep.coverage_counts()["measured"] == 1
    assert sweep.blind_reasons() == {}
    assert not [n for n in sweep.notes if "blind host" in n]
    assert "blind host" not in format_sweep(sweep)
    assert not [r for r in caplog.records if "blind host" in r.getMessage()]
    async with maker() as db:
        (run,) = (await db.execute(select(PriorSpecRun))).scalars().all()
    assert run.blind_reason is None
    await engine.dispose()


async def test_the_blind_reason_names_the_most_entities_when_they_differ() -> None:
    """Hosts with no profile and hosts with an old one, in one estate. The
    reason of the most of them is stated, with their count. A note on an
    entity that is not blind is no blind reason, and a spec that measured an
    entity gets no sweep note."""
    from soc_ai.hunting.prior_sweep import _blind_notes, blind_reasons
    from soc_ai.hunting.priors import PriorResult

    def _r(spec: str, key: str, coverage: str, note: str = "") -> PriorResult:
        return PriorResult(
            spec_id=spec, entity_kind="host", entity_key=key, coverage=coverage, note=note
        )

    results = [
        _r("a", "192.0.2.1", "blind", _NO_SERIES),
        _r("a", "192.0.2.2", "blind", _NO_SERIES),
        _r("a", "192.0.2.3", "blind", _NO_SERIES),
        _r("a", "192.0.2.4", "blind", "no connection rate baseline exists for this host yet."),
        _r("a", "192.0.2.5", "not_applicable", "the analytic applies to the role server."),
        _r("b", "192.0.2.1", "measured", "nothing departed"),
        _r("b", "192.0.2.2", "unmeasurable", "one plane"),
        _r("c", "192.0.2.1", "blind"),
        _r("d", "192.0.2.1", "measured", "nothing departed"),
    ]
    # Every reason carries its count, also when all the blind entities share
    # it. The verification of 2026-10-05 found rows with the count and rows
    # without it on one tab.
    assert blind_reasons(results) == {
        "a": f"3 of 4 blind hosts: {_NO_SERIES}",
        "b": "1 of 1 blind host: one plane",
    }
    # b measured one entity, c has no reason and d has nothing blind.
    assert _blind_notes(results) == {"a": f"a: 3 of 4 blind hosts: {_NO_SERIES}"}


async def test_the_blind_count_names_the_kind_the_blind_entities_share() -> None:
    """A user analytic counts users. Mixed kinds fall back to "entities"."""
    from soc_ai.hunting.prior_sweep import blind_reasons
    from soc_ai.hunting.priors import PriorResult

    def _r(spec: str, kind: str, key: str) -> PriorResult:
        return PriorResult(
            spec_id=spec, entity_kind=kind, entity_key=key, coverage="blind", note="no logon"
        )

    results = [
        _r("u", "user", "alice"),
        _r("u", "user", "bob"),
        _r("m", "user", "alice"),
        _r("m", "host", "192.0.2.1"),
        _r("i", "ip", "192.0.2.9"),
    ]
    assert blind_reasons(results) == {
        "u": "2 of 2 blind users: no logon",
        "m": "2 of 2 blind entities: no logon",
        "i": "1 of 1 blind IP address: no logon",
    }


async def test_the_journal_line_waits_for_a_new_reason(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The sweep runs every hour. A blind count that moves writes no new line.
    A new reason does, and a spec that is measured again starts over."""
    from soc_ai.hunting import prior_sweep as module
    from soc_ai.hunting.priors import PriorResult

    def _sweep(blind: int, note: str) -> None:
        results = [
            PriorResult(
                spec_id="a",
                entity_kind="host",
                entity_key=f"192.0.2.{n}",
                coverage="blind",
                note=note,
            )
            for n in range(blind)
        ]
        reasons = {s: p[0] for s, p in module._most_common_reasons(results).items()}
        module._log_blind(module._blind_notes(results), reasons)

    module._LOGGED_BLIND.clear()
    with caplog.at_level("INFO", logger="soc_ai.hunting.prior_sweep"):
        _sweep(8, _NO_SERIES)
        _sweep(9, _NO_SERIES)
        _sweep(9, "no connection rate baseline exists for this host yet.")
        _sweep(0, _NO_SERIES)
        _sweep(9, _NO_SERIES)
    lines = [r.getMessage() for r in caplog.records]
    assert lines == [
        f"prior sweep: a: 8 of 8 blind hosts: {_NO_SERIES}",
        "prior sweep: a: 9 of 9 blind hosts: no connection rate baseline exists for this host yet.",
        f"prior sweep: a: 9 of 9 blind hosts: {_NO_SERIES}",
    ]
