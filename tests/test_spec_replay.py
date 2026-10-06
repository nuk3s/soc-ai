"""soc-ai spec-replay: the tier 2 replay against a grid, into a scratch store, with a report.

The grid composes three fakes of tests/replay_grid.py. The flows are the
synthetic estate of tests/test_tier2_replay.py, with its three planted
departures and their twins. The planes are five machines for the cross-plane
silence detector. The logons are 40 days of daily sessions for the logon
chain detector. The "live" store is a store the test seeds the way
test_tier2_replay.py seeds its estate: nine declared servers. The replay
copies that census read-only into its scratch store.

The replay window is two days from the Wednesday noon of the synthetic week.
It holds the three profile plants:

* P1, the four-hour burst of A on the Wednesday afternoon;
* P2, the estate-rare port of C on the Thursday morning;
* P3, the four-hour silence of H on the Friday morning.

The twins D and K act in the same hours and must stay quiet. It holds the two
detector plants:

* Q1, on the Thursday from 02:00 to 05:00 UTC, the process events of app-01
  stop and its other planes keep going. The twin app-02 stops every plane in
  the same hours: the machine is off.
* Q2, on the Thursday at 20:20 UTC, a session lands on web-01, and four
  minutes later web-01 tries db-01, which it never reached. The twins: web-01
  reaches backup-01 a minute later, a host in its edge set, and db-01 tries
  backup-01 50 minutes after a session, outside ``chain_minutes``.

The grid's clock stands six hours after the end of the window, as the present
stands after the window of a real replay. Every read of the replay carries a
time anchor, so no read asks the grid about its present.

Every address is from the documentation ranges.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from soc_ai import cli
from soc_ai.config import Settings
from soc_ai.dossier.profile import PROFILE_SHAPE
from soc_ai.dossier.profile_job import build_profiles
from soc_ai.hunting import spec_replay as sr
from soc_ai.hunting.spec import CATALOG_DIR, load_catalog
from soc_ai.store import analytics as analytics_store
from soc_ai.store.db import engine_for_url, make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import EntityObservation, EntityProfile, HostDossier, HostDossierField
from sqlalchemy import func, make_url, select, update

from tests.replay_grid import (
    HOUR,
    EstateGrid,
    Logon,
    LogonGrid,
    PlaneGrid,
    PlaneHost,
    SyntheticGrid,
)
from tests.test_tier2_replay import (
    CIDRS,
    START,
    A,
    C,
    D,
    H,
    K,
    _declare_servers,
    _estate,
    _inside,
    _jitter,
    _Settings,
)

# The replayed window: Wednesday 12:00 to Friday 12:00 of the synthetic week.
END = START + timedelta(days=4, hours=12)
WINDOW_START = END - timedelta(days=2)
# The present of the grid and of the plan: six hours after the window.
PRESENT = END + timedelta(hours=6)

_PLANTS = {
    ("profile-connection-rate-spiked", A),
    ("prior-server-internet-nonweb-novel-port", C),
    ("profile-connection-rate-collapsed", H),
}
_TWINS = {
    ("prior-server-internet-nonweb-novel-port", D),
    ("profile-connection-rate-collapsed", K),
}

# The detector plants. Q1 falls on the first replayed day, Q2 on the second.
SILENCE_ID, CHAIN_ID = "model-cross-plane-silence", "model-logon-chain"
Q1_SILENCE = (START + timedelta(days=3, hours=2), START + timedelta(days=3, hours=5))
Q2_SESSION = START + timedelta(days=3, hours=20, minutes=20)
_MODEL_PLANTS = {(SILENCE_ID, "app-01"), (CHAIN_ID, "web-01")}
_MODEL_TWINS = {(SILENCE_ID, "app-02"), (CHAIN_ID, "db-01")}
_MODEL = (SILENCE_ID, CHAIN_ID)

FIRST = START - timedelta(days=40)
JUMP, WEB, DB, BACKUP = (f"192.0.2.{n}" for n in (40, 42, 43, 44))


def _hourly(base: int, *, off: tuple[datetime, datetime] | None = None) -> Any:
    """A plane at ``base`` documents an hour, with none inside ``off``."""

    def count(at: datetime) -> int:
        return 0 if off is not None and _inside(at, off) else base + _jitter(at)

    return count


def _machines() -> list[PlaneHost]:
    """The plant, its twin, a machine with one plane, a young machine and a quiet one."""
    return [
        PlaneHost(
            "app-01",
            ["192.0.2.21"],
            {
                "system.syslog": _hourly(100),
                "endpoint.events.process": _hourly(200, off=Q1_SILENCE),
            },
            flows=_hourly(300),
            born=FIRST,
        ),
        PlaneHost(
            "app-02",
            ["192.0.2.22"],
            {
                "system.syslog": _hourly(100, off=Q1_SILENCE),
                "endpoint.events.process": _hourly(200, off=Q1_SILENCE),
            },
            flows=_hourly(300, off=Q1_SILENCE),
            born=FIRST,
        ),
        PlaneHost("app-03", ["192.0.2.23"], {"system.syslog": _hourly(100)}, born=FIRST),
        PlaneHost(
            "app-04",
            ["192.0.2.24"],
            {"system.syslog": _hourly(100), "endpoint.events.process": _hourly(200)},
            born=WINDOW_START - timedelta(days=3),
        ),
        PlaneHost(
            "app-05",
            ["192.0.2.25"],
            {"system.syslog": _hourly(100), "endpoint.events.process": _hourly(200)},
            flows=_hourly(300),
            born=FIRST,
        ),
    ]


def _logons() -> list[Logon]:
    """Daily sessions from the jump host at 09:00, the plant and its twins."""
    out: list[Logon] = []
    day, n = FIRST.replace(hour=9), 0
    while day < END:
        n += 1
        out += [
            Logon(f"h{n}-jump-web", day, "web-01", JUMP, [WEB]),
            Logon(f"h{n}-jump-db", day, "db-01", JUMP, [DB]),
            Logon(f"h{n}-jump-nas", day, "nas-01", JUMP, []),
            Logon(f"h{n}-web-backup", day + timedelta(minutes=5), "backup-01", WEB, [BACKUP]),
        ]
        day += timedelta(days=1)
    at = Q2_SESSION
    return [
        *out,
        Logon("q2-session", at, "web-01", JUMP, [WEB]),
        Logon("q2-attempt", at + timedelta(minutes=4), "db-01", WEB, [DB], outcome="invalid"),
        Logon("q2-twin-backup", at + timedelta(minutes=5), "backup-01", WEB, [BACKUP]),
        Logon("q2-twin-session", at - timedelta(hours=6), "db-01", JUMP, [DB]),
        Logon(
            "q2-twin-attempt",
            at - timedelta(hours=5, minutes=10),
            "backup-01",
            DB,
            [BACKUP],
            outcome="failed",
        ),
    ]


def _settings(base: Settings, data_dir: Path) -> Settings:
    """The install's settings, with the synthetic estate's network and clock."""
    return base.model_copy(
        update={
            "soc_ai_data_dir": data_dir,
            "internal_cidrs": list(CIDRS),
            "so_timezone": "UTC",
            "entity_profiles_enabled": False,
        }
    )


async def _live_store(settings: Settings) -> Path:
    """The live store: migrated, with the nine declared servers of the estate."""
    engine = make_engine(settings)
    await run_migrations(engine)
    await _declare_servers(make_sessionmaker(engine), [h.ip for h in _estate()])
    await engine.dispose()
    return Path(settings.soc_ai_data_dir) / "soc-ai.db"


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class _Grid(EstateGrid):
    """The composed grid as the CLI constructs a client: it also closes."""

    async def aclose(self) -> None:
        return None


def _grid() -> _Grid:
    return _Grid(
        flows=SyntheticGrid(hosts=_estate(), clock=PRESENT),
        planes=PlaneGrid(hosts=_machines(), clock=PRESENT),
        logons=LogonGrid(logons=_logons(), clock=PRESENT),
    )


def _window(query: Any) -> Mapping[str, Any] | None:
    """The ``@timestamp`` range of a query, wherever the wrappers put it."""
    if isinstance(query, Mapping):
        bounds = (query.get("range") or {}).get("@timestamp")
        if isinstance(bounds, Mapping):
            return bounds
        for value in query.values():
            found = _window(value)
            if found is not None:
                return found
    elif isinstance(query, list):
        for value in query:
            found = _window(value)
            if found is not None:
                return found
    return None


class _Recorder:
    """A grid that records the time window of every search it passes on."""

    def __init__(self, inner: Any) -> None:
        self.inner = inner
        self.windows: list[Mapping[str, Any]] = []

    @property
    def searches(self) -> int:
        return int(self.inner.searches)

    async def search(self, index: str, query: Any, **kwargs: Any) -> Any:
        bounds = _window(query)
        if bounds is not None:
            self.windows.append(dict(bounds))
        return await self.inner.search(index, query, **kwargs)


class _FailOnHour:
    """A grid that refuses every search of the sweep anchored at one hour."""

    def __init__(self, inner: Any, bad: datetime) -> None:
        self.inner = inner
        self.bad = bad.isoformat()
        self.read: set[str] = set()

    @property
    def searches(self) -> int:
        return int(self.inner.searches)

    async def search(self, index: str, query: Any, **kwargs: Any) -> Any:
        end = (_window(query) or {}).get("lte")
        if end == self.bad:
            raise ConnectionError("the grid did not answer")
        if isinstance(end, str):
            self.read.add(end)
        return await self.inner.search(index, query, **kwargs)


async def _run(
    settings: Settings,
    grid: Any,
    *,
    days: int = 2,
    end: datetime = END,
    evaluators: tuple[str, ...] = (),
) -> tuple[sr.ReplayPlan, sr.ReplayReport]:
    plan = sr.plan_replay(
        settings,
        days=days,
        end=end,
        hosts_from_census=True,
        now=PRESENT,
        evaluators=evaluators,
    )
    estate = await sr.read_live_estate(settings, census=True)
    return plan, await sr.run_replay(grid, settings, plan, estate=estate)


def _rows(report: sr.ReplayReport) -> dict[str, sr.AnalyticRow]:
    return {row.analytic: row for row in report.analytics}


# ---------------------------------------------------------------------------
# The replay and its report
# ---------------------------------------------------------------------------


async def test_a_two_day_replay_counts_the_planted_hits_and_the_twins_stay_quiet(
    settings_kratos: Settings, tmp_path: Path
) -> None:
    settings = _settings(settings_kratos, tmp_path / "data")
    live = await _live_store(settings)
    before = _digest(live)
    composed = _grid()
    grid = _Recorder(composed)

    plan, report = await _run(settings, grid)

    # Every read carries its anchor. A read at "now" reads the grid's present,
    # six hours past the window.
    assert grid.windows
    relative = [w for w in grid.windows if "now" in str(w.get("gte")) + str(w.get("lte"))]
    assert relative == [], relative[:3]

    assert plan.start == WINDOW_START
    assert plan.evaluators == ("profile", "model"), "the default runs both evaluators"
    assert report.hours == 48
    assert report.unread_hours == [], report.unread_hours
    rows = _rows(report)
    assert set(rows) == set(sr.replay_analytics()), "the default is every analytic of both"
    assert set(sr.profile_analytics()) < set(rows)
    assert set(_MODEL) < set(rows)
    # Each evaluator read the grid: the flows for the profiles, the planes and
    # the logons for the detectors.
    assert composed.flows.searches > 0
    assert composed.planes.searches > 0
    assert composed.logons.searches > 0

    # Every plant hit, on its host, the detector plants too.
    plants = _PLANTS | _MODEL_PLANTS
    hit_pairs = {(row.analytic, e["host"]) for row in report.analytics for e in row.top_hosts}
    assert hit_pairs == plants, hit_pairs
    for analytic, host in plants:
        assert rows[analytic].hits >= 1, analytic
        assert rows[analytic].top_hosts[0]["host"] == host
        assert rows[analytic].observations >= 1
    # The twins and every other analytic stayed quiet.
    assert not (hit_pairs & (_TWINS | _MODEL_TWINS))
    assert report.hits == sum(rows[a].hits for a, _h in plants)
    quiet = [row for row in report.analytics if row.analytic not in {a for a, _h in plants}]
    assert all(row.hits == 0 for row in quiet), [(r.analytic, r.hits) for r in quiet]

    # The detector rows. Each fired on one host on one day, and each is a
    # shadow analytic whose shadow hit counts.
    silence, chain = rows[SILENCE_ID], rows[CHAIN_ID]
    assert (silence.evaluator, silence.status, silence.detector) == (
        "model",
        "shadow",
        "cross_plane_silence",
    )
    assert (chain.evaluator, chain.status, chain.detector) == ("model", "shadow", "logon_chain")
    assert (silence.hits, chain.hits) == (1, 1)
    # Host-days: the machines each detector measured, per day. app-01, app-02
    # and app-05 for the planes. web-01, db-01 and backup-01 for the logons.
    assert (silence.host_days, chain.host_days) == (6, 6)
    assert silence.verdict == chain.verdict == sr.OVER
    # The states, folded the way the ledger folds them. app-03 ships one plane
    # and nas-01 has no known address: both are unmeasurable, which is blind.
    # app-04 is three days old: learning.
    assert (silence.measured, silence.learning, silence.blind) == (3 * 48, 48, 48)
    assert silence.folded_states == {"unmeasurable": 48}
    assert (chain.measured, chain.learning, chain.blind) == (3 * 48, 0, 48)
    assert chain.folded_states == {"unmeasurable": 48}
    # Negative control: a profile row has nothing to fold.
    assert all(rows[a].folded_states == {} for a in sr.profile_analytics())
    assert all(rows[a].status == "live" for a in sr.profile_analytics())

    # The rate rows: nine servers on two days, each measured on the rate.
    spiked = rows["profile-connection-rate-spiked"]
    assert spiked.host_days == 18
    assert spiked.measured == 9 * 48
    assert spiked.per_100_host_days == pytest.approx(100.0 * spiked.hits / 18, abs=1e-3)
    assert spiked.wilson_upper_95_per_100 is not None
    assert spiked.wilson_upper_95_per_100 > spiked.per_100_host_days
    assert spiked.verdict == sr.OVER, "a planted burst on 18 host-days is over the budget"
    measured_quiet = [row for row in quiet if row.host_days > 0]
    assert measured_quiet, "no quiet analytic measured a host"
    # No hit on 18 host-days or fewer: the Wilson bound is far over the budget.
    assert all(row.verdict == sr.TOO_FEW for row in measured_quiet)
    assert report.verdict == sr.OVER
    assert report.exit_code == 3
    # Nine addresses for the profile analytics, and six machine names for the
    # detectors, on each of two days.
    assert report.estate_host_days == 2 * (9 + 6)

    # The cost per day comes from the stage clock, and adds up to the grid's count.
    assert [d.day for d in report.day_rows] == [1, 2]
    assert all(d.build_searches > 0 and d.sweep_searches > 0 for d in report.day_rows)
    assert sum(d.build_searches + d.sweep_searches for d in report.day_rows) == grid.searches
    assert report.searches == grid.searches
    assert sum(d.hits for d in report.day_rows) == report.hits

    # The scratch store holds the observations the report read back.
    engine = engine_for_url(make_url(f"sqlite+aiosqlite:///{plan.store}"))
    async with make_sessionmaker(engine)() as db:
        stored = int(await db.scalar(select(func.count(EntityObservation.id))) or 0)
        seeded = int(await db.scalar(select(func.count(HostDossier.id))) or 0)
        roles = int(
            await db.scalar(
                select(func.count(HostDossierField.id)).where(HostDossierField.field == "role")
            )
            or 0
        )
        written = (await db.scalars(select(EntityObservation))).all()
    await engine.dispose()
    assert stored == report.observations > 0
    assert (seeded, roles) == (9, 9), "the census and the roles reached the scratch store"
    # The detectors wrote one observation each, in shadow, as they do live.
    # The chain cites its two documents, and no twin wrote a row.
    by_spec = {(o.spec_id, o.entity_key): o for o in written if o.source == "model"}
    assert set(by_spec) == _MODEL_PLANTS
    assert all(o.shadow for o in by_spec.values())
    assert by_spec[(CHAIN_ID, "web-01")].document_ids == ["q2-session", "q2-attempt"]
    assert by_spec[(SILENCE_ID, "app-01")].born_at < (WINDOW_START + timedelta(days=1)).replace(
        tzinfo=None
    ), "the silence fell on the first day"
    # Negative control: the profile analytics are live, so their rows are not shadow.
    assert not any(o.shadow for o in written if o.source == "profile")

    # The report files.
    json_path, md_path = sr.write_report(report, plan.out)
    loaded = json.loads(json_path.read_text())
    assert loaded["verdict"] == "over budget"
    assert loaded["totals"]["hits"] == report.hits
    assert {a["analytic"] for a in loaded["analytics"]} == set(rows)
    by_row = {a["analytic"]: a for a in loaded["analytics"]}
    assert by_row[CHAIN_ID]["status"] == "shadow"
    assert by_row[CHAIN_ID]["folded_states"] == {"unmeasurable": 48}
    text = md_path.read_text()
    assert "Verdict: over budget." in text
    assert "## Hosts with the most hits" in text
    assert "The replay read every hour." in text
    # The report says that a shadow hit counts, and each row gives its status.
    assert "A shadow hit counts as a hit." in text
    assert f"| `{CHAIN_ID}` | model | shadow | logon_chain | 6 | 1 |" in text
    assert "| unmeasurable 48 |" in text
    # The notes name each evaluator, the analytics it covered and what the
    # replay left out.
    profile = sorted(sr.profile_analytics())
    assert (
        f"- The replay runs the profile evaluator on {len(profile)} analytics: "
        f"{', '.join(profile)}."
    ) in text
    assert (
        "- The replay runs the model evaluator on 2 analytics: model-cross-plane-silence, "
        "model-logon-chain."
    ) in text
    assert (
        "- 2 analytics ran in shadow, as on the live install: model-cross-plane-silence, "
        "model-logon-chain. Each wrote shadow observations. The replay counts a shadow hit "
        "as a hit."
    ) in text
    assert "- The replay leaves out the match evaluator: " in text
    assert "leaves out the model evaluator" not in text
    assert "—" not in text and "–" not in text

    # The live store is unchanged. A write to it would change the digest.
    assert _digest(live) == before
    engine = make_engine(settings)
    async with make_sessionmaker(engine)() as db:
        db.add(HostDossier(host_key="192.0.2.99", ip="192.0.2.99"))
        await db.commit()
    await engine.dispose()
    assert _digest(live) != before, "the digest did not see a write"


async def test_the_profile_evaluator_alone_leaves_the_detectors_out_and_says_so(
    settings_kratos: Settings, tmp_path: Path
) -> None:
    """The same grid carries the planes and the logons. Nothing reads them."""
    settings = _settings(settings_kratos, tmp_path / "data")
    await _live_store(settings)
    grid = _grid()

    plan, report = await _run(settings, grid, evaluators=("profile",))

    assert plan.evaluators == ("profile",)
    assert plan.detectors == ()
    rows = _rows(report)
    assert set(rows) == set(sr.profile_analytics())
    assert not set(_MODEL) & set(rows)
    assert (grid.planes.searches, grid.logons.searches) == (0, 0), "a detector read the grid"
    assert grid.flows.searches > 0
    hit_pairs = {(row.analytic, e["host"]) for row in report.analytics for e in row.top_hosts}
    assert hit_pairs == _PLANTS
    assert report.estate_host_days == 2 * 9
    assert (
        "The replay leaves out the model evaluator: model-cross-plane-silence, "
        "model-logon-chain. --evaluator does not name it. The report holds no rate for them."
    ) in report.notes
    assert not any("ran in shadow" in note for note in report.notes)
    text = sr.render_markdown(report)
    assert "| model |" not in text


async def test_a_detector_approved_to_live_writes_live_observations_and_still_counts(
    settings_kratos: Settings, tmp_path: Path
) -> None:
    """The replay reads each status from the live store, read-only.

    The operator approved the silence detector to live. The chain detector
    stays in shadow. Both hits count. With no profile analytic in the plan,
    the replay builds no profile and reads no flow.
    """
    settings = _settings(settings_kratos, tmp_path / "data")
    live = await _live_store(settings)
    engine = make_engine(settings)
    async with make_sessionmaker(engine)() as db:
        await analytics_store.seed_shipped_shadow(db, load_catalog(CATALOG_DIR))
        await analytics_store.transition(
            db, SILENCE_ID, to_status="live", by="analyst", why="a clean shadow week"
        )
    await engine.dispose()
    before = _digest(live)
    grid = _grid()

    plan, report = await _run(settings, grid, evaluators=("model",))

    assert plan.analytics == _MODEL
    assert plan.builds == 0
    assert grid.flows.searches == 0, "the replay built a profile no analytic reads"
    assert all(d.build_searches == 0 and d.build_rows == 0 for d in report.day_rows)
    rows = _rows(report)
    assert set(rows) == set(_MODEL)
    assert (rows[SILENCE_ID].status, rows[CHAIN_ID].status) == ("live", "shadow")
    assert (rows[SILENCE_ID].hits, rows[CHAIN_ID].hits) == (1, 1), "a shadow hit is a hit"
    assert report.hits == 2

    engine = engine_for_url(make_url(f"sqlite+aiosqlite:///{plan.store}"))
    async with make_sessionmaker(engine)() as db:
        written = (await db.scalars(select(EntityObservation))).all()
    await engine.dispose()
    shadow = {o.spec_id: o.shadow for o in written}
    assert shadow == {SILENCE_ID: False, CHAIN_ID: True}
    assert (
        f"1 analytic ran in shadow, as on the live install: {CHAIN_ID}. Each wrote shadow "
        "observations. The replay counts a shadow hit as a hit."
    ) in report.notes
    assert any(
        note.startswith("The replay leaves out the profile evaluator: ") for note in report.notes
    )
    assert _digest(live) == before, "the replay wrote to the live store"


async def test_an_hour_with_a_grid_error_is_unread_and_the_replay_goes_on(
    settings_kratos: Settings, tmp_path: Path
) -> None:
    settings = _settings(settings_kratos, tmp_path / "data")
    await _live_store(settings)
    end = START + timedelta(days=3, hours=12)
    bad = end - timedelta(days=1) + 5 * HOUR
    grid = _FailOnHour(_grid(), bad)

    _plan, report = await _run(settings, grid, days=1, end=end)

    assert [u["hour"] for u in report.unread_hours] == [bad.isoformat()]
    # The probe swallows the grid's error and says why the read stopped.
    assert "plane probe" in " ".join(report.unread_hours[0]["errors"])
    assert report.day_rows[0].hours_unread == 1
    # Every later hour of the day was read.
    later = {(bad + n * HOUR).isoformat() for n in range(1, 19)}
    assert later <= grid.read, sorted(later - grid.read)
    # The analytics scored 23 hours of the nine hosts.
    assert _rows(report)["profile-connection-rate-spiked"].measured == 9 * 23
    assert report.exit_code == 5, "an unread hour makes the measurement incomplete"
    text = sr.render_markdown(report)
    assert bad.isoformat() in text
    assert "could not read 1 of 24 hours" in text


# ---------------------------------------------------------------------------
# The command: the dry run, the live store
# ---------------------------------------------------------------------------


def _argv(store: Path, *extra: str) -> list[str]:
    return [
        "soc-ai",
        "spec-replay",
        "--days",
        "2",
        "--end",
        END.isoformat(),
        "--store",
        str(store),
        "--hosts-from-census",
        *extra,
    ]


def _main(monkeypatch: pytest.MonkeyPatch, argv: list[str]) -> int:
    monkeypatch.setattr("sys.argv", argv)
    with pytest.raises(SystemExit) as ei:
        cli.main()
    return int(ei.value.code or 0)


def _patch_client(
    monkeypatch: pytest.MonkeyPatch, settings: Settings, grid: _Grid
) -> list[Settings]:
    import soc_ai.so_client.elastic as elastic_mod

    built: list[Settings] = []

    def _client(given: Settings) -> _Grid:
        built.append(given)
        return grid

    monkeypatch.setattr(elastic_mod, "ElasticClient", _client)
    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    return built


async def test_the_dry_run_sends_no_search_and_the_run_does(
    settings_kratos: Settings,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    settings = _settings(settings_kratos, tmp_path / "data")
    await _live_store(settings)
    grid = _grid()
    built = _patch_client(monkeypatch, settings, grid)
    store = tmp_path / "scratch" / "replay.db"

    code = await _run_cli_off_loop(monkeypatch, _argv(store, "--dry-run"))

    out = capsys.readouterr().out
    assert code == 0
    assert grid.searches == 0, "the dry run searched the grid"
    assert built == [], "the dry run built a grid client"
    assert not store.exists() and not store.parent.exists(), "the dry run created the store"
    assert "Prior sweeps: 48, one at each hour" in out
    assert "Profile builds: 2" in out
    assert "9 addresses and 0 agent names" in out
    assert "Searches estimated: at least" in out
    # The plan names the evaluators, the analytics each covers and the
    # searches the detectors add: two per detector per sweep.
    assert "Evaluators: profile, model" in out
    assert f"  profile evaluator: {len(sr.profile_analytics())} analytics" in out
    assert "  model evaluator: 2 analytics" in out
    assert f"    {SILENCE_ID}, detector cross_plane_silence" in out
    assert f"    {CHAIN_ID}, detector logon_chain" in out
    assert (
        "The model evaluator makes at least 4 of the searches of each sweep, 192 in total."
    ) in out
    assert "The replay leaves out the match evaluator" in out
    both = _estimated(out)

    # The profile evaluator alone: the plan says it leaves the detectors out,
    # and the estimate drops their searches.
    code = await _run_cli_off_loop(monkeypatch, _argv(store, "--evaluator", "profile", "--dry-run"))
    alone = capsys.readouterr().out
    assert code == 0
    assert grid.searches == 0
    assert "Evaluators: profile\n" in alone
    assert "model evaluator: 2 analytics" not in alone
    assert "The model evaluator makes" not in alone
    assert (
        "  The replay leaves out the model evaluator: model-cross-plane-silence, "
        "model-logon-chain. --evaluator does not name it. The report holds no rate for them."
    ) in alone
    assert _estimated(alone) == both - 192

    # Negative control: the same command without --dry-run searches the same grid.
    code = await _run_cli_off_loop(monkeypatch, _argv(store))
    assert code == 3, "the planted estate is over budget"
    assert built == [settings]
    assert grid.searches > 0
    assert (store.with_suffix("") / "report.json").is_file()
    assert (store.with_suffix("") / "report.md").is_file()
    # The estimate is a lower bound of what the run sent, for the detectors too.
    plan = sr.plan_replay(
        settings, days=2, end=END, store=tmp_path / "other.db", hosts_from_census=True, now=PRESENT
    )
    estimate = sr.estimate_searches(plan, addresses=9, names=0)
    assert estimate.total == both
    assert 0 < estimate.total <= grid.searches, (estimate, grid.searches)
    assert 0 < estimate.model_total <= grid.planes.searches + grid.logons.searches


def _estimated(out: str) -> int:
    """The search estimate that a dry run printed."""
    import re

    found = re.search(r"Searches estimated: at least ([\d,]+)\.", out)
    assert found is not None, out
    return int(found.group(1).replace(",", ""))


async def _run_cli_off_loop(monkeypatch: pytest.MonkeyPatch, argv: list[str]) -> int:
    """The command runs its own event loop, so it runs in a thread here."""
    import asyncio

    return await asyncio.to_thread(_main, monkeypatch, argv)


async def test_the_replay_refuses_the_live_store(
    settings_kratos: Settings,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    settings = _settings(settings_kratos, tmp_path / "data")
    live = await _live_store(settings)
    before = _digest(live)
    grid = _grid()
    built = _patch_client(monkeypatch, settings, grid)
    alias = tmp_path / "alias.db"
    alias.symlink_to(live)

    for store in (live, live.parent / "." / "soc-ai.db", alias):
        code = _main(monkeypatch, _argv(store))
        err = capsys.readouterr().err
        assert code == 2, store
        assert "live store" in err, err
        with pytest.raises(sr.ReplayRefused, match="live store"):
            sr.plan_replay(settings, days=1, end=END, store=store, now=PRESENT)

    assert grid.searches == 0
    assert built == []
    assert _digest(live) == before
    assert not (live.parent / "replay").exists()

    # Negative control: a scratch path beside it is accepted.
    plan = sr.plan_replay(
        settings, days=1, end=END, store=live.parent / "replay" / "x.db", now=PRESENT
    )
    assert plan.store == (live.parent / "replay" / "x.db").absolute()


async def test_the_plan_refuses_what_would_mismeasure(
    settings_kratos: Settings, tmp_path: Path
) -> None:
    settings = _settings(settings_kratos, tmp_path / "data")
    existing = tmp_path / "used.db"
    existing.write_bytes(b"")
    with pytest.raises(sr.ReplayRefused, match="exists"):
        sr.plan_replay(settings, end=END, store=existing, now=PRESENT)
    with pytest.raises(sr.ReplayRefused, match="later than the present hour"):
        sr.plan_replay(settings, end=PRESENT + HOUR, store=tmp_path / "a.db", now=PRESENT)
    with pytest.raises(sr.ReplayRefused, match="not a shipped analytic of the profile or model"):
        sr.plan_replay(
            settings, end=END, analytics=["no-such"], store=tmp_path / "a.db", now=PRESENT
        )
    # The catalog sweep runs the match analytics. An unknown evaluator is refused.
    with pytest.raises(sr.ReplayRefused, match="catalog sweep runs the match analytics"):
        sr.plan_replay(
            settings, end=END, evaluators=["match"], store=tmp_path / "a.db", now=PRESENT
        )
    with pytest.raises(sr.ReplayRefused, match="nope is not an evaluator"):
        sr.plan_replay(settings, end=END, evaluators=["nope"], store=tmp_path / "a.db", now=PRESENT)
    # A detector named with the profile evaluator alone: the message names the flag.
    with pytest.raises(sr.ReplayRefused, match="Add --evaluator model"):
        sr.plan_replay(
            settings,
            end=END,
            evaluators=["profile"],
            analytics=[CHAIN_ID],
            store=tmp_path / "a.db",
            now=PRESENT,
        )
    # Negative control: the same analytic with its evaluator is accepted.
    named = sr.plan_replay(
        settings,
        end=END,
        evaluators=["model"],
        analytics=[CHAIN_ID],
        store=tmp_path / "a.db",
        now=PRESENT,
    )
    assert (named.analytics, named.detectors, named.builds) == ((CHAIN_ID,), ("logon_chain",), 0)

    # The defaults: seven days to the present hour, a store in the data directory,
    # both evaluators, the profile analytics first.
    plan = sr.plan_replay(settings, now=PRESENT + timedelta(minutes=17))
    assert plan.end == PRESENT
    assert plan.start == PRESENT - timedelta(days=7)
    assert plan.store.parent == (tmp_path / "data" / "replay").absolute()
    assert plan.out == plan.store.with_suffix("")
    assert plan.evaluators == sr.REPLAY_EVALUATORS == ("profile", "model")
    assert plan.analytics == (*sr.profile_analytics(), *_MODEL)
    assert plan.by_evaluator == {"profile": tuple(sr.profile_analytics()), "model": _MODEL}
    assert plan.detectors == ("cross_plane_silence", "logon_chain")
    assert plan.builds == 7


def test_the_wilson_upper_bound() -> None:
    # Zero hits in 100 trials: z^2 / (n + z^2).
    assert sr.wilson_upper(0, 100) == pytest.approx(0.03699, abs=1e-4)
    assert sr.wilson_upper(1, 100) == pytest.approx(0.05449, abs=1e-4)
    assert sr.wilson_upper(5, 5) == 1.0
    assert sr.wilson_upper(0, 0) is None


# ---------------------------------------------------------------------------
# The verdict
# ---------------------------------------------------------------------------


def _row(analytic: str, hits: int, host_days: int) -> sr.AnalyticRow:
    row = sr.AnalyticRow(analytic=analytic, dimension="served_ports")
    row.hits, row.host_days = hits, host_days
    row.per_100_host_days = sr._per_100(hits, host_days)
    row.wilson_upper_95_per_100 = sr._upper_per_100(hits, host_days)
    row.verdict = sr._verdict(hits, host_days)
    return row


def _report_of(*rows: sr.AnalyticRow) -> sr.ReplayReport:
    verdict, notes = sr.fold_verdicts(rows)
    return sr.ReplayReport(
        start=WINDOW_START.isoformat(),
        end=END.isoformat(),
        days=7,
        hours=168,
        store="/tmp/replay.db",
        analytics=list(rows),
        day_rows=[],
        unread_hours=[],
        hits=sum(r.hits for r in rows),
        host_days=sum(r.host_days for r in rows),
        verdict=verdict,
        notes=notes,
    )


def test_the_notes_name_the_evaluators_the_replay_ran_and_left_out() -> None:
    """The replay ran the profile analytics and its report did not say so. An
    operator read the verdict as the verdict of the learned detectors too."""
    catalog = load_catalog(CATALOG_DIR)
    profile = sorted(sr.profile_analytics(catalog))
    model = sorted(a for a, spec in catalog.items() if spec.evaluator == "model")
    match = [a for a, spec in catalog.items() if spec.evaluator == "match"]
    assert model == ["model-cross-plane-silence", "model-logon-chain"]

    # The profile evaluator alone, on two of its analytics.
    notes = sr.evaluator_notes(catalog, profile[:2], ("profile",))
    assert notes[0] == (
        f"The replay runs the profile evaluator on 2 analytics: {', '.join(profile[:2])}."
    )
    assert notes[1] == (
        f"The replay leaves out {len(profile) - 2} profile analytics that --analytic does not "
        f"name: {', '.join(profile[2:])}."
    )
    assert (
        "The replay leaves out the model evaluator: model-cross-plane-silence, "
        "model-logon-chain. --evaluator does not name it. The report holds no rate for them."
    ) in notes
    assert (
        f"The replay leaves out the match evaluator: {len(match)} analytics. The catalog sweep "
        "runs them. The report holds no rate for them."
    ) in notes

    # Both evaluators, on every analytic: one line for each, and the match line.
    both = sr.evaluator_notes(catalog, [*profile, *model])
    assert both == [
        f"The replay runs the profile evaluator on {len(profile)} analytics: {', '.join(profile)}.",
        "The replay runs the model evaluator on 2 analytics: model-cross-plane-silence, "
        "model-logon-chain.",
        f"The replay leaves out the match evaluator: {len(match)} analytics. The catalog sweep "
        "runs them. The report holds no rate for them.",
    ]

    # Negative control: a catalog of profile analytics, all of them run.
    only = {a: catalog[a] for a in profile}
    assert sr.evaluator_notes(only, profile, ("profile",)) == [
        f"The replay runs the profile evaluator on {len(profile)} analytics: {', '.join(profile)}."
    ]


def test_no_hit_on_a_few_host_days_is_not_enough_host_days() -> None:
    """The range replay read 0 hits in 7 host-days as within budget. The
    Wilson upper bound was 35 per 100, 35 times the budget."""
    assert sr._verdict(0, 7) == sr.TOO_FEW
    assert sr.host_days_needed() == 381
    report = _report_of(_row("prior-server-internet-nonweb-novel-port", 0, 7))
    assert report.verdict == sr.TOO_FEW
    assert report.exit_code == 4
    text = sr.render_markdown(report)
    assert "Verdict: not enough host-days." in text
    assert "| not enough host-days |" in text
    assert (
        "Not enough host-days for prior-server-internet-nonweb-novel-port. Each Wilson upper "
        "bound is over the budget. A within-budget verdict needs 381 host-days with no hit."
    ) in text
    assert report.to_dict()["host_days_needed_with_no_hit"] == 381
    lines = sr.summary_lines(report)
    assert any("Wilson upper 35.43, not enough host-days" in line for line in lines), lines
    assert "A within-budget verdict needs 381 host-days with no hit." in lines


def test_within_budget_needs_the_upper_bound_at_or_under_the_budget() -> None:
    """381 host-days with no hit put the bound under 1 per 100. 380 do not.
    That one host-day is the negative control."""
    assert sr._verdict(0, 381) == sr.WITHIN
    assert sr._verdict(0, 380) == sr.TOO_FEW
    assert sr._verdict(1, 1000) == sr.WITHIN
    report = _report_of(_row("a", 0, 381), _row("b", 1, 1000))
    assert report.verdict == sr.WITHIN
    assert report.exit_code == 0
    assert report.notes == []
    assert "Not enough host-days" not in sr.render_markdown(report)
    assert not [line for line in sr.summary_lines(report) if "needs 381" in line]


def test_a_rate_over_the_budget_is_over_budget_whatever_the_host_days() -> None:
    """Over budget reads the rate. A short row beside it does not soften it."""
    assert sr._verdict(2, 100) == sr.OVER
    assert sr._verdict(1, 7) == sr.OVER
    # 1 hit in 100 host-days is at the budget, and the bound is far over it.
    assert sr._verdict(1, 100) == sr.TOO_FEW
    report = _report_of(_row("a", 4, 41), _row("b", 0, 7))
    assert report.verdict == sr.OVER
    assert report.exit_code == 3
    # The short row still gets its note.
    assert any(note.startswith("Not enough host-days for b.") for note in report.notes)


def test_the_parser_takes_the_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, argparse.Namespace] = {}

    def fake(args: argparse.Namespace) -> int:
        captured["args"] = args
        return 0

    monkeypatch.setattr(cli, "_spec_replay", fake)
    argv = [
        "soc-ai",
        "spec-replay",
        "--analytic",
        "profile-connection-rate-spiked",
        "--analytic",
        "profile-connection-rate-collapsed",
        "--out",
        "/tmp/out",
        "--dry-run",
    ]
    assert _main(monkeypatch, argv) == 0
    args = captured["args"]
    assert args.days == 7
    assert args.end is None and args.store is None
    assert args.analytic == ["profile-connection-rate-spiked", "profile-connection-rate-collapsed"]
    assert args.dry_run is True and args.hosts_from_census is False
    assert args.evaluator is None, "no flag leaves the default to the plan: both evaluators"
    argv = ["soc-ai", "spec-replay", "--evaluator", "profile", "--evaluator", "model"]
    assert _main(monkeypatch, argv) == 0
    assert captured["args"].evaluator == ["profile", "model"]
    assert _main(monkeypatch, ["soc-ai", "spec-replay", "--days", "0"]) == 2


# ---------------------------------------------------------------------------
# The build's time anchor
# ---------------------------------------------------------------------------


async def test_an_anchored_build_reads_and_stamps_its_anchor(settings_kratos: Settings) -> None:
    """A replay builds a past day. The build had no anchor, so it read the present."""
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    maker = make_sessionmaker(engine)
    anchor = START + timedelta(days=3)
    grid = _Recorder(SyntheticGrid(hosts=_estate(), clock=anchor + timedelta(days=10)))
    settings = _Settings()
    settings.entity_profiles_enabled = True

    build = await build_profiles(grid, maker, settings, CIDRS, now=anchor)

    assert build.errors == []
    assert build.written > 0
    lag = settings.entity_profile_lag_hours * 60
    span = settings.entity_profile_window_days * 24 * 60 + lag
    assert grid.windows, "the build made no windowed read"
    assert all(w.get("gte") == f"{anchor.isoformat()}||-{span}m" for w in grid.windows)
    assert all(w.get("lte") == f"{anchor.isoformat()}||-{lag}m" for w in grid.windows)
    async with maker() as db:
        stamps = set((await db.scalars(select(EntityProfile.built_at))).all())
        shapes = set((await db.scalars(select(EntityProfile.shape_version))).all())
    assert stamps == {anchor.replace(tzinfo=None)}
    assert shapes == {PROFILE_SHAPE}

    # Rows of an older shape at the anchor: the next anchored build reads
    # every host again and stamps both the anchor and the shape.
    async with maker() as db:
        await db.execute(update(EntityProfile).values(shape_version=None))
        await db.commit()
    later = anchor + timedelta(hours=1)
    again = await build_profiles(grid, maker, settings, CIDRS, now=later)
    assert again.errors == []
    assert again.reshaped > 0
    async with maker() as db:
        stamps = set((await db.scalars(select(EntityProfile.built_at))).all())
        shapes = set((await db.scalars(select(EntityProfile.shape_version))).all())
    assert stamps == {later.replace(tzinfo=None)}
    assert shapes == {PROFILE_SHAPE}
    await engine.dispose()


async def test_without_an_anchor_the_build_reads_and_stamps_the_present(
    settings_kratos: Settings,
) -> None:
    """Negative control: the hourly loop passes no anchor."""
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    maker = make_sessionmaker(engine)
    grid = _Recorder(SyntheticGrid(hosts=_estate(), clock=START + timedelta(days=3)))
    settings = _Settings()
    settings.entity_profiles_enabled = True

    before = datetime.now(UTC).replace(tzinfo=None)
    build = await build_profiles(grid, maker, settings, CIDRS)
    after = datetime.now(UTC).replace(tzinfo=None)

    assert build.written > 0
    assert grid.windows
    assert all(str(w.get("gte", "")).startswith("now-") for w in grid.windows)
    async with maker() as db:
        stamps = set((await db.scalars(select(EntityProfile.built_at))).all())
    assert stamps
    assert all(before <= s <= after for s in stamps)
    await engine.dispose()


def test_the_estimate_counts_one_build_per_day_and_one_sweep_per_hour(
    settings_kratos: Settings, tmp_path: Path
) -> None:
    settings = _settings(settings_kratos, tmp_path / "data")
    plan = sr.plan_replay(settings, days=3, end=END, store=tmp_path / "a.db", now=PRESENT)
    one = sr.estimate_searches(plan, addresses=9)
    assert one.total == 3 * one.per_build + 72 * one.per_sweep
    # Two detectors, two searches each, at each of the 72 sweeps.
    assert (one.per_model_sweep, one.model_total) == (4, 4 * 72)
    # More hosts than one batch holds add a batch of reads to each build.
    two = sr.estimate_searches(plan, addresses=501)
    assert two.per_build > one.per_build
    assert two.per_sweep == one.per_sweep

    # The profile evaluator alone: the same builds, and the sweeps without the detectors.
    profile = sr.plan_replay(
        settings, days=3, end=END, store=tmp_path / "b.db", now=PRESENT, evaluators=["profile"]
    )
    alone = sr.estimate_searches(profile, addresses=9)
    assert alone.per_build == one.per_build
    assert alone.per_sweep == one.per_sweep - 4
    assert (alone.per_model_sweep, alone.model_total) == (0, 0)
    # The model evaluator alone: no build, the detectors at each sweep.
    model = sr.plan_replay(
        settings, days=3, end=END, store=tmp_path / "c.db", now=PRESENT, evaluators=["model"]
    )
    detectors = sr.estimate_searches(model, addresses=9)
    assert (detectors.per_build, detectors.per_sweep, detectors.total) == (0, 4, 4 * 72)


def test_the_report_and_its_directory_are_private(tmp_path: Path) -> None:
    """The report names hosts and their hits, so only the service user reads it.

    The control: a directory the caller made loose beforehand is tightened,
    not left as it was.
    """
    import os
    import stat

    from soc_ai.hunting import spec_replay as sr

    out = tmp_path / "loose"
    out.mkdir(mode=0o755)
    report = _report_of()
    json_path, md_path = sr.write_report(report, out)
    for path in (json_path, md_path):
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(out).st_mode) == 0o700
