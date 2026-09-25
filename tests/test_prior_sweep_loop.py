"""The profile sweep loop: the hunting layer that must run with nobody watching.

On the test range the profile sweep runs from a host timer. Production runs in a
container, and a container has no timer. A deployment therefore recorded no
profile observation and formed no profile lead, while every surface stayed
green. That is the false all-clear this project keeps finding, reached from the
supply side: not a screen that lies, a job that nobody scheduled.

The tests mirror tests/test_hunt_spec_sweep_loop.py. They patch
``main.asyncio.sleep`` so the first N wakes return and the next one raises
``CancelledError``.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from soc_ai.config import Settings

pytestmark = pytest.mark.asyncio


class _Rows:
    """An empty ``scalars()`` result.

    A bare ``AsyncMock`` hands back a coroutine for ``.all()``, which the two
    store reads the loop makes before the sweep (the internal identifiers and
    the analytic states) then try to iterate. This is the honest empty answer:
    no identifier rows, no analytic state rows, so the loop sweeps the shipped
    catalog over the configured address space.
    """

    def all(self) -> list[Any]:
        return []

    def __iter__(self):  # type: ignore[no-untyped-def]
        return iter(())


def _app(settings: Settings, *, down: tuple[str, ...] = ()) -> SimpleNamespace:
    """Just enough app.state for the loop; it touches nothing else."""
    session = AsyncMock()
    session.commit = AsyncMock()
    session.scalars = AsyncMock(return_value=_Rows())
    maker = lambda: _CM(session)  # noqa: E731
    state = SimpleNamespace(settings=settings, db_sessionmaker=maker, elastic=AsyncMock())
    if down:
        state._dep_down_since = {dep: datetime(2026, 9, 22, 12, 0) for dep in down}
    return SimpleNamespace(state=state)


class _CM:
    def __init__(self, session):  # type: ignore[no-untyped-def]
        self._s = session

    async def __aenter__(self):  # type: ignore[no-untyped-def]
        return self._s

    async def __aexit__(self, *exc):  # type: ignore[no-untyped-def]
        return False


async def _tick(app: Any, sweeper: Any, wakes: int = 1) -> None:
    """Run the loop for ``wakes`` wakes with sleep collapsed to nothing."""
    from soc_ai.main import _prior_sweep_loop

    calls = {"n": 0}

    async def _fake_sleep(_seconds: float) -> None:
        calls["n"] += 1
        if calls["n"] > wakes:
            raise asyncio.CancelledError

    with (
        patch("soc_ai.main.asyncio.sleep", new=_fake_sleep),
        patch("soc_ai.hunting.prior_sweep.run_prior_sweep", new=sweeper),
        pytest.raises(asyncio.CancelledError),
    ):
        await _prior_sweep_loop(app)


def _read(path: str) -> str:
    """Blocking read, deliberately outside the async body (ASYNC240)."""
    import pathlib

    return pathlib.Path(path).read_text()


def _departure(member: str = "3389"):  # type: ignore[no-untyped-def]
    from soc_ai.hunting.priors import Departure

    return Departure(
        dimension="dst_port",
        member=member,
        observed={"count": 4},
        baseline_size=12,
        support_days=30,
        observed_count=4,
        sample_ids=("d1",),
    )


def _result(*, coverage: str = "measured", departures: tuple[Any, ...] = ()):  # type: ignore[no-untyped-def]
    from soc_ai.hunting.priors import PriorResult

    return PriorResult(
        spec_id="p1",
        entity_kind="host",
        entity_key="10.1.2.3",
        coverage=coverage,
        departures=departures,
    )


def _sweep(**over):  # type: ignore[no-untyped-def]
    from soc_ai.hunting.prior_sweep import PriorSweep

    return PriorSweep(**over)


def _lead_outcome(**over):  # type: ignore[no-untyped-def]
    from soc_ai.hunting.leads import LeadOutcome

    return LeadOutcome(**over)


def _profile_settings(settings: Settings, *, schedule_enabled: bool = False) -> Settings:
    """Profiles on, the dossier schedule as the range had it: off."""
    settings.entity_profiles_enabled = True
    settings.dossier_schedule_enabled = schedule_enabled
    settings.dossier_schedule_interval_hours = 24
    settings.hunting_prior_sweep_interval_minutes = 60
    return settings


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def _freshness(newest: datetime | None, unmeasurable: dict[str, str] | None = None):  # type: ignore[no-untyped-def]
    from soc_ai.store.entity_profiles import ProfileFreshness

    return ProfileFreshness(newest_built_at=newest, unmeasurable=dict(unmeasurable or {}))


def _build(written: int = 640):  # type: ignore[no-untyped-def]
    from soc_ai.dossier.profile_job import ProfileBuild

    return ProfileBuild(written=written)


async def _tick_with_profiles(app: Any, sweeper: Any, *, freshness: Any, builder: Any) -> None:
    """One wake with the profile job's two entry points replaced."""
    with (
        patch("soc_ai.dossier.profile_job.freshness", new=freshness),
        patch("soc_ai.dossier.profile_job.build_profiles", new=builder),
    ):
        await _tick(app, sweeper, wakes=1)


def _profile_lines(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [
        r.getMessage() for r in caplog.records if r.getMessage().startswith("prior sweep: profiles")
    ]


async def test_the_sweep_is_on_by_default(settings_kratos: Settings) -> None:
    """The opposite posture to the catalog sweep, for the opposite reason.

    A catalog sweep writes findings, so it is opt-in. A profile sweep writes
    observations. Nothing is raised and nobody is paged. A deployment with no
    profile observation has no hunting layer at all, so off by default would
    ship the layer and never run it.
    """
    assert settings_kratos.hunting_prior_sweep_enabled is True
    assert settings_kratos.hunting_prior_sweep_interval_minutes == 60


async def test_off_it_does_not_sweep(settings_kratos: Settings) -> None:
    settings = settings_kratos.model_copy(update={"hunting_prior_sweep_enabled": False})
    sweeper = AsyncMock()
    await _tick(_app(settings), sweeper, wakes=3)
    sweeper.assert_not_awaited()


async def test_on_it_runs_the_sweep_the_cli_runs(settings_kratos: Settings) -> None:
    """``record=True``: the loop replaces ``soc-ai priors --record``.

    A sweep that reads and records nothing is the state this loop exists to
    end, so the flag is pinned rather than assumed.
    """
    sweeper = AsyncMock(return_value=_sweep(results=(_result(),)))
    await _tick(_app(settings_kratos), sweeper, wakes=1)
    sweeper.assert_awaited_once()
    assert sweeper.await_args.kwargs["record"] is True


async def test_it_hands_the_sweep_the_effective_catalog(settings_kratos: Settings) -> None:
    """A retired prior must stop running and a local one in shadow must start.

    Both facts live in the database, so the loop reads the catalog through
    ``effective_catalog`` exactly as the CLI and the catalog sweep do.
    """
    sweeper = AsyncMock(return_value=_sweep(results=(_result(),)))
    await _tick(_app(settings_kratos), sweeper, wakes=1)
    kwargs = sweeper.await_args.kwargs
    assert kwargs["catalog"], "the loop swept with no catalog"
    assert isinstance(kwargs["shadow_ids"], frozenset)


async def test_it_respects_its_interval_rather_than_sweeping_every_wake(
    settings_kratos: Settings,
) -> None:
    """The loop wakes every 60 s. The interval decides whether it works."""
    settings = settings_kratos.model_copy(
        update={"hunting_prior_sweep_interval_minutes": 60},
    )
    sweeper = AsyncMock(return_value=_sweep(results=(_result(),)))
    await _tick(_app(settings), sweeper, wakes=5)
    assert sweeper.await_count == 1, "the loop swept on every wake, ignoring its interval"


async def test_the_interval_has_a_floor(settings_kratos: Settings) -> None:
    """A profile sweep is several aggregations per dimension against the grid.

    The floor is the one number the config console cannot enforce on its own:
    an override written before the bound existed, or a settings object built in
    code, both reach the loop unchecked.
    """
    from soc_ai.main import PRIOR_SWEEP_MIN_INTERVAL_MINUTES, _prior_sweep_interval_minutes

    def _floor(minutes: Any) -> int:
        return _prior_sweep_interval_minutes(
            SimpleNamespace(hunting_prior_sweep_interval_minutes=minutes)
        )

    assert PRIOR_SWEEP_MIN_INTERVAL_MINUTES == 15
    assert _floor(0) == 15
    assert _floor(5) == 15
    assert _floor(60) == 60
    assert _floor(240) == 240


async def test_a_zero_interval_still_does_not_sweep_every_wake(
    settings_kratos: Settings,
) -> None:
    """The floor holds in the loop, not only in the helper."""
    settings = settings_kratos.model_copy(
        update={"hunting_prior_sweep_interval_minutes": 0},
    )
    sweeper = AsyncMock(return_value=_sweep(results=(_result(),)))
    await _tick(_app(settings), sweeper, wakes=3)
    assert sweeper.await_count == 1, "a zero interval swept on every wake"


async def test_a_failed_sweep_does_not_kill_the_loop(settings_kratos: Settings) -> None:
    """One bad sweep must not silently end profile hunting for the process."""
    sweeper = AsyncMock(side_effect=[RuntimeError("grid down"), _sweep(results=(_result(),))])
    await _tick(_app(settings_kratos), sweeper, wakes=2)
    assert sweeper.await_count == 2, "the loop stopped after the first failure"


async def test_a_failed_sweep_is_logged(
    settings_kratos: Settings, caplog: pytest.LogCaptureFixture
) -> None:
    """A loop that swallows its failure silently is a job nobody knows is dead."""
    sweeper = AsyncMock(side_effect=RuntimeError("grid down"))
    with caplog.at_level(logging.WARNING):
        await _tick(_app(settings_kratos), sweeper, wakes=1)
    said = [r.getMessage() for r in caplog.records if "prior sweep" in r.getMessage()]
    assert any("grid down" in m for m in said), said


async def test_a_failed_sweep_is_retried_rather_than_skipping_an_interval(
    settings_kratos: Settings,
) -> None:
    """The last-run stamp is written only after a sweep that returned.

    Stamping before would turn one failure into a skipped hour, and on a
    24-hour profile window an hour of not recording is an hour the baseline
    never learns about.
    """
    settings = settings_kratos.model_copy(
        update={"hunting_prior_sweep_interval_minutes": 1440},
    )
    sweeper = AsyncMock(side_effect=[RuntimeError("boom"), _sweep(results=(_result(),))])
    await _tick(_app(settings), sweeper, wakes=2)
    assert sweeper.await_count == 2, "a failed sweep consumed the whole interval"


async def test_it_says_what_the_sweep_recorded(
    settings_kratos: Settings, caplog: pytest.LogCaptureFixture
) -> None:
    """One line per run, with the three numbers that describe the run.

    Observations recorded, leads formed, and pairs the sweep could not measure.
    The third number is the one an operator needs most: without it a sweep that
    saw nothing reads the same as a sweep that could see nothing.
    """
    sweep = _sweep(
        results=(
            _result(departures=(_departure("3389"), _departure("445"))),
            _result(coverage="blind"),
        ),
        leads=_lead_outcome(formed=(7,)),
    )
    sweeper = AsyncMock(return_value=sweep)
    with caplog.at_level(logging.INFO):
        await _tick(_app(settings_kratos), sweeper, wakes=1)
    said = [r.getMessage() for r in caplog.records if "prior sweep" in r.getMessage()]
    assert len(said) == 1, f"one line per run, got {said}"
    assert "2 observation" in said[0]
    assert "1 lead" in said[0]
    assert "1 blind" in said[0]


async def test_a_sweep_with_no_dossier_behind_it_reports_blind(
    settings_kratos: Settings, caplog: pytest.LogCaptureFixture
) -> None:
    """The two loops are not coupled, and this is what that costs and buys.

    The dossier loop builds the baselines the priors read. It may not have run
    yet. The sweep runs anyway and reports what it could not measure, exactly
    as the CLI does. Blocking on the dossier instead would make one loop able
    to stop the other.
    """
    sweeper = AsyncMock(return_value=_sweep(results=(_result(coverage="blind"),)))
    with caplog.at_level(logging.INFO):
        await _tick(_app(settings_kratos), sweeper, wakes=1)
    sweeper.assert_awaited_once()
    said = [r.getMessage() for r in caplog.records if "prior sweep" in r.getMessage()]
    assert "1 blind" in said[0], said


async def test_a_sweep_that_could_not_read_the_grid_says_so(
    settings_kratos: Settings, caplog: pytest.LogCaptureFixture
) -> None:
    """The sweep never raises. It returns its errors, so the loop must say them."""
    sweeper = AsyncMock(return_value=_sweep(errors=("could not read host roles: nope",)))
    with caplog.at_level(logging.WARNING):
        await _tick(_app(settings_kratos), sweeper, wakes=1)
    said = [r.getMessage() for r in caplog.records if "prior sweep" in r.getMessage()]
    assert any("could not read host roles" in m for m in said), said


async def test_it_skips_a_demo(settings_kratos: Settings) -> None:
    """A demo has no grid to sweep and must never write an observation."""
    settings = settings_kratos.model_copy(update={"soc_ai_demo": True})
    sweeper = AsyncMock()
    await _tick(_app(settings), sweeper, wakes=3)
    sweeper.assert_not_awaited()


async def test_it_skips_while_the_grid_is_down(settings_kratos: Settings) -> None:
    """A sweep against a grid that is known to be down measures nothing.

    Worse, it records that nothing departed. The health probe loop already
    holds the answer, so the check costs no query.
    """
    sweeper = AsyncMock()
    await _tick(_app(settings_kratos, down=("es",)), sweeper, wakes=3)
    sweeper.assert_not_awaited()


async def test_a_down_llm_does_not_stop_the_sweep(settings_kratos: Settings) -> None:
    """NEGATIVE CONTROL. The sweep calls no model, so the gateway is irrelevant."""
    sweeper = AsyncMock(return_value=_sweep(results=(_result(),)))
    await _tick(_app(settings_kratos, down=("llm",)), sweeper, wakes=1)
    sweeper.assert_awaited_once()


async def test_the_toggle_applies_without_a_restart(settings_kratos: Settings) -> None:
    """Settings are read live each wake, like every other scheduler here."""
    from soc_ai.main import _prior_sweep_loop

    settings = settings_kratos.model_copy(update={"hunting_prior_sweep_enabled": False})
    app = _app(settings)
    sweeper = AsyncMock(return_value=_sweep(results=(_result(),)))
    wakes = {"n": 0}

    async def _fake_sleep(_seconds: float) -> None:
        wakes["n"] += 1
        if wakes["n"] == 2:
            app.state.settings = settings.model_copy(update={"hunting_prior_sweep_enabled": True})
        if wakes["n"] > 3:
            raise asyncio.CancelledError

    with (
        patch("soc_ai.main.asyncio.sleep", new=_fake_sleep),
        patch("soc_ai.hunting.prior_sweep.run_prior_sweep", new=sweeper),
        pytest.raises(asyncio.CancelledError),
    ):
        await _prior_sweep_loop(app)

    assert sweeper.await_count >= 1, "flipping the toggle mid-run had no effect"


async def test_cancellation_is_not_swallowed_by_the_error_handler(
    settings_kratos: Settings,
) -> None:
    """Shutdown must actually stop it.

    The loop catches broad exceptions so one bad sweep cannot kill it. A bare
    ``except Exception`` that also caught ``CancelledError`` would make the task
    un-cancellable and hang the lifespan. The explicit re-raise stops that, and
    this is what holds it.
    """
    from soc_ai.main import _prior_sweep_loop

    sweeper = AsyncMock(side_effect=asyncio.CancelledError)

    async def _no_sleep(_seconds: float) -> None:
        return None

    with (
        patch("soc_ai.main.asyncio.sleep", new=_no_sleep),
        patch("soc_ai.hunting.prior_sweep.run_prior_sweep", new=sweeper),
        pytest.raises(asyncio.CancelledError),
    ):
        await _prior_sweep_loop(_app(settings_kratos))


@pytest.mark.asyncio(loop_scope="function")
async def test_the_loop_is_registered_and_cancelled_in_the_lifespan() -> None:
    """A task created and never cancelled would keep the process alive on shutdown."""
    from soc_ai import main

    source = _read(main.__file__)
    assert "prior_sweep_task = asyncio.create_task(_prior_sweep_loop(app))" in source
    assert "prior_sweep_task.cancel()" in source


# ---------------------------------------------------------------------------
# Profile freshness: the sweep is the only consumer, so the sweep owns it
# ---------------------------------------------------------------------------


async def test_stale_profiles_are_rebuilt_before_the_sweep_whatever_the_dossier_schedule_says(
    settings_kratos: Settings, caplog: pytest.LogCaptureFixture
) -> None:
    """The range: the dossier schedule was off, the host timer that built the
    baselines was retired, and the sweep evaluated three-day-old profiles
    every hour and reported ~640 blind. Two schedules an operator has to wire
    together is one schedule too many."""
    settings = _profile_settings(settings_kratos, schedule_enabled=False)
    order: list[str] = []
    seen: dict[str, Any] = {}
    stale_stamp = _now() - timedelta(hours=26)

    async def _read(_maker: Any) -> Any:
        # Stale before the rebuild, current after it.
        return _freshness(stale_stamp if "build" not in order else _now())

    async def _builder(*args: Any, **kwargs: Any) -> Any:
        order.append("build")
        return _build(640)

    async def _sweeper(**kwargs: Any) -> Any:
        order.append("sweep")
        seen.update(kwargs)
        return _sweep(results=(_result(),))

    with caplog.at_level(logging.INFO):
        await _tick_with_profiles(_app(settings), _sweeper, freshness=_read, builder=_builder)
    assert order == ["build", "sweep"]
    state = seen["profiles"]
    assert state.stale is False
    assert state.built_at is not None
    assert _profile_lines(caplog) == ["prior sweep: profiles 26 h old, rebuilt 640 row(s)"]


async def test_fresh_profiles_are_read_not_rebuilt(
    settings_kratos: Settings, caplog: pytest.LogCaptureFixture
) -> None:
    settings = _profile_settings(settings_kratos)
    fresh_stamp = _now() - timedelta(hours=1)
    builder = AsyncMock(return_value=_build())
    sweeper = AsyncMock(return_value=_sweep(results=(_result(),)))
    with caplog.at_level(logging.INFO):
        await _tick_with_profiles(
            _app(settings),
            sweeper,
            freshness=AsyncMock(return_value=_freshness(fresh_stamp)),
            builder=builder,
        )
    builder.assert_not_awaited()
    sweeper.assert_awaited_once()
    state = sweeper.await_args.kwargs["profiles"]
    assert state.built_at == fresh_stamp
    assert state.stale is False
    assert _profile_lines(caplog) == ["prior sweep: profiles 1 h old"]


async def test_profiles_never_built_are_built(
    settings_kratos: Settings, caplog: pytest.LogCaptureFixture
) -> None:
    settings = _profile_settings(settings_kratos)
    reads = iter([_freshness(None), _freshness(_now())])

    async def _read(_maker: Any) -> Any:
        return next(reads)

    builder = AsyncMock(return_value=_build(12))
    sweeper = AsyncMock(return_value=_sweep(results=(_result(),)))
    with caplog.at_level(logging.INFO):
        await _tick_with_profiles(_app(settings), sweeper, freshness=_read, builder=builder)
    builder.assert_awaited_once()
    assert _profile_lines(caplog) == ["prior sweep: profiles never built, rebuilt 12 row(s)"]


async def test_a_stamp_in_the_future_reads_as_stale(settings_kratos: Settings) -> None:
    """A row stamped in local time east of UTC reads as built in the future.
    Rebuilding it is what writes the UTC stamp that ends the skew."""
    settings = _profile_settings(settings_kratos)
    reads = iter([_freshness(_now() + timedelta(hours=3)), _freshness(_now())])

    async def _read(_maker: Any) -> Any:
        return next(reads)

    builder = AsyncMock(return_value=_build())
    sweeper = AsyncMock(return_value=_sweep(results=(_result(),)))
    await _tick_with_profiles(_app(settings), sweeper, freshness=_read, builder=builder)
    builder.assert_awaited_once()


async def test_the_staleness_threshold_is_the_dossier_interval_floored_at_two_sweep_intervals(
    settings_kratos: Settings,
) -> None:
    from soc_ai.main import _profile_stale_after, _profiles_are_stale

    s = settings_kratos
    s.dossier_schedule_interval_hours = 24
    s.hunting_prior_sweep_interval_minutes = 60
    assert _profile_stale_after(s) == timedelta(hours=24)
    s.dossier_schedule_interval_hours = 1
    s.hunting_prior_sweep_interval_minutes = 60
    assert _profile_stale_after(s) == timedelta(minutes=120)
    s.dossier_schedule_interval_hours = 1
    s.hunting_prior_sweep_interval_minutes = 15
    assert _profile_stale_after(s) == timedelta(minutes=60)

    now = _now()
    day = timedelta(hours=24)
    assert _profiles_are_stale(None, now, day) is True
    assert _profiles_are_stale(now - timedelta(hours=1), now, day) is False
    assert _profiles_are_stale(now - timedelta(hours=25), now, day) is True
    assert _profiles_are_stale(now + timedelta(hours=3), now, day) is True


async def test_a_rebuild_failure_is_logged_and_the_sweep_still_runs(
    settings_kratos: Settings, caplog: pytest.LogCaptureFixture
) -> None:
    from soc_ai.api.webui import _get_dossier_status

    settings = _profile_settings(settings_kratos)
    app = _app(settings)
    builder = AsyncMock(side_effect=RuntimeError("the grid is gone"))
    sweeper = AsyncMock(return_value=_sweep(results=(_result(coverage="blind"),)))
    with caplog.at_level(logging.INFO):
        await _tick_with_profiles(
            app,
            sweeper,
            freshness=AsyncMock(return_value=_freshness(_now() - timedelta(days=3))),
            builder=builder,
        )
    sweeper.assert_awaited_once()
    assert sweeper.await_args.kwargs["profiles"].stale is True
    warned = [r.getMessage() for r in caplog.records if "profile rebuild failed" in r.getMessage()]
    assert warned and "the grid is gone" in warned[0]
    # The slot is released whatever happened inside it.
    assert _get_dossier_status(app.state).running is False


async def test_no_rebuild_while_a_dossier_sweep_holds_the_slot(
    settings_kratos: Settings, caplog: pytest.LogCaptureFixture
) -> None:
    """Two network sweeps at once is the connection-pool pressure that has
    frozen this app before. The rebuild shares the dossier's slot and yields."""
    from soc_ai.api.webui import _DossierStatus

    settings = _profile_settings(settings_kratos)
    app = _app(settings)
    held = _DossierStatus()
    held.running = True
    app.state._dossier_status = held
    builder = AsyncMock(return_value=_build())
    sweeper = AsyncMock(return_value=_sweep(results=(_result(),)))
    with caplog.at_level(logging.INFO):
        await _tick_with_profiles(
            app,
            sweeper,
            freshness=AsyncMock(return_value=_freshness(_now() - timedelta(days=3))),
            builder=builder,
        )
    builder.assert_not_awaited()
    sweeper.assert_awaited_once()
    assert sweeper.await_args.kwargs["profiles"].stale is True
    assert any("rebuild skipped this wake" in line for line in _profile_lines(caplog))
    assert held.running is True


async def test_the_unmeasurable_reason_rides_with_the_sweep(settings_kratos: Settings) -> None:
    settings = _profile_settings(settings_kratos)
    state = _freshness(_now() - timedelta(hours=1), {"active_hours": "too many buckets"})
    sweeper = AsyncMock(return_value=_sweep(results=(_result(),)))
    await _tick_with_profiles(
        _app(settings),
        sweeper,
        freshness=AsyncMock(return_value=state),
        builder=AsyncMock(return_value=_build()),
    )
    assert sweeper.await_args.kwargs["profiles"].reason == "active_hours: too many buckets"


async def test_profiles_off_means_no_freshness_read(settings_kratos: Settings) -> None:
    assert settings_kratos.entity_profiles_enabled is False
    reader = AsyncMock(return_value=_freshness(None))
    sweeper = AsyncMock(return_value=_sweep(results=(_result(),)))
    await _tick_with_profiles(_app(settings_kratos), sweeper, freshness=reader, builder=AsyncMock())
    reader.assert_not_awaited()
    assert sweeper.await_args.kwargs["profiles"] is None
