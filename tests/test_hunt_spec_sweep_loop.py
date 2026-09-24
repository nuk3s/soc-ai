"""The catalog sweep loop: off by default, and honest about its own cadence.

This is the seventh lifespan task and the first one that writes findings with no
human in the loop, so the tests here are mostly about restraint: it must do
nothing until an operator turns it on, it must not double-fire, and one bad
sweep must not take the loop out.
"""

from __future__ import annotations

import asyncio
import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from soc_ai.config import Settings

pytestmark = pytest.mark.asyncio


def _app(settings: Settings) -> SimpleNamespace:
    """Just enough app.state for the loop; it touches nothing else."""
    session = AsyncMock()
    session.commit = AsyncMock()
    maker = lambda: _CM(session)  # noqa: E731
    return SimpleNamespace(
        state=SimpleNamespace(settings=settings, db_sessionmaker=maker, elastic=AsyncMock())
    )


class _CM:
    def __init__(self, session):  # type: ignore[no-untyped-def]
        self._s = session

    async def __aenter__(self):  # type: ignore[no-untyped-def]
        return self._s

    async def __aexit__(self, *exc):  # type: ignore[no-untyped-def]
        return False


async def _tick(app, sweeper, wakes: int = 1) -> None:
    """Run the loop for ``wakes`` wakes with sleep collapsed to nothing."""
    from soc_ai.main import _hunt_spec_sweep_loop

    calls = {"n": 0}

    async def _fake_sleep(_seconds: float) -> None:
        calls["n"] += 1
        if calls["n"] > wakes:
            raise asyncio.CancelledError

    with (
        patch("soc_ai.main.asyncio.sleep", new=_fake_sleep),
        patch("soc_ai.hunting.sweep.sweep_catalog", new=sweeper),
        pytest.raises(asyncio.CancelledError),
    ):
        await _hunt_spec_sweep_loop(app)


def _read(path: str) -> str:
    """Blocking read, deliberately outside the async body (ASYNC240)."""
    import pathlib

    return pathlib.Path(path).read_text()


def _result(**over):  # type: ignore[no-untyped-def]
    from soc_ai.hunting.sweep import SweepResult

    return SweepResult(**over)


async def test_it_does_nothing_until_an_operator_turns_it_on(
    settings_kratos: Settings,
) -> None:
    """Off by default. It writes findings unattended, so it is opt-in twice over.

    Once by this flag, and once by the shadow week the setting's own help text
    asks for before the flag is flipped.
    """
    assert settings_kratos.hunt_spec_sweeps_enabled is False
    sweeper = AsyncMock()
    await _tick(_app(settings_kratos), sweeper, wakes=3)
    sweeper.assert_not_awaited()


async def test_enabled_it_sweeps_the_catalog(settings_kratos: Settings) -> None:
    settings = settings_kratos.model_copy(update={"hunt_spec_sweeps_enabled": True})
    sweeper = AsyncMock(return_value=_result(ran=["a"], fresh_candidates=1, hunts={"a": "h1"}))
    await _tick(_app(settings), sweeper, wakes=1)
    sweeper.assert_awaited_once()


async def test_it_respects_its_interval_rather_than_sweeping_every_wake(
    settings_kratos: Settings,
) -> None:
    """The loop wakes every 60s; the interval is what decides whether it works."""
    settings = settings_kratos.model_copy(
        update={"hunt_spec_sweeps_enabled": True, "hunt_spec_sweep_interval_minutes": 60}
    )
    sweeper = AsyncMock(return_value=_result(ran=["a"]))
    await _tick(_app(settings), sweeper, wakes=5)
    assert sweeper.await_count == 1, "the loop swept on every wake, ignoring its interval"


async def test_the_lookback_window_is_wider_than_the_interval(
    settings_kratos: Settings,
) -> None:
    """A spec looking back only as far as the last sweep misses an outage.

    That is precisely the hole a live-tailing rule engine has, and the reason
    this project's own range doc records a Sigma rule that never fired: its
    cursor had already passed the attack. A query has no cursor, and the overlap
    is what makes that true in practice. The fire-once gate stops the overlap
    becoming repeat findings.
    """
    settings = settings_kratos.model_copy(update={"hunt_spec_sweeps_enabled": True})
    assert settings.hunt_spec_sweep_window_minutes > settings.hunt_spec_sweep_interval_minutes

    sweeper = AsyncMock(return_value=_result(ran=["a"]))
    await _tick(_app(settings), sweeper, wakes=1)
    since = sweeper.await_args.kwargs["since"]
    assert since == f"now-{settings.hunt_spec_sweep_window_minutes}m"


async def test_the_interval_has_a_floor(settings_kratos: Settings) -> None:
    """Cheap is not free: each sweep is a real query against the analyst's grid."""
    settings = settings_kratos.model_copy(
        update={"hunt_spec_sweeps_enabled": True, "hunt_spec_sweep_interval_minutes": 0}
    )
    sweeper = AsyncMock(return_value=_result(ran=["a"]))
    await _tick(_app(settings), sweeper, wakes=3)
    assert sweeper.await_count == 1, "a zero interval swept on every wake"


async def test_a_failed_sweep_does_not_kill_the_loop(settings_kratos: Settings) -> None:
    """One bad sweep must not silently end proactive hunting for the process."""
    settings = settings_kratos.model_copy(
        update={"hunt_spec_sweeps_enabled": True, "hunt_spec_sweep_interval_minutes": 5}
    )
    sweeper = AsyncMock(side_effect=[RuntimeError("grid down"), _result(ran=["a"])])
    await _tick(_app(settings), sweeper, wakes=2)
    assert sweeper.await_count == 2, "the loop stopped after the first failure"


async def test_a_failed_sweep_is_retried_rather_than_skipping_an_interval(
    settings_kratos: Settings,
) -> None:
    """`last_run` is stamped only after a COMPLETED sweep.

    Stamping before would turn a crash into a silently skipped interval, which
    on a 24-hour cadence is a day of not looking.
    """
    settings = settings_kratos.model_copy(
        update={"hunt_spec_sweeps_enabled": True, "hunt_spec_sweep_interval_minutes": 1440}
    )
    sweeper = AsyncMock(side_effect=[RuntimeError("boom"), _result(ran=["a"])])
    await _tick(_app(settings), sweeper, wakes=2)
    assert sweeper.await_count == 2, "a failed sweep consumed the whole interval"


async def test_the_toggle_applies_without_a_restart(settings_kratos: Settings) -> None:
    """Settings are read live each wake, like every other scheduler here."""
    from soc_ai.main import _hunt_spec_sweep_loop

    settings = settings_kratos.model_copy(
        update={"hunt_spec_sweeps_enabled": False, "hunt_spec_sweep_interval_minutes": 5}
    )
    app = _app(settings)
    sweeper = AsyncMock(return_value=_result(ran=["a"]))
    wakes = {"n": 0}

    async def _fake_sleep(_seconds: float) -> None:
        wakes["n"] += 1
        if wakes["n"] == 2:
            app.state.settings = settings.model_copy(update={"hunt_spec_sweeps_enabled": True})
        if wakes["n"] > 3:
            raise asyncio.CancelledError

    with (
        patch("soc_ai.main.asyncio.sleep", new=_fake_sleep),
        patch("soc_ai.hunting.sweep.sweep_catalog", new=sweeper),
        pytest.raises(asyncio.CancelledError),
    ):
        await _hunt_spec_sweep_loop(app)

    assert sweeper.await_count >= 1, "flipping the toggle mid-run had no effect"


async def test_cancellation_is_not_swallowed_by_the_error_handler(
    settings_kratos: Settings,
) -> None:
    """Shutdown must actually stop it.

    The loop catches broad exceptions so one bad sweep cannot kill it, which is
    right — but a bare ``except Exception`` that also caught ``CancelledError``
    would make the task un-cancellable and hang the lifespan. The explicit
    re-raise is what stops that, and this is what holds it.
    """
    from soc_ai.main import _hunt_spec_sweep_loop

    settings = settings_kratos.model_copy(update={"hunt_spec_sweeps_enabled": True})
    sweeper = AsyncMock(side_effect=asyncio.CancelledError)

    async def _no_sleep(_seconds: float) -> None:
        return None

    with (
        patch("soc_ai.main.asyncio.sleep", new=_no_sleep),
        patch("soc_ai.hunting.sweep.sweep_catalog", new=sweeper),
        pytest.raises(asyncio.CancelledError),
    ):
        await _hunt_spec_sweep_loop(_app(settings))


@pytest.mark.asyncio(loop_scope="function")
async def test_the_loop_is_registered_and_cancelled_in_the_lifespan() -> None:
    """A task created and never cancelled would keep the process alive on shutdown."""
    from soc_ai import main

    source = _read(main.__file__)
    assert "spec_sweep_task = asyncio.create_task(_hunt_spec_sweep_loop(app))" in source
    assert "spec_sweep_task.cancel()" in source


async def test_a_window_narrower_than_the_interval_is_widened(
    settings_kratos: Settings, caplog: pytest.LogCaptureFixture
) -> None:
    """Otherwise the sweep leaves an unexamined gap and calls it clean.

    window=5 with interval=60 examines five minutes in every sixty and reports
    the other fifty-five as nothing found. The two settings are validated
    independently by the config console, so nothing else catches the pairing.
    The widening is said out loud, once, with both numbers in it: the clamp
    now lives in ``soc_ai.hunting.window`` where the CLI shares it, and this
    pins that the loop kept its voice when the arithmetic moved.
    """
    settings = settings_kratos.model_copy(
        update={
            "hunt_spec_sweeps_enabled": True,
            "hunt_spec_sweep_interval_minutes": 60,
            "hunt_spec_sweep_window_minutes": 5,
        }
    )
    sweeper = AsyncMock(return_value=_result(ran=["a"]))
    with caplog.at_level(logging.WARNING):
        await _tick(_app(settings), sweeper, wakes=1)
    since = sweeper.await_args.kwargs["since"]
    assert since == "now-61m", f"the sweep left a 55-minute blind gap (asked for {since})"
    said = [r.getMessage() for r in caplog.records if "spec sweep" in r.getMessage()]
    assert len(said) == 1, "said once per sweep, not once per wake"
    assert "(5m)" in said[0] and "(60m)" in said[0] and "61m" in said[0]


async def test_a_sweep_whose_only_news_is_a_recovery_still_says_something(
    settings_kratos: Settings, caplog: pytest.LogCaptureFixture
) -> None:
    """The silence this closes, at the surface an unattended loop has.

    A sweep that ends an outage records no hunt, has nothing blind and nothing
    errored — so the summary line's condition was false and the loop logged
    absolutely nothing on the one sweep where a coverage hole closed. Going
    dark had a hunt and a bell entry; coming back had neither, and now it has a
    line of its own that says what happened rather than a number in a summary.
    """
    settings = settings_kratos.model_copy(update={"hunt_spec_sweeps_enabled": True})
    sweeper = AsyncMock(return_value=_result(ran=["a"], gaps_cleared=1))
    with caplog.at_level(logging.INFO):
        await _tick(_app(settings), sweeper, wakes=1)
    said = [r.getMessage() for r in caplog.records if "spec sweep" in r.getMessage()]
    assert any("can see their telemetry again" in m for m in said), (
        f"the sweep that ended an outage logged nothing about it: {said}"
    )


async def test_an_uneventful_sweep_still_says_nothing(
    settings_kratos: Settings, caplog: pytest.LogCaptureFixture
) -> None:
    """NEGATIVE CONTROL. The recovery line is news, so it must be rare.

    An hourly loop that logged it every sweep would bury the one sweep that
    matters, which is the failure the summary's own condition exists to avoid.
    """
    settings = settings_kratos.model_copy(update={"hunt_spec_sweeps_enabled": True})
    sweeper = AsyncMock(return_value=_result(ran=["a"]))
    with caplog.at_level(logging.INFO):
        await _tick(_app(settings), sweeper, wakes=1)
    said = [r.getMessage() for r in caplog.records if "spec sweep" in r.getMessage()]
    assert not any("can see their telemetry again" in m for m in said), said
