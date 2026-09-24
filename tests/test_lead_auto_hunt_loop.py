"""The loop that hunts a lead nobody has clicked (D1).

A lead is already several observations that crossed a threshold together, so
the answer to "is this worth a look?" is yes by the time the lead exists. This
loop is what makes that true without an analyst at the keyboard.

The tests are mostly about restraint. It must leave a dismissed lead alone, it
must leave a reopened lead to the analyst who reopened it, it must hold its
concurrency cap, it must say nothing twice, and one bad lead must not take out
the tick.

The loop is driven by the same sleep-bounding trick as
tests/test_hunt_spec_sweep_loop.py: patch ``main.asyncio.sleep`` so the first N
wakes return and the next raises ``CancelledError``.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from soc_ai import main as main_mod
from soc_ai.config import Settings
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import Hunt, Lead
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

pytestmark = pytest.mark.asyncio

_NOW = datetime(2026, 9, 22, 12, 0, tzinfo=UTC).replace(tzinfo=None)


async def _db(settings: Settings) -> tuple[AsyncEngine, async_sessionmaker[AsyncSession]]:
    engine = make_engine(settings)
    await run_migrations(engine)
    return engine, make_sessionmaker(engine)


def _app(
    maker: async_sessionmaker[AsyncSession], *, enabled: bool = True, concurrency: int = 2
) -> SimpleNamespace:
    return SimpleNamespace(
        state=SimpleNamespace(
            db_sessionmaker=maker,
            settings=SimpleNamespace(
                lead_auto_hunt=enabled, lead_auto_hunt_concurrency=concurrency
            ),
        )
    )


async def _lead(
    maker: async_sessionmaker[AsyncSession],
    *,
    minutes_old: int = 0,
    cites: bool = True,
    **fields: Any,
) -> int:
    """One lead with one observation, cited or not."""
    from soc_ai.store.models import EntityObservation

    formed = _NOW - timedelta(minutes=minutes_old)
    async with maker() as db:
        lead = Lead(
            status=fields.pop("status", "open"),
            entities_json=[["host", "10.1.2.3"]],
            kinds_json=["catalog_match"],
            weight_at_formation=0.9,
            shadow=fields.pop("shadow", False),
            formed_at=formed,
            **fields,
        )
        db.add(lead)
        await db.flush()
        db.add(
            EntityObservation(
                entity_kind="host",
                entity_key="10.1.2.3",
                kind="catalog_match",
                spec_id="s",
                fingerprint=f"fp-{lead.id}",
                birth_weight=0.9,
                born_at=formed,
                first_seen_at=formed,
                occurrences=1,
                source="catalog",
                evidence_json={"sample_ids": ["d1"]} if cites else {},
                lead_id=lead.id,
            )
        )
        await db.commit()
        return int(lead.id)


def _console(started: list[dict[str, Any]], *, fail_on: str = "") -> SimpleNamespace:
    """A hunt console that records the start rather than running an agent."""

    async def _start(_state: Any, **kwargs: Any) -> str:
        if fail_on and fail_on in str(kwargs.get("objective", "")):
            raise RuntimeError("spawn boom")
        started.append(kwargs)
        return f"01HUNT{len(started)}"

    return SimpleNamespace(start=_start)


async def _run(monkeypatch: pytest.MonkeyPatch, app: SimpleNamespace, *, wakes: int = 1) -> None:
    """Run the loop for ``wakes`` body iterations, then unwind."""
    from soc_ai.main import _lead_auto_hunt_loop

    calls = {"n": 0}

    async def _sleep(_seconds: float) -> None:
        calls["n"] += 1
        if calls["n"] <= wakes:
            return None
        raise asyncio.CancelledError

    monkeypatch.setattr(main_mod.asyncio, "sleep", _sleep)
    with contextlib.suppress(asyncio.CancelledError):
        await _lead_auto_hunt_loop(app)


async def test_a_new_lead_gets_a_hunt_within_one_wake(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings, caplog: pytest.LogCaptureFixture
) -> None:
    """The lead no longer waits for a click. The log names the lead and the hunt."""
    engine, maker = await _db(settings_kratos)
    lead_id = await _lead(maker)
    started: list[dict[str, Any]] = []
    monkeypatch.setattr(
        "soc_ai.webui.hunt_console_manager.get_manager", lambda _s: _console(started)
    )

    with caplog.at_level(logging.INFO):
        await _run(monkeypatch, _app(maker))

    assert len(started) == 1
    assert started[0]["kind"] == "lead" and started[0]["starter"] == "lead"
    assert started[0]["lead_id"] == lead_id
    assert started[0]["started_by"] == "auto-hunt"
    async with maker() as db:
        lead = await db.get(Lead, lead_id)
        assert lead.status == "hunting" and lead.hunt_id == "01HUNT1"
    said = [r.getMessage() for r in caplog.records if "lead auto-hunt" in r.getMessage()]
    assert any(str(lead_id) in m and "01HUNT1" in m for m in said), said
    await engine.dispose()


async def test_the_same_lead_is_not_hunted_twice(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings
) -> None:
    """The mark is what stops the second wake. Two wakes, one hunt."""
    engine, maker = await _db(settings_kratos)
    await _lead(maker)
    started: list[dict[str, Any]] = []
    monkeypatch.setattr(
        "soc_ai.webui.hunt_console_manager.get_manager", lambda _s: _console(started)
    )

    await _run(monkeypatch, _app(maker), wakes=3)
    assert len(started) == 1
    await engine.dispose()


async def test_a_dismissed_lead_never_gets_one(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings
) -> None:
    """A dismissal is an answer. The loop does not argue with it."""
    engine, maker = await _db(settings_kratos)
    await _lead(maker, status="dismissed", dismissed_reason="known_change", dismissed_at=_NOW)
    started: list[dict[str, Any]] = []
    monkeypatch.setattr(
        "soc_ai.webui.hunt_console_manager.get_manager", lambda _s: _console(started)
    )

    await _run(monkeypatch, _app(maker), wakes=2)
    assert started == []
    await engine.dispose()


async def test_a_reopened_lead_is_left_to_the_analyst(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings
) -> None:
    """Reopening is a decision to look again. Hunt again is the analyst's button.

    The reopened lead is open with no hunt, which is exactly the shape the
    loop takes. The dismissal it carries as history is what tells the two
    apart.
    """
    engine, maker = await _db(settings_kratos)
    await _lead(maker, dismissed_reason="benign_repeat", dismissed_at=_NOW)
    started: list[dict[str, Any]] = []
    monkeypatch.setattr(
        "soc_ai.webui.hunt_console_manager.get_manager", lambda _s: _console(started)
    )

    await _run(monkeypatch, _app(maker), wakes=2)
    assert started == []
    await engine.dispose()


async def test_a_shadow_lead_is_left_to_the_analyst(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings
) -> None:
    """A shadow lead came from an analytic in shadow. Shadow records and never acts.

    The loop would otherwise run a real agent hunt on the word of an analytic
    nobody has approved. The lead keeps its Hunt button for the analyst.
    """
    engine, maker = await _db(settings_kratos)
    await _lead(maker, shadow=True)
    started: list[dict[str, Any]] = []
    monkeypatch.setattr(
        "soc_ai.webui.hunt_console_manager.get_manager", lambda _s: _console(started)
    )

    await _run(monkeypatch, _app(maker), wakes=2)
    assert started == []
    await engine.dispose()


async def test_the_cap_holds_with_three_leads_waiting(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings
) -> None:
    """Three eligible leads and a cap of two start two hunts, oldest first."""
    engine, maker = await _db(settings_kratos)
    oldest = await _lead(maker, minutes_old=180)
    middle = await _lead(maker, minutes_old=60)
    await _lead(maker, minutes_old=1)
    started: list[dict[str, Any]] = []
    monkeypatch.setattr(
        "soc_ai.webui.hunt_console_manager.get_manager", lambda _s: _console(started)
    )

    await _run(monkeypatch, _app(maker, concurrency=2))

    assert [c["lead_id"] for c in started] == [oldest, middle]
    await engine.dispose()


async def test_a_hunt_already_running_takes_a_slot(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings
) -> None:
    """The cap counts the loop's hunts in flight, not the starts in this wake."""
    engine, maker = await _db(settings_kratos)
    await _lead(maker, minutes_old=180)
    await _lead(maker, minutes_old=60)
    async with maker() as db:
        db.add(
            Hunt(
                id="01INFLIGHT",
                objective="o",
                objective_hash="x",
                started_by="auto-hunt",
                kind="lead",
                starter="lead",
                status="running",
            )
        )
        await db.commit()
    started: list[dict[str, Any]] = []
    monkeypatch.setattr(
        "soc_ai.webui.hunt_console_manager.get_manager", lambda _s: _console(started)
    )

    await _run(monkeypatch, _app(maker, concurrency=2))
    assert len(started) == 1
    await engine.dispose()


async def test_a_hunt_an_analyst_started_does_not_take_a_slot(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings
) -> None:
    """NEGATIVE CONTROL for the cap. The analyst and the loop have separate room."""
    engine, maker = await _db(settings_kratos)
    await _lead(maker, minutes_old=180)
    await _lead(maker, minutes_old=60)
    async with maker() as db:
        db.add(
            Hunt(
                id="01BYHAND",
                objective="o",
                objective_hash="x",
                started_by="ana",
                kind="lead",
                starter="lead",
                status="running",
            )
        )
        await db.commit()
    started: list[dict[str, Any]] = []
    monkeypatch.setattr(
        "soc_ai.webui.hunt_console_manager.get_manager", lambda _s: _console(started)
    )

    await _run(monkeypatch, _app(maker, concurrency=2))
    assert len(started) == 2
    await engine.dispose()


async def test_the_setting_off_starts_nothing(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings
) -> None:
    """Off restores the older behaviour: the lead waits for the analyst's click."""
    engine, maker = await _db(settings_kratos)
    await _lead(maker)
    started: list[dict[str, Any]] = []
    monkeypatch.setattr(
        "soc_ai.webui.hunt_console_manager.get_manager", lambda _s: _console(started)
    )

    await _run(monkeypatch, _app(maker, enabled=False), wakes=3)
    assert started == []
    await engine.dispose()


async def test_the_toggle_applies_without_a_restart(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings
) -> None:
    """Settings are read live each wake, like every other scheduler here."""
    from soc_ai.main import _lead_auto_hunt_loop

    engine, maker = await _db(settings_kratos)
    await _lead(maker)
    started: list[dict[str, Any]] = []
    monkeypatch.setattr(
        "soc_ai.webui.hunt_console_manager.get_manager", lambda _s: _console(started)
    )
    app = _app(maker, enabled=False)
    wakes = {"n": 0}

    async def _sleep(_seconds: float) -> None:
        wakes["n"] += 1
        if wakes["n"] == 2:
            app.state.settings = SimpleNamespace(lead_auto_hunt=True, lead_auto_hunt_concurrency=2)
        if wakes["n"] > 3:
            raise asyncio.CancelledError

    monkeypatch.setattr(main_mod.asyncio, "sleep", _sleep)
    with contextlib.suppress(asyncio.CancelledError):
        await _lead_auto_hunt_loop(app)

    assert len(started) == 1, "flipping the toggle mid-run had no effect"
    await engine.dispose()


async def test_a_lead_that_cites_no_documents_is_skipped_and_said_once(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings, caplog: pytest.LogCaptureFixture
) -> None:
    """A hunt with no evidence to read first searches the grid from scratch.

    The line is said once an hour per lead. A 60-second loop that said it every
    wake would write sixty lines an hour about one lead that is not moving.
    """
    engine, maker = await _db(settings_kratos)
    lead_id = await _lead(maker, cites=False)
    started: list[dict[str, Any]] = []
    monkeypatch.setattr(
        "soc_ai.webui.hunt_console_manager.get_manager", lambda _s: _console(started)
    )

    with caplog.at_level(logging.INFO):
        await _run(monkeypatch, _app(maker), wakes=5)

    assert started == []
    said = [
        r.getMessage()
        for r in caplog.records
        if "lead auto-hunt" in r.getMessage() and "no documents" in r.getMessage()
    ]
    assert len(said) == 1, said
    assert str(lead_id) in said[0]
    await engine.dispose()


async def test_a_cited_lead_still_runs_behind_one_that_cites_nothing(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings
) -> None:
    """The skip must not consume the wake. The older lead is the skipped one."""
    engine, maker = await _db(settings_kratos)
    await _lead(maker, minutes_old=180, cites=False)
    cited = await _lead(maker, minutes_old=60)
    started: list[dict[str, Any]] = []
    monkeypatch.setattr(
        "soc_ai.webui.hunt_console_manager.get_manager", lambda _s: _console(started)
    )

    await _run(monkeypatch, _app(maker, concurrency=1))
    assert [c["lead_id"] for c in started] == [cited]
    await engine.dispose()


async def test_one_bad_lead_does_not_stop_the_tick(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings
) -> None:
    """A spawn that raises is logged. The next lead still gets its hunt."""
    engine, maker = await _db(settings_kratos)
    bad = await _lead(maker, minutes_old=180)
    good = await _lead(maker, minutes_old=60)
    started: list[dict[str, Any]] = []
    monkeypatch.setattr(
        "soc_ai.webui.hunt_console_manager.get_manager",
        lambda _s: _console(started, fail_on=f"[lead {bad}]"),
    )

    await _run(monkeypatch, _app(maker, concurrency=2))
    assert [c["lead_id"] for c in started] == [good]
    await engine.dispose()


async def test_a_failed_wake_does_not_kill_the_loop(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings
) -> None:
    """The whole tick can fail. The next wake must still come."""
    engine, maker = await _db(settings_kratos)
    await _lead(maker)
    started: list[dict[str, Any]] = []
    calls = {"n": 0}

    def _get_manager(_s: Any) -> SimpleNamespace:
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("console down")
        return _console(started)

    monkeypatch.setattr("soc_ai.webui.hunt_console_manager.get_manager", _get_manager)

    await _run(monkeypatch, _app(maker), wakes=2)
    assert len(started) == 1, "the loop stopped after the first failure"
    await engine.dispose()


async def test_cancellation_is_not_swallowed_by_the_error_handler(
    monkeypatch: pytest.MonkeyPatch, settings_kratos: Settings
) -> None:
    """Shutdown must actually stop it.

    A bare ``except Exception`` that also caught ``CancelledError`` would make
    the task un-cancellable and hang the lifespan.
    """
    from soc_ai.main import _lead_auto_hunt_loop

    engine, maker = await _db(settings_kratos)
    await _lead(maker)

    def _get_manager(_s: Any) -> SimpleNamespace:
        raise asyncio.CancelledError

    monkeypatch.setattr("soc_ai.webui.hunt_console_manager.get_manager", _get_manager)

    async def _no_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(main_mod.asyncio, "sleep", _no_sleep)
    with pytest.raises(asyncio.CancelledError):
        await _lead_auto_hunt_loop(_app(maker))
    await engine.dispose()


def _read(path: str) -> str:
    """Blocking read, deliberately outside the async body (ASYNC240)."""
    import pathlib

    return pathlib.Path(path).read_text()


async def test_the_loop_is_registered_and_cancelled_in_the_lifespan() -> None:
    """A task created and never cancelled keeps the process alive on shutdown."""
    from soc_ai import main

    source = _read(main.__file__)
    assert "lead_auto_hunt_task = asyncio.create_task(_lead_auto_hunt_loop(app))" in source
    assert "lead_auto_hunt_task.cancel()" in source
