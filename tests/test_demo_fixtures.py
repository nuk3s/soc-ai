"""Tests for the demo fixture loader + idempotent startup seed (SOC_AI_DEMO).

``soc_ai.demo.fixtures`` parses the sanitized fixture file (version-checked)
and seeds investigations/hunts/backtests into the store, skipping rows that
already exist — so a restart (or a partially seeded store) completes without
duplicates. ``alerts[]``, ``replays[]``, and ``chats[]`` are pass-through for
the mock ES / replay runner / demo chat lookup and must survive a load→seed
round trip untouched (``chats[]`` entries are shape-validated at load time).
"""

from __future__ import annotations

import copy
import json
from datetime import datetime, timedelta
from itertools import pairwise
from pathlib import Path

import pytest
from soc_ai.config import Settings
from soc_ai.demo.catalog_trail import (
    BLIND_SPEC,
    CATALOG_HUNT_ID,
    ERRORED_SPEC,
    FIRED_SPEC,
    ROWS_PER_SPEC,
    seed_catalog_trail,
)
from soc_ai.demo.fixtures import load_fixtures, seed_fixtures
from soc_ai.hunting.spec import CATALOG_DIR, load_catalog
from soc_ai.hunting.sweep import SWEEP_ACTOR
from soc_ai.store.auth import utcnow
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.hunt_spec_sweeps import catalog_status
from soc_ai.store.models import (
    Backtest,
    Hunt,
    HuntEvent,
    HuntSchedule,
    HuntSpecSweep,
    Investigation,
    InvestigationEvent,
    QualitySnapshot,
)
from soc_ai.triage_models import is_pipeline_fallback
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from tests.conftest import _base_settings_kwargs

FIXTURE = {
    "version": 1,
    "investigations": [
        {
            "id": "01DEMO0000000000000000TEST",
            "alert_es_id": "demo-alert-1",
            "rule_name": "ET SCAN Demo",
            "verdict": "false_positive",
            "confidence": 0.9,
            "rationale": "recorded demo run",
            "summary": "demo",
            "report": {},
            "src_ip": "SRC_IP_01",
            "dest_ip": "DST_IP_01",
            "status": "complete",
            "created_at": "2026-07-01T00:00:00Z",
            "finished_at": "2026-07-01T00:05:00Z",
            "events": [
                {"kind": "session_start", "sequence": 0, "payload": {}},
                {"kind": "triage_report", "sequence": 1, "payload": {"verdict": "false_positive"}},
            ],
        }
    ],
    "hunts": [],
    "backtests": [
        {
            "id": "01DEMO0000000000000000BTST",
            "params": {"window_days": 7, "sample_size": 25},
            "status": "complete",
            "sampled": 25,
            "results": {"agreement_rate": 0.8},
            "created_at": "2026-07-01T02:00:00Z",
            "finished_at": "2026-07-01T02:30:00Z",
        }
    ],
    "alerts": [],
    "replays": [],
    "chats": [],
}

HUNT_FIXTURE = {
    "version": 1,
    "investigations": [],
    "hunts": [
        {
            "id": "01DEMO000000000000000HUNT1",
            "objective": "find beacons",
            "kind": "chat",
            "status": "complete",
            "narrative": "nothing found",
            "report": {},
            "created_at": "2026-07-01T01:00:00Z",
            "finished_at": "2026-07-01T01:10:00Z",
            "events": [
                {"kind": "hunt_started", "sequence": 0, "payload": {}},
            ],
        }
    ],
    "backtests": [],
    "alerts": [],
    "replays": [],
    "chats": [],
}


async def _db(settings: Settings) -> tuple[AsyncEngine, async_sessionmaker[AsyncSession]]:
    engine = make_engine(settings)
    await run_migrations(engine)
    return engine, make_sessionmaker(engine)


async def test_seed_inserts_investigation_and_events(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    added = await seed_fixtures(maker, copy.deepcopy(FIXTURE))
    assert added == 2  # the investigation + the backtest
    async with maker() as db:
        inv = await db.get(Investigation, "01DEMO0000000000000000TEST")
        assert inv is not None
        assert inv.rule_name == "ET SCAN Demo"
        assert inv.verdict == "false_positive"
        # ISO strings land as the store's naive-UTC datetimes (models.py docstring),
        # rebased to now on seed — so assert preserved gaps + recency rather than
        # the pre-rebase wall-clock values (see test_seed_rebases_timestamps_to_now).
        assert inv.created_at.tzinfo is None
        assert inv.finished_at - inv.created_at == timedelta(minutes=5)
        events = (
            (
                await db.execute(
                    select(InvestigationEvent)
                    .where(InvestigationEvent.investigation_id == inv.id)
                    .order_by(InvestigationEvent.sequence)
                )
            )
            .scalars()
            .all()
        )
        assert [e.kind for e in events] == ["session_start", "triage_report"]
        assert events[1].payload == {"verdict": "false_positive"}
        bt = await db.get(Backtest, "01DEMO0000000000000000BTST")
        assert bt is not None
        assert bt.status == "complete"
        assert bt.sampled == 25
        assert bt.results == {"agreement_rate": 0.8}
        # Backtest is the newest fixture row → rebased to within minutes of now.
        assert bt.finished_at - bt.created_at == timedelta(minutes=30)
        assert utcnow() - bt.finished_at < timedelta(minutes=5)
    await engine.dispose()


async def test_seed_rebases_timestamps_to_now(settings_kratos: Settings) -> None:
    """Seeding rebases EACH section independently so its own newest row lands at
    'now' — every surface (investigations, hunts, backtests) reads as current,
    with each row's internal gaps preserved. This is why the backtest being ~2
    days newer in the committed fixtures no longer drags investigations away."""
    # Merge a hunt into FIXTURE so all three sections are exercised at once.
    fx = copy.deepcopy(FIXTURE)
    fx["hunts"] = copy.deepcopy(HUNT_FIXTURE["hunts"])
    engine, maker = await _db(settings_kratos)
    await seed_fixtures(maker, fx)
    async with maker() as db:
        inv = await db.get(Investigation, "01DEMO0000000000000000TEST")
        hunt = await db.get(Hunt, "01DEMO000000000000000HUNT1")
        bt = await db.get(Backtest, "01DEMO0000000000000000BTST")
    assert inv is not None
    assert hunt is not None
    assert bt is not None
    # The newest row of EACH section now sits within the last few minutes — not
    # just the single global-newest row. (Each is its section's only/newest row.)
    assert utcnow() - inv.finished_at < timedelta(minutes=5)
    assert utcnow() - hunt.finished_at < timedelta(minutes=5)
    assert utcnow() - bt.finished_at < timedelta(minutes=5)
    # Each row's own gaps survive the shift.
    assert inv.finished_at - inv.created_at == timedelta(minutes=5)
    assert hunt.finished_at - hunt.created_at == timedelta(minutes=10)
    assert bt.finished_at - bt.created_at == timedelta(minutes=30)
    await engine.dispose()


async def test_seed_twice_is_idempotent(settings_kratos: Settings) -> None:
    """Re-seeding (a restart) skips existing rows — no duplicate parents/events."""
    engine, maker = await _db(settings_kratos)
    data = copy.deepcopy(FIXTURE)
    assert await seed_fixtures(maker, data) == 2
    # Same dict object again: seeding must not have destroyed it (no destructive pop).
    assert await seed_fixtures(maker, data) == 0
    async with maker() as db:
        n_inv = await db.scalar(select(func.count()).select_from(Investigation))
        n_ev = await db.scalar(select(func.count()).select_from(InvestigationEvent))
        n_bt = await db.scalar(select(func.count()).select_from(Backtest))
    assert n_inv == 1
    assert n_ev == 2
    assert n_bt == 1
    await engine.dispose()


async def test_seed_hunts_with_events(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    data = copy.deepcopy(HUNT_FIXTURE)
    assert await seed_fixtures(maker, data) == 1
    assert await seed_fixtures(maker, data) == 0
    async with maker() as db:
        hunt = await db.get(Hunt, "01DEMO000000000000000HUNT1")
        assert hunt is not None
        assert hunt.status == "complete"
        # Sole fixture row → rebased so its finished_at lands within minutes of now.
        assert hunt.finished_at - hunt.created_at == timedelta(minutes=10)
        assert utcnow() - hunt.finished_at < timedelta(minutes=5)
        n_ev = await db.scalar(select(func.count()).select_from(HuntEvent))
    assert n_ev == 1
    await engine.dispose()


HUNT_SCHEDULE_FIXTURE = {
    "version": 1,
    "investigations": [],
    "hunts": [],
    "backtests": [],
    "hunt_schedules": [
        {
            "id": 9001,
            "objective": "beacon sweep",
            "interval_minutes": 120,
            "enabled": True,
            "last_run_at": "2026-07-01T03:00:00Z",
            "created_by": "demo",
            "created_at": "2026-07-01T02:30:00Z",
        }
    ],
    "alerts": [],
    "replays": [],
    "chats": [],
}


async def test_seed_hunt_schedules_optional_section(settings_kratos: Settings) -> None:
    """``hunt_schedules[]`` is an OPTIONAL fixture section — absent from the
    shipped fixtures.json today, but when present, seed_fixtures inserts a
    HuntSchedule row the same idempotent-per-id way as the other sections."""
    engine, maker = await _db(settings_kratos)
    data = copy.deepcopy(HUNT_SCHEDULE_FIXTURE)
    assert await seed_fixtures(maker, data) == 1
    assert await seed_fixtures(maker, data) == 0  # idempotent re-seed
    async with maker() as db:
        sched = await db.get(HuntSchedule, 9001)
        assert sched is not None
        assert sched.objective == "beacon sweep"
        assert sched.interval_minutes == 120
        assert sched.enabled is True
        assert sched.created_by == "demo"
        assert sched.last_run_at is not None
        assert sched.last_run_at.tzinfo is None
        assert sched.created_at.tzinfo is None
        n = await db.scalar(select(func.count()).select_from(HuntSchedule))
    assert n == 1
    await engine.dispose()


async def test_seed_without_hunt_schedules_key_is_a_noop(settings_kratos: Settings) -> None:
    """A fixture dict without ``hunt_schedules`` (the shipped fixtures.json shape
    today) must still seed cleanly — no KeyError, no row inserted."""
    engine, maker = await _db(settings_kratos)
    data = copy.deepcopy(FIXTURE)
    assert "hunt_schedules" not in data
    added = await seed_fixtures(maker, data)
    assert added == 2  # unaffected: the investigation + the backtest
    async with maker() as db:
        n = await db.scalar(select(func.count()).select_from(HuntSchedule))
    assert n == 0
    await engine.dispose()


QUALITY_SNAPSHOT_FIXTURE = {
    "version": 1,
    "investigations": [],
    "hunts": [],
    "backtests": [],
    "quality_snapshots": [
        {
            "id": 9001,
            "created_at": "2026-07-01T03:00:00Z",
            "mode": "graded",
            "n_ok": 8,
            "n_error": 0,
            "agreement_rate": 0.85,
            "fallback_rate": 0.0,
            "error_rate": 0.0,
            "verdict_counts": {"true_positive": 3, "false_positive": 4, "needs_more_info": 1},
            "latency_p50_ms": 52000,
            "batch_dir": None,
            "alarmed": False,
            "alarm_reasons": None,
        }
    ],
    "alerts": [],
    "replays": [],
    "chats": [],
}


async def test_seed_quality_snapshots_optional_section(settings_kratos: Settings) -> None:
    """``quality_snapshots[]`` is an OPTIONAL fixture section — when present,
    seed_fixtures inserts a QualitySnapshot row the same idempotent-per-id way as
    the other sections, so the demo Dashboard Quality card has a trend to draw."""
    engine, maker = await _db(settings_kratos)
    data = copy.deepcopy(QUALITY_SNAPSHOT_FIXTURE)
    assert await seed_fixtures(maker, data) == 1
    assert await seed_fixtures(maker, data) == 0  # idempotent re-seed
    async with maker() as db:
        snap = await db.get(QualitySnapshot, 9001)
        assert snap is not None
        assert snap.mode == "graded"
        assert snap.agreement_rate == 0.85
        assert snap.verdict_counts == {
            "true_positive": 3,
            "false_positive": 4,
            "needs_more_info": 1,
        }
        assert snap.alarmed is False
        # created_at is the only time key; it lands as the store's naive-UTC value.
        assert snap.created_at.tzinfo is None
        n = await db.scalar(select(func.count()).select_from(QualitySnapshot))
    assert n == 1
    await engine.dispose()


async def test_seed_without_quality_snapshots_key_is_a_noop(settings_kratos: Settings) -> None:
    """A fixture dict without ``quality_snapshots`` must still seed cleanly — no
    KeyError, no row inserted (mirrors the hunt_schedules no-op guard)."""
    engine, maker = await _db(settings_kratos)
    data = copy.deepcopy(FIXTURE)
    assert "quality_snapshots" not in data
    added = await seed_fixtures(maker, data)
    assert added == 2  # unaffected: the investigation + the backtest
    async with maker() as db:
        n = await db.scalar(select(func.count()).select_from(QualitySnapshot))
    assert n == 0
    await engine.dispose()


async def test_committed_fixtures_seed_the_1_2_x_showcase(settings_kratos: Settings) -> None:
    """The shipped soc_ai/demo/fixtures.json carries the 1.2.x showcase content:
    hunt schedules (Hunts screen), a quality-trend series (Dashboard Quality
    card), and exactly one pipeline-fallback investigation (Dashboard pipeline-
    errors KPI) — so those screens render content in the read-only demo."""
    data = load_fixtures()  # the real committed fixture file (DEFAULT_FIXTURES)
    engine, maker = await _db(settings_kratos)
    await seed_fixtures(maker, data)
    async with maker() as db:
        n_sched = await db.scalar(select(func.count()).select_from(HuntSchedule))
        n_snap = await db.scalar(select(func.count()).select_from(QualitySnapshot))
        rows = (await db.execute(select(Investigation))).scalars().all()
    assert n_sched >= 2
    assert n_snap >= 5
    fallbacks = [r for r in rows if is_pipeline_fallback(r.report)]
    assert len(fallbacks) == 1
    await engine.dispose()


def test_load_fixtures_parses_and_preserves_passthrough(tmp_path: Path) -> None:
    """alerts[]/replays[] are other consumers' keys — the loader keeps them."""
    fixture = copy.deepcopy(FIXTURE)
    fixture["alerts"] = [{"_id": "demo-alert-1", "_source": {"event": {}}}]
    fixture["replays"] = [{"alert_es_id": "demo-alert-1", "investigation": {}, "events": []}]
    path = tmp_path / "fixtures.json"
    path.write_text(json.dumps(fixture))
    data = load_fixtures(path)
    assert data["alerts"] == fixture["alerts"]
    assert data["replays"] == fixture["replays"]
    assert len(data["investigations"]) == 1


def test_load_fixtures_rejects_unknown_version(tmp_path: Path) -> None:
    path = tmp_path / "fixtures.json"
    path.write_text(json.dumps({"version": 2, "investigations": []}))
    with pytest.raises(ValueError, match="unsupported fixtures version"):
        load_fixtures(path)


def test_load_fixtures_preserves_chats(tmp_path: Path) -> None:
    """chats[] is another consumer's key (soc_ai.demo.chat, at request time) —
    the loader keeps it untouched, same as alerts[]/replays[]."""
    fx = copy.deepcopy(FIXTURE)
    fx["chats"] = [
        {
            "target": "investigation",
            "id": "i1",
            "messages": [
                {"role": "user", "content": "q"},
                {"role": "assistant", "content": "a"},
            ],
        }
    ]
    path = tmp_path / "f.json"
    path.write_text(json.dumps(fx))
    data = load_fixtures(path)
    assert data["chats"] == fx["chats"]


def test_load_fixtures_rejects_malformed_chat_entry(tmp_path: Path) -> None:
    """A canned-chat entry missing 'id' must fail loud at load time, not
    silently produce no reply the first time someone opens that chat."""
    fx = copy.deepcopy(FIXTURE)
    fx["chats"] = [{"target": "investigation", "messages": []}]  # no id
    path = tmp_path / "f.json"
    path.write_text(json.dumps(fx))
    with pytest.raises(ValueError, match=r"chats\[0\]"):
        load_fixtures(path)


# --- startup hook (main._init_store) ---------------------------------------


def test_startup_seed_fail_soft_when_fixtures_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Demo mode without a fixtures.json must still boot and serve — the seed
    hook logs and continues with an empty store. The real fixtures.json ships
    in-repo now, so point the default at a path that doesn't exist."""
    from tests.test_demo_mode import _app_client, _demo_app_settings

    monkeypatch.setattr("soc_ai.demo.fixtures.DEFAULT_FIXTURES", tmp_path / "absent.json")
    with _app_client(_demo_app_settings()) as client:
        assert client.get("/healthz").status_code == 200
        assert client.get("/api/v1/investigations").json()["rows"] == []


def test_startup_seeds_fixtures_in_demo_mode(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """With a fixtures file present, demo startup lands the recorded runs in
    the store and the normal list API serves them."""
    from tests.test_demo_mode import _app_client, _demo_app_settings

    path = tmp_path / "fixtures.json"
    path.write_text(json.dumps(FIXTURE))
    monkeypatch.setattr("soc_ai.demo.fixtures.DEFAULT_FIXTURES", path)
    with _app_client(_demo_app_settings()) as client:
        rows = client.get("/api/v1/investigations").json()["rows"]
    assert [r["id"] for r in rows] == ["01DEMO0000000000000000TEST"]


def test_startup_does_not_seed_outside_demo(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The hook is demo-gated: a normal (non-demo) boot never touches fixtures."""
    from tests.test_demo_mode import _app_client

    path = tmp_path / "fixtures.json"
    path.write_text(json.dumps(FIXTURE))
    monkeypatch.setattr("soc_ai.demo.fixtures.DEFAULT_FIXTURES", path)
    with _app_client(Settings(**_base_settings_kwargs())) as client:
        assert client.get("/api/v1/investigations").json()["rows"] == []


# ---------------------------------------------------------------------------
# Hunt catalog trail: a generated week of sweeps, seeded beside the fixtures
# so the Operate hub's catalog panel and the Hunts "Catalog" preset show the
# declarative catalog working on a demo grid that never ran a sweep.
# ---------------------------------------------------------------------------

CATALOG_IDS = list(load_catalog(CATALOG_DIR))


async def _trail(
    settings: Settings,
) -> tuple[AsyncEngine, async_sessionmaker[AsyncSession], datetime]:
    """A migrated store with the trail seeded once, anchored at one 'now'."""
    engine, maker = await _db(settings)
    now = utcnow()
    assert await seed_catalog_trail(maker, now=now) == 1
    return engine, maker, now


def test_catalog_trail_names_shipped_specs() -> None:
    """The trail's spec ids are the catalog's own. A renamed spec must fail
    here rather than reappear on the demo as "not yet swept"."""
    assert {FIRED_SPEC, BLIND_SPEC, ERRORED_SPEC} <= set(CATALOG_IDS)


async def test_catalog_trail_seeds_one_row_per_spec_per_six_hours(
    settings_kratos: Settings,
) -> None:
    engine, maker, now = await _trail(settings_kratos)
    async with maker() as db:
        rows = (await db.scalars(select(HuntSpecSweep).order_by(HuntSpecSweep.id))).all()
    await engine.dispose()
    by_spec: dict[str, list[HuntSpecSweep]] = {}
    for r in rows:
        by_spec.setdefault(r.spec_id, []).append(r)
    assert set(by_spec) == set(CATALOG_IDS)
    for spec_id, spec_rows in by_spec.items():
        assert len(spec_rows) == ROWS_PER_SPEC == 28, spec_id
        ages = [now - r.created_at for r in spec_rows]
        assert timedelta(0) < min(ages) < timedelta(hours=1), spec_id
        assert timedelta(days=6, hours=18) < max(ages) < timedelta(days=7, hours=1), spec_id
        # Rows come back by id, so equal gaps here also prove insertion order is
        # time order: catalog_status reads each spec's newest row by max(id).
        gaps = {b.created_at - a.created_at for a, b in pairwise(spec_rows)}
        assert gaps == {timedelta(hours=6)}, spec_id
        assert all(r.window_since == "now-1440m" and r.window_until == "now" for r in spec_rows)
        assert not any(r.shadow for r in spec_rows), spec_id


async def test_catalog_trail_decoy_spec_is_permanently_blind(settings_kratos: Settings) -> None:
    """A demo grid has no canary, so the decoy spec is blind on every sweep and
    never records a hunt: the panel's amber marker, not a firing."""
    engine, maker, _ = await _trail(settings_kratos)
    async with maker() as db:
        rows = (
            await db.scalars(select(HuntSpecSweep).where(HuntSpecSweep.spec_id == BLIND_SPEC))
        ).all()
    await engine.dispose()
    assert len(rows) == ROWS_PER_SPEC
    assert all(r.blind and r.precondition_docs == 0 and r.matched_docs == 0 for r in rows)
    assert all(r.hunt_id is None and r.error is None for r in rows)


async def test_catalog_trail_fired_row_links_a_triggered_hunt(settings_kratos: Settings) -> None:
    engine, maker, now = await _trail(settings_kratos)
    async with maker() as db:
        linked = (
            await db.scalars(select(HuntSpecSweep).where(HuntSpecSweep.hunt_id.is_not(None)))
        ).all()
        hunt = await db.get(Hunt, CATALOG_HUNT_ID)
        n_events = await db.scalar(
            select(func.count()).select_from(HuntEvent).where(HuntEvent.hunt_id == CATALOG_HUNT_ID)
        )
    await engine.dispose()
    assert len(linked) == 1
    (fired,) = linked
    assert fired.spec_id == FIRED_SPEC
    assert fired.hunt_id == CATALOG_HUNT_ID
    assert not fired.blind and fired.error is None and not fired.shadow
    assert fired.fresh_candidates == 1 and fired.matched_docs >= 1
    assert timedelta(hours=40) < now - fired.created_at < timedelta(hours=56)

    assert hunt is not None
    assert hunt.kind == "triggered"
    assert hunt.started_by == SWEEP_ACTOR
    assert hunt.status == "complete"
    assert hunt.objective.startswith(f"[catalog] {FIRED_SPEC}: ")
    assert hunt.objective.endswith("(now-1440m → now)")
    assert hunt.objective_hash
    assert hunt.created_at == fired.created_at
    assert hunt.finished_at is not None and hunt.finished_at >= hunt.created_at
    assert hunt.findings_count == 1
    assert hunt.report is not None
    (finding,) = hunt.report["findings"]
    assert finding["category"] == "threat"
    assert finding["citations"]
    assert hunt.narrative and hunt.narrative == hunt.report["narrative"]
    assert "1 finding(s)" in hunt.narrative
    # A sweep-recorded hunt has no event stream; the seeded one must not invent one.
    assert n_events == 0


async def test_catalog_trail_handled_rows_follow_the_firing(settings_kratos: Settings) -> None:
    """After the firing the gate holds the same condition back: rows carry
    already_handled (one of them inside the last 24h, so the panel's handled
    count is non-zero) and nothing fires a second time."""
    engine, maker, now = await _trail(settings_kratos)
    async with maker() as db:
        rows = (
            await db.scalars(
                select(HuntSpecSweep)
                .where(HuntSpecSweep.spec_id == FIRED_SPEC)
                .order_by(HuntSpecSweep.id)
            )
        ).all()
    await engine.dispose()
    fired_idx = next(i for i, r in enumerate(rows) if r.hunt_id is not None)
    assert all(r.already_handled == 0 and r.matched_docs == 0 for r in rows[:fired_idx])
    after = rows[fired_idx + 1 :]
    assert any(r.already_handled >= 1 for r in after)
    assert any(r.already_handled >= 1 for r in after if now - r.created_at < timedelta(hours=24))
    assert all(r.fresh_candidates == 0 and r.hunt_id is None for r in after)
    # A held-back candidate is a matched one: handled never exceeds matched.
    assert all(r.matched_docs >= r.already_handled for r in rows)


async def test_catalog_trail_one_transient_error_days_back(settings_kratos: Settings) -> None:
    """One errored row about four days back exercises the red marker in the
    history without putting it on any spec's newest row."""
    engine, maker, now = await _trail(settings_kratos)
    async with maker() as db:
        errored = (
            await db.scalars(select(HuntSpecSweep).where(HuntSpecSweep.error.is_not(None)))
        ).all()
    await engine.dispose()
    assert len(errored) == 1
    (row,) = errored
    assert row.spec_id == ERRORED_SPEC
    assert timedelta(days=3, hours=12) < now - row.created_at < timedelta(days=4, hours=12)
    assert row.hunt_id is None and not row.blind
    assert row.error is not None and len(row.error) < 80


async def test_catalog_trail_status_reads_as_the_panel_expects(settings_kratos: Settings) -> None:
    engine, maker, now = await _trail(settings_kratos)
    async with maker() as db:
        status = await catalog_status(db, now=now)
    await engine.dispose()
    assert set(status) == set(CATALOG_IDS)
    assert all(s.last_error is None for s in status.values())
    assert [sid for sid, s in status.items() if s.blind] == [BLIND_SPEC]
    assert all(s.sweeps_24h == 4 for s in status.values())
    assert all(s.fired_24h == 0 for s in status.values())
    assert all(s.fresh_24h == 0 for s in status.values())
    assert all(s.shadow_24h == 0 for s in status.values()), "the demo trail is live sweeps only"
    assert [sid for sid, s in status.items() if s.last_fired_at is not None] == [FIRED_SPEC]
    fired = status[FIRED_SPEC]
    assert fired.last_fired_at is not None
    assert timedelta(hours=40) < now - fired.last_fired_at < timedelta(hours=56)
    assert fired.already_handled_24h >= 1
    assert all(s.already_handled_24h == 0 for sid, s in status.items() if sid != FIRED_SPEC)


async def test_catalog_trail_seed_twice_is_idempotent(settings_kratos: Settings) -> None:
    """A restart skips the trail the same way it skips a fixture row: by the
    hunt's primary key, with the sweep rows riding along like events."""
    engine, maker, now = await _trail(settings_kratos)
    assert await seed_catalog_trail(maker, now=now + timedelta(hours=1)) == 0
    async with maker() as db:
        n_rows = await db.scalar(select(func.count()).select_from(HuntSpecSweep))
        n_hunts = await db.scalar(
            select(func.count()).select_from(Hunt).where(Hunt.kind == "triggered")
        )
    await engine.dispose()
    assert n_rows == ROWS_PER_SPEC * len(CATALOG_IDS)
    assert n_hunts == 1


def test_startup_seeds_catalog_trail_in_demo_mode(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Demo startup lands the trail beside the fixtures: the catalog route
    reads the week of sweeps and the Hunts "Catalog" preset lists the hunt."""
    from tests.test_demo_mode import _app_client, _demo_app_settings

    path = tmp_path / "fixtures.json"
    path.write_text(json.dumps(FIXTURE))
    monkeypatch.setattr("soc_ai.demo.fixtures.DEFAULT_FIXTURES", path)
    with _app_client(_demo_app_settings()) as client:
        catalog = client.get("/api/v1/hunt-catalog").json()
        triggered = client.get("/api/v1/hunts", params={"kind": "triggered"}).json()
    specs = {s["id"]: s for s in catalog["specs"]}
    assert set(specs) == set(CATALOG_IDS)
    assert catalog["last_sweep_at"] is not None
    assert all(s["last_swept_at"] is not None for s in specs.values())
    assert all(s["last_error"] is None for s in specs.values())
    assert [sid for sid, s in specs.items() if s["blind"]] == [BLIND_SPEC]
    assert all(s["fired_24h"] == 0 for s in specs.values())
    fired = specs[FIRED_SPEC]
    assert fired["last_fired_at"] is not None
    assert fired["already_handled_24h"] >= 1
    assert [h["id"] for h in triggered] == [CATALOG_HUNT_ID]
    assert triggered[0]["kind"] == "triggered"
    assert triggered[0]["startedBy"] == SWEEP_ACTOR
    assert triggered[0]["objective"].startswith(f"[catalog] {FIRED_SPEC}: ")
    assert triggered[0]["findingCount"] == 1


def test_startup_does_not_seed_catalog_trail_outside_demo() -> None:
    """The trail is demo content: a normal boot leaves every spec unswept."""
    from tests.test_demo_mode import _app_client

    with _app_client(Settings(**_base_settings_kwargs())) as client:
        catalog = client.get("/api/v1/hunt-catalog").json()
        triggered = client.get("/api/v1/hunts", params={"kind": "triggered"}).json()
    assert all(s["last_swept_at"] is None for s in catalog["specs"])
    assert triggered == []
