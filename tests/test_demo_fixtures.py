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
from datetime import timedelta
from pathlib import Path

import pytest
from soc_ai.config import Settings
from soc_ai.demo.fixtures import load_fixtures, seed_fixtures
from soc_ai.store.auth import utcnow
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import Backtest, Hunt, HuntEvent, Investigation, InvestigationEvent
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
        assert client.get("/api/v1/investigations").json() == []


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
        rows = client.get("/api/v1/investigations").json()
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
        assert client.get("/api/v1/investigations").json() == []
