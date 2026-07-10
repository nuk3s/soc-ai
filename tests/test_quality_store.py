"""Tests for the quality_snapshots store service + the 0019 migration.

Mirrors tests/test_hunts_store.py: exercises insert (with its same-transaction
prune) and the newest-first / mode-filtered reads against a real SQLite file
migrated to head. Uses the ``settings_kratos`` fixture, which the autouse
``clean_env`` fixture isolates to a per-test temp dir.
"""

from __future__ import annotations

from soc_ai.config import Settings
from soc_ai.store import quality as quality_svc
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from sqlalchemy import inspect


async def _db(settings: Settings):  # type: ignore[no-untyped-def]
    engine = make_engine(settings)
    await run_migrations(engine)
    return engine, make_sessionmaker(engine)


def _snapshot_kwargs(**overrides: object) -> dict[str, object]:
    """Baseline insert kwargs for a healthy graded snapshot."""
    base: dict[str, object] = {
        "mode": "graded",
        "n_ok": 5,
        "n_error": 0,
        "agreement_rate": 0.8,
        "fallback_rate": 0.0,
        "error_rate": 0.0,
        "verdict_counts": {"false_positive": 4, "true_positive": 1},
        "latency_p50_ms": 90_000,
        "batch_dir": "evals/batch-x",
        "alarmed": False,
        "alarm_reasons": None,
    }
    base.update(overrides)
    return base


async def test_migration_creates_quality_snapshots_table(settings_kratos: Settings) -> None:
    engine, _maker = await _db(settings_kratos)
    async with engine.connect() as conn:
        tables = await conn.run_sync(lambda sc: inspect(sc).get_table_names())
        assert "quality_snapshots" in tables
        cols = await conn.run_sync(
            lambda sc: {c["name"] for c in inspect(sc).get_columns("quality_snapshots")}
        )
        # The nullable metric columns are the honesty contract (local mode has
        # no agreement; a zero-success run has no fallback denominator).
        assert {
            "mode",
            "agreement_rate",
            "fallback_rate",
            "error_rate",
            "verdict_counts",
            "latency_p50_ms",
            "batch_dir",
            "alarmed",
            "alarm_reasons",
        } <= cols
    await engine.dispose()


async def test_insert_and_read_back(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        row = await quality_svc.insert_snapshot(db, **_snapshot_kwargs())  # type: ignore[arg-type]
        assert row.id is not None
        got = await quality_svc.recent_snapshots(db)
        assert len(got) == 1
        assert got[0].mode == "graded"
        assert got[0].agreement_rate == 0.8
        assert got[0].verdict_counts == {"false_positive": 4, "true_positive": 1}
        assert got[0].alarmed is False
        assert got[0].alarm_reasons is None
        assert got[0].created_at is not None
    await engine.dispose()


async def test_nullable_metrics_round_trip_as_null(settings_kratos: Settings) -> None:
    """Local mode's agreement_rate=None must come back None — never 0.0."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await quality_svc.insert_snapshot(
            db,
            **_snapshot_kwargs(mode="local", agreement_rate=None, fallback_rate=None),  # type: ignore[arg-type]
        )
        got = (await quality_svc.recent_snapshots(db))[0]
        assert got.agreement_rate is None
        assert got.fallback_rate is None
    await engine.dispose()


async def test_recent_is_newest_first_and_mode_filtered(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        first = await quality_svc.insert_snapshot(db, **_snapshot_kwargs(mode="local"))  # type: ignore[arg-type]
        second = await quality_svc.insert_snapshot(db, **_snapshot_kwargs(mode="graded"))  # type: ignore[arg-type]
        third = await quality_svc.insert_snapshot(db, **_snapshot_kwargs(mode="local"))  # type: ignore[arg-type]

        recent = await quality_svc.recent_snapshots(db)
        assert [r.id for r in recent] == [third.id, second.id, first.id]

        local_only = await quality_svc.recent_snapshots(db, mode="local")
        assert [r.id for r in local_only] == [third.id, first.id]

        limited = await quality_svc.recent_snapshots(db, limit=1)
        assert [r.id for r in limited] == [third.id]
    await engine.dispose()


async def test_insert_prunes_to_keep_last(settings_kratos: Settings) -> None:
    """The prune keeps the NEWEST keep_last rows (including the point just
    inserted) and deletes the oldest — exercised at keep_last=5 so the test
    doesn't grind through 90+ inserts."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        ids: list[int] = []
        for _ in range(8):
            row = await quality_svc.insert_snapshot(
                db,
                keep_last=5,
                **_snapshot_kwargs(),  # type: ignore[arg-type]
            )
            ids.append(row.id)
        remaining = await quality_svc.recent_snapshots(db, limit=100)
        # Newest 5 survive, and the newest of all is the row just inserted.
        assert [r.id for r in remaining] == list(reversed(ids[-5:]))
    await engine.dispose()


async def test_default_keep_last_is_90(settings_kratos: Settings) -> None:
    """~3 months of nightlies; a silent constant change should fail a test."""
    assert quality_svc.KEEP_LAST == 90
