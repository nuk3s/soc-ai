"""Tests for the quality_snapshots store service + the 0019 migration.

Mirrors tests/test_hunts_store.py: exercises insert (with its same-transaction
prune) and the newest-first / mode-filtered reads against a real SQLite file
migrated to head. Uses the ``settings_kratos`` fixture, which the autouse
``clean_env`` fixture isolates to a per-test temp dir.
"""

from __future__ import annotations

from datetime import datetime

from soc_ai.config import Settings
from soc_ai.store import quality as quality_svc
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import QualityEvalAttempt
from sqlalchemy import inspect, select


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
            # 0026: the counts behind agreement_rate. NULL on pre-0026 rows —
            # "never recorded" is not "nothing agreed".
            "n_yes",
            "n_partial",
            "n_no",
            "n_classified",
            # 0027: the alarm's IDENTITY and how long it has held. Without
            # these the alarm has no memory and re-fires every run a condition
            # persists (prod rows 9/10/11 — one condition, three pages).
            "alarm_key",
            "alarm_since",
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


async def test_grade_counts_round_trip_and_default_to_null(settings_kratos: Settings) -> None:
    """The detector tests counts, not rates, so they have to survive the write.
    A caller that passes none leaves NULLs, which is the sentinel the detector
    reads as "pre-0026 row, fall back to the median rule"."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await quality_svc.insert_snapshot(
            db,
            **_snapshot_kwargs(  # type: ignore[arg-type]
                agreement_rate=0.6, n_yes=3, n_partial=1, n_no=1, n_classified=5
            ),
        )
        counted = (await quality_svc.recent_snapshots(db))[0]
        assert (counted.n_yes, counted.n_partial, counted.n_no) == (3, 1, 1)
        assert counted.n_classified == 5

        await quality_svc.insert_snapshot(db, **_snapshot_kwargs())  # type: ignore[arg-type]
        legacy = (await quality_svc.recent_snapshots(db))[0]
        assert legacy.n_yes is None
        assert legacy.n_classified is None
    await engine.dispose()


async def test_alarm_identity_round_trips_and_defaults_to_null(settings_kratos: Settings) -> None:
    """The key is what the next run compares against to decide whether anyone is
    told, and ``alarm_since`` is what the card reads to say "ongoing since" —
    both have to survive the write. A caller that passes neither (every pre-0027
    row, and every clean point) leaves NULLs: "no condition recorded" is not
    "the condition started at epoch"."""
    engine, maker = await _db(settings_kratos)
    since = datetime(2026, 8, 6, 2, 17, 0)
    async with maker() as db:
        await quality_svc.insert_snapshot(
            db,
            **_snapshot_kwargs(  # type: ignore[arg-type]
                alarmed=True,
                alarm_reasons=["agreement_rate 0.80 is more than 0.15 below the median 1.00"],
                alarm_key="agreement_drop",
                alarm_since=since,
            ),
        )
        alarmed = (await quality_svc.recent_snapshots(db))[0]
        assert alarmed.alarm_key == "agreement_drop"
        assert alarmed.alarm_since == since

        await quality_svc.insert_snapshot(db, **_snapshot_kwargs())  # type: ignore[arg-type]
        clean = (await quality_svc.recent_snapshots(db))[0]
        assert clean.alarm_key is None
        assert clean.alarm_since is None
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


# ---------------------------------------------------------------------------
# quality_eval_attempts — the nightly ran, on the nights it wrote nothing too.
#
# Exit 2 (no eligible alerts) and exit 5 (failed) deliberately write no
# snapshot, so the trend is silent on exactly the nights an operator needs to
# know what happened. That fact used to live in a status slot on ``app.state``.


async def test_migration_creates_the_attempt_trail(settings_kratos: Settings) -> None:
    engine, _maker = await _db(settings_kratos)
    async with engine.connect() as conn:
        tables = await conn.run_sync(lambda sc: inspect(sc).get_table_names())
        assert "quality_eval_attempts" in tables
        cols = await conn.run_sync(
            lambda sc: {c["name"] for c in inspect(sc).get_columns("quality_eval_attempts")}
        )
        assert {"attempted_at", "trigger", "exit_code", "detail"} <= cols
        indexes = await conn.run_sync(
            lambda sc: {ix["name"] for ix in inspect(sc).get_indexes("quality_eval_attempts")}
        )
        assert "ix_quality_eval_attempts_attempted_at" in indexes
    await engine.dispose()


async def test_no_attempt_recorded_reads_as_none(settings_kratos: Settings) -> None:
    """The distinction persistence buys. ``None`` now means "this deployment
    has never run one", where the in-memory slot also said None after every
    restart — so a reader could not tell that from "ran last night, forgot"."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        assert await quality_svc.latest_attempt(db) is None
    await engine.dispose()


async def test_an_attempt_that_wrote_no_snapshot_is_still_recorded(
    settings_kratos: Settings,
) -> None:
    """The whole point: no snapshot, and the run is still on the record with
    its own exit code and reason."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await quality_svc.record_attempt(
            db,
            trigger="schedule",
            exit_code=2,
            detail="no eligible alerts for 'x' — no snapshot written",
        )
        assert await quality_svc.recent_snapshots(db) == []
        row = await quality_svc.latest_attempt(db)
        assert row is not None
        assert (row.exit_code, row.trigger) == (2, "schedule")
        assert "no eligible alerts" in row.detail
    await engine.dispose()


async def test_the_newest_attempt_is_the_one_returned(settings_kratos: Settings) -> None:
    """A trail, and the reader wants its head. The run-now button and the
    scheduler share the table, so "the last attempt" has to be the last one and
    not the last SCHEDULED one."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await quality_svc.record_attempt(db, trigger="schedule", exit_code=2, detail="quiet")
        await quality_svc.record_attempt(db, trigger="manual", exit_code=0, detail="")
        row = await quality_svc.latest_attempt(db)
        assert row is not None
        assert (row.trigger, row.exit_code, row.detail) == ("manual", 0, "")
    await engine.dispose()


async def test_recording_an_attempt_prunes_in_the_same_transaction(
    settings_kratos: Settings,
) -> None:
    """Insert + prune in one commit, the trend table's own idiom: the table can
    never be observed over capacity, and a crash between the two cannot lose
    the new row while keeping stale ones."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        ids = [
            (
                await quality_svc.record_attempt(
                    db, trigger="schedule", exit_code=0, detail="", keep_last=3
                )
            ).id
            for _ in range(7)
        ]
        rows = (
            await db.execute(select(QualityEvalAttempt).order_by(QualityEvalAttempt.id.desc()))
        ).scalars()
        assert [r.id for r in rows] == list(reversed(ids[-3:]))
    await engine.dispose()
