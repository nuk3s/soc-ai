"""A quality measurement that cannot name its instrument cannot blame anything.

The nightly trend recorded agreement, fallback, errors and latency, and nothing
at all about what produced them. Both deployments run the image as ``:latest``
and every build of one release carries the same version string, so a bend in the
line had nowhere to point: "quality dropped after Tuesday" and "a change landed
on Tuesday" could not be joined up.

Three columns close that (migration 0040). ``app_version`` and ``code_commit``
say which build ran — the commit stamped into the image at build time, since
``.dockerignore`` excludes ``.git`` and the container has no other way to know.
``analyst_model`` says which route the verdicts came out of, because the failure
the trend exists to catch is named in the model's own docstring as "an
inference-engine swap, a bad model bump", and neither of those changes a line of
code.

Unknown stays unknown throughout: an unstamped build records NULL rather than a
guess, because a wrong commit is worse than a missing one when the entire point
is attribution.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

from soc_ai.config import Settings
from soc_ai.store import quality as quality_svc
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from sqlalchemy import inspect, text


async def _db(settings: Settings) -> Any:
    engine = make_engine(settings)
    await run_migrations(engine)
    return engine, make_sessionmaker(engine)


def _snapshot(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "mode": "graded",
        "n_ok": 5,
        "n_error": 0,
        "agreement_rate": 0.8,
        "fallback_rate": 0.0,
        "error_rate": 0.0,
        "verdict_counts": {},
        "latency_p50_ms": 90_000,
        "batch_dir": "evals/batch-x",
        "alarmed": False,
        "alarm_reasons": None,
    }
    base.update(overrides)
    return base


async def test_migration_adds_the_provenance_columns(settings_kratos: Settings) -> None:
    engine, _maker = await _db(settings_kratos)
    async with engine.connect() as conn:
        cols = await conn.run_sync(
            lambda sc: {c["name"] for c in inspect(sc).get_columns("quality_snapshots")}
        )
    assert {"app_version", "code_commit", "analyst_model"} <= cols
    async with engine.connect() as conn:
        head = await conn.execute(text("SELECT version_num FROM alembic_version"))
    assert head.scalar_one() == "0050"
    await engine.dispose()


async def test_a_snapshot_records_the_build_that_measured_it(
    settings_kratos: Settings,
) -> None:
    """Version and commit come from the writing process, not from the caller.

    Deliberately not parameters: the process performing the write IS the process
    that ran the eval, so there is no caller who could know them better — and
    making them arguments would only create a path on which they get forgotten.
    """
    engine, maker = await _db(settings_kratos)
    with (
        patch("soc_ai.__version__", "9.9.9"),
        patch("soc_ai.__commit__", "0123456789abcdef0123"),
    ):
        async with maker() as db:
            await quality_svc.insert_snapshot(db, **_snapshot(analyst_model="soc-ai-analyst"))
            row = (await quality_svc.recent_snapshots(db))[0]
    assert row.app_version == "9.9.9"
    assert row.code_commit == "0123456789abcdef0123"
    assert row.analyst_model == "soc-ai-analyst"
    await engine.dispose()


async def test_an_unstamped_build_records_unknown_rather_than_a_guess(
    settings_kratos: Settings,
) -> None:
    """A source checkout has no commit to record, and must not invent one."""
    engine, maker = await _db(settings_kratos)
    with patch("soc_ai.__commit__", None):
        async with maker() as db:
            await quality_svc.insert_snapshot(db, **_snapshot())
            row = (await quality_svc.recent_snapshots(db))[0]
    assert row.code_commit is None
    # And it is a real SQL absence, not the string "None" or an empty string.
    async with maker() as db:
        raw = await db.scalar(text("SELECT code_commit FROM quality_snapshots"))
    assert raw is None
    await engine.dispose()


def test_the_commit_is_read_from_the_build_stamp_and_never_guessed(
    monkeypatch: Any,
) -> None:
    """``SOC_AI_COMMIT`` is the only source, and blank means unknown."""
    from soc_ai import _resolve_commit

    monkeypatch.setenv("SOC_AI_COMMIT", "deadbeefcafe")
    assert _resolve_commit() == "deadbeefcafe"
    monkeypatch.setenv("SOC_AI_COMMIT", "   ")
    assert _resolve_commit() is None
    monkeypatch.delenv("SOC_AI_COMMIT")
    assert _resolve_commit() is None


async def test_the_nightly_records_the_route_its_verdicts_came_from(
    settings_kratos: Settings,
) -> None:
    """The model is config, so it is passed in — and the nightly has to pass it.

    A column nobody populates is the same blind spot with extra steps, so this
    holds the wiring rather than the storage.
    """
    from soc_ai.eval.nightly import _record_trend_point

    metrics = _Metrics()
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _record_trend_point(
            db,
            metrics=metrics,
            mode="local",
            alarm_drop=0.15,
            batch_dir="evals/batch-y",
            analyst_model="some-other-route",
        )
        row = (await quality_svc.recent_snapshots(db))[0]
    assert row.analyst_model == "some-other-route"
    await engine.dispose()


class _Metrics:
    """The slice of ``SnapshotMetrics`` the trend writer reads."""

    mode = "local"
    n_ok = 5
    n_error = 0
    agreement_rate = None
    fallback_rate = 0.0
    error_rate = 0.0
    verdict_counts: dict[str, int] = {}  # noqa: RUF012 - plain test double
    latency_p50_ms = 1000
    n_yes = 0
    n_partial = 0
    n_no = 0
    n_classified = 0
