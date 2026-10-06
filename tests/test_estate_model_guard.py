"""The estate model's guards: off, absent, foreign files, the doctor row, the setting, the loop.

None of these tests needs the ``ml`` extra. They run under a venv with it and
under one without it, and the import guard is proven with the import blocked.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from soc_ai import doctor
from soc_ai.config import Settings
from soc_ai.hunting import estate_model
from soc_ai.hunting.estate_model import artifact as art
from soc_ai.hunting.estate_model import job, schedule
from soc_ai.store import config_overrides as cfg
from soc_ai.store import estate_model as store
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import EstateModelFit

from tests import estate_fixture as fx


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None, microsecond=0)


async def _maker(settings: Settings) -> Any:
    engine = make_engine(settings)
    await run_migrations(engine)
    return engine, make_sessionmaker(engine)


async def _fit_rows(maker: Any) -> int:
    from sqlalchemy import func, select

    async with maker() as db:
        return int((await db.execute(select(func.count(EstateModelFit.id)))).scalar_one())


def _block_the_extra(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make every import of the extra fail, as on an install without it."""
    for name in (
        "numpy",
        "scipy",
        "scipy.optimize",
        "sklearn",
        "sklearn.cluster",
        "sklearn.ensemble",
        "sklearn.metrics",
        "soc_ai.hunting.estate_model.fit",
    ):
        monkeypatch.setitem(sys.modules, name, None)


# ---------------------------------------------------------------------------
# Off and absent
# ---------------------------------------------------------------------------


async def test_the_disabled_setting_runs_nothing(
    settings_kratos: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _no_import() -> None:
        raise AssertionError("the run imported the extra with the setting off")

    monkeypatch.setattr(job, "load_ml", _no_import)
    assert settings_kratos.estate_model_enabled is False
    engine, maker = await _maker(settings_kratos)
    async with maker() as db:
        db.add_all(fx.profile_models(fx.estate()[:30]))
        await db.commit()
    run = await job.run_estate_model(db_sessionmaker=maker, settings=settings_kratos)
    rows = await _fit_rows(maker)
    await engine.dispose()
    assert run.status == job.STATUS_DISABLED
    assert rows == 0
    assert not art.model_dir(settings_kratos.soc_ai_data_dir).exists()


async def test_the_missing_extra_logs_one_line_and_does_nothing(
    settings_kratos: Settings,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    _block_the_extra(monkeypatch)
    assert estate_model.ml_installed() is False
    assert estate_model.load_ml() is None
    settings = settings_kratos.model_copy(update={"estate_model_enabled": True})
    engine, maker = await _maker(settings)
    async with maker() as db:
        db.add_all(fx.profile_models(fx.estate()[:30]))
        await db.commit()
    caplog.set_level(logging.DEBUG, logger="soc_ai.hunting.estate_model")
    run = await job.run_estate_model(db_sessionmaker=maker, settings=settings)
    rows = await _fit_rows(maker)
    await engine.dispose()
    lines = [r for r in caplog.records if r.name.startswith("soc_ai.hunting.estate_model")]
    assert run.status == job.STATUS_UNAVAILABLE
    assert [r.getMessage() for r in lines] == [job.UNAVAILABLE_LINE]
    assert rows == 0
    assert not art.model_dir(settings.soc_ai_data_dir).exists()


def test_the_package_imports_no_part_of_the_extra() -> None:
    """The doctor, the console and the loop import the package. The extra stays out."""
    source = Path(estate_model.__file__).parent
    for module in ("__init__.py", "features.py", "artifact.py", "job.py", "schedule.py"):
        text = (source / module).read_text(encoding="utf-8")
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith(("import ", "from ")) and not line.startswith(" "):
                assert "numpy" not in stripped and "sklearn" not in stripped, (module, line)
                assert "estate_model.fit" not in stripped and "import fit" not in stripped, (
                    module,
                    line,
                )


# ---------------------------------------------------------------------------
# The model file
# ---------------------------------------------------------------------------


def test_a_recorded_file_with_its_recorded_hash_loads(tmp_path: Path) -> None:
    at = datetime(2026, 10, 4, 2, 0, tzinfo=UTC)
    name, sha = art.write_model(tmp_path, {"groups": [], "feature_names": []}, fitted_at=at)
    payload = art.read_verified(tmp_path, name, {name: sha})
    assert payload["format"] == art.FORMAT
    assert (art.model_dir(tmp_path) / name).stat().st_mode & 0o777 == 0o600


def test_a_foreign_model_file_is_refused(tmp_path: Path) -> None:
    """A file the store has no row for is never read, whatever it holds."""
    directory = art.model_dir(tmp_path)
    directory.mkdir(parents=True)
    planted = directory / "estate-20261004T020000Z-000000000000.json"
    planted.write_text(json.dumps({"format": art.FORMAT, "groups": []}))
    with pytest.raises(art.ModelRefused, match="No fit on record wrote"):
        art.read_verified(tmp_path, planted.name, {})
    assert art.foreign_files(tmp_path, {}) == [planted.name]


def test_a_recorded_name_with_other_bytes_is_refused(tmp_path: Path) -> None:
    at = datetime(2026, 10, 4, 2, 0, tzinfo=UTC)
    name, sha = art.write_model(tmp_path, {"groups": []}, fitted_at=at)
    path = art.model_dir(tmp_path) / name
    path.write_text(json.dumps({"format": art.FORMAT, "groups": [{"id": 99}]}))
    with pytest.raises(art.ModelRefused, match="does not load it"):
        art.read_verified(tmp_path, name, {name: sha})


def test_a_name_outside_the_directory_is_refused(tmp_path: Path) -> None:
    outside = tmp_path / "elsewhere.json"
    outside.write_text(json.dumps({"format": art.FORMAT}))
    digest = art.sha256_of(outside.read_bytes())
    directory = art.model_dir(tmp_path)
    directory.mkdir(parents=True)
    link = directory / "estate-link.json"
    link.symlink_to(outside)
    with pytest.raises(art.ModelRefused, match="outside the model directory"):
        art.read_verified(tmp_path, link.name, {link.name: digest})
    with pytest.raises(art.ModelRefused, match="not a plain model file name"):
        art.read_verified(tmp_path, "../elsewhere.json", {"../elsewhere.json": digest})


def test_a_recorded_file_of_another_format_is_refused(tmp_path: Path) -> None:
    directory = art.model_dir(tmp_path)
    directory.mkdir(parents=True)
    path = directory / "estate-other.json"
    path.write_text(json.dumps({"format": "something-else"}))
    with pytest.raises(art.ModelRefused, match="not an estate model"):
        art.read_verified(tmp_path, path.name, {path.name: art.sha256_of(path.read_bytes())})


# ---------------------------------------------------------------------------
# The store record
# ---------------------------------------------------------------------------


async def test_a_challenger_becomes_the_champion_after_24_hours(settings_kratos: Settings) -> None:
    engine, maker = await _maker(settings_kratos)
    now = _now()
    async with maker() as db:
        first = await store.record_fit(
            db, fitted_at=now - timedelta(days=2), state=store.STATE_MEASURED
        )
        second = await store.record_fit(
            db, fitted_at=now - timedelta(hours=30), state=store.STATE_MEASURED
        )
        third = await store.record_fit(
            db, fitted_at=now - timedelta(hours=2), state=store.STATE_MEASURED
        )
        moved = await store.promote_challengers(db, now=now)
        roles = {
            row.id: row.role for row in (await db.execute(EstateModelFit.__table__.select())).all()
        }
    await engine.dispose()
    assert moved == 2
    assert roles == {
        first: store.ROLE_RETIRED,
        second: store.ROLE_CHAMPION,
        third: store.ROLE_CHALLENGER,
    }


async def test_a_learned_group_serves_only_from_a_fresh_measured_fit(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _maker(settings_kratos)
    now = _now()
    sha = "a" * 64
    async with maker() as db:
        await store.record_fit(
            db,
            fitted_at=now - timedelta(hours=72),
            state=store.STATE_MEASURED,
            model_sha256=sha,
            model_file="estate-a.json",
        )
        await store.replace_groups(
            db,
            [store.GroupRow(entity_key="192.0.2.1", group_id=1, distance=0.1, score=0.4)],
            model_sha256=sha,
            fitted_at=now - timedelta(hours=72),
        )
        stale = await store.learned_group(db, "192.0.2.1", now=now)
        fresh = await store.learned_group(db, "192.0.2.1", now=now - timedelta(hours=60))
        with pytest.raises(ValueError, match="unknown estate model state"):
            await store.record_fit(db, fitted_at=now, state="failed")
    await engine.dispose()
    assert stale is None
    assert fresh is not None and fresh.group_id == 1


# ---------------------------------------------------------------------------
# The doctor row
# ---------------------------------------------------------------------------


def _with(settings: Settings, **update: Any) -> Settings:
    return settings.model_copy(update=update)


async def test_the_doctor_says_unavailable_when_the_extra_is_absent(
    settings_kratos: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    _block_the_extra(monkeypatch)
    [off] = await doctor.check_estate_model(settings_kratos)
    [on] = await doctor.check_estate_model(_with(settings_kratos, estate_model_enabled=True))
    assert off.status == "INFO" and off.detail.startswith("unavailable.")
    assert on.status == "WARN" and on.detail.startswith("unavailable.")
    assert "uv sync --extra ml" in on.hint


async def test_the_doctor_says_off_learning_measured_and_drifted_with_the_date(
    settings_kratos: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(estate_model, "ml_installed", lambda: True)
    [off] = await doctor.check_estate_model(settings_kratos)
    assert (off.status, off.detail) == ("INFO", "off. The ml extra is installed.")

    settings = _with(settings_kratos, estate_model_enabled=True)
    engine, maker = await _maker(settings)
    [none_yet] = await doctor.check_estate_model(settings)
    assert none_yet.status == "INFO" and none_yet.detail.startswith("learning.")

    at = datetime(2026, 10, 4, 2, 0)
    async with maker() as db:
        await store.record_fit(db, fitted_at=at, state=store.STATE_MEASURED, hosts=305, groups=3)
    [measured] = await doctor.check_estate_model(settings, now=at + timedelta(hours=3))
    assert measured.status == "PASS"
    assert measured.detail.startswith("measured. The last fit ran on 2026-10-04 02:00 UTC.")

    async with maker() as db:
        await store.record_fit(
            db,
            fitted_at=at + timedelta(days=1),
            state=store.STATE_DRIFTED,
            reason="The data changed after the last fit.",
        )
    [drifted] = await doctor.check_estate_model(settings, now=at + timedelta(days=1, hours=1))
    assert drifted.status == "INFO"
    assert drifted.detail == (
        "drifted. The last fit ran on 2026-10-05 02:00 UTC. The data changed after the last fit."
    )

    [stale] = await doctor.check_estate_model(settings, now=at + timedelta(days=4))
    assert stale.status == "WARN" and stale.detail.startswith("stale.")
    await engine.dispose()
    for row in (off, none_yet, measured, drifted, stale):
        assert "—" not in row.detail and "–" not in row.detail


async def test_the_doctor_off_row_keeps_the_last_fit(
    settings_kratos: Settings, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Range dogfood C2: a learning fit ran, the setting went off, and the row lost the fit."""
    monkeypatch.setattr(estate_model, "ml_installed", lambda: True)
    settings = _with(settings_kratos, soc_ai_data_dir=tmp_path / "data")

    # Negative control first: no store on disk. The row reads plain "off", and the
    # doctor does not create a store to find that out.
    [bare] = await doctor.check_estate_model(settings)
    assert (bare.status, bare.detail) == ("INFO", "off. The ml extra is installed.")
    assert not (tmp_path / "data" / "soc-ai.db").exists()

    engine, maker = await _maker(settings)
    async with maker() as db:
        await store.record_fit(
            db,
            fitted_at=datetime(2026, 10, 5, 1, 50),
            state=store.STATE_LEARNING,
            reason="Learning, day 6 of 7. The median host has 6 days of profiles.",
            hosts=31,
            groups=3,
        )
    await engine.dispose()
    [off] = await doctor.check_estate_model(settings)
    assert off.status == "INFO"
    assert off.detail == (
        "off. The ml extra is installed. The last fit ran on 2026-10-05 01:50 UTC, "
        "in state learning."
    )


# ---------------------------------------------------------------------------
# The setting
# ---------------------------------------------------------------------------


def test_the_setting_is_off_by_default_and_in_the_console() -> None:
    assert Settings.model_fields["estate_model_enabled"].default is False
    spec = next(s for s in cfg.WHITELIST if s.key == "estate_model_enabled")
    assert spec.type == "bool"
    assert spec.hot
    assert spec.section == "Behavioural profiles"
    assert "ml extra" in spec.help
    assert "—" not in spec.help and "–" not in spec.help
    for sentence in spec.help.split(". "):
        assert len(sentence.split()) <= 25, sentence


# ---------------------------------------------------------------------------
# The loop
# ---------------------------------------------------------------------------


def test_a_fit_is_due_once_a_day() -> None:
    now = _now()
    assert schedule.estate_model_due(None, now)
    assert not schedule.estate_model_due(now - timedelta(hours=23), now)
    assert schedule.estate_model_due(now - timedelta(hours=24), now)
    assert schedule.estate_model_due(now + timedelta(hours=1), now)


async def test_the_loop_runs_once_a_day_under_the_dossier_slot(
    settings_kratos: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    from soc_ai.api.webui import _get_dossier_status

    calls: list[bool] = []

    async def fake_run(**kwargs: Any) -> str:
        # The run holds the dossier slot while it fits.
        calls.append(_get_dossier_status(app.state).running)
        return "ran"

    monkeypatch.setattr(schedule, "run_estate_model", fake_run)
    engine, maker = await _maker(settings_kratos)
    app = SimpleNamespace(state=SimpleNamespace(settings=settings_kratos, db_sessionmaker=maker))
    now = _now()
    assert await schedule.estate_model_wake(app, now=now) is None  # off
    app.state.settings = _with(settings_kratos, estate_model_enabled=True)
    _get_dossier_status(app.state).running = True
    assert await schedule.estate_model_wake(app, now=now) is None  # the slot is held
    _get_dossier_status(app.state).running = False
    assert await schedule.estate_model_wake(app, now=now) == "ran"
    assert _get_dossier_status(app.state).running is False
    assert await schedule.estate_model_wake(app, now=now + timedelta(hours=2)) is None
    assert await schedule.estate_model_wake(app, now=now + timedelta(hours=25)) == "ran"
    await engine.dispose()
    assert calls == [True, True]
