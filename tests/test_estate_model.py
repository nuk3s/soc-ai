"""The estate model on a synthetic estate: groups, scores, reasons, gates and states.

300 hosts in three behaviour groups and 5 planted outliers (tests/estate_fixture.py).
The grid is faked: the job reads one document per host through an injected
reader. These tests need the ``ml`` extra and skip without it. The guard tests
in tests/test_estate_model_guard.py run without it.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

pytest.importorskip("sklearn")
pytest.importorskip("numpy")

from soc_ai.config import Settings
from soc_ai.hunting.estate_model import (
    SPEC_ID,
    STATISTIC,
    job,
)
from soc_ai.hunting.estate_model import artifact as art
from soc_ai.hunting.estate_model import features as ft
from soc_ai.hunting.estate_model import fit as fit_mod
from soc_ai.so_client.oql import parse_oql, validate_oql
from soc_ai.store import estate_model as store
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import EntityObservation, EstatePeerGroup
from sqlalchemy import select

from tests import estate_fixture as fx

PLANTED = set(fx.PLANTED_FEATURES)


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None, microsecond=0)


def _fit(hosts: Sequence[fx.Host], previous: dict[str, Any] | None = None) -> fit_mod.EstateFit:
    read = ft.vectors_from_rows(fx.rows_of(hosts))
    features = ft.feature_list(read.vectors)
    raw, model = ft.matrix(read.vectors, features)
    keys = [v.entity_key for v in read.vectors]
    return fit_mod.fit_estate(keys, features, raw, model, previous=previous)


def _previous(fitted: fit_mod.EstateFit) -> dict[str, Any]:
    return {
        "feature_names": fitted.feature_names,
        "groups": [{"id": g.id, "centroid_model": g.centroid_model} for g in fitted.groups],
        "histograms": fitted.histograms,
    }


class _Reader:
    """A fake grid: one current document per host, except the hosts it is told to drop."""

    def __init__(self, *, empty: Sequence[str] = ()) -> None:
        self.empty = set(empty)
        self.asked: list[str] = []

    async def __call__(self, entity_key: str) -> Sequence[job.Document]:
        self.asked.append(entity_key)
        if entity_key in self.empty:
            return []
        at = _now() - timedelta(minutes=30)
        return [job.Document(id=f"doc-{entity_key}-1", at=at)]


class _Audit:
    def __init__(self) -> None:
        self.records: list[tuple[str, str, dict[str, Any]]] = []

    async def log_kind(self, session_id: str, kind: str, payload: dict[str, Any], **_: Any) -> None:
        self.records.append((session_id, kind, payload))


async def _store(settings: Settings, hosts: Sequence[fx.Host]) -> Any:
    engine = make_engine(settings)
    await run_migrations(engine)
    maker = make_sessionmaker(engine)
    async with maker() as db:
        db.add_all(fx.profile_models(hosts))
        await db.commit()
    return engine, maker


def _on(settings: Settings) -> Settings:
    return settings.model_copy(update={"estate_model_enabled": True})


async def _observations(maker: Any) -> list[EntityObservation]:
    async with maker() as db:
        return list(
            (
                await db.execute(
                    select(EntityObservation).where(EntityObservation.spec_id == SPEC_ID)
                )
            )
            .scalars()
            .all()
        )


# ---------------------------------------------------------------------------
# Groups
# ---------------------------------------------------------------------------


async def test_the_three_groups_are_found_and_hold_across_two_fits() -> None:
    hosts = fx.estate()
    first = _fit(hosts)
    second = _fit(hosts, previous=_previous(first))
    origin = {h.key: h.group for h in hosts}

    assert first.k == 3
    by_origin: dict[str, set[int]] = {}
    for host in first.hosts:
        by_origin.setdefault(origin[host.entity_key], set()).add(host.group_id)
    # Every desk shares one group, every server another, every printer a third.
    assert all(len(by_origin[name]) == 1 for name in ("desk", "server", "printer"))
    assert len({next(iter(by_origin[name])) for name in ("desk", "server", "printer")}) == 3
    # The second fit keeps every id: the same data gives the same groups.
    assert [h.group_id for h in second.hosts] == [h.group_id for h in first.hosts]
    assert second.aligned == 3
    assert max(second.psi.values()) == pytest.approx(0.0, abs=1e-9)


async def test_a_far_outlier_never_keeps_a_group_of_its_own() -> None:
    """k-means gives a far host a cluster of one. A group of one has no peers."""
    fitted = _fit(fx.estate())
    assert min(g.size for g in fitted.groups) >= fit_mod.MIN_GROUP_SIZE


# ---------------------------------------------------------------------------
# Scores and reasons
# ---------------------------------------------------------------------------


async def test_the_planted_outliers_score_in_the_top_five_with_their_features_named() -> None:
    fitted = _fit(fx.estate())
    top = sorted(fitted.hosts, key=lambda h: -h.score)[:5]
    assert {h.entity_key for h in top} == PLANTED
    for host in top:
        assert host.score >= fit_mod.SCORE_THRESHOLD, host
        assert host.explained, host
        named = {c.name for c in host.top}
        assert named & fx.PLANTED_FEATURES[host.entity_key], (host.entity_key, named)


async def test_the_job_writes_one_shadow_observation_per_planted_outlier(
    settings_kratos: Settings,
) -> None:
    settings = _on(settings_kratos)
    engine, maker = await _store(settings, fx.estate())
    reader = _Reader()
    audit = _Audit()
    run = await job.run_estate_model(
        db_sessionmaker=maker, settings=settings, documents=reader, audit=audit, now=_now()
    )
    rows = await _observations(maker)
    async with maker() as db:
        fit = await store.latest_fit(db)
    await engine.dispose()

    assert run.state == store.STATE_MEASURED, run.reason
    assert run.observations == 5
    assert {row.entity_key for row in rows} == PLANTED
    assert fit is not None and fit.observations == 5 and fit.audited
    for row in rows:
        assert row.shadow is True
        assert row.source == "model"
        assert row.kind == "estate_outlier"
        assert row.statistic == STATISTIC
        assert row.statistic_value is not None
        assert row.statistic_value >= fit_mod.SCORE_THRESHOLD
        group = fit.group(int(row.evidence_json["group"]["id"]))
        assert group is not None
        # The baseline is the group median of the same statistic.
        assert row.baseline_value == pytest.approx(group["score_median"], abs=1e-4)
        assert row.document_ids == [f"doc-{row.entity_key}-1"]
        assert row.rerun_query is not None
        validate_oql(parse_oql(row.rerun_query))
        # The reason names three features, each with its value and the peer value.
        features = row.evidence_json["features"]
        assert len(features) == 3
        assert set(features) & fx.PLANTED_FEATURES[row.entity_key]
        assert row.summary is not None
        assert row.summary.count("The peer median is") == 3
        assert "—" not in row.summary and "–" not in row.summary
        assert row.evidence_json["detector"]["model_sha256"] == run.model_sha256
    # The audit chain got the hash of the file the store records.
    assert [(s, k) for s, k, _p in audit.records] == [("estate-model", "estate_model_fit")]
    assert audit.records[0][2]["model_sha256"] == run.model_sha256
    # Only the hosts that qualified were read from the grid.
    assert set(reader.asked) == PLANTED


async def test_a_host_identical_to_its_group_does_not_fire(settings_kratos: Settings) -> None:
    settings = _on(settings_kratos)
    middle = fx.desk_median("192.0.2.250")
    engine, maker = await _store(settings, [*fx.estate(), middle])
    run = await job.run_estate_model(
        db_sessionmaker=maker, settings=settings, documents=_Reader(), now=_now()
    )
    rows = await _observations(maker)
    async with maker() as db:
        own = (
            await db.execute(
                select(EstatePeerGroup).where(EstatePeerGroup.entity_key == middle.key)
            )
        ).scalar_one()
    await engine.dispose()
    assert run.state == store.STATE_MEASURED
    assert middle.key not in {row.entity_key for row in rows}
    assert own.score is not None and own.score < fit_mod.SCORE_THRESHOLD


async def test_a_small_tight_group_scores_high_and_still_states_no_reason() -> None:
    """The needle on the path the score alone would miss.

    The forest isolates a small group of identical appliances in few cuts, so
    they score above the threshold. They match their own group exactly. With
    no feature that departs, there is no reason to state, and no observation.
    """
    fitted = _fit([*fx.estate(), *fx.appliances()])
    appliances = [h for h in fitted.hosts if h.entity_key.startswith("198.18.1.")]
    assert len(appliances) == 6
    assert len({h.group_id for h in appliances}) == 1
    assert all(h.score >= fit_mod.SCORE_THRESHOLD for h in appliances)
    assert not any(h.explained for h in appliances)


async def test_the_appliances_count_as_unexplained_and_write_nothing(
    settings_kratos: Settings,
) -> None:
    settings = _on(settings_kratos)
    engine, maker = await _store(settings, [*fx.estate(), *fx.appliances()])
    run = await job.run_estate_model(
        db_sessionmaker=maker, settings=settings, documents=_Reader(), now=_now()
    )
    rows = await _observations(maker)
    await engine.dispose()
    assert run.state == store.STATE_MEASURED
    assert not any(row.entity_key.startswith("198.18.1.") for row in rows)
    assert run.unexplained >= 6
    assert run.outliers == run.unexplained + run.shared + run.no_documents + run.observations


async def test_a_subgroup_that_acts_alike_is_shared_and_not_an_outlier() -> None:
    """The needle on the second path the score would miss.

    Six desks serve four ports each. k-means folds them into the desk group,
    so each departs from the desk median far enough to state a reason, and
    the forest scores some of them above the threshold. Each has the other
    five close by: the behaviour belongs to a subgroup.
    """
    estate = fx.estate()
    dev_keys = {h.key for h in fx.dev_desks()}
    desk_keys = {h.key for h in estate if h.group == "desk"}
    fitted = _fit([*estate, *fx.dev_desks()])
    desks = {h.group_id for h in fitted.hosts if h.entity_key in desk_keys}
    dev = [h for h in fitted.hosts if h.entity_key in dev_keys]
    assert len(dev) == 6
    assert {h.group_id for h in dev} <= desks
    flagged = [h for h in dev if h.score >= fit_mod.SCORE_THRESHOLD and h.explained]
    assert flagged, "the control must reach the shared guard"
    assert all(h.shared for h in dev)
    # A planted outlier has no such company.
    planted = [h for h in fitted.hosts if h.entity_key in PLANTED]
    assert not any(h.shared for h in planted)


async def test_the_shared_subgroup_writes_no_observation(settings_kratos: Settings) -> None:
    settings = _on(settings_kratos)
    engine, maker = await _store(settings, [*fx.estate(), *fx.dev_desks()])
    run = await job.run_estate_model(
        db_sessionmaker=maker, settings=settings, documents=_Reader(), now=_now()
    )
    rows = await _observations(maker)
    async with maker() as db:
        fit = await store.latest_fit(db)
    await engine.dispose()
    assert run.state == store.STATE_MEASURED
    assert not {row.entity_key for row in rows} & {h.key for h in fx.dev_desks()}
    assert run.shared >= 1
    assert fit is not None and fit.shared == run.shared
    assert {row.entity_key for row in rows} == PLANTED


async def test_zero_document_ids_writes_no_observation_and_is_counted(
    settings_kratos: Settings,
) -> None:
    settings = _on(settings_kratos)
    engine, maker = await _store(settings, fx.estate())
    silent = "198.51.100.2"
    run = await job.run_estate_model(
        db_sessionmaker=maker, settings=settings, documents=_Reader(empty=[silent]), now=_now()
    )
    rows = await _observations(maker)
    async with maker() as db:
        fit = await store.latest_fit(db)
    await engine.dispose()
    assert silent not in {row.entity_key for row in rows}
    assert {row.entity_key for row in rows} == PLANTED - {silent}
    assert run.no_documents == 1
    assert fit is not None and fit.no_documents == 1


async def test_a_reader_that_fails_counts_as_no_document(settings_kratos: Settings) -> None:
    settings = _on(settings_kratos)
    engine, maker = await _store(settings, fx.estate())

    async def broken(_key: str) -> Sequence[job.Document]:
        raise ConnectionError("grid down")

    run = await job.run_estate_model(
        db_sessionmaker=maker, settings=settings, documents=broken, now=_now()
    )
    rows = await _observations(maker)
    await engine.dispose()
    assert rows == []
    assert run.no_documents == 5
    assert len(run.errors) == 5


# ---------------------------------------------------------------------------
# The model file and the audit chain
# ---------------------------------------------------------------------------


async def test_the_second_run_loads_the_first_model_and_keeps_the_groups(
    settings_kratos: Settings,
) -> None:
    settings = _on(settings_kratos)
    engine, maker = await _store(settings, fx.estate())
    first_at = _now() - timedelta(days=1)
    first = await job.run_estate_model(
        db_sessionmaker=maker, settings=settings, documents=_Reader(), now=first_at
    )
    async with maker() as db:
        before = await store.learned_map(db, model_sha256=str(first.model_sha256))
    second = await job.run_estate_model(
        db_sessionmaker=maker, settings=settings, documents=_Reader(), now=_now()
    )
    async with maker() as db:
        after = await store.learned_map(db, model_sha256=str(second.model_sha256))
        fits = await store.recorded_files(db)
    await engine.dispose()

    assert first.refused == [] and second.refused == []
    # The same data: the same group per host, and no drift.
    assert after == before
    assert second.psi == pytest.approx(0.0, abs=1e-9)
    assert second.state == store.STATE_MEASURED
    assert set(fits) == {first.model_file, second.model_file}
    path = art.model_dir(settings.soc_ai_data_dir) / str(second.model_file)
    assert art.sha256_of(path.read_bytes()) == second.model_sha256
    assert path.stat().st_mode & 0o777 == 0o600


async def test_an_altered_model_file_is_refused_and_the_fit_runs_without_it(
    settings_kratos: Settings,
) -> None:
    settings = _on(settings_kratos)
    engine, maker = await _store(settings, fx.estate())
    first = await job.run_estate_model(
        db_sessionmaker=maker,
        settings=settings,
        documents=_Reader(),
        now=_now() - timedelta(days=1),
    )
    path = art.model_dir(settings.soc_ai_data_dir) / str(first.model_file)
    payload = json.loads(path.read_bytes())
    # A planted edit: the same format, one centroid moved.
    payload["groups"][0]["centroid_model"][0] += 50.0
    path.write_text(json.dumps(payload))
    second = await job.run_estate_model(
        db_sessionmaker=maker, settings=settings, documents=_Reader(), now=_now()
    )
    async with maker() as db:
        fit = await store.latest_fit(db)
    await engine.dispose()
    assert any("does not load it" in line for line in second.refused)
    # No previous model was read: no drift index, and the refusal is on record.
    assert second.psi is None
    assert fit is not None and fit.reason is not None and "does not load it" in fit.reason


async def test_a_foreign_file_in_the_model_directory_is_reported_and_never_read(
    settings_kratos: Settings,
) -> None:
    settings = _on(settings_kratos)
    engine, maker = await _store(settings, fx.estate())
    directory = art.model_dir(settings.soc_ai_data_dir)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "estate-planted.json").write_text(json.dumps({"format": art.FORMAT}))
    run = await job.run_estate_model(
        db_sessionmaker=maker, settings=settings, documents=_Reader(), now=_now()
    )
    await engine.dispose()
    assert any("estate-planted.json" in line for line in run.refused)
    assert run.psi is None
    assert run.state == store.STATE_MEASURED


async def test_old_model_files_are_pruned_and_the_rows_stay(settings_kratos: Settings) -> None:
    settings = _on(settings_kratos)
    hosts = fx.estate()[:60]
    engine, maker = await _store(settings, hosts)
    start = _now() - timedelta(days=10)
    names = []
    for day in range(job.KEEP_FILES + 2):
        run = await job.run_estate_model(
            db_sessionmaker=maker,
            settings=settings,
            documents=_Reader(),
            now=start + timedelta(days=day),
        )
        names.append(run.model_file)
    async with maker() as db:
        recorded = await store.recorded_files(db)
    await engine.dispose()
    on_disk = {p.name for p in art.model_dir(settings.soc_ai_data_dir).iterdir()}
    assert on_disk == set(names[-job.KEEP_FILES :])
    assert set(recorded) == set(names)


# ---------------------------------------------------------------------------
# States
# ---------------------------------------------------------------------------


async def test_under_seven_days_of_profiles_the_model_is_learning(
    settings_kratos: Settings,
) -> None:
    settings = _on(settings_kratos)
    engine, maker = await _store(settings, fx.estate(days=3))
    run = await job.run_estate_model(
        db_sessionmaker=maker, settings=settings, documents=_Reader(), now=_now()
    )
    rows = await _observations(maker)
    async with maker() as db:
        usable = await store.usable_fit(db)
        fit = await store.latest_fit(db)
    await engine.dispose()
    assert run.state == store.STATE_LEARNING
    assert run.reason is not None and "day 3 of 7" in run.reason
    assert rows == []
    assert usable is None
    assert fit is not None and fit.model_sha256 == run.model_sha256


async def test_the_two_learning_cases_record_what_the_states_table_says(
    settings_kratos: Settings, tmp_path: Any
) -> None:
    """Range dogfood C6: HUNTING.md said a learning fit records groups in both cases.

    Under 20 hosts the model does not fit, so there is nothing to group: the run
    records the fit row and returns. With 20 hosts or more and under 7 days of
    profiles, the model fits and records its groups. The doc now states both.
    """
    small = _on(settings_kratos).model_copy(update={"soc_ai_data_dir": tmp_path / "small"})
    engine, maker = await _store(small, fx.estate(days=30)[:12])
    audit = _Audit()
    run = await job.run_estate_model(
        db_sessionmaker=maker, settings=small, audit=audit, documents=_Reader(), now=_now()
    )
    async with maker() as db:
        fit = await store.latest_fit(db)
        groups = (await db.execute(select(EstatePeerGroup))).scalars().all()
    await engine.dispose()
    assert run.state == store.STATE_LEARNING
    assert run.reason == "The estate holds 12 hosts with a profile. The model needs 20."
    assert fit is not None and fit.state == store.STATE_LEARNING and fit.hosts == 12
    assert fit.groups == 0 and fit.model_file is None and fit.model_sha256 is None
    assert list(groups) == []
    assert audit.records == []
    assert not (tmp_path / "small" / "models" / "estate").exists()

    young = _on(settings_kratos).model_copy(update={"soc_ai_data_dir": tmp_path / "young"})
    engine, maker = await _store(young, fx.estate(days=3))
    audit = _Audit()
    run = await job.run_estate_model(
        db_sessionmaker=maker, settings=young, audit=audit, documents=_Reader(), now=_now()
    )
    async with maker() as db:
        fit = await store.latest_fit(db)
        groups = (await db.execute(select(EstatePeerGroup))).scalars().all()
    await engine.dispose()
    assert run.state == store.STATE_LEARNING
    assert fit is not None and fit.groups == 3 and fit.model_file is not None
    assert len(groups) == run.hosts
    assert [kind for _, kind, _ in audit.records] == ["estate_model_fit"]


async def test_a_changed_estate_reads_as_drifted_and_writes_nothing(
    settings_kratos: Settings,
) -> None:
    settings = _on(settings_kratos)
    engine, maker = await _store(settings, fx.estate())
    await job.run_estate_model(
        db_sessionmaker=maker,
        settings=settings,
        documents=_Reader(),
        now=_now() - timedelta(days=1),
    )
    # Overnight every desk moved: ten times the peers, the names and the processes.
    async with maker() as db:
        from soc_ai.store.models import EntityProfile

        await db.execute(
            EntityProfile.__table__.delete().where(EntityProfile.entity_key.like("192.0.2.%"))
        )
        rng = fx.random.Random(7)
        moved = []
        for n in range(fx.GROUP_SIZE):
            host = fx.desk(rng, f"192.0.2.{n + 1}")
            for dim in ("peers_out", "dns_names", "process_names"):
                _coverage, days, _vector = host.rows[dim]
                host.rows[dim] = fx._set_row(dim[:4], 400, 20000, days)
            moved.append(host)
        db.add_all(fx.profile_models(moved))
        await db.commit()
    before = len(await _observations(maker))
    run = await job.run_estate_model(
        db_sessionmaker=maker, settings=settings, documents=_Reader(), now=_now()
    )
    after = len(await _observations(maker))
    async with maker() as db:
        usable = await store.usable_fit(db)
    await engine.dispose()
    assert run.state == store.STATE_DRIFTED, run.reason
    assert len(run.drifted) >= job.PSI_DRIFT_FEATURES
    assert run.psi is not None and run.psi > job.PSI_DRIFT
    assert after == before
    assert usable is None


def test_the_fire_budget_holds_a_fit_that_marks_too_many_hosts() -> None:
    assert job.fire_budget(305) == 10
    assert job.fire_budget(20_000) == 200
    state, reason = job.decide_state(hosts=305, support_days=30, drifted=(), qualified=11)
    assert state == store.STATE_HELD
    assert reason is not None and "fire budget is 10" in reason
    assert job.decide_state(hosts=305, support_days=30, drifted=(), qualified=10)[0] == (
        store.STATE_MEASURED
    )
    # Learning outranks drift, and drift outranks a hold.
    assert job.decide_state(hosts=305, support_days=3, drifted=("a", "b"), qualified=50)[0] == (
        store.STATE_LEARNING
    )
    assert job.decide_state(hosts=305, support_days=30, drifted=("a", "b"), qualified=50)[0] == (
        store.STATE_DRIFTED
    )
    assert job.decide_state(hosts=305, support_days=30, drifted=("a",), qualified=0)[0] == (
        store.STATE_MEASURED
    )


async def test_the_planted_outliers_are_the_top_five_in_the_store(
    settings_kratos: Settings,
) -> None:
    settings = _on(settings_kratos)
    engine, maker = await _store(settings, fx.estate())
    await job.run_estate_model(
        db_sessionmaker=maker, settings=settings, documents=_Reader(), now=_now()
    )
    async with maker() as db:
        rows = list((await db.execute(select(EstatePeerGroup))).scalars().all())
    await engine.dispose()
    assert len(rows) == 305
    top = sorted(rows, key=lambda r: -(r.score or 0.0))[:5]
    assert {r.entity_key for r in top} == PLANTED
    assert Counter(r.group_id for r in rows if r.entity_key not in PLANTED).most_common()[-1][
        1
    ] == (fx.GROUP_SIZE)
