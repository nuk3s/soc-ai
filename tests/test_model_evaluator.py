"""The ``model`` evaluator: the spec block, the dispatch, the record path.

A stub detector stands in for the real ones, so these tests read the
evaluator alone: what it hands the detector, what it writes from a hit, the
hit it drops, and the states it records. The detectors have their own tests.

Every address here is from the documentation ranges.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from pydantic import ValidationError
from soc_ai.config import Settings
from soc_ai.hunting import model as model_mod
from soc_ai.hunting.detectors.base import (
    STATE_LEARNING,
    STATE_MEASURED,
    STATE_UNMEASURABLE,
    STATISTIC_PLANE_DOCUMENTS,
    DetectorContext,
    DetectorRun,
    EntityState,
    ModelHit,
)
from soc_ai.hunting.detectors.params import CrossPlaneSilenceParams
from soc_ai.hunting.prior_sweep import format_sweep, run_prior_sweep
from soc_ai.hunting.spec import HuntSpec, parse_spec
from soc_ai.hunting.weight import Kind
from soc_ai.so_client.oql import parse_oql, validate_oql
from soc_ai.store.models import EntityObservation, PriorSpecRun
from sqlalchemy import select

from tests.test_prior_sweep import _db, _settings_like

_HOST = "app-01"
_SPEC_ID = "model-under-test"
_ANCHOR = datetime(2026, 9, 9, 12, tzinfo=UTC)
_QUERY = (
    f'host.name:"{_HOST}" AND @timestamp:["2026-09-09T08:00:00Z" TO "2026-09-09T12:00:00Z"] '
    "| groupby event.dataset"
)


def _catalog() -> dict[str, HuntSpec]:
    spec = HuntSpec.model_validate(
        {
            "id": _SPEC_ID,
            "title": "A detector under test",
            "evaluator": "model",
            "model": {"detector": "cross_plane_silence"},
            "false_positives": ["something"],
        }
    )
    return {spec.id: spec}


def _hit(
    *, ids: tuple[str, ...] = ("doc-silent-1", "doc-live-1"), plane: str = "process"
) -> ModelHit:
    return ModelHit(
        entity_key=_HOST,
        kind=Kind.TELEMETRY_SILENCE,
        fingerprint=("cross_plane_silence", plane),
        statistic=STATISTIC_PLANE_DOCUMENTS,
        statistic_value=0.0,
        baseline_value=412.0,
        document_ids=ids,
        rerun_query=_QUERY,
        reason=(
            f"The {plane} plane of {_HOST} fell to 0 documents in 2 hours. "
            "The baseline expects 412 in those hours."
        ),
        features={"silent_plane_documents": 0, "silent_plane_expected": 412},
        observed_at=_ANCHOR - timedelta(hours=3),
    )


class _Stub:
    """A detector that returns what the test gives it and records its context."""

    def __init__(self, run: DetectorRun) -> None:
        self.run = run
        self.calls: list[tuple[Any, DetectorContext]] = []

    async def __call__(self, params: Any, ctx: DetectorContext) -> DetectorRun:
        self.calls.append((params, ctx))
        return self.run


@pytest.fixture
def stub(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Install a stub as the cross-plane silence detector."""

    def install(run: DetectorRun) -> _Stub:
        detector = _Stub(run)
        monkeypatch.setitem(model_mod.DETECTORS, "cross_plane_silence", detector)
        return detector

    return install


async def _sweep(
    settings_kratos: Settings, *, record: bool = True, shadow: bool = True
) -> tuple[Any, Any, Any]:
    """Run the sweep over the catalog. ``shadow`` puts the spec in ``shadow_ids``,
    as the effective catalog does for an analytic in shadow."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        sweep = await run_prior_sweep(
            elastic=object(),
            settings=_settings_like(settings_kratos),
            db=db,
            catalog=_catalog(),
            shadow_ids=frozenset({_SPEC_ID}) if shadow else frozenset(),
            record=record,
            now=_ANCHOR,
        )
    return engine, maker, sweep


# ---------------------------------------------------------------------------
# The spec block
# ---------------------------------------------------------------------------


def test_a_model_spec_names_a_detector_and_its_parameters() -> None:
    spec = parse_spec(
        "id: model-x\n"
        "title: A model spec\n"
        "evaluator: model\n"
        "model:\n"
        "  detector: cross_plane_silence\n"
        "  params:\n"
        "    min_silent_hours: 3\n"
        "false_positives: [x]\n"
    )
    assert spec.model is not None
    assert spec.model.detector == "cross_plane_silence"
    assert isinstance(spec.model.params, CrossPlaneSilenceParams)
    assert spec.model.params.min_silent_hours == 3
    assert spec.runs_in_prior_sweep


@pytest.mark.parametrize(
    "body",
    [
        # No model block on a model spec.
        {"evaluator": "model"},
        # A detector nobody wrote.
        {"evaluator": "model", "model": {"detector": "isolation_forest"}},
        # A parameter the detector does not read.
        {"evaluator": "model", "model": {"detector": "logon_chain", "params": {"nope": 1}}},
        # A bar the detector can never meet.
        {
            "evaluator": "model",
            "model": {"detector": "logon_chain", "params": {"warm_days": 40, "learning_days": 30}},
        },
        # Two blocks: which one decides is ambiguous.
        {
            "evaluator": "model",
            "model": {"detector": "logon_chain"},
            "profile": {"dimension": "served_ports"},
        },
        # A profile spec that carries a model block.
        {
            "evaluator": "profile",
            "profile": {"dimension": "served_ports"},
            "model": {"detector": "logon_chain"},
        },
    ],
)
def test_a_wrong_model_block_fails_at_load(body: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        HuntSpec.model_validate({"id": "model-x", "title": "t", **body})


def test_a_model_spec_compiles_to_no_query() -> None:
    spec = _catalog()[_SPEC_ID]
    with pytest.raises(ValueError, match="tier 3 detector"):
        spec.to_query(since="now-1h", until="now")


# ---------------------------------------------------------------------------
# The dispatch and the record path
# ---------------------------------------------------------------------------


async def test_the_sweep_runs_the_detector_at_the_time_anchor(
    settings_kratos: Settings, stub: Any
) -> None:
    detector = stub(DetectorRun(entities=(EntityState(_HOST, STATE_MEASURED),)))
    engine, _maker, sweep = await _sweep(settings_kratos, record=False)

    assert len(detector.calls) == 1
    params, ctx = detector.calls[0]
    assert isinstance(params, CrossPlaneSilenceParams)
    assert ctx.now == _ANCHOR
    assert _SPEC_ID in sweep.evaluated_specs
    assert sweep.errors == ()
    await engine.dispose()


async def test_a_hit_is_written_as_a_shadow_model_observation_with_every_evidence_column(
    settings_kratos: Settings, stub: Any
) -> None:
    stub(DetectorRun(entities=(EntityState(_HOST, STATE_MEASURED, hits=(_hit(),)),)))
    engine, maker, sweep = await _sweep(settings_kratos)

    assert sweep.errors == ()
    assert [r.entity_key for r in sweep.fired] == [_HOST]
    async with maker() as db:
        row = (await db.execute(select(EntityObservation))).scalars().one()
        trail = (await db.execute(select(PriorSpecRun))).scalars().one()

    assert row.source == "model"
    # The analytic is in shadow, so its observation is.
    assert row.shadow is True
    assert row.spec_id == _SPEC_ID
    assert row.entity_key == _HOST
    assert row.kind == "telemetry_silence"
    assert row.statistic == STATISTIC_PLANE_DOCUMENTS
    assert row.statistic_value == 0.0
    assert row.baseline_value == 412.0
    assert row.document_ids == ["doc-silent-1", "doc-live-1"]
    assert row.rerun_query == _QUERY
    validate_oql(parse_oql(row.rerun_query))
    assert row.summary is not None and row.summary.startswith("The process plane of app-01")
    assert row.observed_at == (_ANCHOR - timedelta(hours=3)).replace(tzinfo=None)
    assert row.born_at == _ANCHOR.replace(tzinfo=None)
    receipts = row.evidence_json["receipts"]
    assert receipts["matched_ids"] == ["doc-silent-1", "doc-live-1"]
    assert receipts["complete"] is True
    assert row.evidence_json["baseline"]["features"]["silent_plane_expected"] == 412
    # The trail row of a model spec says shadow, as its observations do.
    assert trail.spec_id == _SPEC_ID
    assert trail.shadow is True
    assert (trail.measured, trail.fired) == (1, 1)
    await engine.dispose()


async def test_a_live_model_analytic_writes_a_live_observation(
    settings_kratos: Settings, stub: Any
) -> None:
    """The control: the shadow flag is the analytic's status, not the evaluator.

    An approval to live must lift the shadow on a detector's observations, or
    the approval changes nothing. The sweep reads the status from
    ``shadow_ids`` the way it does for a profile analytic.
    """
    stub(DetectorRun(entities=(EntityState(_HOST, STATE_MEASURED, hits=(_hit(),)),)))
    engine, maker, sweep = await _sweep(settings_kratos, shadow=False)

    assert sweep.errors == ()
    async with maker() as db:
        row = (await db.execute(select(EntityObservation))).scalars().one()
        trail = (await db.execute(select(PriorSpecRun))).scalars().one()
    assert row.shadow is False
    assert trail.shadow is False
    await engine.dispose()


def test_the_shipped_detectors_ship_in_shadow_with_a_budget() -> None:
    """Both learned detectors declare ``ships_as: shadow`` and the limits the
    self-healing hold reads. A detector that shipped live would raise leads
    the shadow week never measured."""
    from soc_ai.hunting.spec import CATALOG_DIR, load_catalog

    catalog = load_catalog(CATALOG_DIR)
    models = {sid: spec for sid, spec in catalog.items() if spec.evaluator == "model"}
    assert set(models) == {"model-cross-plane-silence", "model-logon-chain"}
    for spec in models.values():
        assert spec.ships_as == "shadow", spec.id
        assert spec.fire_budget_per_day is not None, spec.id
        assert spec.precision_floor is not None, spec.id


async def test_a_hit_without_a_document_is_dropped_and_counted(
    settings_kratos: Settings, stub: Any
) -> None:
    """The false-all-clear rule. The lead auto-hunt skips a lead with no cited
    document, so an observation without one is a claim nobody can open."""
    stub(
        DetectorRun(
            entities=(
                EntityState(
                    _HOST,
                    STATE_MEASURED,
                    hits=(_hit(), _hit(ids=(), plane="endpoint_network")),
                ),
            )
        )
    )
    engine, maker, sweep = await _sweep(settings_kratos)

    assert sweep.dropped == 1
    (result,) = [r for r in sweep.results if r.spec_id == _SPEC_ID]
    assert result.dropped == 1
    assert [h.fingerprint[1] for h in result.hits] == ["process"]
    assert any("1 hit cited no document" in note for note in sweep.notes), sweep.notes
    async with maker() as db:
        rows = (await db.execute(select(EntityObservation))).scalars().all()
    assert [r.document_ids for r in rows] == [["doc-silent-1", "doc-live-1"]]
    await engine.dispose()


async def test_a_lone_hit_without_a_document_writes_nothing(
    settings_kratos: Settings, stub: Any
) -> None:
    """Negative control on the same path: the only hit cites nothing."""
    stub(DetectorRun(entities=(EntityState(_HOST, STATE_MEASURED, hits=(_hit(ids=()),)),)))
    engine, maker, sweep = await _sweep(settings_kratos)

    assert sweep.dropped == 1
    assert sweep.fired == ()
    async with maker() as db:
        assert (await db.execute(select(EntityObservation))).scalars().all() == []
    await engine.dispose()


async def test_the_states_land_in_the_sweep_notes_and_the_trail(
    settings_kratos: Settings, stub: Any
) -> None:
    stub(
        DetectorRun(
            entities=(
                EntityState("app-01", STATE_MEASURED),
                EntityState("app-02", STATE_LEARNING, note="learning: the process plane"),
                EntityState("app-03", STATE_UNMEASURABLE, note="one plane"),
            ),
            notes=("the flow plane answered for 2 machines.",),
        )
    )
    engine, maker, sweep = await _sweep(settings_kratos)

    assert (
        f"{_SPEC_ID}: entity states: measured 1, learning 1, blind 0, unmeasurable 1, "
        "stale 0, drifted 0, held 0."
    ) in sweep.notes
    assert f"{_SPEC_ID}: the flow plane answered for 2 machines." in sweep.notes
    # The coverage counts fold as the trail folds: unmeasurable is blind.
    # Counted under its own name, it was a fifth column in soc-ai priors and
    # the journal said one blind less than the store.
    counts = sweep.coverage_counts()
    assert counts == {"measured": 1, "learning": 1, "blind": 1, "not_applicable": 0}
    text = format_sweep(sweep)
    assert "  coverage: blind=1, learning=1, measured=1\n" in text
    assert f"{_SPEC_ID:48} blind=1, learning=1, measured=1" in text
    assert "unmeasurable=" not in text
    # The count of each detector state stays in the per-state note.
    assert "unmeasurable 1" in text
    # The blind reason is the note of the unmeasurable entity, after its count.
    assert "       1 of 1 blind host: one plane" in text
    async with maker() as db:
        trail = (await db.execute(select(PriorSpecRun))).scalars().one()
    # The trail has four columns. Unmeasurable folds into blind.
    assert (trail.measured, trail.learning, trail.blind, trail.fired) == (1, 1, 1, 0)
    assert trail.blind_reason == "1 of 1 blind host: one plane"
    await engine.dispose()


async def test_each_priors_row_states_the_status_of_its_analytic(
    settings_kratos: Settings, stub: Any
) -> None:
    """A shadow detector and a live analytic looked the same in soc-ai priors.
    Each row now states the status from the effective catalog the sweep ran,
    and a retired analytic that the sweep did not run is named."""
    from soc_ai.hunting.catalog_tiers import Catalog

    stub(DetectorRun(entities=(EntityState(_HOST, STATE_MEASURED),)))
    engine, _maker, sweep = await _sweep(settings_kratos, record=False)
    spec = _catalog()[_SPEC_ID]
    retired = spec.model_copy(update={"id": "model-retired"})
    match = spec.model_copy(update={"id": "match-retired", "evaluator": "match", "model": None})

    shadow = Catalog(
        specs={_SPEC_ID: spec},
        listed={_SPEC_ID: spec, "model-retired": retired, "match-retired": match},
        tiers={
            _SPEC_ID: ("shipped", "shadow"),
            "model-retired": ("shipped", "retired"),
            "match-retired": ("shipped", "retired"),
        },
        shadow_ids=frozenset({_SPEC_ID}),
    )
    text = format_sweep(sweep, catalog=shadow)
    assert f"     {_SPEC_ID:48} shadow    measured=1" in text
    assert "  not run: model-retired is retired" in text
    # A match analytic is the catalog sweep's. This sweep never runs it.
    assert "match-retired" not in text

    live = Catalog(specs={_SPEC_ID: spec}, listed={_SPEC_ID: spec})
    assert f"     {_SPEC_ID:48} live      measured=1" in format_sweep(sweep, catalog=live)
    # Negative control: with no catalog the row states no status.
    assert f"     {_SPEC_ID:48} measured=1" in format_sweep(sweep)
    await engine.dispose()


async def test_a_detector_that_raises_makes_its_spec_blind(
    settings_kratos: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def broken(params: Any, ctx: DetectorContext) -> DetectorRun:
        raise RuntimeError("the grid refused the read")

    monkeypatch.setitem(model_mod.DETECTORS, "cross_plane_silence", broken)
    engine, maker, sweep = await _sweep(settings_kratos)

    assert any("the grid refused the read" in e for e in sweep.errors), sweep.errors
    (result,) = sweep.results
    assert (result.coverage, result.entity_key) == ("blind", "*")
    async with maker() as db:
        assert (await db.execute(select(EntityObservation))).scalars().all() == []
    await engine.dispose()


async def test_a_blind_detector_run_records_one_blind_result(
    settings_kratos: Settings, stub: Any
) -> None:
    stub(DetectorRun(blind="no plane on this grid carries a logon"))
    engine, _maker, sweep = await _sweep(settings_kratos)

    (result,) = sweep.results
    assert result.coverage == "blind"
    assert f"{_SPEC_ID}: no plane on this grid carries a logon" in sweep.notes
    await engine.dispose()


async def test_a_spec_whose_detector_is_not_installed_is_blind(
    settings_kratos: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delitem(model_mod.DETECTORS, "cross_plane_silence", raising=False)
    engine, _maker, sweep = await _sweep(settings_kratos)

    (result,) = sweep.results
    assert result.coverage == "blind"
    assert any("no detector named cross_plane_silence" in e for e in sweep.errors)
    await engine.dispose()


async def test_a_repeat_over_the_same_documents_refreshes_one_row(
    settings_kratos: Settings, stub: Any
) -> None:
    """The fingerprint names what was noticed, not when. Two sweeps that read
    the same silence write one row."""
    stub(DetectorRun(entities=(EntityState(_HOST, STATE_MEASURED, hits=(_hit(),)),)))
    engine, maker = await _db(settings_kratos)
    for step in range(2):
        async with maker() as db:
            await run_prior_sweep(
                elastic=object(),
                settings=_settings_like(settings_kratos),
                db=db,
                catalog=_catalog(),
                record=True,
                now=_ANCHOR + timedelta(hours=step),
            )
    async with maker() as db:
        rows = (await db.execute(select(EntityObservation))).scalars().all()
    assert len(rows) == 1
    assert rows[0].occurrences == 1
    await engine.dispose()
