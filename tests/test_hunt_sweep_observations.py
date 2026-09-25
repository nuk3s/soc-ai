"""A catalog hit is an observation. It is not a hunt row."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import patch

import pytest
from soc_ai.config import Settings
from soc_ai.hunting import sweep as sweep_mod
from soc_ai.hunting.execute import Candidate, SpecRun
from soc_ai.hunting.spec import HuntSpec
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import EntityObservation, Hunt, HuntSpecState, Lead
from sqlalchemy import select

pytestmark = pytest.mark.asyncio

_NOW = datetime(2026, 9, 18, 12, 0, tzinfo=UTC)


def _spec() -> HuntSpec:
    return HuntSpec.model_validate(
        {
            "id": "t-hit",
            "title": "A test analytic fires",
            "description": "For the sweep test.",
            "level": "high",
            "scope_field": "source.ip",
            "scope_kind": "host",
            "precondition": {"all": [{"field": "event.code", "value": "1"}]},
            "detection": {"all": [{"field": "event.code", "value": "1"}]},
        }
    )


def _run(spec: HuntSpec) -> SpecRun:
    return SpecRun(
        spec_id=spec.id,
        since="now-24h",
        until="now",
        blind=False,
        precondition_docs=10,
        matched_docs=2,
        candidates=[
            Candidate(
                spec_id=spec.id,
                scope_key="198.51.100.7",
                scope_kind="host",
                doc_count=2,
                sample_ids=("d1", "d2"),
                anchor_id="d1",
                anchor_index="logs-x",
                first_seen=None,
                last_seen=None,
            )
        ],
        precondition_since="",
    )


async def test_a_fresh_hit_writes_an_observation_and_no_hunt_row(
    settings_kratos: Settings,
) -> None:
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    maker = make_sessionmaker(engine)
    spec = _spec()

    async def fake_run_spec(*_args, **_kwargs):  # type: ignore[no-untyped-def]
        return _run(spec)

    with patch.object(sweep_mod, "run_spec", fake_run_spec):
        async with maker() as session:
            run, hunt_id = await sweep_mod.sweep_spec(
                spec,
                elastic=None,
                settings=settings_kratos,
                session=session,
                since="now-24h",
                until="now",
                now=_NOW,
                record=True,
                backfill=False,
                include_synth=False,
            )
            hunts = (await session.execute(select(Hunt))).scalars().all()
            observations = (await session.execute(select(EntityObservation))).scalars().all()
            state = (await session.execute(select(HuntSpecState))).scalars().all()
    await engine.dispose()

    assert run.candidates
    assert hunt_id is None
    assert hunts == []
    assert len(observations) == 1
    assert observations[0].source == "catalog"
    assert observations[0].entity_key == "198.51.100.7"
    # The gate row is handled: it points at the observation, so the same
    # condition does not fire again on the next sweep.
    assert all(row.hunt_id and row.hunt_id.startswith("obs:") for row in state)


async def test_the_setting_restores_the_hunt_row_beside_the_observation(
    settings_kratos: Settings,
) -> None:
    """``catalog_hunt_rows`` on writes the row the sweep wrote before 1.5.0.

    The observation is written either way. The setting adds the hunt row. It
    does not take the observation away.
    """
    settings = settings_kratos.model_copy(update={"catalog_hunt_rows": True})
    engine = make_engine(settings)
    await run_migrations(engine)
    maker = make_sessionmaker(engine)
    spec = _spec()

    async def fake_run_spec(*_args, **_kwargs):  # type: ignore[no-untyped-def]
        return _run(spec)

    with patch.object(sweep_mod, "run_spec", fake_run_spec):
        async with maker() as session:
            _run_out, hunt_id = await sweep_mod.sweep_spec(
                spec,
                elastic=None,
                settings=settings,
                session=session,
                since="now-24h",
                until="now",
                now=_NOW,
                record=True,
                backfill=False,
                include_synth=False,
            )
            hunts = (await session.execute(select(Hunt))).scalars().all()
            observations = (await session.execute(select(EntityObservation))).scalars().all()
            state = (await session.execute(select(HuntSpecState))).scalars().all()
    await engine.dispose()

    assert hunt_id is not None
    assert [h.kind for h in hunts] == ["triggered"]
    assert hunts[0].id == hunt_id
    assert len(observations) == 1
    assert observations[0].source == "catalog"
    # The fired row points at the hunt that reports it, as it did before.
    assert all(row.hunt_id == hunt_id for row in state)


async def test_the_setting_is_off_by_default(settings_kratos: Settings) -> None:
    """The negative control for the setting: the shipped default writes no row."""
    assert settings_kratos.catalog_hunt_rows is False


async def test_a_shadow_analytic_writes_a_shadow_observation_with_receipts(
    settings_kratos: Settings,
) -> None:
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    maker = make_sessionmaker(engine)
    spec = _spec()
    calls: list[str] = []

    async def fake_run_spec(spec_arg, *, since, **_kwargs):  # type: ignore[no-untyped-def]
        calls.append(since)
        return _run(spec_arg)

    with patch.object(sweep_mod, "run_spec", fake_run_spec):
        async with maker() as session:
            run, hunt_id = await sweep_mod.sweep_spec(
                spec,
                elastic=None,
                settings=settings_kratos,
                session=session,
                since="now-24h",
                until="now",
                now=_NOW,
                record=True,
                backfill=False,
                include_synth=False,
                shadow_ids=frozenset({spec.id}),
            )
            observations = (await session.execute(select(EntityObservation))).scalars().all()
            hunts = (await session.execute(select(Hunt))).scalars().all()
    await engine.dispose()

    assert run.candidates
    assert hunt_id is None and hunts == []
    assert len(observations) == 1
    observation = observations[0]
    # The source names the adapter that wrote the row. The shadow flag carries
    # the status of the analytic, so an approval changes one field only.
    assert observation.shadow is True and observation.source == "catalog"
    receipts = observation.evidence_json["receipts"]
    assert receipts["complete"] is True
    assert receipts["matched_ids"] == ["d1", "d2"]
    assert receipts["matched_fields"] == ["event.code"]
    assert receipts["dry_run"]["window_days"] == 30
    # The dry run is a second run of the analytic over the last 30 days.
    assert "now-30d" in calls


async def test_a_shadow_analytic_forms_no_live_lead(settings_kratos: Settings) -> None:
    """A shadow observation can join a lead. The lead is then a shadow lead."""
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    maker = make_sessionmaker(engine)
    spec = _spec()

    async def fake_run_spec(spec_arg, *, since, **_kwargs):  # type: ignore[no-untyped-def]
        return _run(spec_arg)

    with patch.object(sweep_mod, "run_spec", fake_run_spec):
        async with maker() as session:
            await sweep_mod.sweep_spec(
                spec,
                elastic=None,
                settings=settings_kratos,
                session=session,
                since="now-24h",
                until="now",
                now=_NOW,
                record=True,
                backfill=False,
                include_synth=False,
                shadow_ids=frozenset({spec.id}),
            )
            leads = (await session.execute(select(Lead))).scalars().all()
    await engine.dispose()
    assert all(lead.shadow for lead in leads)


async def test_the_next_sweep_after_an_approval_writes_a_live_observation(
    settings_kratos: Settings,
) -> None:
    """The approval keeps the hit. The next sweep turns it live.

    This is the design's range step: approve one local analytic, run the sweep,
    and read a live hit beside a shadow hit. The observation carries the status
    the analytic had at its latest sighting, so the hit leaves the shadow half
    on the sweep and not on the approval.
    """
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    maker = make_sessionmaker(engine)
    spec = _spec()

    async def fake_run_spec(spec_arg, *, since, **_kwargs):  # type: ignore[no-untyped-def]
        return _run(spec_arg)

    with patch.object(sweep_mod, "run_spec", fake_run_spec):
        async with maker() as session:
            await sweep_mod.sweep_spec(
                spec,
                elastic=None,
                settings=settings_kratos,
                session=session,
                since="now-24h",
                until="now",
                now=_NOW,
                record=True,
                backfill=False,
                include_synth=False,
                shadow_ids=frozenset({spec.id}),
            )
            born = (await session.execute(select(EntityObservation))).scalars().one()
            assert born.shadow is True
            # The analyst approved the analytic. It leaves the shadow set.
            lead = Lead(status="open", entities_json=[["host", born.entity_key]], kinds_json=[])
            lead.shadow = True
            session.add(lead)
            await session.flush()
            born.lead_id = lead.id
            await session.commit()
            lead_id = int(lead.id)

            await sweep_mod.sweep_spec(
                spec,
                elastic=None,
                settings=settings_kratos,
                session=session,
                since="now-24h",
                until="now",
                now=_NOW,
                record=True,
                backfill=False,
                include_synth=False,
            )
            rows = (await session.execute(select(EntityObservation))).scalars().all()
            after = await session.get(Lead, lead_id)
            shadow_now = bool(after.shadow)
    await engine.dispose()

    assert len(rows) == 1, "the sweep refreshes the row it wrote, it does not add one"
    assert rows[0].shadow is False
    assert rows[0].occurrences == 1, "the same documents on both sweeps are one sighting"
    assert shadow_now is False, "the lead reads its mark back from its observations"


async def test_the_trail_keeps_the_run_duration_on_the_seeing_path(
    settings_kratos: Settings,
) -> None:
    # The gated run is rebuilt field by field after the gate. The duration
    # was lost in the rebuild, and every trail row read 0 ms.
    from soc_ai.store.models import HuntSpecSweep

    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    maker = make_sessionmaker(engine)
    spec = _spec()

    async def slow_run_spec(*_args, **_kwargs):  # type: ignore[no-untyped-def]
        import asyncio

        await asyncio.sleep(0.02)
        return _run(spec)

    with patch.object(sweep_mod, "run_spec", slow_run_spec):
        async with maker() as session:
            await sweep_mod.sweep_catalog(
                {spec.id: spec},
                session=session,
                elastic=None,
                settings=settings_kratos,
                since="now-24h",
                until="now",
                now=_NOW,
            )
            rows = (await session.execute(select(HuntSpecSweep))).scalars().all()
    assert rows and rows[-1].duration_ms >= 10
