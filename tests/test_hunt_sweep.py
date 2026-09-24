"""The whole path: query, gate, record — and what must NOT be recorded.

The ordering is the part worth proving. Gate BEFORE record, so a condition
already handled never becomes a second hunt; and record what SURVIVED the gate,
so a hunt never claims four candidates while showing one.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from soc_ai.config import Settings
from soc_ai.hunting.spec import HuntSpec, load_catalog
from soc_ai.hunting.sweep import sweep_catalog, sweep_spec
from soc_ai.so_client.elastic import ElasticClient, EsSearchResult
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.hunt_spec_state import GAP_CLEAR_HOLD
from soc_ai.store.models import EntityObservation, Hunt, HuntSpecState, HuntSpecSweep
from sqlalchemy import select

pytestmark = pytest.mark.asyncio

from pathlib import Path  # noqa: E402

CATALOG = load_catalog(Path(__file__).resolve().parents[1] / "soc_ai/hunting/catalog")
DCSYNC = CATALOG["identity-4662-dcsync-nonmachine"]
NOW = datetime(2026, 9, 4, 17, 0, tzinfo=UTC).replace(tzinfo=None)
LATER = datetime(2026, 9, 5, 17, 0, tzinfo=UTC).replace(tzinfo=None)


@pytest_asyncio.fixture
async def session(settings_kratos: Settings):  # type: ignore[no-untyped-def]
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    async with make_sessionmaker(engine)() as s:
        yield s
    await engine.dispose()


def _bucket(key: str, ids: list[str]) -> dict[str, Any]:
    return {
        "key": key,
        "doc_count": len(ids),
        "first_seen": {"value_as_string": "2026-09-04T16:35:51Z"},
        "last_seen": {"value_as_string": "2026-09-04T16:35:51Z"},
        "samples": {"hits": {"hits": [{"_id": i, "_index": ".ds-sec"} for i in ids]}},
    }


def _elastic(settings: Settings, results: list[Any]) -> ElasticClient:
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=AsyncMock()):
        client = ElasticClient(settings)
    client.search = AsyncMock(side_effect=results)  # type: ignore[method-assign]
    return client


def _found(buckets: list[dict[str, Any]], undecided: int = 0) -> list[EsSearchResult]:
    """Precondition sees data, nothing is undecided, detection returns ``buckets``.

    Three results, in the order the executor asks: the DCSync spec excludes on
    ``winlog.event_data.SubjectUserName``, so it also asks how many documents
    satisfy its positive clauses without carrying that field. A spec with no
    exclusion asks twice; see ``test_hunt_execute``.
    """
    matched = sum(b["doc_count"] for b in buckets)
    return [
        EsSearchResult(total=47, took_ms=1),
        EsSearchResult(total=undecided, took_ms=1),
        # The total is DERIVED from the buckets. Hard-coded at 2 it disagreed
        # with an empty bucket list, so every "clean" case in this module was
        # really a run with two unattributable documents, and nothing noticed
        # because a run with no candidates recorded nothing whatever else it
        # held.
        EsSearchResult(total=matched, took_ms=1, aggregations={"scopes": {"buckets": buckets}}),
    ]


async def test_the_recorded_finding_keeps_which_field_the_run_found_missing(
    session, settings_kratos
) -> None:
    """The gate rebuilds the run, and the rebuilt one composes the finding.

    A field dropped there costs the analyst the only part of the sentence that
    says which clause to change: with two exclusions the finding falls back to
    naming both, which is what the fix is for.
    """
    spec = HuntSpec.model_validate(
        {
            "id": "identity-4624-two-exclusions",
            "title": "Logon by a non-machine account",
            "description": "Windows 4624 logons, machine accounts excluded.",
            "scope_field": "user.name",
            "detection": {
                "all": [{"field": "event.code", "value": "4624"}],
                "none": [
                    {
                        "field": "winlog.event_data.SubjectUserName",
                        "op": "wildcard",
                        "value": "*$",
                    },
                    {"field": "user.name", "op": "wildcard", "value": "*$"},
                ],
            },
            "precondition": {"all": [{"field": "event.code", "value": "4624"}]},
        }
    )
    results = [
        EsSearchResult(total=5422, took_ms=1),
        EsSearchResult(
            total=52,
            took_ms=1,
            aggregations={
                "missing_exclusion_field": {
                    "buckets": {
                        "winlog.event_data.SubjectUserName": {"doc_count": 0},
                        "user.name": {"doc_count": 52},
                    }
                }
            },
        ),
        EsSearchResult(total=0, took_ms=1, aggregations={"scopes": {"buckets": []}}),
    ]
    run, hunt_id = await sweep_spec(
        spec,
        session=session,
        elastic=_elastic(settings_kratos, results),
        settings=settings_kratos,
        since="a",
        until="b",
        now=NOW,
    )
    assert run.undecided_by_field == (
        ("winlog.event_data.SubjectUserName", 0),
        ("user.name", 52),
    ), "the gated rebuild dropped the breakdown"
    assert hunt_id
    (hunt,) = await _hunts(session)
    (finding,) = hunt.report["findings"]
    assert "carry no value for user.name" in finding["detail"]
    assert "SubjectUserName" not in finding["detail"], "all 52 of those documents carry that field"


async def test_a_spec_that_could_not_evaluate_its_exclusions_is_not_a_clean_sweep(
    session, settings_kratos
) -> None:
    """The defect this ordering exists for, at the level an operator sees.

    A run whose detection returns nothing while thousands of documents were
    dropped for lacking the field its exclusion reads must not record silence.
    Measured on the development range over 2026-09-05: the reconstructed 4624
    spec had 5,240 such documents, a precondition of 182 saying it could see,
    and a detection of zero.
    """
    run, hunt_id = await sweep_spec(
        DCSYNC,
        session=session,
        elastic=_elastic(settings_kratos, _found([], undecided=5240)),
        settings=settings_kratos,
        since="a",
        until="b",
        now=NOW,
    )
    assert run.undecided_docs == 5240
    assert run.clean is False
    assert hunt_id, "a run that discarded 5,240 documents recorded nothing"
    (hunt,) = await _hunts(session)
    (finding,) = hunt.report["findings"]
    assert finding["category"] == "visibility_gap"
    assert "5240 document(s)" in finding["detail"]
    assert "winlog.event_data.SubjectUserName" in finding["detail"]
    assert not run.candidates, "the gap is bookkeeping and must not render as an entity"

    # And once, not on every sweep. The condition is standing; a hunt per hour
    # is the notification flood the gap gate exists to prevent.
    _again, second = await sweep_spec(
        DCSYNC,
        session=session,
        elastic=_elastic(settings_kratos, _found([], undecided=5240)),
        settings=settings_kratos,
        since="a",
        until="b",
        now=LATER,
    )
    assert second is None
    assert len(await _hunts(session)) == 1


async def _hunts(session) -> list[Hunt]:
    return list((await session.execute(select(Hunt))).scalars())


async def _observations(session) -> list[EntityObservation]:
    """What the sweep recorded about entities. A hit lands here, not in Hunt."""
    stmt = select(EntityObservation).order_by(EntityObservation.id)
    return list((await session.execute(stmt)).scalars())


async def test_a_fresh_candidate_becomes_an_observation(session, settings_kratos) -> None:
    """A hit is an observation on its entity. It is no longer a hunt row.

    An analytic is one detection logic. A hunt is an investigation of one
    hypothesis. Recording each firing as a hunt was the inversion. The
    observation carries the evidence ids, so the lead layer can join it with
    what the profile analytics saw on the same entity.
    """
    _run, hunt_id = await sweep_spec(
        DCSYNC,
        session=session,
        elastic=_elastic(settings_kratos, _found([_bucket("localuser", ["idA", "idB"])])),
        settings=settings_kratos,
        since="a",
        until="b",
        now=NOW,
    )
    assert hunt_id is None
    assert await _hunts(session) == []
    (observation,) = await _observations(session)
    assert observation.entity_kind == "user"
    assert observation.entity_key == "localuser"
    # The analytic declares no benign population, so its hit is finding grade.
    assert observation.kind == "prior_no_baseline"
    assert observation.source == "catalog"
    assert observation.evidence_json["sample_ids"] == ["idA", "idB"]


async def test_the_same_condition_does_not_produce_a_second_observation(
    session, settings_kratos
) -> None:
    """Gate before record. Otherwise every sweep re-reports a standing condition.

    This is the negative control the design names: a handled catalog condition
    never becomes an observation.
    """
    for now in (NOW, LATER):
        await sweep_spec(
            DCSYNC,
            session=session,
            elastic=_elastic(settings_kratos, _found([_bucket("localuser", ["idA"])])),
            settings=settings_kratos,
            since="a",
            until="b",
            now=now,
        )
    (observation,) = await _observations(session)
    assert observation.occurrences == 1, "the gate let a handled condition write again"
    assert await _hunts(session) == []


async def test_only_what_survived_the_gate_is_recorded(session, settings_kratos) -> None:
    """Recording a handled condition a second time is worse than either number."""
    await sweep_spec(
        DCSYNC,
        session=session,
        elastic=_elastic(settings_kratos, _found([_bucket("known", ["id1"])])),
        settings=settings_kratos,
        since="a",
        until="b",
        now=NOW,
    )
    buckets = [_bucket("known", ["id1"]), _bucket("brandnew", ["id2"])]
    await sweep_spec(
        DCSYNC,
        session=session,
        elastic=_elastic(settings_kratos, _found(buckets)),
        settings=settings_kratos,
        since="a",
        until="b",
        now=LATER,
    )
    by_key = {o.entity_key: o for o in await _observations(session)}
    assert set(by_key) == {"known", "brandnew"}
    assert by_key["known"].occurrences == 1, "the handled condition was written again"
    assert by_key["known"].born_at == NOW


async def test_a_blind_spec_is_recorded_as_a_visibility_gap(session, settings_kratos) -> None:
    """Silence here would be the false all-clear the precondition exists to prevent."""
    _run, hunt_id = await sweep_spec(
        DCSYNC,
        session=session,
        elastic=_elastic(settings_kratos, [EsSearchResult(total=0, took_ms=1)]),
        settings=settings_kratos,
        since="a",
        until="b",
        now=NOW,
    )
    assert hunt_id
    (hunt,) = await _hunts(session)
    (finding,) = hunt.report["findings"]
    assert finding["category"] == "visibility_gap"


async def test_a_clean_spec_records_nothing(session, settings_kratos) -> None:
    """A hunt row per quiet sweep would bury the ones that matter."""
    _run, hunt_id = await sweep_spec(
        DCSYNC,
        session=session,
        elastic=_elastic(settings_kratos, _found([])),
        settings=settings_kratos,
        since="a",
        until="b",
        now=NOW,
    )
    assert hunt_id is None
    assert await _hunts(session) == []


async def test_a_backfill_seeds_state_and_records_no_hunt(session, settings_kratos) -> None:
    """Sweeping history must not fire N findings at somebody who was not watching."""
    _run, hunt_id = await sweep_spec(
        DCSYNC,
        session=session,
        elastic=_elastic(settings_kratos, _found([_bucket("localuser", ["idA"])])),
        settings=settings_kratos,
        since="a",
        until="b",
        now=NOW,
        backfill=True,
    )
    assert hunt_id is None
    assert await _hunts(session) == []
    rows = list((await session.execute(select(HuntSpecState))).scalars())
    assert [r.disposition for r in rows] == ["backfill_seed"]


async def test_after_a_backfill_the_live_condition_still_reports(session, settings_kratos) -> None:
    """End to end over the trap: seeding must not silence the real finding."""
    await sweep_spec(
        DCSYNC,
        session=session,
        elastic=_elastic(settings_kratos, _found([_bucket("localuser", ["idA"])])),
        settings=settings_kratos,
        since="a",
        until="b",
        now=NOW,
        backfill=True,
    )
    assert await _observations(session) == [], "a backfill records nothing"
    await sweep_spec(
        DCSYNC,
        session=session,
        elastic=_elastic(settings_kratos, _found([_bucket("localuser", ["idA"])])),
        settings=settings_kratos,
        since="a",
        until="b",
        now=LATER,
    )
    keys = [o.entity_key for o in await _observations(session)]
    assert keys == ["localuser"], "the backfill silenced the live finding, which is the trap"


async def test_one_spec_failing_does_not_stop_the_catalog(session, settings_kratos) -> None:
    with patch("soc_ai.hunting.sweep.run_spec", new=AsyncMock()) as runner:
        from soc_ai.hunting.execute import SpecRun

        runner.side_effect = [
            SpecRun(s.id, "a", "b", False, 1, 0, error="boom")
            if i == 0
            else SpecRun(s.id, "a", "b", False, 1, 0)
            for i, s in enumerate(s for s in CATALOG.values() if s.evaluator == "match")
        ]
        result = await sweep_catalog(
            CATALOG,
            session=session,
            elastic=_elastic(settings_kratos, []),
            settings=settings_kratos,
            since="a",
            until="b",
            now=NOW,
        )
    # Query specs only: a profile spec is answered from a stored baseline, not
    # from a search, and is skipped by sweep_catalog.
    assert len(result.ran) == len([s for s in CATALOG.values() if s.evaluator == "match"])
    assert len(result.errored) == 1


async def test_record_false_runs_everything_and_writes_no_hunt(session, settings_kratos) -> None:
    """Shadow mode: count what a spec WOULD surface before letting it spend anything."""
    _run, hunt_id = await sweep_spec(
        DCSYNC,
        session=session,
        elastic=_elastic(settings_kratos, _found([_bucket("localuser", ["idA"])])),
        settings=settings_kratos,
        since="a",
        until="b",
        now=NOW,
        record=False,
    )
    assert hunt_id is None
    assert await _hunts(session) == []


async def test_shadow_mode_does_not_spend_the_fire_once_budget(session, settings_kratos) -> None:
    """The bug this test exists for: shadow silencing the spec it is assessing.

    Shadow mode counts what a spec WOULD surface, for a week, before it is
    allowed to spend anything. A first version recorded those conditions as
    ``fired``, so the day the spec went live every one of them was already
    suppressed and it opened silent. Same trap as the backfill, different hat.
    """
    for _ in range(3):
        await sweep_spec(
            DCSYNC,
            session=session,
            elastic=_elastic(settings_kratos, _found([_bucket("localuser", ["idA"])])),
            settings=settings_kratos,
            since="a",
            until="b",
            now=NOW,
            record=False,
        )
    rows = list((await session.execute(select(HuntSpecState))).scalars())
    assert {r.disposition for r in rows} == {"backfill_seed"}

    assert await _observations(session) == [], "shadow mode recorded a live observation"
    await sweep_spec(
        DCSYNC,
        session=session,
        elastic=_elastic(settings_kratos, _found([_bucket("localuser", ["idA"])])),
        settings=settings_kratos,
        since="a",
        until="b",
        now=LATER,
    )
    keys = [o.entity_key for o in await _observations(session)]
    assert keys == ["localuser"], "a week of shadow mode silenced the spec on its first live run"


async def test_shadow_mode_still_reports_what_it_would_have_surfaced(
    session, settings_kratos
) -> None:
    """Counting is the whole point; a shadow run that returns nothing measures nothing."""
    run, hunt_id = await sweep_spec(
        DCSYNC,
        session=session,
        elastic=_elastic(settings_kratos, _found([_bucket("localuser", ["idA"])])),
        settings=settings_kratos,
        since="a",
        until="b",
        now=NOW,
        record=False,
    )
    assert hunt_id is None
    assert [c.scope_key for c in run.candidates] == ["localuser"]


async def test_a_new_low_volume_scope_is_not_starved_by_noisy_ones(
    session, settings_kratos
) -> None:
    """THE starvation bug. top_k used to cut in the query, upstream of the gate.

    Sweep 1 fires on the noisiest scopes and records them terminal. Sweep 2
    returns those same scopes plus a new one ranked below them. With the cut in
    the aggregation, the new scope was dropped before the gate ever saw it — no
    state row, no finding, invisible forever. Both catalog identity specs
    document exactly this shape: a recurring high-volume benign scope alongside
    a one-document signal.
    """
    noisy = [_bucket(f"svc{i:02d}", ["x"] * 50) for i in range(10)]
    await sweep_spec(
        DCSYNC,
        session=session,
        elastic=_elastic(settings_kratos, _found(noisy)),
        settings=settings_kratos,
        since="a",
        until="b",
        now=NOW,
    )
    await sweep_spec(
        DCSYNC,
        session=session,
        elastic=_elastic(settings_kratos, _found([*noisy, _bucket("attacker", ["idNEW"])])),
        settings=settings_kratos,
        since="a",
        until="b",
        now=LATER,
    )
    keys = [o.entity_key for o in await _observations(session)]
    assert "attacker" in keys, "the new low-volume scope was starved by already-fired noisy ones"


async def test_a_permanently_blind_spec_reports_once_not_every_sweep(
    session, settings_kratos
) -> None:
    """A deployment without OpenCanary is blind on that spec forever, by construction.

    The blind path used to return before the gate, so every sweep recorded
    another hunt — and every hunt is another notification-bell entry, evicting
    the real ones.
    """
    for i in range(5):
        await sweep_spec(
            DCSYNC,
            session=session,
            elastic=_elastic(settings_kratos, [EsSearchResult(total=0, took_ms=1)]),
            settings=settings_kratos,
            since="a",
            until="b",
            now=NOW if i == 0 else LATER,
        )
    assert len(await _hunts(session)) == 1, "a blind spec re-reported on every sweep"


async def test_a_backfill_does_not_record_a_hunt_for_a_blind_spec(session, settings_kratos) -> None:
    """The early return also skipped the backfill guard, contradicting the contract."""
    _run, hunt_id = await sweep_spec(
        DCSYNC,
        session=session,
        elastic=_elastic(settings_kratos, [EsSearchResult(total=0, took_ms=1)]),
        settings=settings_kratos,
        since="a",
        until="b",
        now=NOW,
        backfill=True,
    )
    assert hunt_id is None
    assert await _hunts(session) == []


async def test_the_sweep_reports_how_many_conditions_it_held_back(session, settings_kratos) -> None:
    """A second sweep over a standing condition must SAY it held it back.

    Reporting zero would read as "there was nothing there", which is a different
    and wrong fact — the whole point of the gate is that something IS there and
    has already been shown.
    """
    for now in (NOW, LATER):
        result = await sweep_catalog(
            {DCSYNC.id: DCSYNC},
            session=session,
            elastic=_elastic(settings_kratos, _found([_bucket("localuser", ["idA"])])),
            settings=settings_kratos,
            since="a",
            until="b",
            now=now,
        )
    assert result.fresh_candidates == 0
    assert result.already_handled == 1, "the sweep silently reported nothing held back"


async def test_each_spec_commits_rather_than_holding_the_write_lock(
    session, settings_kratos
) -> None:
    """SQLite has ONE write lock, and this sweep used to hold it across ES calls.

    `apply_gate` and `link_hunt` stage row mutations without committing. The next
    spec's SELECT autoflushes them, taking the write lock — which was then held
    across that spec's Elasticsearch round-trips and every remaining spec's.
    With ES slow or hanging (the case this loop exists to survive) that is
    minutes, and `busy_timeout` is five seconds, so every other writer in the
    process fails with "database is locked".
    """
    commits = {"n": 0}
    real_commit = session.commit

    async def _counting_commit() -> None:
        commits["n"] += 1
        await real_commit()

    session.commit = _counting_commit  # type: ignore[method-assign]

    catalog = {s.id: s for s in list(CATALOG.values())[:2]}
    with patch("soc_ai.hunting.sweep.run_spec", new=AsyncMock()) as runner:
        from soc_ai.hunting.execute import SpecRun

        runner.side_effect = [SpecRun(s.id, "a", "b", False, 1, 0) for s in catalog.values()]
        await sweep_catalog(
            catalog,
            session=session,
            elastic=_elastic(settings_kratos, []),
            settings=settings_kratos,
            since="a",
            until="b",
            now=NOW,
        )
    assert commits["n"] >= len(catalog), (
        "the sweep did not commit per spec, so pending writes hold the lock "
        "across the next spec's Elasticsearch calls"
    )


async def test_a_database_error_on_one_spec_rolls_back_and_continues(
    session, settings_kratos
) -> None:
    """One spec's DB failure must not poison the next one's flush or end the sweep."""
    catalog = {s.id: s for s in list(CATALOG.values())[:2]}
    with (
        patch("soc_ai.hunting.sweep.run_spec", new=AsyncMock()) as runner,
        patch("soc_ai.hunting.sweep.apply_gate", new=AsyncMock()) as gate,
    ):
        from soc_ai.hunting.execute import SpecRun

        runner.side_effect = [SpecRun(s.id, "a", "b", False, 1, 0) for s in catalog.values()]
        gate.side_effect = [RuntimeError("database is locked"), _gate_ok()]
        result = await sweep_catalog(
            catalog,
            session=session,
            elastic=_elastic(settings_kratos, []),
            settings=settings_kratos,
            since="a",
            until="b",
            now=NOW,
        )
    assert len(result.ran) == 2, "the sweep stopped at the first database error"
    assert len(result.errored) == 1
    assert "locked" in next(iter(result.errored.values()))


def _gate_ok():  # type: ignore[no-untyped-def]
    from soc_ai.store.hunt_spec_state import GateDecision

    return GateDecision(fresh=[], already_handled=[], over_budget=[], seeded=[])


async def test_a_newly_blind_spec_is_counted_separately_from_a_known_blind_one(
    session, settings_kratos
) -> None:
    """`len(blind)` counts both; the transition is what an operator needs.

    A deployment without OpenCanary is blind on that spec forever. Reporting the
    same count every sweep makes "this has always been dark" indistinguishable
    from "this just went dark", which is the only one worth waking up for.
    """
    blind_es = [EsSearchResult(total=0, took_ms=1)]
    first = await sweep_catalog(
        {DCSYNC.id: DCSYNC},
        session=session,
        elastic=_elastic(settings_kratos, blind_es),
        settings=settings_kratos,
        since="a",
        until="b",
        now=NOW,
    )
    assert first.blind == [DCSYNC.id]
    assert first.blind_reported == 1, "the first time a spec goes blind must be reported"

    second = await sweep_catalog(
        {DCSYNC.id: DCSYNC},
        session=session,
        elastic=_elastic(settings_kratos, blind_es),
        settings=settings_kratos,
        since="a",
        until="b",
        now=LATER,
    )
    assert second.blind == [DCSYNC.id], "it is still blind"
    assert second.blind_reported == 0, "but it is not news the second time"


async def test_a_gap_that_clears_and_comes_back_is_reported_a_second_time(
    session, settings_kratos
) -> None:
    """Blind, seeing, blind. The gap path always documented this and never did it.

    The gate had no way to retire a terminal row, so the first gap a spec
    recorded was the only one it could ever record. A deployment that logged a
    gap for a spec since fixed had already spent the report it would need the
    day that plane genuinely died.
    """
    blind_es = [EsSearchResult(total=0, took_ms=1)]
    dark = await sweep_catalog(
        {DCSYNC.id: DCSYNC},
        session=session,
        elastic=_elastic(settings_kratos, blind_es),
        settings=settings_kratos,
        since="a",
        until="b",
        now=NOW,
    )
    assert dark.blind_reported == 1

    # The plane comes back. A clean sweep is what proves the spec can see.
    await sweep_catalog(
        {DCSYNC.id: DCSYNC},
        session=session,
        elastic=_elastic(settings_kratos, _found([])),
        settings=settings_kratos,
        since="a",
        until="b",
        now=NOW + GAP_CLEAR_HOLD,
    )

    dark_again = await sweep_catalog(
        {DCSYNC.id: DCSYNC},
        session=session,
        elastic=_elastic(settings_kratos, blind_es),
        settings=settings_kratos,
        since="a",
        until="b",
        now=NOW + GAP_CLEAR_HOLD + GAP_CLEAR_HOLD,
    )
    assert dark_again.blind_reported == 1, "a spec going dark a second time said nothing"
    assert len(await _hunts(session)) == 2


async def test_the_sweep_that_ends_an_outage_reports_that_it_did(session, settings_kratos) -> None:
    """The other half of ``blind_reported``, and it reported nothing at all.

    Going dark is loud: the gap records a hunt, which reaches the notification
    bell and the hunts list. Coming back set ``retired_at`` inside the gate and
    returned to nobody, so the sweep that ended an outage produced a report
    byte for byte identical to the hundred sweeps before the outage started.
    The only evidence of a recovery was the blind marker no longer being on the
    catalog row — an absence, read by whoever remembered it had been there.
    """
    blind_es = [EsSearchResult(total=0, took_ms=1)]
    dark = await sweep_catalog(
        {DCSYNC.id: DCSYNC},
        session=session,
        elastic=_elastic(settings_kratos, blind_es),
        settings=settings_kratos,
        since="a",
        until="b",
        now=NOW,
    )
    assert dark.blind_reported == 1
    assert dark.gaps_cleared == 0, "going dark is not a recovery"

    recovered = await sweep_catalog(
        {DCSYNC.id: DCSYNC},
        session=session,
        elastic=_elastic(settings_kratos, _found([])),
        settings=settings_kratos,
        since="a",
        until="b",
        now=LATER,
    )
    assert recovered.gaps_cleared == 1
    # Nothing else on the report moved. This is the whole defect: without the
    # field, the sweep that ended the outage and a sweep on a spec that was
    # never blind produce the same object.
    assert recovered.blind == [] and recovered.hunts == {}
    assert recovered.fresh_candidates == 0
    assert recovered.to_dict()["gaps_cleared"] == 1, "the CLI prints to_dict()"


async def test_an_ordinary_clean_sweep_reports_no_recovery(session, settings_kratos) -> None:
    """NEGATIVE CONTROL. A spec that was never blind clears nothing.

    Without this the field would be a decoration that fires on every clean
    sweep, which is the same as not having it: an operator cannot read "the
    outage ended" out of a number that is 1 every hour forever.
    """
    first = await sweep_catalog(
        {DCSYNC.id: DCSYNC},
        session=session,
        elastic=_elastic(settings_kratos, _found([])),
        settings=settings_kratos,
        since="a",
        until="b",
        now=NOW,
    )
    second = await sweep_catalog(
        {DCSYNC.id: DCSYNC},
        session=session,
        elastic=_elastic(settings_kratos, _found([])),
        settings=settings_kratos,
        since="a",
        until="b",
        now=LATER,
    )
    assert (first.gaps_cleared, second.gaps_cleared) == (0, 0)


async def test_a_recovery_is_reported_once_not_on_every_sweep_after(
    session, settings_kratos
) -> None:
    """The report is the TRANSITION, like ``blind_reported`` is.

    The retirement is a one-way column write, so the second clean sweep finds
    nothing left to retire. If it did not, a spec that recovered in March would
    still be announcing its recovery in June and the line would be noise.
    """
    blind_es = [EsSearchResult(total=0, took_ms=1)]
    await sweep_catalog(
        {DCSYNC.id: DCSYNC},
        session=session,
        elastic=_elastic(settings_kratos, blind_es),
        settings=settings_kratos,
        since="a",
        until="b",
        now=NOW,
    )
    first_clean = await sweep_catalog(
        {DCSYNC.id: DCSYNC},
        session=session,
        elastic=_elastic(settings_kratos, _found([])),
        settings=settings_kratos,
        since="a",
        until="b",
        now=LATER,
    )
    second_clean = await sweep_catalog(
        {DCSYNC.id: DCSYNC},
        session=session,
        elastic=_elastic(settings_kratos, _found([])),
        settings=settings_kratos,
        since="a",
        until="b",
        now=LATER + (LATER - NOW),
    )
    assert first_clean.gaps_cleared == 1
    assert second_clean.gaps_cleared == 0, "a recovery announced forever is noise"


async def test_a_shadow_sweep_reports_no_recovery(session, settings_kratos) -> None:
    """NEGATIVE CONTROL, and the one that matters most.

    Shadow leaves the gate exactly as it found it: it retires nothing, so it
    must claim nothing. A shadow sweep reporting "the outage ended" while the
    gap is still open would be the false all-clear the gap exists to prevent,
    told by the mode whose whole promise is that it changes nothing.
    """
    blind_es = [EsSearchResult(total=0, took_ms=1)]
    await sweep_catalog(
        {DCSYNC.id: DCSYNC},
        session=session,
        elastic=_elastic(settings_kratos, blind_es),
        settings=settings_kratos,
        since="a",
        until="b",
        now=NOW,
    )
    shadow = await sweep_catalog(
        {DCSYNC.id: DCSYNC},
        session=session,
        elastic=_elastic(settings_kratos, _found([])),
        settings=settings_kratos,
        since="a",
        until="b",
        now=LATER,
        record=False,
    )
    assert shadow.gaps_cleared == 0, "shadow retires nothing, so it reports nothing"
    # And the gap really is still open: the next LIVE clean sweep is the one
    # that gets to say so.
    live = await sweep_catalog(
        {DCSYNC.id: DCSYNC},
        session=session,
        elastic=_elastic(settings_kratos, _found([])),
        settings=settings_kratos,
        since="a",
        until="b",
        now=LATER + (LATER - NOW),
    )
    assert live.gaps_cleared == 1


async def test_a_spec_that_stopped_being_blind_and_started_discarding_is_not_a_recovery(
    session, settings_kratos
) -> None:
    """An unclean run passes a gap candidate, so the gate retires nothing.

    This is the case that would make the field a lie. The precondition matches
    again, so ``blind`` is False and the row stops wearing the blind marker —
    but the detection now cannot evaluate its exclusions, which rides the same
    gap scope. Coverage did not come back; it changed shape.
    """
    blind_es = [EsSearchResult(total=0, took_ms=1)]
    await sweep_catalog(
        {DCSYNC.id: DCSYNC},
        session=session,
        elastic=_elastic(settings_kratos, blind_es),
        settings=settings_kratos,
        since="a",
        until="b",
        now=NOW,
    )
    unclean = await sweep_catalog(
        {DCSYNC.id: DCSYNC},
        session=session,
        elastic=_elastic(settings_kratos, _found([], undecided=5240)),
        settings=settings_kratos,
        since="a",
        until="b",
        now=LATER,
    )
    assert unclean.blind == [], "the precondition matched, so it is not blind"
    assert unclean.undecided_docs == 5240
    assert unclean.gaps_cleared == 0, "coverage changed shape; it did not come back"


async def test_a_shadow_sweep_does_not_re_arm_a_visibility_gap(session, settings_kratos) -> None:
    """NEGATIVE CONTROL. Shadow leaves the gate exactly as it found it.

    Spending the fire-once budget in shadow would silence a spec under
    assessment; handing it back would make the next live sweep re-report a gap
    the operator has already read. Both are the same rule.
    """
    blind_es = [EsSearchResult(total=0, took_ms=1)]
    await sweep_catalog(
        {DCSYNC.id: DCSYNC},
        session=session,
        elastic=_elastic(settings_kratos, blind_es),
        settings=settings_kratos,
        since="a",
        until="b",
        now=NOW,
    )

    await sweep_catalog(
        {DCSYNC.id: DCSYNC},
        session=session,
        elastic=_elastic(settings_kratos, _found([])),
        settings=settings_kratos,
        since="a",
        until="b",
        now=NOW + GAP_CLEAR_HOLD,
        record=False,
    )

    after = await sweep_catalog(
        {DCSYNC.id: DCSYNC},
        session=session,
        elastic=_elastic(settings_kratos, blind_es),
        settings=settings_kratos,
        since="a",
        until="b",
        now=NOW + GAP_CLEAR_HOLD + GAP_CLEAR_HOLD,
    )
    assert after.blind_reported == 0, "a shadow sweep cleared a live gap"
    assert len(await _hunts(session)) == 1


async def test_a_spec_blind_all_week_reports_once(session, settings_kratos) -> None:
    """NEGATIVE CONTROL. Retirement must not turn fire-once into fire-hourly.

    A deployment without OpenCanary is blind on that spec forever by
    construction, so this is the normal case rather than an edge, and it is the
    case that once produced twenty-four hunts a day and evicted the real ones
    from the bell.
    """
    for hour in range(168):
        await sweep_catalog(
            {DCSYNC.id: DCSYNC},
            session=session,
            elastic=_elastic(settings_kratos, [EsSearchResult(total=0, took_ms=1)]),
            settings=settings_kratos,
            since="a",
            until="b",
            now=NOW + timedelta(hours=hour),
        )
    assert len(await _hunts(session)) == 1, "a permanently blind spec re-reported"


# ---------------------------------------------------------------------------
# The sweep trail (#56): every spec leaves a row on every sweep, clean or not
# ---------------------------------------------------------------------------


async def _trail(session) -> list[HuntSpecSweep]:
    return list((await session.execute(select(HuntSpecSweep).order_by(HuntSpecSweep.id))).scalars())


async def _catalog_sweep(session, settings, elastic, **kw):  # type: ignore[no-untyped-def]
    return await sweep_catalog(
        {DCSYNC.id: DCSYNC},
        session=session,
        elastic=elastic,
        settings=settings,
        since="a",
        until="b",
        now=NOW,
        **kw,
    )


async def test_a_clean_sweep_leaves_a_row(session, settings_kratos) -> None:
    """The point of the table. `test_a_clean_spec_records_nothing` holds that a
    quiet sweep writes no HUNT; this holds that it still writes its trail, so
    "ran and saw nothing" is a fact rather than an absence."""
    await _catalog_sweep(session, settings_kratos, _elastic(settings_kratos, _found([])))
    (row,) = await _trail(session)
    assert row.spec_id == DCSYNC.id
    assert row.blind is False
    assert row.error is None
    assert row.shadow is False
    assert row.hunt_id is None
    assert row.fresh_candidates == 0
    assert row.precondition_docs == 47
    assert row.created_at == NOW
    assert (row.window_since, row.window_until) == ("a", "b")


async def test_a_firing_sweep_counts_what_it_recorded(session, settings_kratos) -> None:
    """A hit writes an observation, so the trail row points at no hunt.

    The gap path still links its row to the hunt it recorded. See
    ``test_a_blind_sweep_writes_a_blind_row``.
    """
    result = await _catalog_sweep(
        session, settings_kratos, _elastic(settings_kratos, _found([_bucket("localuser", ["idA"])]))
    )
    (row,) = await _trail(session)
    assert result.hunts == {}
    assert row.hunt_id is None
    assert row.fresh_candidates == 1
    assert [o.entity_key for o in await _observations(session)] == ["localuser"]


async def test_a_shadow_sweep_writes_a_shadow_row(session, settings_kratos) -> None:
    """Shadow spends nothing, and the row must say so: a clean live sweep has no
    hunt either, and the two differ in exactly whether the budget was spent."""
    await _catalog_sweep(
        session,
        settings_kratos,
        _elastic(settings_kratos, _found([_bucket("localuser", ["idA"])])),
        record=False,
    )
    (row,) = await _trail(session)
    assert row.shadow is True
    assert row.hunt_id is None
    assert row.fresh_candidates == 1, "shadow still counts what it WOULD have surfaced"


async def test_a_backfill_sweep_writes_a_shadow_row(session, settings_kratos) -> None:
    """A backfill seeds the gate and records no hunt, so by the model's own
    definition of ``shadow`` — was the fire-once budget spent — its row is a
    shadow row. Written as live, ``fresh > 0`` with no hunt is a state no live
    sweep can produce (fresh always records), and the catalog page read it as
    "the loop found N and recorded nothing" right after the seeding step the
    docs tell an operator to run."""
    await _catalog_sweep(
        session,
        settings_kratos,
        _elastic(settings_kratos, _found([_bucket("localuser", ["idA"])])),
        backfill=True,
    )
    (row,) = await _trail(session)
    assert row.shadow is True
    assert row.hunt_id is None
    assert row.fresh_candidates == 1, "a backfill still counts what it seeded"


async def test_a_backfill_that_errors_still_writes_a_shadow_row(session, settings_kratos) -> None:
    """The except branch has its own trail write; it must agree with the happy path."""
    with patch("soc_ai.hunting.sweep.apply_gate", new=AsyncMock()) as gate:
        gate.side_effect = RuntimeError("database is locked")
        await _catalog_sweep(
            session,
            settings_kratos,
            _elastic(settings_kratos, _found([_bucket("localuser", ["idA"])])),
            backfill=True,
        )
    (row,) = await _trail(session)
    assert row.error is not None
    assert row.shadow is True


async def test_a_backfill_is_a_sweep_but_never_a_firing(session, settings_kratos) -> None:
    """Through ``catalog_status``: the loop ran, so the backfill counts as a
    sweep and its seeded count reaches ``fresh_24h``, but it fired nothing.
    ``fired_24h`` already needs a hunt id, so this pins the contract rather
    than discriminating the fix; the row test above is the one that fails
    against ``shadow=not record``."""
    from soc_ai.store.hunt_spec_sweeps import catalog_status

    await _catalog_sweep(
        session,
        settings_kratos,
        _elastic(settings_kratos, _found([_bucket("localuser", ["idA"])])),
        backfill=True,
    )
    s = (await catalog_status(session, now=NOW))[DCSYNC.id]
    assert s.sweeps_24h == 1
    assert s.fresh_24h == 1
    assert s.fired_24h == 0
    assert s.last_fired_at is None


async def test_a_blind_sweep_writes_a_blind_row(session, settings_kratos) -> None:
    result = await _catalog_sweep(
        session, settings_kratos, _elastic(settings_kratos, [EsSearchResult(total=0, took_ms=1)])
    )
    (row,) = await _trail(session)
    assert row.blind is True
    assert row.precondition_docs == 0
    assert row.hunt_id == result.hunts[DCSYNC.id], "the gap hunt is linked like any other"


async def test_a_grid_error_writes_an_errored_row(session, settings_kratos) -> None:
    from soc_ai.hunting.execute import SpecRun

    with patch("soc_ai.hunting.sweep.run_spec", new=AsyncMock()) as runner:
        runner.return_value = SpecRun(DCSYNC.id, "a", "b", False, 1, 0, error="grid down")
        await _catalog_sweep(session, settings_kratos, _elastic(settings_kratos, []))
    (row,) = await _trail(session)
    assert row.error == "grid down"
    assert row.blind is False


async def test_a_database_error_still_leaves_an_errored_row(session, settings_kratos) -> None:
    """The except branch rolls back. The row has to be written AFTER that, in
    its own transaction, or it rolls back with the failure it records."""
    from soc_ai.hunting.execute import SpecRun

    with (
        patch("soc_ai.hunting.sweep.run_spec", new=AsyncMock()) as runner,
        patch("soc_ai.hunting.sweep.apply_gate", new=AsyncMock()) as gate,
    ):
        runner.return_value = SpecRun(DCSYNC.id, "a", "b", False, 1, 0)
        gate.side_effect = RuntimeError("database is locked")
        result = await _catalog_sweep(session, settings_kratos, _elastic(settings_kratos, []))
    (row,) = await _trail(session)
    assert row.error == result.errored[DCSYNC.id]
    assert "locked" in row.error
    assert await _hunts(session) == []


async def test_every_spec_in_the_catalog_leaves_a_row(session, settings_kratos) -> None:
    from soc_ai.hunting.execute import SpecRun

    # Only the query specs are swept here; a ``profile`` spec is answered from a
    # stored baseline by run_prior_sweep and compiles to no query at all.
    query_specs = [s for s in CATALOG.values() if s.evaluator == "match"]
    with patch("soc_ai.hunting.sweep.run_spec", new=AsyncMock()) as runner:
        runner.side_effect = [
            SpecRun(s.id, "a", "b", False, 1, 0, error="boom")
            if i == 0
            else SpecRun(s.id, "a", "b", False, 1, 0)
            for i, s in enumerate(query_specs)
        ]
        await sweep_catalog(
            CATALOG,
            session=session,
            elastic=_elastic(settings_kratos, []),
            settings=settings_kratos,
            since="a",
            until="b",
            now=NOW,
        )
    rows = await _trail(session)
    assert [r.spec_id for r in rows] == [s.id for s in query_specs]
    assert [r.error for r in rows] == ["boom"] + [None] * (len(query_specs) - 1)


async def test_a_trail_write_failure_does_not_fail_the_spec(
    session, settings_kratos, caplog
) -> None:
    """The hunt is already committed when the trail is written. Failing the
    spec at that point would report a spec that FIRED as errored, which is a
    worse lie than a missing trail row — so the failure is logged, loudly."""
    with patch(
        "soc_ai.hunting.sweep.record_sweep", new=AsyncMock(side_effect=RuntimeError("disk full"))
    ):
        result = await _catalog_sweep(
            session,
            settings_kratos,
            _elastic(settings_kratos, _found([_bucket("localuser", ["idA"])])),
        )
    assert result.errored == {}
    assert [o.entity_key for o in await _observations(session)] == ["localuser"]
    assert await _trail(session) == []
    assert any(
        "disk full" in r.getMessage() or "disk full" in str(r.exc_info) for r in caplog.records
    )


async def test_a_hunt_recorded_under_a_synth_scope_is_marked_as_one(
    session, settings_kratos
) -> None:
    """The recorder contract from _synth_scope: bool(scope) says synth-eval.

    A sweep that could see planted documents must not leave an unmarked hunt
    in the operator's queue; the hunt list and the bell badge the row from
    this flag, and nothing else tells them apart from a real one.
    """
    _run, hunt_id = await sweep_spec(
        DCSYNC,
        session=session,
        elastic=_elastic(settings_kratos, _found([_bucket("localuser", ["idA"])])),
        settings=settings_kratos,
        since="a",
        until="b",
        now=NOW,
        include_synth=True,
    )
    assert hunt_id
    (hunt,) = await _hunts(session)
    assert hunt.is_synth_eval is True, "a hunt over planted data was recorded as a real one"


async def test_the_production_scope_records_an_observation_and_no_hunt(
    session, settings_kratos
) -> None:
    """The other half of the marker contract, after the hit path changed.

    A sweep of real data writes an observation and no hunt row at all, so no
    unmarked row can reach the operator's queue. The synth scope above keeps
    the old path, because an observation carries no synth marker yet.
    """
    _run, hunt_id = await sweep_spec(
        DCSYNC,
        session=session,
        elastic=_elastic(settings_kratos, _found([_bucket("localuser", ["idA"])])),
        settings=settings_kratos,
        since="a",
        until="b",
        now=NOW,
    )
    assert hunt_id is None
    assert await _hunts(session) == []
    assert [o.entity_key for o in await _observations(session)] == ["localuser"]


async def test_a_profile_spec_is_not_swept_as_a_query(session, settings_kratos) -> None:
    """A prior compiles to no query and must not leave a sweep row.

    Sweeping one calls to_query, which raises — nine errors and a non-zero exit
    from a healthy catalog. Skipping is not enough on its own either: a
    hunt_spec_sweeps row for a spec this sweep never evaluated is a claim that
    it was checked and found clean, which is the one thing the trail must never
    say.
    """
    from soc_ai.hunting.spec import CATALOG_DIR, load_catalog

    full = load_catalog(CATALOG_DIR)
    priors = [s for s in full.values() if s.evaluator == "profile"]
    assert priors, "the catalog ships no priors to test with"

    await sweep_catalog(
        {s.id: s for s in priors},
        session=session,
        elastic=_elastic(settings_kratos, []),
        settings=settings_kratos,
        since="a",
        until="b",
        now=NOW,
    )
    rows = await _trail(session)
    assert rows == [] or [r.spec_id for r in rows] == []


async def test_run_spec_refuses_a_profile_spec_without_touching_the_grid() -> None:
    """Belt and braces behind sweep_catalog's skip.

    run_spec is also reachable from `soc-ai spec-run <id>`. Every step in it
    reads spec.detection, so a prior reaching it produced
    "AttributeError: 'NoneType' object has no attribute 'exclusion_fields'" --
    which is exactly what nine priors did to a live spec-sweep on the range.

    The guard sits above the first settings read, so passing None for both
    clients proves nothing downstream is reached.
    """
    from soc_ai.hunting.execute import run_spec
    from soc_ai.hunting.spec import CATALOG_DIR, load_catalog

    priors = [s for s in load_catalog(CATALOG_DIR).values() if s.evaluator == "profile"]
    assert priors

    run = await run_spec(priors[0], elastic=None, settings=None, since="now-1h", until="now")
    assert run.error is not None
    assert "soc-ai priors" in run.error
    assert run.candidates == []


async def test_the_gap_path_returns_the_row_it_wrote(session, settings_kratos) -> None:
    """The visibility-gap row and the catalog hunt row are different rows.

    One local name carried both. The returned id must be the id of the row
    this path wrote, and the row must carry the gap finding.
    """
    _run, hunt_id = await sweep_spec(
        DCSYNC,
        session=session,
        elastic=_elastic(settings_kratos, [EsSearchResult(total=0, took_ms=1)]),
        settings=settings_kratos,
        since="a",
        until="b",
        now=NOW,
    )
    (hunt,) = await _hunts(session)
    assert hunt_id == hunt.id
    assert hunt.report["findings"][0]["category"] == "visibility_gap"
    assert hunt.is_synth_eval is False


async def test_the_synth_path_returns_the_row_it_wrote(session, settings_kratos) -> None:
    """The same check on the synthetic-evaluation path."""
    _run, hunt_id = await sweep_spec(
        DCSYNC,
        session=session,
        elastic=_elastic(settings_kratos, _found([_bucket("localuser", ["idA"])])),
        settings=settings_kratos,
        since="a",
        until="b",
        now=NOW,
        include_synth=True,
    )
    (hunt,) = await _hunts(session)
    assert hunt_id == hunt.id
    assert hunt.is_synth_eval is True
