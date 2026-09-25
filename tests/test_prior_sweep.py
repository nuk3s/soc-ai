"""The prior sweep: running every role prior against every profiled entity.

Two behaviours here are planted against defects that were actually written.

The role reader used ``getattr(row, "override_value", None)`` — the column is
``operator_value`` — so every operator declaration silently read as "nobody has
declared a role", on every host, forever. The tests read a declared role back.

And the recent window must differ from the baseline window. Run over the same
thirty days, every observation is by construction already in the baseline built
from it, and the sweep returns clean no matter what happened.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from soc_ai.config import Settings
from soc_ai.hunting.prior_sweep import DEFAULT_RECENT_HOURS, run_prior_sweep
from soc_ai.hunting.priors import COVERAGE_BLIND, COVERAGE_MEASURED
from soc_ai.hunting.spec import HuntSpec
from soc_ai.so_client.elastic import EsSearchResult
from soc_ai.store import entity_profiles as ep
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import HostDossier, HostDossierField

pytestmark = pytest.mark.asyncio

_SWITCH = "10.1.10.254"


def _settings_like(settings: Settings) -> Any:
    class _S:
        events_index_pattern = "logs-*"
        so_timezone = "UTC"

    return _S()


async def _db(settings: Settings):  # type: ignore[no-untyped-def]
    engine = make_engine(settings)
    await run_migrations(engine)
    return engine, make_sessionmaker(engine)


def _doc_ids(member: str) -> list[str]:
    """The ids a top_hits sample returns for one member of a dimension."""
    return [f"doc-{member}-{n}" for n in (1, 2, 3)]


def _sample_hits(ids: Sequence[str]) -> dict[str, Any]:
    """The shape Elasticsearch returns for a top_hits sub-aggregation."""
    return {"hits": {"hits": [{"_index": "logs-x", "_id": i} for i in ids]}}


class _FakeES:
    """Answers the plane probe as healthy and returns canned recent members."""

    def __init__(
        self,
        recent: dict[str, dict[str, int]] | None = None,
        *,
        peers: int = 2,
        days: int = 2,
        salt: str = "",
    ) -> None:
        self.recent = recent or {}
        # Every member reports this many distinct peers and active days. Two
        # each by default, so a member counts as a served port unless a test
        # says otherwise.
        self.peers = peers
        self.days = days
        # Appended to every sampled document id. A second fake with a
        # different salt is a sweep that saw different documents.
        self.salt = salt
        self.windows: list[Any] = []
        # (agg keys, query) of every read that is not the plane probe.
        self.reads: list[tuple[set[str], dict[str, Any]]] = []
        # The aggregation body of every read that is not the plane probe. A
        # test that only reads the query cannot tell whether the sweep asked
        # for document ids at all.
        self.aggs: list[dict[str, Any]] = []

    def _stamps(self) -> dict[str, Any]:
        """``first`` and ``last`` that span ``self.days`` calendar dates.

        The reader derives the day count from these two stamps. Fewer than
        one day means no stamps at all, which the reader reads as zero.
        """
        if self.days < 1:
            return {}
        last = datetime.now(UTC)
        first = last - timedelta(days=self.days - 1)
        return {
            "first": {"value_as_string": first.isoformat()},
            "last": {"value_as_string": last.isoformat()},
        }

    def _buckets(self) -> list[dict[str, Any]]:
        return [
            {
                "key": entity,
                "doc_count": sum(members.values()),
                "members": {
                    "buckets": [
                        {
                            "key": m,
                            "doc_count": c,
                            "samples": _sample_hits([f"{i}{self.salt}" for i in _doc_ids(m)]),
                            "peers": {"value": self.peers},
                            **self._stamps(),
                        }
                        for m, c in members.items()
                    ]
                },
            }
            for entity, members in self.recent.items()
        ]

    async def search(
        self,
        index: str,
        query: dict[str, Any],
        *,
        size: int = 100,
        from_: int = 0,
        sort: Any = None,
        source: Any = None,
        aggs: dict[str, Any] | None = None,
        track_total_hits: bool | None = None,
    ) -> EsSearchResult:
        keys = set(aggs or {})
        if "plane_probe" in keys:
            probe = (aggs or {})["plane_probe"]["filters"]["filters"]
            return EsSearchResult(
                total=0,
                took_ms=1,
                hits=[],
                aggregations={"plane_probe": {"buckets": {k: {"doc_count": 100} for k in probe}}},
                total_is_lower_bound=False,
            )

        self.reads.append((keys, query))
        self.aggs.append(dict(aggs or {}))
        # Record the window every recent read used, so a test can prove the
        # sweep is not asking about the same thirty days the baseline covers.
        for clause in query.get("bool", {}).get("filter", []):
            if "range" in clause and "@timestamp" in clause["range"]:
                self.windows.append(clause["range"]["@timestamp"])

        key = next(iter(keys), None)
        return EsSearchResult(
            total=0,
            took_ms=1,
            hits=[],
            aggregations={key: {"buckets": self._buckets()}} if key else {},
            total_is_lower_bound=False,
        )


class _ShapedES(_FakeES):
    """Answers a shaped read: one entity, hourly buckets, each with samples."""

    def __init__(self, entity: str, hourly: Sequence[tuple[str, int]]) -> None:
        super().__init__()
        self.entity = entity
        self.hourly = hourly

    def _buckets(self) -> list[dict[str, Any]]:
        return [
            {
                "key": self.entity,
                "doc_count": sum(count for _stamp, count in self.hourly),
                "per_hour": {
                    "buckets": [
                        {
                            "key_as_string": stamp,
                            "doc_count": count,
                            "samples": _sample_hits(_doc_ids(stamp)),
                        }
                        for stamp, count in self.hourly
                    ]
                },
            }
        ]


def _prior(**profile: Any) -> dict[str, HuntSpec]:
    block = {"dimension": "served_ports", "test": "novel_for", "roles": ["network_device"]}
    block.update(profile)
    return {
        "prior-under-test": HuntSpec.model_validate(
            {
                "id": "prior-under-test",
                "title": "A prior under test",
                "evaluator": "profile",
                "profile": block,
                "scope_field": "host.name",
                "false_positives": ["something"],
            }
        )
    }


async def _seed_host(maker: Any, *, role: str | None, operator: bool, confidence: float) -> None:
    async with maker() as db:
        host = HostDossier(host_key=_SWITCH, ip=_SWITCH)
        db.add(host)
        await db.flush()
        row = HostDossierField(dossier_id=host.id, field="role")
        if operator:
            row.operator_value = role
            row.operator_set_at = datetime.now(UTC).replace(tzinfo=None)
        else:
            row.inferred_value = role
            row.inferred_confidence = confidence
        db.add(row)
        await db.commit()


async def _seed_profile(
    maker: Any,
    *,
    vector: Any,
    coverage: str = "measured",
    dimension: str = "served_ports",
) -> None:
    async with maker() as db:
        await ep.upsert_profile(
            db,
            entity_kind="host",
            entity_key=_SWITCH,
            dimension=dimension,
            shape="categorical",
            vector=vector,
            coverage=coverage,
            support_days=30,
        )


async def test_an_operator_declared_role_is_read_and_trusted(
    settings_kratos: Settings,
) -> None:
    # The planted defect: getattr(row, "override_value", None) against a column
    # actually named operator_value. It failed silently and made every declared
    # host blind, which is the exact opposite of what declaring one is for.
    engine, maker = await _db(settings_kratos)
    await _seed_host(maker, role="network_device", operator=True, confidence=0.0)
    await _seed_profile(maker, vector={"22": {"count": 40}})

    es = _FakeES(recent={_SWITCH: {"445": 3}})
    async with maker() as db:
        sweep = await run_prior_sweep(
            elastic=es, settings=_settings_like(settings_kratos), db=db, catalog=_prior()
        )

    assert len(sweep.fired) == 1
    assert sweep.fired[0].coverage == COVERAGE_MEASURED
    assert [d.member for d in sweep.fired[0].departures] == ["445"]
    await engine.dispose()


async def test_a_low_confidence_inferred_role_is_blind(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    await _seed_host(maker, role="network_device", operator=False, confidence=0.5)
    await _seed_profile(maker, vector={"22": {"count": 40}})

    es = _FakeES(recent={_SWITCH: {"445": 3}})
    async with maker() as db:
        sweep = await run_prior_sweep(
            elastic=es, settings=_settings_like(settings_kratos), db=db, catalog=_prior()
        )

    assert sweep.fired == ()
    assert sweep.results[0].coverage == COVERAGE_BLIND
    await engine.dispose()


async def test_a_retracted_role_is_not_a_belief(settings_kratos: Settings) -> None:
    # The sweep retracts a fact when its evidence stops arriving. Scoring
    # against a role the dossier has already given up on is scoring against
    # something nothing currently supports.
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        host = HostDossier(host_key=_SWITCH, ip=_SWITCH)
        db.add(host)
        await db.flush()
        db.add(
            HostDossierField(
                dossier_id=host.id,
                field="role",
                inferred_value="network_device",
                inferred_confidence=0.9,
                inferred_retracted_at=datetime.now(UTC).replace(tzinfo=None),
            )
        )
        await db.commit()
    await _seed_profile(maker, vector={"22": {"count": 40}})

    es = _FakeES(recent={_SWITCH: {"445": 3}})
    async with maker() as db:
        sweep = await run_prior_sweep(
            elastic=es, settings=_settings_like(settings_kratos), db=db, catalog=_prior()
        )

    assert sweep.fired == ()
    assert sweep.results[0].coverage == COVERAGE_BLIND
    await engine.dispose()


async def test_the_recent_window_is_not_the_baseline_window(
    settings_kratos: Settings,
) -> None:
    # Run over the same thirty days, every observation is by construction
    # already in the baseline built from it, and the sweep returns clean
    # whatever happened.
    engine, maker = await _db(settings_kratos)
    await _seed_host(maker, role="network_device", operator=True, confidence=0.0)
    await _seed_profile(maker, vector={"22": {"count": 40}})

    es = _FakeES(recent={_SWITCH: {"445": 3}})
    async with maker() as db:
        await run_prior_sweep(
            elastic=es, settings=_settings_like(settings_kratos), db=db, catalog=_prior()
        )

    assert es.windows, "the sweep made no windowed read at all"
    minutes = DEFAULT_RECENT_HOURS * 60
    assert all(w.get("gte") == f"now-{minutes}m" for w in es.windows), (
        f"recent reads must use the recent window, got {es.windows}"
    )
    await engine.dispose()


async def test_an_entity_with_no_profile_is_blind_not_clean(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _db(settings_kratos)
    await _seed_host(maker, role="network_device", operator=True, confidence=0.0)
    # No profile seeded at all.

    es = _FakeES(recent={_SWITCH: {"445": 3}})
    async with maker() as db:
        sweep = await run_prior_sweep(
            elastic=es, settings=_settings_like(settings_kratos), db=db, catalog=_prior()
        )

    assert sweep.fired == ()
    assert sweep.results[0].coverage == COVERAGE_BLIND
    assert sweep.coverage_counts()[COVERAGE_BLIND] == 1
    await engine.dispose()


async def test_coverage_is_reported_alongside_findings(settings_kratos: Settings) -> None:
    # A sweep with no findings must be able to say which kind of nothing it is.
    engine, maker = await _db(settings_kratos)
    await _seed_host(maker, role="network_device", operator=True, confidence=0.0)
    await _seed_profile(maker, vector={"22": {"count": 40}, "445": {"count": 2}})

    es = _FakeES(recent={_SWITCH: {"445": 3}})
    async with maker() as db:
        sweep = await run_prior_sweep(
            elastic=es, settings=_settings_like(settings_kratos), db=db, catalog=_prior()
        )

    assert sweep.fired == ()
    assert sweep.coverage_counts()[COVERAGE_MEASURED] == 1
    await engine.dispose()


async def test_the_sweep_survives_a_grid_failure(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    await _seed_host(maker, role="network_device", operator=True, confidence=0.0)

    class _Broken(_FakeES):
        async def search(self, *a: Any, **k: Any) -> Any:
            raise RuntimeError("the grid is gone")

    async with maker() as db:
        sweep = await run_prior_sweep(
            elastic=_Broken(),
            settings=_settings_like(settings_kratos),
            db=db,
            catalog=_prior(),
        )

    assert sweep.errors
    assert sweep.fired == ()
    await engine.dispose()


async def test_the_recent_read_applies_the_same_port_bound_as_the_baseline(
    settings_kratos: Settings,
) -> None:
    """Asymmetry here is the ephemeral-port defect in reverse.

    If the baseline excludes dynamic ports and the recent read does not, every
    dynamic port surfaces as novel -- the same unbounded false-positive stream,
    arriving through the other half of the comparison.
    """
    from soc_ai.dossier.profile import EPHEMERAL_PORT_FLOOR

    engine, maker = await _db(settings_kratos)
    await _seed_host(maker, role="network_device", operator=True, confidence=0.0)
    await _seed_profile(maker, vector={"22": {"count": 40}})

    class _Recorder(_FakeES):
        def __init__(self) -> None:
            super().__init__(recent={_SWITCH: {"445": 3}})
            self.queries: list[Any] = []

        async def search(self, index: str, query: Any, **kwargs: Any) -> Any:
            self.queries.append(query)
            return await super().search(index, query, **kwargs)

    es = _Recorder()
    async with maker() as db:
        await run_prior_sweep(
            elastic=es, settings=_settings_like(settings_kratos), db=db, catalog=_prior()
        )

    bounds = [
        f["range"]["destination.port"]
        for q in es.queries
        for f in q.get("bool", {}).get("filter", [])
        if "range" in f and "destination.port" in f["range"]
    ]
    assert bounds, "the recent read applied no ephemeral-port bound"
    assert all(b["lt"] == EPHEMERAL_PORT_FLOOR for b in bounds)
    await engine.dispose()


async def test_reading_the_sweep_has_no_side_effects_by_default(
    settings_kratos: Settings,
) -> None:
    """An operator running this to see coverage must not thereby change what
    the next run concludes."""
    from soc_ai.store.models import EntityObservation
    from sqlalchemy import select

    engine, maker = await _db(settings_kratos)
    await _seed_host(maker, role="network_device", operator=True, confidence=0.0)
    await _seed_profile(maker, vector={"22": {"count": 40}})

    es = _FakeES(recent={_SWITCH: {"445": 6}})
    async with maker() as db:
        sweep = await run_prior_sweep(
            elastic=es, settings=_settings_like(settings_kratos), db=db, catalog=_prior()
        )
        rows = (await db.execute(select(EntityObservation))).scalars().all()

    assert len(sweep.fired) == 1
    assert rows == [], "reading the sweep wrote observations"
    assert sweep.leads is None
    await engine.dispose()


async def test_record_writes_observations_and_forms_leads(
    settings_kratos: Settings,
) -> None:
    from soc_ai.store.models import EntityObservation
    from sqlalchemy import select

    engine, maker = await _db(settings_kratos)
    await _seed_host(maker, role="network_device", operator=True, confidence=0.0)
    await _seed_profile(maker, vector={"22": {"count": 40}})

    es = _FakeES(recent={_SWITCH: {"445": 6}})
    async with maker() as db:
        sweep = await run_prior_sweep(
            elastic=es,
            settings=_settings_like(settings_kratos),
            db=db,
            catalog=_prior(),
            record=True,
        )
        rows = (await db.execute(select(EntityObservation))).scalars().all()

    assert len(rows) == 1
    assert rows[0].entity_key == _SWITCH
    assert sweep.leads is not None
    # One novel member alone is not two kinds, so no lead yet -- which is the
    # rule working, not a gap.
    assert sweep.leads.formed == ()
    await engine.dispose()


async def test_the_profile_state_reaches_the_trail_past_the_per_entity_read(
    settings_kratos: Settings,
) -> None:
    """The sweep reads one entity's baselines into a local on every turn of
    its loop. That local shared the name of the caller's ProfileState, so the
    trail recorded a dict of rows where it meant the freshness verdict."""
    from datetime import UTC, datetime, timedelta

    from soc_ai.hunting.prior_sweep import ProfileState
    from soc_ai.store.models import PriorSpecRun
    from sqlalchemy import select

    engine, maker = await _db(settings_kratos)
    await _seed_host(maker, role="network_device", operator=True, confidence=0.0)
    await _seed_profile(maker, vector={"22": {"count": 40}})
    built = datetime.now(UTC).replace(tzinfo=None) - timedelta(hours=26)

    es = _FakeES(recent={_SWITCH: {"445": 6}})
    async with maker() as db:
        await run_prior_sweep(
            elastic=es,
            settings=_settings_like(settings_kratos),
            db=db,
            catalog=_prior(),
            record=True,
            profiles=ProfileState(built_at=built, stale=True, reason="active_hours: refused"),
        )
        runs = (await db.execute(select(PriorSpecRun))).scalars().all()

    assert runs, "the sweep left no trail"
    assert all(r.profiles_stale is True for r in runs)
    assert all(r.profiles_built_at == built for r in runs)
    assert all(r.profiles_reason == "active_hours: refused" for r in runs)
    await engine.dispose()


async def test_a_no_baseline_prior_records_at_finding_weight(
    settings_kratos: Settings,
) -> None:
    # The kind comes from the SPEC. Read off the departure instead, every prior
    # would be equally loud and the no-baseline declaration would mean nothing.
    from soc_ai.hunting.weight import Kind
    from soc_ai.store.models import EntityObservation
    from sqlalchemy import select

    engine, maker = await _db(settings_kratos)
    await _seed_host(maker, role="network_device", operator=True, confidence=0.0)
    await _seed_profile(maker, vector={"22": {"count": 40}})

    catalog = _prior()
    spec = catalog["prior-under-test"]
    catalog["prior-under-test"] = spec.model_copy(update={"no_benign_baseline": True})

    es = _FakeES(recent={_SWITCH: {"445": 6}})
    async with maker() as db:
        sweep = await run_prior_sweep(
            elastic=es,
            settings=_settings_like(settings_kratos),
            db=db,
            catalog=catalog,
            record=True,
        )
        row = (await db.execute(select(EntityObservation))).scalars().one()

    assert row.kind == Kind.PRIOR_NO_BASELINE.value
    assert row.birth_weight == 1.0
    # ...and a finding forms a lead on its own.
    assert sweep.leads is not None
    assert len(sweep.leads.formed) == 1
    await engine.dispose()


async def test_a_shadow_profile_analytic_writes_a_shadow_observation_with_a_baseline_receipt(
    settings_kratos: Settings,
) -> None:
    """A profile analytic has no query, so its baseline is its receipt."""
    from soc_ai.store.models import EntityObservation
    from sqlalchemy import select

    engine, maker = await _db(settings_kratos)
    await _seed_host(maker, role="network_device", operator=True, confidence=0.0)
    await _seed_profile(maker, vector={"22": {"count": 40}})

    es = _FakeES(recent={_SWITCH: {"445": 6}})
    async with maker() as db:
        await run_prior_sweep(
            elastic=es,
            settings=_settings_like(settings_kratos),
            db=db,
            catalog=_prior(),
            record=True,
            shadow_ids=frozenset({"prior-under-test"}),
        )
        row = (await db.execute(select(EntityObservation))).scalars().one()

    # The source names the adapter. The shadow flag carries the status, so an
    # approval changes one field and the row still says where it came from.
    assert row.shadow is True and row.source == "profile"
    receipts = row.evidence_json["receipts"]
    assert receipts["complete"] is True and receipts["missing"] == []
    assert receipts["dry_run"] is None
    assert receipts["baseline"]["member"] == "445"
    assert receipts["matched_fields"] == ["served_ports"]
    # The document ids ride alongside the receipts. Writing them must not cost
    # the shadow hit the proof that earns its approval.
    assert row.evidence_json["sample_ids"] == _doc_ids("445")
    await engine.dispose()


async def test_the_recent_read_scopes_outbound_ports_like_the_baseline(
    settings_kratos: Settings,
) -> None:
    """An asymmetry between the two windows is the ephemeral-port defect again.

    The baseline counts outbound ports to destinations outside the estate. A
    recent read that counted internal destinations as well would report every
    one of them as a port the baseline has never held.
    """
    import ipaddress

    engine, maker = await _db(settings_kratos)
    await _seed_host(maker, role="server", operator=True, confidence=0.0)
    es = _FakeES(recent={_SWITCH: {"8220": 6}})
    async with maker() as db:
        await run_prior_sweep(
            elastic=es,
            settings=_settings_like(settings_kratos),
            db=db,
            catalog=_prior(dimension="consumed_ports", roles=["server"]),
            cidrs=[ipaddress.ip_network("10.1.0.0/16")],
        )
    await engine.dispose()

    reads = [q for keys, q in es.reads if "consumed_ports" in keys]
    assert reads, "the sweep issued no outbound port read"
    must_not = reads[0]["bool"]["must_not"]
    estate = [c for c in must_not if "terms" in c and "destination.ip" in c["terms"]]
    assert estate and estate[0]["terms"]["destination.ip"] == ["10.1.0.0/16"]
    bounds = [
        c["range"]["destination.port"]
        for c in reads[0]["bool"]["filter"]
        if "range" in c and "destination.port" in c["range"]
    ]
    assert bounds and bounds[0]["lt"] == 49152


async def test_the_recent_read_asks_for_the_documents_behind_each_member(
    settings_kratos: Settings,
) -> None:
    """A departure the analyst cannot open is a claim, not evidence.

    The range formed a lead from three profile departures and the objective
    said "no document ids recorded" against every one of them. The hunt agent
    re-queried the grid on its own and could not confirm the departure it had
    been sent to confirm.
    """
    engine, maker = await _db(settings_kratos)
    await _seed_host(maker, role="network_device", operator=True, confidence=0.0)
    await _seed_profile(maker, vector={"22": {"count": 40}})

    es = _FakeES(recent={_SWITCH: {"445": 6}})
    async with maker() as db:
        await run_prior_sweep(
            elastic=es, settings=_settings_like(settings_kratos), db=db, catalog=_prior()
        )

    bodies = [a["served_ports"] for a in es.aggs if "served_ports" in a]
    assert bodies, "the sweep made no recent read"
    samples = bodies[0]["aggs"]["members"]["aggs"]["samples"]
    assert samples == {
        "top_hits": {"size": 3, "_source": False, "sort": [{"@timestamp": {"order": "desc"}}]}
    }
    await engine.dispose()


async def test_a_recorded_departure_carries_the_documents_behind_it(
    settings_kratos: Settings,
) -> None:
    from soc_ai.store.models import EntityObservation
    from sqlalchemy import select

    engine, maker = await _db(settings_kratos)
    await _seed_host(maker, role="network_device", operator=True, confidence=0.0)
    await _seed_profile(maker, vector={"22": {"count": 40}})

    es = _FakeES(recent={_SWITCH: {"445": 6}})
    async with maker() as db:
        await run_prior_sweep(
            elastic=es,
            settings=_settings_like(settings_kratos),
            db=db,
            catalog=_prior(),
            record=True,
        )
        row = (await db.execute(select(EntityObservation))).scalars().one()

    evidence = row.evidence_json
    assert evidence["sample_ids"] == _doc_ids("445")
    # The anchor is the first of them, the same key the catalog path writes,
    # so every reader of an observation finds the documents the same way.
    assert evidence["anchor_id"] == _doc_ids("445")[0]
    assert evidence["baseline"]["member"] == "445"
    assert evidence["baseline"]["dimension"] == "served_ports"
    await engine.dispose()


async def test_a_repeat_of_the_same_departure_keeps_one_row(
    settings_kratos: Settings,
) -> None:
    """The ids are evidence, not content. The fingerprint must not read them.

    Were the ids part of the fingerprint, every sweep would sample different
    documents for the same condition and write a new row for each, and one
    beacon would outrank the network by arithmetic alone.

    And the count moves with the evidence. Two sweeps over the same documents
    are one sighting read twice. A sweep that samples a document the row has
    not cited is a second sighting.
    """
    from soc_ai.store.models import EntityObservation
    from sqlalchemy import select

    engine, maker = await _db(settings_kratos)
    await _seed_host(maker, role="network_device", operator=True, confidence=0.0)
    await _seed_profile(maker, vector={"22": {"count": 40, "peers": 3, "days": 12}})

    async with maker() as db:
        for _run in (1, 2):
            await run_prior_sweep(
                elastic=_FakeES(recent={_SWITCH: {"445": 6}}),
                settings=_settings_like(settings_kratos),
                db=db,
                catalog=_prior(),
                record=True,
            )
        rows = (await db.execute(select(EntityObservation))).scalars().all()
        assert len(rows) == 1
        assert rows[0].occurrences == 1, "the same documents were read twice, not seen twice"

        await run_prior_sweep(
            elastic=_FakeES(recent={_SWITCH: {"445": 6}}, salt="-later"),
            settings=_settings_like(settings_kratos),
            db=db,
            catalog=_prior(),
            record=True,
        )
        rows = (await db.execute(select(EntityObservation))).scalars().all()

    assert len(rows) == 1
    assert rows[0].occurrences == 2
    await engine.dispose()


async def test_the_shaped_recent_read_asks_for_the_documents_behind_each_hour(
    settings_kratos: Settings,
) -> None:
    """The shaped dimensions need the same ids, through a different bucket.

    ``active_hours`` and ``connection_rate`` read an hourly histogram rather
    than a member terms aggregation, so the sample rides on the hour.
    """
    from soc_ai.store.models import EntityObservation
    from sqlalchemy import select

    engine, maker = await _db(settings_kratos)
    await _seed_host(maker, role="network_device", operator=True, confidence=0.0)
    await _seed_profile(
        maker, vector={"9": {"count": 300}, "10": {"count": 280}}, dimension="active_hours"
    )

    stamp = "2026-09-18T03:00:00.000Z"
    es = _ShapedES(_SWITCH, [(stamp, 5)])
    async with maker() as db:
        sweep = await run_prior_sweep(
            elastic=es,
            settings=_settings_like(settings_kratos),
            db=db,
            catalog=_prior(dimension="active_hours", test="outside_active_hours"),
            record=True,
        )
        row = (await db.execute(select(EntityObservation))).scalars().one()

    bodies = [a["active_hours"] for a in es.aggs if "active_hours" in a]
    assert bodies, "the sweep made no shaped recent read"
    samples = bodies[0]["aggs"]["per_hour"]["aggs"]["samples"]
    assert samples == {
        "top_hits": {"size": 3, "_source": False, "sort": [{"@timestamp": {"order": "desc"}}]}
    }

    assert [d.member for d in sweep.fired[0].departures] == ["3"]
    assert list(sweep.fired[0].departures[0].sample_ids) == _doc_ids(stamp)
    assert row.evidence_json["sample_ids"] == _doc_ids(stamp)
    await engine.dispose()


async def test_a_dimension_spec_hands_back_the_dataset_list_not_a_string() -> None:
    """``_dimension_spec`` returns the candidate DATASETS as a tuple.

    The return type said ``tuple[str, ...]`` and a ``type: ignore`` held it
    down, so a reader takes the first member for one dataset NAME. A string
    reaching ``resolve_plane`` iterates as characters, and the plane probe then
    asks Elasticsearch about a dataset called "n".
    """
    from soc_ai.dossier.profile import FLOW_CANDIDATES
    from soc_ai.hunting.prior_sweep import _dimension_spec

    spec = _dimension_spec("served_ports")
    assert spec is not None
    candidates, probe_field, entity_field, member_field = spec
    assert candidates == FLOW_CANDIDATES
    assert all(len(c) > 1 for c in candidates), "the candidates unpacked as characters"
    assert (probe_field, entity_field, member_field) == (
        "destination.port",
        "destination.ip",
        "destination.port",
    )
    assert _dimension_spec("no-such-dimension") is None


async def test_the_plane_probe_names_every_candidate_dataset(
    settings_kratos: Settings,
) -> None:
    """The probe the sweep sends carries the dataset names it was given."""
    from soc_ai.dossier.profile import FLOW_CANDIDATES

    engine, maker = await _db(settings_kratos)
    await _seed_host(maker, role="network_device", operator=True, confidence=0.0)
    await _seed_profile(maker, vector={"22": {"count": 40}})

    class _ProbeRecorder(_FakeES):
        def __init__(self) -> None:
            super().__init__(recent={_SWITCH: {"445": 3}})
            self.probe_keys: list[str] = []

        async def search(self, index: str, query: Any, **kwargs: Any) -> Any:
            aggs = kwargs.get("aggs") or {}
            if "plane_probe" in aggs:
                self.probe_keys.extend(aggs["plane_probe"]["filters"]["filters"])
            return await super().search(index, query, **kwargs)

    es = _ProbeRecorder()
    async with maker() as db:
        await run_prior_sweep(
            elastic=es, settings=_settings_like(settings_kratos), db=db, catalog=_prior()
        )

    assert es.probe_keys, "the sweep sent no plane probe"
    assert set(es.probe_keys) == {f"{d}|destination.port" for d in FLOW_CANDIDATES}
    await engine.dispose()


async def test_the_recent_read_asks_for_peers_and_days_behind_each_served_port(
    settings_kratos: Settings,
) -> None:
    """The recent read carries the same two numbers the baseline does.

    Without them the guard reads zero peers and zero days for every member
    and nothing on a served port can ever fire.
    """
    engine, maker = await _db(settings_kratos)
    await _seed_host(maker, role="network_device", operator=True, confidence=0.0)
    await _seed_profile(maker, vector={"22": {"count": 40}})

    es = _FakeES(recent={_SWITCH: {"445": 6}})
    async with maker() as db:
        await run_prior_sweep(
            elastic=es, settings=_settings_like(settings_kratos), db=db, catalog=_prior()
        )

    bodies = [a["served_ports"] for a in es.aggs if "served_ports" in a]
    assert bodies, "the sweep made no recent read"
    member_aggs = bodies[0]["aggs"]["members"]["aggs"]
    assert member_aggs["peers"] == {"cardinality": {"field": "source.ip"}}
    assert member_aggs["first"] == {"min": {"field": "@timestamp"}}
    assert member_aggs["last"] == {"max": {"field": "@timestamp"}}
    assert "days" not in member_aggs
    await engine.dispose()


async def test_a_served_port_reached_from_one_peer_on_one_day_does_not_fire(
    settings_kratos: Settings,
) -> None:
    """The production case, end to end through the sweep."""
    engine, maker = await _db(settings_kratos)
    await _seed_host(maker, role="network_device", operator=True, confidence=0.0)
    await _seed_profile(maker, vector={"22": {"count": 40, "peers": 3, "days": 12}})

    async with maker() as db:
        quiet = await run_prior_sweep(
            elastic=_FakeES(recent={_SWITCH: {"33897": 19}}, peers=1, days=1),
            settings=_settings_like(settings_kratos),
            db=db,
            catalog=_prior(),
        )
        loud = await run_prior_sweep(
            elastic=_FakeES(recent={_SWITCH: {"33897": 19}}, peers=2, days=2),
            settings=_settings_like(settings_kratos),
            db=db,
            catalog=_prior(),
        )
    assert quiet.fired == ()
    assert [d.member for r in loud.fired for d in r.departures] == ["33897"]
    await engine.dispose()


async def test_the_recent_read_applies_the_same_direction_clauses_as_the_baseline(
    settings_kratos: Settings,
) -> None:
    """Asymmetry here is the port-bound defect again, with a new field.

    A baseline that excludes DNS mirrors and a recent read that keeps them
    makes every mirrored lookup a novel served port.
    """
    engine, maker = await _db(settings_kratos)
    await _seed_host(maker, role="network_device", operator=True, confidence=0.0)
    await _seed_profile(maker, vector={"22": {"count": 40, "peers": 3, "days": 12}})

    es = _FakeES(recent={_SWITCH: {"445": 3}})
    async with maker() as db:
        await run_prior_sweep(
            elastic=es, settings=_settings_like(settings_kratos), db=db, catalog=_prior()
        )

    reads = [q for keys, q in es.reads if "served_ports" in keys]
    assert reads, "the sweep made no recent read"
    must_not = reads[0]["bool"]["must_not"]
    assert {"term": {"network.protocol": "dns"}} in must_not
    assert {"terms": {"event.action": ["lookup_requested", "lookup_result"]}} in must_not
    assert {"terms": {"network.direction": ["egress", "outbound", "external"]}} in must_not
    # The fake answers the plane probe as healthy for every candidate, so the
    # endpoint plane is in the read and its accepted-connection clause is too.
    assert '"connection_accepted"' in json.dumps(reads[0]["bool"]["filter"])
    await engine.dispose()


async def test_a_recorded_departure_states_documents_in_the_window_it_read(
    settings_kratos: Settings,
) -> None:
    from soc_ai.store.models import EntityObservation
    from sqlalchemy import select

    engine, maker = await _db(settings_kratos)
    await _seed_host(maker, role="network_device", operator=True, confidence=0.0)
    await _seed_profile(maker, vector={"22": {"count": 40, "peers": 3, "days": 12}})

    async with maker() as db:
        await run_prior_sweep(
            elastic=_FakeES(recent={_SWITCH: {"445": 6}}),
            settings=_settings_like(settings_kratos),
            db=db,
            catalog=_prior(),
            recent_hours=6,
            record=True,
        )
        row = (await db.execute(select(EntityObservation))).scalars().one()

    assert row.summary == (
        "new served port for this host: 445. 6 documents in the last 6 h. "
        "The baseline holds 1 value over 30 days."
    )
    await engine.dispose()


async def test_the_default_window_is_the_one_the_sweep_reads() -> None:
    from soc_ai.hunting.window import DEFAULT_RECENT_HOURS as FROM_WINDOW

    assert DEFAULT_RECENT_HOURS == FROM_WINDOW == 24
