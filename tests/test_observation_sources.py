"""Every source writes observations through one function.

The negative controls are the paths a guard would miss: a handled catalog
condition, a false-positive alert, a gap record, a finding with no host.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime

import pytest
from soc_ai.config import Settings
from soc_ai.hunting.execute import Candidate
from soc_ai.hunting.sources import (
    internal_hosts,
    observe_alert_verdict,
    observe_catalog_hits,
    observe_hunt_finding,
)
from soc_ai.hunting.spec import HuntSpec
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.hunt_spec_state import GAP_SCOPE
from soc_ai.store.models import EntityObservation, Lead
from sqlalchemy import select

pytestmark = pytest.mark.asyncio

_NOW = datetime(2026, 9, 18, 12, 0, tzinfo=UTC)


async def _db(settings: Settings):  # type: ignore[no-untyped-def]
    engine = make_engine(settings)
    await run_migrations(engine)
    return engine, make_sessionmaker(engine)


def _spec(no_baseline: bool) -> HuntSpec:
    return HuntSpec.model_validate(
        {
            "id": "t-spec",
            "title": "A test analytic fires",
            "description": "For the adapter tests.",
            "level": "high",
            "no_benign_baseline": no_baseline,
            "scope_field": "source.ip",
            "scope_kind": "host",
            "precondition": {"all": [{"field": "event.code", "value": "1"}]},
            "detection": {"all": [{"field": "event.code", "value": "1"}]},
        }
    )


def _candidate(scope_key: str, docs: int = 2) -> Candidate:
    return Candidate(
        spec_id="t-spec",
        scope_key=scope_key,
        scope_kind="host",
        doc_count=docs,
        sample_ids=("d1", "d2"),
        anchor_id="d1",
        anchor_index="logs-x",
        first_seen="2026-09-18T11:00:00Z",
        last_seen="2026-09-18T11:30:00Z",
    )


async def _rows(db):  # type: ignore[no-untyped-def]
    return (await db.execute(select(EntityObservation))).scalars().all()


# --- catalog ---------------------------------------------------------------


async def test_a_catalog_hit_becomes_a_weighted_observation(settings_kratos: Settings) -> None:
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        outcome = await observe_catalog_hits(
            db, spec=_spec(False), candidates=[_candidate("198.51.100.7")], now=_NOW
        )
        rows = await _rows(db)
    assert len(rows) == 1
    assert rows[0].kind == "catalog_match"
    assert rows[0].birth_weight == 0.7
    assert rows[0].source == "catalog"
    assert rows[0].entity_key == "198.51.100.7"
    assert rows[0].evidence_json["sample_ids"] == ["d1", "d2"]
    assert outcome.formed == ()  # one kind at 0.7 is not a lead


async def test_a_no_baseline_catalog_hit_is_finding_grade_and_forms_alone(
    settings_kratos: Settings,
) -> None:
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        outcome = await observe_catalog_hits(
            db, spec=_spec(True), candidates=[_candidate("198.51.100.7")], now=_NOW
        )
        rows = await _rows(db)
    assert rows[0].kind == "prior_no_baseline"
    assert rows[0].birth_weight == 1.0
    assert len(outcome.formed) == 1


async def test_a_gap_candidate_is_never_an_observation(settings_kratos: Settings) -> None:
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await observe_catalog_hits(
            db, spec=_spec(True), candidates=[_candidate(GAP_SCOPE)], now=_NOW
        )
        rows = await _rows(db)
    assert rows == []


async def test_a_repeated_catalog_hit_refreshes_instead_of_duplicating(
    settings_kratos: Settings,
) -> None:
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        for _ in range(2):
            await observe_catalog_hits(
                db, spec=_spec(False), candidates=[_candidate("198.51.100.7")], now=_NOW
            )
        rows = await _rows(db)
        assert len(rows) == 1
        assert rows[0].occurrences == 1, "the same two documents, read twice, are one sighting"

        later = replace(_candidate("198.51.100.7"), sample_ids=("d3",), anchor_id="d3")
        await observe_catalog_hits(db, spec=_spec(False), candidates=[later], now=_NOW)
        rows = await _rows(db)
    assert len(rows) == 1
    assert rows[0].occurrences == 2


async def test_a_catalog_hit_and_a_departure_on_one_host_form_one_lead(
    settings_kratos: Settings,
) -> None:
    # The acceptance test of the spec, at the unit level.
    from soc_ai.hunting.leads import content_fingerprint, record_observation
    from soc_ai.hunting.weight import Kind

    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await record_observation(
            db,
            entity_kind="host",
            entity_key="198.51.100.7",
            kind=Kind.OFF_HOURS,
            spec_id="profile-activity-outside-measured-hours",
            fingerprint=content_fingerprint("active_hours", "3"),
            now=_NOW,
        )
        outcome = await observe_catalog_hits(
            db, spec=_spec(False), candidates=[_candidate("198.51.100.7")], now=_NOW
        )
        leads = (await db.execute(select(Lead))).scalars().all()
    assert len(outcome.formed) == 1
    assert sorted(leads[0].kinds_json) == ["catalog_match", "off_hours"]


async def test_a_catalog_hit_records_the_hosts_the_documents_name_as_related(
    settings_kratos: Settings,
) -> None:
    # A hit scoped on an account names the machine its documents came from, so
    # the lead spans both. Without it the account and the machine hold two
    # leads about one event.
    _engine, maker = await _db(settings_kratos)
    c = replace(_candidate("localuser"), scope_kind="user", hosts=("10.1.2.11",))
    spec = _spec(True).model_copy(
        update={"scope_kind": "user", "scope_field": "winlog.event_data.SubjectUserName"}
    )
    async with maker() as db:
        await observe_catalog_hits(db, spec=spec, candidates=[c], now=_NOW)
        rows = await _rows(db)
        leads = (await db.execute(select(Lead))).scalars().all()
    assert rows[0].entity_kind == "user"
    assert rows[0].evidence_json["related"] == [["host", "10.1.2.11"]]
    assert sorted(tuple(e) for e in leads[0].entities_json) == [
        ("host", "10.1.2.11"),
        ("user", "localuser"),
    ]


async def test_every_scope_kind_records_under_a_named_entity_kind(
    settings_kratos: Settings,
) -> None:
    """The scope kind decides the entity kind, and none of them falls through.

    The lookup sat behind ``spec.scope_kind or "host"``. ``scope_kind`` is a
    Literal with no empty member, so that operand never ran. The fallback that
    does the work is the lookup's own default.
    """
    from typing import get_args

    from soc_ai.hunting.sources import _SCOPE_TO_ENTITY

    kinds = get_args(HuntSpec.model_fields["scope_kind"].annotation)
    assert set(kinds) >= {"host", "ip", "user"}
    assert "" not in kinds, "an empty scope kind would need the guard back"

    _engine, maker = await _db(settings_kratos)
    for index, kind in enumerate(kinds):
        key = f"198.51.100.{index + 1}"
        spec = _spec(False).model_copy(update={"scope_kind": kind})
        async with maker() as db:
            await observe_catalog_hits(db, spec=spec, candidates=[_candidate(key)], now=_NOW)
            written = [r for r in await _rows(db) if r.entity_key == key]
        assert len(written) == 1, kind
        assert written[0].entity_kind == _SCOPE_TO_ENTITY.get(kind, "host"), kind
        assert written[0].entity_kind in {"host", "user"}, kind


# --- alerts ----------------------------------------------------------------


async def test_internal_hosts_keeps_private_unicast_only() -> None:
    assert internal_hosts(["10.1.2.3", "8.8.8.8", "127.0.0.1", "224.0.0.251", None, ""]) == [
        "10.1.2.3"
    ]


async def test_a_true_positive_alert_is_recorded_at_full_weight_on_its_internal_host(
    settings_kratos: Settings,
) -> None:
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        outcome = await observe_alert_verdict(
            db,
            alert_id="abc123",
            rule_name="ET MALWARE Test",
            verdict="true_positive",
            confidence=0.9,
            hosts=["10.1.2.3"],
            now=_NOW,
        )
        rows = await _rows(db)
    assert len(rows) == 1
    assert rows[0].kind == "alert"
    assert rows[0].birth_weight == 1.0
    assert rows[0].source == "alert"
    assert rows[0].fingerprint == "abc123"
    assert len(outcome.formed) == 1


async def test_a_false_positive_alert_is_never_recorded(settings_kratos: Settings) -> None:
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await observe_alert_verdict(
            db,
            alert_id="abc123",
            rule_name="ET INFO Test",
            verdict="false_positive",
            confidence=0.9,
            hosts=["10.1.2.3"],
            now=_NOW,
        )
        rows = await _rows(db)
    assert rows == []


async def test_a_verdict_changed_to_false_positive_removes_the_observation(
    settings_kratos: Settings,
) -> None:
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await observe_alert_verdict(
            db,
            alert_id="abc123",
            rule_name="r",
            verdict="needs_more_info",
            confidence=0.5,
            hosts=["10.1.2.3"],
            now=_NOW,
        )
        assert len(await _rows(db)) == 1
        await observe_alert_verdict(
            db,
            alert_id="abc123",
            rule_name="r",
            verdict="false_positive",
            confidence=0.9,
            hosts=["10.1.2.3"],
            now=_NOW,
        )
        rows = await _rows(db)
    assert rows == []


async def test_an_alert_with_no_internal_host_records_nothing(
    settings_kratos: Settings,
) -> None:
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await observe_alert_verdict(
            db,
            alert_id="x",
            rule_name="r",
            verdict="true_positive",
            confidence=0.9,
            hosts=["8.8.8.8"],
            now=_NOW,
        )
        rows = await _rows(db)
    assert rows == []


# --- hunt findings ------------------------------------------------------------


async def test_a_promoted_finding_is_recorded_on_each_of_its_hosts(
    settings_kratos: Settings,
) -> None:
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await observe_hunt_finding(
            db,
            hunt_id="01HUNT",
            ordinal=2,
            finding={
                "title": "RC4 ticket for svc_sql",
                "hosts": ["10.1.2.3", "10.1.2.4"],
                "citations": ["d1"],
            },
            now=_NOW,
        )
        rows = await _rows(db)
    assert {r.entity_key for r in rows} == {"10.1.2.3", "10.1.2.4"}
    assert all(r.kind == "hunt_finding" and r.source == "hunt" for r in rows)
    assert rows[0].summary == "RC4 ticket for svc_sql"


async def test_a_finding_with_no_host_records_nothing(settings_kratos: Settings) -> None:
    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await observe_hunt_finding(
            db, hunt_id="01HUNT", ordinal=0, finding={"title": "t", "hosts": []}, now=_NOW
        )
        rows = await _rows(db)
    assert rows == []


# --- the triage store -------------------------------------------------------


async def test_finalize_records_the_alert_on_its_internal_hosts(
    settings_kratos: Settings,
) -> None:
    from soc_ai.store import investigations as inv_store

    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        inv = await inv_store.create(
            db,
            alert_es_id="es-1",
            rule_name="ET MALWARE Test",
            started_by="test",
            src_ip="10.1.2.3",
            dest_ip="203.0.113.9",
        )
        await inv_store.finalize(
            db, inv.id, status="complete", verdict="true_positive", confidence=0.9
        )
        rows = await _rows(db)
    assert [r.entity_key for r in rows] == ["10.1.2.3"]
    assert rows[0].fingerprint == "es-1"


async def test_resolve_to_false_positive_removes_the_alert_observation(
    settings_kratos: Settings,
) -> None:
    from soc_ai.store import investigations as inv_store

    _engine, maker = await _db(settings_kratos)
    async with maker() as db:
        inv = await inv_store.create(
            db, alert_es_id="es-2", rule_name="r", started_by="test", src_ip="10.1.2.3"
        )
        await inv_store.finalize(
            db, inv.id, status="complete", verdict="needs_more_info", confidence=0.5
        )
        assert len(await _rows(db)) == 1
        await inv_store.resolve(
            db,
            inv.id,
            verdict="false_positive",
            confidence=0.95,
            rationale="benign",
            recommended_actions=None,
            resolved_by="analyst",
        )
        rows = await _rows(db)
    assert rows == []
