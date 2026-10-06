"""A live analytic can move back to shadow, in a system hand only.

The self-healing hold needs a live-to-shadow transition. The system takes that
one step and no other: approval to live and retirement stay an analyst's.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.config import Settings
from soc_ai.hunting.catalog_tiers import effective_catalog
from soc_ai.hunting.leads import content_fingerprint, record_observation
from soc_ai.hunting.weight import Kind
from soc_ai.main import create_app
from soc_ai.store import analytics as analytics_store
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import AnalyticState, EntityObservation
from sqlalchemy import select

from tests.test_analytics_store import SPEC_TEXT

_LOCAL = "local-svc-ticket-from-workstation"
_SHIPPED = "identity-4662-dcsync-nonmachine"
_NOW = datetime(2026, 10, 4, 12, 0, tzinfo=UTC)
_REASON = "The analytic wrote 42 hits in 24 hours. Its fire budget is 10 a day."
_EVIDENCE: dict[str, Any] = {
    "breaches": [{"rule": "fire_budget", "hits": 42, "budget": 10}],
}


async def _db(settings: Settings):  # type: ignore[no-untyped-def]
    engine = make_engine(settings)
    await run_migrations(engine)
    return engine, make_sessionmaker(engine)


async def _live_local(db: Any) -> None:
    await analytics_store.create_local(db, spec_text=SPEC_TEXT, by="analyst", now=_NOW)
    await analytics_store.transition(db, _LOCAL, to_status="shadow", by="analyst", why="try")
    await analytics_store.transition(db, _LOCAL, to_status="live", by="analyst", why="clean")


async def _observe(db: Any, spec_id: str, entity: str) -> EntityObservation:
    return await record_observation(
        db,
        entity_kind="host",
        entity_key=entity,
        kind=Kind.CATALOG_MATCH,
        spec_id=spec_id,
        fingerprint=content_fingerprint(spec_id, entity),
        summary=f"a hit on {entity}",
        evidence={"sample_ids": [f"doc-{entity}"]},
        source="catalog",
        shadow=False,
        now=_NOW - timedelta(hours=2),
    )


@pytest.mark.asyncio
async def test_a_demotion_writes_the_actor_the_reason_and_the_evidence(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _live_local(db)
        state = await analytics_store.demote_to_shadow(
            db, _LOCAL, reason=_REASON, evidence=_EVIDENCE, now=_NOW
        )
        versions = await analytics_store.versions(db, _LOCAL)
        cat = await effective_catalog(db)
    await engine.dispose()
    assert state.status == "shadow"
    assert state.reason == _REASON
    demotion = versions[-1]
    assert (demotion.from_status, demotion.to_status) == ("live", "shadow")
    assert demotion.who == analytics_store.SYSTEM_ACTOR
    assert demotion.why == _REASON
    assert analytics_store.evidence_of(demotion) == _EVIDENCE
    assert analytics_store.is_system_demotion(demotion)
    # The spec text rides on the row, as on every other transition.
    assert demotion.spec_before == demotion.spec_after == SPEC_TEXT.strip() + "\n"
    assert cat.status_of(_LOCAL) == ("local", "shadow")
    assert _LOCAL in cat.shadow_ids


@pytest.mark.asyncio
async def test_a_demotion_leaves_the_observations_it_wrote_untouched(
    settings_kratos: Settings,
) -> None:
    """Written live and read live. The next sweep writes the new ones in shadow."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _live_local(db)
        for entity in ("10.1.2.3", "10.1.2.4"):
            await _observe(db, _LOCAL, entity)
        before = [
            (o.id, o.shadow, o.born_at, o.occurrences, o.read_at, o.lead_id)
            for o in (await db.scalars(select(EntityObservation).order_by(EntityObservation.id)))
        ]
        await analytics_store.demote_to_shadow(
            db, _LOCAL, reason=_REASON, evidence=_EVIDENCE, now=_NOW
        )
        db.expire_all()
        after = [
            (o.id, o.shadow, o.born_at, o.occurrences, o.read_at, o.lead_id)
            for o in (await db.scalars(select(EntityObservation).order_by(EntityObservation.id)))
        ]
    await engine.dispose()
    assert len(before) == 2
    assert after == before
    assert all(row[1] is False for row in after)


@pytest.mark.asyncio
async def test_a_shipped_analytic_with_no_row_gets_its_first_row_from_the_demotion(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await analytics_store.demote_to_shadow(
            db, _SHIPPED, reason=_REASON, evidence=_EVIDENCE, now=_NOW
        )
        row = await db.get(AnalyticState, _SHIPPED)
        versions = await analytics_store.versions(db, _SHIPPED)
        cat = await effective_catalog(db)
    await engine.dispose()
    assert row is not None and (row.tier, row.status) == ("shipped", "shadow")
    assert [(v.from_status, v.to_status) for v in versions] == [("live", "shadow")]
    shipped_text = versions[0].spec_after or ""
    assert "id: identity-4662-dcsync-nonmachine" in shipped_text
    assert cat.status_of(_SHIPPED) == ("shipped", "shadow")
    assert _SHIPPED in cat.shadow_ids


@pytest.mark.asyncio
async def test_a_second_demotion_writes_no_second_row(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _live_local(db)
        await analytics_store.demote_to_shadow(
            db, _LOCAL, reason=_REASON, evidence=_EVIDENCE, now=_NOW
        )
        await analytics_store.demote_to_shadow(
            db, _LOCAL, reason="another reason", evidence=_EVIDENCE, now=_NOW
        )
        versions = await analytics_store.versions(db, _LOCAL)
        state = await db.get(AnalyticState, _LOCAL)
    await engine.dispose()
    assert [v.to_status for v in versions] == ["candidate", "shadow", "live", "shadow"]
    assert state is not None and state.reason == _REASON


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["retired", "candidate"])
async def test_a_demotion_never_moves_an_analytic_that_is_not_live(
    settings_kratos: Settings, status: str
) -> None:
    """A demotion that revived a retired analytic would undo an analyst's decision."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await analytics_store.create_local(db, spec_text=SPEC_TEXT, by="analyst", now=_NOW)
        if status == "retired":
            await analytics_store.transition(
                db, _LOCAL, to_status="retired", by="analyst", why="noise"
            )
        with pytest.raises(ValueError, match="not a demotion"):
            await analytics_store.demote_to_shadow(
                db, _LOCAL, reason=_REASON, evidence=_EVIDENCE, now=_NOW
            )
        state = await db.get(AnalyticState, _LOCAL)
        versions = await analytics_store.versions(db, _LOCAL)
    await engine.dispose()
    assert state is not None and state.status == status
    assert versions[-1].to_status == status


@pytest.mark.asyncio
async def test_a_person_cannot_demote_and_a_demotion_needs_a_reason(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _live_local(db)
        with pytest.raises(ValueError, match="not a system actor"):
            await analytics_store.demote_to_shadow(
                db, _LOCAL, reason=_REASON, evidence=None, actor="analyst"
            )
        with pytest.raises(ValueError, match="needs a reason"):
            await analytics_store.demote_to_shadow(db, _LOCAL, reason="  ", evidence=None)
        state = await db.get(AnalyticState, _LOCAL)
    await engine.dispose()
    assert state is not None and state.status == "live"


@pytest.mark.asyncio
@pytest.mark.parametrize("actor", [analytics_store.SYSTEM_ACTOR, "system", "System:other"])
async def test_a_system_actor_can_never_approve_to_live(
    settings_kratos: Settings, actor: str
) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _live_local(db)
        await analytics_store.demote_to_shadow(
            db, _LOCAL, reason=_REASON, evidence=_EVIDENCE, now=_NOW
        )
        with pytest.raises(analytics_store.SystemActorRefused, match="approve"):
            await analytics_store.transition(
                db, _LOCAL, to_status="live", by=actor, why="the budget recovered"
            )
        state = await db.get(AnalyticState, _LOCAL)
        versions = await analytics_store.versions(db, _LOCAL)
    await engine.dispose()
    assert state is not None and state.status == "shadow"
    assert versions[-1].to_status == "shadow"


@pytest.mark.asyncio
async def test_a_system_actor_can_never_retire(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _live_local(db)
        with pytest.raises(analytics_store.SystemActorRefused, match="retire"):
            await analytics_store.transition(
                db, _LOCAL, to_status="retired", by=analytics_store.SYSTEM_ACTOR, why="noise"
            )
        with pytest.raises(analytics_store.SystemActorRefused, match="retire"):
            await analytics_store.retire_shipped(
                db,
                _SHIPPED,
                shipped_text="",
                by=analytics_store.SYSTEM_ACTOR,
                why="noise",
            )
        local = await db.get(AnalyticState, _LOCAL)
        shipped = await db.get(AnalyticState, _SHIPPED)
    await engine.dispose()
    assert local is not None and local.status == "live"
    # The shipped analytic got no row at all, so it is still live by default.
    assert shipped is None


@pytest.mark.asyncio
async def test_an_analyst_still_approves_and_retires_after_a_demotion(
    settings_kratos: Settings,
) -> None:
    """Negative control: the refusal reads the hand, not the transition."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _live_local(db)
        await analytics_store.demote_to_shadow(
            db, _LOCAL, reason=_REASON, evidence=_EVIDENCE, now=_NOW
        )
        holds = await analytics_store.system_holds(db)
        await analytics_store.transition(
            db, _LOCAL, to_status="live", by="analyst", why="read the hits, they are real"
        )
        after_approval = await analytics_store.system_holds(db)
        await analytics_store.transition(
            db, _LOCAL, to_status="retired", by="analyst", why="too noisy after all"
        )
        state = await db.get(AnalyticState, _LOCAL)
    await engine.dispose()
    assert set(holds) == {_LOCAL}
    assert holds[_LOCAL].why == _REASON
    assert after_approval == {}
    assert state is not None and state.status == "retired"


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    fake_es = AsyncMock()
    fake_auth = AsyncMock()
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
        patch("soc_ai.main.make_auth", return_value=fake_auth),
        patch("soc_ai.main.get_settings", return_value=settings_kratos),
    ):
        app = create_app()
        with TestClient(app) as test_client:
            yield test_client


def _demote(client: TestClient, analytic_id: str) -> None:
    async def go() -> None:
        async with client.app.state.db_sessionmaker() as db:
            await analytics_store.demote_to_shadow(
                db, analytic_id, reason=_REASON, evidence=_EVIDENCE
            )

    asyncio.run(go())


def test_the_ledger_and_the_card_show_a_system_demotion_with_its_reason(
    client: TestClient,
) -> None:
    _demote(client, _SHIPPED)
    detail = client.get(f"/api/v1/analytics/{_SHIPPED}").json()
    assert detail["status"] == "shadow"
    assert detail["held_by_system"] == _REASON
    assert detail["reason"] == _REASON
    demotion = detail["versions"][-1]
    assert demotion["system"] is True
    assert demotion["who"] == analytics_store.SYSTEM_ACTOR
    assert demotion["why"] == _REASON
    assert demotion["evidence"] == _EVIDENCE
    # Evidence is no approval receipt.
    assert demotion["has_receipts"] is False
    row = next(
        a for a in client.get("/api/v1/analytics").json()["analytics"] if a["id"] == _SHIPPED
    )
    assert row["status"] == "shadow"
    assert row["held_by_system"] == _REASON


def _catalog_row(client: TestClient, analytic_id: str) -> dict[str, Any]:
    specs = client.get("/api/v1/hunt-catalog").json()["specs"]
    return next(s for s in specs if s["id"] == analytic_id)


_PROFILE = "profile-connection-rate-spiked"


def test_the_operate_catalog_row_carries_the_hold(client: TestClient) -> None:
    """N4 of the 2026-10-05 verification. Operate showed a held analytic with
    the "shadow" chip of an analyst's shadow. The Analytics tab said "held by
    soc-ai". The catalog row now carries the hold, on a match row and on a
    profile row."""
    _demote(client, _SHIPPED)
    _demote(client, _PROFILE)
    match_row = _catalog_row(client, _SHIPPED)
    assert match_row["status"] == "shadow"
    assert match_row["held_by_system"] == _REASON
    profile_row = _catalog_row(client, _PROFILE)
    assert profile_row["evaluator"] == "profile"
    assert profile_row["status"] == "shadow"
    assert profile_row["held_by_system"] == _REASON


def test_an_analyst_shadow_carries_no_hold_on_the_catalog_row(client: TestClient) -> None:
    """Negative control: an analyst's shadow and an approval after a hold."""
    client.post("/api/v1/analytics", json={"spec_text": SPEC_TEXT})
    client.post(f"/api/v1/analytics/{_LOCAL}/status", json={"to": "shadow", "why": "try"})
    local = _catalog_row(client, _LOCAL)
    assert local["status"] == "shadow"
    assert local["held_by_system"] is None

    _demote(client, _SHIPPED)
    client.post(f"/api/v1/analytics/{_SHIPPED}/status", json={"to": "live", "why": "read"})
    shipped = _catalog_row(client, _SHIPPED)
    assert shipped["status"] == "live"
    assert shipped["held_by_system"] is None


def test_an_analyst_approval_ends_the_hold_on_the_card(client: TestClient) -> None:
    _demote(client, _SHIPPED)
    res = client.post(
        f"/api/v1/analytics/{_SHIPPED}/status", json={"to": "live", "why": "read the hits"}
    )
    assert res.status_code == 200, res.text
    assert res.json()["held_by_system"] is None
    detail = client.get(f"/api/v1/analytics/{_SHIPPED}").json()
    assert detail["status"] == "live"
    assert detail["held_by_system"] is None
    assert [v["system"] for v in detail["versions"]] == [True, False]


def test_an_analyst_row_reads_as_no_system_change(client: TestClient) -> None:
    """Negative control: the flag is the hand on the row, not every row."""
    client.post("/api/v1/analytics", json={"spec_text": SPEC_TEXT})
    client.post(f"/api/v1/analytics/{_LOCAL}/status", json={"to": "shadow", "why": "try"})
    detail = client.get(f"/api/v1/analytics/{_LOCAL}").json()
    assert [v["system"] for v in detail["versions"]] == [False, False]
    assert all(v["evidence"] is None for v in detail["versions"])
    assert detail["held_by_system"] is None


def test_a_person_with_a_system_name_is_refused_through_the_route(client: TestClient) -> None:
    _demote(client, _SHIPPED)
    with patch(
        "soc_ai.api.webui.routes_analytics.identify_caller", AsyncMock(return_value="system")
    ):
        res = client.post(
            f"/api/v1/analytics/{_SHIPPED}/status", json={"to": "live", "why": "looks fine"}
        )
    assert res.status_code == 422, res.text
    assert "system_actor_refused" in res.text
    detail = client.get(f"/api/v1/analytics/{_SHIPPED}").json()
    assert detail["status"] == "shadow"
