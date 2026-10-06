"""The self-healing hold: a live analytic that breaches its own budget goes back to shadow.

Each test runs at fixed times relative to one anchor, and every row it reads
is written at those times. Nothing here reads the wall clock, so no test rots
as the calendar moves.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.config import Settings
from soc_ai.hunting import self_heal
from soc_ai.hunting.catalog_tiers import effective_catalog
from soc_ai.hunting.spec import parse_spec
from soc_ai.main import _run_self_heal, create_app
from soc_ai.store import analytics as analytics_store
from soc_ai.store.config_overrides import WHITELIST_BY_KEY
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.leads import HUNT_CLEAN_REASON
from soc_ai.store.models import (
    AnalyticState,
    EntityObservation,
    Hunt,
    Investigation,
    Lead,
)
from sqlalchemy import func, select

from tests.test_analytics_store import SPEC_TEXT

_ID = "local-svc-ticket-from-workstation"


def _local(ids: list[str]) -> list[str]:
    """The checked ids without the shipped profile analytics.

    Three shipped profile analytics declare a fire budget since the production
    replay of 2026-10-05, so the hold checks them on every run. These tests
    read the fixture analytic only.
    """
    return [i for i in ids if not i.startswith("profile-")]


_T0 = datetime(2026, 10, 4, 6, 0)


def _spec_text(*, budget: int | None = None, floor: float | None = None) -> str:
    text = SPEC_TEXT
    if budget is not None:
        text += f"fire_budget_per_day: {budget}\n"
    if floor is not None:
        text += f"precision_floor: {floor}\n"
    return text


async def _db(settings: Settings):  # type: ignore[no-untyped-def]
    engine = make_engine(settings)
    await run_migrations(engine)
    return engine, make_sessionmaker(engine)


async def _live(db: Any, text: str, *, at: datetime = _T0) -> None:
    """A local analytic, approved to live at ``at``."""
    await analytics_store.create_local(db, spec_text=text, by="analyst", now=at)
    await analytics_store.transition(db, _ID, to_status="shadow", by="analyst", why="try", now=at)
    await analytics_store.transition(
        db, _ID, to_status="live", by="analyst", why="a clean week", now=at
    )


_seq = iter(range(1, 1_000_000))


def _hit(at: datetime, *, shadow: bool = False, lead_id: int | None = None) -> EntityObservation:
    n = next(_seq)
    return EntityObservation(
        entity_kind="host",
        entity_key=f"10.9.0.{n % 250}",
        kind="catalog_match",
        spec_id=_ID,
        fingerprint=f"fp-{n}",
        birth_weight=0.5,
        born_at=at,
        first_seen_at=at,
        occurrences=1,
        source="catalog",
        shadow=shadow,
        lead_id=lead_id,
    )


async def _hits(db: Any, count: int, at: datetime, *, shadow: bool = False) -> None:
    db.add_all([_hit(at, shadow=shadow) for _ in range(count)])
    await db.commit()


async def _versions(db: Any) -> list[Any]:
    return list(await analytics_store.versions(db, _ID))


# ── the fire budget ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_breach_demotes_with_the_numbers_as_evidence(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _live(db, _spec_text(budget=3))
        await _hits(db, 5, _T0 + timedelta(hours=20))
        result = await self_heal.run_self_heal(db, now=_T0 + timedelta(hours=30))
        versions = await _versions(db)
        state = await db.get(AnalyticState, _ID)
        live_hits = await db.scalar(
            select(func.count(EntityObservation.id)).where(EntityObservation.shadow.is_(False))
        )
    await engine.dispose()
    assert [d.analytic_id for d in result.demoted] == [_ID]
    assert state is not None and state.status == "shadow"
    demotion = versions[-1]
    assert (demotion.from_status, demotion.to_status) == ("live", "shadow")
    assert demotion.who == analytics_store.SYSTEM_ACTOR
    assert demotion.why == ("The analytic wrote 5 hits in 24 hours. Its fire budget is 3 a day.")
    evidence = analytics_store.evidence_of(demotion)
    assert evidence is not None
    (breach,) = evidence["breaches"]
    assert breach["rule"] == "fire_budget"
    assert (breach["hits"], breach["budget"], breach["window_hours"]) == (5, 3, 24)
    assert breach["window_end"] == (_T0 + timedelta(hours=30)).isoformat() + "Z"
    # The hits it wrote stay live hits.
    assert live_hits == 5


@pytest.mark.asyncio
async def test_a_live_analytic_under_its_budget_stays_live(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _live(db, _spec_text(budget=5))
        await _hits(db, 5, _T0 + timedelta(hours=1))
        result = await self_heal.run_self_heal(db, now=_T0 + timedelta(hours=2))
        versions = await _versions(db)
        state = await db.get(AnalyticState, _ID)
    await engine.dispose()
    assert _local(result.checked) == [_ID]
    assert result.demoted == []
    assert state is not None and state.status == "live"
    assert [v.to_status for v in versions] == ["candidate", "shadow", "live"]


@pytest.mark.asyncio
async def test_hits_outside_the_window_and_shadow_hits_do_not_count(
    settings_kratos: Settings,
) -> None:
    """Eight hits, and only two of them inside the window and live."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _live(db, _spec_text(budget=2), at=_T0 - timedelta(days=3))
        await _hits(db, 3, _T0 - timedelta(hours=30))
        await _hits(db, 3, _T0 - timedelta(hours=1), shadow=True)
        await _hits(db, 2, _T0 - timedelta(hours=1))
        result = await self_heal.run_self_heal(db, now=_T0)
    await engine.dispose()
    assert result.demoted == []


@pytest.mark.asyncio
async def test_an_analytic_with_no_budget_declared_is_never_demoted(
    settings_kratos: Settings,
) -> None:
    """Negative control. Five hundred hits and no budget: the hold has nothing to read."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _live(db, _spec_text())
        await _hits(db, 500, _T0 + timedelta(hours=1))
        result = await self_heal.run_self_heal(db, now=_T0 + timedelta(hours=2))
        state = await db.get(AnalyticState, _ID)
        versions = await _versions(db)
    await engine.dispose()
    assert _ID not in result.checked
    assert result.demoted == []
    assert state is not None and state.status == "live"
    assert versions[-1].to_status == "live"


@pytest.mark.asyncio
async def test_an_empty_store_moves_no_shipped_analytic(settings_kratos: Settings) -> None:
    """The check on a fresh install writes no row at all."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        result = await self_heal.run_self_heal(db, now=_T0)
        rows = await analytics_store.states(db)
    await engine.dispose()
    assert result.demoted == []
    assert rows == {}


@pytest.mark.asyncio
async def test_an_analytic_in_shadow_is_never_demoted(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await analytics_store.create_local(db, spec_text=_spec_text(budget=1), by="analyst")
        await analytics_store.transition(db, _ID, to_status="shadow", by="analyst", why="try")
        await _hits(db, 20, _T0 + timedelta(hours=1))
        await _hits(db, 20, _T0 + timedelta(hours=1), shadow=True)
        result = await self_heal.run_self_heal(db, now=_T0 + timedelta(hours=2))
        versions = await _versions(db)
    await engine.dispose()
    assert _local(result.checked) == [] and result.demoted == []
    assert [v.to_status for v in versions] == ["candidate", "shadow"]


@pytest.mark.asyncio
async def test_the_same_breach_is_not_written_twice(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _live(db, _spec_text(budget=3))
        await _hits(db, 5, _T0 + timedelta(hours=1))
        first = await self_heal.run_self_heal(db, now=_T0 + timedelta(hours=2))
        second = await self_heal.run_self_heal(db, now=_T0 + timedelta(hours=3))
        # The analyst reads the evidence and approves it again. The five hits
        # that earned the hold are still inside 24 hours, and they must not
        # earn a second one.
        await analytics_store.transition(
            db,
            _ID,
            to_status="live",
            by="analyst",
            why="the hits were a backup run",
            now=_T0 + timedelta(hours=4),
        )
        third = await self_heal.run_self_heal(db, now=_T0 + timedelta(hours=5))
        versions = await _versions(db)
    await engine.dispose()
    assert len(first.demoted) == 1
    assert second.demoted == [] and _local(second.checked) == []
    assert third.demoted == [] and _local(third.checked) == [_ID]
    demotions = [v for v in versions if analytics_store.is_system_demotion(v)]
    assert len(demotions) == 1
    assert versions[-1].to_status == "live"


@pytest.mark.asyncio
async def test_a_new_breach_after_an_approval_demotes_again(settings_kratos: Settings) -> None:
    """Positive control for the window: it ends at the approval, not for ever."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _live(db, _spec_text(budget=3))
        await _hits(db, 5, _T0 + timedelta(hours=1))
        await self_heal.run_self_heal(db, now=_T0 + timedelta(hours=2))
        await analytics_store.transition(
            db, _ID, to_status="live", by="analyst", why="read", now=_T0 + timedelta(hours=4)
        )
        await _hits(db, 4, _T0 + timedelta(hours=6))
        again = await self_heal.run_self_heal(db, now=_T0 + timedelta(hours=7))
        versions = await _versions(db)
    await engine.dispose()
    assert len(again.demoted) == 1
    assert again.demoted[0].reason == (
        "The analytic wrote 4 hits in 3 hours since its approval to live. "
        "Its fire budget is 3 a day."
    )
    assert len([v for v in versions if analytics_store.is_system_demotion(v)]) == 2


@pytest.mark.asyncio
async def test_a_hold_already_in_the_window_is_not_written_again(
    settings_kratos: Settings,
) -> None:
    """The row went back to live with no approval on record. The breach is the same one."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _live(db, _spec_text(budget=3))
        await _hits(db, 5, _T0 + timedelta(hours=1))
        await self_heal.run_self_heal(db, now=_T0 + timedelta(hours=2))
        state = await db.get(AnalyticState, _ID)
        assert state is not None
        state.status = "live"
        await db.commit()
        again = await self_heal.run_self_heal(db, now=_T0 + timedelta(hours=3))
        versions = await _versions(db)
    await engine.dispose()
    assert again.demoted == []
    assert again.skipped == {_ID: "already demoted in this window"}
    assert len([v for v in versions if analytics_store.is_system_demotion(v)]) == 1


# ── the precision floor ───────────────────────────────────────────────────


async def _lead(
    db: Any,
    *,
    status: str,
    formed_at: datetime,
    dismissed_reason: str | None = None,
    hunt_id: str | None = None,
) -> Lead:
    lead = Lead(
        status=status,
        formed_at=formed_at,
        shadow=False,
        hunt_id=hunt_id,
        dismissed_reason=dismissed_reason,
        entities_json=[["host", "10.9.0.1"]],
        kinds_json=["catalog_match"],
    )
    db.add(lead)
    await db.flush()
    db.add(_hit(formed_at, lead_id=int(lead.id)))
    await db.commit()
    return lead


async def _clean(db: Any, at: datetime) -> Lead:
    return await _lead(db, status="dismissed", formed_at=at, dismissed_reason=HUNT_CLEAN_REASON)


async def _promoted_finding(db: Any, at: datetime, n: int) -> Lead:
    """A lead whose hunt had a finding promoted to an investigation."""
    hunt_id = f"HUNT{n:04d}"
    lead = await _lead(db, status="hunting", formed_at=at, hunt_id=hunt_id)
    db.add(Hunt(id=hunt_id, objective="o", kind="triggered", status="complete", lead_id=lead.id))
    db.add(
        Investigation(
            id=f"INV{n:04d}",
            alert_es_id=f"hunt:{hunt_id}",
            kind="hunt",
            hunt_id=hunt_id,
            finding_ordinal=0,
            status="complete",
        )
    )
    await db.commit()
    return lead


@pytest.mark.asyncio
async def test_a_precision_breach_demotes_with_the_lead_numbers(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _live(db, _spec_text(floor=0.5), at=_T0 - timedelta(days=20))
        day = _T0 - timedelta(days=10)
        await _lead(db, status="promoted", formed_at=day)
        for _ in range(4):
            await _clean(db, day)
        result = await self_heal.run_self_heal(db, now=_T0)
        versions = await _versions(db)
    await engine.dispose()
    assert [d.analytic_id for d in result.demoted] == [_ID]
    demotion = versions[-1]
    assert demotion.why == (
        "1 of 5 hunted leads reached a finding or an investigation. "
        "The precision is 0.20. Its floor is 0.50."
    )
    evidence = analytics_store.evidence_of(demotion)
    assert evidence is not None
    (breach,) = evidence["breaches"]
    assert breach["rule"] == "precision_floor"
    assert (breach["reached"], breach["closed_clean"], breach["decided"]) == (1, 4, 5)
    assert breach["precision"] == 0.2 and breach["floor"] == 0.5
    assert len(breach["lead_ids"]) == 5


@pytest.mark.asyncio
async def test_a_promoted_finding_counts_as_a_lead_that_reached(
    settings_kratos: Settings,
) -> None:
    """Two leads reached through a promoted hunt finding, three closed clean.

    Read without the promoted findings, the analytic has three decided leads,
    under the minimum, and no breach. Read with them, it has five and 0.40.
    """
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _live(db, _spec_text(floor=0.5), at=_T0 - timedelta(days=20))
        day = _T0 - timedelta(days=10)
        await _promoted_finding(db, day, 1)
        await _promoted_finding(db, day, 2)
        for _ in range(3):
            await _clean(db, day)
        outcomes = await self_heal.lead_outcomes(db, _ID, since=_T0 - timedelta(days=30), until=_T0)
        result = await self_heal.run_self_heal(db, now=_T0)
    await engine.dispose()
    assert len(outcomes.reached) == 2 and len(outcomes.closed_clean) == 3
    assert len(result.demoted) == 1
    assert result.demoted[0].breaches[0].evidence["precision"] == 0.4


@pytest.mark.asyncio
async def test_a_floor_needs_five_decided_leads(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _live(db, _spec_text(floor=0.9), at=_T0 - timedelta(days=20))
        for _ in range(self_heal.PRECISION_MIN_LEADS - 1):
            await _clean(db, _T0 - timedelta(days=2))
        result = await self_heal.run_self_heal(db, now=_T0)
    await engine.dispose()
    assert _local(result.checked) == [_ID] and result.demoted == []


@pytest.mark.asyncio
async def test_an_analyst_dismissal_counts_on_neither_side(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _live(db, _spec_text(floor=0.9), at=_T0 - timedelta(days=20))
        for _ in range(8):
            await _lead(
                db,
                status="dismissed",
                formed_at=_T0 - timedelta(days=2),
                dismissed_reason="benign_repeat",
            )
        outcomes = await self_heal.lead_outcomes(db, _ID, since=_T0 - timedelta(days=30), until=_T0)
        result = await self_heal.run_self_heal(db, now=_T0)
    await engine.dispose()
    assert outcomes.decided == 0
    assert result.demoted == []


@pytest.mark.asyncio
async def test_leads_before_the_approval_do_not_count(settings_kratos: Settings) -> None:
    """The analyst approved the analytic after reading those leads."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _live(db, _spec_text(floor=0.5), at=_T0 - timedelta(days=1))
        for _ in range(6):
            await _clean(db, _T0 - timedelta(days=5))
        result = await self_heal.run_self_heal(db, now=_T0)
    await engine.dispose()
    assert result.demoted == []


# ── the spec fields, the setting and the loop ─────────────────────────────


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        ("fire_budget_per_day: 0\n", "fire_budget_per_day"),
        ("precision_floor: 0\n", "precision_floor"),
        ("precision_floor: 1.5\n", "precision_floor"),
    ],
)
def test_a_budget_or_a_floor_out_of_range_is_refused(extra: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        parse_spec(SPEC_TEXT + extra)


def test_the_spec_fields_default_to_no_budget_and_no_floor() -> None:
    spec = parse_spec(SPEC_TEXT)
    assert spec.fire_budget_per_day is None and spec.precision_floor is None


def test_the_setting_is_on_by_default_and_in_the_console(settings_kratos: Settings) -> None:
    assert settings_kratos.analytic_self_heal_enabled is True
    spec = WHITELIST_BY_KEY["analytic_self_heal_enabled"]
    assert spec.type == "bool" and spec.hot is True
    assert spec.section == "Hunting"
    assert "\u2014" not in spec.help and "\u2013" not in spec.help


@pytest.mark.asyncio
async def test_the_loop_hook_does_nothing_with_the_setting_off(settings_kratos: Settings) -> None:
    # The hook reads the wall clock, so this one test seeds relative to it.
    now = datetime.now(UTC).replace(tzinfo=None)
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _live(db, _spec_text(budget=1), at=now - timedelta(hours=3))
        await _hits(db, 3, now - timedelta(hours=1))
    app = SimpleNamespace(state=SimpleNamespace(db_sessionmaker=maker))
    off = settings_kratos.model_copy(update={"analytic_self_heal_enabled": False})
    await _run_self_heal(app, off)  # type: ignore[arg-type]
    async with maker() as db:
        held_off = (await db.get(AnalyticState, _ID)).status  # type: ignore[union-attr]
    await _run_self_heal(app, settings_kratos)  # type: ignore[arg-type]
    async with maker() as db:
        held_on = (await db.get(AnalyticState, _ID)).status  # type: ignore[union-attr]
    await engine.dispose()
    assert held_off == "live"
    assert held_on == "shadow"


# ── the bell ──────────────────────────────────────────────────────────────


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


def test_a_hold_raises_a_bell_entry_until_the_analyst_acts(client: TestClient) -> None:
    # The bell reads the wall clock for its "when", so this test seeds
    # relative to it.
    async def breach() -> None:
        now = datetime.now(UTC).replace(tzinfo=None)
        async with client.app.state.db_sessionmaker() as db:
            await _live(db, _spec_text(budget=2), at=now - timedelta(hours=3))
            await _hits(db, 4, now - timedelta(hours=1))
            result = await self_heal.run_self_heal(db, now=now)
            assert len(result.demoted) == 1

    asyncio.run(breach())
    entries = [
        n
        for n in client.get("/api/v1/notifications").json()
        if n["id"].startswith("analytic-held:")
    ]
    assert len(entries) == 1
    entry = entries[0]
    assert entry["group"] == "hunting"
    assert entry["tone"] == "warn"
    assert entry["title"].startswith("soc-ai moved A Kerberos ticket request names a service")
    assert "Its fire budget is 2 a day." in entry["title"]
    assert entry["href"] == f"/hunts?tab=analytics&open={_ID}"

    res = client.post(f"/api/v1/analytics/{_ID}/status", json={"to": "live", "why": "read"})
    assert res.status_code == 200, res.text
    after = [
        n
        for n in client.get("/api/v1/notifications").json()
        if n["id"].startswith("analytic-held:")
    ]
    assert after == []


def test_no_bell_entry_without_a_hold(client: TestClient) -> None:
    """Negative control: an analyst's own shadow raises no hold entry."""
    client.post("/api/v1/analytics", json={"spec_text": SPEC_TEXT})
    client.post(f"/api/v1/analytics/{_ID}/status", json={"to": "shadow", "why": "try"})
    entries = [
        n
        for n in client.get("/api/v1/notifications").json()
        if n["id"].startswith("analytic-held:")
    ]
    assert entries == []


@pytest.mark.asyncio
async def test_the_check_reads_the_effective_catalog(settings_kratos: Settings) -> None:
    """A caller with no catalog gets the store's: the analytic's spec text carries the budget."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _live(db, _spec_text(budget=4))
        cat = await effective_catalog(db)
    await engine.dispose()
    assert cat.specs[_ID].fire_budget_per_day == 4
