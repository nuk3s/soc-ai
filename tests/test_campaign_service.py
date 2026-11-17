"""The campaign service: rebuild with stable ids, freshness, and the read side (Task 8).

``rebuild`` reads the standing true positive runs and the runs on their
sessions, and writes the drafts of the engine. A campaign keeps its id over
a rebuild. A new run that links two campaigns merges them into the older
one, and a campaign with no true positive left is withdrawn.

The data is synthetic: placeholder addresses, names and rule names.
"""

from __future__ import annotations

import asyncio
import logging
import sqlite3
import threading
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from soc_ai.campaigns import service
from soc_ai.campaigns.engine import build_campaigns
from soc_ai.config import Settings
from soc_ai.so_client.elastic import EsSearchResult
from soc_ai.store import investigations as inv_svc
from soc_ai.store.auth import utcnow
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import (
    AuthorizedActivity,
    Campaign,
    CampaignMember,
    CampaignParty,
    CampaignRunFacts,
    Investigation,
    InvestigationEvent,
)
from sqlalchemy import delete, event, func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.test_campaign_engine import run
from tests.test_campaign_facts import (
    ACTOR,
    ACTOR_2,
    OUTSIDE,
    RULE,
    RULE_B,
    TARGET,
    TARGET_2,
    seed_hosts,
    seed_run,
)


@pytest.fixture
async def maker(settings_kratos: Settings) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    try:
        yield make_sessionmaker(engine)
    finally:
        await engine.dispose()


async def _three_runs(db: AsyncSession) -> list[str]:
    """Three true positive alert runs of one actor on one target, an hour apart."""
    await seed_hosts(db)
    return [
        await seed_run(db, f"alert-000{n}", event_hours_ago=4 - n, created_minutes_ago=40 - n)
        for n in (1, 2, 3)
    ]


async def _count(db: AsyncSession, model: Any) -> int:
    return int(await db.scalar(select(func.count()).select_from(model)) or 0)


async def _members(db: AsyncSession, campaign_id: int) -> dict[str, str]:
    rows = await db.execute(
        select(CampaignMember.run_id, CampaignMember.link).where(
            CampaignMember.campaign_id == campaign_id
        )
    )
    return {str(run_id): str(link) for run_id, link in rows.all()}


async def _campaigns(db: AsyncSession) -> list[Campaign]:
    return list((await db.scalars(select(Campaign).order_by(Campaign.id))).all())


# ── Rebuild ────────────────────────────────────────────────────────────────


async def test_three_linked_runs_give_one_campaign_three_members_and_two_parties(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    async with maker() as db:
        runs = await _three_runs(db)
        result = await service.rebuild(db)
    assert (result.campaigns, result.members, result.created) == (1, 3, 1)
    assert (result.merged, result.withdrawn, result.unresolved_runs) == (0, 0, 0)
    async with maker() as db:
        (campaign,) = await _campaigns(db)
        assert campaign.status == "active"
        assert campaign.title == "actor-a against web-1"
        assert campaign.stage == "attempt"
        assert campaign.member_count == 3
        assert campaign.seed_run_id == runs[0]
        assert set(campaign.detail) == {
            "ladder",
            "waves",
            "sessions",
            "named",
            "detection",
            "pairs",
            "edges",
            "hash",
        }
        assert campaign.detail["pairs"] == [["agent:a1", "ip:t1"]]
        # One arrow from the actor to the target holds the three runs.
        (edge,) = campaign.detail["edges"]
        assert (edge["source"], edge["target"], edge["runs"], edge["stage"]) == (
            "agent:a1",
            "ip:t1",
            3,
            "attempt",
        )
        assert (edge["beyond"], edge["from_documents"]) == (False, False)
        assert edge["first_at"] < edge["last_at"]
        assert await _members(db, campaign.id) == {
            runs[0]: "seed",
            runs[1]: "actor",
            runs[2]: "actor",
        }
        member = await db.scalar(select(CampaignMember).where(CampaignMember.run_id == runs[1]))
        assert member is not None
        assert "type" not in member.evidence
        assert member.evidence["member_run_id"] == runs[0]
        assert member.evidence["machine"] == "agent:a1"
        assert (member.actor_key, member.target_key) == ("agent:a1", "ip:t1")
        assert member.verdict_differs is False
        parties = (await db.scalars(select(CampaignParty))).all()
        assert {(p.machine_key, p.role, p.join_kind) for p in parties} == {
            ("agent:a1", "actor", "agent"),
            ("ip:t1", "target", "network"),
        }
        assert await _count(db, CampaignRunFacts) == 3


async def test_a_second_rebuild_with_no_change_keeps_the_campaign_and_its_members(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    async with maker() as db:
        await _three_runs(db)
        await service.rebuild(db)
    async with maker() as db:
        (before,) = await _campaigns(db)
        members_before = await _members(db, before.id)
    async with maker() as db:
        result = await service.rebuild(db)
    assert (result.created, result.merged, result.withdrawn) == (0, 0, 0)
    async with maker() as db:
        (after,) = await _campaigns(db)
        assert after.id == before.id
        assert after.status == "active"
        assert await _members(db, after.id) == members_before
        assert await _count(db, CampaignParty) == 2


async def test_a_run_that_links_two_campaigns_merges_them_into_the_older_one(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    async with maker() as db:
        await seed_hosts(db)
        first = await seed_run(db, "alert-a", event_hours_ago=10)
        second = await seed_run(
            db, "alert-b", src=ACTOR_2, dst=TARGET_2, rule=RULE_B, event_hours_ago=8
        )
        result = await service.rebuild(db)
    assert result.campaigns == 2
    async with maker() as db:
        older, newer = await _campaigns(db)
        assert await _members(db, older.id) == {first: "seed"}
        assert await _members(db, newer.id) == {second: "seed"}

    # The same actor as the first campaign, on the target of the second with its rule.
    async with maker() as db:
        link = await seed_run(db, "alert-c", dst=TARGET_2, rule=RULE_B, event_hours_ago=1)
        result = await service.rebuild(db)
    assert (result.campaigns, result.created, result.merged, result.withdrawn) == (1, 0, 1, 0)
    async with maker() as db:
        kept, merged = await _campaigns(db)
        assert (kept.id, kept.status) == (older.id, "active")
        assert set(await _members(db, kept.id)) == {first, second, link}
        assert (merged.id, merged.status, merged.merged_into_id) == (
            newer.id,
            "merged",
            older.id,
        )
        assert await _members(db, merged.id) == {}


async def test_an_override_of_the_only_true_positive_withdraws_the_campaign(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    async with maker() as db:
        await seed_hosts(db)
        run_id = await seed_run(db, "alert-0001")
        await service.rebuild(db)
        await inv_svc.resolve(
            db,
            run_id,
            verdict="false_positive",
            confidence=0.9,
            rationale="The upload was a scheduled test.",
            recommended_actions=None,
            resolved_by="analyst",
            resolved_via="manual",
        )
    async with maker() as db:
        result = await service.rebuild(db)
    assert (result.campaigns, result.withdrawn) == (0, 1)
    async with maker() as db:
        (campaign,) = await _campaigns(db)
        assert campaign.status == "withdrawn"
        assert campaign.merged_into_id is None
        assert await _count(db, CampaignMember) == 0
        assert await _count(db, CampaignParty) == 0
        # The run stands in no scan, so its facts go.
        assert await _count(db, CampaignRunFacts) == 0


async def test_a_rerun_that_replaces_a_member_takes_its_place(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    async with maker() as db:
        await seed_hosts(db)
        first = await seed_run(db, "alert-a", event_hours_ago=3, created_minutes_ago=50)
        old = await seed_run(db, "alert-b", event_hours_ago=2, created_minutes_ago=40)
        await service.rebuild(db)
    async with maker() as db:
        (campaign,) = await _campaigns(db)
        assert set(await _members(db, campaign.id)) == {first, old}
        new = await seed_run(db, "alert-b", event_hours_ago=2, created_minutes_ago=5)
        await service.rebuild(db)
    async with maker() as db:
        (after,) = await _campaigns(db)
        assert after.id == campaign.id
        assert set(await _members(db, after.id)) == {first, new}
        assert await db.get(CampaignRunFacts, old) is None


async def test_a_dry_run_writes_no_row(maker: async_sessionmaker[AsyncSession]) -> None:
    async with maker() as db:
        await _three_runs(db)
        result = await service.rebuild(db, dry_run=True)
    assert (result.campaigns, result.members, result.created) == (1, 3, 1)
    assert len(result.drafts) == 1
    async with maker() as db:
        for model in (Campaign, CampaignMember, CampaignParty, CampaignRunFacts):
            assert await _count(db, model) == 0


async def test_a_replay_a_synthetic_run_and_a_pipeline_error_are_no_members(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    async with maker() as db:
        await seed_hosts(db)
        real = await seed_run(db, "alert-0001", event_hours_ago=3)
        await seed_run(db, "alert-0002", event_hours_ago=2, started_by="backtest")
        await seed_run(db, "alert-0003", event_hours_ago=2, synthetic=True)
        await seed_run(
            db,
            "alert-0004",
            event_hours_ago=2,
            report={"resolution": {"provenance": "pipeline_fallback"}},
        )
        result = await service.rebuild(db)
    assert result.members == 1
    async with maker() as db:
        (campaign,) = await _campaigns(db)
        assert await _members(db, campaign.id) == {real: "seed"}


async def test_a_false_positive_on_the_session_of_a_member_joins_as_a_differing_verdict(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    async with maker() as db:
        await seed_hosts(db)
        seed = await seed_run(db, "alert-0001", community_id="1:sess", event_hours_ago=2)
        other = await seed_run(
            db,
            "alert-0002",
            src=TARGET,
            dst=OUTSIDE,
            verdict="false_positive",
            community_id="1:sess",
            event_hours_ago=1.9,
        )
        far = await seed_run(
            db,
            "alert-0003",
            src=TARGET,
            dst=OUTSIDE,
            verdict="false_positive",
            community_id="1:sess",
            event_hours_ago=120,
        )
        await service.rebuild(db)
    async with maker() as db:
        (campaign,) = await _campaigns(db)
        assert await _members(db, campaign.id) == {seed: "seed", other: "session"}
        member = await db.scalar(select(CampaignMember).where(CampaignMember.run_id == other))
        assert member is not None
        assert member.verdict_differs is True
        assert member.stage is None
        assert await _count(db, CampaignParty) == 2
        # The far run was read, and the engine left it out: five days apart.
        assert await db.get(CampaignRunFacts, far) is not None


async def test_a_later_campaign_on_the_same_pair_names_the_earlier_one(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    async with maker() as db:
        await seed_hosts(db)
        await seed_run(db, "alert-0001", event_hours_ago=400, created_minutes_ago=24000)
        await seed_run(db, "alert-0002", rule=RULE_B, event_hours_ago=1)
        result = await service.rebuild(db)
    assert result.campaigns == 2
    async with maker() as db:
        older, newer = await _campaigns(db)
        assert older.earlier_campaign_id is None
        assert newer.earlier_campaign_id == older.id


# ── Freshness ──────────────────────────────────────────────────────────────


async def test_ensure_fresh_rebuilds_once_for_one_basis_and_again_after_a_new_run(
    maker: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    real = service.rebuild
    calls: list[int] = []

    async def spy(db: AsyncSession, **kwargs: Any) -> service.RebuildResult:
        calls.append(1)
        return await real(db, **kwargs)

    monkeypatch.setattr(service, "rebuild", spy)
    async with maker() as db:
        await _three_runs(db)
    for _ in range(2):
        async with maker() as db:
            assert await service.ensure_fresh(db) is True
    assert len(calls) == 1
    async with maker() as db:
        assert await _count(db, Campaign) == 1
        await seed_run(db, "alert-0009", event_hours_ago=0.5, created_minutes_ago=1)
    for _ in range(2):
        async with maker() as db:
            assert await service.ensure_fresh(db) is True
    assert len(calls) == 2


async def test_ensure_fresh_gives_false_and_raises_nothing_when_the_rebuild_fails(
    maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    calls: list[int] = []

    async def broken(db: AsyncSession, **kwargs: Any) -> service.RebuildResult:
        calls.append(1)
        raise RuntimeError("the store is locked")

    monkeypatch.setattr(service, "rebuild", broken)
    async with maker() as db:
        await _three_runs(db)
    with caplog.at_level(logging.WARNING, logger="soc_ai.campaigns.service"):
        async with maker() as db:
            assert await service.ensure_fresh(db) is False
            # The session stays usable for the stored rows.
            assert await service.list_campaigns(db) == []
    assert any("could not rebuild" in r.getMessage() for r in caplog.records)
    # A failed rebuild stores no basis, so the next read tries again.
    async with maker() as db:
        assert await service.ensure_fresh(db) is False
    assert len(calls) == 2


# ── Read ───────────────────────────────────────────────────────────────────


async def test_a_campaign_with_a_last_event_one_horizon_ago_is_ended(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    async with maker() as db:
        await seed_hosts(db)
        await seed_run(db, "alert-0001", event_hours_ago=208)
        await seed_run(db, "alert-0002", dst=TARGET_2, rule=RULE_B, src=ACTOR_2, event_hours_ago=1)
        await service.rebuild(db)
    async with maker() as db:
        old, new = await _campaigns(db)
        ended = await service.get_campaign(db, old.id, now=utcnow())
        current = await service.get_campaign(db, new.id, now=utcnow())
        rows = await service.list_campaigns(db, now=utcnow())
    assert ended is not None and ended.status == "ended"
    assert current is not None and current.status == "open"
    # The newest last event first.
    assert [(r.id, r.status) for r in rows] == [(new.id, "open"), (old.id, "ended")]


async def test_get_campaign_reads_the_members_parties_authorizations_and_related_runs(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    async with maker() as db:
        runs = await _three_runs(db)
        now = utcnow()
        authorization = AuthorizedActivity(
            label="upload test",
            sources=[{"address": ACTOR, "machine_key": "agent:a1", "name": "actor-a"}],
            target_address=TARGET,
            target_machine_key="ip:t1",
            rule_names=["ET EXPLOIT Example Upload Request (CVE-2026-0001)"],
            rule_class="exploit_attempt",
            starts_at=now - timedelta(days=1),
            expires_at=now + timedelta(days=2),
            created_by="analyst",
        )
        db.add(authorization)
        await db.commit()
        row = await db.get(Investigation, runs[2])
        assert row is not None
        row.authorization_id = authorization.id
        await db.commit()
        waiting = await seed_run(
            db, "alert-0010", verdict="needs_more_info", rule="ET INFO Example Probe"
        )
        await seed_run(db, "alert-0011", src=TARGET, dst=OUTSIDE, verdict="false_positive")
        await seed_run(db, "alert-0012", src=TARGET, dst=ACTOR, verdict="false_positive")
        await service.rebuild(db)
        (campaign,) = await _campaigns(db)
        view = await service.get_campaign(db, campaign.id)
    assert view is not None
    assert view.status == "open"
    assert [m.run_id for m in view.members] == runs
    first, second, _third = view.members
    assert (first.link, first.kind, first.tier, first.verdict) == (
        "seed",
        "alert",
        "alert",
        "true_positive",
    )
    assert first.label == "ET EXPLOIT Example Upload Request (CVE-2026-0001)"
    assert (first.source_address, first.target_address) == (ACTOR, TARGET)
    assert second.evidence.machine_key == "agent:a1"
    assert second.evidence.machine_name == "actor-a"
    assert second.evidence.member_run_id == runs[0]
    assert {(p.machine_key, p.has_agent) for p in view.parties} == {
        ("agent:a1", True),
        ("ip:t1", False),
    }
    (auth,) = view.authorizations
    assert (auth.id, auth.label, auth.state, auth.member_runs) == (
        authorization.id,
        "upload test",
        "active",
        1,
    )
    assert [r.run_id for r in view.needs_more_info] == [waiting]
    # One false positive from the target to a host that is no party. The run
    # to the actor names a party, so it does not count.
    assert view.false_positive_from_targets == 1
    assert [s.stage for s in view.ladder if s.reached] == ["attempt"]
    (waves,) = view.waves
    assert waves.actor == service.PartyBrief("agent:a1", "actor-a", ACTOR)

    # A deleted run keeps its stored label and has no verdict.
    async with maker() as db:
        await db.execute(
            delete(InvestigationEvent).where(InvestigationEvent.investigation_id == runs[1])
        )
        await db.execute(delete(Investigation).where(Investigation.id == runs[1]))
        await db.commit()
        again = await service.get_campaign(db, campaign.id)
    assert again is not None
    gone = next(m for m in again.members if m.run_id == runs[1])
    assert gone.verdict is None
    assert gone.label == "ET EXPLOIT Example Upload Request (CVE-2026-0001)"


async def test_get_campaign_gives_the_arrows_and_the_machine_keys_of_each_member(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    async with maker() as db:
        runs = await _three_runs(db)
        await service.rebuild(db)
        (campaign,) = await _campaigns(db)
        view = await service.get_campaign(db, campaign.id)
    assert view is not None
    (edge,) = view.edges
    assert (edge.source, edge.target, edge.runs, edge.stage) == ("agent:a1", "ip:t1", 3, "attempt")
    assert (edge.beyond, edge.from_documents) == (False, False)
    assert edge.first_at == view.members[0].event_at
    assert edge.last_at == view.members[-1].event_at
    assert [m.run_id for m in view.members] == runs
    assert {(m.source_key, m.target_key) for m in view.members} == {("agent:a1", "ip:t1")}


async def test_a_stored_detail_with_no_edges_gives_no_arrow_and_raises_nothing(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    async with maker() as db:
        await _three_runs(db)
        await service.rebuild(db)
        (campaign,) = await _campaigns(db)
        # A row of the earlier release: its detail has no ``edges`` key.
        campaign.detail = {k: v for k, v in campaign.detail.items() if k != "edges"}
        await db.commit()
        view = await service.get_campaign(db, campaign.id)
    assert view is not None
    assert view.edges == ()
    # NEGATIVE CONTROL: the other sections of the row still read.
    assert len(view.members) == 3
    assert [s.stage for s in view.ladder if s.reached] == ["attempt"]
    # A broken value or a broken item gives no arrow, and no error.
    assert service._edges({"edges": "broken"}) == ()
    assert service._edges({"edges": [{"source": "agent:a1"}, "x", None]}) == ()


async def test_a_rebuild_rewrites_a_campaign_whose_stored_detail_has_no_edges(
    maker: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    # The rebuild of the earlier release wrote no edges and hashed none.
    real = service._detail

    def earlier_release(draft: Any) -> dict[str, Any]:
        return {k: v for k, v in real(draft).items() if k != "edges"}

    async with maker() as db:
        await _three_runs(db)
        monkeypatch.setattr(service, "_detail", earlier_release)
        await service.rebuild(db)
    async with maker() as db:
        (before,) = await _campaigns(db)
    assert "edges" not in before.detail

    # The same release rebuilds and leaves the row: the content did not change.
    with _Statements(maker) as seen:
        async with maker() as db:
            await service.rebuild(db)
    assert seen.writes("campaigns") == []

    # This release hashes the edges too, so the row is written once.
    monkeypatch.setattr(service, "_detail", real)
    with _Statements(maker) as seen:
        async with maker() as db:
            await service.rebuild(db)
    assert seen.writes("campaigns")
    async with maker() as db:
        (after,) = await _campaigns(db)
    assert after.id == before.id
    assert after.detail["hash"] != before.detail["hash"]
    assert [e["runs"] for e in after.detail["edges"]] == [3]

    # NEGATIVE CONTROL: the next rebuild with no change writes nothing.
    with _Statements(maker) as seen:
        async with maker() as db:
            await service.rebuild(db)
    assert seen.writes("campaigns") == []


async def test_get_campaign_of_an_unknown_id_is_none(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    async with maker() as db:
        assert await service.get_campaign(db, 404) is None


def test_the_plan_of_ids_takes_the_seed_campaign_then_the_lowest_free_one() -> None:
    drafts = build_campaigns([run("r1", 0.0), run("r2", 1.0)])
    (draft,) = drafts
    # The seed run is in campaign 7, so the draft takes 7. Campaign 3 merges into it.
    plan = service.plan_ids(drafts, {"r1": 7, "r2": 3}, [3, 7, 9])
    assert plan.taken == (7,)
    assert plan.merged == {3: 0}
    assert plan.withdrawn == (9,)
    assert draft.seed_run_id == "r1"
    # A draft whose members hold no campaign gets a new row.
    assert service.plan_ids(drafts, {}, []).taken == (None,)


# ── Review fixes: write lock, freshness, unchanged rows, stable ids ─────────


class _Statements:
    """The SQL statements that the engine of a session maker runs, in upper case."""

    def __init__(self, maker: async_sessionmaker[AsyncSession]) -> None:
        self.engine = maker.kw["bind"]
        self.seen: list[str] = []

    def __enter__(self) -> _Statements:
        event.listen(self.engine.sync_engine, "before_cursor_execute", self._add)
        return self

    def __exit__(self, *_exc: object) -> None:
        event.remove(self.engine.sync_engine, "before_cursor_execute", self._add)

    def _add(self, _conn: Any, _cursor: Any, statement: str, *_args: Any) -> None:
        self.seen.append(" ".join(statement.split()).upper())

    def writes(self, table: str) -> list[str]:
        name = table.upper()
        heads = (f"INSERT INTO {name} ", f"DELETE FROM {name} ", f"UPDATE {name} ")
        return [s for s in self.seen if s.startswith(heads)]


async def test_the_rebuild_reads_with_no_write_lock_and_builds_off_the_event_loop(
    maker: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    async with maker() as db:
        await _three_runs(db)
    path = maker.kw["bind"].url.database
    real = service.build_campaigns
    seen: dict[str, Any] = {}

    def probe(runs: Any, **kwargs: Any) -> Any:
        # A second writer while the engine runs: the review saw "database is locked".
        seen["main_thread"] = threading.current_thread() is threading.main_thread()
        con = sqlite3.connect(path, timeout=0.2)
        try:
            con.execute("UPDATE investigations SET rationale = rationale")
            con.commit()
            seen["write"] = "ok"
        except sqlite3.OperationalError as exc:
            seen["write"] = str(exc)
        finally:
            con.close()
        return real(runs, **kwargs)

    monkeypatch.setattr(service, "build_campaigns", probe)
    async with maker() as db:
        result = await service.rebuild(db)
    assert seen == {"main_thread": False, "write": "ok"}
    assert (result.campaigns, result.members) == (1, 3)
    async with maker() as db:
        assert await _count(db, Campaign) == 1
        assert await _count(db, CampaignRunFacts) == 3


async def test_ensure_fresh_rebuilds_for_a_true_positive_change_and_a_member_session_only(
    maker: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    real = service.rebuild
    calls: list[int] = []

    async def spy(db: AsyncSession, **kwargs: Any) -> service.RebuildResult:
        calls.append(1)
        return await real(db, **kwargs)

    monkeypatch.setattr(service, "rebuild", spy)

    async def fresh() -> int:
        for _ in range(2):
            async with maker() as db:
                assert await service.ensure_fresh(db) is True
        return len(calls)

    async with maker() as db:
        await seed_hosts(db)
        first = await seed_run(
            db, "alert-0001", community_id="1:sess", event_hours_ago=3, created_minutes_ago=50
        )
        second = await seed_run(db, "alert-0002", event_hours_ago=2, created_minutes_ago=40)
    # The first call of the process rebuilds.
    assert await fresh() == 1

    # A false positive on no member session: no rebuild.
    async with maker() as db:
        await seed_run(
            db,
            "alert-0050",
            src=OUTSIDE,
            dst=TARGET_2,
            verdict="false_positive",
            community_id="1:other",
        )
    assert await fresh() == 1

    async with maker() as db:
        third = await seed_run(db, "alert-0003", event_hours_ago=1, created_minutes_ago=5)
    assert await fresh() == 2

    async with maker() as db:
        await inv_svc.resolve(
            db,
            second,
            verdict="false_positive",
            confidence=0.9,
            rationale="The upload was a test.",
            recommended_actions=None,
            resolved_by="analyst",
            resolved_via="manual",
        )
    assert await fresh() == 3

    async with maker() as db:
        await db.execute(
            delete(InvestigationEvent).where(InvestigationEvent.investigation_id == third)
        )
        await db.execute(delete(Investigation).where(Investigation.id == third))
        await db.commit()
    assert await fresh() == 4

    # A new run on a member session.
    async with maker() as db:
        await seed_run(
            db,
            "alert-0060",
            src=TARGET,
            dst=OUTSIDE,
            verdict="false_positive",
            community_id="1:sess",
            event_hours_ago=2.9,
        )
    assert await fresh() == 5

    # A Re-run with another verdict and no session replaces a true positive.
    async with maker() as db:
        await seed_run(db, "alert-0001", verdict="false_positive", created_minutes_ago=1)
    assert await fresh() == 6
    async with maker() as db:
        assert first not in {
            str(r) for r in (await db.scalars(select(CampaignMember.run_id))).all()
        }


async def test_a_second_rebuild_with_no_change_writes_no_member_or_party_row(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    async with maker() as db:
        await _three_runs(db)
        await service.rebuild(db)
    async with maker() as db:
        (before,) = await _campaigns(db)
    with _Statements(maker) as seen:
        async with maker() as db:
            await service.rebuild(db)
    assert seen.writes("campaign_members") == []
    assert seen.writes("campaign_parties") == []
    assert seen.writes("campaigns") == []
    async with maker() as db:
        (after,) = await _campaigns(db)
    assert after.built_at == before.built_at
    assert after.detail["hash"] == before.detail["hash"]

    # A new member changes the content: the rows are written again.
    async with maker() as db:
        await seed_run(db, "alert-0004", event_hours_ago=0.5, created_minutes_ago=2)
    with _Statements(maker) as seen:
        async with maker() as db:
            await service.rebuild(db)
    assert seen.writes("campaign_members")
    async with maker() as db:
        (changed,) = await _campaigns(db)
    assert changed.id == before.id
    assert changed.detail["hash"] != before.detail["hash"]
    assert changed.member_count == 4


async def test_a_rerun_of_the_only_member_keeps_the_campaign_id(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    async with maker() as db:
        await seed_hosts(db)
        await seed_run(db, "alert-a", created_minutes_ago=50)
        await service.rebuild(db)
    async with maker() as db:
        (campaign,) = await _campaigns(db)
        new = await seed_run(db, "alert-a", created_minutes_ago=5)
        result = await service.rebuild(db)
    assert (result.created, result.withdrawn, result.merged) == (0, 0, 0)
    async with maker() as db:
        (after,) = await _campaigns(db)
        assert (after.id, after.status) == (campaign.id, "active")
        assert await _members(db, after.id) == {new: "seed"}


async def test_an_override_away_and_back_revives_the_withdrawn_campaign(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    async with maker() as db:
        await seed_hosts(db)
        run_id = await seed_run(db, "alert-a")
        await service.rebuild(db)
    async with maker() as db:
        (campaign,) = await _campaigns(db)
    for verdict, status in (("false_positive", "withdrawn"), ("true_positive", "active")):
        async with maker() as db:
            await inv_svc.resolve(
                db,
                run_id,
                verdict=verdict,
                confidence=0.9,
                rationale="The analyst changed the verdict.",
                recommended_actions=None,
                resolved_by="analyst",
                resolved_via="manual",
            )
            await service.rebuild(db)
        async with maker() as db:
            (after,) = await _campaigns(db)
            assert (after.id, after.status, after.merged_into_id) == (campaign.id, status, None)
    async with maker() as db:
        assert await _members(db, campaign.id) == {run_id: "seed"}


async def test_two_merged_campaigns_stay_merged_when_a_member_is_rerun(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    async with maker() as db:
        await seed_hosts(db)
        first = await seed_run(db, "alert-a", event_hours_ago=10, created_minutes_ago=50)
        await seed_run(
            db,
            "alert-b",
            src=ACTOR_2,
            dst=TARGET_2,
            rule=RULE_B,
            event_hours_ago=8,
            created_minutes_ago=45,
        )
        await service.rebuild(db)
        link = await seed_run(
            db, "alert-c", dst=TARGET_2, rule=RULE_B, event_hours_ago=1, created_minutes_ago=40
        )
        await service.rebuild(db)
    async with maker() as db:
        older, newer = await _campaigns(db)
        assert (newer.status, newer.merged_into_id) == ("merged", older.id)
        rerun = await seed_run(
            db,
            "alert-b",
            src=ACTOR_2,
            dst=TARGET_2,
            rule=RULE_B,
            event_hours_ago=8,
            created_minutes_ago=5,
        )
        result = await service.rebuild(db)
    assert (result.created, result.merged, result.withdrawn) == (0, 0, 0)
    async with maker() as db:
        kept, merged = await _campaigns(db)
        assert (kept.id, kept.status) == (older.id, "active")
        assert set(await _members(db, kept.id)) == {first, rerun, link}
        assert (merged.id, merged.status, merged.merged_into_id) == (newer.id, "merged", older.id)


async def test_the_related_lists_read_in_chunks_and_hold_the_50_newest(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    now = utcnow()
    others = [f"203.0.113.{n}" for n in range(1, 255)]
    async with maker() as db:
        db.add_all(
            [
                Investigation(
                    id=f"01NMI{n:021d}",
                    alert_es_id=f"nmi-{n}",
                    status="complete",
                    verdict="needs_more_info",
                    rule_name="ET INFO Example Probe",
                    src_ip=ACTOR,
                    dest_ip=TARGET,
                    created_at=now - timedelta(minutes=n),
                    finished_at=now - timedelta(minutes=n),
                )
                for n in range(55)
            ]
        )
        for n, dest in enumerate((OUTSIDE, ACTOR, None)):
            db.add(
                Investigation(
                    id=f"01FPR{n:021d}",
                    alert_es_id=f"fp-{n}",
                    status="complete",
                    verdict="false_positive",
                    src_ip=TARGET,
                    dest_ip=dest,
                    created_at=now,
                    finished_at=now,
                )
            )
        await db.commit()
        related = await service._needs_more_info(db, [ACTOR, TARGET, *others], {f"01NMI{0:021d}"})
        count = await service._false_positives_from(db, [TARGET, *others], [ACTOR, TARGET, *others])
    assert [r.run_id for r in related] == [f"01NMI{n:021d}" for n in range(1, 51)]
    # To a host that is no party, and to no host. The run to the actor does not count.
    assert count == 2


async def test_the_member_count_holds_only_the_true_positive_members(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    async with maker() as db:
        await seed_hosts(db)
        await seed_run(db, "alert-0001", community_id="1:sess", event_hours_ago=2)
        await seed_run(
            db,
            "alert-0002",
            src=TARGET,
            dst=OUTSIDE,
            verdict="false_positive",
            community_id="1:sess",
            event_hours_ago=1.9,
        )
        await service.rebuild(db)
    async with maker() as db:
        (campaign,) = await _campaigns(db)
        assert len(await _members(db, campaign.id)) == 2
        assert campaign.member_count == 1
        (row,) = await service.list_campaigns(db)
    assert row.members == 1


# ── Events ─────────────────────────────────────────────────────────────────


class _Grid:
    """A grid with one canned answer, or an error. Counts the searches."""

    def __init__(self, answer: EsSearchResult | None = None, *, delay: float = 0.0) -> None:
        self.answer = answer
        self.delay = delay
        self.calls = 0

    async def search(self, index: str, query: dict[str, Any], **kwargs: Any) -> EsSearchResult:
        self.calls += 1
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.answer is None:
            raise ConnectionError("the grid refused the connection")
        return self.answer


def _grid_answer(alerts: int = 40) -> EsSearchResult:
    stamp = utcnow()
    when = {"value": stamp.replace(tzinfo=UTC).timestamp() * 1000}
    return EsSearchResult(
        total=alerts,
        took_ms=2,
        aggregations={
            "pairs": {
                "buckets": {
                    "0": {
                        "doc_count": alerts,
                        "alerts": {
                            "doc_count": alerts,
                            "by_rule": {
                                "buckets": [
                                    {"key": RULE, "doc_count": alerts, "first": when, "last": when}
                                ]
                            },
                        },
                    }
                }
            },
            "confirmed": {"buckets": {"0": {"doc_count": alerts}}},
        },
    )


async def _built(maker: async_sessionmaker[AsyncSession]) -> int:
    async with maker() as db:
        await _three_runs(db)
        await service.rebuild(db)
    async with maker() as db:
        (campaign,) = await _campaigns(db)
        return campaign.id


async def _refresh(
    maker: async_sessionmaker[AsyncSession],
    campaign_id: int,
    grid: _Grid,
    settings: Settings,
    now: datetime,
) -> Campaign:
    async with maker() as db:
        await service.refresh_events(db, campaign_id, grid, settings, now=now)  # type: ignore[arg-type]
    async with maker() as db:
        row = await db.get(Campaign, campaign_id)
        assert row is not None
        return row


async def test_refresh_events_reads_once_and_again_after_15_minutes_of_an_open_campaign(
    maker: async_sessionmaker[AsyncSession], settings_kratos: Settings
) -> None:
    campaign_id = await _built(maker)
    grid = _Grid(_grid_answer())
    now = utcnow()
    row = await _refresh(maker, campaign_id, grid, settings_kratos, now)
    assert grid.calls == 1
    assert row.events is not None
    assert (row.events["source"], row.events["alerts"], row.events_at) == ("grid", 40, now)
    assert row.events_basis is not None and len(row.events_basis) == 40
    await _refresh(maker, campaign_id, grid, settings_kratos, now + timedelta(minutes=10))
    assert grid.calls == 1
    await _refresh(maker, campaign_id, grid, settings_kratos, now + timedelta(minutes=16))
    assert grid.calls == 2
    async with maker() as db:
        view = await service.get_campaign(db, campaign_id)
    assert view is not None
    assert (view.events.source, view.events.alerts, view.events.findings) == ("grid", 40, 0)


async def test_refresh_events_reads_again_when_a_new_true_positive_changes_the_basis(
    maker: async_sessionmaker[AsyncSession], settings_kratos: Settings
) -> None:
    campaign_id = await _built(maker)
    grid = _Grid(_grid_answer())
    now = utcnow()
    before = await _refresh(maker, campaign_id, grid, settings_kratos, now)
    async with maker() as db:
        await seed_run(db, "alert-0009", rule=RULE_B, event_hours_ago=0.5, created_minutes_ago=1)
        await service.rebuild(db)
    # The rebuild leaves the stored events as they are.
    async with maker() as db:
        held = await db.get(Campaign, campaign_id)
        assert held is not None
        assert (held.events, held.events_basis) == (before.events, before.events_basis)
    after = await _refresh(maker, campaign_id, grid, settings_kratos, now + timedelta(minutes=1))
    assert grid.calls == 2
    assert after.events_basis != before.events_basis


async def test_refresh_events_never_reads_an_ended_campaign_that_has_grid_events(
    maker: async_sessionmaker[AsyncSession], settings_kratos: Settings
) -> None:
    campaign_id = await _built(maker)
    grid = _Grid(_grid_answer())
    now = utcnow()
    await _refresh(maker, campaign_id, grid, settings_kratos, now)
    later = now + timedelta(days=30)
    row = await _refresh(maker, campaign_id, grid, settings_kratos, later)
    assert grid.calls == 1
    async with maker() as db:
        view = await service.get_campaign(db, campaign_id, now=later)
    assert view is not None
    assert (view.status, view.events.source, view.events.alerts) == ("ended", "grid", 40)
    assert row.events_at == now
    # NEGATIVE CONTROL: an ended campaign with no stored grid events reads once.
    async with maker() as db:
        held = await db.get(Campaign, campaign_id)
        assert held is not None
        held.events, held.events_at, held.events_basis = None, None, None
        await db.commit()
    await _refresh(maker, campaign_id, grid, settings_kratos, later)
    assert grid.calls == 2


async def test_refresh_events_keeps_the_stored_events_when_the_grid_fails(
    maker: async_sessionmaker[AsyncSession],
    settings_kratos: Settings,
    caplog: pytest.LogCaptureFixture,
) -> None:
    campaign_id = await _built(maker)
    now = utcnow()
    before = await _refresh(maker, campaign_id, _Grid(_grid_answer()), settings_kratos, now)
    async with maker() as db:
        await seed_run(db, "alert-0009", rule=RULE_B, event_hours_ago=0.5, created_minutes_ago=1)
        await service.rebuild(db)
    broken = _Grid()
    with caplog.at_level(logging.WARNING, logger="soc_ai.campaigns.events"):
        after = await _refresh(maker, campaign_id, broken, settings_kratos, now)
    assert broken.calls == 1
    assert (after.events, after.events_at, after.events_basis) == (
        before.events,
        before.events_at,
        before.events_basis,
    )
    assert [r.name for r in caplog.records if r.levelno == logging.WARNING] == [
        "soc_ai.campaigns.events"
    ]
    # The read of the new basis failed: the page keeps the older grid events.
    async with maker() as db:
        view = await service.get_campaign(db, campaign_id)
    assert view is not None
    assert (view.events.source, view.events.alerts) == ("grid", 40)
    # NEGATIVE CONTROL: with no failed read on record, a stale basis gives the stored events.
    service.reset_fresh_cache()
    async with maker() as db:
        view = await service.get_campaign(db, campaign_id)
    assert view is not None
    assert (view.events.source, view.events.alerts) == ("stored", 4)


async def test_two_refreshes_at_once_read_the_grid_once(
    maker: async_sessionmaker[AsyncSession], settings_kratos: Settings
) -> None:
    campaign_id = await _built(maker)
    grid = _Grid(_grid_answer(), delay=0.05)
    now = utcnow()

    async def one() -> None:
        async with maker() as db:
            await service.refresh_events(db, campaign_id, grid, settings_kratos, now=now)  # type: ignore[arg-type]

    await asyncio.gather(one(), one())
    assert grid.calls == 1


async def test_get_campaign_gives_the_stored_events_with_no_grid_read(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    campaign_id = await _built(maker)
    async with maker() as db:
        view = await service.get_campaign(db, campaign_id)
        (row,) = await service.list_campaigns(db)
    assert view is not None
    events = view.events
    assert (events.source, events.read_at, events.alerts, events.rules) == ("stored", None, 3, 1)
    (pair,) = events.pairs
    assert (pair.source, pair.target, pair.alerts, pair.records) == ("agent:a1", "ip:t1", 3, None)
    assert [(r.name, r.verdict) for r in pair.rules] == [(RULE, "true_positive")]
    # The list row counts grid alerts only: no read stored any.
    assert row.alerts is None


async def test_a_merged_campaign_has_no_events(maker: async_sessionmaker[AsyncSession]) -> None:
    campaign_id = await _built(maker)
    async with maker() as db:
        held = await db.get(Campaign, campaign_id)
        assert held is not None
        held.status = "withdrawn"
        await db.commit()
    async with maker() as db:
        view = await service.get_campaign(db, campaign_id)
    assert view is not None
    assert (view.events.source, view.events.pairs) == ("none", ())


# ── A Re-run in progress (S2) ──────────────────────────────────────────────


async def _rerun(db: AsyncSession, alert_id: str, *, status: str, **finish: Any) -> str:
    """A Re-run of the alert, newer than every seeded run. ``status`` running stays open."""
    inv = await inv_svc.create(db, alert_es_id=alert_id, started_by="analyst")
    if status != "running":
        await inv_svc.finalize(db, inv.id, status=status, **finish)
    return str(inv.id)


async def test_a_rerun_in_progress_keeps_the_campaign_its_id_and_its_member(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    async with maker() as db:
        await seed_hosts(db)
        old = await seed_run(db, "alert-a", created_minutes_ago=50)
        await service.rebuild(db)
    async with maker() as db:
        (campaign,) = await _campaigns(db)
        rerun = await _rerun(db, "alert-a", status="running")
        result = await service.rebuild(db)
    assert (result.campaigns, result.withdrawn, result.created) == (1, 0, 0)
    async with maker() as db:
        (after,) = await _campaigns(db)
        assert (after.id, after.status) == (campaign.id, "active")
        assert await _members(db, after.id) == {old: "seed"}
        assert rerun not in await _members(db, after.id)
        # The shared rule is unchanged: the confirmed threats read the running
        # Re-run as the run of its alert, so the old run stands there no more.
        runs, _total = await inv_svc.standing_true_positives(db, since=datetime.min, until=utcnow())
        assert old not in {inv.id for inv in runs}


async def test_a_rerun_in_progress_changes_no_basis_so_ensure_fresh_skips_the_rebuild(
    maker: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    async with maker() as db:
        await seed_hosts(db)
        await seed_run(db, "alert-a", created_minutes_ago=50)
        assert await service.ensure_fresh(db)
    calls: list[int] = []
    real = service.rebuild

    async def counted(db: AsyncSession, **kw: Any) -> service.RebuildResult:
        calls.append(1)
        return await real(db, **kw)

    monkeypatch.setattr(service, "rebuild", counted)
    async with maker() as db:
        await _rerun(db, "alert-a", status="running")
        assert await service.ensure_fresh(db)
    assert calls == []


async def test_a_rerun_that_completes_with_another_verdict_changes_the_campaign(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    async with maker() as db:
        await seed_hosts(db)
        first = await seed_run(db, "alert-a", event_hours_ago=3, created_minutes_ago=50)
        old = await seed_run(db, "alert-b", event_hours_ago=2, created_minutes_ago=40)
        await service.rebuild(db)
    async with maker() as db:
        (campaign,) = await _campaigns(db)
        assert set(await _members(db, campaign.id)) == {first, old}
        await _rerun(
            db,
            "alert-b",
            status="complete",
            verdict="false_positive",
            report={"verdict": "false_positive", "recommended_actions": []},
        )
        await service.rebuild(db)
    async with maker() as db:
        (after,) = await _campaigns(db)
        assert after.id == campaign.id
        assert set(await _members(db, after.id)) == {first}


async def test_a_rerun_that_completes_with_a_false_positive_withdraws_a_one_member_campaign(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    async with maker() as db:
        await seed_hosts(db)
        await seed_run(db, "alert-a", created_minutes_ago=50)
        await service.rebuild(db)
        await _rerun(
            db,
            "alert-a",
            status="complete",
            verdict="false_positive",
            report={"verdict": "false_positive", "recommended_actions": []},
        )
        result = await service.rebuild(db)
    assert (result.campaigns, result.withdrawn) == (0, 1)


@pytest.mark.parametrize(
    ("status", "finish"),
    [
        ("error", {}),
        ("cancelled", {}),
        (
            "complete",
            {
                "verdict": "needs_more_info",
                "report": {
                    "verdict": "needs_more_info",
                    "resolution": {"provenance": "pipeline_fallback"},
                },
            },
        ),
    ],
    ids=["error", "cancelled", "pipeline-fallback"],
)
async def test_a_rerun_that_ends_in_an_error_keeps_the_campaign(
    maker: async_sessionmaker[AsyncSession], status: str, finish: dict[str, Any]
) -> None:
    async with maker() as db:
        await seed_hosts(db)
        old = await seed_run(db, "alert-a", created_minutes_ago=50)
        await service.rebuild(db)
    async with maker() as db:
        (campaign,) = await _campaigns(db)
        await _rerun(db, "alert-a", status=status, **finish)
        result = await service.rebuild(db)
    assert (result.campaigns, result.withdrawn) == (1, 0)
    async with maker() as db:
        (after,) = await _campaigns(db)
        assert (after.id, after.status) == (campaign.id, "active")
        assert await _members(db, after.id) == {old: "seed"}


async def test_a_finding_rerun_in_progress_keeps_the_finding_in_its_campaign(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    async with maker() as db:
        await seed_hosts(db)
        old = await seed_run(db, "", finding=("hunt-1", 0), created_minutes_ago=50)
        await service.rebuild(db)
    async with maker() as db:
        (campaign,) = await _campaigns(db)
        await inv_svc.create(
            db,
            alert_es_id="",
            started_by="analyst",
            kind="hunt",
            hunt_id="hunt-1",
            finding_ordinal=0,
            subject={"type": "hunt", "judges": "finding", "hunt_id": "hunt-1"},
        )
        await service.rebuild(db)
    async with maker() as db:
        (after,) = await _campaigns(db)
        assert (after.id, after.status) == (campaign.id, "active")
        assert await _members(db, after.id) == {old: "seed"}
