"""Every page that shows an investigation names its campaign (S3).

The owner decided on 2026-11-14 that the campaign is the unit of work of
the analyst. No page other than the campaign pages knew that a campaign
exists. ``campaign_svc.links_of`` reads the campaign of each investigation
of a page in one read, from the members of the active campaigns. Four
payloads carry it as ``campaign``: the rows of ``GET /investigations``, the
investigation page, the groups of ``GET /alerts`` and the investigation of a
hunt finding.

The negative controls: an investigation in no campaign has ``campaign``
null, and a withdrawn or a merged campaign gives no link.

The data is synthetic: placeholder addresses, names and rule names.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.campaigns import service as campaign_svc
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.store import investigations as inv_svc
from soc_ai.store.auth import utcnow
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import Campaign, CampaignMember, CampaignParty
from soc_ai.webui.alerts_query import AlertGroup, GroupPage
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.test_campaign_facts import (
    ACTOR_2,
    HUNT_ID,
    OUTSIDE,
    RULE,
    RULE_B,
    TARGET_2,
    seed_hosts,
    seed_hunt,
    seed_run,
)

LINK_KEYS = {"id", "title", "status", "stage", "differs", "decision"}
_FLOW = "1:flow-of-the-seed"


@pytest.fixture
async def maker(settings_kratos: Settings) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    try:
        yield make_sessionmaker(engine)
    finally:
        await engine.dispose()


async def _campaigns(db: AsyncSession) -> list[Campaign]:
    return list((await db.scalars(select(Campaign).order_by(Campaign.id))).all())


# ── links_of ───────────────────────────────────────────────────────────────


async def test_links_of_names_the_campaign_of_a_member_and_nothing_for_another_run(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    async with maker() as db:
        await seed_hosts(db)
        member = await seed_run(db, "alert-a", community_id=_FLOW)
        differs = await seed_run(
            db, "alert-b", verdict="false_positive", community_id=_FLOW, created_minutes_ago=20
        )
        alone = await seed_run(
            db, "alert-c", src=OUTSIDE, dst=OUTSIDE, verdict="false_positive", rule=RULE_B
        )
        await campaign_svc.rebuild(db)
    async with maker() as db:
        (campaign,) = await _campaigns(db)
        links = await campaign_svc.links_of(db, [member, differs, alone, "no-such-run"])
    assert set(links) == {member, differs}
    link = links[member]
    assert (link.id, link.title, link.stage) == (campaign.id, campaign.title, campaign.stage)
    assert link.status == "open"
    assert link.differs is False
    assert links[differs].differs is True


async def test_links_of_reads_a_long_list_of_ids_in_chunks(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    async with maker() as db:
        await seed_hosts(db)
        member = await seed_run(db, "alert-a")
        await campaign_svc.rebuild(db)
    async with maker() as db:
        ids = [f"other-{n:05d}" for n in range(2500)] + [member]
        links = await campaign_svc.links_of(db, ids)
    assert set(links) == {member}


async def test_links_of_gives_no_link_for_a_withdrawn_campaign(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    async with maker() as db:
        await seed_hosts(db)
        run_id = await seed_run(db, "alert-a")
        await campaign_svc.rebuild(db)
        assert set(await campaign_svc.links_of(db, [run_id])) == {run_id}
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
        await campaign_svc.rebuild(db)
    async with maker() as db:
        (campaign,) = await _campaigns(db)
        assert campaign.status == "withdrawn"
        assert await campaign_svc.links_of(db, [run_id]) == {}


async def test_links_of_gives_no_link_for_a_merged_campaign_and_names_the_campaign_that_holds_it(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    async with maker() as db:
        await seed_hosts(db)
        first = await seed_run(db, "alert-a", event_hours_ago=10, created_minutes_ago=50)
        second = await seed_run(
            db,
            "alert-b",
            src=ACTOR_2,
            dst=TARGET_2,
            rule=RULE_B,
            event_hours_ago=8,
            created_minutes_ago=45,
        )
        await campaign_svc.rebuild(db)
        await seed_run(
            db, "alert-c", dst=TARGET_2, rule=RULE_B, event_hours_ago=1, created_minutes_ago=40
        )
        await campaign_svc.rebuild(db)
    async with maker() as db:
        older, newer = await _campaigns(db)
        assert (newer.status, newer.merged_into_id) == ("merged", older.id)
        links = await campaign_svc.links_of(db, [first, second])
    assert {link.id for link in links.values()} == {older.id}


async def test_links_of_states_an_ended_campaign(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    async with maker() as db:
        await seed_hosts(db)
        run_id = await seed_run(db, "alert-a")
        await campaign_svc.rebuild(db)
        (campaign,) = await _campaigns(db)
        later = campaign.last_event.replace(year=campaign.last_event.year + 1)
        links = await campaign_svc.links_of(db, [run_id], now=later)
    assert links[run_id].status == "ended"


# ── The four payloads ──────────────────────────────────────────────────────


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=AsyncMock()),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=settings_kratos),
    ):
        app = create_app()
        with TestClient(app) as test_client:
            yield test_client


def _do(client: TestClient, work: Any) -> Any:
    async def go() -> Any:
        async with client.app.state.db_sessionmaker() as db:
            return await work(db)

    return asyncio.run(go())


def _seed_member_and_other(client: TestClient) -> tuple[str, str, dict[str, Any]]:
    """One campaign of one true positive, and a false positive in no campaign."""

    async def work(db: Any) -> tuple[str, str, dict[str, Any]]:
        await seed_hosts(db)
        member = await seed_run(db, "alert-a")
        other = await seed_run(
            db, "alert-z", src=OUTSIDE, dst=OUTSIDE, rule=RULE_B, verdict="false_positive"
        )
        await campaign_svc.rebuild(db)
        (row,) = await _campaigns(db)
        expect = {
            "id": row.id,
            "title": row.title,
            "status": "open",
            "stage": row.stage,
            "differs": False,
            "decision": None,
        }
        return member, other, expect

    out: tuple[str, str, dict[str, Any]] = _do(client, work)
    return out


def test_the_investigations_list_names_the_campaign_of_a_member_row(
    client: TestClient,
) -> None:
    member, other, expect = _seed_member_and_other(client)
    res = client.get("/api/v1/investigations")
    assert res.status_code == 200, res.text
    rows = {row["id"]: row for row in res.json()["rows"]}
    assert set(rows[member]["campaign"]) == LINK_KEYS
    assert rows[member]["campaign"] == expect
    assert rows[other]["campaign"] is None


def test_the_investigation_page_names_its_campaign(client: TestClient) -> None:
    member, other, expect = _seed_member_and_other(client)
    res = client.get(f"/api/v1/investigations/{member}")
    assert res.status_code == 200, res.text
    assert res.json()["campaign"] == expect
    res = client.get(f"/api/v1/investigations/{other}")
    assert res.status_code == 200, res.text
    assert res.json()["campaign"] is None


def _groups(client: TestClient, *rules: str) -> dict[str, dict[str, Any]]:
    page = GroupPage(
        [
            AlertGroup(
                rule_name=rule,
                count=2,
                severity="high",
                latest_ts=datetime.now(UTC).isoformat(),
                latest_id=f"latest-{n}",
            )
            for n, rule in enumerate(rules)
        ],
        2 * len(rules),
    )
    with patch("soc_ai.webui.alerts_query.fetch_groups", AsyncMock(return_value=page)):
        res = client.get("/api/v1/alerts", params={"range": "24h"})
    assert res.status_code == 200, res.text
    return {group["name"]: group for group in res.json()["groups"]}


def test_an_alert_group_names_the_campaign_of_its_verdict_investigation(
    client: TestClient,
) -> None:
    member, other, expect = _seed_member_and_other(client)
    groups = _groups(client, RULE, RULE_B, "ET POLICY A rule nobody investigated")
    assert groups[RULE]["invId"] == member
    assert groups[RULE]["campaign"] == expect
    assert groups[RULE_B]["invId"] == other
    assert groups[RULE_B]["campaign"] is None
    assert groups["ET POLICY A rule nobody investigated"]["campaign"] is None


def test_a_hunt_finding_names_the_campaign_of_its_investigation(client: TestClient) -> None:
    async def work(db: Any) -> tuple[str, dict[str, Any]]:
        await seed_hosts(db)
        await seed_hunt(
            db,
            report={
                "findings": [
                    {"title": "An upload to web-1", "detail": "The actor sent an upload."},
                    {"title": "A quiet finding", "detail": "Nothing came of it."},
                ]
            },
        )
        member = await seed_run(db, "", finding=(HUNT_ID, 0))
        await campaign_svc.rebuild(db)
        (row,) = await _campaigns(db)
        return member, {
            "id": row.id,
            "title": row.title,
            "status": "open",
            "stage": row.stage,
            "differs": False,
            "decision": None,
        }

    member, expect = _do(client, work)
    res = client.get(f"/api/v1/hunts/{HUNT_ID}")
    assert res.status_code == 200, res.text
    first, second = res.json()["findings"]
    assert first["investigation"]["id"] == member
    assert first["investigation"]["campaign"] == expect
    assert second["investigation"] is None


def test_a_withdrawn_campaign_gives_null_on_every_payload(client: TestClient) -> None:
    member, _other, _expect = _seed_member_and_other(client)

    async def withdraw(db: Any) -> None:
        await inv_svc.resolve(
            db,
            member,
            verdict="false_positive",
            confidence=0.9,
            rationale="The upload was a scheduled test.",
            recommended_actions=None,
            resolved_by="analyst",
            resolved_via="manual",
        )
        await campaign_svc.rebuild(db)

    _do(client, withdraw)
    rows = {row["id"]: row for row in client.get("/api/v1/investigations").json()["rows"]}
    assert rows[member]["campaign"] is None
    assert client.get(f"/api/v1/investigations/{member}").json()["campaign"] is None
    assert _groups(client, RULE)[RULE]["campaign"] is None


# ── The host page (S4) ─────────────────────────────────────────────────────

HOST_KEYS = LINK_KEYS | {"role", "firstEvent", "lastEvent", "alerts"}


async def _stored_campaign(
    db: AsyncSession,
    *,
    title: str,
    hours_ago: float,
    parties: dict[str, str],
    members: list[tuple[str, str | None, str | None, bool]],
    status: str = "active",
) -> int:
    """One campaign row with its parties and members, written as a rebuild writes them."""
    last = utcnow() - timedelta(hours=hours_ago)
    row = Campaign(
        status=status,
        seed_run_id=members[0][0],
        title=title,
        bottom_line="An actor sent exploit requests.",
        stage="access",
        first_event=last - timedelta(hours=3),
        last_event=last,
        member_count=len(members),
        detail={},
        built_at=utcnow(),
        events={"source": "grid", "alerts": 1104},
    )
    db.add(row)
    await db.flush()
    for key, role in parties.items():
        db.add(
            CampaignParty(
                campaign_id=row.id,
                machine_key=key,
                role=role,
                addresses=[],
                member_runs=1,
                beyond=False,
            )
        )
    for run_id, actor, target, differs in members:
        db.add(
            CampaignMember(
                campaign_id=row.id,
                run_id=run_id,
                link="seed",
                evidence={},
                direction="inbound",
                verdict_differs=differs,
                actor_key=actor,
                target_key=target,
            )
        )
    await db.commit()
    return int(row.id)


async def test_the_campaigns_of_a_machine_state_its_role_newest_first(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    async with maker() as db:
        older = await _stored_campaign(
            db,
            title="actor-a against web-1",
            hours_ago=30,
            parties={"agent:a1": "actor", "ip:t1": "target"},
            members=[("r1", "agent:a1", "ip:t1", False)],
        )
        newer = await _stored_campaign(
            db,
            title="web-1 against web-2",
            hours_ago=2,
            parties={"ip:t1": "target", "ip:t2": "target", "agent:a2": "target"},
            members=[
                ("r2", "agent:a1", "ip:t1", False),
                ("r3", "ip:t1", "ip:t2", False),
                ("r4", "ip:t1", "agent:a2", True),
            ],
        )
        gone = await _stored_campaign(
            db,
            title="a withdrawn campaign",
            hours_ago=1,
            parties={"ip:t1": "target"},
            members=[("r5", "agent:a1", "ip:t1", False)],
            status="withdrawn",
        )
        on_t1 = await campaign_svc.campaigns_of_machine(db, ["ip:t1"])
        on_a1 = await campaign_svc.campaigns_of_machine(db, ["agent:a1"])
        on_a2 = await campaign_svc.campaigns_of_machine(db, ["agent:a2"])
        merged_key = await campaign_svc.campaigns_of_machine(db, ["ip:old", "ip:t2"])
        nothing = await campaign_svc.campaigns_of_machine(db, ["ip:none"])
    assert [c.id for c in on_t1] == [newer, older]
    assert gone not in {c.id for c in on_t1}
    # web-1 is a target that acts as a source in the newer campaign.
    assert [c.role for c in on_t1] == ["both", "target"]
    assert on_t1[0].alerts == 1104
    assert on_t1[0].status == "open"
    assert [c.role for c in on_a1] == ["actor"]
    # actor-b is a party only through a verdict that differs.
    assert [(c.role, c.differs) for c in on_a2] == [("target", True)]
    assert on_t1[0].differs is False
    assert [c.id for c in merged_key] == [newer]
    assert nothing == []


def test_the_host_page_lists_the_campaigns_of_the_machine(client: TestClient) -> None:
    member, _other, expect = _seed_member_and_other(client)
    actor = client.get("/api/v1/hosts/agent:a1")
    assert actor.status_code == 200, actor.text
    (row,) = actor.json()["campaigns"]
    assert set(row) == HOST_KEYS
    assert {k: row[k] for k in LINK_KEYS} == expect
    assert row["role"] == "actor"
    assert row["firstEvent"].endswith("+00:00") and row["lastEvent"].endswith("+00:00")
    target = client.get("/api/v1/hosts/ip:t1").json()["campaigns"]
    assert [c["role"] for c in target] == ["target"]
    # A machine in no campaign has an empty list.
    assert client.get("/api/v1/hosts/ip:t2").json()["campaigns"] == []
    assert member
