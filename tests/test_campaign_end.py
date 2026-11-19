"""The end of a campaign (round 4, E1 and E2).

The owner, 2026-11-19: "A later alert of a confirmed rule keeps a campaign
open." Production: campaign 2 had its last investigation event at 13:12 and
its last alert of a confirmed rule at 15:08. A later alert of the same rule
between the same machines takes its verdict from the earlier investigation,
so it moves no investigation event. The campaign ended one horizon after
13:12 while its alerts went on, and an ended campaign read the grid no more.

E1: an active campaign ends one horizon after its last activity, the later
of the last investigation event and the last alert event of a confirmed rule
that a grid read saw. Each reader of the status reads that one rule.

E2: a campaign must not end on a grid read that did not cover the horizon
after its last activity. The refresh step reads that horizon once more for
each ended campaign, the oldest end first.

The data is synthetic: placeholder addresses, names and rule names. Each
stored time is relative to now. The grid is a fake.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from soc_ai.campaigns import events, service
from soc_ai.campaigns.types import jsonable, naive_utc
from soc_ai.config import Settings
from soc_ai.hunting import campaign_block
from soc_ai.so_client.elastic import EsSearchResult
from soc_ai.store import rule_prior
from soc_ai.store.auth import utcnow
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import Campaign, CampaignMember
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.test_campaign_facts import ACTOR, TARGET
from tests.test_campaign_later_alerts import RecordingGrid, _refresh, _row, _when, grid_answer
from tests.test_campaign_service import _built

pytestmark = pytest.mark.asyncio

HORIZON = timedelta(hours=service.decay_horizon_hours())
OTHER_RULE = "Example Other Rule"


@pytest.fixture
async def maker(settings_kratos: Settings) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    try:
        yield make_sessionmaker(engine)
    finally:
        await engine.dispose()


def other_rule_answer(alerts: int, last: datetime) -> EsSearchResult:
    """One pair: ``alerts`` events of a rule that soc-ai did not confirm, the last at ``last``."""
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
                                    {
                                        "key": OTHER_RULE,
                                        "doc_count": alerts,
                                        "first": _when(last - timedelta(hours=1)),
                                        "last": _when(last),
                                    }
                                ]
                            },
                        },
                    }
                }
            },
            "confirmed": {"buckets": {"0": {"doc_count": 0}}},
        },
    )


async def statuses(
    maker: async_sessionmaker[AsyncSession], campaign_id: int, at: datetime
) -> set[str]:
    """The status of the campaign on each reader: the row, the list, the page, the links."""
    async with maker() as db:
        row = await db.get(Campaign, campaign_id)
        assert row is not None
        (listed,) = await service.list_campaigns(db, ids=[campaign_id], now=at)
        view = await service.get_campaign(db, campaign_id, now=at)
        assert view is not None
        run_id = await db.scalar(
            select(CampaignMember.run_id).where(CampaignMember.campaign_id == campaign_id)
        )
        links = await service.links_of(db, [str(run_id)], now=at)
        by_id = await service.links_by_id(db, [campaign_id], now=at)
        (host,) = await service.campaigns_of_machine(db, ["agent:a1"], now=at)
        found = {
            service.api_status(row, at),
            listed.status,
            view.status,
            links[str(run_id)].status,
            by_id[campaign_id].status,
            host.status,
        }
        # The SQL rule gives the same answer.
        held = await db.scalar(
            select(func.count(Campaign.id)).where(Campaign.id == campaign_id, service.open_sql(at))
        )
        found.add(service.STATUS_OPEN if held else service.STATUS_ENDED)
        return found


# ── E1: the end rule ───────────────────────────────────────────────────────


async def test_a_confirmed_rule_alert_keeps_the_campaign_open_past_the_horizon(
    maker: async_sessionmaker[AsyncSession], settings_kratos: Settings
) -> None:
    campaign_id = await _built(maker)
    now = utcnow()
    alert = now - timedelta(minutes=5)
    await _refresh(maker, campaign_id, RecordingGrid(grid_answer(23, alert)), settings_kratos, now)
    row = await _row(maker, campaign_id)
    # The grid read writes the two facts of the end rule.
    assert (row.last_alert_at, row.events_to) == (alert, now)
    past = row.last_event + HORIZON + timedelta(minutes=30)
    assert past - alert < HORIZON
    assert await statuses(maker, campaign_id, past) == {service.STATUS_OPEN}
    # The page states the last activity: the time of the alert.
    async with maker() as db:
        view = await service.get_campaign(db, campaign_id, now=past)
    assert view is not None and view.last_activity == alert
    # One horizon after the alert, the campaign ends.
    after = alert + HORIZON + timedelta(minutes=1)
    assert await statuses(maker, campaign_id, after) == {service.STATUS_ENDED}


async def test_an_alert_of_a_rule_that_soc_ai_did_not_confirm_keeps_nothing_open(
    maker: async_sessionmaker[AsyncSession], settings_kratos: Settings
) -> None:
    """NEGATIVE CONTROL: only a confirmed rule is activity of the campaign."""
    campaign_id = await _built(maker)
    now = utcnow()
    grid = RecordingGrid(other_rule_answer(40, now - timedelta(minutes=5)))
    await _refresh(maker, campaign_id, grid, settings_kratos, now)
    row = await _row(maker, campaign_id)
    assert row.events_at == now
    assert row.last_alert_at is None
    past = row.last_event + HORIZON + timedelta(minutes=30)
    assert await statuses(maker, campaign_id, past) == {service.STATUS_ENDED}


async def test_a_campaign_with_no_grid_read_ends_by_its_last_investigation_event(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    """NEGATIVE CONTROL: with no grid read the rule of today holds."""
    campaign_id = await _built(maker)
    row = await _row(maker, campaign_id)
    assert (row.last_alert_at, row.events_to) == (None, None)
    inside = row.last_event + HORIZON - timedelta(minutes=1)
    assert await statuses(maker, campaign_id, inside) == {service.STATUS_OPEN}
    outside = row.last_event + HORIZON + timedelta(minutes=1)
    assert await statuses(maker, campaign_id, outside) == {service.STATUS_ENDED}


async def test_the_open_selectors_read_the_last_alert(
    maker: async_sessionmaker[AsyncSession], settings_kratos: Settings
) -> None:
    """A rule prior and a hunt read the open campaigns by the same rule."""
    campaign_id = await _built(maker)
    now = utcnow()
    alert = now - timedelta(minutes=5)
    await _refresh(maker, campaign_id, RecordingGrid(grid_answer(23, alert)), settings_kratos, now)
    row = await _row(maker, campaign_id)
    past = row.last_event + HORIZON + timedelta(minutes=30)
    assert past - alert < HORIZON
    async with maker() as db:
        assert await rule_prior.in_open_campaign(db, [ACTOR, TARGET], now=past)
    blocks = await campaign_block.blocks_for_hunt(
        maker, scope=campaign_block.EVERY_CAMPAIGN, hours=24, now=past
    )
    assert [b.campaign_id for b in blocks] == [campaign_id]
    # NEGATIVE CONTROL: one horizon after the alert, neither reads it.
    gone = alert + HORIZON + timedelta(minutes=1)
    async with maker() as db:
        assert not await rule_prior.in_open_campaign(db, [ACTOR, TARGET], now=gone)
    blocks = await campaign_block.blocks_for_hunt(
        maker, scope=campaign_block.EVERY_CAMPAIGN, hours=24, now=gone
    )
    assert blocks == ()


# ── E2: the end check ──────────────────────────────────────────────────────


class EndGrid:
    """A grid that holds alert events of the confirmed rules at ``times``.

    It answers the window of the query of the end check: the count and the
    time of the last alert in it. ``fail`` refuses each search.
    """

    def __init__(self, times: list[datetime] | None = None, *, fail: bool = False) -> None:
        self.times = times or []
        self.fail = fail
        self.calls: list[dict[str, Any]] = []

    async def search(self, index: str, query: dict[str, Any], **kwargs: Any) -> EsSearchResult:
        self.calls.append({"query": query, **kwargs})
        if self.fail:
            raise ConnectionError("the grid refused the connection")
        window = query["bool"]["filter"][0]["range"]["@timestamp"]
        lo, hi = naive_utc(window["gt"]), naive_utc(window["lte"])
        assert lo is not None and hi is not None
        held = [t for t in self.times if lo < t <= hi]
        last = max(held, default=None)
        return EsSearchResult(
            total=len(held),
            took_ms=2,
            aggregations={
                "last": {"value": last.replace(tzinfo=UTC).timestamp() * 1000 if last else None}
            },
        )


def _end_window(call: dict[str, Any]) -> tuple[datetime | None, datetime | None]:
    held = call["query"]["bool"]["filter"][0]["range"]["@timestamp"]
    return naive_utc(held["gt"]), naive_utc(held["lte"])


async def _wake(
    maker: async_sessionmaker[AsyncSession], grid: Any, settings: Settings, at: datetime
) -> int:
    async with maker() as db:
        return await service.refresh_behind(db, grid, settings, now=at)


async def _read_once(
    maker: async_sessionmaker[AsyncSession], settings: Settings
) -> tuple[int, datetime]:
    """A campaign with one grid read: the last alert 5 minutes before the read."""
    campaign_id = await _built(maker)
    now = utcnow()
    alert = now - timedelta(minutes=5)
    await _refresh(maker, campaign_id, RecordingGrid(grid_answer(23, alert)), settings, now)
    return campaign_id, alert


async def test_the_end_check_finds_an_alert_inside_the_horizon_and_opens_the_campaign(
    maker: async_sessionmaker[AsyncSession], settings_kratos: Settings
) -> None:
    campaign_id, alert = await _read_once(maker, settings_kratos)
    # The read ended at the time of the read. One horizon after the alert the
    # campaign ends by E1, and the grid holds an alert that the read missed.
    at = alert + HORIZON + timedelta(hours=1)
    missed = at - timedelta(hours=3)
    assert await statuses(maker, campaign_id, at) == {service.STATUS_ENDED}
    grid = EndGrid([missed])
    assert await _wake(maker, grid, settings_kratos, at) == 1
    (call,) = grid.calls
    # The check reads after the last activity, one horizon.
    assert _end_window(call) == (alert, alert + HORIZON)
    assert call["size"] == 0
    # It counts every alert: no filter on the acknowledge state.
    assert "event.acknowledged" not in str(call["query"])
    row = await _row(maker, campaign_id)
    assert (row.last_alert_at, row.events_to) == (missed, alert + HORIZON)
    assert await statuses(maker, campaign_id, at) == {service.STATUS_OPEN}
    # The campaign is open, so the next wake reads its events to now.
    full = RecordingGrid(grid_answer(30, missed))
    assert await _wake(maker, full, settings_kratos, at + timedelta(minutes=1)) == 1
    (read,) = full.calls
    assert read["query"]["bool"]["filter"][0]["range"]["@timestamp"]["lte"] == (
        (at + timedelta(minutes=1)).isoformat() + "Z"
    )


async def test_an_alert_more_than_one_horizon_later_opens_nothing_and_the_check_ends(
    maker: async_sessionmaker[AsyncSession], settings_kratos: Settings
) -> None:
    """NEGATIVE CONTROL: the check reads one horizon only, and then no more."""
    campaign_id, alert = await _read_once(maker, settings_kratos)
    at = alert + HORIZON + timedelta(hours=2)
    late = alert + HORIZON + timedelta(minutes=30)
    grid = EndGrid([late])
    assert await _wake(maker, grid, settings_kratos, at) == 1
    row = await _row(maker, campaign_id)
    # No alert in the horizon: the read covers it, and the campaign stays ended.
    assert (row.last_alert_at, row.events_to) == (alert, alert + HORIZON)
    assert await statuses(maker, campaign_id, at) == {service.STATUS_ENDED}
    # A later wake asks for no read of that campaign.
    assert await _wake(maker, grid, settings_kratos, at + timedelta(days=3)) == 0
    assert len(grid.calls) == 1


async def test_an_alert_inside_the_horizon_but_long_ago_checks_the_next_horizon(
    maker: async_sessionmaker[AsyncSession], settings_kratos: Settings
) -> None:
    campaign_id, alert = await _read_once(maker, settings_kratos)
    at = alert + 3 * HORIZON
    found = alert + timedelta(hours=6)
    grid = EndGrid([found])
    assert await _wake(maker, grid, settings_kratos, at) == 1
    row = await _row(maker, campaign_id)
    assert (row.last_alert_at, row.events_to) == (found, alert + HORIZON)
    # The new last activity is more than one horizon old: still ended.
    assert await statuses(maker, campaign_id, at) == {service.STATUS_ENDED}
    # The next wake checks the horizon after the new last activity.
    assert await _wake(maker, grid, settings_kratos, at + timedelta(minutes=5)) == 1
    assert _end_window(grid.calls[-1]) == (found, found + HORIZON)
    row = await _row(maker, campaign_id)
    assert (row.last_alert_at, row.events_to) == (found, found + HORIZON)
    assert await _wake(maker, grid, settings_kratos, at + timedelta(minutes=10)) == 0
    assert len(grid.calls) == 2


async def test_a_grid_error_leaves_the_stored_state_and_the_status(
    maker: async_sessionmaker[AsyncSession], settings_kratos: Settings
) -> None:
    """NEGATIVE CONTROL: a grid that does not answer changes nothing."""
    campaign_id, alert = await _read_once(maker, settings_kratos)
    before = await _row(maker, campaign_id)
    at = alert + HORIZON + timedelta(hours=1)
    grid = EndGrid([at - timedelta(hours=3)], fail=True)
    assert await _wake(maker, grid, settings_kratos, at) == 1
    after = await _row(maker, campaign_id)
    held = ("last_alert_at", "events_to", "events_at", "events", "events_basis", "built_at")
    assert {k: getattr(after, k) for k in held} == {k: getattr(before, k) for k in held}
    assert await statuses(maker, campaign_id, at) == {service.STATUS_ENDED}
    # No hot loop: one read for each wake, and the next wake tries again.
    assert len(grid.calls) == 1
    assert await _wake(maker, grid, settings_kratos, at + timedelta(minutes=5)) == 1
    assert len(grid.calls) == 2


async def test_the_end_check_reads_a_campaign_with_a_read_of_an_earlier_release(
    maker: async_sessionmaker[AsyncSession], settings_kratos: Settings
) -> None:
    """A read of an earlier release holds no last alert time and no end of its window.

    Production campaigns 1 and 3 ended by the rule of an earlier release. The
    fill of migration 0076 gives the last alert time from the pairs, and no
    end of the window. The first wake reads the horizon after the last
    activity, so no one-time step exists.
    """
    campaign_id = await _built(maker)
    row = await _row(maker, campaign_id)
    alert = row.last_event - timedelta(minutes=20)
    pair = events.PairEvents(
        "agent:a1",
        "ip:t1",
        alerts=12,
        first_at=row.first_event,
        last_at=alert,
        rules=(
            events.RuleEvents(
                "ET EXPLOIT Example Upload Request (CVE-2026-0001)",
                12,
                row.first_event,
                alert,
                "true_positive",
            ),
        ),
    )
    stored = jsonable(events.CampaignEvents(source="grid", alerts=12, pairs=(pair,)))
    del stored["last_alert_at"]
    del stored["read_to"]
    async with maker() as db:
        held = await db.get(Campaign, campaign_id)
        assert held is not None
        held.events = stored
        held.events_at = row.last_event + timedelta(hours=1)
        held.events_basis = "an-earlier-basis"
        # The values of the fill of migration 0076.
        held.last_alert_at = events.last_alert_of(stored)
        held.events_to = None
        await db.commit()
    assert (await _row(maker, campaign_id)).last_alert_at == alert
    at = row.last_event + 2 * HORIZON
    grid = EndGrid([])
    assert await _wake(maker, grid, settings_kratos, at) == 1
    # The last activity is the last investigation event: the alert is earlier.
    (call,) = grid.calls
    assert _end_window(call) == (row.last_event, row.last_event + HORIZON)
    done = await _row(maker, campaign_id)
    assert (done.last_alert_at, done.events_to) == (alert, row.last_event + HORIZON)
    # The stored read of the page stays as it was.
    assert done.events == stored
    assert await statuses(maker, campaign_id, at) == {service.STATUS_ENDED}
    assert await _wake(maker, grid, settings_kratos, at + timedelta(hours=1)) == 0
