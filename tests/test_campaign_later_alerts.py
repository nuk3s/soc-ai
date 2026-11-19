"""The later alerts of a campaign (round 3, part 2, G1).

Production, 2026-11-19: campaign 2 stated its span to the last event of its
investigations. The grid held 20 more alerts of 2 rules of the campaign from
the same actor to the same target, the last two hours later. A later alert of
the same rule and the same machines takes its verdict from the earlier
investigation and gets no investigation of its own, and the grid read ended
30 minutes after the last investigation event. So the campaign never learned
of those alerts.

For a campaign that is not ended the grid read now goes to now. The stored
read holds the time of the last alert event of a confirmed rule, and every
surface states the span to the later of that time and the last investigation
event. A campaign that ended keeps its read window.

The data is synthetic: placeholder addresses, names and rule names. Each
stored time is relative to now. The grid is a fake.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from scripts.demo import mock_es
from soc_ai.api.webui.routes_campaigns import _campaign_out, _events_out, _row_out
from soc_ai.api.webui.routes_meta import _campaign_items
from soc_ai.campaigns import decisions, events, refresh, service, words
from soc_ai.campaigns import since_decision as since_svc
from soc_ai.campaigns.events import CampaignEvents, PairEvents, RuleEvents
from soc_ai.campaigns.types import jsonable
from soc_ai.config import Settings
from soc_ai.so_client.elastic import EsSearchResult
from soc_ai.store.auth import utcnow
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import AuthorizedActivity, Campaign, Investigation
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.test_campaign_engine import T0
from tests.test_campaign_facts import (
    ACTOR,
    OUTSIDE,
    RULE,
    RULE_B,
    TARGET,
    seed_hosts,
    seed_run,
)
from tests.test_campaign_service import _built


@pytest.fixture
async def maker(settings_kratos: Settings) -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    try:
        yield make_sessionmaker(engine)
    finally:
        await engine.dispose()


def _when(at: datetime) -> dict[str, Any]:
    return {"value": at.replace(tzinfo=UTC).timestamp() * 1000}


def grid_answer(
    alerts: int,
    last: datetime,
    *,
    first: datetime | None = None,
    later: tuple[int, list[str], datetime] | None = None,
) -> EsSearchResult:
    """One pair, one confirmed rule: ``alerts`` events from ``first`` to ``last``.

    ``later`` is the answer of the aggregation of the later alert events:
    the count, the rule names and the time of the last.
    """
    start = first or last - timedelta(hours=3)
    extra: dict[str, Any] = {}
    if later is not None:
        n, names, at = later
        extra["later"] = {
            "doc_count": n,
            "by_rule": {"buckets": [{"key": name, "doc_count": 1} for name in names]},
            "last": _when(at),
        }
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
                                        "key": RULE,
                                        "doc_count": alerts,
                                        "first": _when(start),
                                        "last": _when(last),
                                    }
                                ]
                            },
                        },
                    }
                }
            },
            "confirmed": {"buckets": {"0": {"doc_count": alerts}}},
            **extra,
        },
    )


class RecordingGrid:
    """A grid with one canned answer, or an error. Records each search."""

    def __init__(self, answer: EsSearchResult | None = None) -> None:
        self.answer = answer
        self.calls: list[dict[str, Any]] = []

    async def search(self, index: str, query: dict[str, Any], **kwargs: Any) -> EsSearchResult:
        self.calls.append({"query": query, **kwargs})
        if self.answer is None:
            raise ConnectionError("the grid refused the connection")
        return self.answer


def _window(call: dict[str, Any]) -> tuple[str, str]:
    held = call["query"]["bool"]["filter"][0]["range"]["@timestamp"]
    return held["gte"], held["lte"]


def _z(at: datetime) -> str:
    return at.isoformat() + "Z"


async def _row(maker: async_sessionmaker[AsyncSession], campaign_id: int) -> Campaign:
    async with maker() as db:
        row = await db.get(Campaign, campaign_id)
        assert row is not None
        return row


async def _refresh(
    maker: async_sessionmaker[AsyncSession],
    campaign_id: int,
    grid: RecordingGrid,
    settings: Settings,
    now: datetime,
) -> None:
    async with maker() as db:
        await service.refresh_events(db, campaign_id, grid, settings, now=now)  # type: ignore[arg-type]


# ── The read window ────────────────────────────────────────────────────────


def test_the_read_window_goes_to_now_for_a_campaign_that_is_not_ended() -> None:
    end = T0 + timedelta(hours=2)
    now = T0 + timedelta(hours=5)
    assert events.read_window(T0, end, now) == (T0 - events.WINDOW_PAD, now)
    # NEGATIVE CONTROL: a campaign that ended keeps the rule of today.
    assert events.read_window(T0, end) == (T0 - events.WINDOW_PAD, end + events.WINDOW_PAD)


def test_the_basis_of_a_read_to_now_holds_a_mark_and_no_time() -> None:
    pair = events.PairSpec(
        "agent:a1", "ip:t1", ("192.0.2.1",), ("198.51.100.10",), frozenset({RULE})
    )
    end = T0 + timedelta(hours=2)
    to_now = events.events_basis([pair], T0, end, to_now=True)
    assert to_now == events.events_basis([pair], T0, end, to_now=True)
    assert to_now != events.events_basis([pair], T0, end)
    # A new last investigation event still needs a new read.
    assert to_now != events.events_basis([pair], T0, end + timedelta(hours=1), to_now=True)


def test_the_stored_read_holds_the_last_alert_of_a_confirmed_rule() -> None:
    confirmed = RuleEvents(RULE, 20, T0, T0 + timedelta(hours=4), "true_positive")
    other = RuleEvents("Example Other Rule", 3, T0, T0 + timedelta(hours=9))
    pair = PairEvents(
        "agent:a1",
        "ip:t1",
        alerts=20,
        other_alerts=3,
        first_at=T0,
        last_at=T0 + timedelta(hours=4),
        rules=(confirmed, other),
    )
    held = events._summary(events.SOURCE_GRID, [pair], events.Timeline(), findings=0)
    # The alert of the other rule is no activity of the campaign.
    assert held.last_alert_at == T0 + timedelta(hours=4)
    stored = jsonable(held)
    assert CampaignEvents.from_json(stored).last_alert_at == T0 + timedelta(hours=4)
    assert events.last_alert_of(stored) == T0 + timedelta(hours=4)
    # A read of an earlier release holds no such field: the pairs give the time.
    del stored["last_alert_at"]
    assert events.last_alert_of(stored) == T0 + timedelta(hours=4)
    # NEGATIVE CONTROL: the events that the investigations hold are no grid read.
    assert events.last_alert_of({**stored, "source": "stored"}) is None
    assert events.last_alert_of(None) is None


def test_the_bottom_line_states_the_period_to_the_last_activity() -> None:
    line = "actor-a acted against web-1 from 2026-10-24 to 2026-11-18. Stage reached: Access."
    first, last = datetime(2026, 10, 24, 1, 11), datetime(2026, 11, 18, 13, 12)
    assert words.with_last_activity(line, first, last, datetime(2026, 11, 19, 0, 30)) == (
        "actor-a acted against web-1 from 2026-10-24 to 2026-11-19. Stage reached: Access."
    )
    # NEGATIVE CONTROLS: an alert on the same day, or before, changes no word.
    assert words.with_last_activity(line, first, last, datetime(2026, 11, 18, 15, 8)) == line
    assert words.with_last_activity(line, first, last, datetime(2026, 11, 1)) == line
    assert words.with_last_activity(line, first, last, None) == line


# ── The campaign ───────────────────────────────────────────────────────────


async def test_an_open_campaign_reads_the_grid_to_now(
    maker: async_sessionmaker[AsyncSession], settings_kratos: Settings
) -> None:
    campaign_id = await _built(maker)
    held = await _row(maker, campaign_id)
    now = utcnow()
    grid = RecordingGrid(grid_answer(23, now - timedelta(minutes=5)))
    await _refresh(maker, campaign_id, grid, settings_kratos, now)
    (call,) = grid.calls
    assert _window(call) == (_z(held.first_event - events.WINDOW_PAD), _z(now))
    # The read does not end 30 minutes after the last investigation event.
    assert _window(call)[1] != _z(held.last_event + events.WINDOW_PAD)


async def test_an_ended_campaign_reads_to_its_last_event_and_a_pad(
    maker: async_sessionmaker[AsyncSession], settings_kratos: Settings
) -> None:
    """NEGATIVE CONTROL: a campaign that ended keeps the rule of today."""
    campaign_id = await _built(maker)
    held = await _row(maker, campaign_id)
    later = utcnow() + timedelta(days=30)
    grid = RecordingGrid(grid_answer(23, held.last_event))
    await _refresh(maker, campaign_id, grid, settings_kratos, later)
    (call,) = grid.calls
    assert _window(call) == (
        _z(held.first_event - events.WINDOW_PAD),
        _z(held.last_event + events.WINDOW_PAD),
    )


async def test_each_surface_states_the_span_to_the_last_alert_event(
    maker: async_sessionmaker[AsyncSession], settings_kratos: Settings
) -> None:
    campaign_id = await _built(maker)
    held = await _row(maker, campaign_id)
    now = utcnow()
    later = held.last_event + timedelta(minutes=56)
    assert later < now
    await _refresh(maker, campaign_id, RecordingGrid(grid_answer(23, later)), settings_kratos, now)
    async with maker() as db:
        (row,) = await service.list_campaigns(db, ids=[campaign_id], now=now)
        view = await service.get_campaign(db, campaign_id, now=now)
        (host,) = await service.campaigns_of_machine(db, ["agent:a1"], now=now)
    assert view is not None
    # The list row, the Confirmed threats row and the host page.
    assert (row.last_event, row.last_alert_at, row.last_activity) == (held.last_event, later, later)
    out = _row_out(row)
    assert out.lastEvent.startswith(held.last_event.isoformat()[:19])
    assert out.lastActivity is not None and out.lastActivity.startswith(later.isoformat()[:19])
    assert host.last_activity == later
    # The page: the header, the timeline and the Alerts fold read the same read.
    assert view.last_activity == later
    assert view.events.last_alert_at == later
    page = _campaign_out(view, stale=False)
    assert page.lastActivity == out.lastActivity
    assert page.events.lastAlertAt == _events_out(view.events).lastAlertAt
    # The Needs you row states the newest event.
    (item,) = _campaign_items([row])
    assert item.eventAt is not None and item.eventAt.startswith(later.isoformat()[:19])


async def test_an_earlier_alert_leaves_the_span_at_the_last_investigation_event(
    maker: async_sessionmaker[AsyncSession], settings_kratos: Settings
) -> None:
    """NEGATIVE CONTROL: an alert before the last investigation event moves no end."""
    campaign_id = await _built(maker)
    held = await _row(maker, campaign_id)
    now = utcnow()
    earlier = held.last_event - timedelta(minutes=20)
    await _refresh(maker, campaign_id, RecordingGrid(grid_answer(9, earlier)), settings_kratos, now)
    async with maker() as db:
        (row,) = await service.list_campaigns(db, ids=[campaign_id], now=now)
        view = await service.get_campaign(db, campaign_id, now=now)
    assert view is not None
    assert (row.last_alert_at, row.last_activity) == (earlier, held.last_event)
    assert view.last_activity == held.last_event
    assert view.bottom_line == held.bottom_line


async def test_the_refresh_loop_reads_an_open_campaign_whose_read_is_old(
    maker: async_sessionmaker[AsyncSession], settings_kratos: Settings
) -> None:
    campaign_id = await _built(maker)
    now = utcnow()
    first = RecordingGrid(grid_answer(9, now - timedelta(hours=1)))
    async with maker() as db:
        assert await service.refresh_behind(db, first, settings_kratos, now=now) == 1  # type: ignore[arg-type]
    # A read of 10 minutes is current: no read.
    grid = RecordingGrid(grid_answer(23, now))
    async with maker() as db:
        soon = now + timedelta(minutes=10)
        assert await service.refresh_behind(db, grid, settings_kratos, now=soon) == 0  # type: ignore[arg-type]
    # A read of 16 minutes is old, and the alerts can go on with no investigation.
    async with maker() as db:
        late = now + timedelta(minutes=16)
        assert await service.refresh_behind(db, grid, settings_kratos, now=late) == 1  # type: ignore[arg-type]
    assert len(grid.calls) == 1
    assert (await _row(maker, campaign_id)).events_at == now + timedelta(minutes=16)
    # NEGATIVE CONTROL: an ended campaign with a grid read reads its events no
    # more. Its end check reads the horizon after its last activity once (E2).
    ended = RecordingGrid(
        EsSearchResult(total=0, took_ms=1, aggregations={"last": {"value": None}})
    )
    far = now + timedelta(days=30)
    for at in (far, far + timedelta(hours=1)):
        async with maker() as db:
            await service.refresh_behind(db, ended, settings_kratos, now=at)  # type: ignore[arg-type]
    (check,) = ended.calls
    assert check["size"] == 0 and "pairs" not in (check.get("aggs") or {})


# ── The later alert events since the decision (G2) ─────────────────────────


def test_the_read_counts_the_later_alert_events_in_the_same_search() -> None:
    spec = events.PairSpec(
        "agent:a1", "ip:t1", ("192.0.2.1",), ("198.51.100.10",), frozenset({RULE}), 3
    )
    after = T0 + timedelta(hours=2)
    _query, aggs = events._search([spec], T0, T0 + timedelta(hours=5), "1m", after)
    later = aggs["later"]["filter"]["bool"]["filter"]
    assert later[0] == {"range": {"@timestamp": {"gt": _z(after)}}}
    assert later[1]["bool"]["should"] == list(aggs["confirmed"]["filters"]["filters"].values())
    # NEGATIVE CONTROL: a read with no time counts nothing later.
    assert "later" not in events._search([spec], T0, T0 + timedelta(hours=5), "1m")[1]


async def test_the_later_count_is_unknown_when_the_grid_does_not_answer_it() -> None:
    spec = events.PairSpec(
        "agent:a1", "ip:t1", ("192.0.2.1",), ("198.51.100.10",), frozenset({RULE}), 3
    )
    after = T0 + timedelta(hours=2)
    last = T0 + timedelta(hours=4)

    async def read(answer: EsSearchResult) -> CampaignEvents:
        got = await events.read_events(
            RecordingGrid(answer),  # type: ignore[arg-type]
            type("S", (), {"events_index_pattern": "logs-*"})(),  # type: ignore[arg-type]
            pairs=[spec],
            start=T0,
            end=after,
            until=T0 + timedelta(hours=5),
            after=after,
        )
        assert got is not None
        return got

    held = await read(grid_answer(30, last, later=(20, [RULE, RULE_B, RULE], last)))
    assert held.later == events.LaterAlerts(after=after, alerts=20, rules=2, last_at=last)
    assert CampaignEvents.from_json(jsonable(held)).later == held.later
    # NEGATIVE CONTROL: a grid that leaves the aggregation out states no count.
    unknown = await read(grid_answer(30, last))
    assert unknown.later == events.LaterAlerts(after=after, known=False)


async def _reopened(maker: async_sessionmaker[AsyncSession]) -> int:
    """A campaign that an analyst closed and opened again: no new investigation."""
    campaign_id = await _built(maker)
    now = utcnow()
    async with maker() as db:
        row = await db.get(Campaign, campaign_id)
        assert row is not None
        basis = await decisions.basis_for(db, row)
        await decisions.write_close(
            db, campaign_id, reason="test_over", note="", by="casey", basis=basis, now=now
        )
        await db.commit()
        row = await db.get(Campaign, campaign_id)
        assert row is not None
        decisions.write_reopen(db, row, by="casey", note="", now=now)
        await db.commit()
    return campaign_id


async def _since(maker: async_sessionmaker[AsyncSession], campaign_id: int) -> Any:
    async with maker() as db:
        (row,) = await service.list_campaigns(db, ids=[campaign_id])
    return row


async def test_a_reopened_campaign_states_the_later_alert_events_on_each_surface(
    maker: async_sessionmaker[AsyncSession], settings_kratos: Settings
) -> None:
    campaign_id = await _reopened(maker)
    held = await _row(maker, campaign_id)
    now = utcnow()
    last = now - timedelta(minutes=4)
    grid = RecordingGrid(grid_answer(53, last, later=(20, [RULE, RULE_B], last)))
    await _refresh(maker, campaign_id, grid, settings_kratos, now)
    # The read counts after the newest investigation event, the boundary here.
    (call,) = grid.calls
    assert call["aggs"]["later"]["filter"]["bool"]["filter"][0] == {
        "range": {"@timestamp": {"gt": _z(held.last_event)}}
    }
    row = await _since(maker, campaign_id)
    since = row.since_decision
    assert since is not None
    assert (since.later_alerts, since.later_rules, since.later_last_at) == (20, 2, last)
    line = (
        f"The grid holds 20 later alert events of 2 rules until {since_svc.stamp(last)}. "
        "They take the verdict of the investigations of the campaign."
    )
    assert since_svc.later_sentence(since) == line
    # The Needs you row and the API state the same facts.
    (item,) = _campaign_items([row])
    assert item.newFacts is not None and item.newFacts.endswith(line)
    out = _row_out(row).sinceDecision
    assert out is not None
    assert (out.laterAlerts, out.laterRules) == (20, 2)
    assert out.laterLastAt is not None and out.laterLastAt.startswith(last.isoformat()[:19])


async def test_a_new_investigation_moves_the_time_and_an_older_read_states_nothing(
    maker: async_sessionmaker[AsyncSession], settings_kratos: Settings
) -> None:
    """NEGATIVE CONTROL: a read that counted after an older time claims nothing."""
    campaign_id = await _reopened(maker)
    now = utcnow()
    last = now - timedelta(minutes=4)
    await _refresh(
        maker,
        campaign_id,
        RecordingGrid(grid_answer(53, last, later=(20, [RULE], last))),
        settings_kratos,
        now,
    )
    async with maker() as db:
        await seed_run(db, "alert-0009", event_hours_ago=0.2, created_minutes_ago=1)
        await service.rebuild(db)
    row = await _since(maker, campaign_id)
    assert row.since_decision is not None
    assert row.since_decision.investigations == 1
    assert row.since_decision.later_alerts == 0
    assert since_svc.later_sentence(row.since_decision) is None
    # The next read counts after the new investigation event.
    grid = RecordingGrid(grid_answer(54, last, later=(3, [RULE], last)))
    await _refresh(maker, campaign_id, grid, settings_kratos, now + timedelta(minutes=1))
    assert len(grid.calls) == 1
    row = await _since(maker, campaign_id)
    assert row.since_decision is not None
    assert row.since_decision.later_alerts == 3
    assert since_svc.later_sentence(row.since_decision) == (
        f"The grid holds 3 later alert events of 1 rule until {since_svc.stamp(last)}. "
        "They take the verdict of these investigations."
    )


async def test_a_campaign_with_no_later_alert_states_no_line(
    maker: async_sessionmaker[AsyncSession], settings_kratos: Settings
) -> None:
    """NEGATIVE CONTROL: no later alert event, and a count that the grid did not answer."""
    campaign_id = await _reopened(maker)
    now = utcnow()
    for answer in (grid_answer(33, now, later=(0, [], now)), grid_answer(33, now)):
        async with maker() as db:
            row = await db.get(Campaign, campaign_id)
            assert row is not None
            row.events, row.events_at, row.events_basis = None, None, None
            await db.commit()
        await _refresh(maker, campaign_id, RecordingGrid(answer), settings_kratos, now)
        row = await _since(maker, campaign_id)
        assert row.since_decision is not None
        assert row.since_decision.later_alerts == 0
        (item,) = _campaign_items([row])
        assert item.newFacts is not None and "later alert" not in item.newFacts
    # A count that the grid did not answer asks again only after the usual age.
    grid = RecordingGrid(grid_answer(33, now))
    await _refresh(maker, campaign_id, grid, settings_kratos, now + timedelta(minutes=5))
    assert grid.calls == []


# ── A close covers what the page states (G3) ───────────────────────────────


def _no_hits() -> EsSearchResult:
    return EsSearchResult(total=0, took_ms=1, hits=[])


async def _scope_window(
    maker: async_sessionmaker[AsyncSession], campaign_id: int, settings: Settings, now: datetime
) -> tuple[str, str]:
    grid = RecordingGrid(_no_hits())
    async with maker() as db:
        scope = await service.close_scope(db, campaign_id, grid, settings, now=now)  # type: ignore[arg-type]
    assert scope is not None and scope.alerts == 0
    (call,) = grid.calls
    return _window(call)


async def _close(maker: async_sessionmaker[AsyncSession], campaign_id: int, now: datetime) -> Any:
    async with maker() as db:
        row = await db.get(Campaign, campaign_id)
        assert row is not None
        basis = await service.close_basis(db, row, now=now)
        await decisions.write_close(
            db, campaign_id, reason="test_over", note="", by="casey", basis=basis, now=now
        )
        await db.commit()
    return basis


async def test_the_close_scope_and_the_basis_end_at_the_grid_read_of_the_page(
    maker: async_sessionmaker[AsyncSession], settings_kratos: Settings
) -> None:
    campaign_id = await _built(maker)
    held = await _row(maker, campaign_id)
    read = utcnow()
    grid = RecordingGrid(grid_answer(53, read - timedelta(minutes=3)))
    await _refresh(maker, campaign_id, grid, settings_kratos, read)
    start = _z(held.first_event - events.WINDOW_PAD)
    # The dialog: the scope ends at the end of the read that the page states.
    later = read + timedelta(minutes=9)
    assert await _scope_window(maker, campaign_id, settings_kratos, later) == (start, _z(read))
    basis = await _close(maker, campaign_id, later)
    assert basis["last_event"] == read.isoformat()
    # The acknowledge after the close and the route "Acknowledge" take no
    # alert after the time that the decision covers.
    for at in (later, later + timedelta(hours=3)):
        assert await _scope_window(maker, campaign_id, settings_kratos, at) == (start, _z(read))


async def test_with_no_grid_read_the_close_keeps_the_rule_of_today(
    maker: async_sessionmaker[AsyncSession], settings_kratos: Settings
) -> None:
    """NEGATIVE CONTROL: a grid that did not answer changes nothing."""
    campaign_id = await _built(maker)
    held = await _row(maker, campaign_id)
    now = utcnow()
    await _refresh(maker, campaign_id, RecordingGrid(), settings_kratos, now)
    assert (await _row(maker, campaign_id)).events is None
    today = (_z(held.first_event - events.WINDOW_PAD), _z(held.last_event + events.WINDOW_PAD))
    assert await _scope_window(maker, campaign_id, settings_kratos, now) == today
    basis = await _close(maker, campaign_id, now)
    assert basis["last_event"] == held.last_event.isoformat()
    assert await _scope_window(maker, campaign_id, settings_kratos, now) == today


async def test_an_ended_campaign_and_an_earlier_close_keep_the_rule_of_today(
    maker: async_sessionmaker[AsyncSession], settings_kratos: Settings
) -> None:
    """NEGATIVE CONTROL: the read of a campaign that ended, and a basis of an earlier release."""
    campaign_id = await _built(maker)
    held = await _row(maker, campaign_id)
    now = utcnow()
    await _refresh(maker, campaign_id, RecordingGrid(grid_answer(53, now)), settings_kratos, now)
    today = (_z(held.first_event - events.WINDOW_PAD), _z(held.last_event + events.WINDOW_PAD))
    ended = now + timedelta(days=30)
    assert await _scope_window(maker, campaign_id, settings_kratos, ended) == today
    async with maker() as db:
        row = await db.get(Campaign, campaign_id)
        assert row is not None
        assert (await service.close_basis(db, row, now=ended))["last_event"] == (
            held.last_event.isoformat()
        )
        # A close of an earlier release recorded the last event.
        earlier = await decisions.basis_for(db, row)
        await decisions.write_close(
            db, campaign_id, reason="test_over", note="", by="casey", basis=earlier, now=now
        )
        await db.commit()
    assert await _scope_window(maker, campaign_id, settings_kratos, now) == today


# ── A closed campaign opens again when its activity goes on (G4) ───────────


class DocGrid:
    """A grid of documents: the demo grid answers each query. Counts the searches."""

    def __init__(self, docs: list[dict[str, Any]] | None = None) -> None:
        self.docs = docs
        self.calls = 0

    async def search(self, index: str, query: dict[str, Any], **kw: Any) -> EsSearchResult:
        self.calls += 1
        if self.docs is None:
            raise ConnectionError("the grid refused the connection")
        body = {"query": query, "size": kw["size"], "_source": kw["source"], "sort": kw["sort"]}
        answer = mock_es.search_docs(body, self.docs)
        return EsSearchResult(
            total=answer["hits"]["total"]["value"], took_ms=1, hits=answer["hits"]["hits"]
        )


def _alert_doc(
    doc_id: str, at: datetime, *, rule: str = RULE, acknowledged: bool = False
) -> dict[str, Any]:
    return {
        "_id": doc_id,
        "_index": "logs-test",
        "_source": {
            "@timestamp": _z(at),
            "rule": {"name": rule},
            "event": {"dataset": "suricata.alert", "acknowledged": acknowledged},
            "source": {"ip": ACTOR},
            "destination": {"ip": TARGET},
        },
    }


async def _closed_with_later(
    maker: async_sessionmaker[AsyncSession], settings: Settings
) -> tuple[int, datetime, datetime]:
    """A campaign that the analyst closed on the page read, then a read with later alerts.

    Returns the id, the time that the close covers and the time of the second read.
    """
    campaign_id = await _built(maker)
    now = utcnow()
    read = now - timedelta(minutes=40)
    await _refresh(
        maker,
        campaign_id,
        RecordingGrid(grid_answer(53, read - timedelta(minutes=5))),
        settings,
        read,
    )
    basis = await _close(maker, campaign_id, read + timedelta(minutes=1))
    assert basis["last_event"] == read.isoformat()
    second = now - timedelta(minutes=2)
    later = RecordingGrid(grid_answer(56, second, later=(3, [RULE], second)))
    await _refresh(maker, campaign_id, later, settings, second)
    assert len(later.calls) == 1
    return campaign_id, read, now


async def _reopen(
    maker: async_sessionmaker[AsyncSession], grid: DocGrid, settings: Settings, now: datetime
) -> int:
    async with maker() as db:
        return await service.reopen_on_activity(db, grid, settings, now=now)  # type: ignore[arg-type]


async def test_an_open_alert_after_the_close_opens_the_campaign_again(
    maker: async_sessionmaker[AsyncSession], settings_kratos: Settings
) -> None:
    campaign_id, covered, now = await _closed_with_later(maker, settings_kratos)
    first = covered + timedelta(minutes=10)
    grid = DocGrid([_alert_doc("a1", first), _alert_doc("a2", first + timedelta(minutes=9))])
    assert await _reopen(maker, grid, settings_kratos, now) == 1
    row = await _row(maker, campaign_id)
    assert row.decision is None
    async with maker() as db:
        (change, *_rest) = await decisions.changes_of(db, campaign_id)
    assert (change.type, change.detail["cause"]) == ("reopened", "activity")
    assert (change.detail["alerts"], change.detail["rules"]) == (2, 1)
    assert change.detail["firstAlertAt"] == first.isoformat()
    assert change.detail["was"]["decision"] == "closed"
    # The banner states the reopen and the later alert events.
    since = (await _since(maker, campaign_id)).since_decision
    assert since is not None
    assert (since.cause, since.investigations, since.later_alerts) == ("activity", 0, 3)
    # NEGATIVE CONTROL: the same stored read gives no second check.
    assert await _reopen(maker, grid, settings_kratos, now) == 0
    assert grid.calls == 1


@pytest.mark.parametrize(
    "docs",
    [
        pytest.param([_alert_doc("b1", utcnow() - timedelta(minutes=10), rule=RULE_B)], id="rule"),
        pytest.param([_alert_doc("b2", utcnow() - timedelta(minutes=50))], id="before"),
        pytest.param(
            [_alert_doc("b3", utcnow() - timedelta(minutes=10), acknowledged=True)],
            id="acknowledged",
        ),
    ],
)
async def test_an_alert_that_is_no_later_activity_opens_nothing(
    maker: async_sessionmaker[AsyncSession], settings_kratos: Settings, docs: list[dict[str, Any]]
) -> None:
    """NEGATIVE CONTROL: another rule, an alert before the basis, an acknowledged alert."""
    campaign_id, _covered, now = await _closed_with_later(maker, settings_kratos)
    grid = DocGrid(docs)
    assert await _reopen(maker, grid, settings_kratos, now) == 1
    assert grid.calls == 1
    assert (await _row(maker, campaign_id)).decision == "closed"


async def test_with_the_grid_down_nothing_opens(
    maker: async_sessionmaker[AsyncSession], settings_kratos: Settings
) -> None:
    """NEGATIVE CONTROL: a grid that does not answer changes nothing."""
    campaign_id, covered, now = await _closed_with_later(maker, settings_kratos)
    down = DocGrid()
    assert await _reopen(maker, down, settings_kratos, now) == 1
    assert (await _row(maker, campaign_id)).decision == "closed"
    # The next wake waits for the next grid read of the campaign.
    up = DocGrid([_alert_doc("c1", covered + timedelta(minutes=10))])
    assert await _reopen(maker, up, settings_kratos, now) == 0
    assert up.calls == 0


@pytest.mark.parametrize("decision", ["authorized", "case"])
async def test_an_authorized_or_a_case_decision_does_not_open_again(
    maker: async_sessionmaker[AsyncSession], settings_kratos: Settings, decision: str
) -> None:
    """NEGATIVE CONTROL: only a close opens again on activity."""
    campaign_id, covered, now = await _closed_with_later(maker, settings_kratos)
    async with maker() as db:
        row = await db.get(Campaign, campaign_id)
        assert row is not None
        row.decision = decision
        await db.commit()
    grid = DocGrid([_alert_doc("d1", covered + timedelta(minutes=10))])
    assert await _reopen(maker, grid, settings_kratos, now) == 0
    assert grid.calls == 0
    assert (await _row(maker, campaign_id)).decision == decision


async def test_an_ended_campaign_reads_nothing(
    maker: async_sessionmaker[AsyncSession], settings_kratos: Settings
) -> None:
    """NEGATIVE CONTROL: a closed campaign that ended."""
    campaign_id, covered, now = await _closed_with_later(maker, settings_kratos)
    grid = DocGrid([_alert_doc("e1", covered + timedelta(minutes=10))])
    assert await _reopen(maker, grid, settings_kratos, now + timedelta(days=30)) == 0
    assert grid.calls == 0
    assert (await _row(maker, campaign_id)).decision == "closed"


async def test_a_stored_read_with_no_later_alert_reads_nothing(
    maker: async_sessionmaker[AsyncSession], settings_kratos: Settings
) -> None:
    """NEGATIVE CONTROL: the stored read of the close holds no later alert."""
    campaign_id = await _built(maker)
    read = utcnow() - timedelta(minutes=20)
    answer = grid_answer(53, read - timedelta(minutes=5), later=(0, [], read))
    await _refresh(maker, campaign_id, RecordingGrid(answer), settings_kratos, read)
    await _close(maker, campaign_id, read)
    grid = DocGrid([_alert_doc("f1", read + timedelta(minutes=5))])
    assert await _reopen(maker, grid, settings_kratos, utcnow()) == 0
    assert grid.calls == 0


async def test_the_loop_step_shares_one_limit_of_reads(
    maker: async_sessionmaker[AsyncSession], settings_kratos: Settings
) -> None:
    asked: list[tuple[str, int]] = []

    class Service:
        EVENTS_REFRESH_MAX = 5
        EVENTS_REFRESH_BUDGET_S = 5.0

        async def reopen_on_activity(self, db: Any, *_a: Any, **_kw: Any) -> int:
            asked.append(("reopen", 0))
            return 2

        async def refresh_behind(self, db: Any, *_a: Any, limit: int, **_kw: Any) -> int:
            asked.append(("counts", limit))
            return 0

    state = type(
        "S", (), {"db_sessionmaker": maker, "elastic": RecordingGrid(), "settings": settings_kratos}
    )
    await refresh._refresh_counts(type("A", (), {"state": state})(), Service())
    assert asked == [("reopen", 0), ("counts", 3)]


# ── One count for one fact (G5) ────────────────────────────────────────────


async def test_the_authorization_line_counts_the_investigations_that_the_campaign_holds(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    """Production: "covers 24 of the 55 investigations" above "Investigations 54".

    The count of an authorization took each member, and a member whose verdict
    differs is no investigation of the campaign: the fold leaves it out.
    """
    async with maker() as db:
        await seed_hosts(db)
        now = utcnow()
        authorization = AuthorizedActivity(
            label="upload test",
            sources=[{"address": ACTOR, "machine_key": "agent:a1", "name": "actor-a"}],
            target_address=TARGET,
            target_machine_key="ip:t1",
            rule_names=[RULE],
            rule_class="exploit_attempt",
            starts_at=now - timedelta(days=1),
            expires_at=now + timedelta(days=2),
            created_by="analyst",
        )
        db.add(authorization)
        await db.commit()
        held = await seed_run(db, "alert-0001", community_id="1:sess", event_hours_ago=2)
        differs = await seed_run(
            db,
            "alert-0002",
            src=TARGET,
            dst=OUTSIDE,
            verdict="false_positive",
            community_id="1:sess",
            event_hours_ago=1.9,
        )
        for run_id in (held, differs):
            inv = await db.get(Investigation, run_id)
            assert inv is not None
            inv.authorization_id = authorization.id
        await db.commit()
        await service.rebuild(db)
        (row,) = await service.list_campaigns(db)
        view = await service.get_campaign(db, row.id)
    assert view is not None
    assert {(m.run_id, m.verdict_differs) for m in view.members} == {(held, False), (differs, True)}
    (auth,) = view.authorizations
    # NEGATIVE CONTROL: the investigation that the campaign holds still counts.
    assert auth.member_runs == 1


# ── The words of a hunt answer (G6) ────────────────────────────────────────


async def test_the_page_states_the_later_alert_events_of_the_stored_read(
    maker: async_sessionmaker[AsyncSession], settings_kratos: Settings
) -> None:
    campaign_id = await _built(maker)
    held = await _row(maker, campaign_id)
    now = utcnow()
    last = now - timedelta(minutes=3)
    grid = RecordingGrid(grid_answer(53, last, later=(20, [RULE, RULE_B], last)))
    await _refresh(maker, campaign_id, grid, settings_kratos, now)
    # The read counts after the newest investigation event.
    (call,) = grid.calls
    assert call["aggs"]["later"]["filter"]["bool"]["filter"][0] == {
        "range": {"@timestamp": {"gt": _z(held.last_event)}}
    }
    async with maker() as db:
        view = await service.get_campaign(db, campaign_id, now=now)
    assert view is not None
    out = _events_out(view.events)
    assert (out.laterAlerts, out.laterRules) == (20, 2)
    assert out.laterLastAt is not None and out.laterLastAt.startswith(last.isoformat()[:19])
    # NEGATIVE CONTROL: a new investigation makes the stored count older than
    # the campaign. The page states none until the next read, with no new read.
    async with maker() as db:
        await seed_run(db, "alert-0009", event_hours_ago=0.2, created_minutes_ago=1)
        await service.rebuild(db)
    # The grid does not answer the read of the new basis, so the page keeps
    # the older grid read, and its count of the later alerts is older too.
    down = RecordingGrid()
    await _refresh(maker, campaign_id, down, settings_kratos, now + timedelta(minutes=1))
    assert len(down.calls) == 1
    async with maker() as db:
        view = await service.get_campaign(db, campaign_id, now=now)
    assert view is not None
    assert (view.events.source, view.events.alerts) == ("grid", 53)
    out = _events_out(view.events)
    assert (out.laterAlerts, out.laterRules, out.laterLastAt) == (0, 0, None)
