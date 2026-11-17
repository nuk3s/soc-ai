"""The events of a campaign: alert events of the grid between its machines.

``stored_events`` counts the alert documents that the true positive members
hold. ``read_events`` reads the grid once for the whole campaign. A failed or
slow read gives None and never raises.

Every machine key, address and rule name here is a placeholder.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from scripts.demo import mock_es
from soc_ai.campaigns import events
from soc_ai.campaigns.engine import build_campaigns
from soc_ai.campaigns.events import CampaignEvents, PairSpec
from soc_ai.campaigns.types import CampaignDraft, jsonable
from soc_ai.so_client.elastic import EsSearchResult, GridPartialResultsError

from tests.test_campaign_engine import A1, ADDRESS, T0, T1, T2, X1, at, doc, finding, run

pytestmark = pytest.mark.asyncio

FIXTURES = Path(__file__).resolve().parents[1] / "soc_ai" / "demo" / "fixtures.json"
STORY_RULE = "BZAR ATTACK::Execution_Service_Creation"


def _alert(doc_id: str, hours: float, src: str = A1, dst: str = T1, rule: str = "RULE A") -> Any:
    return doc(doc_id, hours, src, dst, is_alert=True, rule_key=rule, dataset="suricata.alert")


def _campaign() -> CampaignDraft:
    """Two alert runs and a reverse alert run on A1 and T1, and two findings that cite one alert."""
    shared = _alert("d6", 2, dst=T2, rule="RULE B")
    facts = [
        run("r1", 0, documents=(_alert("d1", 0),)),
        run(
            "r2",
            1,
            sessions=(("1:x", at(1)),),
            documents=(
                _alert("d2", 1),
                # The answer of the server: a reverse alert counts on the pair of its actor.
                _alert("d3", 1.01, src=T1, dst=A1),
                # Other hosts: X1 is no party.
                _alert("d4", 1.02, dst=X1),
                # A rule that no true positive investigation holds.
                _alert("d5", 1.03, rule="RULE Z"),
            ),
        ),
        run(
            "r5",
            1.25,
            src=T1,
            dst=A1,
            sessions=(("1:x", at(1.25)),),
            documents=(_alert("d7", 1.25, src=T1, dst=A1),),
        ),
        finding("f3", 2, documents=(shared,)),
        finding("f4", 2.1, documents=(shared,)),
    ]
    drafts = build_campaigns(facts)
    assert len(drafts) == 1, [d.run_ids for d in drafts]
    return drafts[0]


def _parties(draft: CampaignDraft) -> dict[str, tuple[str, ...]]:
    return {p.machine_key: p.addresses or (ADDRESS[p.machine_key],) for p in draft.parties}


async def test_stored_events_count_the_alert_documents_by_pair_and_rule() -> None:
    draft = _campaign()
    member_of = {m.run.run_id: m for m in draft.members}
    assert member_of["r5"].direction == "reverse"
    got = events.stored_events(draft, _parties(draft))
    assert (got.source, got.read_at, got.records) == ("stored", None, None)
    assert (got.alerts, got.rules, got.findings) == (5, 2, 2)
    pairs = {(p.source, p.target): p for p in got.pairs}
    assert set(pairs) == {(A1, T1), (A1, T2)}
    main = pairs[(A1, T1)]
    # d1, d2, d3 and d7. The reverse documents count on the pair of the actor.
    assert (main.alerts, main.other_alerts, main.records, main.datasets) == (4, 1, None, ())
    assert (main.first_at, main.last_at) == (at(0), at(1.25))
    assert [(r.name, r.alerts, r.verdict) for r in main.rules] == [
        ("RULE A", 4, "true_positive"),
        ("RULE Z", 1, "not_judged"),
    ]
    assert (main.rules[0].first_at, main.rules[0].last_at) == (at(0), at(1.25))
    # One document that two findings hold counts once.
    second = pairs[(A1, T2)]
    assert [(r.name, r.alerts, r.verdict) for r in second.rules] == [("RULE B", 1, "true_positive")]
    # NEGATIVE CONTROL: the document of other hosts counts on no pair.
    assert X1 not in {key for pair in pairs for key in pair}

    assert got.timeline.bucket_seconds == 60
    (lane,) = got.timeline.lanes
    assert lane.machine_key == A1
    # The minute of each document of a confirmed rule. RULE Z is not on the timeline.
    assert [(b.at, b.alerts) for b in lane.buckets] == [
        (at(0), 1),
        (at(1), 2),
        (at(1.25), 1),
        (at(2), 1),
    ]


async def test_stored_events_of_members_with_no_document_have_no_pair() -> None:
    draft = build_campaigns([run("r1"), run("r2", 1)])[0]
    got = events.stored_events(draft.members, _parties(draft))
    assert (got.source, got.alerts, got.pairs, got.timeline.lanes) == ("stored", 0, (), ())


async def test_the_events_round_trip_through_json() -> None:
    draft = _campaign()
    got = events.stored_events(draft, _parties(draft))
    stored = json.loads(json.dumps(jsonable(got)))
    assert CampaignEvents.from_json(stored) == got
    # NEGATIVE CONTROL: a broken value reads as no events, never as an error.
    assert CampaignEvents.from_json({"pairs": "x", "timeline": 3}) == CampaignEvents(source="none")


async def test_the_pairs_hold_their_addresses_confirmed_rules_and_investigations() -> None:
    draft = _campaign()
    specs = {(s.source, s.target): s for s in events.campaign_pairs(draft, _parties(draft))}
    main = specs[(A1, T1)]
    assert (main.source_addresses, main.target_addresses) == ((ADDRESS[A1],), (ADDRESS[T1],))
    assert main.confirmed == frozenset({"RULE A"})
    # r1, r2, r5 and the two findings, which have A1 and T1 as their ends.
    assert main.investigations == 5
    assert specs[(A1, T2)].confirmed == frozenset({"RULE B"})
    assert specs[(A1, T2)].investigations == 2


# ── The grid read ─────────────────────────────────────────────────────────


class _Elastic:
    """A grid that answers each search with one canned result."""

    def __init__(
        self,
        result: EsSearchResult | None = None,
        *,
        error: Exception | None = None,
        delay: float = 0.0,
    ) -> None:
        self.result = result
        self.error = error
        self.delay = delay
        self.calls: list[dict[str, Any]] = []

    async def search(self, index: str, query: dict[str, Any], **kwargs: Any) -> EsSearchResult:
        self.calls.append({"index": index, "query": query, **kwargs})
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.error is not None:
            raise self.error
        assert self.result is not None
        return self.result


class _Settings:
    events_index_pattern = "logs-*"


def _ms(at_: datetime) -> int:
    return int(at_.replace(tzinfo=UTC).timestamp() * 1000)


def _when(at_: datetime) -> dict[str, Any]:
    return {"value": float(_ms(at_)), "value_as_string": at_.isoformat() + "Z"}


def _rule(name: str, count: int, first: float, last: float) -> dict[str, Any]:
    return {"key": name, "doc_count": count, "first": _when(at(first)), "last": _when(at(last))}


def _answer() -> EsSearchResult:
    return EsSearchResult(
        total=1072,
        took_ms=4,
        aggregations={
            "pairs": {
                "buckets": {
                    "0": {
                        "doc_count": 1072,
                        "datasets": {
                            "buckets": [
                                {"key": "zeek.conn", "doc_count": 900},
                                {"key": "suricata.alert", "doc_count": 172},
                            ]
                        },
                        "alerts": {
                            "doc_count": 172,
                            "by_rule": {
                                "buckets": [
                                    _rule("RULE A", 160, 0, 1.5),
                                    _rule("RULE Q", 12, 0.5, 0.75),
                                ]
                            },
                        },
                    }
                }
            },
            "confirmed": {
                "buckets": {
                    "0": {
                        "doc_count": 160,
                        "timeline": {
                            "buckets": [
                                {"key": _ms(at(0)), "doc_count": 100},
                                {"key": _ms(at(1.5)), "doc_count": 60},
                            ]
                        },
                    }
                }
            },
        },
    )


def _pair(**over: Any) -> PairSpec:
    base: dict[str, Any] = {
        "source": A1,
        "target": T1,
        "source_addresses": (ADDRESS[A1],),
        "target_addresses": (ADDRESS[T1], "198.51.100.40"),
        "confirmed": frozenset({"RULE A"}),
        "investigations": 3,
    }
    base.update(over)
    return PairSpec(**base)


async def _read(
    elastic: _Elastic, *, pairs: list[PairSpec] | None = None, hours: float = 2
) -> CampaignEvents | None:
    return await events.read_events(
        elastic,  # type: ignore[arg-type]
        _Settings(),  # type: ignore[arg-type]
        pairs=pairs or [_pair()],
        start=T0,
        end=T0 + timedelta(hours=hours),
    )


async def test_read_events_counts_the_alerts_of_the_confirmed_rules_of_each_pair() -> None:
    elastic = _Elastic(_answer())
    got = await _read(elastic)
    assert got is not None
    assert got.source == "grid"
    assert got.read_at is not None
    assert (got.alerts, got.rules, got.records) == (160, 1, 1072)
    (pair,) = got.pairs
    assert (pair.source, pair.target, pair.alerts, pair.other_alerts) == (A1, T1, 160, 12)
    assert (pair.records, pair.first_at, pair.last_at) == (1072, at(0), at(1.5))
    assert [(r.name, r.alerts, r.verdict, r.first_at) for r in pair.rules] == [
        ("RULE A", 160, "true_positive", at(0)),
        ("RULE Q", 12, "not_judged", at(0.5)),
    ]
    assert [(d.name, d.records) for d in pair.datasets] == [
        ("zeek.conn", 900),
        ("suricata.alert", 172),
    ]
    assert got.timeline.bucket_seconds == 60
    (lane,) = got.timeline.lanes
    assert (lane.machine_key, [(b.at, b.alerts) for b in lane.buckets]) == (
        A1,
        [(at(0), 100), (at(1.5), 60)],
    )


async def test_read_events_sends_one_search_with_the_addresses_window_and_dataset() -> None:
    elastic = _Elastic(_answer())
    await _read(elastic)
    (call,) = elastic.calls
    assert call["index"] == "logs-*"
    assert (call["size"], call["require_complete"]) == (0, True)
    text = json.dumps(call["query"])
    window = call["query"]["bool"]["filter"][0]["range"]["@timestamp"]
    assert (window["gte"], window["lte"]) == (
        (T0 - timedelta(minutes=30)).isoformat() + "Z",
        (T0 + timedelta(hours=2, minutes=30)).isoformat() + "Z",
    )
    for address in (ADDRESS[A1], ADDRESS[T1], "198.51.100.40"):
        assert address in text
    # Either direction between any address of one machine and any address of the other.
    clause = call["aggs"]["pairs"]["filters"]["filters"]["0"]
    sides = [
        {next(iter(f["terms"])): f["terms"][next(iter(f["terms"]))] for f in way["bool"]["filter"]}
        for way in clause["bool"]["should"]
    ]
    target = [ADDRESS[T1], "198.51.100.40"]
    assert sides == [
        {"source.ip": [ADDRESS[A1]], "destination.ip": target},
        {"source.ip": target, "destination.ip": [ADDRESS[A1]]},
        # A Sigma alert holds the addresses of its document under event_data.
        {"event_data.source.ip": [ADDRESS[A1]], "event_data.destination.ip": target},
        {"event_data.source.ip": target, "event_data.destination.ip": [ADDRESS[A1]]},
    ]
    alerts = call["aggs"]["pairs"]["aggs"]["alerts"]
    assert alerts["filter"] == {"wildcard": {"event.dataset": {"value": "*.alert"}}}
    assert alerts["aggs"]["by_rule"]["terms"] == {"field": "rule.name", "size": 50}
    assert call["aggs"]["pairs"]["aggs"]["datasets"]["terms"] == {
        "field": "event.dataset",
        "size": 8,
    }
    confirmed = call["aggs"]["confirmed"]["filters"]["filters"]["0"]["bool"]["filter"]
    assert {"terms": {"rule.name": ["RULE A"]}} in confirmed
    histogram = call["aggs"]["confirmed"]["aggs"]["timeline"]["date_histogram"]
    assert histogram == {"field": "@timestamp", "fixed_interval": "1m", "min_doc_count": 1}


@pytest.mark.parametrize(
    ("hours", "interval", "seconds"),
    [(2, "1m", 60), (3 * 24, "5m", 300), (19 * 24, "15m", 900), (60 * 24, "1h", 3600)],
)
async def test_one_interval_holds_the_window_in_at_most_2000_buckets(
    hours: float, interval: str, seconds: int
) -> None:
    elastic = _Elastic(_answer())
    got = await _read(elastic, hours=hours)
    assert got is not None
    assert got.timeline.bucket_seconds == seconds
    histogram = elastic.calls[0]["aggs"]["confirmed"]["aggs"]["timeline"]["date_histogram"]
    assert histogram["fixed_interval"] == interval
    lo = T0 - timedelta(minutes=30)
    hi = T0 + timedelta(hours=hours, minutes=30)
    count = int(hi.replace(tzinfo=UTC).timestamp()) // seconds
    count -= int(lo.replace(tzinfo=UTC).timestamp()) // seconds
    assert count + 1 <= 2000


async def test_a_pair_with_no_confirmed_rule_has_no_timeline_filter() -> None:
    empty = {"pairs": {"buckets": {"0": {"doc_count": 0}}}}
    elastic = _Elastic(EsSearchResult(total=0, took_ms=1, aggregations=empty))
    got = await _read(elastic, pairs=[_pair(confirmed=frozenset())])
    assert got is not None
    assert "confirmed" not in elastic.calls[0]["aggs"]
    (pair,) = got.pairs
    # The grid answered: zero is a count.
    assert (pair.alerts, pair.other_alerts, pair.records, got.timeline.lanes) == (0, 0, 0, ())


async def test_the_read_covers_the_20_pairs_with_the_most_investigations() -> None:
    pairs = [
        _pair(target=f"ip:t{n}", target_addresses=(f"198.51.100.{n}",), investigations=n)
        for n in range(1, 26)
    ]
    elastic = _Elastic(EsSearchResult(total=0, took_ms=1, aggregations={"pairs": {"buckets": {}}}))
    got = await _read(elastic, pairs=pairs)
    assert got is not None
    assert {p.target for p in got.pairs} == {f"ip:t{n}" for n in range(6, 26)}
    assert len(elastic.calls[0]["aggs"]["pairs"]["filters"]["filters"]) == 20


@pytest.mark.parametrize(
    "error",
    [
        RuntimeError("connection refused"),
        GridPartialResultsError("partial search results", shards_failed=2, shards_total=4),
    ],
)
async def test_a_failed_grid_read_gives_none_and_one_warning(
    error: Exception, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING, logger="soc_ai.campaigns.events"):
        got = await _read(_Elastic(error=error))
    assert got is None
    lines = [r.getMessage() for r in caplog.records if r.name == "soc_ai.campaigns.events"]
    assert lines == [
        "campaigns: soc-ai could not read the events of the campaign from the grid. "
        "The page shows the events that the investigations hold."
    ]


async def test_a_grid_answer_with_no_aggregation_gives_none() -> None:
    """A grid that does not evaluate the aggregations states no count. A zero would be invented."""
    assert await _read(_Elastic(EsSearchResult(total=0, took_ms=1))) is None
    # NEGATIVE CONTROL: an answer with the aggregation of the pairs reads.
    assert await _read(_Elastic(_answer())) is not None


async def test_the_demo_grid_answers_the_read_with_the_events_of_the_story() -> None:
    """The demo grid evaluates the read over its fixture documents.

    The story campaign is the PsExec activity from jump01 to fs01. The grid
    holds one alert of the confirmed rule and one alert of a policy rule
    between the two machines.
    """
    grid = mock_es.load_fixture(FIXTURES)

    class Demo:
        async def search(self, index: str, query: dict[str, Any], **kw: Any) -> EsSearchResult:
            body = {"query": query, "size": kw["size"], "aggs": kw["aggs"]}
            answer = mock_es.search_docs(body, grid.docs, traffic=grid.traffic)
            return EsSearchResult(
                total=answer["hits"]["total"]["value"],
                took_ms=1,
                aggregations=answer.get("aggregations"),
            )

    # The alert of the story: the service creation alert from the jump host, address .50.
    (story,) = (
        mock_es._doc_source(d)
        for d in grid.docs
        if (mock_es._doc_source(d).get("rule") or {}).get("name") == STORY_RULE
        and mock_es._doc_source(d)["source"]["ip"].endswith(".50")
    )
    when = datetime.fromisoformat(story["@timestamp"].replace("Z", "+00:00")).replace(tzinfo=None)
    actor, target = story["source"]["ip"], story["destination"]["ip"]
    spec = PairSpec("agent:jump01", "agent:fs01", (actor,), (target,), frozenset({STORY_RULE}), 1)
    got = await events.read_events(
        Demo(),  # type: ignore[arg-type]
        _Settings(),  # type: ignore[arg-type]
        pairs=[spec],
        start=when,
        end=when,
    )
    assert got is not None
    (pair,) = got.pairs
    assert (got.source, pair.alerts, pair.other_alerts) == ("grid", 1, 1)
    assert [r.verdict for r in pair.rules] == ["true_positive", "not_judged"]
    assert pair.records is not None
    assert pair.records > pair.alerts + pair.other_alerts
    assert "suricata.alert" in {d.name for d in pair.datasets}


def _grid_doc(doc_id: str, minutes: int, source: dict[str, Any]) -> dict[str, Any]:
    stamp = (T0 + timedelta(minutes=minutes)).isoformat() + "Z"
    return {"_id": doc_id, "_index": "logs-test", "_source": {"@timestamp": stamp, **source}}


def _sigma_alert(doc_id: str, minutes: int, src: str, dst: str, rule: str) -> dict[str, Any]:
    """A Sigma alert of Security Onion: the shape of 52 stored production documents.

    The top level holds the time, the rule, the Sigma level, the event and the
    tags. The addresses and the host name of the matched record are under
    ``event_data``, and the top level holds no address.
    """
    return _grid_doc(
        doc_id,
        minutes,
        {
            "sigma_level": "high",
            "rule": {"name": rule},
            "event": {"dataset": "sigma.alert", "module": "sigma"},
            "tags": ["alert"],
            "event_data": {
                "event": {"dataset": "zeek.http"},
                "source": {"ip": src},
                "destination": {"ip": dst},
                "host": {"name": "sensor-1", "ip": ["10.20.30.5"]},
            },
        },
    )


async def test_the_grid_read_counts_a_sigma_alert_by_the_addresses_of_its_document() -> None:
    """A confirmed Sigma rule counted 0: the read matched top-level addresses only."""
    actor, target = ADDRESS[A1], ADDRESS[T1]
    docs = [
        _sigma_alert("s1", 10, actor, target, "Sigma Web Shell Upload"),
        _sigma_alert("s2", 20, target, actor, "Sigma Web Shell Upload"),
        # A negative control: a Sigma alert between other machines.
        _sigma_alert("s3", 30, actor, "198.51.100.99", "Sigma Web Shell Upload"),
        # A negative control: the envelope of a document that is no alert.
        _grid_doc(
            "z1",
            40,
            {"event": {"dataset": "zeek.http"}, "event_data": {"source": {"ip": actor}}},
        ),
        _grid_doc(
            "a1",
            50,
            {
                "rule": {"name": "RULE A"},
                "event": {"dataset": "suricata.alert"},
                "source": {"ip": actor},
                "destination": {"ip": target},
            },
        ),
    ]

    class Grid:
        async def search(self, index: str, query: dict[str, Any], **kw: Any) -> EsSearchResult:
            body = {"query": query, "size": kw["size"], "aggs": kw["aggs"]}
            answer = mock_es.search_docs(body, docs)
            return EsSearchResult(
                total=answer["hits"]["total"]["value"],
                took_ms=1,
                aggregations=answer.get("aggregations"),
            )

    spec = PairSpec(
        "agent:a1",
        "ip:t1",
        (actor,),
        (target,),
        frozenset({"Sigma Web Shell Upload"}),
        1,
    )
    got = await events.read_events(
        Grid(),  # type: ignore[arg-type]
        _Settings(),  # type: ignore[arg-type]
        pairs=[spec],
        start=T0,
        end=T0 + timedelta(hours=1),
    )
    assert got is not None
    (pair,) = got.pairs
    assert (pair.alerts, pair.other_alerts) == (2, 1)
    assert pair.records == 3
    # The timeline counts the two Sigma alerts of the confirmed rule.
    assert got.timeline is not None
    assert sum(b.alerts for lane in got.timeline.lanes for b in lane.buckets) == 2


async def test_the_close_scope_holds_a_sigma_alert_of_the_confirmed_rule() -> None:
    actor, target = ADDRESS[A1], ADDRESS[T1]
    docs = [
        _sigma_alert("s1", 10, actor, target, "Sigma Web Shell Upload"),
        _sigma_alert("s3", 30, actor, "198.51.100.99", "Sigma Web Shell Upload"),
    ]

    class Grid:
        async def search(self, index: str, query: dict[str, Any], **kw: Any) -> EsSearchResult:
            body = {"query": query, "size": kw["size"], "_source": kw["source"], "sort": kw["sort"]}
            answer = mock_es.search_docs(body, docs)
            return EsSearchResult(
                total=answer["hits"]["total"]["value"], took_ms=1, hits=answer["hits"]["hits"]
            )

    spec = PairSpec(
        "agent:a1", "ip:t1", (actor,), (target,), frozenset({"Sigma Web Shell Upload"}), 1
    )
    scope = await events.read_close_scope(
        Grid(),  # type: ignore[arg-type]
        _Settings(),  # type: ignore[arg-type]
        pairs=[spec],
        start=T0,
        end=T0 + timedelta(hours=1),
    )
    assert (scope.alerts, scope.alert_ids) == (1, ("s1",))


async def test_a_slow_grid_read_gives_none_after_the_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(events, "READ_TIMEOUT_S", 0.05)
    started = asyncio.get_running_loop().time()
    got = await _read(_Elastic(_answer(), delay=5))
    assert got is None
    assert asyncio.get_running_loop().time() - started < 2
    # NEGATIVE CONTROL: the same grid inside the timeout answers.
    monkeypatch.setattr(events, "READ_TIMEOUT_S", 10.0)
    assert await _read(_Elastic(_answer(), delay=0.01)) is not None


async def test_a_campaign_with_no_pair_reads_nothing() -> None:
    elastic = _Elastic(_answer())
    got = await events.read_events(
        elastic,  # type: ignore[arg-type]
        _Settings(),  # type: ignore[arg-type]
        pairs=[],
        start=T0,
        end=T0,
    )
    assert got is not None
    assert (got.source, got.pairs, elastic.calls) == ("grid", (), [])


async def test_the_basis_changes_with_a_confirmed_rule_an_address_or_the_window() -> None:
    base = events.events_basis([_pair()], T0, T0 + timedelta(hours=1))
    assert base == events.events_basis([_pair()], T0, T0 + timedelta(hours=1))
    assert base != events.events_basis(
        [_pair(confirmed=frozenset({"RULE A", "RULE B"}))], T0, T0 + timedelta(hours=1)
    )
    assert base != events.events_basis(
        [_pair(source_addresses=("192.0.2.99",))], T0, T0 + timedelta(hours=1)
    )
    assert base != events.events_basis([_pair()], T0, T0 + timedelta(hours=2))
    # NEGATIVE CONTROL: the count of investigations is no part of the basis.
    assert base == events.events_basis([_pair(investigations=9)], T0, T0 + timedelta(hours=1))
