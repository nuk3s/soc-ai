"""An empty alert queue has to say WHICH empty it is.

Measured on a Security Onion grid on 2026-09-05: the configured alerts filter
matched 2 documents in 24 hours while another alert label matched 25. The
console showed a single group, and a hunt run against the same grid concluded
that no malicious indication was found, partly because the alert plane it
consulted was empty. Nothing in the response could tell that apart from a quiet
night.

Two answers are wrong here and only one of them is obvious. Reporting a
mismatch on an idle grid is the over-correction, and it is how a real mismatch
gets scrolled past; reporting a quiet grid when the read failed is the original
sin in a new place. Both are guarded below.

Documentation addresses only (RFC 5737 / RFC 1918).
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from elastic_transport import ConnectionError as EsConnectionError
from fastapi.testclient import TestClient
from soc_ai.config import DEFAULT_ALERTS_QUERY, Settings
from soc_ai.main import create_app
from soc_ai.so_client import inventory as inventory_svc
from soc_ai.so_client.elastic import ElasticClient, EsSearchResult, GridPartialResultsError
from soc_ai.so_client.oql import filter_to_dsl, parse_oql

_RETRY_SHORTLY = "retry shortly"


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    inventory_svc._clear_cache()  # the inventory TTL cache outlives a test
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


class _LabelCounts:
    """``ElasticClient.search`` double scripted by alert-label OQL.

    Attributes a call to whichever label's clause it carries in ``must[0]``,
    translated through the same ``parse_oql``/``filter_to_dsl`` path the feed's
    filter builder uses. An unscripted label answers 0, and every call is
    recorded so a test can assert what the route did and did not spend.
    """

    def __init__(self, counts: dict[str, int]) -> None:
        self._by_clause = {_clause(label): total for label, total in counts.items()}
        self.calls: list[dict[str, Any]] = []

    async def __call__(self, index: str, query: dict[str, Any], **kwargs: Any) -> EsSearchResult:
        self.calls.append({"index": index, "query": query, **kwargs})
        clause = _key(query["bool"]["must"][0])
        return EsSearchResult(total=self._by_clause.get(clause, 0), took_ms=1)


def _key(clause: dict[str, Any]) -> str:
    return repr(sorted(clause.items()))


def _clause(label: str) -> str:
    return _key(filter_to_dsl(parse_oql(label).filter_))


def _empty_reason(client: TestClient, search: Any) -> dict[str, Any]:
    with patch.object(ElasticClient, "search", search):
        resp = client.get("/api/v1/alerts/empty-reason?range=24h")
    assert resp.status_code == 200
    body: dict[str, Any] = resp.json()
    return body


class TestTheConsoleSaysWhichEmptyItIs:
    def test_a_grid_where_no_label_finds_anything_is_quiet(self, client: TestClient) -> None:
        """Nothing is misconfigured. Saying otherwise on every idle grid is how
        the row stops being read on the one night it matters."""
        body = _empty_reason(client, _LabelCounts({}))
        assert body["reason"] == "quiet"
        assert "filter" not in body["hint"].lower()

    def test_a_filter_that_matched_nothing_while_another_label_did_says_so(
        self, client: TestClient
    ) -> None:
        """The measured shape. The hint has to name the label and the count, or
        the analyst is told something is wrong and not what."""
        body = _empty_reason(client, _LabelCounts({"event.kind:alert": 25}))
        assert body["reason"] == "filter_mismatch"
        assert "event.kind:alert" in body["hint"]
        assert "25" in body["hint"]

    def test_a_feed_that_is_not_empty_has_nothing_to_explain(
        self, client: TestClient, settings_kratos: Settings
    ) -> None:
        counts = {settings_kratos.webui_alerts_query: 12}
        body = _empty_reason(client, _LabelCounts(counts))
        assert body["reason"] == "not_empty"


def _with_filter(client: TestClient, oql: str, counts: dict[str, int]) -> dict[str, Any]:
    """Answer the empty-reason route with ``oql`` configured as the feed filter."""
    state = client.app.state  # type: ignore[attr-defined]
    original = state.settings
    state.settings = original.model_copy(update={"webui_alerts_query": oql})
    try:
        return _empty_reason(client, _LabelCounts(counts))
    finally:
        state.settings = original


class TestTheExplanationNamesSomethingTheAnalystCanSet:
    def test_a_tie_goes_to_a_label_the_product_ships(self, client: TestClient) -> None:
        """``tags:alerts`` is measured, its mechanism is not confirmed, and it
        is a strict subset of the shipped default. Naming it on a tie tells an
        analyst to trust a label this project cannot explain, over one it
        ships. Order alone decided this, and the order was written for the
        doctor's output, not for a recommendation.
        """
        body = _with_filter(client, "tags:alert", {"tags:alerts": 22, "event.kind:alert": 22})
        assert body["reason"] == "filter_mismatch"
        assert "event.kind:alert" in body["hint"]
        assert "tags:alerts" not in body["hint"]

    def test_the_sentence_names_a_value_to_paste(self, client: TestClient) -> None:
        """ "Change WEBUI_ALERTS_QUERY" leaves the analyst exactly where they
        were: they already know the queue is empty. The value has to be in the
        sentence, and it has to keep what the current filter matches, for the
        same reason the doctor's hint does.
        """
        body = _with_filter(client, "tags:alert", {"event.kind:alert": 34})
        assert f"WEBUI_ALERTS_QUERY={DEFAULT_ALERTS_QUERY}" in body["hint"]

    def test_a_label_that_actually_wins_is_still_named(self, client: TestClient) -> None:
        """The negative control: this is a tie-break, not a ban.

        A route that refused to name ``tags:alerts`` at all would hide the
        larger number on the grid it was measured on, which is the same class
        of defect one preference deeper: the explanation would be tidy and
        would no longer describe the grid.
        """
        body = _with_filter(client, "tags:alert", {"tags:alerts": 33, "event.kind:alert": 10})
        assert "tags:alerts" in body["hint"]
        assert "33" in body["hint"]
        assert "WEBUI_ALERTS_QUERY=tags:alert OR tags:alerts" in body["hint"]


class TestAnUnreadableGridIsNeverReportedAsAQuietOne:
    """The over-correction guard, and the one this codebase has shipped wrong
    before: a failed read answered as a fact about the network."""

    def test_an_unreachable_grid_is_unknown(self, client: TestClient) -> None:
        search = AsyncMock(side_effect=EsConnectionError("connection refused"))
        body = _empty_reason(client, search)
        assert body["reason"] == "unknown"
        assert _RETRY_SHORTLY in body["hint"]

    def test_a_half_read_grid_is_unknown_and_keeps_the_shard_story(
        self, client: TestClient
    ) -> None:
        """A partial read undercounts every label at once, so it can produce a
        perfect-looking mismatch out of nothing. It also is not slowness: the
        shard hint must not tell the analyst to retry."""
        exc = GridPartialResultsError(
            "partial search results from logs-*: 2 of 4 shards failed",
            shards_failed=2,
            shards_total=4,
        )
        body = _empty_reason(client, AsyncMock(side_effect=exc))
        assert body["reason"] == "unknown"
        assert "2 of 4" in body["hint"]
        assert _RETRY_SHORTLY not in body["hint"]

    def test_a_filter_the_query_builder_rejects_is_not_a_quiet_grid(
        self, client: TestClient
    ) -> None:
        """An unparseable filter empties the feed on every request, and the
        console used to render that as a calm night too."""
        state = client.app.state  # type: ignore[attr-defined]
        original = state.settings
        state.settings = original.model_copy(update={"webui_alerts_query": "not_a_field:alert"})
        try:
            body = _empty_reason(client, _LabelCounts({}))
        finally:
            state.settings = original
        assert body["reason"] == "bad_filter"
        assert "WEBUI_ALERTS_QUERY" in body["hint"]
        # A filter that does not parse matches nothing anywhere, so there is
        # nothing to preserve and no count to compare — but the sentence still
        # has to end somewhere the analyst can act, and the product ships the
        # value. Same branch, same answer, as `soc-ai doctor`.
        assert DEFAULT_ALERTS_QUERY in body["hint"]


def test_an_empty_feed_costs_the_list_route_no_more_than_a_full_one(
    client: TestClient,
) -> None:
    """The explanation is a second request, on purpose.

    Folding the label counts into the list route would put four extra searches
    on a screen that polls every ten seconds, for the case that is normal on a
    calm grid. This pins the cost: the list route issues the same searches
    whether or not it found anything.
    """
    bucket = {
        "key": "ET DOC TEST Suspicious Beacon",
        "doc_count": 3,
        "latest": {"hits": {"hits": [{"_id": "abc123", "_source": {"@timestamp": "2026-09-05"}}]}},
    }

    def _count_list_searches(aggregations: dict[str, Any] | None, total: int) -> int:
        search = AsyncMock(
            return_value=EsSearchResult(total=total, took_ms=1, aggregations=aggregations)
        )
        with patch.object(ElasticClient, "search", search):
            resp = client.get("/api/v1/alerts?range=24h")
        assert resp.status_code == 200
        return int(search.await_count)

    full = _count_list_searches({"rules": {"buckets": [bucket]}}, 3)
    empty = _count_list_searches({"rules": {"buckets": []}}, 0)
    assert empty == full
