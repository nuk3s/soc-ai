"""A count that does not say what it counted gets the reader's unit.

Measured defect. ``t_query_events_oql`` ran ``source.ip:<router> AND
destination.port:22 | groupby destination.ip`` over the events index and
returned ``total: 358`` with bucket ``doc_count`` values, an empty ``hits`` list
and nothing at all saying what had been counted. Triage wrote that up as "the
router made 358 SSH connections to internal hosts (111 to one host)" and closed
a honeypot alert on it.

The arithmetic was right and the sentence was wrong. 348 of the 358 documents
were periodic packetbeat flow records, 3 were endpoint network events and 2 were
the decoy's own log. A flow record is re-emitted per interval, so one session
yields many documents: the 106 documents naming the decoy carried 19 distinct
source ports and sat in two hourly buckets across the whole three-day window.
Two bursts, described as a routine.

The events index is a superset of every sensor on the grid, so this is not a
honeypot-shaped problem. Any query over it can draw documents from datasets the
model never considered, and a bare integer under a key called ``total`` will be
read as whatever unit the question was asked in. So the tool now reports the
composition of what it counted, and names the unit.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from soc_ai.config import Settings
from soc_ai.so_client.elastic import ElasticClient, EsSearchResult
from soc_ai.tools.query_events import query_events_oql

# The reserved aggregations the tool adds so a count can name its own contents.
_COMPOSITION_AGG = "__soc_ai_counted_by_dataset__"
_COMPOSITION_FALLBACK_AGG = "__soc_ai_counted_by_event_dataset__"


def _make_elastic(settings: Settings, response: dict[str, Any]) -> ElasticClient:
    """An ElasticClient backed by a mocked AsyncElasticsearch."""
    fake_es = AsyncMock()
    fake_es.search.return_value = response
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es):
        return ElasticClient(settings)


def _buckets(pairs: list[tuple[str, int]]) -> dict[str, Any]:
    return {
        "doc_count_error_upper_bound": 0,
        "sum_other_doc_count": 0,
        "buckets": [{"key": k, "doc_count": n} for k, n in pairs],
    }


def _the_measured_response() -> dict[str, Any]:
    """The grid's real answer to the query that produced "358 SSH connections".

    Bucket values are the ones the live run received; the composition is what
    the same document set looks like broken out by ``data_stream.dataset``.
    """
    return {
        "took": 4,
        "hits": {"total": {"value": 358, "relation": "eq"}, "hits": []},
        "aggregations": {
            "by_destination_ip": _buckets(
                [("10.0.0.41", 227), ("10.0.0.31", 111), ("10.0.0.42", 20)]
            ),
            _COMPOSITION_AGG: _buckets(
                [
                    ("network_traffic.flow", 348),
                    ("endpoint.events.network", 3),
                    ("opencanary.events", 2),
                ]
            ),
            _COMPOSITION_FALLBACK_AGG: _buckets(
                [
                    ("(no dataset field)", 348),
                    ("endpoint.events.network", 3),
                    ("opencanary.events", 2),
                ]
            ),
        },
    }


@pytest.mark.asyncio
async def test_a_count_names_its_unit_and_its_datasets(settings_kratos: Settings) -> None:
    """358 is 348 flow records plus 5 real events, and the payload has to say so."""
    elastic = _make_elastic(settings_kratos, _the_measured_response())

    result = await query_events_oql(
        "source.ip:10.0.0.254 AND destination.port:22 | groupby destination.ip",
        elastic=elastic,
        settings=settings_kratos,
    )

    assert isinstance(result, EsSearchResult)
    assert result.total == 358
    counted = result.counted
    assert counted is not None, "a bare total with no unit is the defect"
    assert counted["unit"] == "documents"
    assert counted["index_pattern"] == settings_kratos.events_index_pattern
    assert counted["by_dataset"] == [
        {"dataset": "network_traffic.flow", "documents": 348},
        {"dataset": "endpoint.events.network", "documents": 3},
        {"dataset": "opencanary.events", "documents": 2},
    ]
    # The note has to name the specific mislabelling that happened, not gesture
    # at care in general.
    note = counted["note"].lower()
    assert "document" in note
    assert "session" in note and "connection" in note


@pytest.mark.asyncio
async def test_the_composition_does_not_pollute_the_model_s_aggregations(
    settings_kratos: Settings,
) -> None:
    """The model asked for one groupby; it must still see exactly one."""
    elastic = _make_elastic(settings_kratos, _the_measured_response())

    result = await query_events_oql(
        "source.ip:10.0.0.254 AND destination.port:22 | groupby destination.ip",
        elastic=elastic,
        settings=settings_kratos,
    )

    assert result.aggregations is not None
    assert set(result.aggregations) == {"by_destination_ip"}


@pytest.mark.asyncio
async def test_a_single_dataset_count_is_reported_plainly(settings_kratos: Settings) -> None:
    """NEGATIVE CONTROL. The descriptor is not a warning that fires on mixture.

    The same run's decoy-scoped query returned 2 documents from one dataset and
    was entirely honest. The descriptor still attaches, and still says only what
    is true — no caveat, no inflation warning, nothing for a reader to learn to
    ignore.
    """
    response = {
        "took": 3,
        "hits": {"total": {"value": 2, "relation": "eq"}, "hits": []},
        "aggregations": {
            "by_log_logger": _buckets(
                [("LOG_SSH_NEW_CONNECTION", 1), ("LOG_SSH_REMOTE_VERSION_SENT", 1)]
            ),
            _COMPOSITION_AGG: _buckets([("opencanary.events", 2)]),
            _COMPOSITION_FALLBACK_AGG: _buckets([("opencanary.events", 2)]),
        },
    }
    elastic = _make_elastic(settings_kratos, response)

    result = await query_events_oql(
        "source.ip:10.0.0.254 AND event.dataset:opencanary.events | groupby log.logger",
        elastic=elastic,
        settings=settings_kratos,
    )

    assert result.counted is not None
    assert result.counted["by_dataset"] == [{"dataset": "opencanary.events", "documents": 2}]


@pytest.mark.asyncio
async def test_a_grid_without_data_streams_falls_back_to_event_dataset(
    settings_kratos: Settings,
) -> None:
    """NEGATIVE CONTROL. Not every grid ships data streams.

    ``data_stream.dataset`` is unmapped on a classic-index deployment, where an
    unmapped terms agg puts every document in the missing bucket. The descriptor
    must then read ``event.dataset`` rather than report the whole result as
    unlabelled — the failure mode where a fix reports "I cannot tell" on the
    grids it was not developed against.
    """
    response = {
        "took": 2,
        "hits": {"total": {"value": 12, "relation": "eq"}, "hits": []},
        "aggregations": {
            "by_destination_ip": _buckets([("10.0.0.31", 12)]),
            _COMPOSITION_AGG: _buckets([("(no dataset field)", 12)]),
            _COMPOSITION_FALLBACK_AGG: _buckets([("zeek.conn", 12)]),
        },
    }
    elastic = _make_elastic(settings_kratos, response)

    result = await query_events_oql(
        "destination.ip:10.0.0.31 | groupby destination.ip",
        elastic=elastic,
        settings=settings_kratos,
    )

    assert result.counted is not None
    assert result.counted["by_dataset"] == [{"dataset": "zeek.conn", "documents": 12}]


@pytest.mark.asyncio
async def test_a_plain_hits_query_is_described_too(settings_kratos: Settings) -> None:
    """A ``total`` accompanies every result, so every result names its datasets.

    A query with no pipe stage caps its hits at 100 and still reports the full
    total, so the model is told about documents it cannot read — the same naked
    number, one stage earlier. ``aggregations`` stays ``None`` here, the
    documented contract, even though the tool asked for a composition.
    """
    response = {
        "took": 5,
        "hits": {
            "total": {"value": 1, "relation": "eq"},
            "hits": [{"_id": "alert-1", "_source": {"foo": "bar"}}],
        },
        "aggregations": {_COMPOSITION_AGG: _buckets([("suricata.alerts", 1)])},
    }
    elastic = _make_elastic(settings_kratos, response)

    result = await query_events_oql("rule.name:foo", elastic=elastic, settings=settings_kratos)

    assert result.aggregations is None
    assert result.counted is not None
    assert result.counted["by_dataset"] == [{"dataset": "suricata.alerts", "documents": 1}]


@pytest.mark.asyncio
async def test_a_grid_that_returns_no_composition_gets_no_invented_one(
    settings_kratos: Settings,
) -> None:
    """NEGATIVE CONTROL. The descriptor never guesses.

    An ES that declines the aggregation, or a client stubbed to skip it, leaves
    ``counted`` as ``None``. A descriptor that filled in a plausible dataset
    would be the same defect wearing the fix's clothes.
    """
    response = {
        "took": 1,
        "hits": {"total": {"value": 7, "relation": "eq"}, "hits": []},
    }
    elastic = _make_elastic(settings_kratos, response)

    result = await query_events_oql(
        "destination.ip:10.0.0.31 | groupby destination.ip",
        elastic=elastic,
        settings=settings_kratos,
    )

    assert result.counted is None
