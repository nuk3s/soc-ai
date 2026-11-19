"""A query the grid rejects is a query error, and it is not a grid failure.

Production, 2026-11-19: a campaign hunt stated that the process events of a
time "cannot be answered: every query ... returned grid_unavailable across six
variations". The grid was up. Each of the 19 ``grid_unavailable`` results was a
200 answer with ``_shards.failed > 0``: the query was wrong for the type of a
field on the shards that map the field, and the other shards answered. The
seven failure reasons below are the reasons the production grid returned, on
``logs-*`` with 612 shards and ``timed_out`` false.

These tests pin the class (:class:`GridQueryRejectedError`) and the negative
controls on the paths the class must NOT take: a node failure, a mix, a
time-out and an empty failure list stay a :class:`GridPartialResultsError`.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from elastic_transport import TransportError
from soc_ai.config import Settings
from soc_ai.so_client.elastic import (
    QUERY_FAILURE_TYPES,
    ElasticClient,
    GridPartialResultsError,
    GridQueryRejectedError,
)

_TOTAL = 612
_INDEX = ".ds-logs-zeek-so-2026.10.28-000001"

# (failed shards, type, reason) as the production grid returned them.
_PRODUCTION_REJECTIONS: dict[str, tuple[int, str, str]] = {
    "prefix_on_ip": (
        97,
        "query_shard_exception",
        "Can only use prefix queries on keyword, text and wildcard fields - not on "
        "[destination.ip] which is of type [ip]",
    ),
    "date_with_a_space": (
        168,
        "query_shard_exception",
        "failed to create query: failed to parse date field [2026-10-28 22:44] with format "
        "[strict_date_optional_time||epoch_millis]",
    ),
    "sort_network_bytes": (
        3,
        "query_shard_exception",
        "No mapping found for [network.bytes] in order to sort on",
    ),
    "sort_orig_bytes": (
        15,
        "query_shard_exception",
        "No mapping found for [zeek.conn.orig_bytes] in order to sort on",
    ),
    "groupby_text": (
        3,
        "illegal_argument_exception",
        "match_only_text fields do not support sorting and aggregations",
    ),
    "text_on_a_number": (
        2,
        "query_shard_exception",
        'failed to create query: For input string: "TXT"',
    ),
    "date_math_ms": (
        339,
        "parse_exception",
        "operator not supported for date math [-1728000ms]",
    ),
}


def _failure(kind: str, reason: str, **extra: Any) -> dict[str, Any]:
    return {
        "shard": 0,
        "index": _INDEX,
        "node": "node-a",
        "reason": {"type": kind, "reason": reason, "index": _INDEX, **extra},
    }


def _response(
    failures: list[dict[str, Any]] | None,
    *,
    failed: int,
    timed_out: bool = False,
    hits: int = 0,
) -> dict[str, Any]:
    shards: dict[str, Any] = {
        "total": _TOTAL,
        "successful": _TOTAL - failed,
        "skipped": 0,
        "failed": failed,
    }
    if failures is not None:
        shards["failures"] = failures
    return {
        "took": 70,
        "timed_out": timed_out,
        "_shards": shards,
        "hits": {
            "total": {"value": hits, "relation": "eq"},
            "hits": [{"_id": f"doc-{n}"} for n in range(hits)],
        },
    }


async def _search(settings: Settings, response: dict[str, Any]) -> Any:
    fake_es = AsyncMock()
    fake_es.search.return_value = response
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es):
        client = ElasticClient(settings)
        return await client.search("logs-*", {"match_all": {}})


# ---------------------------------------------------------------------------
# The class
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("case", sorted(_PRODUCTION_REJECTIONS))
@pytest.mark.asyncio
async def test_each_production_rejection_is_a_rejected_query(
    settings_kratos: Settings, case: str
) -> None:
    failed, kind, reason = _PRODUCTION_REJECTIONS[case]
    response = _response([_failure(kind, reason)], failed=failed, hits=5)

    with pytest.raises(GridQueryRejectedError) as excinfo:
        await _search(settings_kratos, response)

    exc = excinfo.value
    assert exc.reason == f"{kind}: {reason}"
    assert exc.shards_failed == failed
    assert exc.shards_total == _TOTAL
    assert exc.timed_out is False


def test_a_rejected_query_keeps_every_existing_except_arm() -> None:
    """Every ``except GridPartialResultsError`` and ``except TransportError``
    arm, the doctor and the audit chain catch it as today."""
    assert issubclass(GridQueryRejectedError, GridPartialResultsError)
    assert issubclass(GridQueryRejectedError, TransportError)


def test_the_query_failure_types_are_one_constant() -> None:
    assert {
        "query_shard_exception",
        "parse_exception",
        "parsing_exception",
        "illegal_argument_exception",
        "number_format_exception",
        "date_time_parse_exception",
        "x_content_parse_exception",
    } == QUERY_FAILURE_TYPES


@pytest.mark.asyncio
async def test_every_listed_failure_of_a_query_type_is_a_rejection(
    settings_kratos: Settings,
) -> None:
    """Two reasons from two indices, both query types."""
    response = _response(
        [
            _failure("query_shard_exception", "No mapping found for [x.y] in order to sort on"),
            _failure("number_format_exception", 'For input string: "TXT"'),
        ],
        failed=4,
    )
    with pytest.raises(GridQueryRejectedError) as excinfo:
        await _search(settings_kratos, response)
    assert excinfo.value.reason.startswith("query_shard_exception: No mapping found")


@pytest.mark.asyncio
async def test_a_wrapped_query_failure_is_read_through_its_cause(
    settings_kratos: Settings,
) -> None:
    """A shard on another cluster answers through ``remote_transport_exception``.
    The reason is the one of the cause: the wrapper text names nodes."""
    wrapped = {
        "shard": 0,
        "index": "remote:" + _INDEX,
        "reason": {
            "type": "remote_transport_exception",
            "reason": "[node-b][198.51.100.9:9300][indices:data/read/search[phase/query]]",
            "caused_by": {
                "type": "query_shard_exception",
                "reason": "No mapping found for [network.bytes] in order to sort on",
            },
        },
    }
    with pytest.raises(GridQueryRejectedError) as excinfo:
        await _search(settings_kratos, _response([wrapped], failed=1))
    assert excinfo.value.reason == (
        "query_shard_exception: No mapping found for [network.bytes] in order to sort on"
    )
    assert "198.51.100.9" not in excinfo.value.reason


@pytest.mark.asyncio
async def test_a_rejected_query_returns_no_hits_under_the_partial_opt_out(
    settings_kratos: Settings,
) -> None:
    """``es_fail_on_partial_results=false`` lets an operator read a chronically
    red shard. It must not hand back the hits of a rejected query: the shards
    that hold the field did not answer, so 5 hits are not 5 of the answer."""
    settings_kratos.es_fail_on_partial_results = False
    failed, kind, reason = _PRODUCTION_REJECTIONS["prefix_on_ip"]
    response = _response([_failure(kind, reason)], failed=failed, hits=5)

    with pytest.raises(GridQueryRejectedError):
        await _search(settings_kratos, response)


# ---------------------------------------------------------------------------
# Negative controls: the grid did not answer, and the class stays as today
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "kind",
    ["node_not_connected_exception", "no_shard_available_action_exception"],
)
@pytest.mark.asyncio
async def test_a_node_failure_stays_a_partial_read(settings_kratos: Settings, kind: str) -> None:
    response = _response([_failure(kind, "the node is gone")], failed=2)
    with pytest.raises(GridPartialResultsError) as excinfo:
        await _search(settings_kratos, response)
    assert not isinstance(excinfo.value, GridQueryRejectedError)
    assert excinfo.value.reason == f"{kind}: the node is gone"


@pytest.mark.asyncio
async def test_a_query_failure_beside_a_node_failure_stays_a_partial_read(
    settings_kratos: Settings,
) -> None:
    failed, kind, reason = _PRODUCTION_REJECTIONS["prefix_on_ip"]
    response = _response(
        [
            _failure(kind, reason),
            _failure("node_not_connected_exception", "[node-c] not connected"),
        ],
        failed=failed + 1,
    )
    with pytest.raises(GridPartialResultsError) as excinfo:
        await _search(settings_kratos, response)
    assert not isinstance(excinfo.value, GridQueryRejectedError)


@pytest.mark.asyncio
async def test_a_wrapped_node_failure_stays_a_partial_read(settings_kratos: Settings) -> None:
    wrapped = {
        "shard": 0,
        "reason": {
            "type": "remote_transport_exception",
            "reason": "[node-b][indices:data/read/search[phase/query]]",
            "caused_by": {
                "type": "circuit_breaking_exception",
                "reason": "[parent] Data too large",
            },
        },
    }
    with pytest.raises(GridPartialResultsError) as excinfo:
        await _search(settings_kratos, _response([wrapped], failed=1))
    assert not isinstance(excinfo.value, GridQueryRejectedError)


@pytest.mark.asyncio
async def test_a_timed_out_search_stays_a_partial_read(settings_kratos: Settings) -> None:
    failed, kind, reason = _PRODUCTION_REJECTIONS["sort_network_bytes"]
    response = _response([_failure(kind, reason)], failed=failed, timed_out=True)
    with pytest.raises(GridPartialResultsError) as excinfo:
        await _search(settings_kratos, response)
    assert not isinstance(excinfo.value, GridQueryRejectedError)
    assert excinfo.value.timed_out is True


@pytest.mark.parametrize("failures", [None, []])
@pytest.mark.asyncio
async def test_failed_shards_with_no_failure_list_stay_a_partial_read(
    settings_kratos: Settings, failures: list[dict[str, Any]] | None
) -> None:
    with pytest.raises(GridPartialResultsError) as excinfo:
        await _search(settings_kratos, _response(failures, failed=3))
    assert not isinstance(excinfo.value, GridQueryRejectedError)


@pytest.mark.asyncio
async def test_a_node_failure_under_the_opt_out_still_returns_its_hits(
    settings_kratos: Settings,
) -> None:
    """The opt-out keeps its meaning for a grid that did not answer."""
    settings_kratos.es_fail_on_partial_results = False
    response = _response(
        [_failure("no_shard_available_action_exception", "recovering")], failed=2, hits=4
    )
    result = await _search(settings_kratos, response)
    assert result.total == 4
