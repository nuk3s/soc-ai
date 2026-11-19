"""The OQL tool sends the forms that the grid takes, from the field types of the grid.

Production, 2026-11-19: ``... | sortby network.bytes desc | head 5`` failed 3 of
612 shards with "No mapping found for [network.bytes] in order to sort on". A
sort on a field that one index does not map fails the shards of that index.
The tool now reads the type of the sort field from ``_field_caps`` and sends it
as the ``unmapped_type``. These tests drive the real :class:`ElasticClient`
with a stub of the Elasticsearch client, so the request shape is pinned.

The rule for a field with two types: no ``unmapped_type``. The sort then goes
as written, and a rejection carries its reason to the model.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from elastic_transport import ConnectionError as EsConnectionError
from soc_ai.config import Settings
from soc_ai.errors import OqlValidationError
from soc_ai.so_client.elastic import ElasticClient, EsSearchResult
from soc_ai.tools.query_events import query_events_oql

_INDICES = [
    ".ds-logs-zeek-so-2026.10.28-000001",
    ".ds-logs-endpoint.events.process-default-2026.10.28-000001",
    ".ds-logs-suricata-so-2026.10.28-000001",
]

_OK = {
    "took": 3,
    "timed_out": False,
    "_shards": {"total": 3, "successful": 3, "skipped": 0, "failed": 0},
    "hits": {"total": {"value": 0, "relation": "eq"}, "hits": []},
}


def _one_type(field: str, kind: str) -> dict[str, Any]:
    """A field with one type in each index that maps it: no ``indices`` key."""
    return {field: {kind: {"type": kind, "searchable": True, "aggregatable": True}}}


def _caps(*entries: dict[str, Any]) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    for entry in entries:
        fields.update(entry)
    return {"indices": list(_INDICES), "fields": fields}


# The production answer for ``message``: text in most indices, keyword in some.
_TWO_TYPES = {
    "message": {
        "text": {
            "type": "text",
            "searchable": True,
            "aggregatable": False,
            "indices": _INDICES[:2],
        },
        "keyword": {
            "type": "keyword",
            "searchable": True,
            "aggregatable": True,
            "indices": _INDICES[2:],
        },
    }
}


@pytest.fixture
def fake_es() -> Iterator[AsyncMock]:
    es = AsyncMock()
    es.search.return_value = _OK
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=es):
        yield es


def _body(fake_es: AsyncMock) -> dict[str, Any]:
    """The body of the query search. A zero-hit answer adds a field-check search after it."""
    body: dict[str, Any] = fake_es.search.call_args_list[0].kwargs["body"]
    return body


def _sort_of(fake_es: AsyncMock) -> list[dict[str, Any]]:
    body = _body(fake_es)
    sort: list[dict[str, Any]] = body["sort"]
    return sort


async def _query(settings: Settings, query: str, client: ElasticClient | None = None) -> Any:
    return await query_events_oql(
        query, elastic=client or ElasticClient(settings), settings=settings
    )


_SORT_QUERY = "event.dataset:zeek.conn | sortby network.bytes desc | head 5"


@pytest.mark.asyncio
async def test_a_field_with_one_type_sorts_with_its_unmapped_type(
    settings_kratos: Settings, fake_es: AsyncMock
) -> None:
    fake_es.field_caps.return_value = _caps(_one_type("network.bytes", "long"))
    await _query(settings_kratos, _SORT_QUERY)
    assert _sort_of(fake_es) == [{"network.bytes": {"order": "desc", "unmapped_type": "long"}}]


@pytest.mark.asyncio
async def test_the_field_caps_request_names_the_fields_as_a_list(
    settings_kratos: Settings, fake_es: AsyncMock
) -> None:
    """A comma string came back as an empty ``fields`` object on production."""
    fake_es.field_caps.return_value = _caps(_one_type("network.bytes", "long"))
    await _query(settings_kratos, _SORT_QUERY)
    kwargs = fake_es.field_caps.call_args.kwargs
    assert kwargs == {
        "index": settings_kratos.events_index_pattern,
        "fields": ["network.bytes"],
        "ignore_unavailable": True,
        "allow_no_indices": True,
    }


@pytest.mark.asyncio
async def test_a_field_that_no_index_maps_is_a_query_error_with_no_search(
    settings_kratos: Settings, fake_es: AsyncMock
) -> None:
    fake_es.field_caps.return_value = _caps(_one_type("zeek.conn.orig_bytes", "long"))
    with pytest.raises(OqlValidationError) as excinfo:
        await _query(settings_kratos, "* | sortby network.bytes desc")
    assert "network.bytes" in str(excinfo.value)
    assert excinfo.value.fragment == "network.bytes"
    fake_es.search.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_parent_object_is_no_type(settings_kratos: Settings, fake_es: AsyncMock) -> None:
    """The answer holds parent objects (``destination``, ``zeek.conn``) as ``object``."""
    fake_es.field_caps.return_value = _caps(
        {"zeek.conn": {"object": {"type": "object", "searchable": False, "aggregatable": False}}}
    )
    with pytest.raises(OqlValidationError):
        await _query(settings_kratos, "* | sortby zeek.conn desc")
    fake_es.search.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_scaled_float_field_sorts_with_the_unmapped_type_double(
    settings_kratos: Settings, fake_es: AsyncMock
) -> None:
    """``scaled_float`` needs a scaling factor, so it is no ``unmapped_type``.

    The production grid failed the unmapped shards with "Field [scaling_factor]
    is required" (2026-11-19, read only). A scaled float sorts as a double.
    """
    fake_es.field_caps.return_value = _caps(_one_type("network.bytes", "scaled_float"))
    await _query(settings_kratos, _SORT_QUERY)
    assert _sort_of(fake_es) == [{"network.bytes": {"order": "desc", "unmapped_type": "double"}}]


@pytest.mark.asyncio
async def test_a_type_that_is_no_unmapped_type_sorts_as_written(
    settings_kratos: Settings, fake_es: AsyncMock
) -> None:
    """NEGATIVE CONTROL: a type outside the table is never sent as an ``unmapped_type``."""
    fake_es.field_caps.return_value = _caps(_one_type("network.bytes", "geo_point"))
    await _query(settings_kratos, _SORT_QUERY)
    assert _sort_of(fake_es) == [{"network.bytes": {"order": "desc"}}]


@pytest.mark.asyncio
async def test_a_field_with_two_types_sorts_as_written(
    settings_kratos: Settings, fake_es: AsyncMock
) -> None:
    fake_es.field_caps.return_value = _caps(_TWO_TYPES)
    await _query(settings_kratos, "* | sortby message asc")
    assert _sort_of(fake_es) == [{"message": {"order": "asc"}}]


@pytest.mark.asyncio
async def test_with_no_answer_from_the_field_caps_the_sort_goes_as_written(
    settings_kratos: Settings, fake_es: AsyncMock
) -> None:
    fake_es.field_caps.side_effect = EsConnectionError("connection refused")
    await _query(settings_kratos, _SORT_QUERY)
    assert _sort_of(fake_es) == [{"network.bytes": {"order": "desc"}}]


@pytest.mark.asyncio
async def test_an_answer_of_an_unknown_shape_is_no_answer(
    settings_kratos: Settings, fake_es: AsyncMock
) -> None:
    fake_es.field_caps.return_value = {"indices": []}
    await _query(settings_kratos, _SORT_QUERY)
    assert _sort_of(fake_es) == [{"network.bytes": {"order": "desc"}}]


@pytest.mark.asyncio
async def test_the_types_are_cached_and_a_failed_read_is_not_retried_at_once(
    settings_kratos: Settings, fake_es: AsyncMock
) -> None:
    client = ElasticClient(settings_kratos)
    fake_es.field_caps.return_value = _caps(_one_type("network.bytes", "long"))
    await _query(settings_kratos, _SORT_QUERY, client)
    await _query(settings_kratos, _SORT_QUERY, client)
    assert fake_es.field_caps.await_count == 1

    fake_es.field_caps.reset_mock()
    fake_es.field_caps.side_effect = EsConnectionError("connection refused")
    other = "* | sortby zeek.conn.orig_bytes desc"
    await _query(settings_kratos, other, client)
    await _query(settings_kratos, other, client)
    assert fake_es.field_caps.await_count == 1


@pytest.mark.asyncio
async def test_a_query_with_no_sort_reads_no_field_caps(
    settings_kratos: Settings, fake_es: AsyncMock
) -> None:
    await _query(settings_kratos, "event.dataset:zeek.conn | head 5")
    fake_es.field_caps.assert_not_awaited()
    assert "sort" not in _body(fake_es)


@pytest.mark.asyncio
async def test_sortby_count_after_groupby_reads_no_field_caps(
    settings_kratos: Settings, fake_es: AsyncMock
) -> None:
    await _query(settings_kratos, "* | groupby source.ip | sortby count desc")
    fake_es.field_caps.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_client_double_with_no_field_types_sends_the_sort_as_written(
    settings_kratos: Settings,
) -> None:
    """Negative control on the fallback: a stub that only searches."""

    class _SearchOnly:
        def __init__(self) -> None:
            self.sort: Any = None

        async def search(self, index: str, query: dict[str, Any], **kw: Any) -> EsSearchResult:
            self.sort = kw.get("sort")
            return EsSearchResult(total=0, took_ms=1)

    stub = _SearchOnly()
    await query_events_oql(_SORT_QUERY, elastic=stub, settings=settings_kratos)  # type: ignore[arg-type]
    assert stub.sort == [{"network.bytes": {"order": "desc"}}]


# ---------------------------------------------------------------------------
# R5: two exact rewrites, each stated to the model
# ---------------------------------------------------------------------------


def _must(fake_es: AsyncMock) -> Any:
    """The clause of the query that the OQL filter became."""
    return _body(fake_es)["query"]["bool"]["must"][0]


_IP_CAPS = _caps(_one_type("destination.ip", "ip"))


@pytest.mark.parametrize(
    ("written", "cidr"),
    [
        ("10.*", "10.0.0.0/8"),
        ("198.51.*", "198.51.0.0/16"),
        ("198.51.100.*", "198.51.100.0/24"),
        ("192.*.*.*", "192.0.0.0/8"),
    ],
)
@pytest.mark.asyncio
async def test_a_wildcard_of_whole_octets_on_an_ip_field_becomes_the_cidr(
    settings_kratos: Settings, fake_es: AsyncMock, written: str, cidr: str
) -> None:
    fake_es.field_caps.return_value = _IP_CAPS
    result = await _query(settings_kratos, f"destination.ip:{written}")
    assert _must(fake_es) == {"term": {"destination.ip": cidr}}
    assert result.rewrites == [
        f'destination.ip:{written} became destination.ip:"{cidr}". An IP field takes a CIDR.'
    ]
    # The model reads the note in the tool result.
    assert result.model_dump(mode="json")["rewrites"] == result.rewrites


@pytest.mark.asyncio
async def test_a_cidr_on_an_ip_field_stays_and_reads_no_field_caps(
    settings_kratos: Settings, fake_es: AsyncMock
) -> None:
    result = await _query(settings_kratos, 'destination.ip:"198.51.100.0/24"')
    assert _must(fake_es) == {"term": {"destination.ip": "198.51.100.0/24"}}
    assert result.rewrites is None
    fake_es.field_caps.assert_not_awaited()


@pytest.mark.parametrize("written", ["192.0.2.1*", "198.51.?.*", "198.51.100.*.*", "2001:db8:*"])
@pytest.mark.asyncio
async def test_any_other_wildcard_on_an_ip_field_is_a_query_error_with_no_search(
    settings_kratos: Settings, fake_es: AsyncMock, written: str
) -> None:
    fake_es.field_caps.return_value = _IP_CAPS
    with pytest.raises(OqlValidationError) as excinfo:
        await _query(settings_kratos, f"destination.ip:{written}")
    message = str(excinfo.value)
    assert "IP field" in message
    assert "CIDR" in message
    assert '"192.0.2.0/24"' in message
    fake_es.search.assert_not_awaited()


@pytest.mark.parametrize(
    "caps",
    [
        # Mapped in no index.
        _caps(_one_type("source.ip", "ip")),
        # Two types: ip in some indices and keyword in others.
        _caps(
            {
                "destination.ip": {
                    "ip": {"type": "ip", "indices": _INDICES[:2]},
                    "keyword": {"type": "keyword", "indices": _INDICES[2:]},
                }
            }
        ),
    ],
    ids=["mapped_in_none", "two_types"],
)
@pytest.mark.asyncio
async def test_an_ip_wildcard_goes_as_written_when_the_field_is_not_ip_only(
    settings_kratos: Settings, fake_es: AsyncMock, caps: dict[str, Any]
) -> None:
    fake_es.field_caps.return_value = caps
    result = await _query(settings_kratos, "destination.ip:198.51.100.*")
    assert _must(fake_es) == {"wildcard": {"destination.ip": {"value": "198.51.100.*"}}}
    assert result.rewrites is None


@pytest.mark.asyncio
async def test_an_ip_wildcard_goes_as_written_with_no_answer(
    settings_kratos: Settings, fake_es: AsyncMock
) -> None:
    """The grid then rejects it, and the tool result carries the reason and the hint."""
    fake_es.field_caps.side_effect = EsConnectionError("connection refused")
    result = await _query(settings_kratos, "destination.ip:198.51.100.*")
    assert _must(fake_es) == {"wildcard": {"destination.ip": {"value": "198.51.100.*"}}}
    assert result.rewrites is None


@pytest.mark.asyncio
async def test_a_wildcard_on_a_keyword_field_is_not_touched(
    settings_kratos: Settings, fake_es: AsyncMock
) -> None:
    fake_es.field_caps.return_value = _caps(_one_type("process.name", "keyword"))
    result = await _query(settings_kratos, "process.name:cmd*")
    assert _must(fake_es) == {"wildcard": {"process.name": {"value": "cmd*"}}}
    assert result.rewrites is None


_DATE_CAPS = _caps(_one_type("@timestamp", "date"))


@pytest.mark.asyncio
async def test_a_spaced_time_range_on_a_date_field_becomes_iso_in_utc(
    settings_kratos: Settings, fake_es: AsyncMock
) -> None:
    fake_es.field_caps.return_value = _DATE_CAPS
    result = await _query(
        settings_kratos, '@timestamp:["2026-10-28 22:44" TO "2026-10-28 23:59:30"]'
    )
    assert _must(fake_es) == {
        "range": {"@timestamp": {"gte": "2026-10-28T22:44:00Z", "lte": "2026-10-28T23:59:30Z"}}
    }
    assert result.rewrites == [
        '@timestamp:["2026-10-28 22:44" TO "2026-10-28 23:59:30"] became '
        '@timestamp:["2026-10-28T22:44:00Z" TO "2026-10-28T23:59:30Z"]. '
        "A date field takes ISO 8601 in UTC."
    ]


@pytest.mark.asyncio
async def test_one_spaced_bound_and_an_open_bound(
    settings_kratos: Settings, fake_es: AsyncMock
) -> None:
    fake_es.field_caps.return_value = _DATE_CAPS
    result = await _query(settings_kratos, '@timestamp:["2026-10-28 22:44" TO *]')
    assert _must(fake_es) == {"range": {"@timestamp": {"gte": "2026-10-28T22:44:00Z"}}}
    assert result.rewrites == [
        '@timestamp:["2026-10-28 22:44" TO *] became @timestamp:["2026-10-28T22:44:00Z" TO *]. '
        "A date field takes ISO 8601 in UTC."
    ]


@pytest.mark.asyncio
async def test_a_spaced_time_value_on_a_date_field_becomes_iso(
    settings_kratos: Settings, fake_es: AsyncMock
) -> None:
    fake_es.field_caps.return_value = _caps(
        {"event.created": {"date": {"type": "date"}, "date_nanos": {"type": "date_nanos"}}}
    )
    result = await _query(settings_kratos, 'event.created:"2026-10-28 22:44:05"')
    assert _must(fake_es) == {"term": {"event.created": "2026-10-28T22:44:05Z"}}
    assert result.rewrites == [
        'event.created:"2026-10-28 22:44:05" became event.created:"2026-10-28T22:44:05Z". '
        "A date field takes ISO 8601 in UTC."
    ]


@pytest.mark.parametrize(
    ("query", "caps"),
    [
        # A date in some indices and a keyword in others.
        (
            '@timestamp:["2026-10-28 22:44" TO "2026-10-28 23:59"]',
            _caps(
                {
                    "@timestamp": {
                        "date": {"type": "date", "indices": _INDICES[:2]},
                        "keyword": {"type": "keyword", "indices": _INDICES[2:]},
                    }
                }
            ),
        ),
        # Mapped in no index.
        ('@timestamp:["2026-10-28 22:44" TO "2026-10-28 23:59"]', _caps()),
        # Not a real time.
        ('@timestamp:["2026-13-40 25:61" TO *]', _DATE_CAPS),
        # A keyword field that holds a time as text.
        ('message:"2026-10-28 22:44"', _caps(_one_type("message", "keyword"))),
    ],
    ids=["two_types", "mapped_in_none", "not_a_time", "keyword_field"],
)
@pytest.mark.asyncio
async def test_a_spaced_time_goes_as_written_when_the_rewrite_is_not_exact(
    settings_kratos: Settings, fake_es: AsyncMock, query: str, caps: dict[str, Any]
) -> None:
    fake_es.field_caps.return_value = caps
    result = await _query(settings_kratos, query)
    assert result.rewrites is None
    assert "T22:44:00Z" not in str(_must(fake_es))


@pytest.mark.asyncio
async def test_a_spaced_time_goes_as_written_with_no_answer(
    settings_kratos: Settings, fake_es: AsyncMock
) -> None:
    fake_es.field_caps.side_effect = EsConnectionError("connection refused")
    result = await _query(settings_kratos, '@timestamp:["2026-10-28 22:44" TO *]')
    assert _must(fake_es) == {"range": {"@timestamp": {"gte": "2026-10-28 22:44"}}}
    assert result.rewrites is None


@pytest.mark.asyncio
async def test_the_dry_run_of_a_rule_reads_the_query_as_written(
    settings_kratos: Settings, fake_es: AsyncMock
) -> None:
    """``rewrite_forms=False`` (the Sigma dry run): no read, no rewrite."""
    fake_es.field_caps.return_value = _IP_CAPS
    result = await query_events_oql(
        "destination.ip:198.51.100.*",
        elastic=ElasticClient(settings_kratos),
        settings=settings_kratos,
        widen_names=False,
        rewrite_forms=False,
    )
    fake_es.field_caps.assert_not_awaited()
    assert _must(fake_es) == {"wildcard": {"destination.ip": {"value": "198.51.100.*"}}}
    assert result.rewrites is None


@pytest.mark.asyncio
async def test_both_rewrites_and_the_sort_in_one_query_read_the_field_caps_once(
    settings_kratos: Settings, fake_es: AsyncMock
) -> None:
    fake_es.field_caps.return_value = _caps(
        _one_type("destination.ip", "ip"),
        _one_type("@timestamp", "date"),
        _one_type("network.bytes", "long"),
    )
    result = await _query(
        settings_kratos,
        'destination.ip:10.* AND @timestamp:["2026-10-28 22:44" TO "2026-10-28 23:59"]'
        " | sortby network.bytes desc | head 5",
    )
    assert fake_es.field_caps.await_count == 1
    assert sorted(fake_es.field_caps.call_args.kwargs["fields"]) == [
        "@timestamp",
        "destination.ip",
        "network.bytes",
    ]
    assert result.rewrites is not None
    assert len(result.rewrites) == 2
    assert _sort_of(fake_es) == [{"network.bytes": {"order": "desc", "unmapped_type": "long"}}]
