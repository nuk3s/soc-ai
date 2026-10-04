"""Tests for the egress-policy audit counts (``soc_ai/audit/counts.py``).

The live finding: one old monthly audit index maps ``kind`` as ``text``. The
``terms`` aggregation over ``soc-ai-audit-*`` then failed with "Fielddata is
disabled on [kind]", every count on the egress panel went null, and the panel
gave no reason. The fake grid below refuses the aggregation exactly that way
whenever the request reaches the text-mapped index on ``kind``.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

from elasticsearch import BadRequestError
from pydantic import SecretStr
from soc_ai.audit.counts import audit_counts_by_kind, audit_counts_with_reason
from soc_ai.config import Settings
from soc_ai.so_client.elastic import ElasticClient

_OLD = "soc-ai-audit-2026.05.29"
_NEW = "soc-ai-audit-2026.09.30"


def _fielddata_error(index: str) -> BadRequestError:
    meta: Any = type("Meta", (), {"status": 400, "headers": {}})()
    return BadRequestError(
        message=f"Fielddata is disabled on [kind] in [{index}]",
        meta=meta,
        body={"error": {"type": "illegal_argument_exception"}},
    )


class _DriftedGrid:
    """A grid with one audit index whose ``kind`` is text (with or without a keyword sub-field).

    ``field_caps`` answers the way ES does for a field with two types. A search
    whose index expression reaches the old index (not excluded with ``-name``)
    and aggregates on ``kind`` fails with the real fielddata error.
    """

    def __init__(self, *, keyword: bool, field_caps_fails: bool = False) -> None:
        self.keyword = keyword
        self.field_caps_fails = field_caps_fails
        self.searches: list[tuple[str, str]] = []
        # Seven-day counts each index holds.
        self.counts = {
            _NEW: {"oracle_escalation": 3, "notification": 4},
            _OLD: {"oracle_escalation": 2},
        }

    async def field_caps(self, **kw: Any) -> dict[str, Any]:
        if self.field_caps_fails:
            raise RuntimeError("field caps unavailable")
        # Elasticsearch 9 answers the string form of ``fields`` with no fields
        # at all. Production read ``{}`` that way and aggregated on ``kind``.
        assert isinstance(kw.get("fields"), list), "fields must be a list"
        fields: dict[str, Any] = {
            "kind": {
                "keyword": {"type": "keyword", "aggregatable": True, "indices": [_NEW]},
                "text": {"type": "text", "aggregatable": False, "indices": [_OLD]},
            }
        }
        if self.keyword:
            fields["kind.keyword"] = {
                "keyword": {"type": "keyword", "aggregatable": True, "indices": [_OLD]}
            }
        return {"indices": [_NEW, _OLD], "fields": fields}

    def _targets(self, index: str) -> list[str]:
        parts = index.split(",")
        excluded = {p[1:] for p in parts if p.startswith("-")}
        chosen: list[str] = []
        for p in parts:
            if p.startswith("-"):
                continue
            if p.endswith("*"):
                chosen.extend(i for i in (_NEW, _OLD) if i.startswith(p[:-1]))
            else:
                chosen.append(p)
        return [i for i in chosen if i not in excluded]

    async def search(self, *, index: str, body: dict[str, Any], **_kw: Any) -> dict[str, Any]:
        field = body["aggs"]["by_kind"]["terms"]["field"]
        self.searches.append((index, field))
        targets = self._targets(index)
        if field == "kind" and _OLD in targets:
            raise _fielddata_error(_OLD)
        totals: dict[str, int] = {}
        for idx in targets:
            for kind, n in self.counts[idx].items():
                totals[kind] = totals.get(kind, 0) + n
        buckets = [{"key": k, "doc_count": n} for k, n in totals.items()]
        return {
            "took": 1,
            "timed_out": False,
            "hits": {"total": {"value": 0, "relation": "eq"}, "hits": []},
            "aggregations": {"by_kind": {"buckets": buckets}},
        }


def _elastic(grid: _DriftedGrid) -> ElasticClient:
    settings = Settings(
        so_host="https://so.example.com",
        so_username="analyst",
        so_password=SecretStr("password123"),
        so_verify_ssl=False,
        es_hosts=["https://so.example.com:9200"],
        litellm_base_url="http://localhost:4000",
        api_auth_required=False,
    )
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=grid):
        return ElasticClient(settings)


_KINDS = ["notification", "oracle_adjudication", "oracle_escalation"]


async def test_a_text_mapped_index_is_counted_on_its_keyword_form() -> None:
    """The old index counts through ``kind.keyword``; the rest through ``kind``."""
    grid = _DriftedGrid(keyword=True)
    result = await audit_counts_with_reason(_elastic(grid), "soc-ai-audit", _KINDS)
    assert result.counts == {"notification": 4, "oracle_adjudication": 0, "oracle_escalation": 5}
    assert result.reason is None
    assert ("soc-ai-audit-*,-" + _OLD, "kind") in grid.searches
    assert (_OLD, "kind.keyword") in grid.searches


async def test_a_text_mapped_index_without_keyword_is_left_out_and_named() -> None:
    """No keyword form: the index is excluded, the count stays, the reason names it."""
    grid = _DriftedGrid(keyword=False)
    result = await audit_counts_with_reason(_elastic(grid), "soc-ai-audit", _KINDS)
    assert result.counts == {"notification": 4, "oracle_adjudication": 0, "oracle_escalation": 3}
    assert result.reason is not None
    assert _OLD in result.reason
    assert "—" not in result.reason


async def test_a_refused_count_returns_null_with_the_reason(caplog: Any) -> None:
    """When the aggregation still fails, every count is null and the reason says why.

    The negative control: without the field-caps read (it fails here), the
    plain aggregation over the whole pattern meets the fielddata refusal. That
    is the live failure, and it must surface as a reason and a WARNING.
    """
    grid = _DriftedGrid(keyword=True, field_caps_fails=True)
    with caplog.at_level("WARNING", logger="soc_ai.audit.counts"):
        result = await audit_counts_with_reason(_elastic(grid), "soc-ai-audit", _KINDS)
    assert result.counts == {k: None for k in _KINDS}
    assert result.reason is not None
    assert "Fielddata is disabled" in result.reason
    assert any(r.levelname == "WARNING" for r in caplog.records)
    # The dict-only form keeps its contract: unknown is None, never 0.
    assert await audit_counts_by_kind(_elastic(grid), "soc-ai-audit", _KINDS) == {
        k: None for k in _KINDS
    }


async def test_no_grid_is_unknown_with_a_reason() -> None:
    result = await audit_counts_with_reason(None, "soc-ai-audit", _KINDS)
    assert result.counts == {k: None for k in _KINDS}
    assert result.reason


async def test_an_empty_indices_list_means_every_index_maps_kind_as_text() -> None:
    """The client serialises a missing ``indices`` list as ``[]``. Production's
    field caps came back that way for every audit index, and the count then
    ran on ``kind`` and failed with the fielddata error it was meant to avoid."""
    from soc_ai.audit.counts import _non_aggregatable

    bad, everywhere = _non_aggregatable(
        {"text": {"type": "text", "aggregatable": False, "indices": []}}
    )
    assert bad == set() and everywhere is True
