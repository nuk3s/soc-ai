"""``so-case*`` documents in the Security Onion 3.3 shape (dogfood 2026-10-01 RA4).

The MCP ``cases`` tool and the agent's ``t_query_cases`` crashed with
KeyError 'id' in ``SoCase.from_so_doc``: the 3.3 index document nests the case
under ``so_case`` and carries its id only as the hit's ``_id``.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from soc_ai.config import Settings
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.so_client.models import CaseReadError, SoCase
from soc_ai.tools.query_cases import query_cases

# Modelled on an SO 3.3 so-case document: no top-level id, the case nested
# under so_case, list-wrapped scalars possible.
SO33_CASE_SOURCE: dict[str, Any] = {
    "@timestamp": "2026-09-30T12:00:00.000Z",
    "so_kind": "case",
    "so_case": {
        "title": "NTLM session setup from a workstation",
        "description": "Escalated from the alerts grid.",
        "status": "new",
        "severity": "medium",
        "assigneeId": "analyst-1",
        "createTime": "2026-09-30T12:00:00Z",
        "tags": ["escalated"],
    },
}


def test_so33_case_reads_its_id_from_the_hit() -> None:
    case = SoCase.from_so_doc(SO33_CASE_SOURCE, doc_id="hit-id-1")
    assert case.id == "hit-id-1"
    assert case.title == "NTLM session setup from a workstation"
    assert case.status == "new"
    assert case.severity == "medium"
    assert case.assignee_id == "analyst-1"
    assert case.tags == ["escalated"]
    assert case.created == datetime(2026, 9, 30, 12, 0, 0, tzinfo=UTC)


def test_so33_case_prefers_the_nested_id() -> None:
    doc = {"so_case": {"id": ["case-nested"], "title": "x"}}
    assert SoCase.from_so_doc(doc, doc_id="hit-id").id == "case-nested"


def test_a_case_with_only_an_id_reads() -> None:
    case = SoCase.from_so_doc({"so_case": {}}, doc_id="bare")
    assert case.id == "bare"
    assert case.title == ""
    assert case.status == "unknown"


def test_a_case_with_no_id_anywhere_raises_value_error() -> None:
    with pytest.raises(ValueError, match="no id"):
        SoCase.from_so_doc({"so_case": {"title": "x"}})


@pytest.mark.asyncio
async def test_query_cases_maps_a_malformed_doc_to_an_error_entry(
    settings_kratos: Settings,
) -> None:
    fake_es = AsyncMock()
    fake_es.search.return_value = {
        "took": 1,
        "hits": {
            "total": {"value": 3},
            "hits": [
                {"_id": "case-a", "_source": SO33_CASE_SOURCE},
                # No _id and no id anywhere: unreadable.
                {"_source": {"so_case": {"title": "orphan"}}},
                {"_id": "case-c", "_source": {"id": "case-c", "title": "Flat", "status": "closed"}},
            ],
        },
    }
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es):
        elastic = ElasticClient(settings_kratos)
    out = await query_cases("*", elastic=elastic, settings=settings_kratos)
    assert len(out) == 3
    assert isinstance(out[0], SoCase)
    assert out[0].id == "case-a"
    assert isinstance(out[1], CaseReadError)
    dumped = out[1].model_dump(mode="json")
    assert dumped["error"] == "unreadable_case"
    assert "ValueError" in dumped["reason"]
    assert isinstance(out[2], SoCase)
    assert out[2].title == "Flat"
    # The MCP tool and t_query_cases serialise every entry the same way.
    assert all(isinstance(c.model_dump(mode="json"), dict) for c in out)
