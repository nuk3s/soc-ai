"""Tests for ``get_rule_content`` — fetch a detection's full rule text.

Live SO 3.x stores detections nested under ``so_detection.*`` (including
``so_detection.content``, the rule body); older/flat docs keep fields at the
top level. The tool must handle both shapes and look up by SID/publicId OR
exact rule title.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from soc_ai.config import Settings
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.tools.get_rule_content import get_rule_content

RULE_TEXT = (
    'alert icmp any any -> $HOME_NET any (msg:"ET MALWARE Possible BPFDoor ICMP Activity"; '
    'itype:8; content:"justCHECK"; sid:2054989; rev:1;)'
)


def _hits(docs: list[dict[str, Any]]) -> dict[str, Any]:
    return {"took": 1, "hits": {"total": {"value": len(docs)}, "hits": docs}}


def _nested_doc(content: str = RULE_TEXT, public_id: str = "2054989") -> dict[str, Any]:
    return {
        "_id": "det-es-id",
        "_source": {
            "so_kind": "detection",
            "so_detection": {
                "id": "uuid-1",
                "publicId": public_id,
                "title": "ET MALWARE Possible BPFDoor ICMP Activity",
                "severity": "high",
                "engine": "suricata",
                "language": "suricata",
                "ruleset": "ETOPEN",
                "isEnabled": True,
                "author": "Emerging Threats",
                "content": content,
                "tags": ["malware"],
            },
        },
    }


def _flat_doc() -> dict[str, Any]:
    return {
        "_id": "det-es-id",
        "_source": {
            "id": "det-001",
            "publicId": "2054989",
            "title": "ET MALWARE Possible BPFDoor ICMP Activity",
            "severity": "high",
            "engine": "suricata",
            "isEnabled": True,
            "content": RULE_TEXT,
        },
    }


def _make_elastic(
    settings: Settings, responses: list[dict[str, Any]]
) -> tuple[ElasticClient, AsyncMock]:
    fake_es = AsyncMock()
    fake_es.search.side_effect = responses
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es):
        return ElasticClient(settings), fake_es


@pytest.mark.asyncio
async def test_nested_so3_doc_returns_rule_text(settings_kratos: Settings) -> None:
    elastic, fake_es = _make_elastic(settings_kratos, [_hits([_nested_doc()])])

    result = await get_rule_content("2054989", elastic=elastic, settings=settings_kratos)

    assert result["found"] is True
    assert result["content"] == RULE_TEXT
    assert result["public_id"] == "2054989"
    assert result["title"] == "ET MALWARE Possible BPFDoor ICMP Activity"
    assert result["engine"] == "suricata"
    assert fake_es.search.call_args.kwargs["index"] == settings_kratos.detections_index_pattern
    # The lookup must tolerate BOTH doc shapes and match by publicId OR title.
    body = fake_es.search.call_args.kwargs["body"]
    body_str = str(body)
    assert "so_detection.publicId" in body_str
    assert "publicId" in body_str
    assert "title" in body_str
    # `so-detection*` also matches so-detectionhistory (every past revision) —
    # the newest doc must win, so the query sorts by @timestamp desc.
    assert body["sort"][0]["@timestamp"]["order"] == "desc"


@pytest.mark.asyncio
async def test_flat_legacy_doc_returns_rule_text(settings_kratos: Settings) -> None:
    elastic, _ = _make_elastic(settings_kratos, [_hits([_flat_doc()])])

    result = await get_rule_content("2054989", elastic=elastic, settings=settings_kratos)

    assert result["found"] is True
    assert result["content"] == RULE_TEXT


@pytest.mark.asyncio
async def test_not_found_returns_hint(settings_kratos: Settings) -> None:
    elastic, _ = _make_elastic(settings_kratos, [_hits([])])

    result = await get_rule_content("9999999", elastic=elastic, settings=settings_kratos)

    assert result["found"] is False
    assert "t_query_detections" in result["hint"]


@pytest.mark.asyncio
async def test_long_content_is_clamped(settings_kratos: Settings) -> None:
    elastic, _ = _make_elastic(settings_kratos, [_hits([_nested_doc(content="A" * 20_000)])])

    result = await get_rule_content("2054989", elastic=elastic, settings=settings_kratos)

    assert result["found"] is True
    assert len(result["content"]) <= 6_100
    assert result["content_truncated"] is True


@pytest.mark.asyncio
async def test_multiple_matches_reported(settings_kratos: Settings) -> None:
    elastic, _ = _make_elastic(
        settings_kratos, [_hits([_nested_doc(), _nested_doc(public_id="2054990")])]
    )

    result = await get_rule_content("2054989", elastic=elastic, settings=settings_kratos)

    assert result["found"] is True
    assert result["matches"] == 2
