"""A count nobody can take is not a count of zero.

The alert queue draws its per-group "N acknowledged" chip from a filter
sub-aggregation on ``event.acknowledged``. Elastic Defend's endpoint alert
index — ``.ds-logs-endpoint.alerts-default-*`` — is mapped ``dynamic: false``
and does not map that field, or ``event.escalated`` beside it. Security Onion
still stamps both when an analyst acts, into ``_source``, where no query
reaches. So the aggregation answers 0 for a group that was cleared this morning
exactly as it answers 0 for one nobody has opened, and the row said "untouched"
either way.

The write path already knows this: ``ack_group`` stopped trusting the query and
reads the flag off each hit instead (see ``tests/test_ack_group_drain.py``). The
read path cannot do the same — a group can hold thousands of events and the
console will not page them to draw one chip — so it does the other honest
thing and reports that it cannot tell.

These tests hold the three facts that separates: which groups the grid can
answer for, which it cannot, and that the aggregation carrying that decision is
actually asked for.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.webui import alerts_query as aq
from soc_ai.webui.alerts_query import AlertGroup, GroupPage


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    fake_es = AsyncMock()
    fake_auth = AsyncMock()
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
        patch("soc_ai.main.make_auth", return_value=fake_auth),
        patch("soc_ai.main.get_settings", return_value=settings_kratos),
    ):
        app = create_app()
        with TestClient(app) as c:
            yield c


def _bucket(
    *,
    datasets: list[str] | None,
    acked: int = 0,
    escalated: int = 0,
    other: int = 0,
) -> dict[str, Any]:
    """One terms bucket shaped the way Elasticsearch returns it.

    ``datasets=None`` omits the sub-aggregation entirely — an older cached
    response, or a double written before it existed.
    """
    bucket: dict[str, Any] = {
        "key": "Malicious Behavior Detection Alert",
        "doc_count": 16,
        "latest": {
            "hits": {
                "hits": [
                    {
                        "_id": "es-1",
                        "_source": {
                            "@timestamp": "2026-09-06T10:00:00Z",
                            "event": {"severity_label": "high", "dataset": "endpoint.alerts"},
                        },
                    }
                ]
            }
        },
        "acked": {"doc_count": acked},
        "escalated": {"doc_count": escalated},
    }
    if datasets is not None:
        bucket["datasets"] = {
            "sum_other_doc_count": other,
            "buckets": [{"key": name, "doc_count": 16} for name in datasets],
        }
    return bucket


def test_the_aggregation_that_decides_answerability_is_actually_requested() -> None:
    """Without the datasets sub-aggregation the decision below can never fire.

    Pinned separately because the reader defaults a MISSING block to
    "answerable" — which is right for an old cached response and would quietly
    turn the whole fix off if the query ever stopped asking.
    """
    aggs = aq._bucket_aggs()
    assert aggs["datasets"]["terms"]["field"] == "event.dataset"
    assert aggs["datasets"]["terms"]["size"] == aq._DATASETS_PER_GROUP


def test_a_group_the_grid_can_answer_for_keeps_its_number() -> None:
    group = aq._group_from_bucket(_bucket(datasets=["suricata.alert"], acked=3, escalated=1))
    assert group.acked_count == 3
    assert group.escalated_count == 1


def test_an_untouched_suricata_group_still_reads_as_zero_not_unknown() -> None:
    """Zero is a real answer on an index that maps the flag — don't lose it."""
    group = aq._group_from_bucket(_bucket(datasets=["suricata.alert"]))
    assert group.acked_count == 0
    assert group.escalated_count == 0


def test_an_endpoint_group_reports_unknown_rather_than_zero() -> None:
    group = aq._group_from_bucket(_bucket(datasets=["endpoint.alerts"]))
    assert group.acked_count is None
    assert group.escalated_count is None


def test_a_mixed_group_reports_unknown_because_the_number_would_undercount() -> None:
    """Half an answer is not an answer.

    The aggregation can still see the Suricata copies, so it returns a number —
    one that silently omits every endpoint document in the same group. An
    undercount of unknown size reads exactly like a complete count.
    """
    group = aq._group_from_bucket(_bucket(datasets=["suricata.alert", "endpoint.alerts"], acked=2))
    assert group.acked_count is None


def test_a_truncated_dataset_list_reports_unknown() -> None:
    """Past the terms cap we cannot rule a blind dataset out, so we do not."""
    group = aq._group_from_bucket(_bucket(datasets=["suricata.alert"], acked=2, other=4))
    assert group.acked_count is None
    assert group.escalated_count is None


def test_a_response_without_the_sub_aggregation_still_answers() -> None:
    """Same default the alert-class breakdown takes: no block, no blind spot.

    Inventing "cannot tell" from an absent aggregation would put the unknown
    chip on every group on a grid that answers fine.
    """
    group = aq._group_from_bucket(_bucket(datasets=None, acked=3))
    assert group.acked_count == 3


def test_the_unanswerable_count_reaches_the_console_as_null(client: TestClient) -> None:
    """It has to survive the response model — an ``int`` field would coerce it."""
    groups = [
        AlertGroup(
            rule_name="Malicious Behavior Detection Alert",
            count=16,
            severity="high",
            latest_ts="2026-09-06T10:00:00Z",
            latest_id="es-1",
            kind="alert",
            acked_count=None,
            escalated_count=None,
        )
    ]
    with (
        patch(
            "soc_ai.api.webui_api.aq.fetch_groups", AsyncMock(return_value=GroupPage(groups, 16))
        ),
        patch("soc_ai.api.webui_api.inv_svc.latest_for_rules", AsyncMock(return_value={})),
    ):
        resp = client.get("/api/v1/alerts")
    assert resp.status_code == 200
    body = resp.json()
    assert body["groups"][0]["ackedCount"] is None
    assert body["groups"][0]["escalatedCount"] is None
