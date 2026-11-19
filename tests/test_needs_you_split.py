"""Needs you counts decisions. Shadow hits are a separate review count.

Production review 2026-11-12 (ui-core 4): "Needs you 280" was 233 unread shadow
hits plus 47 decisions, in red on the Dashboard tile, the bell and the Hunts
badge. A shadow hit is review work: one press of Dismiss all reads every hit.
``GET /needs-you`` and ``GET /hunts/needs-you`` now state ``decisions`` and
``review`` from one server rule, and ``total`` keeps its old meaning.

ui-core 7: the Investigations badge said 39 (9 needs more info plus 30
actions) and the list opened on 64 other rows. ``investigations_waiting``
counts the runs the ``needs_you`` list filter returns, with the same query.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.webui.alerts_query import GroupPage

from tests.test_analytics_api import _seed_shadow_hit
from tests.test_needs_you_count import (
    _ACK,
    _ESCALATE,
    _needs_you,
    _one_untriaged_group,
    _seed_lead,
    _seed_run,
)


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
        with TestClient(app) as test_client:
            yield test_client


def _count(client: TestClient, page: GroupPage | None = None) -> dict[str, Any]:
    with patch(
        "soc_ai.webui.alerts_query.fetch_groups",
        AsyncMock(return_value=page if page is not None else GroupPage([], 0)),
    ):
        return _needs_you(client)


def _since_days(days: int) -> str:
    return (datetime.now(UTC) - timedelta(days=days)).isoformat()


# ---------------------------------------------------------------------------
# I1: decisions and review
# ---------------------------------------------------------------------------


def test_the_count_splits_the_decisions_from_the_shadow_hits(client: TestClient) -> None:
    _seed_lead(client)
    _seed_shadow_hit(client, complete=True)
    _seed_run(client, "INV-NMI", alert_id="es-nmi", verdict="needs_more_info")
    _seed_run(client, "INV-TP", alert_id="es-tp", verdict="true_positive", actions=[_ESCALATE])
    body = _count(client, _one_untriaged_group())
    # A lead, an alert group, a verdict that needs more info and an action.
    assert body["decisions"] == 4
    assert body["review"] == 1
    # Backward compatible: the old total holds every part.
    assert body["total"] == 5
    assert body["total"] == body["decisions"] + body["review"]


def test_a_shadow_hit_alone_is_no_decision(client: TestClient) -> None:
    """NEGATIVE CONTROL. Unread hits move the review count and nothing else."""
    _seed_shadow_hit(client, complete=True)
    body = _count(client)
    assert body["decisions"] == 0
    assert body["review"] == 1
    hunting = client.get("/api/v1/hunts/needs-you").json()
    assert hunting["decisions"] == 0
    assert hunting["review"] == 1


def test_a_lead_alone_is_a_decision(client: TestClient) -> None:
    """NEGATIVE CONTROL. The split must not drop a real decision."""
    _seed_lead(client)
    body = _count(client)
    assert body["decisions"] == 1
    assert body["review"] == 0


def test_the_hunts_count_states_the_same_split(client: TestClient) -> None:
    _seed_lead(client)
    _seed_shadow_hit(client, complete=True)
    hunting = client.get("/api/v1/hunts/needs-you").json()
    assert hunting["decisions"] == 1
    assert hunting["review"] == 1
    assert hunting["total"] == 2
    body = _count(client)
    assert body["leads_needing_decision"] == hunting["decisions"]
    assert body["review"] == hunting["review"]


def test_a_failed_hunting_read_leaves_the_review_count_unknown(client: TestClient) -> None:
    """A failed read is not a zero. The review count is null, and the decision
    count is a floor of the parts that answered."""
    _seed_run(client, "INV-NMI", alert_id="es-nmi", verdict="needs_more_info")
    with patch(
        "soc_ai.api.webui.routes_analytics.needs_you",
        AsyncMock(side_effect=RuntimeError("store down")),
    ):
        body = _count(client)
    assert body["review"] is None
    assert body["decisions"] == 1
    assert "unread_shadow_hits" in body["unknown"]


# ---------------------------------------------------------------------------
# I3: the Investigations badge and the Needs you list
# ---------------------------------------------------------------------------


def _seed_needs_you_runs(client: TestClient) -> None:
    _seed_run(client, "INV-NMI", alert_id="es-nmi", verdict="needs_more_info", hours_ago=2)
    # Two actions on one run: the action count is 2, the run count is 1.
    second = {**_ACK, "tool_args": {"alert_id": "es-tp"}}
    _seed_run(
        client,
        "INV-TP-WAITS",
        alert_id="es-tp",
        verdict="true_positive",
        actions=[_ESCALATE, second],
        hours_ago=1,
    )
    # A true positive with no action waits for a decision of the analyst
    # (round "decide once" part 2, OW2).
    _seed_run(client, "INV-TP-NONE", alert_id="es-none", verdict="true_positive", hours_ago=3)
    # The runs below wait on nobody. The analyst acknowledged the true
    # positive with no action from the card "No automatic action".
    _seed_run(
        client,
        "INV-TP-BARE",
        alert_id="es-bare",
        verdict="true_positive",
        events=[("analyst_settled", {"action": "ack", "by": "analyst", "alerts": 1})],
    )
    _seed_run(client, "INV-FP", alert_id="es-fp", verdict="false_positive", actions=[_ACK])
    _seed_run(
        client,
        "INV-NMI-OLD",
        alert_id="es-nmi-old",
        verdict="needs_more_info",
        hours_ago=24 * 31,
    )
    _seed_run(
        client,
        "INV-NMI-REPLAY",
        alert_id="es-nmi-replay",
        verdict="needs_more_info",
        started_by="backtest",
    )


def _needs_you_list(client: TestClient, **params: Any) -> dict[str, Any]:
    res = client.get("/api/v1/investigations", params={"needs_you": "true", **params})
    assert res.status_code == 200, res.text
    body: dict[str, Any] = res.json()
    return body


def test_the_badge_counts_the_runs_the_needs_you_list_holds(client: TestClient) -> None:
    _seed_needs_you_runs(client)
    body = _count(client)
    # Every age counts: a verdict that needs more info waits until a person decides.
    assert body["needs_more_info"] == 2
    assert body["pending_actions"] == 2
    assert body["investigations_waiting"] == 4
    listed = _needs_you_list(client)
    assert {row["id"] for row in listed["rows"]} == {
        "INV-NMI",
        "INV-NMI-OLD",
        "INV-TP-WAITS",
        "INV-TP-NONE",
    }
    assert listed["total"] == body["investigations_waiting"]
    # The row of the run with actions carries them, as under the action filter.
    tp = next(row for row in listed["rows"] if row["id"] == "INV-TP-WAITS")
    assert tp["pendingActions"] == 2
    assert len(tp["waitingActions"]) == 2


def test_the_needs_you_list_leaves_out_every_run_that_waits_on_nobody(
    client: TestClient,
) -> None:
    """NEGATIVE CONTROL. A true positive that the analyst acknowledged, a false
    positive with an acknowledge, a replay and a run outside the window wait
    on nobody."""
    _seed_needs_you_runs(client)
    ids = {row["id"] for row in _needs_you_list(client, since=_since_days(30))["rows"]}
    assert not ids & {"INV-TP-BARE", "INV-FP", "INV-NMI-OLD", "INV-NMI-REPLAY"}


def test_the_needs_you_list_joins_the_other_filters(client: TestClient) -> None:
    """The filter narrows. A verdict filter on top keeps its own meaning."""
    _seed_needs_you_runs(client)
    only_tp = _needs_you_list(client, since=_since_days(30), verdict="true_positive")
    assert [row["id"] for row in only_tp["rows"]] == ["INV-TP-WAITS", "INV-TP-NONE"]
    narrow = _needs_you_list(client, since=(datetime.now(UTC) - timedelta(hours=1.5)).isoformat())
    assert [row["id"] for row in narrow["rows"]] == ["INV-TP-WAITS"]


def test_an_empty_store_lists_no_run_under_needs_you(client: TestClient) -> None:
    """NEGATIVE CONTROL. An empty set is no row. It is not "no filter"."""
    _seed_run(client, "INV-FP", alert_id="es-fp", verdict="false_positive")
    body = _needs_you_list(client, since=_since_days(30))
    assert body["rows"] == []
    assert body["total"] == 0
    assert _count(client)["investigations_waiting"] == 0


def test_a_verdict_that_a_later_run_replaced_waits_on_nobody(client: TestClient) -> None:
    """Production 2026-11-13: 8 of 10 needs-more-info rows had a later run with a verdict."""
    _seed_run(client, "INV-NMI-FIRST", alert_id="es-twice", verdict="needs_more_info", hours_ago=3)
    _seed_run(client, "INV-FP-LATER", alert_id="es-twice", verdict="false_positive", hours_ago=1)
    _seed_run(client, "INV-NMI-ALONE", alert_id="es-once", verdict="needs_more_info", hours_ago=2)

    listed = _needs_you_list(client, since=_since_days(30))
    assert {row["id"] for row in listed["rows"]} == {"INV-NMI-ALONE"}

    count = _count(client)
    assert count["needs_more_info"] == 1
    assert count["investigations_waiting"] == 1


def test_a_later_needs_more_info_run_still_waits(client: TestClient) -> None:
    """The newest run of an alert is the answer, also when it needs more info."""
    _seed_run(client, "INV-FP-FIRST", alert_id="es-back", verdict="false_positive", hours_ago=3)
    _seed_run(client, "INV-NMI-LATER", alert_id="es-back", verdict="needs_more_info", hours_ago=1)

    listed = _needs_you_list(client, since=_since_days(30))
    assert {row["id"] for row in listed["rows"]} == {"INV-NMI-LATER"}
