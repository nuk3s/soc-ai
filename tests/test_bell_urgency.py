"""The bell orders its rows by urgency, and folds the routine ones.

Production review 2026-11-12 (ui-core 5): the first 12 rows of the bell were 3
analytic notices 25 to 38 days old, 3 failed triages (two of them the same) and
6 false positives. The true positives were rows 35 to 37 of 68.

The order is now: a dependency that is down, confirmed threats, decisions
that wait, failures, notices, runs in flight, closures, then old notices.
Newest first inside each tier. Two or more false positive closures fold into
one row with a count and a link. The
same failure on the same subject folds into one row with a count. Every test
seeds its rows relative to now.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.api.webui.routes_meta import NotificationOut, by_urgency
from soc_ai.config import Settings
from soc_ai.main import create_app

from tests.test_needs_you_count import _seed_run


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


def _ago(hours: float) -> datetime:
    return (datetime.now(UTC) - timedelta(hours=hours)).replace(tzinfo=None)


def _bell(client: TestClient, **params: Any) -> list[dict[str, Any]]:
    res = client.get("/api/v1/notifications", params={"events_only": "true", **params})
    assert res.status_code == 200, res.text
    body: list[dict[str, Any]] = res.json()
    return body


def _seed_failed(client: TestClient, run_id: str, *, rule: str, hours_ago: float) -> None:
    """A triage that died with no verdict: the bell's failed-triage row."""
    from soc_ai.store.models import Investigation

    async def go() -> None:
        async with client.app.state.db_sessionmaker() as db:
            db.add(
                Investigation(
                    id=run_id,
                    alert_es_id=f"es-{run_id}",
                    kind="suricata",
                    rule_name=rule,
                    status="error",
                    created_at=_ago(hours_ago),
                    finished_at=_ago(hours_ago),
                )
            )
            await db.commit()

    asyncio.run(go())


def _seed_false_positives(client: TestClient, n: int, *, first_hours_ago: float = 0.5) -> None:
    for i in range(n):
        _seed_run(
            client,
            f"INV-FP-{i:03d}",
            alert_id=f"es-fp-{i}",
            verdict="false_positive",
            hours_ago=first_hours_ago + i / 100,
        )


# ---------------------------------------------------------------------------
# The order
# ---------------------------------------------------------------------------


def test_a_true_positive_leads_the_bell_over_newer_routine_rows(client: TestClient) -> None:
    _seed_run(client, "INV-TP", alert_id="es-tp", verdict="true_positive", hours_ago=6)
    _seed_run(client, "INV-NMI", alert_id="es-nmi", verdict="needs_more_info", hours_ago=5)
    _seed_failed(client, "INV-DEAD", rule="ET TEST dead", hours_ago=4)
    # 20 newer false positives filled the old list cap of completed runs.
    _seed_false_positives(client, 20, first_hours_ago=0.2)
    ids = [row["id"] for row in _bell(client)]
    assert ids[:4] == [
        "inv-done:INV-TP",
        "inv-done:INV-NMI",
        "inv-failed:INV-DEAD",
        "inv-fp:INV-FP-000",
    ]


def test_the_rows_of_one_tier_are_newest_first(client: TestClient) -> None:
    _seed_run(client, "INV-TP-OLD", alert_id="es-1", verdict="true_positive", hours_ago=9)
    _seed_run(client, "INV-TP-NEW", alert_id="es-2", verdict="true_positive", hours_ago=1)
    ids = [row["id"] for row in _bell(client)]
    assert ids == ["inv-done:INV-TP-NEW", "inv-done:INV-TP-OLD"]


def _row(
    row_id: str, *, hours_ago: float | None, tone: str = "warn", **extra: Any
) -> NotificationOut:
    at = None
    if hours_ago is not None:
        at = (datetime.now(UTC) - timedelta(hours=hours_ago)).isoformat()
    return NotificationOut(id=row_id, tone=tone, title=row_id, when="", at=at, **extra)


def test_an_old_analytic_notice_sinks_below_the_closures() -> None:
    rows = [
        _row("analytic-held:1", hours_ago=24 * 25),
        _row("analytic-held:2", hours_ago=24 * 38),
        _row("analytic-held:3", hours_ago=2),
        _row("hunt-done:h1", hours_ago=3, tone="accent", outcome="no_threat"),
        _row("inv-done:tp", hours_ago=7, tone="danger"),
        _row("dep-down:es:1", hours_ago=30, tone="danger"),
        _row("inv:run", hours_ago=0.1, tone="accent"),
        _row("lead:4", hours_ago=50),
        _row("lead-more", hours_ago=None),
        _row("hunt-done:h2", hours_ago=4, tone="danger", outcome="threat_found"),
    ]
    ordered = [row.id for row in by_urgency(rows)]
    assert ordered == [
        # A dependency that is down leads, whatever its age.
        "dep-down:es:1",
        # Threats, newest first.
        "hunt-done:h2",
        "inv-done:tp",
        # Decisions. The count of more leads has no moment, so it ends its tier.
        "lead:4",
        "lead-more",
        # A recent notice.
        "analytic-held:3",
        # A run in flight.
        "inv:run",
        # Closures.
        "hunt-done:h1",
        # The old notices, newest first.
        "analytic-held:1",
        "analytic-held:2",
    ]


def test_a_dependency_that_is_down_leads_the_bell_above_the_threats() -> None:
    """With the grid, the model gateway or the Security Onion API down, no
    other row of the bell is reliable. Each one goes above a newer threat."""
    rows = [
        _row("inv-done:tp", hours_ago=0.1, tone="danger"),
        _row("lead:4", hours_ago=0.2),
        _row("dep-down:llm:20261113090000", hours_ago=2, tone="danger"),
        _row("dep-down:so:20261113080000", hours_ago=3, tone="danger"),
        _row("dep-down:es:20261113070000", hours_ago=4, tone="danger"),
    ]
    assert [row.id for row in by_urgency(rows)] == [
        "dep-down:llm:20261113090000",
        "dep-down:so:20261113080000",
        "dep-down:es:20261113070000",
        "inv-done:tp",
        "lead:4",
    ]


def test_the_other_standing_conditions_stay_below_the_threats() -> None:
    """Negative control: only a dependency that is down moves up. A broken
    audit chain, a paused Oracle, a certificate that expires and an unknown
    dependency stay in the tier of the failures."""
    rows = [
        _row("audit-chain-break:1", hours_ago=0.1, tone="danger", dismissible=False),
        _row("oracle-paused:1", hours_ago=0.2, tone="warn"),
        _row("tls-expiry:1", hours_ago=0.3, tone="warn"),
        _row("dep-down:pcap:1", hours_ago=0.4, tone="danger"),
        _row("lead:4", hours_ago=5),
        _row("inv-done:tp", hours_ago=6, tone="danger"),
    ]
    assert [row.id for row in by_urgency(rows)] == [
        "inv-done:tp",
        "lead:4",
        "audit-chain-break:1",
        "oracle-paused:1",
        "tls-expiry:1",
        "dep-down:pcap:1",
    ]


def test_a_hunt_that_could_not_run_is_a_failure() -> None:
    rows = [
        _row("hunt-done:ok", hours_ago=1, tone="accent", outcome="no_threat"),
        _row("hunt-done:bad", hours_ago=2, tone="warn", outcome="could_not_run"),
    ]
    assert [row.id for row in by_urgency(rows)] == ["hunt-done:bad", "hunt-done:ok"]


# ---------------------------------------------------------------------------
# The false positive fold
# ---------------------------------------------------------------------------


def test_false_positive_closures_fold_into_one_row_with_a_count_and_a_link(
    client: TestClient,
) -> None:
    _seed_false_positives(client, 25)
    rows = _bell(client)
    folds = [row for row in rows if row["id"].startswith("inv-fp:")]
    assert len(folds) == 1
    fold = folds[0]
    # The count is a SQL count, not the cap of the list read.
    assert fold["title"] == "25 false positives closed in the last 24 hours"
    assert fold["href"] == "/investigations?range=24h&verdict=false_positive&clock=investigated"
    assert fold["tone"] == "accent"
    assert fold["id"] == "inv-fp:INV-FP-000"
    assert fold["at"]
    assert not [row for row in rows if row["id"].startswith("inv-done:")]


def test_one_false_positive_keeps_its_own_row(client: TestClient) -> None:
    """NEGATIVE CONTROL. A fold of one row says less than the row."""
    _seed_false_positives(client, 1)
    ids = [row["id"] for row in _bell(client)]
    assert ids == ["inv-done:INV-FP-000"]


def test_the_fold_counts_only_the_closures_after_a_dismiss_all(client: TestClient) -> None:
    """Dismiss all stays truthful: the fold counts what the analyst has not
    dismissed, and says that its count starts at the Dismiss all."""
    _seed_false_positives(client, 3, first_hours_ago=0.5)
    for i in range(4):
        _seed_run(
            client,
            f"INV-FP-OLD-{i}",
            alert_id=f"es-fp-old-{i}",
            verdict="false_positive",
            hours_ago=5 + i,
        )
    mark = (datetime.now(UTC) - timedelta(hours=2)).isoformat()
    fold = next(row for row in _bell(client, after=mark) if row["id"].startswith("inv-fp:"))
    assert fold["title"] == "3 false positives closed after the last Dismiss all"
    plain = next(row for row in _bell(client) if row["id"].startswith("inv-fp:"))
    assert plain["title"] == "7 false positives closed in the last 24 hours"


def test_a_true_positive_is_never_folded(client: TestClient) -> None:
    """NEGATIVE CONTROL. Only a false positive closure folds."""
    for i in range(3):
        _seed_run(
            client, f"INV-TP-{i}", alert_id=f"es-tp-{i}", verdict="true_positive", hours_ago=1 + i
        )
    ids = [row["id"] for row in _bell(client)]
    assert ids == ["inv-done:INV-TP-0", "inv-done:INV-TP-1", "inv-done:INV-TP-2"]


# ---------------------------------------------------------------------------
# The same failure on the same subject
# ---------------------------------------------------------------------------


def test_the_same_failure_on_the_same_rule_folds_into_one_row(client: TestClient) -> None:
    _seed_failed(client, "INV-DEAD-1", rule="ET TEST dead", hours_ago=3)
    _seed_failed(client, "INV-DEAD-2", rule="ET TEST dead", hours_ago=2)
    failed = [row for row in _bell(client) if row["id"].startswith("inv-failed:")]
    assert len(failed) == 1
    row = failed[0]
    # The newest run names the row, so a dismissal holds until a new failure.
    assert row["id"] == "inv-failed:INV-DEAD-2"
    assert row["title"] == (
        "Triage failed, no verdict: ET TEST dead. 2 investigations failed the same way."
    )


def test_two_failures_on_two_rules_keep_two_rows(client: TestClient) -> None:
    """NEGATIVE CONTROL. A fold joins the same failure on the same subject only."""
    _seed_failed(client, "INV-DEAD-1", rule="ET TEST one", hours_ago=3)
    _seed_failed(client, "INV-DEAD-2", rule="ET TEST two", hours_ago=2)
    failed = [row["id"] for row in _bell(client) if row["id"].startswith("inv-failed:")]
    assert failed == ["inv-failed:INV-DEAD-2", "inv-failed:INV-DEAD-1"]


def test_the_failure_fold_leaves_out_a_run_before_the_dismiss_all(client: TestClient) -> None:
    _seed_failed(client, "INV-DEAD-1", rule="ET TEST dead", hours_ago=5)
    _seed_failed(client, "INV-DEAD-2", rule="ET TEST dead", hours_ago=1)
    mark = (datetime.now(UTC) - timedelta(hours=2)).isoformat()
    failed = [row for row in _bell(client, after=mark) if row["id"].startswith("inv-failed:")]
    assert [row["title"] for row in failed] == ["Triage failed, no verdict: ET TEST dead"]
