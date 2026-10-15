"""An alert group row names the worst verdict among its alerts (dogfood 2026-10-06, S5).

The row said "False positive · inherited 1d ago" while one event of the group
carried a true-positive investigation at 0.62. Only the Investigations list
and a lead showed it. The row now carries the verdict counts of its alerts and
the worst verdict, and each event carries the verdict that applies to it.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.triage_models import PIPELINE_FALLBACK_PROVENANCE
from soc_ai.webui.alerts_query import AlertEvent, AlertGroup, GroupPage

_RULE = "Security Onion - Grid Node Login Failure (SSH)"


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


def _fallback_marker(fallback: bool) -> dict[str, Any]:
    """The report marker the alerts route reads to call a standing run a fallback."""
    if not fallback:
        return {}
    return {"resolution": {"provenance": PIPELINE_FALLBACK_PROVENANCE}}


def _run(
    client: TestClient,
    run_id: str,
    *,
    alert_id: str,
    verdict: str,
    hours_ago: float,
    src: str = "192.0.2.26",
    fallback: bool = False,
    started_by: str = "anonymous",
) -> None:
    from soc_ai.store.models import Investigation

    async def go() -> None:
        async with client.app.state.db_sessionmaker() as db:
            db.add(
                Investigation(
                    id=run_id,
                    alert_es_id=alert_id,
                    rule_name=_RULE,
                    status="complete",
                    verdict=verdict,
                    confidence=0.62 if verdict == "true_positive" else 0.9,
                    src_ip=src,
                    dest_ip="192.0.2.1",
                    is_fallback=fallback,
                    started_by=started_by,
                    report={"verdict": verdict, **_fallback_marker(fallback)},
                    created_at=_ago(hours_ago),
                    finished_at=_ago(hours_ago),
                )
            )
            await db.commit()

    asyncio.run(go())


def _page() -> GroupPage:
    return GroupPage(
        [
            AlertGroup(
                rule_name=_RULE,
                count=9,
                severity="medium",
                latest_ts=datetime.now(UTC).isoformat(),
                latest_id="es-latest",
            )
        ],
        9,
    )


def _group(
    client: TestClient, range_: str = "30d", params: dict[str, str] | None = None
) -> dict[str, Any]:
    query = params if params is not None else {"range": range_}
    with patch("soc_ai.webui.alerts_query.fetch_groups", AsyncMock(return_value=_page())):
        res = client.get("/api/v1/alerts", params=query)
    assert res.status_code == 200, res.text
    groups: list[dict[str, Any]] = res.json()["groups"]
    assert len(groups) == 1
    return groups[0]


def test_a_group_row_names_the_true_positive_among_its_false_positives(
    client: TestClient,
) -> None:
    # Eight alerts closed as false positive, one true positive four days ago,
    # and the newest run (the standing verdict) a false positive.
    for n in range(8):
        _run(client, f"INV-FP{n}", alert_id=f"es-fp{n}", verdict="false_positive", hours_ago=24 + n)
    _run(
        client,
        "INV-TP",
        alert_id="es-tp",
        verdict="true_positive",
        hours_ago=96,
        src="192.0.2.29",
    )
    group = _group(client)
    assert group["verdict"] == "false_positive"
    assert group["verdictCounts"] == {"false_positive": 8, "true_positive": 1}
    assert group["worstVerdict"] == "true_positive"
    assert group["worstConf"] == pytest.approx(0.62)
    assert group["worstInvId"] == "INV-TP"
    assert group["windowVerdict"] == "true_positive"
    assert group["windowConf"] == pytest.approx(0.62)
    assert group["windowInvId"] == "INV-TP"


def test_a_group_whose_standing_verdict_is_the_worst_names_no_other(client: TestClient) -> None:
    """NEGATIVE CONTROL. No worse verdict, no second chip."""
    _run(client, "INV-FP", alert_id="es-fp", verdict="false_positive", hours_ago=30)
    _run(client, "INV-TP", alert_id="es-tp", verdict="true_positive", hours_ago=2)
    group = _group(client)
    assert group["verdict"] == "true_positive"
    assert group["worstVerdict"] is None
    assert group["verdictCounts"] == {"false_positive": 1, "true_positive": 1}


def test_one_alert_counts_once_with_its_newest_verdict(client: TestClient) -> None:
    """A re-run replaced the true positive of one alert. It no longer counts."""
    _run(client, "INV-OLD", alert_id="es-1", verdict="true_positive", hours_ago=10)
    _run(client, "INV-NEW", alert_id="es-1", verdict="false_positive", hours_ago=2)
    group = _group(client)
    assert group["verdictCounts"] == {"false_positive": 1}
    assert group["worstVerdict"] is None


def test_a_pipeline_fallback_counts_as_no_verdict(client: TestClient) -> None:
    """NEGATIVE CONTROL. A run that reached no verdict says nothing about an alert."""
    _run(client, "INV-FP", alert_id="es-fp", verdict="false_positive", hours_ago=3)
    _run(client, "INV-FB", alert_id="es-fb", verdict="needs_more_info", hours_ago=2, fallback=True)
    group = _group(client)
    assert group["verdictCounts"] == {"false_positive": 1}
    assert group["worstVerdict"] is None


def test_a_pipeline_fallback_does_not_hide_an_older_true_positive(client: TestClient) -> None:
    """The newest run of the rule fell back. The true positive before it still shows.

    The Dashboard breakdown counts the group under its worst verdict (prod
    2026-10-13). With the worst verdict withheld behind a fallback, a later
    pipeline error removed the true positive from the breakdown.
    """
    _run(client, "INV-TP", alert_id="es-tp", verdict="true_positive", hours_ago=10)
    _run(client, "INV-FB", alert_id="es-fb", verdict="needs_more_info", hours_ago=2, fallback=True)
    group = _group(client)
    assert group["fallback"] is True
    assert group["worstVerdict"] == "true_positive"
    assert group["worstInvId"] == "INV-TP"


def test_a_pipeline_fallback_names_no_verdict_that_is_not_worse(client: TestClient) -> None:
    """NEGATIVE CONTROL. A false positive is not worse than a fallback's needs_more_info."""
    _run(client, "INV-FP", alert_id="es-fp", verdict="false_positive", hours_ago=10)
    _run(client, "INV-FB", alert_id="es-fb", verdict="needs_more_info", hours_ago=2, fallback=True)
    group = _group(client)
    assert group["fallback"] is True
    assert group["worstVerdict"] is None


def test_a_run_older_than_both_windows_is_not_counted(client: TestClient) -> None:
    _run(client, "INV-FP", alert_id="es-fp", verdict="false_positive", hours_ago=2)
    _run(client, "INV-TP", alert_id="es-tp", verdict="true_positive", hours_ago=24 * 40)
    group = _group(client)
    assert group["verdictCounts"] == {"false_positive": 1}


def test_each_event_carries_the_verdict_that_applies_to_it(client: TestClient) -> None:
    _run(client, "INV-TP", alert_id="es-tp", verdict="true_positive", hours_ago=96)
    events = [
        AlertEvent(
            es_id="es-tp",
            timestamp=datetime.now(UTC).isoformat(),
            src="192.0.2.29",
            dst="192.0.2.1",
            severity="medium",
            host="—",
            src_ip="192.0.2.29",
            dst_ip="192.0.2.1",
        ),
        AlertEvent(
            es_id="es-none",
            timestamp=datetime.now(UTC).isoformat(),
            src="192.0.2.26",
            dst="192.0.2.9",
            severity="medium",
            host="—",
            src_ip="192.0.2.26",
            dst_ip="192.0.2.9",
        ),
    ]
    with patch("soc_ai.webui.alerts_query.fetch_group_events", AsyncMock(return_value=events)):
        res = client.get("/api/v1/alerts/events", params={"rule_name": _RULE, "range": "30d"})
    assert res.status_code == 200, res.text
    by_id = {e["id"]: e for e in res.json()}
    assert by_id["es-tp"]["verdict"] == "true_positive"
    assert by_id["es-tp"]["conf"] == pytest.approx(0.62)
    assert by_id["es-tp"]["investigated"] is True


# Runs made inside the page window decide the verdict of a group (owner rule,
# 2026-10-14). Everything on a page follows the time filter of the page, and
# the verdict mix reached back seven days past a 24 hour window. A group with
# no run in the window keeps its standing verdict, and the console says
# "inherited" with the age from ``verdictAt``.


def test_a_true_positive_before_the_window_does_not_count(client: TestClient) -> None:
    """NEGATIVE CONTROL. The true positive is four days old and the window is 24 hours."""
    _run(client, "INV-FP", alert_id="es-fp", verdict="false_positive", hours_ago=2)
    _run(client, "INV-TP", alert_id="es-tp", verdict="true_positive", hours_ago=96)
    group = _group(client, "24h")
    assert group["windowVerdict"] == "false_positive"
    assert group["windowInvId"] == "INV-FP"
    assert group["verdictCounts"] == {"false_positive": 1}
    assert group["worstVerdict"] is None


def test_a_true_positive_in_the_window_outranks_later_false_positives(
    client: TestClient,
) -> None:
    _run(client, "INV-TP", alert_id="es-tp", verdict="true_positive", hours_ago=10)
    _run(client, "INV-FP1", alert_id="es-fp1", verdict="false_positive", hours_ago=5)
    _run(client, "INV-FP2", alert_id="es-fp2", verdict="false_positive", hours_ago=2)
    group = _group(client, "24h")
    assert group["verdict"] == "false_positive"
    assert group["windowVerdict"] == "true_positive"
    assert group["windowConf"] == pytest.approx(0.62)
    assert group["windowInvId"] == "INV-TP"
    assert group["verdictCounts"] == {"false_positive": 2, "true_positive": 1}


def test_a_group_with_no_run_in_the_window_keeps_its_standing_verdict(
    client: TestClient,
) -> None:
    _run(client, "INV-FP", alert_id="es-fp", verdict="false_positive", hours_ago=72)
    group = _group(client, "24h")
    assert group["windowVerdict"] is None
    assert group["windowConf"] is None
    assert group["windowInvId"] is None
    assert group["verdictCounts"] == {}
    assert group["verdict"] == "false_positive"
    assert group["invId"] == "INV-FP"
    at = datetime.fromisoformat(group["verdictAt"])
    assert at.tzinfo is not None
    assert abs((datetime.now(UTC) - at) - timedelta(hours=72)) < timedelta(minutes=5)


def test_an_untriaged_group_has_no_verdict_time(client: TestClient) -> None:
    group = _group(client, "24h")
    assert group["verdict"] == "untriaged"
    assert group["windowVerdict"] is None
    assert group["verdictAt"] is None


def _custom(hours_from: float, hours_to: float) -> dict[str, str]:
    """A custom window with explicit UTC bounds, as hours before now."""
    frm = (datetime.now(UTC) - timedelta(hours=hours_from)).isoformat()
    to = (datetime.now(UTC) - timedelta(hours=hours_to)).isoformat()
    return {"from": frm, "to": to}


@pytest.mark.parametrize("marker", [True, False], ids=["range-custom", "bounds-only"])
def test_a_custom_window_bounds_both_ends(client: TestClient, marker: bool) -> None:
    """A run after ``to`` and a run before ``from`` do not count.

    The console sent the bounds of a custom window without ``range=custom``,
    and the route read the default 24 hours for the mix. The bounds alone now
    make the window custom, as they already did for the grid query.
    """
    _run(client, "INV-OLD", alert_id="es-old", verdict="needs_more_info", hours_ago=60)
    _run(client, "INV-TP", alert_id="es-tp", verdict="true_positive", hours_ago=30)
    _run(client, "INV-NEW", alert_id="es-new", verdict="false_positive", hours_ago=2)
    params = _custom(48, 24)
    if marker:
        params["range"] = "custom"
    group = _group(client, params=params)
    assert group["verdict"] == "false_positive"
    assert group["windowVerdict"] == "true_positive"
    assert group["verdictCounts"] == {"true_positive": 1}


def test_a_custom_bound_without_an_offset_reads_in_the_grid_time_zone(
    client: TestClient,
) -> None:
    """The grid reads a bound with no offset in ``so_timezone``. The mix reads it the same way.

    The run is two hours before ``to``. Read as UTC, a bound in a zone west of
    UTC ends hours early, and the run falls out of the window.
    """
    from zoneinfo import ZoneInfo

    zone = ZoneInfo(client.app.state.settings.so_timezone)
    if datetime.now(zone).utcoffset() == timedelta(0):
        pytest.skip("so_timezone is UTC, so a naive bound reads the same either way")

    def local(hours: float) -> str:
        at = datetime.now(UTC) - timedelta(hours=hours)
        return at.astimezone(zone).replace(tzinfo=None).isoformat(timespec="minutes")

    _run(client, "INV-TP", alert_id="es-tp", verdict="true_positive", hours_ago=26)
    group = _group(client, params={"range": "custom", "from": local(48), "to": local(24)})
    assert group["windowVerdict"] == "true_positive"


def test_a_window_of_fallbacks_only_has_no_window_verdict(client: TestClient) -> None:
    """NEGATIVE CONTROL. A pipeline fallback in the window reached no verdict."""
    _run(client, "INV-FP", alert_id="es-fp", verdict="false_positive", hours_ago=72)
    _run(client, "INV-FB", alert_id="es-fb", verdict="needs_more_info", hours_ago=2, fallback=True)
    group = _group(client, "24h")
    assert group["fallback"] is True
    assert group["windowVerdict"] is None
    assert group["verdictCounts"] == {}


def test_a_backtest_replay_does_not_decide_the_window_verdict(client: TestClient) -> None:
    """NEGATIVE CONTROL. A replay is a measurement, and the standing verdict skips it too."""
    _run(client, "INV-FP", alert_id="es-fp", verdict="false_positive", hours_ago=3)
    _run(
        client,
        "INV-BT",
        alert_id="es-bt",
        verdict="true_positive",
        hours_ago=2,
        started_by="backtest",
    )
    group = _group(client, "24h")
    assert group["verdict"] == "false_positive"
    assert group["windowVerdict"] == "false_positive"
    assert group["verdictCounts"] == {"false_positive": 1}
    assert group["worstVerdict"] is None
