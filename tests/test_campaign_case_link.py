"""The link of a campaign case to the campaign page of the console."""

from __future__ import annotations

from datetime import datetime
from types import SimpleNamespace
from unittest.mock import patch

from soc_ai.api.webui import routes_campaign_case as case_routes
from soc_ai.config import Settings


def _request(base: str) -> SimpleNamespace:
    return SimpleNamespace(base_url=base)


def test_the_link_keeps_the_address_that_the_analyst_used() -> None:
    with patch.object(case_routes, "_request_is_https", return_value=False):
        link = case_routes._campaign_link(_request("http://console.example.test/"), 7)  # type: ignore[arg-type]
    assert link == "http://console.example.test/app/campaigns/7"


def test_the_link_is_https_behind_a_proxy_that_ends_tls() -> None:
    """The app sees http. A trusted proxy reports https. The case then holds
    the address that opens in the browser of the analyst."""
    with patch.object(case_routes, "_request_is_https", return_value=True):
        link = case_routes._campaign_link(_request("http://console.example.test/"), 7)  # type: ignore[arg-type]
    assert link == "https://console.example.test/app/campaigns/7"


def test_an_https_address_stays_as_it_is() -> None:
    with patch.object(case_routes, "_request_is_https", return_value=True):
        link = case_routes._campaign_link(_request("https://console.example.test/"), 7)  # type: ignore[arg-type]
    assert link == "https://console.example.test/app/campaigns/7"


def test_the_alert_read_of_a_case_names_the_period_of_its_alerts(settings_kratos: Settings) -> None:
    """The grid opens the indices of those days only. A read with no window
    passed the grid timeout on a production grid after a quiet hour."""
    settings = settings_kratos
    window = (datetime(2026, 1, 10, 6, 0, 0), datetime(2026, 1, 12, 18, 30, 0))
    query = case_routes._alerts_query(settings, ["alert-1", "alert-2"], window)
    filters = query["bool"]["filter"]
    assert {"ids": {"values": ["alert-1", "alert-2"]}} in filters
    assert {
        "range": {"@timestamp": {"gte": "2026-01-09T06:00:00Z", "lte": "2026-01-13T18:30:00Z"}}
    } in filters


def test_the_alert_read_has_no_window_when_a_time_is_not_known(settings_kratos: Settings) -> None:
    query = case_routes._alerts_query(settings_kratos, ["alert-1"], None)
    assert all("range" not in clause for clause in query["bool"]["filter"])
