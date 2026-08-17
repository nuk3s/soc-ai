"""Route-level OQL hardening (2026-08-10 full-sweep, batch 5).

Covers the two findings whose fix lives at the HTTP boundary rather than inside
the OQL translator:

* ``unbounded-oql-body-parse`` — the ``q`` OQL filter has no length cap on the
  POST bodies or the GET query params, so a 30k-term OR body is ~1 s of
  synchronous lark parse on the event loop. An over-length ``q`` must be
  rejected (422) before the parse runs.
* ``es-badrequest-escapes-handler`` — ``elasticsearch.BadRequestError`` is an
  ``ApiError``, NOT a ``TransportError``, so an ES 400 escaped the route's
  ``except`` tuple as an unhandled 500. A malformed absolute time range is a
  400, and a genuine ES ``BadRequestError`` maps to 400 (not 500).
"""

from __future__ import annotations

from collections.abc import Iterator
from unittest.mock import AsyncMock, patch

import pytest
from elastic_transport import ApiResponseMeta, HttpHeaders
from elasticsearch import BadRequestError
from fastapi.testclient import TestClient
from soc_ai.config import Settings
from soc_ai.main import create_app


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


# ── unbounded-oql-body-parse ────────────────────────────────────────────────

_OVERLONG_Q = "a" * 3000  # over the 2048 cap; small enough to fit a GET query string


def test_ack_group_rejects_overlong_q_before_parse(client: TestClient) -> None:
    """An over-length ``q`` on the ack-group POST body is a 422 (pydantic), so the
    synchronous lark parse never runs on the event loop."""
    with patch("soc_ai.webui.alerts_query.fetch_group_events") as fetch:
        resp = client.post(
            "/api/v1/alerts/ack-group",
            json={"rule_name": "R", "range": "24h", "q": _OVERLONG_Q},
        )
    assert resp.status_code == 422
    fetch.assert_not_called()  # rejected at validation, before any OQL parse


def test_escalate_group_rejects_overlong_q_before_parse(client: TestClient) -> None:
    with patch("soc_ai.webui.alerts_query.fetch_group_events") as fetch:
        resp = client.post(
            "/api/v1/alerts/escalate-group",
            json={"rule_name": "R", "range": "24h", "q": _OVERLONG_Q},
        )
    assert resp.status_code == 422
    fetch.assert_not_called()


def test_list_alerts_rejects_overlong_q_query_param(client: TestClient) -> None:
    """The GET ``q`` query param carries the same cap as the POST body field."""
    with patch("soc_ai.webui.alerts_query.fetch_groups") as fetch:
        resp = client.get("/api/v1/alerts", params={"q": _OVERLONG_Q})
    assert resp.status_code == 422
    fetch.assert_not_called()


def test_auto_triage_rejects_overlong_q_before_parse(client: TestClient) -> None:
    """The bulk auto-triage start is the other door into ``parse_oql`` — it
    carries the same cap, so an over-length ``q`` is a 422 before planning runs."""
    with patch("soc_ai.webui.autotriage.plan_targets") as plan:
        resp = client.post(
            "/api/v1/auto-triage",
            json={"range": "24h", "q": _OVERLONG_Q},
        )
    assert resp.status_code == 422
    plan.assert_not_called()


def test_ack_group_accepts_normal_q(client: TestClient) -> None:
    """A short, well-formed ``q`` is NOT rejected by the cap — the route runs and
    reaches the (patched) fetch."""
    with patch("soc_ai.webui.alerts_query.fetch_group_events", AsyncMock(return_value=[])) as fetch:
        resp = client.post(
            "/api/v1/alerts/ack-group",
            json={"rule_name": "R", "range": "24h", "q": "source.ip:10.0.0.5"},
        )
    assert resp.status_code == 200
    fetch.assert_called_once()


# ── es-badrequest-escapes-handler ───────────────────────────────────────────


def test_list_alerts_bad_abs_range_is_400_not_500(client: TestClient) -> None:
    """A non-ISO absolute time range is rejected in build_filter as an
    OqlValidationError (400), never handed verbatim to ES to 500 on."""
    resp = client.get("/api/v1/alerts", params={"from": "lol", "to": "lol"})
    assert resp.status_code == 400
    assert resp.json()["detail"]["reason"] == "bad_oql"


def _bad_request_error() -> BadRequestError:
    meta = ApiResponseMeta(
        status=400,
        http_version="1.1",
        headers=HttpHeaders({}),
        duration=0.0,
        node=None,  # type: ignore[arg-type]
    )
    return BadRequestError("failed to parse date field", meta=meta, body={})


def test_list_alerts_es_badrequest_maps_to_400(client: TestClient) -> None:
    """A genuine ``elasticsearch.BadRequestError`` (an ApiError, NOT a
    TransportError) maps to 400 — before the fix it matched no ``except`` clause
    and surfaced as an unhandled 500 with a traceback."""
    with patch(
        "soc_ai.webui.alerts_query.fetch_groups",
        AsyncMock(side_effect=_bad_request_error()),
    ):
        resp = client.get("/api/v1/alerts", params={"range": "24h"})
    assert resp.status_code == 400
