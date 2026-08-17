"""Unknown availability is not availability (degraded-grid dogfood, batch G).

Three findings, one sentence: where the console cannot state a fact it must say
so, rather than substituting a confident wrong one.

* **D10** — a half-read grid was described as "slow or unreachable — retry
  shortly". It was neither: it answered 200 in under 100 ms off two of four
  shards, and retrying returns the same short answer until shard health is
  fixed. The diagnosis was already in hand — ``GridPartialResultsError`` carries
  the shard counters — and a flat ``_GRID_UNAVAILABLE`` dict threw it away. The
  classifier reaches every site that shared that constant except the two batch F
  is editing, which stay pinned below.
* **#97** — an ES 408 was filed as the analyst's bad query while the agent
  toolset filed the same status as the grid struggling.
* **D14** (server half) — hunt templates report ``available=True`` when the
  inventory read FAILED, which is fail-open and correct, but indistinguishable
  from a measured yes. ``availabilityKnown`` separates the two.

The over-correction each of these invites is guarded here too, because both
mistakes have shipped on this codebase: a connect failure keeps "retry shortly"
(true of it, and a shard-health remedy would send the analyst to the wrong
system), and a grid whose inventory reads fine still reports availability known.

Documentation addresses only (RFC 5737 / RFC 1918).
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from elastic_transport import ApiResponseMeta, HttpHeaders
from elastic_transport import ConnectionError as EsConnectionError
from elastic_transport import ConnectionTimeout as EsConnectionTimeout
from elasticsearch import ApiError
from fastapi.testclient import TestClient
from soc_ai.api.webui.routes_alerts import _es_api_error_http, _grid_unavailable
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.so_client import inventory as inventory_svc
from soc_ai.so_client.elastic import ElasticClient, GridPartialResultsError
from soc_ai.store import investigations as inv_svc

# The advice the console gave for every grid failure, of any class, before this
# batch. Still correct for a grid that never answered; wrong for one that did.
_RETRY_SHORTLY = "retry shortly"

# Documentation rule name — never a real signature on anyone's grid.
_RULE = "ET DOC TEST Suspicious Beacon"


def _partial(
    *,
    shards_failed: int = 2,
    shards_total: int = 4,
    timed_out: bool = False,
    reason: str | None = None,
) -> GridPartialResultsError:
    """The exception ``ElasticClient._check_complete`` raises on a partial read."""
    return GridPartialResultsError(
        f"partial search results from logs-*: {shards_failed} of {shards_total} shards failed",
        shards_failed=shards_failed,
        shards_total=shards_total,
        timed_out=timed_out,
        reason=reason,
    )


def _es_meta(status: int) -> ApiResponseMeta:
    return ApiResponseMeta(
        status=status,
        http_version="1.1",
        headers=HttpHeaders({}),
        duration=0.0,
        node=None,  # type: ignore[arg-type]
    )


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    inventory_svc._clear_cache()  # the inventory TTL cache outlives a test
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


def _grid_raising(exc: BaseException) -> Any:
    """Patch the one call every route below funnels through."""
    return patch.object(ElasticClient, "search", AsyncMock(side_effect=exc))


def _hint(resp: Any) -> str:
    detail = resp.json()["detail"]
    assert detail["reason"] == "grid_unavailable"
    hint: str = detail["hint"]
    return hint


# ---------------------------------------------------------------------------
# D10 — the hint is a function of the failure, not a constant
# ---------------------------------------------------------------------------


class TestAHalfReadGridIsToldApartFromAnUnreachableOne:
    def test_the_hint_names_the_shards_the_search_missed(self) -> None:
        """The count was never missing — it was discarded. The Hosts banner in
        the same outage prints "2 of 4 shards failed" off the same exception."""
        hint = _grid_unavailable(_partial(shards_failed=2, shards_total=4))["hint"]
        assert "shards" in hint
        assert "2 of 4" in hint

    def test_the_hint_drops_the_remedy_that_cannot_work(self) -> None:
        """The assertion that matters, and the one a presence-only test misses.

        Appending a shard sentence to the old string is the likely partial fix,
        and it leaves "retry shortly" on screen as advice — an instruction to
        loop on an action that returns the identical partial read every time,
        because nothing about the next request changes shard health.
        """
        hint = _grid_unavailable(_partial())["hint"]
        assert _RETRY_SHORTLY not in hint
        assert "slow or unreachable" not in hint

    def test_it_says_incomplete_rather_than_empty(self) -> None:
        """A partial read's whole danger is being read as a fact about the
        network. The hint has to say which one it is."""
        hint = _grid_unavailable(_partial())["hint"]
        assert "incomplete" in hint

    def test_a_search_that_ran_out_of_time_mid_read_is_still_a_partial_read(self) -> None:
        """``timed_out`` with zero failed shards: ES answered 200 having given up
        on some shards. Not the connect/timeout class — the grid ANSWERED — so it
        keeps the partial story rather than inheriting "retry shortly"."""
        hint = _grid_unavailable(_partial(shards_failed=0, shards_total=0, timed_out=True))["hint"]
        assert "shard" in hint
        assert _RETRY_SHORTLY not in hint

    def test_missing_shard_counters_still_get_a_partial_reads_advice(self) -> None:
        """Absent metadata must not fall back to the unreachable-grid remedy."""
        hint = _grid_unavailable(_partial(shards_failed=0, shards_total=0))["hint"]
        assert "shard" in hint
        assert _RETRY_SHORTLY not in hint

    def test_the_first_shard_failure_type_reaches_the_operator(self) -> None:
        """The actionable half of the reason the exception already carries."""
        hint = _grid_unavailable(_partial(reason="circuit_breaking_exception: [parent] too large"))[
            "hint"
        ]
        assert "circuit_breaking_exception" in hint

    def test_the_hint_never_carries_grid_internals(self) -> None:
        """A shard-failure reason carries node names and ``host:port`` pairs, and
        an operator-facing hint is the wrong place for them (the sweep's D11 is
        that same leak from the other direction). Only the exception TYPE token
        is let through, so the rest cannot escape by accident."""
        leaky = "no_shard_available_action_exception: [node-1][198.51.100.7:9300] shard [3]"
        hint = _grid_unavailable(_partial(reason=leaky))["hint"]
        assert "198.51.100.7" not in hint
        assert "9300" not in hint
        assert "no_shard_available_action_exception" in hint


class TestAGridThatNeverAnsweredKeepsItsOwnRemedy:
    """The over-correction guard. "Retry shortly" is TRUE of a refused
    connection and a read timeout — the next attempt genuinely may succeed — and
    pointing those at Elasticsearch shard health sends the analyst to a system
    that is not the problem."""

    @pytest.mark.parametrize(
        "exc",
        [
            EsConnectionError("connection refused"),
            EsConnectionTimeout("read timed out"),
            TimeoutError(),
        ],
        ids=["connection_refused", "read_timeout", "asyncio_timeout"],
    )
    def test_the_connect_and_timeout_classes_are_unchanged(self, exc: BaseException) -> None:
        hint = _grid_unavailable(exc)["hint"]
        assert _RETRY_SHORTLY in hint
        assert "shard" not in hint

    def test_no_exception_at_all_is_the_default_body(self) -> None:
        assert _grid_unavailable()["hint"] == _grid_unavailable(EsConnectionError("x"))["hint"]


class TestTheRoutesInheritTheClassifiedHint:
    """End to end, on the two screens the shot came from: the Alerts list (the
    503 behind ``▶ Details``) and the Hunt Console's alert resolve."""

    def test_the_alerts_list_tells_the_shard_story(self, client: TestClient) -> None:
        with _grid_raising(_partial()):
            resp = client.get("/api/v1/alerts?range=24h")
        assert resp.status_code == 503
        hint = _hint(resp)
        assert "2 of 4" in hint
        assert _RETRY_SHORTLY not in hint

    def test_starting_a_hunt_tells_the_shard_story(self, client: TestClient) -> None:
        with _grid_raising(_partial()):
            resp = client.post("/api/v1/hunt", json={"alert_id": "ev-partial-1"})
        assert resp.status_code == 503
        hint = _hint(resp)
        assert "2 of 4" in hint
        assert _RETRY_SHORTLY not in hint

    def test_the_alerts_list_on_a_refused_grid_still_says_retry_shortly(
        self, client: TestClient
    ) -> None:
        """Proves the negative assertions above are not vacuous: the same route,
        one failure class over, still renders the phrase they look for."""
        with _grid_raising(EsConnectionError("connection refused")):
            resp = client.get("/api/v1/alerts?range=24h")
        assert resp.status_code == 503
        assert _RETRY_SHORTLY in _hint(resp)


# ---------------------------------------------------------------------------
# Task #97 — 408 is a statement about the grid, never about the query text
# ---------------------------------------------------------------------------


class TestARequestTimeoutIsTheGridsStory:
    def test_an_es_408_is_answered_the_way_the_grids_other_failures_are(self) -> None:
        """Three classifiers answer "is this the query's fault or the grid's?",
        and 408 was the one status they split on. RFC 9110 says the client may
        repeat the request — the definition of retryable — and no edit to a
        filter makes a search finish inside a proxy's patience."""
        exc = ApiError("request timeout", meta=_es_meta(408), body={})
        http = _es_api_error_http(exc)
        assert http.status_code == 503
        assert http.detail["reason"] == "grid_unavailable"

    def test_a_real_bad_query_is_still_the_analysts_to_fix(self) -> None:
        """The over-correction: a 400 must keep pointing at the query, or every
        typo reads as an outage."""
        exc = ApiError("parsing_exception", meta=_es_meta(400), body={})
        http = _es_api_error_http(exc)
        assert http.status_code == 400
        assert http.detail["reason"] == "bad_query"

    def test_the_alerts_list_answers_a_408_with_a_retryable_card(self, client: TestClient) -> None:
        with _grid_raising(ApiError("request timeout", meta=_es_meta(408), body={})):
            resp = client.get("/api/v1/alerts?range=24h")
        assert resp.status_code == 503
        assert resp.json()["detail"]["reason"] == "grid_unavailable"


# ---------------------------------------------------------------------------
# D14 (server half) — a fail-open availability is not a measured one
# ---------------------------------------------------------------------------


class TestUnknownTemplateAvailabilityIsLabelledUnknown:
    def test_a_failed_inventory_read_marks_availability_unknown(self, client: TestClient) -> None:
        """``available`` stays True — an unreadable inventory must never hide or
        falsely flag a hunt — but the flag beside it says the value was never
        measured, so the picker can stop presenting it as telemetry the grid is
        seeing."""
        with patch(
            "soc_ai.api.webui.routes_hunts.discover_datasets",
            AsyncMock(side_effect=EsConnectionError("inventory unreadable")),
        ):
            resp = client.get("/api/v1/hunt-templates")
        assert resp.status_code == 200
        payload = resp.json()
        assert payload, "no builtin templates seeded — the assertion below would be vacuous"
        assert all(t["availabilityKnown"] is False for t in payload)
        assert all(t["available"] is True for t in payload)
        assert all(t["missingDatasets"] == [] for t in payload)

    def test_a_readable_inventory_still_reports_availability_known(
        self, client: TestClient
    ) -> None:
        """The over-correction guard: a healthy grid must not start claiming its
        template annotations are guesses."""

        class _Inv:
            def dataset_names(self) -> set[str]:
                return {"zeek.conn", "zeek.dns"}

        with patch(
            "soc_ai.api.webui.routes_hunts.discover_datasets",
            AsyncMock(return_value=_Inv()),
        ):
            resp = client.get("/api/v1/hunt-templates")
        assert resp.status_code == 200
        payload = resp.json()
        assert payload
        assert all(t["availabilityKnown"] is True for t in payload)
        # ...and the availability axis is still being evaluated, not stubbed:
        # some builtin needs telemetry this inventory does not list.
        assert any(t["available"] is False for t in payload)


# ---------------------------------------------------------------------------
# D10 across the rest of the console — every site that shared the flat constant
# ---------------------------------------------------------------------------


def _seed_nameless_investigation(client: TestClient, *, verdict: str | None = None) -> str:
    """A row with an alert but no rule name — the branch these two routes read
    the grid on. Without it they never touch Elasticsearch and the request
    below would assert on a code path the outage never reaches."""

    async def _seed() -> str:
        async with client.app.state.db_sessionmaker() as db:  # type: ignore[attr-defined]
            inv = await inv_svc.create(db, alert_es_id="ev-partial-nameless", started_by="tester")
            if verdict is not None:
                inv.verdict = verdict
                await db.commit()
            return inv.id

    return asyncio.run(_seed())


# Every remaining site that passed the flat constant and is reachable without
# editing a file an in-flight batch owns. The ids name the surface an analyst
# sees, because that is what the hint is for.
_CONVERTED_ROUTES = (
    "detection_tuning",
    "dossier_activity",
    "ack_group",
    "escalate_group",
    "find_alert",
    "bulk_rehunt",
    "request_more_info",
)


def _request_for(route: str, client: TestClient) -> tuple[str, str, dict[str, Any] | None]:
    """(method, path, json body) for one converted site."""
    if route == "detection_tuning":
        # The panel behind D15. Its muted-rules header now prints "(—)" for a
        # count it could not read; this is the advice printed directly above it.
        return "GET", "/api/v1/detection-tuning", None
    if route == "dossier_activity":
        return "GET", "/api/v1/dossiers/192.0.2.10/activity", None
    if route == "ack_group":
        return "POST", "/api/v1/alerts/ack-group", {"rule_name": _RULE}
    if route == "escalate_group":
        return "POST", "/api/v1/alerts/escalate-group", {"rule_name": _RULE}
    if route == "find_alert":
        # Root-mounted, NOT under /api/v1.
        return "POST", "/find-alert", {"source_ip": "192.0.2.10"}
    if route == "bulk_rehunt":
        return (
            "POST",
            "/api/v1/investigations/rehunt",
            {"inv_ids": [_seed_nameless_investigation(client)]},
        )
    if route == "request_more_info":
        inv_id = _seed_nameless_investigation(client, verdict="needs_more_info")
        return "POST", f"/api/v1/investigations/{inv_id}/request-more-info", {}
    raise AssertionError(f"unhandled route {route!r}")


def _send(client: TestClient, route: str) -> Any:
    method, path, body = _request_for(route, client)
    if method == "GET":
        return client.get(path)
    return client.post(path, json=body)


class TestEveryScreenTellsTheHalfReadGridApart:
    """The hint is only worth classifying where the analyst can read it.

    ``_grid_unavailable`` shipped with two callers, so seven other sites went on
    describing a grid that answered in 100 ms as "slow or unreachable — retry
    shortly". One of them is the route behind this batch's own D15 panel, which
    left one screen saying two things at once: a muted-rules count honestly
    marked unknown, under an error card advising an action that returns the same
    partial read every time. Another is the Backtest screen D10 names by name.

    A pin recorded the gap; a pin is not a fix. These are the sites the round's
    file ownership left reachable: four of the five files belong to no batch,
    and the fifth (``routes_investigations.py``) belongs to batch C, which
    merged before this branch's base.
    """

    @pytest.mark.parametrize("route", _CONVERTED_ROUTES)
    def test_a_half_read_grid_gets_the_shard_story(self, client: TestClient, route: str) -> None:
        with _grid_raising(_partial()):
            resp = _send(client, route)
        assert resp.status_code == 503
        hint = _hint(resp)
        assert "2 of 4" in hint
        assert _RETRY_SHORTLY not in hint

    @pytest.mark.parametrize("route", _CONVERTED_ROUTES)
    def test_a_refused_grid_still_gets_the_remedy_that_works(
        self, client: TestClient, route: str
    ) -> None:
        """The over-correction guard, one per route rather than once for the set.

        A route wired to ``_grid_unavailable`` by hand can pass the wrong
        exception (the ``from exc`` chain has two candidates at several of these
        sites), and the failure mode is silent: every outage would read as a
        shard problem and send the analyst to a healthy Elasticsearch. It also
        proves the negative assertion above is not vacuous — same route, one
        failure class over, and the phrase it looks for is there.
        """
        with _grid_raising(EsConnectionError("connection refused")):
            resp = _send(client, route)
        assert resp.status_code == 503
        hint = _hint(resp)
        assert _RETRY_SHORTLY in hint
        assert "shard" not in hint


# ---------------------------------------------------------------------------
# Pins on routes this batch does not own
# ---------------------------------------------------------------------------


def test_pin_the_grid_budget_routes_still_flatten_a_partial_read(client: TestClient) -> None:
    """RED WHEN YOU FIX IT, which is the point — this records a gap, it does not
    endorse one.

    Two sites still hand the analyst "slow or unreachable — retry shortly" for a
    grid that answered in 100 ms, and both live in files batch F
    (``grid-budgets``) is editing right now:

        soc_ai/api/webui/routes_autotriage.py:155   (Auto-Investigate)
        soc_ai/api/webui/routes_backtest.py:125     (Backtest — named by D10)

    Batch F: import ``_grid_unavailable`` from ``routes_alerts`` alongside
    ``_es_api_error_http`` and pass the caught ``exc`` — one line each, nothing
    else needed. The new "sampled. Security Onion (Elasticsearch) is slow or
    unreachable; retry shortly." string in ``soc_ai/webui/backtest.py`` needs the
    same treatment: on a partial read the sample is not short because the grid is
    unreachable, it is short because part of the index was never read, and the
    two call for different actions. When both land, delete this test.

    Driven through Auto-Investigate rather than asserted against the source
    text, so it fails on the behaviour rather than on a constant's name.
    """
    with _grid_raising(_partial()):
        resp = client.post("/api/v1/auto-triage", json={"range": "24h"})
    assert resp.status_code == 503
    assert _RETRY_SHORTLY in _hint(resp)
