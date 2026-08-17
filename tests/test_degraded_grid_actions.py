"""Degraded-grid guards on the routes an analyst ACTS through (sweep batch E1).

Every route here is something an analyst clicks *while the grid is sick*: start
an investigation, acknowledge or escalate a detection group, resolve a row from
an external console, bulk re-hunt. Each one used to answer an unhandled 500 with
an ASGI traceback, because it called Elasticsearch with no guard at all.

Three things are asserted, and the order matters:

* ``status_code != 500`` — the single assertion that would have caught all seven
  instances of this class at once. It is spelled out separately from the
  ``in (503, 400)`` check on purpose, so the failure message names the defect.
* the ES-answers-an-error state, not just connection-refused. ``elasticsearch.
  ApiError`` is NOT an ``elastic_transport.TransportError`` — the two are
  separate hierarchies — so a guard that catches only the
  ``(TimeoutError, TransportError)`` tuple still leaks every ES 4xx as a 500.
  Testing connection-refused alone is exactly how finding G11 survived MR !70.
* nothing was written. A 503 that arrives *after* a partial ack is worse than
  the 500 was: the analyst retries and double-acks. The write path is spied on,
  with a control proving the spy is wired to something that really does fire.

Documentation addresses only (RFC 5737 / RFC 1918).
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Iterator
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from elastic_transport import ApiResponseMeta, HttpHeaders
from elastic_transport import ConnectionError as EsConnectionError
from elastic_transport import ConnectionTimeout as EsConnectionTimeout
from elasticsearch import ApiError, BadRequestError
from fastapi.testclient import TestClient
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.so_client import inventory as inventory_svc
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.store import investigations as inv_svc
from soc_ai.webui.alerts_query import AlertEvent

_RULE = "ET DOC TEST Suspicious Beacon"


def _client(settings: Settings) -> Iterator[TestClient]:
    fake_es = AsyncMock()
    fake_auth = AsyncMock()
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
        patch("soc_ai.main.make_auth", return_value=fake_auth),
        patch("soc_ai.main.get_settings", return_value=settings),
    ):
        app = create_app()
        with TestClient(app) as client:
            yield client


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    inventory_svc._clear_cache()  # the inventory TTL cache outlives a test
    yield from _client(settings_kratos)


# ── the three grid states ───────────────────────────────────────────────────
#
# ConnectionError / ConnectionTimeout are TransportErrors -> 503 grid_unavailable.
# BadRequestError is an ApiError, a SEPARATE hierarchy -> 400 bad_query. A route
# guarded only by the (TimeoutError, TransportError) tuple passes the first two
# and 500s on the third.


def _es_meta(status: int) -> ApiResponseMeta:
    return ApiResponseMeta(
        status=status,
        http_version="1.1",
        headers=HttpHeaders({}),
        duration=0.0,
        node=None,  # type: ignore[arg-type]
    )


def _es_bad_request() -> BadRequestError:
    return BadRequestError("failed to parse date field", meta=_es_meta(400), body={})


_GRID_STATES: dict[str, Any] = {
    "connection_refused": EsConnectionError("connection refused"),
    "connection_timeout": EsConnectionTimeout("read timed out"),
    "es_api_error_400": _es_bad_request(),
}
_TRANSPORT_STATES = ("connection_refused", "connection_timeout")


def _grid_down(state: str) -> Any:
    """Patch the ONE call every route below funnels through: ``ElasticClient.search``."""
    return patch.object(ElasticClient, "search", AsyncMock(side_effect=_GRID_STATES[state]))


# ── the six analyst actions ─────────────────────────────────────────────────


def _seed_nameless_investigation(client: TestClient, *, verdict: str | None = None) -> str:
    """A row with an alert but no rule name — the branch bulk re-hunt reads ES on."""

    async def _seed() -> str:
        async with client.app.state.db_sessionmaker() as db:  # type: ignore[attr-defined]
            inv = await inv_svc.create(db, alert_es_id="ev-e1-nameless", started_by="tester")
            if verdict is not None:
                inv.verdict = verdict
                await db.commit()
            return inv.id

    return asyncio.run(_seed())


_ACTIONS = (
    "hunt",
    "ack_group",
    "escalate_group",
    "find_alert",
    "bulk_rehunt",
    "request_more_info",
)


def _request_for(action: str, client: TestClient) -> tuple[str, dict[str, Any]]:
    """(path, json body) for one analyst action."""
    if action == "hunt":
        return "/api/v1/hunt", {"alert_id": "ev-e1-alert"}
    if action == "ack_group":
        return "/api/v1/alerts/ack-group", {"rule_name": _RULE}
    if action == "escalate_group":
        return "/api/v1/alerts/escalate-group", {"rule_name": _RULE}
    if action == "find_alert":
        # Root-mounted, NOT under /api/v1 — which is why this one was missed.
        return "/find-alert", {"source_ip": "192.0.2.10", "destination_ip": "198.51.100.20"}
    if action == "bulk_rehunt":
        return (
            "/api/v1/investigations/rehunt",
            {"inv_ids": [_seed_nameless_investigation(client)]},
        )
    if action == "request_more_info":
        # Reads the grid on exactly the same nameless-row branch as bulk re-hunt,
        # and was guarded with it — but sat outside this matrix, which is how a
        # guard rots. The verdict gate must be satisfied to reach the grid call.
        inv_id = _seed_nameless_investigation(client, verdict="needs_more_info")
        return f"/api/v1/investigations/{inv_id}/request-more-info", {}
    raise AssertionError(f"unhandled action {action!r}")


@pytest.mark.parametrize("action", _ACTIONS)
@pytest.mark.parametrize("state", sorted(_GRID_STATES))
def test_analyst_actions_answer_a_sick_grid_honestly(
    client: TestClient, action: str, state: str
) -> None:
    """No analyst action 500s on a sick grid, in any of its three states.

    Before batch E1 every cell of this matrix was an unhandled 500 with a
    traceback in the log: POST /hunt is the Investigate button, the most-clicked
    control in the product, and it 500'd on a hiccup while the alerts list one
    tab over answered a clean 503.
    """
    path, body = _request_for(action, client)
    with _grid_down(state):
        resp = client.post(path, json=body)

    # The load-bearing assertion, spelled out on its own line.
    assert resp.status_code != 500, f"{action} on a {state} grid is an unhandled 500"
    assert resp.status_code in (503, 400)

    detail = resp.json()["detail"]
    if state in _TRANSPORT_STATES:
        assert resp.status_code == 503
        assert detail["reason"] == "grid_unavailable"
    else:
        # ApiError is not a TransportError: a route whose only guard is the
        # transport tuple reaches here as a 500, and a route that lumps ES 4xx
        # in with the outage reaches here as a 503 telling the wrong story.
        assert resp.status_code == 400
        assert detail["reason"] == "bad_query"


# ── the write-ordering guarantee ────────────────────────────────────────────


def test_ack_group_acknowledges_nothing_when_the_event_fetch_fails(client: TestClient) -> None:
    """A 503 from ack-group must never arrive on top of a partial ack.

    Status code alone is not enough here. If the group fetch failed *after* some
    events had already been acknowledged in Security Onion, the analyst would
    read the 503 as "nothing happened", retry, and acknowledge those events
    twice. Assert the write path was never entered at all — the fetch is a read
    that must complete before the first write.
    """
    writes = AsyncMock(return_value=(None, None))
    with (
        patch("soc_ai.api.webui.routes_alert_actions.execute_write_tool", writes),
        _grid_down("connection_refused"),
    ):
        resp = client.post("/api/v1/alerts/ack-group", json={"rule_name": _RULE})

    assert resp.status_code == 503
    assert resp.json()["detail"]["reason"] == "grid_unavailable"
    assert writes.await_count == 0, "ack-group wrote to Security Onion before failing"


def test_ack_group_write_spy_fires_on_a_healthy_grid(client: TestClient) -> None:
    """Control for the test above: the spied symbol IS the ack write path.

    Without this, ``await_count == 0`` would also pass if the patch target were
    wrong or the route had stopped acking entirely — a false green of exactly
    the shape this project has shipped before.
    """
    events = [
        AlertEvent(
            es_id="ev-doc-1",
            timestamp="2026-08-13T00:00:00Z",
            src="192.0.2.10:44321",
            dst="198.51.100.20:443",
            severity="high",
            host="workstation.example",
        )
    ]
    writes = AsyncMock(return_value=(None, None))
    with (
        patch("soc_ai.api.webui.routes_alert_actions.execute_write_tool", writes),
        patch(
            "soc_ai.webui.alerts_query.fetch_group_events",
            AsyncMock(return_value=events),
        ),
    ):
        resp = client.post("/api/v1/alerts/ack-group", json={"rule_name": _RULE})

    assert resp.status_code == 200
    assert resp.json()["acked"] == 1
    assert writes.await_count == 1


def test_escalate_group_opens_no_cases_when_the_event_fetch_fails(client: TestClient) -> None:
    """Same ordering guarantee on the escalate sibling: a failed fetch opens no
    SOC cases, so the 503 is not a report on a half-done escalate."""
    writes = AsyncMock(return_value=(None, None))
    with (
        patch("soc_ai.api.webui.routes_alert_actions.execute_write_tool", writes),
        _grid_down("es_api_error_400"),
    ):
        resp = client.post("/api/v1/alerts/escalate-group", json={"rule_name": _RULE})

    assert resp.status_code == 400
    assert writes.await_count == 0


def test_bulk_rehunt_keeps_the_runs_it_already_started(client: TestClient) -> None:
    """A grid failure mid-batch must not discard re-hunts already launched.

    Raising a bare 503 here would report failure for live background runs and
    invite a retry that starts every one of them a second time — the same
    partial-write trap as ack-group, one route over. The honest answer is the
    partial result, with the unreadable id marked.
    """

    async def _seed() -> tuple[str, str]:
        async with client.app.state.db_sessionmaker() as db:  # type: ignore[attr-defined]
            named = await inv_svc.create(
                db, alert_es_id="ev-e1-named", started_by="tester", rule_name=_RULE
            )
            nameless = await inv_svc.create(db, alert_es_id="ev-e1-nameless-2", started_by="tester")
            return named.id, nameless.id

    named_id, nameless_id = asyncio.run(_seed())

    fake_mgr = AsyncMock()
    fake_mgr.start = AsyncMock(return_value="NEW-INV")
    mgr_target = "soc_ai.api.webui.routes_investigations.hunt_manager.get_manager"
    with (
        patch(mgr_target, return_value=fake_mgr),
        _grid_down("connection_refused"),
    ):
        resp = client.post(
            "/api/v1/investigations/rehunt", json={"inv_ids": [named_id, nameless_id]}
        )

    assert resp.status_code == 200
    body = resp.json()
    assert [s["invId"] for s in body["started"]] == [named_id]
    assert body["skipped"] == [{"invId": nameless_id, "reason": "grid_unavailable"}]


def test_bulk_rehunt_skip_reason_matches_what_the_same_error_would_be_raised_as(
    client: TestClient,
) -> None:
    """A mid-batch skip must tell the same story the raised error tells.

    The same ES rejection answers 400 ``bad_query`` when nothing has started yet
    and used to be folded into the partial result as ``grid_unavailable`` — one
    request, one exception, two contradictory diagnoses, and the Investigations
    screen renders the raw code. A rejected query is not an outage.
    """

    async def _seed() -> tuple[str, str]:
        async with client.app.state.db_sessionmaker() as db:  # type: ignore[attr-defined]
            named = await inv_svc.create(
                db, alert_es_id="ev-e1-named-3", started_by="tester", rule_name=_RULE
            )
            nameless = await inv_svc.create(db, alert_es_id="ev-e1-nameless-3", started_by="tester")
            return named.id, nameless.id

    named_id, nameless_id = asyncio.run(_seed())

    fake_mgr = AsyncMock()
    fake_mgr.start = AsyncMock(return_value="NEW-INV")
    mgr_target = "soc_ai.api.webui.routes_investigations.hunt_manager.get_manager"
    with (
        patch(mgr_target, return_value=fake_mgr),
        _grid_down("es_api_error_400"),
    ):
        resp = client.post(
            "/api/v1/investigations/rehunt", json={"inv_ids": [named_id, nameless_id]}
        )

    assert resp.status_code == 200
    body = resp.json()
    assert [s["invId"] for s in body["started"]] == [named_id]
    assert body["skipped"] == [{"invId": nameless_id, "reason": "bad_query"}]

    # The control: the very same request with NOTHING started raises rather than
    # skips, and it must reach for the identical label.
    with _grid_down("es_api_error_400"):
        raised = client.post("/api/v1/investigations/rehunt", json={"inv_ids": [nameless_id]})
    assert raised.status_code == 400
    assert raised.json()["detail"]["reason"] == "bad_query"


# ── a 4xx by number is not always the analyst's fault ───────────────────────


_SATURATION_ACTIONS = ("hunt", "ack_group", "find_alert")


@pytest.mark.parametrize("action", _SATURATION_ACTIONS)
def test_a_saturated_grid_reads_as_retryable_not_as_a_typo(client: TestClient, action: str) -> None:
    """A grid that is UP but over its limits must not be reported as a bad query.

    ES answers 429 ``circuit_breaking_exception`` when the search queue is full
    or a circuit breaker has tripped: retryable, and nothing is wrong with the
    query. Sorted by its number alone it became "check the fields and time range"
    — told to an analyst whose query is fine, and, because a 400 reads as
    non-retryable to the SPA, hiding the one useful fact, which is *retry*.

    This test shipped RED on purpose. ``_es_api_error_http`` lives in
    ``routes_alerts.py``, which a sibling batch owned, so this batch pinned the
    wrong answer rather than growing a local variant of the house guard, with a
    note telling whoever fixed the helper to come back and flip it. That batch
    landed the 429 arm; these are the flipped expectations.

    Worth keeping in the docstring: ``ElasticClient`` already sets
    ``retry_on_status=(429, 502, 503, 504)``, so a 429 that reaches a route has
    already been retried ``es_max_retries`` times. It means SUSTAINED saturation,
    which is what makes "the grid is unavailable, try shortly" honest here rather
    than a guess.
    """
    path, body = _request_for(action, client)
    saturated = ApiError("circuit_breaking_exception", meta=_es_meta(429), body={})
    with patch.object(ElasticClient, "search", AsyncMock(side_effect=saturated)):
        resp = client.post(path, json=body)

    assert resp.status_code != 500, f"{action} on a saturated grid is an unhandled 500"
    assert resp.status_code == 503, f"{action} blamed a saturated grid on the analyst's query"
    assert resp.json()["detail"]["reason"] == "grid_unavailable"


# ── the stall bound (a silent grid is not a hang) ───────────────────────────
#
# Against a grid that accepts the connection and never answers, an unguarded
# route rides the ES client's retry budget: (1 + es_max_retries) x
# es_request_timeout_s, about 90 s at shipped defaults, per click. Elapsed time
# is asserted against webui_grid_timeout_s rather than a hardcoded number, so
# these track the setting.


def _stalling_search() -> Any:
    async def _never(*_a: Any, **_k: Any) -> None:
        await asyncio.sleep(30)

    return patch.object(ElasticClient, "search", _never)


@pytest.mark.parametrize(
    ("method", "path", "body", "expected_status"),
    [
        ("POST", "/api/v1/hunt", {"alert_id": "ev-e1-alert"}, 503),
        ("POST", "/api/v1/alerts/ack-group", {"rule_name": _RULE}, 503),
        # Fail OPEN, but fail FAST: a stalled inventory read must not hold the
        # Hunt Console, and it must not dim the starters either.
        ("GET", "/api/v1/hunt-templates", None, 200),
    ],
)
def test_stalled_grid_is_bounded_by_the_console_budget(
    settings_kratos: Settings,
    method: str,
    path: str,
    body: dict[str, Any] | None,
    expected_status: int,
) -> None:
    budget = 1
    settings = settings_kratos.model_copy(update={"webui_grid_timeout_s": budget})
    inventory_svc._clear_cache()
    for c in _client(settings):
        with _stalling_search():
            started = time.monotonic()
            resp = c.request(method, path, json=body)
            elapsed = time.monotonic() - started
        assert resp.status_code == expected_status
        assert elapsed < budget * 2, f"{path} took {elapsed:.1f}s against a {budget}s budget"


def test_stalled_grid_costs_a_rehunt_batch_one_budget_not_one_per_row(
    settings_kratos: Settings,
) -> None:
    """A bulk re-hunt pays ONE grid budget, however many nameless rows it holds.

    Nameless rows are precisely the runs that died early — the rows an analyst
    bulk re-hunts to clean up AFTER an outage, plausibly while the grid is still
    sick. Re-probing an accepting-but-silent grid once per row is linear in the
    batch: at the shipped cap of 50 ids that is 49 consecutive timeouts, minutes
    past any client's patience, with the server still starting runs nobody is
    watching for. The first failure settles the question for the whole batch.
    """
    budget = 1
    settings = settings_kratos.model_copy(update={"webui_grid_timeout_s": budget})
    inventory_svc._clear_cache()
    for c in _client(settings):

        async def _seed(client: TestClient = c) -> tuple[str, list[str]]:
            async with client.app.state.db_sessionmaker() as db:  # type: ignore[attr-defined]
                named = await inv_svc.create(
                    db, alert_es_id="ev-e1-batch-named", started_by="tester", rule_name=_RULE
                )
                nameless = [
                    (
                        await inv_svc.create(
                            db, alert_es_id=f"ev-e1-batch-{i}", started_by="tester"
                        )
                    ).id
                    for i in range(4)
                ]
                return named.id, nameless

        named_id, nameless_ids = asyncio.run(_seed())
        fake_mgr = AsyncMock()
        fake_mgr.start = AsyncMock(return_value="NEW-INV")
        mgr_target = "soc_ai.api.webui.routes_investigations.hunt_manager.get_manager"
        with patch(mgr_target, return_value=fake_mgr), _stalling_search():
            started = time.monotonic()
            resp = c.post(
                "/api/v1/investigations/rehunt", json={"inv_ids": [named_id, *nameless_ids]}
            )
            elapsed = time.monotonic() - started

        assert resp.status_code == 200
        body = resp.json()
        # Still the honest partial result: the started run is kept, and every
        # row we could not name is REPORTED, not silently dropped or invented.
        assert [s["invId"] for s in body["started"]] == [named_id]
        assert [s["invId"] for s in body["skipped"]] == nameless_ids
        assert {s["reason"] for s in body["skipped"]} == {"grid_unavailable"}
        assert elapsed < budget * 2, (
            f"{len(nameless_ids)} nameless rows spent {elapsed:.1f}s of a {budget}s budget — "
            "the batch is paying one timeout per row"
        )


def test_stalled_acked_probe_does_not_hold_the_investigation_detail_page(
    settings_kratos: Settings,
) -> None:
    """The detail page's acked-state probe is discardable, so it is bounded
    TIGHTER than the console budget — it must never be what makes the page slow."""
    budget = 4
    settings = settings_kratos.model_copy(update={"webui_grid_timeout_s": budget})
    for c in _client(settings):

        async def _seed(client: TestClient = c) -> str:
            async with client.app.state.db_sessionmaker() as db:  # type: ignore[attr-defined]
                inv = await inv_svc.create(
                    db, alert_es_id="ev-e1-detail", started_by="tester", rule_name=_RULE
                )
                return inv.id

        inv_id = asyncio.run(_seed())
        with _stalling_search():
            started = time.monotonic()
            resp = c.get(f"/api/v1/investigations/{inv_id}")
            elapsed = time.monotonic() - started
        # Still a 200: a failed probe means "not acked", so the action is simply
        # offered again (an ack is idempotent).
        assert resp.status_code == 200
        assert elapsed < budget, f"the discardable probe spent {elapsed:.1f}s of a {budget}s budget"
