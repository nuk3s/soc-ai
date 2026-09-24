"""Slice 1 of the hunting release: finding → investigation promotion.

Covers migration 0031, which adds ``kind`` / ``hunt_id`` / ``finding_ordinal``
to ``investigations``. Mirrors the ``_db`` helper in
tests/test_store_investigations.py: a real SQLite file migrated to head via
``settings_kratos`` (isolated to a per-test temp dir by the autouse
``clean_env`` fixture), not a hand-rolled engine.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Iterator
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.api.runner import recorded_run, run_recorded
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.so_client.elastic import ElasticClient, EsSearchResult
from soc_ai.store import hunts as hunt_svc
from soc_ai.store import investigations as inv_svc
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import Investigation
from sqlalchemy.exc import InvalidRequestError


async def _db(settings: Settings):  # type: ignore[no-untyped-def]
    engine = make_engine(settings)
    await run_migrations(engine)
    return engine, make_sessionmaker(engine)


async def test_investigation_has_kind_and_hunt_provenance_columns(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        inv = Investigation(
            id="01TESTPROMOTE0000000000000",
            alert_es_id="anchor-es-id",
            kind="hunt",
            hunt_id="01HUNT0000000000000000000000",
            finding_ordinal=2,
        )
        db.add(inv)
        await db.commit()
        got = await db.get(Investigation, "01TESTPROMOTE0000000000000")
        assert got is not None
        assert got.kind == "hunt"
        assert got.hunt_id == "01HUNT0000000000000000000000"
        assert got.finding_ordinal == 2
    await engine.dispose()


async def test_investigation_kind_defaults_to_suricata(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        inv = Investigation(id="01TESTDEFAULTKIND000000000", alert_es_id="x")
        db.add(inv)
        await db.commit()
        got = await db.get(Investigation, "01TESTDEFAULTKIND000000000")
        assert got is not None
        assert got.kind == "suricata"
        assert got.hunt_id is None
        assert got.finding_ordinal is None
    await engine.dispose()


async def test_create_accepts_promotion_provenance(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        inv = await inv_svc.create(
            db,
            alert_es_id="anchor-1",
            started_by="admin",
            rule_name="Beacon to rare external IP",
            kind="hunt",
            hunt_id="01HUNTA000000000000000000000",
            finding_ordinal=0,
        )
        assert (inv.kind, inv.hunt_id, inv.finding_ordinal) == (
            "hunt",
            "01HUNTA000000000000000000000",
            0,
        )
    await engine.dispose()


async def test_latest_for_finding_is_the_idempotency_probe(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        a = await inv_svc.create(
            db,
            alert_es_id="anchor-1",
            started_by="x",
            kind="hunt",
            hunt_id="01HUNTB000000000000000000000",
            finding_ordinal=1,
        )
        got = await inv_svc.latest_for_finding(db, "01HUNTB000000000000000000000", 1)
        assert got is not None
        assert got.id == a.id
        assert await inv_svc.latest_for_finding(db, "01HUNTB000000000000000000000", 2) is None
    await engine.dispose()


async def test_latest_for_finding_returns_the_newer_of_two_promotions(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await inv_svc.create(
            db,
            alert_es_id="anchor-1",
            started_by="x",
            kind="hunt",
            hunt_id="01HUNTC000000000000000000000",
            finding_ordinal=3,
        )
        b = await inv_svc.create(
            db,
            alert_es_id="anchor-2",
            started_by="x",
            kind="hunt",
            hunt_id="01HUNTC000000000000000000000",
            finding_ordinal=3,
        )
        got = await inv_svc.latest_for_finding(db, "01HUNTC000000000000000000000", 3)
        assert got is not None
        assert got.id == b.id
    await engine.dispose()


# ── Task 3: promotion provenance threads through recorded_run to the row ──


async def _empty_stream() -> AsyncIterator[Any]:
    """An event stream with no events — the recorder still creates the row
    (and emits investigation_created) before anything is consumed."""
    return
    yield  # pragma: no cover


async def test_recorded_run_threads_promotion_provenance(settings_kratos: Settings) -> None:
    """The promotion route launches via HuntManager.start -> run_recorded ->
    recorded_run -> InvestigationRecorder.start -> inv_svc.create. This test
    pins the kwargs recorded_run passes down to that create() call; the upper
    hops (the route itself) are covered by the promotion-route tests below."""
    engine, maker = await _db(settings_kratos)
    state = type("S", (), {"db_sessionmaker": maker})()
    events = [
        ev
        async for ev in recorded_run(
            state,
            alert_id="anchor-1",
            started_by="admin",
            event_stream=_empty_stream(),
            rule_name="Beacon to rare external IP",
            kind="hunt",
            hunt_id="01HUNTC000000000000000000000",
            finding_ordinal=3,
        )
    ]
    created = dict(events)["investigation_created"]
    async with maker() as db:
        inv = await db.get(Investigation, created["investigation_id"])
    assert inv is not None
    assert (inv.kind, inv.hunt_id, inv.finding_ordinal) == (
        "hunt",
        "01HUNTC000000000000000000000",
        3,
    )
    await engine.dispose()


async def test_recorded_run_defaults_to_suricata_kind(settings_kratos: Settings) -> None:
    """Every existing caller (alert grid, re-hunt, auto-triage) omits the new
    kwargs entirely — the row must still land kind='suricata' with null
    provenance, unchanged from before this chain was threaded."""
    engine, maker = await _db(settings_kratos)
    state = type("S", (), {"db_sessionmaker": maker})()
    events = [
        ev
        async for ev in recorded_run(
            state,
            alert_id="anchor-2",
            started_by="admin",
            event_stream=_empty_stream(),
        )
    ]
    created = dict(events)["investigation_created"]
    async with maker() as db:
        inv = await db.get(Investigation, created["investigation_id"])
    assert inv is not None
    assert (inv.kind, inv.hunt_id, inv.finding_ordinal) == ("suricata", None, None)
    await engine.dispose()


# ── Task 4: investigations speak their stored kind; hunt provenance on detail ──
#
# Route-level tests. Harness mirrors tests/test_hunts_api.py's `_client`/`client`
# fixture: create_app() with the ES client + auth backend mocked out, driven
# through a real TestClient so the seeded SQLite DB round-trips through the
# actual routes (not a hand-rolled response model).


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
def kind_client(settings_kratos: Settings) -> Iterator[TestClient]:
    yield from _client(settings_kratos)


# >160 chars (205) so the detail route's `hunt.objective[:160]` slice is
# exercised for real — a short fixture would pass the length assertion
# whether or not the truncation actually fired.
_LONG_OBJECTIVE = (
    "Sweep for beaconing to rare external IPs over 72h. Cross-reference DNS "
    "lookups, TLS SNI fields, and firewall egress logs for any host exhibiting "
    "a fixed low-jitter connection cadence to a rare destination."
)


def _seed_promoted_and_plain(client: TestClient) -> tuple[str, str, str]:
    """Seed a complete hunt + its promoted investigation, and a plain investigation.

    Returns (hunt_id, promoted_investigation_id, plain_investigation_id).
    """

    async def _go() -> tuple[str, str, str]:
        maker = client.app.state.db_sessionmaker
        async with maker() as db:
            hunt = await hunt_svc.create(
                db,
                objective=_LONG_OBJECTIVE,
                started_by="admin",
            )
            await hunt_svc.finalize(
                db,
                hunt.id,
                status="complete",
                narrative="One host beacons to a rare external IP.",
                report={
                    "findings": [
                        {
                            "title": "Beaconing to rare external IP",
                            "detail": "10.0.0.5 -> 203.0.113.9 on a fixed cadence.",
                            "severity": "high",
                            "hosts": ["10.0.0.5"],
                            "citations": ["es-abc"],
                        }
                    ]
                },
            )
            promoted = await inv_svc.create(
                db,
                alert_es_id="promoted-anchor",
                started_by="admin",
                rule_name="Beaconing to rare external IP",
                kind="hunt",
                hunt_id=hunt.id,
                finding_ordinal=0,
            )
            await inv_svc.finalize(
                db, promoted.id, status="complete", verdict="true_positive", confidence=0.8
            )
            plain = await inv_svc.create(
                db, alert_es_id="plain-anchor", started_by="admin", rule_name="ET SCAN Suspicious"
            )
            await inv_svc.finalize(
                db, plain.id, status="complete", verdict="false_positive", confidence=0.4
            )
            return hunt.id, promoted.id, plain.id

    return asyncio.run(_go())


def test_investigations_list_and_detail_speak_stored_kind(kind_client: TestClient) -> None:
    hunt_id, promoted_id, plain_id = _seed_promoted_and_plain(kind_client)

    rows = {r["id"]: r for r in kind_client.get("/api/v1/investigations").json()["rows"]}
    assert rows[promoted_id]["kind"] == "hunt"
    assert rows[plain_id]["kind"] == "suricata"

    promoted_detail = kind_client.get(f"/api/v1/investigations/{promoted_id}")
    assert promoted_detail.status_code == 200
    body = promoted_detail.json()
    assert body["kind"] == "hunt"
    assert body["huntId"] == hunt_id
    assert body["huntObjective"] is not None
    assert body["huntObjective"].startswith("Sweep for beaconing")
    assert body["huntObjective"] == _LONG_OBJECTIVE[:160]
    assert len(body["huntObjective"]) == 160

    plain_detail = kind_client.get(f"/api/v1/investigations/{plain_id}")
    assert plain_detail.status_code == 200
    plain_body = plain_detail.json()
    assert plain_body["kind"] == "suricata"
    assert plain_body["huntId"] is None
    assert plain_body["huntObjective"] is None


def test_investigation_detail_degrades_gracefully_when_hunt_deleted(
    kind_client: TestClient,
) -> None:
    """hunt_id has no FK — the referenced hunt row may not exist (deleted, or
    never existed). The detail response must still 200, with huntId set and
    huntObjective None, never a 500."""

    async def _go() -> str:
        maker = kind_client.app.state.db_sessionmaker
        async with maker() as db:
            inv = await inv_svc.create(
                db,
                alert_es_id="dangling-anchor",
                started_by="admin",
                kind="hunt",
                hunt_id="01HUNTDOESNOTEXIST00000000000",
                finding_ordinal=0,
            )
            await inv_svc.finalize(db, inv.id, status="complete", verdict="true_positive")
            return inv.id

    inv_id = asyncio.run(_go())

    resp = kind_client.get(f"/api/v1/investigations/{inv_id}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["kind"] == "hunt"
    assert body["huntId"] == "01HUNTDOESNOTEXIST00000000000"
    assert body["huntObjective"] is None


# ── Task 5: POST /hunts/{hunt_id}/findings/{ordinal}/investigate ──────────────
#
# _resolve_finding_anchor's _ID_SHAPED gate requires >=12 chars, so every
# citation used below as a "real" anchor is a 12+ char det-doc-/tel-doc- id —
# short enough to read as the plan's det-doc-1/tel-doc-1 shorthand, long enough
# to actually pass the regex it's exercising.

_MGR_TARGET = "soc_ai.api.webui.routes_hunts.hunt_manager.get_manager"


def _seed_hunt(
    client: TestClient, *, status: str = "complete", findings: list[dict[str, Any]] | None = None
) -> str:
    """Seed a hunt with the given status/findings; returns its id. A 'running'
    hunt is never finalized, so its report stays empty — every caller that
    seeds one is only exercising the still-running guard, before findings are
    ever read."""

    async def _go() -> str:
        maker = client.app.state.db_sessionmaker
        async with maker() as db:
            hunt = await hunt_svc.create(db, objective=_LONG_OBJECTIVE, started_by="admin")
            if status != "running":
                await hunt_svc.finalize(
                    db,
                    hunt.id,
                    status=status,
                    report={"findings": findings if findings is not None else []},
                )
            return hunt.id

    return asyncio.run(_go())


async def _fake_start_creates_row(
    state: Any,
    *,
    alert_id: str,
    started_by: str,
    rule_name: str | None = None,
    focus_hint: str | None = None,
    deep: bool = False,
    kind: str = "suricata",
    hunt_id: str | None = None,
    finding_ordinal: int | None = None,
    allow_so_writes: bool = True,
    focus_origin: str = "rerun",
    subject: Any = None,
    is_synth_eval: bool = False,
) -> str:
    """Stand-in for HuntManager.start that mirrors just enough of its contract
    to test the route's promotion kwargs end-to-end: it persists a real
    Investigation row via inv_svc.create with exactly the kwargs the route
    passed, instead of running the actual agent loop."""
    async with state.db_sessionmaker() as db:
        inv = await inv_svc.create(
            db,
            alert_es_id=alert_id,
            started_by=started_by,
            rule_name=rule_name,
            kind=kind,
            hunt_id=hunt_id,
            finding_ordinal=finding_ordinal,
        )
        return inv.id


def _fetch_inv(client: TestClient, inv_id: str) -> Investigation | None:
    async def _go() -> Investigation | None:
        async with client.app.state.db_sessionmaker() as db:
            return await db.get(Investigation, inv_id)

    return asyncio.run(_go())


def test_promote_finding_404_unknown_hunt(kind_client: TestClient) -> None:
    resp = kind_client.post("/api/v1/hunts/01HUNTDOESNOTEXIST00000000000/findings/0/investigate")
    assert resp.status_code == 404
    assert resp.json()["detail"]["reason"] == "not_found"


def test_promote_finding_404_ordinal_past_the_end(kind_client: TestClient) -> None:
    hunt_id = _seed_hunt(
        kind_client, findings=[{"title": "F0", "detail": "d", "citations": ["tel-doc-000001"]}]
    )
    resp = kind_client.post(f"/api/v1/hunts/{hunt_id}/findings/5/investigate")
    assert resp.status_code == 404
    assert resp.json()["detail"]["reason"] == "finding_not_found"
    assert resp.json()["detail"]["hint"] == "That finding is not in this hunt's report."


def test_promote_finding_negative_ordinal_404s_not_500s(kind_client: TestClient) -> None:
    """FastAPI's `int` path convertor regex (``[0-9]+``) never matches a
    leading '-', so a negative ordinal doesn't even reach the handler — this
    is Starlette's bare route-not-found 404, not the handler's JSON
    {"reason": "finding_not_found"} body. The contract that matters is "404,
    never 500 from Python's negative-index wraparound", which this proves."""
    hunt_id = _seed_hunt(
        kind_client, findings=[{"title": "F0", "detail": "d", "citations": ["tel-doc-000001"]}]
    )
    resp = kind_client.post(f"/api/v1/hunts/{hunt_id}/findings/-1/investigate")
    assert resp.status_code == 404


def test_promote_finding_409_still_running(kind_client: TestClient) -> None:
    hunt_id = _seed_hunt(kind_client, status="running")
    resp = kind_client.post(f"/api/v1/hunts/{hunt_id}/findings/0/investigate")
    assert resp.status_code == 409
    assert resp.json()["detail"]["reason"] == "still_running"
    assert (
        resp.json()["detail"]["hint"]
        == "The hunt is still running. Findings promote after it lands its report."
    )


def test_promote_finding_422_when_no_citation_resolves(kind_client: TestClient) -> None:
    hunt_id = _seed_hunt(
        kind_client,
        findings=[
            {
                "title": "Beaconing to rare external IP",
                "detail": "10.0.0.5 -> 203.0.113.9 on a fixed cadence.",
                "hosts": ["10.0.0.5"],
                "citations": ["tel-doc-missing0"],
            }
        ],
    )
    with patch.object(
        ElasticClient,
        "search",
        AsyncMock(return_value=EsSearchResult(total=0, took_ms=1, hits=[])),
    ):
        resp = kind_client.post(f"/api/v1/hunts/{hunt_id}/findings/0/investigate")
    assert resp.status_code == 422
    assert resp.json()["detail"]["reason"] == "no_promotable_evidence"


def test_promote_finding_happy_path_prefers_telemetry_anchor(kind_client: TestClient) -> None:
    hunt_id = _seed_hunt(
        kind_client,
        findings=[
            {
                "title": "Beaconing to rare external IP",
                "detail": "10.0.0.5 -> 203.0.113.9 on a fixed cadence.",
                "hosts": ["10.0.0.5"],
                "citations": ["det-doc-000001", "tel-doc-000001"],
            }
        ],
    )
    fake_mgr = AsyncMock()
    fake_mgr.start = _fake_start_creates_row
    search_result = EsSearchResult(
        total=2,
        took_ms=1,
        hits=[
            {"_id": "det-doc-000001", "_source": {"event": {"dataset": "suricata.alert"}}},
            {"_id": "tel-doc-000001", "_source": {"event": {"dataset": "zeek.conn"}}},
        ],
    )
    with (
        patch(_MGR_TARGET, return_value=fake_mgr),
        patch.object(ElasticClient, "search", AsyncMock(return_value=search_result)),
    ):
        resp = kind_client.post(f"/api/v1/hunts/{hunt_id}/findings/0/investigate")

    assert resp.status_code == 200
    inv_id = resp.json()["investigation_id"]
    inv = _fetch_inv(kind_client, inv_id)
    assert inv is not None
    assert inv.alert_es_id == "tel-doc-000001"
    assert inv.kind == "hunt"
    assert inv.hunt_id == hunt_id
    assert inv.finding_ordinal == 0
    assert inv.rule_name == "Beaconing to rare external IP"


def test_promote_finding_focus_hint_names_the_finding(kind_client: TestClient) -> None:
    """The focus_hint threaded into HuntManager.start is the finding->prompt
    bridge for the spawned investigation — pin that it actually carries the
    finding's title and hosts, not just that it exists."""
    hunt_id = _seed_hunt(
        kind_client,
        findings=[
            {
                "title": "Beaconing to rare external IP",
                "detail": "10.0.0.5 -> 203.0.113.9 on a fixed cadence.",
                "hosts": ["10.0.0.5"],
                "citations": ["tel-doc-000001"],
            }
        ],
    )
    fake_mgr = AsyncMock()
    fake_mgr.start = AsyncMock(return_value="INV-FOCUS")
    search_result = EsSearchResult(
        total=1,
        took_ms=1,
        hits=[{"_id": "tel-doc-000001", "_source": {"event": {"dataset": "zeek.conn"}}}],
    )
    with (
        patch(_MGR_TARGET, return_value=fake_mgr),
        patch.object(ElasticClient, "search", AsyncMock(return_value=search_result)),
    ):
        resp = kind_client.post(f"/api/v1/hunts/{hunt_id}/findings/0/investigate")

    assert resp.status_code == 200
    focus_hint = fake_mgr.start.call_args.kwargs["focus_hint"]
    assert focus_hint.startswith("Promoted hunt finding: ")
    assert "Beaconing to rare external IP" in focus_hint
    assert "10.0.0.5" in focus_hint
    # Task 6: the route's own start() call carries both SO-write suppression
    # and the honest-header origin explicitly — a promoted finding's anchor
    # has nothing in SO to ack, and its focus text is the finding's framing,
    # not a prior run's open questions.
    assert fake_mgr.start.call_args.kwargs["allow_so_writes"] is False
    assert fake_mgr.start.call_args.kwargs["focus_origin"] == "hunt_finding"


def test_promote_finding_detector_only_still_promotable(kind_client: TestClient) -> None:
    """No cited telemetry doc — only a detector's own alert. Still resolves an
    anchor (the detector doc itself), not a 422: the promoted investigation
    re-examines the detector's claim rather than refusing outright."""
    hunt_id = _seed_hunt(
        kind_client,
        findings=[
            {
                "title": "ET SCAN Suspicious",
                "detail": "Sigma rule fired on a rare parent/child pair.",
                "hosts": ["10.0.0.9"],
                "citations": ["det-doc-000002"],
            }
        ],
    )
    fake_mgr = AsyncMock()
    fake_mgr.start = _fake_start_creates_row
    search_result = EsSearchResult(
        total=1,
        took_ms=1,
        hits=[{"_id": "det-doc-000002", "_source": {"event": {"dataset": "sigma.alert"}}}],
    )
    with (
        patch(_MGR_TARGET, return_value=fake_mgr),
        patch.object(ElasticClient, "search", AsyncMock(return_value=search_result)),
    ):
        resp = kind_client.post(f"/api/v1/hunts/{hunt_id}/findings/0/investigate")

    assert resp.status_code == 200
    inv = _fetch_inv(kind_client, resp.json()["investigation_id"])
    assert inv is not None
    assert inv.alert_es_id == "det-doc-000002"


def test_promote_finding_skips_prose_citations(kind_client: TestClient) -> None:
    """A prose citation ('the beacon interval was 60s') can't be an ES id — it
    must never reach the `ids` query, and it must not break resolution of the
    real citation alongside it."""
    hunt_id = _seed_hunt(
        kind_client,
        findings=[
            {
                "title": "Beaconing to rare external IP",
                "detail": "10.0.0.5 -> 203.0.113.9 on a fixed cadence.",
                "hosts": ["10.0.0.5"],
                "citations": ["the beacon interval was 60s", "tel-doc-000001"],
            }
        ],
    )
    fake_mgr = AsyncMock()
    fake_mgr.start = _fake_start_creates_row
    search_mock = AsyncMock(
        return_value=EsSearchResult(
            total=1,
            took_ms=1,
            hits=[{"_id": "tel-doc-000001", "_source": {"event": {"dataset": "zeek.conn"}}}],
        )
    )
    with (
        patch(_MGR_TARGET, return_value=fake_mgr),
        patch.object(ElasticClient, "search", search_mock),
    ):
        resp = kind_client.post(f"/api/v1/hunts/{hunt_id}/findings/0/investigate")

    assert resp.status_code == 200
    # the prose string never made it into the `ids` query.
    assert search_mock.call_args.args[1] == {"ids": {"values": ["tel-doc-000001"]}}
    inv = _fetch_inv(kind_client, resp.json()["investigation_id"])
    assert inv is not None
    assert inv.alert_es_id == "tel-doc-000001"


def test_promote_finding_tolerates_non_str_citations(kind_client: TestClient) -> None:
    """The stored report's citations list isn't schema-enforced — a stray int
    or None (a legacy or partially-written report) must not TypeError the
    ID-shape regex match. Anchor resolution still finds the one real citation
    alongside them."""
    hunt_id = _seed_hunt(
        kind_client,
        findings=[
            {
                "title": "Beaconing to rare external IP",
                "detail": "d",
                "hosts": [],
                "citations": ["tel-doc-000001", 42, None],
            }
        ],
    )
    fake_mgr = AsyncMock()
    fake_mgr.start = _fake_start_creates_row
    search_result = EsSearchResult(
        total=1,
        took_ms=1,
        hits=[{"_id": "tel-doc-000001", "_source": {"event": {"dataset": "zeek.conn"}}}],
    )
    with (
        patch(_MGR_TARGET, return_value=fake_mgr),
        patch.object(ElasticClient, "search", AsyncMock(return_value=search_result)),
    ):
        resp = kind_client.post(f"/api/v1/hunts/{hunt_id}/findings/0/investigate")

    assert resp.status_code == 200
    inv = _fetch_inv(kind_client, resp.json()["investigation_id"])
    assert inv is not None
    assert inv.alert_es_id == "tel-doc-000001"


def test_promote_finding_403_in_demo_mode(settings_kratos: Settings) -> None:
    """Not in main.py's _DEMO_WRITE_ALLOW*, so the demo read-only middleware
    refuses it with the same structured 403 every other unlisted mutating
    route gets — before the handler (and any ES/manager call) ever runs."""
    demo_settings = settings_kratos.model_copy(
        update={"soc_ai_demo": True, "es_hosts": ["http://127.0.0.1:9200"]}
    )
    resp = None
    for client in _client(demo_settings):
        resp = client.post("/api/v1/hunts/some-hunt-id/findings/0/investigate")
    assert resp is not None
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == "demo_mode"


def test_promote_finding_idempotent_while_promotion_running(kind_client: TestClient) -> None:
    hunt_id = _seed_hunt(
        kind_client,
        findings=[
            {
                "title": "Beaconing to rare external IP",
                "detail": "d",
                "hosts": [],
                "citations": ["tel-doc-000001"],
            }
        ],
    )

    async def _seed_running() -> str:
        async with kind_client.app.state.db_sessionmaker() as db:
            inv = await inv_svc.create(
                db,
                alert_es_id="tel-doc-000001",
                started_by="admin",
                kind="hunt",
                hunt_id=hunt_id,
                finding_ordinal=0,
            )
            return inv.id

    running_id = asyncio.run(_seed_running())

    fake_mgr = AsyncMock()
    with patch(_MGR_TARGET, return_value=fake_mgr):
        resp = kind_client.post(f"/api/v1/hunts/{hunt_id}/findings/0/investigate")

    assert resp.status_code == 200
    assert resp.json() == {"investigation_id": running_id, "existing": True}
    fake_mgr.start.assert_not_called()


def test_promote_finding_idempotent_after_complete(kind_client: TestClient) -> None:
    hunt_id = _seed_hunt(
        kind_client,
        findings=[
            {
                "title": "Beaconing to rare external IP",
                "detail": "d",
                "hosts": [],
                "citations": ["tel-doc-000001"],
            }
        ],
    )

    async def _seed_complete() -> str:
        async with kind_client.app.state.db_sessionmaker() as db:
            inv = await inv_svc.create(
                db,
                alert_es_id="tel-doc-000001",
                started_by="admin",
                kind="hunt",
                hunt_id=hunt_id,
                finding_ordinal=0,
            )
            await inv_svc.finalize(db, inv.id, status="complete", verdict="true_positive")
            return inv.id

    complete_id = asyncio.run(_seed_complete())

    fake_mgr = AsyncMock()
    with patch(_MGR_TARGET, return_value=fake_mgr):
        resp = kind_client.post(f"/api/v1/hunts/{hunt_id}/findings/0/investigate")

    assert resp.status_code == 200
    assert resp.json() == {"investigation_id": complete_id, "existing": True}
    fake_mgr.start.assert_not_called()


def test_promote_finding_respawns_after_errored_promotion(kind_client: TestClient) -> None:
    hunt_id = _seed_hunt(
        kind_client,
        findings=[
            {
                "title": "Beaconing to rare external IP",
                "detail": "d",
                "hosts": [],
                "citations": ["tel-doc-000001"],
            }
        ],
    )

    async def _seed_errored() -> str:
        async with kind_client.app.state.db_sessionmaker() as db:
            inv = await inv_svc.create(
                db,
                alert_es_id="tel-doc-000001",
                started_by="admin",
                kind="hunt",
                hunt_id=hunt_id,
                finding_ordinal=0,
            )
            await inv_svc.finalize(db, inv.id, status="error")
            return inv.id

    errored_id = asyncio.run(_seed_errored())

    fake_mgr = AsyncMock()
    fake_mgr.start = AsyncMock(return_value="NEW-AFTER-ERROR")
    search_result = EsSearchResult(
        total=1,
        took_ms=1,
        hits=[{"_id": "tel-doc-000001", "_source": {"event": {"dataset": "zeek.conn"}}}],
    )
    with (
        patch(_MGR_TARGET, return_value=fake_mgr),
        patch.object(ElasticClient, "search", AsyncMock(return_value=search_result)),
    ):
        resp = kind_client.post(f"/api/v1/hunts/{hunt_id}/findings/0/investigate")

    assert resp.status_code == 200
    body = resp.json()
    assert body["investigation_id"] == "NEW-AFTER-ERROR"
    assert "existing" not in body
    fake_mgr.start.assert_called_once()
    assert fake_mgr.start.call_args.kwargs["hunt_id"] == hunt_id
    assert fake_mgr.start.call_args.kwargs["finding_ordinal"] == 0
    assert fake_mgr.start.call_args.kwargs["kind"] == "hunt"
    assert errored_id != "NEW-AFTER-ERROR"


# ── Task 6: SO-write suppression for hunt-kind investigations ─────────────
#
# A promoted finding's alert_es_id names a cited TELEMETRY document, not an SO
# alert — there is nothing in Security Onion to ack/escalate. Three
# suppression points: the execute route refuses the write outright (below),
# the orchestrator's opt-in auto-ack is gated off before it can fire (see
# tests/test_autotriage.py::TestMaybeAutoAckFpGated), and the seed prompt's
# focus header never falsely claims a prior investigation exists (see
# tests/test_agent.py's format_focus_hint_block origin tests).


async def _seed_action_inv(
    client: TestClient,
    *,
    kind: str = "suricata",
    alert_es_id: str = "es-anchor-000001",
    rule_name: str | None = None,
) -> str:
    """Seed a completed investigation carrying one ack_alert recommended
    action. ``rule_name`` defaults to None so the ack takes the simple
    single-alert path (mirrors tests/test_webui_api.py's
    test_execute_action_acks_and_defaults_alert_id) rather than the
    rule-keyed group-ack branch, which this suite doesn't need to exercise."""
    async with client.app.state.db_sessionmaker() as db:
        inv = await inv_svc.create(
            db, alert_es_id=alert_es_id, started_by="admin", rule_name=rule_name, kind=kind
        )
        inv.report = {"recommended_actions": [{"tool_name": "ack_alert", "tool_args": {}}]}
        await db.commit()
        return inv.id


def test_execute_action_refuses_hunt_kind_write(kind_client: TestClient) -> None:
    """A hunt-kind investigation's anchor is cited telemetry, not an SO
    alert — the execute route must refuse the write outright, BEFORE target
    binding, so the rule-keyed group ack can never see a finding title
    mistaken for a rule_name."""
    inv_id = asyncio.run(_seed_action_inv(kind_client, kind="hunt"))
    resp = kind_client.post(f"/api/v1/investigations/{inv_id}/actions/0/execute")
    assert resp.status_code == 400
    assert resp.json()["detail"]["reason"] == "hunt_kind_no_so_target"


def test_execute_action_suricata_kind_still_executes(kind_client: TestClient) -> None:
    """Control: an identical action on a plain suricata-kind investigation
    still reaches the normal write path — the guard is kind-scoped, not a
    blanket regression on every execute call."""
    from soc_ai.tools._registry import ToolSpec

    inv_id = asyncio.run(_seed_action_inv(kind_client, kind="suricata"))

    async def fn(alert_id: str, comment: str | None = None, *, auth, settings=None) -> dict:
        return {"acknowledged": True}

    tool = ToolSpec(name="ack_alert", read_only=False, description="", func=fn)
    with patch("soc_ai.tools.write_exec.get_tool", return_value=tool):
        resp = kind_client.post(f"/api/v1/investigations/{inv_id}/actions/0/execute")
    assert resp.status_code == 200
    assert resp.json()["status"] == "executed"


def test_run_recorded_and_investigate_default_focus_origin_to_rerun() -> None:
    """Every existing caller of run_recorded/investigate omits the new
    keyword-only params entirely — they must default to the pre-Task-6
    behavior (write-capable, rerun-worded focus header), never silently
    change for callers that don't know about promotion."""
    import inspect

    from soc_ai.agent.orchestrator import investigate

    for fn in (run_recorded, investigate):
        params = inspect.signature(fn).parameters
        assert params["allow_so_writes"].default is True
        assert params["focus_origin"].default == "rerun"


# ── Task 6b: close the relaunch loophole (bulk re-hunt + request-more-info) ──
#
# Bulk re-hunt and request-more-info are two ordinary UI buttons that relaunch
# investigations WITHOUT reading inv.kind — pushed through on a hunt-kind row
# either would mint an unlabeled kind="suricata" duplicate targeting the
# anchor telemetry doc, carrying the finding title as rule_name (the exact
# string Task 6's group-ack guard exists to keep out). Both must refuse.

_REHUNT_MGR_TARGET = "soc_ai.api.webui.routes_investigations.hunt_manager.get_manager"


def test_bulk_rehunt_skips_hunt_kind_but_proceeds_for_suricata_kind(
    kind_client: TestClient,
) -> None:
    async def _seed() -> tuple[str, str]:
        maker = kind_client.app.state.db_sessionmaker
        async with maker() as db:
            hunt_row = await hunt_svc.create(db, objective=_LONG_OBJECTIVE, started_by="admin")
            promoted = await inv_svc.create(
                db,
                alert_es_id="tel-doc-000001",
                started_by="admin",
                rule_name="Beaconing to rare external IP",
                kind="hunt",
                hunt_id=hunt_row.id,
                finding_ordinal=0,
            )
            await inv_svc.finalize(db, promoted.id, status="complete", verdict="true_positive")
            plain = await inv_svc.create(
                db, alert_es_id="ev-rh-plain", started_by="admin", rule_name="ET SCAN Suspicious"
            )
            await inv_svc.finalize(db, plain.id, status="complete", verdict="false_positive")
            return promoted.id, plain.id

    hunt_kind_id, plain_id = asyncio.run(_seed())

    async def fake_start(
        _state, *, alert_id: str, started_by: str, rule_name: str | None = None
    ) -> str:
        return "NEW-PLAIN"

    fake_mgr = AsyncMock()
    fake_mgr.start = fake_start

    with patch(_REHUNT_MGR_TARGET, return_value=fake_mgr):
        resp = kind_client.post(
            "/api/v1/investigations/rehunt", json={"inv_ids": [hunt_kind_id, plain_id]}
        )

    assert resp.status_code == 200
    body = resp.json()
    skipped = {s["invId"]: s["reason"] for s in body["skipped"]}
    assert skipped[hunt_kind_id] == "hunt_kind"
    started = {s["invId"]: s for s in body["started"]}
    assert started[plain_id]["newInvId"] == "NEW-PLAIN"
    assert started[plain_id]["alertEsId"] == "ev-rh-plain"


def test_request_more_info_refuses_hunt_kind_row(kind_client: TestClient) -> None:
    async def _seed() -> str:
        maker = kind_client.app.state.db_sessionmaker
        async with maker() as db:
            hunt_row = await hunt_svc.create(db, objective=_LONG_OBJECTIVE, started_by="admin")
            promoted = await inv_svc.create(
                db,
                alert_es_id="tel-doc-000001",
                started_by="admin",
                rule_name="Beaconing to rare external IP",
                kind="hunt",
                hunt_id=hunt_row.id,
                finding_ordinal=0,
            )
            # needs_more_info is exactly the verdict this route exists to
            # relaunch — the kind guard must still block it before that check.
            await inv_svc.finalize(db, promoted.id, status="complete", verdict="needs_more_info")
            return promoted.id

    inv_id = asyncio.run(_seed())

    fake_mgr = AsyncMock()
    fake_mgr.start = AsyncMock(return_value="SHOULD-NOT-START")

    with patch(_REHUNT_MGR_TARGET, return_value=fake_mgr):
        resp = kind_client.post(f"/api/v1/investigations/{inv_id}/request-more-info")

    assert resp.status_code == 409
    body = resp.json()["detail"]
    assert body["reason"] == "hunt_kind_no_rerun"
    assert body["hint"] == "Re-promote the finding from its hunt instead."
    fake_mgr.start.assert_not_called()


def test_request_more_info_suricata_kind_control_gets_past_kind_check(
    kind_client: TestClient,
) -> None:
    """Control: an ordinary suricata-kind needs_more_info row is NOT caught by
    the new kind guard — it reaches the real happy path (200, a new
    investigation id) exactly like the pre-Task-6b behavior."""

    async def _seed() -> str:
        maker = kind_client.app.state.db_sessionmaker
        async with maker() as db:
            inv = await inv_svc.create(
                db, alert_es_id="ev-rmi-control", started_by="admin", rule_name="ET NMI control"
            )
            await inv_svc.finalize(db, inv.id, status="complete", verdict="needs_more_info")
            return inv.id

    inv_id = asyncio.run(_seed())

    fake_mgr = AsyncMock()
    fake_mgr.start = AsyncMock(return_value="NEW-CONTROL")

    with patch(_REHUNT_MGR_TARGET, return_value=fake_mgr):
        resp = kind_client.post(f"/api/v1/investigations/{inv_id}/request-more-info")

    assert resp.status_code == 200
    assert resp.json()["investigation_id"] == "NEW-CONTROL"
    fake_mgr.start.assert_called_once()


# ── Quality review: manager forces allow_so_writes (single source of truth) ──


def test_hunt_manager_forces_allow_so_writes_false_for_hunt_kind() -> None:
    """HuntManager.start(kind="hunt") must force allow_so_writes=False onto
    run_recorded EVEN WHEN the caller omits the kwarg entirely (its default is
    True) — the route's explicit allow_so_writes=False is documentation, not
    the only thing standing between a hunt-kind run and an unattended ack. A
    future kind="hunt" caller that forgets the kwarg must not reopen the hole."""
    from unittest.mock import patch

    from soc_ai.webui import hunt_manager as hm

    captured: dict[str, Any] = {}

    async def fake_run_recorded(state: Any, **kwargs: Any):
        captured.update(kwargs)
        yield "investigation_created", {"investigation_id": "INV-HUNT"}

    async def run() -> str | None:
        with (
            patch.object(hm, "run_recorded", fake_run_recorded),
            patch.object(hm, "ctx_from_state", lambda _s: object()),
        ):
            mgr = hm.HuntManager()
            inv_id = await mgr.start(
                object(),
                alert_id="tel-doc-000001",
                started_by="tester",
                kind="hunt",
                hunt_id="01HUNTFORCED0000000000000000",
                finding_ordinal=0,
                # allow_so_writes deliberately OMITTED — defaults to True.
            )
            await asyncio.sleep(0)  # let the drain task settle
            return inv_id

    inv_id = asyncio.run(run())
    assert inv_id == "INV-HUNT"
    assert captured["allow_so_writes"] is False


def test_hunt_manager_leaves_allow_so_writes_true_for_non_hunt_kind() -> None:
    """Control: an ordinary (default kind="suricata") caller is unaffected by
    the force — allow_so_writes passes through exactly as given."""
    from unittest.mock import patch

    from soc_ai.webui import hunt_manager as hm

    captured: dict[str, Any] = {}

    async def fake_run_recorded(state: Any, **kwargs: Any):
        captured.update(kwargs)
        yield "investigation_created", {"investigation_id": "INV-PLAIN"}

    async def run() -> str | None:
        with (
            patch.object(hm, "run_recorded", fake_run_recorded),
            patch.object(hm, "ctx_from_state", lambda _s: object()),
        ):
            mgr = hm.HuntManager()
            inv_id = await mgr.start(object(), alert_id="ev-plain", started_by="tester")
            await asyncio.sleep(0)
            return inv_id

    inv_id = asyncio.run(run())
    assert inv_id == "INV-PLAIN"
    assert captured["allow_so_writes"] is True


# ── Spec-review follow-up: POST /hunt refuses to re-run a promoted finding's ──
# ── anchor once promotion owns its latest investigation row ──────────────────
#
# The Task 9 UI gates (toolbar Re-run, failedEl, the pipeline-fallback panel)
# hide the button for kind='hunt' — but an ad-hoc POST /hunt against the same
# alert_id (the anchor event) reached the ordinary duplicate-guard path
# unchanged, which only checked `status == "running"`. That would mint an
# unlabeled kind='suricata' duplicate and re-enable SO writes on an event a
# promoted finding already claims. Mirrors bulk_rehunt/request_more_info
# (Task 6b, commit 4fbe8132), but keyed on the ALERT's latest row rather than
# the investigation being relaunched — start_hunt has no inv id, only alert_id.

_START_HUNT_RESOLVE_TARGET = "soc_ai.api.webui.routes_hunts.resolve_alert_for_hunt"
_START_HUNT_MGR_TARGET = "soc_ai.api.webui.routes_hunts.hunt_manager.get_manager"


def test_start_hunt_refuses_when_latest_investigation_for_alert_is_hunt_kind(
    kind_client: TestClient,
) -> None:
    async def _seed() -> str:
        maker = kind_client.app.state.db_sessionmaker
        async with maker() as db:
            hunt_row = await hunt_svc.create(db, objective=_LONG_OBJECTIVE, started_by="admin")
            promoted = await inv_svc.create(
                db,
                alert_es_id="tel-doc-000001",
                started_by="admin",
                rule_name="Beaconing to rare external IP",
                kind="hunt",
                hunt_id=hunt_row.id,
                finding_ordinal=0,
            )
            await inv_svc.finalize(db, promoted.id, status="complete", verdict="true_positive")
            return promoted.id

    asyncio.run(_seed())

    fake_mgr = AsyncMock()
    fake_mgr.start = AsyncMock(return_value="SHOULD-NOT-START")

    with (
        patch(_START_HUNT_RESOLVE_TARGET, AsyncMock(return_value=(True, "some rule"))),
        patch(_START_HUNT_MGR_TARGET, return_value=fake_mgr),
    ):
        resp = kind_client.post("/api/v1/hunt", json={"alert_id": "tel-doc-000001"})

    assert resp.status_code == 409
    body = resp.json()["detail"]
    assert body["reason"] == "hunt_kind_no_rerun"
    assert body["hint"] == (
        "This event is a promoted finding's anchor. Re-promote the finding from its hunt."
    )
    # The blocked row is already settled (complete) — no running deep-link to carry.
    assert "running_inv_id" not in body
    fake_mgr.start.assert_not_called()


def test_start_hunt_hunt_kind_409_includes_running_inv_id_when_running(
    kind_client: TestClient,
) -> None:
    """When the hunt-kind guard fires against a row that is itself still
    running, the 409 carries running_inv_id — the deep-link the old
    hunt_in_progress branch offered — so a caller that only checks for the
    field doesn't lose it to the hunt_kind guard firing first."""

    async def _seed() -> str:
        maker = kind_client.app.state.db_sessionmaker
        async with maker() as db:
            hunt_row = await hunt_svc.create(db, objective=_LONG_OBJECTIVE, started_by="admin")
            promoted = await inv_svc.create(
                db,
                alert_es_id="tel-doc-000002",
                started_by="admin",
                rule_name="Beaconing to rare external IP",
                kind="hunt",
                hunt_id=hunt_row.id,
                finding_ordinal=0,
            )
            # Left running (no finalize) — Investigation.status defaults to "running".
            return promoted.id

    promoted_id = asyncio.run(_seed())

    fake_mgr = AsyncMock()
    fake_mgr.start = AsyncMock(return_value="SHOULD-NOT-START")

    with (
        patch(_START_HUNT_RESOLVE_TARGET, AsyncMock(return_value=(True, "some rule"))),
        patch(_START_HUNT_MGR_TARGET, return_value=fake_mgr),
    ):
        resp = kind_client.post("/api/v1/hunt", json={"alert_id": "tel-doc-000002"})

    assert resp.status_code == 409
    body = resp.json()["detail"]
    assert body["reason"] == "hunt_kind_no_rerun"
    assert body["running_inv_id"] == promoted_id
    fake_mgr.start.assert_not_called()


# ── Slice 1 follow-up: finding cards show their promotion state ──────────────
#
# GET /hunts/{hunt_id} now reports each finding's newest promoted investigation
# (id/status/verdict/conf) so the hunt page can render Investigate / Investigating…
# / Open+verdict instead of always offering a doomed re-promote.


async def test_latest_per_finding_returns_newest_per_ordinal_and_skips_null(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        hunt_id = "01HUNTLPF0000000000000000000"
        older = await inv_svc.create(
            db, alert_es_id="a1", started_by="x", kind="hunt", hunt_id=hunt_id, finding_ordinal=0
        )
        newer = await inv_svc.create(
            db, alert_es_id="a2", started_by="x", kind="hunt", hunt_id=hunt_id, finding_ordinal=0
        )
        other_ordinal = await inv_svc.create(
            db, alert_es_id="a3", started_by="x", kind="hunt", hunt_id=hunt_id, finding_ordinal=1
        )
        # A row for the same hunt with no ordinal (not a promotion) — must
        # never surface in the map.
        await inv_svc.create(
            db,
            alert_es_id="a4",
            started_by="x",
            kind="hunt",
            hunt_id=hunt_id,
            finding_ordinal=None,
        )
        # A row for a DIFFERENT hunt — must never leak into this hunt's map.
        await inv_svc.create(
            db,
            alert_es_id="a5",
            started_by="x",
            kind="hunt",
            hunt_id="01HUNTOTHER00000000000000000",
            finding_ordinal=0,
        )
        out = await inv_svc.latest_per_finding(db, hunt_id)
        assert set(out.keys()) == {0, 1}
        assert out[0].id == newer.id
        assert out[0].id != older.id
        assert out[1].id == other_ordinal.id
    await engine.dispose()


async def test_latest_per_finding_empty_when_no_promotions(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        out = await inv_svc.latest_per_finding(db, "01HUNTNOPROMOTIONS00000000000")
        assert out == {}
    await engine.dispose()


async def test_latest_per_finding_is_column_scoped(settings_kratos: Settings) -> None:
    """The hunt detail is polled by the SPA and its per-finding card reads four
    scalars, so this lookup must not pull each promotion's report/summary blob
    through the session on every tick. The card's columns come back populated;
    the blob columns are never loaded (access raises instead of lazy-loading)."""
    engine, maker = await _db(settings_kratos)
    hunt_id = "01HUNTLIGHT00000000000000000"
    async with maker() as db:
        inv = await inv_svc.create(
            db,
            alert_es_id="a1",
            started_by="x",
            rule_name="F0 promoted",
            kind="hunt",
            hunt_id=hunt_id,
            finding_ordinal=0,
        )
        await inv_svc.finalize(
            db,
            inv.id,
            status="complete",
            verdict="true_positive",
            confidence=0.8,
            summary="a summary the card never renders",
            report={"findings": ["x" * 4096]},
        )
        inv_id = inv.id
    # A FRESH session: the seeding session's identity map already holds the
    # fully-loaded row, which would mask the column scoping.
    async with maker() as db:
        out = await inv_svc.latest_per_finding(db, hunt_id)
        got = out[0]
        assert (got.id, got.status, got.verdict) == (inv_id, "complete", "true_positive")
        assert got.confidence == pytest.approx(0.8)
        assert got.finding_ordinal == 0
        with pytest.raises(InvalidRequestError):
            _ = got.report
        with pytest.raises(InvalidRequestError):
            _ = got.summary
    await engine.dispose()


def test_get_hunt_detail_reports_promotion_state_per_finding(kind_client: TestClient) -> None:
    findings = [
        {"title": "F0 unpromoted", "detail": "d0", "citations": ["tel-doc-000001"]},
        {"title": "F1 promoted", "detail": "d1", "citations": ["tel-doc-000002"]},
    ]
    hunt_id = _seed_hunt(kind_client, findings=findings)

    async def _promote() -> str:
        async with kind_client.app.state.db_sessionmaker() as db:
            inv = await inv_svc.create(
                db,
                alert_es_id="tel-doc-000002",
                started_by="admin",
                rule_name="F1 promoted",
                kind="hunt",
                hunt_id=hunt_id,
                finding_ordinal=1,
            )
            await inv_svc.finalize(
                db, inv.id, status="complete", verdict="false_positive", confidence=0.72
            )
            return inv.id

    inv_id = asyncio.run(_promote())

    resp = kind_client.get(f"/api/v1/hunts/{hunt_id}")
    assert resp.status_code == 200
    body = resp.json()
    findings_out = body["findings"]
    assert findings_out[0]["investigation"] is None
    assert findings_out[1]["investigation"] == {
        "id": inv_id,
        "status": "complete",
        "verdict": "false_positive",
        "conf": 0.72,
    }


def test_get_hunt_detail_errored_promotion_reports_error_status_honestly(
    kind_client: TestClient,
) -> None:
    """An errored/cancelled promotion frees the re-promote slot (blocks_rehunt),
    but GET /hunts/{id} still reports its true terminal status — the UI, not the
    API, decides to re-offer Investigate."""
    findings = [{"title": "F0", "detail": "d0", "citations": ["tel-doc-000001"]}]
    hunt_id = _seed_hunt(kind_client, findings=findings)

    async def _promote_error() -> str:
        async with kind_client.app.state.db_sessionmaker() as db:
            inv = await inv_svc.create(
                db,
                alert_es_id="tel-doc-000001",
                started_by="admin",
                kind="hunt",
                hunt_id=hunt_id,
                finding_ordinal=0,
            )
            await inv_svc.finalize(db, inv.id, status="error")
            return inv.id

    inv_id = asyncio.run(_promote_error())

    resp = kind_client.get(f"/api/v1/hunts/{hunt_id}")
    assert resp.status_code == 200
    finding0 = resp.json()["findings"][0]
    assert finding0["investigation"] == {
        "id": inv_id,
        "status": "error",
        "verdict": None,
        "conf": None,
    }


def test_get_hunt_detail_running_promotion_reports_running_status(
    kind_client: TestClient,
) -> None:
    findings = [{"title": "F0", "detail": "d0", "citations": ["tel-doc-000001"]}]
    hunt_id = _seed_hunt(kind_client, findings=findings)

    async def _promote_running() -> str:
        async with kind_client.app.state.db_sessionmaker() as db:
            inv = await inv_svc.create(
                db,
                alert_es_id="tel-doc-000001",
                started_by="admin",
                kind="hunt",
                hunt_id=hunt_id,
                finding_ordinal=0,
            )
            return inv.id  # left running — no finalize

    inv_id = asyncio.run(_promote_running())

    resp = kind_client.get(f"/api/v1/hunts/{hunt_id}")
    assert resp.status_code == 200
    finding0 = resp.json()["findings"][0]
    assert finding0["investigation"]["id"] == inv_id
    assert finding0["investigation"]["status"] == "running"
    assert finding0["investigation"]["verdict"] is None


def test_start_hunt_still_starts_for_an_alert_promotion_never_touched(
    kind_client: TestClient,
) -> None:
    """Control: an alert_id with no investigation at all (or whose latest row
    is an ordinary suricata-kind run) is unaffected — the guard only fires
    once promotion owns the latest row for that doc."""
    fake_mgr = AsyncMock()
    fake_mgr.start = AsyncMock(return_value="NEW-PLAIN")

    with (
        patch(_START_HUNT_RESOLVE_TARGET, AsyncMock(return_value=(True, "ET SCAN Suspicious"))),
        patch(_START_HUNT_MGR_TARGET, return_value=fake_mgr),
    ):
        resp = kind_client.post("/api/v1/hunt", json={"alert_id": "ev-never-promoted"})

    assert resp.status_code == 200
    assert resp.json()["investigation_id"] == "NEW-PLAIN"
    fake_mgr.start.assert_called_once()
