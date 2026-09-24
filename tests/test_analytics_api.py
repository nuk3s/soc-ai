"""The analytics routes and the shadow-hit list."""

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

from tests.test_analytics_store import SPEC_TEXT

_LOCAL = "local-svc-ticket-from-workstation"
_SHIPPED = "identity-4662-dcsync-nonmachine"
_RETIRABLE = "prior-hypervisor-novel-served-port"


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


def test_list_carries_both_tiers_with_status(client: TestClient) -> None:
    res = client.post("/api/v1/analytics", json={"spec_text": SPEC_TEXT})
    assert res.status_code == 201, res.text
    body = client.get("/api/v1/analytics").json()
    by_id = {a["id"]: a for a in body["analytics"]}
    assert by_id[_SHIPPED]["tier"] == "shipped"
    assert by_id[_SHIPPED]["status"] == "live"
    assert by_id[_LOCAL]["tier"] == "local"
    assert by_id[_LOCAL]["status"] == "candidate"
    assert body["counts"]["live"] >= 12 and body["counts"]["candidate"] == 1


def test_a_candidate_goes_to_shadow_then_live_with_a_reason(client: TestClient) -> None:
    client.post("/api/v1/analytics", json={"spec_text": SPEC_TEXT})
    bad = client.post(f"/api/v1/analytics/{_LOCAL}/status", json={"to": "live", "why": "x"})
    assert bad.status_code == 422
    ok = client.post(f"/api/v1/analytics/{_LOCAL}/status", json={"to": "shadow", "why": "try"})
    assert ok.status_code == 200 and ok.json()["status"] == "shadow"
    live = client.post(
        f"/api/v1/analytics/{_LOCAL}/status", json={"to": "live", "why": "two true hits"}
    )
    assert live.status_code == 200
    detail = client.get(f"/api/v1/analytics/{_LOCAL}").json()
    assert [v["to_status"] for v in detail["versions"]] == ["candidate", "shadow", "live"]
    assert detail["ledger"]["observations"] == 0
    assert detail["spec_text"].startswith("id: local-svc-ticket-from-workstation")


def test_a_bad_spec_is_refused_with_the_reason(client: TestClient) -> None:
    res = client.post("/api/v1/analytics", json={"spec_text": "- nope, not a mapping\n"})
    assert res.status_code == 422
    assert "mapping" in res.json()["detail"]["hint"]


def test_retire_a_shipped_analytic_needs_a_reason_and_is_reversible(client: TestClient) -> None:
    assert (
        client.post(f"/api/v1/analytics/{_RETIRABLE}/status", json={"to": "retired"}).status_code
        == 422
    )
    res = client.post(
        f"/api/v1/analytics/{_RETIRABLE}/status",
        json={"to": "retired", "why": "no hypervisor on this grid"},
    )
    assert res.status_code == 200 and res.json()["status"] == "retired"
    back = client.post(
        f"/api/v1/analytics/{_RETIRABLE}/status", json={"to": "shadow", "why": "reinstate"}
    )
    assert back.status_code == 200 and back.json()["status"] == "shadow"


def test_a_shipped_analytic_can_only_be_retired(client: TestClient) -> None:
    res = client.post(f"/api/v1/analytics/{_SHIPPED}/status", json={"to": "shadow", "why": "x"})
    assert res.status_code == 422
    assert res.json()["detail"]["reason"] == "transition_not_allowed"


def test_an_unknown_analytic_is_a_404(client: TestClient) -> None:
    assert client.get("/api/v1/analytics/no-such-analytic").status_code == 404
    assert (
        client.post("/api/v1/analytics/no-such-analytic/status", json={"to": "shadow"}).status_code
        == 404
    )


def _seed_shadow_hit(client: TestClient, *, complete: bool) -> None:
    # A shadow hit belongs to an analytic in shadow. The list hides a hit whose
    # analytic was approved or retired, so the seed puts the analytic in shadow.
    if _LOCAL not in {a["id"] for a in client.get("/api/v1/analytics").json()["analytics"]}:
        client.post("/api/v1/analytics", json={"spec_text": SPEC_TEXT})
    client.post(f"/api/v1/analytics/{_LOCAL}/status", json={"to": "shadow", "why": "seed"})
    from soc_ai.hunting.leads import content_fingerprint, record_observation
    from soc_ai.hunting.weight import Kind

    receipts: dict[str, object] = {
        "matched_ids": ["d1"],
        "matched_fields": ["event.code"],
        "dry_run": {"window_days": 30, "fires": 2, "entities": ["10.1.2.3"]},
        "overlap": [],
        "baseline": None,
        "complete": True,
        "missing": [],
    }
    if not complete:
        receipts.update({"dry_run": None, "complete": False, "missing": ["dry_run"]})

    async def seed() -> None:
        async with client.app.state.db_sessionmaker() as db:
            await record_observation(
                db,
                entity_kind="host",
                entity_key="10.1.2.3",
                kind=Kind.CATALOG_MATCH,
                spec_id=_LOCAL,
                fingerprint=content_fingerprint(_LOCAL, "10.1.2.3"),
                summary="A Kerberos ticket request names a service account: 10.1.2.3 (3 documents)",
                evidence={"sample_ids": ["d1"], "receipts": receipts},
                source="catalog",
                shadow=True,
                now=datetime(2026, 9, 18, 12, 0, tzinfo=UTC),
            )

    asyncio.run(seed())


def test_shadow_hits_list_and_read_mark(client: TestClient) -> None:
    client.post("/api/v1/analytics", json={"spec_text": SPEC_TEXT})
    _seed_shadow_hit(client, complete=False)
    body = client.get("/api/v1/hunts/shadow-hits").json()
    assert body["unread"] == 1 and len(body["hits"]) == 1
    hit = body["hits"][0]
    assert hit["state"] == "could_not_run" and hit["missing"] == ["dry_run"]
    assert hit["read"] is False
    assert hit["analytic_id"] == _LOCAL
    assert hit["occurrences"] >= 1
    assert "first_seen_at" in hit
    res = client.post(f"/api/v1/hunts/shadow-hits/{hit['id']}/read")
    assert res.status_code == 200
    assert client.get("/api/v1/hunts/shadow-hits").json()["unread"] == 0


def test_a_hit_with_complete_receipts_reads_as_a_hit(client: TestClient) -> None:
    client.post("/api/v1/analytics", json={"spec_text": SPEC_TEXT})
    _seed_shadow_hit(client, complete=True)
    hit = client.get("/api/v1/hunts/shadow-hits").json()["hits"][0]
    assert hit["state"] == "hit" and hit["missing"] == []
    assert hit["receipts"]["dry_run"]["fires"] == 2


def test_a_shadow_hit_with_no_receipts_at_all_could_not_run(client: TestClient) -> None:
    """A hit without a receipts packet is never shown as a hit, and never hidden."""
    from soc_ai.hunting.leads import content_fingerprint, record_observation
    from soc_ai.hunting.weight import Kind

    async def seed() -> None:
        async with client.app.state.db_sessionmaker() as db:
            await record_observation(
                db,
                entity_kind="host",
                entity_key="10.1.2.4",
                kind=Kind.CATALOG_MATCH,
                spec_id="local-no-receipts",
                fingerprint=content_fingerprint("local-no-receipts", "10.1.2.4"),
                evidence={"sample_ids": ["d1"]},
                source="catalog",
                shadow=True,
                now=datetime(2026, 9, 18, 12, 0, tzinfo=UTC),
            )

    asyncio.run(seed())
    hit = client.get("/api/v1/hunts/shadow-hits").json()["hits"][0]
    assert hit["state"] == "could_not_run" and hit["missing"] == ["receipts"]
    assert hit["receipts"] is None


def test_a_live_observation_is_not_a_shadow_hit(client: TestClient) -> None:
    from soc_ai.hunting.leads import content_fingerprint, record_observation
    from soc_ai.hunting.weight import Kind

    async def seed() -> None:
        async with client.app.state.db_sessionmaker() as db:
            await record_observation(
                db,
                entity_kind="host",
                entity_key="10.1.2.5",
                kind=Kind.CATALOG_MATCH,
                spec_id=_SHIPPED,
                fingerprint=content_fingerprint(_SHIPPED, "10.1.2.5"),
                source="catalog",
                now=datetime(2026, 9, 18, 12, 0, tzinfo=UTC),
            )

    asyncio.run(seed())
    body = client.get("/api/v1/hunts/shadow-hits").json()
    assert body["hits"] == [] and body["unread"] == 0
    assert client.post("/api/v1/hunts/shadow-hits/1/read").status_code == 404


def test_the_hunt_catalog_carries_the_tier_and_the_status(client: TestClient) -> None:
    client.post("/api/v1/analytics", json={"spec_text": SPEC_TEXT})
    client.post(f"/api/v1/analytics/{_LOCAL}/status", json={"to": "shadow", "why": "try"})
    client.post(
        f"/api/v1/analytics/{_RETIRABLE}/status", json={"to": "retired", "why": "no hypervisor"}
    )
    specs = {s["id"]: s for s in client.get("/api/v1/hunt-catalog").json()["specs"]}
    assert specs[_SHIPPED]["tier"] == "shipped" and specs[_SHIPPED]["status"] == "live"
    assert specs[_LOCAL]["tier"] == "local" and specs[_LOCAL]["status"] == "shadow"
    assert specs[_RETIRABLE]["status"] == "retired"


# ---------------------------------------------------------------------------
# Every 4xx carries a reason AND a hint
# ---------------------------------------------------------------------------


def _detail(res: Any) -> dict[str, str]:
    body = res.json()["detail"]
    assert isinstance(body, dict), body
    assert body["reason"] and body["hint"].strip(), body
    return body


def test_an_unknown_analytic_names_itself_and_says_where_to_look(client: TestClient) -> None:
    got = client.get("/api/v1/analytics/no-such-analytic")
    assert got.status_code == 404
    assert "no-such-analytic" in _detail(got)["hint"]
    posted = client.post("/api/v1/analytics/no-such-analytic/status", json={"to": "shadow"})
    assert posted.status_code == 404
    assert _detail(posted)["reason"] == "analytic_not_found"


def test_a_retirement_without_a_reason_says_what_is_missing(client: TestClient) -> None:
    res = client.post(f"/api/v1/analytics/{_RETIRABLE}/status", json={"to": "retired"})
    assert res.status_code == 422
    detail = _detail(res)
    assert detail["reason"] == "reason_required"
    assert "reason" in detail["hint"]


def test_a_refused_transition_names_the_allowed_targets(client: TestClient) -> None:
    res = client.post(f"/api/v1/analytics/{_SHIPPED}/status", json={"to": "shadow", "why": "x"})
    assert res.status_code == 422
    detail = _detail(res)
    assert detail["reason"] == "transition_not_allowed"
    # live -> retired is the only allowed move, and the hint has to say so.
    assert "retired" in detail["hint"] and "live" in detail["hint"]


def test_an_unknown_target_status_names_the_four_statuses(client: TestClient) -> None:
    res = client.post(f"/api/v1/analytics/{_SHIPPED}/status", json={"to": "banana", "why": "x"})
    assert res.status_code == 422
    detail = _detail(res)
    assert detail["reason"] == "unknown_status"
    for status in ("candidate", "shadow", "live", "retired"):
        assert status in detail["hint"]


def test_an_unknown_shadow_hit_says_where_the_hits_are(client: TestClient) -> None:
    res = client.post("/api/v1/hunts/shadow-hits/424242/read")
    assert res.status_code == 404
    assert _detail(res)["reason"] == "shadow_hit_not_found"


def test_a_pydantic_rejection_reads_as_one_sentence(client: TestClient) -> None:
    """The body validator's report becomes a reason and a hint, not a list of dicts."""
    res = client.post("/api/v1/analytics", json={"spec_text": "no"})
    assert res.status_code == 422
    detail = _detail(res)
    assert detail["reason"] == "bad_request"
    assert detail["hint"].startswith("spec_text ")
    assert "got 'no'" in detail["hint"]


def test_unparseable_yaml_is_a_422_with_the_parser_message(client: TestClient) -> None:
    """A YAML error is a bad spec, not a 500."""
    res = client.post("/api/v1/analytics", json={"spec_text": "id: [unclosed\ntitle: x\n"})
    assert res.status_code == 422, res.text
    detail = _detail(res)
    assert detail["reason"] == "bad_spec"
    assert "flow sequence" in detail["hint"]


def test_a_missing_shipped_file_is_a_404_not_a_500(client: TestClient, tmp_path: Any) -> None:
    """The catalog lists the analytic and the file is gone. Say which."""
    with patch("soc_ai.api.webui.routes_analytics.CATALOG_DIR", tmp_path):
        res = client.get(f"/api/v1/analytics/{_SHIPPED}")
    assert res.status_code == 404, res.text
    detail = _detail(res)
    assert detail["reason"] == "spec_file_missing"
    assert _SHIPPED in detail["hint"]


def test_an_approval_with_no_receipts_is_allowed_and_says_so(client: TestClient) -> None:
    """A shadow analytic that never fired can still go live. The version row is honest."""
    client.post("/api/v1/analytics", json={"spec_text": SPEC_TEXT})
    client.post(f"/api/v1/analytics/{_LOCAL}/status", json={"to": "shadow", "why": "try"})
    live = client.post(f"/api/v1/analytics/{_LOCAL}/status", json={"to": "live", "why": "quiet"})
    assert live.status_code == 200 and live.json()["status"] == "live"
    versions = client.get(f"/api/v1/analytics/{_LOCAL}").json()["versions"]
    approval = next(v for v in versions if v["to_status"] == "live")
    assert approval["has_receipts"] is False


def test_the_list_reads_the_ledgers_in_one_call_when_the_store_offers_one(
    client: TestClient,
) -> None:
    from soc_ai.hunting import ledger as ledger_module

    calls: list[int] = []

    async def _bulk(db: Any, analytic_ids: Any, **kwargs: Any) -> dict[str, Any]:
        ids = list(analytic_ids)
        calls.append(len(ids))
        return {
            spec_id: ledger_module.Ledger(analytic_id=spec_id, since=kwargs["since"])
            for spec_id in ids
        }

    with patch.object(ledger_module, "analytic_ledgers", _bulk, create=True):
        body = client.get("/api/v1/analytics").json()
    assert len(calls) == 1 and calls[0] == len(body["analytics"])


def test_the_list_still_works_without_the_bulk_ledger(client: TestClient) -> None:
    """The bulk reader is optional. The per-analytic reader is the floor."""
    body = client.get("/api/v1/analytics").json()
    assert body["analytics"] and all("observations_7d" in a for a in body["analytics"])


def _insert_observation(client: TestClient, **fields: Any) -> int:
    """Insert one observation row with no adapter in the way.

    Written at the row level on purpose. These tests pin how the API READS a
    row, including a row written by a version of the sweep that no longer runs.
    """
    from soc_ai.store.models import EntityObservation

    born = fields.pop("born_at", datetime(2026, 9, 18, 12, 0))

    async def go() -> int:
        async with client.app.state.db_sessionmaker() as db:
            row = EntityObservation(
                entity_kind="host",
                entity_key="10.1.2.3",
                kind="catalog_match",
                spec_id=fields.pop("spec_id", _LOCAL),
                fingerprint=fields.pop("fingerprint", "fp1"),
                birth_weight=0.7,
                born_at=born,
                first_seen_at=fields.pop("first_seen_at", born),
                occurrences=1,
                **fields,
            )
            db.add(row)
            await db.commit()
            return int(row.id)

    return asyncio.run(go())


def test_the_unread_count_covers_every_unread_hit_not_the_page(client: TestClient) -> None:
    """``unread`` is the count the band, the bell and the sidebar all show."""
    for i in range(3):
        _insert_observation(client, fingerprint=f"fp{i}", shadow=True, source="catalog")
    body = client.get("/api/v1/hunts/shadow-hits?limit=1").json()
    assert len(body["hits"]) == 1
    assert body["unread"] == 3


def test_a_partial_receipts_packet_arrives_shaped(client: TestClient) -> None:
    """A half-written packet never reaches the screen with keys missing."""
    _insert_observation(
        client,
        shadow=True,
        source="catalog",
        evidence_json={"receipts": {"matched_ids": ["d1"], "missing": ["dry_run"]}},
    )
    hit = client.get("/api/v1/hunts/shadow-hits").json()["hits"][0]
    assert hit["state"] == "could_not_run" and hit["missing"] == ["dry_run"]
    receipts = hit["receipts"]
    assert receipts["matched_ids"] == ["d1"]
    assert receipts["matched_fields"] == []
    assert receipts["dry_run"] is None
    assert receipts["overlap"] == []
    assert receipts["baseline"] is None
    assert receipts["complete"] is False
    assert receipts["missing"] == ["dry_run"]


def test_the_ledger_reads_the_cost_of_a_sweep(client: TestClient) -> None:
    """Retirement is a cost decision. A ledger of zeros cannot carry one."""
    from soc_ai.hunting.execute import SpecRun
    from soc_ai.store import hunt_spec_sweeps as sweeps_store

    async def sweep() -> None:
        run = SpecRun(
            spec_id=_SHIPPED,
            since="2026-09-18T00:00:00Z",
            until="2026-09-18T12:00:00Z",
            blind=False,
            precondition_docs=4210,
            matched_docs=3,
            duration_ms=1840,
        )
        async with client.app.state.db_sessionmaker() as db:
            await sweeps_store.record(
                db,
                spec_id=_SHIPPED,
                run=run,
                hunt_id=None,
                shadow=False,
                since=run.since,
                until=run.until,
                now=datetime.now(UTC).replace(tzinfo=None),
            )

    asyncio.run(sweep())
    ledger = client.get(f"/api/v1/analytics/{_SHIPPED}").json()["ledger"]
    assert ledger["sweeps"] == 1
    assert ledger["docs_scanned"] == 4210
    assert ledger["runtime_ms"] == 1840


def test_the_observations_route_needs_an_entity(client: TestClient) -> None:
    """A blank entity read the whole table. Refuse it and name the parameter."""
    for url in (
        "/api/v1/hunts/observations",
        "/api/v1/hunts/observations?entity=",
        "/api/v1/hunts/observations?entity=%20%20",
    ):
        res = client.get(url)
        assert res.status_code == 422, url
        detail = _detail(res)
        assert detail["reason"] == "entity_required", url
        assert "entity" in detail["hint"]


def test_the_observations_window_is_bounded(client: TestClient) -> None:
    for days in (0, -1, 91, 3650):
        res = client.get(f"/api/v1/hunts/observations?entity=10.1.2.3&days={days}")
        assert res.status_code == 422, days
        assert _detail(res)["reason"] == "bad_request"
    ok = client.get("/api/v1/hunts/observations?entity=10.1.2.3&days=90")
    assert ok.status_code == 200 and ok.json()["days"] == 90


def test_a_legacy_candidate_source_reads_as_catalog(client: TestClient) -> None:
    """The retired 'candidate' value stays in the table. It must not reach a screen."""
    _insert_observation(client, source="candidate", shadow=True)
    body = client.get("/api/v1/hunts/observations?entity=10.1.2.3").json()
    assert [o["source"] for o in body["observations"]] == ["catalog"]


def test_a_rejected_credential_field_never_echoes_its_value(client: TestClient) -> None:
    """The plant is on the path the hint would miss: a named secret field.

    The hint quotes the rejected value so an analyst sees what they sent. A
    password is the one value that must never come back. A 4xx body lands in
    proxy capture logs and in browser history.
    """
    secret = "S3CRET-PLAINTEXT-" + ("x" * 4000)
    res = client.post("/api/v1/login", json={"username": "admin", "password": secret})
    assert res.status_code == 422
    assert "S3CRET-PLAINTEXT" not in res.text
    detail = _detail(res)
    assert detail["reason"] == "bad_request"
    assert "password" in detail["hint"]


# ---------------------------------------------------------------------------
# GET /hunts/hits: one surface for the live half and the shadow half
# ---------------------------------------------------------------------------


def _ago(hours: float) -> datetime:
    """A stored (naive UTC) timestamp that many hours back from now.

    Relative, not a fixed date. The window this route reads is seven days wide,
    and a hard-coded date walks out of it.
    """
    return (datetime.now(UTC) - timedelta(hours=hours)).replace(tzinfo=None)


def _shadow_analytic(client: TestClient) -> None:
    """Put the local analytic in shadow, so its hits are shadow hits."""
    if _LOCAL not in {a["id"] for a in client.get("/api/v1/analytics").json()["analytics"]}:
        client.post("/api/v1/analytics", json={"spec_text": SPEC_TEXT})
    client.post(f"/api/v1/analytics/{_LOCAL}/status", json={"to": "shadow", "why": "seed"})


def _seed_three_hits(client: TestClient) -> dict[str, int]:
    """One live hit, one unread shadow hit and one read shadow hit.

    The live hit belongs to a shipped analytic, which is live unless an analyst
    retired it. The two shadow hits belong to the local analytic in shadow.
    """
    _shadow_analytic(client)
    live = _insert_observation(
        client,
        spec_id=_SHIPPED,
        fingerprint="fp-live",
        source="catalog",
        shadow=False,
        born_at=_ago(3),
        evidence_json={"sample_ids": ["d1", "d2", "d3"]},
    )
    unread = _insert_observation(
        client,
        fingerprint="fp-unread",
        source="catalog",
        shadow=True,
        born_at=_ago(1),
        evidence_json={"sample_ids": ["d4"]},
    )
    read = _insert_observation(
        client,
        fingerprint="fp-read",
        source="catalog",
        shadow=True,
        born_at=_ago(2),
        read_at=_ago(1),
    )
    return {"live": live, "unread": unread, "read": read}


def test_the_hits_list_holds_the_live_half_and_the_shadow_half(client: TestClient) -> None:
    ids = _seed_three_hits(client)
    body = client.get("/api/v1/hunts/hits").json()
    by_id = {h["id"]: h for h in body["hits"]}
    assert set(by_id) == set(ids.values())
    assert by_id[ids["live"]]["analytic_status"] == "live"
    assert by_id[ids["live"]]["tier"] == "shipped"
    assert by_id[ids["unread"]]["analytic_status"] == "shadow"
    assert by_id[ids["unread"]]["tier"] == "local"


def test_the_live_hit_leads_and_the_unread_shadow_hit_follows(client: TestClient) -> None:
    """Live first, newest first. Then shadow, unread first, then newest first.

    The live hit here is the OLDEST of the three. It still leads, because the
    real signal is never ranked below a provisional one.
    """
    ids = _seed_three_hits(client)
    body = client.get("/api/v1/hunts/hits").json()
    assert [h["id"] for h in body["hits"]] == [ids["live"], ids["unread"], ids["read"]]


def test_each_hit_filter_returns_its_own_rows(client: TestClient) -> None:
    ids = _seed_three_hits(client)

    def listed(name: str) -> list[int]:
        return [h["id"] for h in client.get(f"/api/v1/hunts/hits?filter={name}").json()["hits"]]

    assert listed("all") == [ids["live"], ids["unread"], ids["read"]]
    assert listed("live") == [ids["live"]]
    assert listed("shadow") == [ids["unread"], ids["read"]]
    assert listed("unread") == [ids["unread"]]


def test_the_hit_counts_read_the_window_not_the_page(client: TestClient) -> None:
    _seed_three_hits(client)
    full = client.get("/api/v1/hunts/hits").json()
    assert full["counts"] == {"all": 3, "unread": 1, "live": 1, "shadow": 2}
    page = client.get("/api/v1/hunts/hits?limit=1").json()
    assert len(page["hits"]) == 1
    assert page["counts"] == full["counts"]


def test_a_live_hit_carries_no_read_flag(client: TestClient) -> None:
    """A live hit has no read flag. False would draw an unread dot on it."""
    ids = _seed_three_hits(client)
    by_id = {h["id"]: h for h in client.get("/api/v1/hunts/hits").json()["hits"]}
    assert by_id[ids["live"]]["read"] is None
    assert by_id[ids["unread"]]["read"] is False
    assert by_id[ids["read"]]["read"] is True


def test_a_live_hit_reads_as_a_hit_without_receipts(client: TestClient) -> None:
    """Receipts prove a SHADOW analytic works. A live analytic was approved on them.

    The negative control for the state rule: the live hit carries no receipts
    packet at all, and it must not read 'could not run'.
    """
    ids = _seed_three_hits(client)
    by_id = {h["id"]: h for h in client.get("/api/v1/hunts/hits").json()["hits"]}
    live = by_id[ids["live"]]
    assert live["receipts"] is None
    assert live["state"] == "hit" and live["missing"] == []
    # The shadow hit keeps the old rule: no packet means it could not run.
    assert by_id[ids["unread"]]["state"] == "could_not_run"
    assert by_id[ids["unread"]]["missing"] == ["receipts"]


def test_a_hit_counts_the_documents_behind_it(client: TestClient) -> None:
    ids = _seed_three_hits(client)
    by_id = {h["id"]: h for h in client.get("/api/v1/hunts/hits").json()["hits"]}
    assert by_id[ids["live"]]["document_count"] == 3
    assert by_id[ids["unread"]]["document_count"] == 1
    assert by_id[ids["read"]]["document_count"] == 0


def test_a_hit_carries_the_status_of_the_lead_that_holds_it(client: TestClient) -> None:
    """A lead holds the decision, so the card reads the lead's status off the hit."""
    from soc_ai.store.models import EntityObservation, Lead

    ids = _seed_three_hits(client)

    async def attach() -> int:
        async with client.app.state.db_sessionmaker() as db:
            lead = Lead(status="hunting", entities_json=[["host", "10.1.2.3"]], kinds_json=[])
            db.add(lead)
            await db.commit()
            row = await db.get(EntityObservation, ids["live"])
            row.lead_id = lead.id
            await db.commit()
            return int(lead.id)

    lead_id = asyncio.run(attach())
    by_id = {h["id"]: h for h in client.get("/api/v1/hunts/hits").json()["hits"]}
    assert by_id[ids["live"]]["lead_id"] == lead_id
    assert by_id[ids["live"]]["lead_status"] == "hunting"
    assert by_id[ids["unread"]]["lead_id"] is None
    assert by_id[ids["unread"]]["lead_status"] is None


def test_an_approval_keeps_the_hit_that_earned_it_on_the_shadow_half(
    client: TestClient,
) -> None:
    """A hit born in shadow stays a shadow hit until the sweep refreshes it.

    The approval is a decision about the analytic. It is not a decision about
    the hit, and the hit is the evidence the approval rests on. Hiding it here
    took the card off every hits surface for as long as the row lived.
    """
    ids = _seed_three_hits(client)
    approved = client.post(
        f"/api/v1/analytics/{_LOCAL}/status", json={"to": "live", "why": "two true hits"}
    )
    assert approved.status_code == 200, approved.text
    body = client.get("/api/v1/hunts/hits").json()
    by_id = {h["id"]: h for h in body["hits"]}
    assert set(by_id) == set(ids.values())
    assert by_id[ids["unread"]]["recorded_in_shadow"] is True
    assert by_id[ids["unread"]]["read"] is False
    assert by_id[ids["read"]]["read"] is True
    assert body["counts"] == {"all": 3, "unread": 1, "live": 1, "shadow": 2}
    unread = client.get("/api/v1/hunts/hits?filter=unread").json()
    assert [h["id"] for h in unread["hits"]] == [ids["unread"]]
    assert client.get("/api/v1/hunts/needs-you").json()["unread_shadow_hits"] == 1


def test_a_hit_reads_the_status_of_its_analytic_now(client: TestClient) -> None:
    """The status chip is the analytic today. The flag says where the hit was born.

    The row flag records the status at the last sighting, and it holds until the
    analytic fires again. The card read that flag as the status, so a hit of an
    approved analytic still wore the shadow chip and still offered the approval.
    """
    ids = _seed_three_hits(client)
    by_id = {h["id"]: h for h in client.get("/api/v1/hunts/hits").json()["hits"]}
    # The local analytic is in shadow, so its hit reads shadow on both fields.
    assert by_id[ids["unread"]]["analytic_status"] == "shadow"
    assert by_id[ids["unread"]]["recorded_in_shadow"] is True
    # The shipped analytic is live, and the hit was born live.
    assert by_id[ids["live"]]["analytic_status"] == "live"
    assert by_id[ids["live"]]["recorded_in_shadow"] is False

    approved = client.post(
        f"/api/v1/analytics/{_LOCAL}/status", json={"to": "live", "why": "two true hits"}
    )
    assert approved.status_code == 200, approved.text
    by_id = {h["id"]: h for h in client.get("/api/v1/hunts/hits").json()["hits"]}
    hit = by_id[ids["unread"]]
    assert hit["analytic_status"] == "live"
    assert hit["recorded_in_shadow"] is True
    # The half it lists under is the flag, so the Shadow filter still holds it.
    shadow = client.get("/api/v1/hunts/hits?filter=shadow").json()
    assert [h["id"] for h in shadow["hits"]] == [ids["unread"], ids["read"]]


def test_a_hit_of_an_analytic_the_catalog_lost_reads_the_flag(client: TestClient) -> None:
    """No catalog answer, so the flag answers. A removed analytic keeps its hits."""
    _shadow_analytic(client)
    orphan = _insert_observation(
        client,
        spec_id="gone-analytic",
        fingerprint="fp-orphan",
        source="catalog",
        shadow=True,
        born_at=_ago(1),
    )
    by_id = {h["id"]: h for h in client.get("/api/v1/hunts/hits").json()["hits"]}
    assert by_id[orphan]["analytic_status"] == "shadow"
    assert by_id[orphan]["recorded_in_shadow"] is True
    assert by_id[orphan]["analytic_exists"] is False


def test_a_refreshed_hit_moves_to_the_live_half(client: TestClient) -> None:
    """The sweep flips the flag, so the Live filter lists the hit.

    The route reads the flag on the row. The sweep writes it. This test pins
    the route half of the rule; the sweep half is in
    ``tests/test_hunt_sweep_observations.py``.
    """
    from soc_ai.store.models import EntityObservation

    ids = _seed_three_hits(client)
    client.post(f"/api/v1/analytics/{_LOCAL}/status", json={"to": "live", "why": "two true hits"})

    async def refresh() -> None:
        async with client.app.state.db_sessionmaker() as db:
            row = await db.get(EntityObservation, ids["unread"])
            row.shadow = False
            await db.commit()

    asyncio.run(refresh())
    live = client.get("/api/v1/hunts/hits?filter=live").json()
    assert set(h["id"] for h in live["hits"]) == {ids["live"], ids["unread"]}
    body = client.get("/api/v1/hunts/hits").json()
    assert body["counts"] == {"all": 3, "unread": 0, "live": 2, "shadow": 1}
    by_id = {h["id"]: h for h in body["hits"]}
    assert by_id[ids["unread"]]["analytic_status"] == "live"
    assert by_id[ids["unread"]]["recorded_in_shadow"] is False
    assert by_id[ids["unread"]]["read"] is None


def test_a_hit_whose_analytic_was_retired_is_hidden(client: TestClient) -> None:
    """A rejection retires the analytic. Its hits leave the surfaces.

    This is the one status that hides a hit. The analyst said the analytic is
    wrong, so its hits are not work.
    """
    ids = _seed_three_hits(client)
    retired = client.post(
        f"/api/v1/analytics/{_LOCAL}/status", json={"to": "retired", "why": "too noisy"}
    )
    assert retired.status_code == 200, retired.text
    body = client.get("/api/v1/hunts/hits").json()
    assert [h["id"] for h in body["hits"]] == [ids["live"]]
    assert body["counts"] == {"all": 1, "unread": 0, "live": 1, "shadow": 0}
    assert client.get("/api/v1/hunts/needs-you").json()["unread_shadow_hits"] == 0


def test_a_hit_outside_the_window_is_not_listed(client: TestClient) -> None:
    _shadow_analytic(client)
    fresh = _insert_observation(
        client, fingerprint="fp-fresh", source="catalog", shadow=True, born_at=_ago(24)
    )
    _insert_observation(
        client, fingerprint="fp-old", source="catalog", shadow=True, born_at=_ago(24 * 9)
    )
    body = client.get("/api/v1/hunts/hits").json()
    assert [h["id"] for h in body["hits"]] == [fresh]
    assert body["counts"]["all"] == 1
    assert client.get("/api/v1/hunts/hits?days=30").json()["counts"]["all"] == 2


def test_an_observation_from_another_source_is_not_an_analytic_hit(client: TestClient) -> None:
    """A profile departure is an observation. It is not an analytic hit."""
    _shadow_analytic(client)
    _insert_observation(client, fingerprint="fp-profile", source="profile", born_at=_ago(1))
    assert client.get("/api/v1/hunts/hits").json()["hits"] == []


def test_a_hit_says_whether_its_analytic_can_be_opened(client: TestClient) -> None:
    """The card links the title to the analytic drawer. The link needs a target.

    A hit whose analytic the catalog no longer knows stays listed, so the row
    has to say the analytic is gone. The drawer opened on the id and read
    "Could not read the analytic."
    """
    ids = _seed_three_hits(client)
    gone = _insert_observation(
        client,
        spec_id="local-was-deleted",
        fingerprint="fp-gone",
        source="catalog",
        shadow=True,
        born_at=_ago(4),
    )
    by_id = {h["id"]: h for h in client.get("/api/v1/hunts/hits").json()["hits"]}
    assert by_id[ids["live"]]["analytic_exists"] is True
    assert by_id[ids["unread"]]["analytic_exists"] is True
    assert by_id[gone]["analytic_exists"] is False


def test_an_observation_says_whether_its_analytic_can_be_opened(client: TestClient) -> None:
    """The host page lists observations from every source. Two write no analytic.

    An alert verdict and a promoted hunt finding are both recorded under a
    spec id that names the adapter, not an analytic. The link opened a drawer
    titled "alert / alert" that could not be read.
    """
    _shadow_analytic(client)
    _insert_observation(client, spec_id=_LOCAL, fingerprint="fp-a", source="catalog", shadow=True)
    _insert_observation(client, spec_id="alert", fingerprint="fp-b", source="alert")
    rows = client.get("/api/v1/hunts/observations?entity=10.1.2.3&days=90").json()["observations"]
    by_spec = {o["spec_id"]: o for o in rows}
    assert by_spec[_LOCAL]["analytic_exists"] is True
    assert by_spec["alert"]["analytic_exists"] is False


def test_the_hits_query_bounds_refuse_with_a_reason_and_a_hint(client: TestClient) -> None:
    for days in (0, -1, 31, 3650):
        res = client.get(f"/api/v1/hunts/hits?days={days}")
        assert res.status_code == 422, days
        assert _detail(res)["reason"] == "bad_days"
    for limit in (0, -1, 201):
        res = client.get(f"/api/v1/hunts/hits?limit={limit}")
        assert res.status_code == 422, limit
        assert _detail(res)["reason"] == "bad_limit"
    res = client.get("/api/v1/hunts/hits?filter=bogus")
    assert res.status_code == 422
    detail = _detail(res)
    assert detail["reason"] == "bad_filter"
    # "type", not "kind": the word the analyst reads on every surface.
    assert "type" in detail["hint"]
    for ok in ("/api/v1/hunts/hits?days=30", "/api/v1/hunts/hits?limit=200"):
        assert client.get(ok).status_code == 200, ok


# ---------------------------------------------------------------------------
# GET /hunts/needs-you: the sidebar badge and the Needs-you strip
# ---------------------------------------------------------------------------


def _seed_lead(
    client: TestClient, *, status: str, hunt_status: str | None, reopened: bool = False
) -> int:
    """One lead, with a hunt attached when ``hunt_status`` names one.

    ``reopened`` leaves the dismissal on an open lead, as a reopen does.
    """
    from datetime import datetime as _dt

    from soc_ai.store.models import Hunt, Lead

    async def go() -> int:
        async with client.app.state.db_sessionmaker() as db:
            hunt_id = None
            if hunt_status is not None:
                hunt = Hunt(
                    id=f"h-{status}-{hunt_status}",
                    objective="look at this lead",
                    objective_hash="x",
                    started_by="admin",
                    kind="lead",
                    status=hunt_status,
                )
                db.add(hunt)
                await db.flush()
                hunt_id = hunt.id
            lead = Lead(
                status=status,
                entities_json=[["host", "10.1.2.3"]],
                kinds_json=["catalog_match"],
                hunt_id=hunt_id,
                shadow=False,
                dismissed_reason="benign_repeat" if reopened else None,
                dismissed_at=_dt(2026, 9, 20, 9, 0) if reopened else None,
            )
            db.add(lead)
            await db.commit()
            return int(lead.id)

    return asyncio.run(go())


def test_needs_you_carries_the_auto_hunt_setting(client: TestClient) -> None:
    """The leads block says which rule runs: a lead hunts itself, or waits.

    It read the rule off whether any listed lead was queued, which reads as
    "off" the moment the queue is empty.
    """
    assert client.get("/api/v1/hunts/needs-you").json()["lead_auto_hunt"] is True
    client.app.state.settings = client.app.state.settings.model_copy(
        update={"lead_auto_hunt": False}
    )
    assert client.get("/api/v1/hunts/needs-you").json()["lead_auto_hunt"] is False


def test_needs_you_counts_unread_shadow_hits(client: TestClient) -> None:
    _seed_three_hits(client)
    body = client.get("/api/v1/hunts/needs-you").json()
    assert body == {
        "unread_shadow_hits": 1,
        "leads_needing_decision": 0,
        "total": 1,
        "lead_auto_hunt": True,
    }


def test_needs_you_leaves_out_a_new_lead_whose_hunt_is_queued(client: TestClient) -> None:
    """The loop will start the hunt, so the lead waits on soc-ai, not the analyst.

    The strip counts what an analyst must act on. A lead soc-ai is about to
    hunt is not that, and counting it would put a number on the sidebar that
    clears itself a minute later.
    """
    _seed_lead(client, status="open", hunt_status=None)
    body = client.get("/api/v1/hunts/needs-you").json()
    assert body == {
        "unread_shadow_hits": 0,
        "leads_needing_decision": 0,
        "total": 0,
        "lead_auto_hunt": True,
    }


def test_needs_you_counts_a_new_lead_when_the_loop_is_off(client: TestClient) -> None:
    """Off, nobody will start the hunt, so the lead is back on the analyst."""
    _seed_lead(client, status="open", hunt_status=None)
    client.app.state.settings = client.app.state.settings.model_copy(
        update={"lead_auto_hunt": False}
    )
    body = client.get("/api/v1/hunts/needs-you").json()
    assert body == {
        "unread_shadow_hits": 0,
        "leads_needing_decision": 1,
        "total": 1,
        "lead_auto_hunt": False,
    }


def test_needs_you_counts_a_reopened_lead_with_the_loop_on(client: TestClient) -> None:
    """The loop leaves a reopened lead alone, so nothing is queued for it."""
    _seed_lead(client, status="open", hunt_status=None, reopened=True)
    assert client.get("/api/v1/hunts/needs-you").json()["leads_needing_decision"] == 1


def test_needs_you_counts_a_reopened_lead_that_kept_its_hunt(client: TestClient) -> None:
    """A reopen keeps the hunt, so the lead is open with a finished hunt.

    The loop leaves a reopened lead alone, so the analyst is the only one who
    can move it. The count held it under neither setting.
    """
    _seed_lead(client, status="open", hunt_status="complete", reopened=True)
    assert client.get("/api/v1/hunts/needs-you").json()["leads_needing_decision"] == 1
    client.app.state.settings = client.app.state.settings.model_copy(
        update={"lead_auto_hunt": False}
    )
    assert client.get("/api/v1/hunts/needs-you").json()["leads_needing_decision"] == 1


def test_needs_you_leaves_out_an_open_lead_whose_hunt_runs(client: TestClient) -> None:
    """NEGATIVE CONTROL. Hunt again on a reopened lead: the hunt runs, nothing waits."""
    _seed_lead(client, status="open", hunt_status="running")
    assert client.get("/api/v1/hunts/needs-you").json()["leads_needing_decision"] == 0


def test_needs_you_counts_a_hunting_lead_whose_hunt_finished(client: TestClient) -> None:
    _seed_lead(client, status="hunting", hunt_status="complete")
    _seed_lead(client, status="hunting", hunt_status="error")
    assert client.get("/api/v1/hunts/needs-you").json()["leads_needing_decision"] == 2


def test_needs_you_leaves_out_a_lead_whose_hunt_runs(client: TestClient) -> None:
    _seed_lead(client, status="hunting", hunt_status="running")
    assert client.get("/api/v1/hunts/needs-you").json()["leads_needing_decision"] == 0


def test_needs_you_leaves_out_a_closed_lead(client: TestClient) -> None:
    _seed_lead(client, status="dismissed", hunt_status="complete")
    _seed_lead(client, status="promoted", hunt_status="complete")
    assert client.get("/api/v1/hunts/needs-you").json()["leads_needing_decision"] == 0


def test_the_needs_you_total_is_the_sum_of_the_two_counts(client: TestClient) -> None:
    _seed_three_hits(client)
    _seed_lead(client, status="open", hunt_status=None, reopened=True)
    _seed_lead(client, status="hunting", hunt_status="complete")
    body = client.get("/api/v1/hunts/needs-you").json()
    assert body == {
        "unread_shadow_hits": 1,
        "leads_needing_decision": 2,
        "total": 3,
        "lead_auto_hunt": True,
    }
