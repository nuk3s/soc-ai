"""Bulk decisions on leads: dismiss, reopen, hunt, and the Undo of each.

The owner asked for bulk management of leads, like the alerts and the
investigations have (2026-10-20). Every lead decision was one lead at a time,
so ten noise leads on one host cost about thirty clicks.

Each bulk route sends every lead through the store function its single route
uses, so a bulk decision writes the same history row a single decision
writes. A lead the press cannot take is skipped with a reason, and never
forced.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.config import Settings
from soc_ai.main import create_app


def _client(settings: Settings) -> Iterator[TestClient]:
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=AsyncMock()),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=settings),
    ):
        app = create_app()
        with TestClient(app) as client:
            yield client


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    yield from _client(settings_kratos)


def _seed(
    client: TestClient,
    *,
    status: str = "open",
    hunt_status: str | None = None,
    shadow: bool = False,
    dismissed_reason: str | None = None,
    dismissed_by: str | None = None,
    investigation_id: str | None = None,
    host: str = "192.0.2.10",
) -> int:
    """One lead row, with a hunt attached when ``hunt_status`` names one.

    Written at the row level, relative to now. These tests pin what the bulk
    routes do with a lead in each state, and formation has its own tests.
    """
    from soc_ai.store.models import Hunt, Lead

    async def go() -> int:
        now = datetime.now(UTC).replace(tzinfo=None) - timedelta(hours=1)
        async with client.app.state.db_sessionmaker() as db:
            hunt_id = None
            if hunt_status is not None:
                hunt_id = f"bulk-{uuid.uuid4().hex[:12]}"
                db.add(
                    Hunt(
                        id=hunt_id,
                        objective="look at this lead",
                        objective_hash="x",
                        started_by="analyst",
                        kind="lead",
                        starter="lead",
                        status=hunt_status,
                    )
                )
                await db.flush()
            lead = Lead(
                status=status,
                formed_at=now,
                updated_at=now,
                entities_json=[["host", host]],
                kinds_json=["novel_destination", "off_hours"],
                hunt_id=hunt_id,
                investigation_id=investigation_id,
                shadow=shadow,
                dismissed_reason=dismissed_reason,
                dismissed_by=dismissed_by,
                dismissed_at=now if dismissed_reason else None,
            )
            db.add(lead)
            await db.commit()
            return int(lead.id)

    return asyncio.run(go())


def _lead(client: TestClient, lead_id: int) -> dict[str, Any]:
    res = client.get(f"/api/v1/hunts/leads/{lead_id}")
    assert res.status_code == 200, res.text
    body: dict[str, Any] = res.json()
    return body


def _seen(client: TestClient, ids: list[int]) -> dict[str, str | None]:
    """The change token of each lead, as the list on the page holds it."""
    rows = {int(r["id"]): r for r in client.get("/api/v1/leads?status=all&limit=200").json()}
    return {str(i): rows[i]["updated_at"] for i in ids}


def _touch(client: TestClient, lead_id: int) -> None:
    """Move the lead's change token, as a new observation type does."""
    from soc_ai.store.models import Lead

    async def go() -> None:
        async with client.app.state.db_sessionmaker() as db:
            lead = await db.get(Lead, lead_id)
            assert lead is not None
            lead.updated_at = datetime.now(UTC).replace(tzinfo=None)
            await db.commit()

    asyncio.run(go())


def _post(client: TestClient, route: str, ids: list[int], **body: Any) -> Any:
    payload: dict[str, Any] = {"ids": ids, "expected": len(set(ids))}
    payload.update(body)
    return client.post(f"/api/v1/hunts/leads/{route}", json=payload)


def _skip_reasons(body: dict[str, Any]) -> dict[int, str]:
    return {int(s["id"]): s["reason"] for s in body["skipped"]}


# ── Dismiss ──────────────────────────────────────────────────────────────────


def test_a_bulk_dismiss_writes_one_history_row_per_lead_with_one_reason(
    client: TestClient,
) -> None:
    ids = [_seed(client) for _ in range(3)]
    res = _post(
        client,
        "bulk-dismiss",
        ids,
        reason="benign_repeat",
        note="patch window",
        seen=_seen(client, ids),
    )
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["action"] == "dismiss"
    assert [d["id"] for d in body["done"]] == ids
    assert body["skipped"] == [] and body["failed"] == []
    actors = set()
    for lead_id in ids:
        lead = _lead(client, lead_id)
        assert lead["status"] == "dismissed"
        assert lead["dismissed_reason"] == "benign_repeat"
        dismissals = [d for d in lead["decisions"] if d["action"] == "dismissed"]
        assert len(dismissals) == 1
        assert dismissals[0]["reason"] == "benign_repeat"
        assert dismissals[0]["note"] == "patch window"
        actors.add(dismissals[0]["by"])
    # One hand for the whole press.
    assert len(actors) == 1
    # Each answer carries the token Undo sends back.
    for done in body["done"]:
        assert done["updated_at"] == _seen(client, [done["id"]])[str(done["id"])]


def test_a_bulk_dismiss_skips_every_lead_it_cannot_take_and_names_the_reason(
    client: TestClient,
) -> None:
    plain = _seed(client)
    shadow = _seed(client, shadow=True)
    dismissed = _seed(client, status="dismissed", dismissed_reason="known_change")
    promoted = _seed(client, status="promoted", investigation_id="inv-bulk-1")
    running = _seed(client, status="hunting", hunt_status="running")
    hunted = _seed(client, status="hunting", hunt_status="complete")
    changed = _seed(client)
    missing = 999_999
    ids = [plain, shadow, dismissed, promoted, running, hunted, changed, missing]
    seen = _seen(client, [i for i in ids if i != missing])
    _touch(client, changed)

    res = _post(client, "bulk-dismiss", ids, reason="lab_host", seen=seen)
    assert res.status_code == 200, res.text
    body = res.json()
    assert sorted(d["id"] for d in body["done"]) == sorted([plain, hunted])
    assert _skip_reasons(body) == {
        shadow: "shadow",
        dismissed: "already_closed",
        promoted: "already_closed",
        running: "hunt_running",
        changed: "changed",
        missing: "not_found",
    }
    # Every skip carries the sentence the console shows.
    assert all(s["hint"] for s in body["skipped"])
    # A skipped lead is untouched: no status change and no history row.
    assert _lead(client, shadow)["status"] == "open"
    assert _lead(client, changed)["status"] == "open"
    assert _lead(client, running)["status"] == "hunting"
    assert _lead(client, dismissed)["dismissed_reason"] == "known_change"
    assert _lead(client, promoted)["status"] == "promoted"
    assert not any(d["action"] == "dismissed" for d in _lead(client, shadow)["decisions"])


def test_a_bulk_dismiss_refuses_a_count_the_confirm_did_not_name(client: TestClient) -> None:
    ids = [_seed(client) for _ in range(3)]
    res = client.post(
        "/api/v1/hunts/leads/bulk-dismiss",
        json={"ids": ids, "expected": 2, "reason": "benign_repeat"},
    )
    assert res.status_code == 409
    detail = res.json()["detail"]
    assert detail["reason"] == "lead_selection_changed"
    assert "2" in detail["hint"] and "3" in detail["hint"]
    # The refusal writes nothing.
    assert all(_lead(client, i)["status"] == "open" for i in ids)


def test_a_repeated_id_counts_once_against_the_confirm(client: TestClient) -> None:
    lead_id = _seed(client)
    res = client.post(
        "/api/v1/hunts/leads/bulk-dismiss",
        json={"ids": [lead_id, lead_id], "expected": 1, "reason": "benign_repeat"},
    )
    assert res.status_code == 200, res.text
    assert [d["id"] for d in res.json()["done"]] == [lead_id]


def test_a_bulk_dismiss_needs_a_reason_from_the_list(client: TestClient) -> None:
    lead_id = _seed(client)
    res = _post(client, "bulk-dismiss", [lead_id], reason="hunt_clean")
    assert res.status_code == 422
    assert res.json()["detail"]["reason"] == "unknown_dismiss_reason"
    assert _lead(client, lead_id)["status"] == "open"


def test_a_lead_whose_write_fails_is_reported_and_the_rest_land(client: TestClient) -> None:
    from soc_ai.store import leads as leads_store

    good, bad = _seed(client), _seed(client)
    real = leads_store.dismiss

    async def flaky(db: Any, lead_id: int, **kw: Any) -> Any:
        if int(lead_id) == bad:
            raise RuntimeError("disk full")
        return await real(db, lead_id, **kw)

    with patch.object(leads_store, "dismiss", flaky):
        res = _post(client, "bulk-dismiss", [bad, good], reason="benign_repeat")
    assert res.status_code == 200, res.text
    body = res.json()
    assert [d["id"] for d in body["done"]] == [good]
    assert [(f["id"], f["reason"]) for f in body["failed"]] == [(bad, "write_failed")]
    assert _lead(client, bad)["status"] == "open"


def test_a_bulk_dismiss_moves_the_needs_you_count_and_the_tab_count(client: TestClient) -> None:
    client.app.state.settings = client.app.state.settings.model_copy(
        update={"lead_auto_hunt": False}
    )
    ids = [_seed(client, host="192.0.2.20") for _ in range(4)]
    before = client.get("/api/v1/hunts/needs-you").json()["leads_needing_decision"]
    tab = client.get("/api/v1/leads/count?status=needs_decision&entity=192.0.2.20").json()
    assert tab["total"] == 4
    res = _post(client, "bulk-dismiss", ids[:3], reason="benign_repeat")
    assert res.status_code == 200, res.text
    after = client.get("/api/v1/hunts/needs-you").json()["leads_needing_decision"]
    assert after == before - 3
    tab = client.get("/api/v1/leads/count?status=needs_decision&entity=192.0.2.20").json()
    assert tab["total"] == 1
    closed = client.get("/api/v1/leads/count?status=closed&entity=192.0.2.20").json()
    assert closed["total"] == 3


def test_a_bulk_press_writes_one_audit_record(client: TestClient) -> None:
    audit = AsyncMock()
    client.app.state.audit = audit
    ids = [_seed(client) for _ in range(2)]
    res = _post(client, "bulk-dismiss", ids, reason="duplicate")
    assert res.status_code == 200, res.text
    calls = [c for c in audit.log_kind.await_args_list if c.args[1] == "leads_bulk_decision"]
    assert len(calls) == 1
    payload = calls[0].args[2]
    assert payload["action"] == "dismiss"
    assert payload["reason"] == "duplicate"
    assert sorted(payload["done"]) == sorted(ids)


# ── Reopen and the Undo of a dismiss ─────────────────────────────────────────


def test_a_bulk_reopen_opens_the_dismissed_leads_and_skips_the_rest(client: TestClient) -> None:
    analyst = _seed(client, status="dismissed", dismissed_reason="known_change", dismissed_by="ana")
    by_hunt = _seed(
        client, status="dismissed", dismissed_reason="hunt_clean", dismissed_by="auto-hunt"
    )
    promoted = _seed(client, status="promoted", investigation_id="inv-bulk-2")
    still_open = _seed(client)
    shadow = _seed(client, status="dismissed", dismissed_reason="lab_host", shadow=True)
    ids = [analyst, by_hunt, promoted, still_open, shadow]

    res = _post(client, "bulk-reopen", ids, seen=_seen(client, ids))
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["action"] == "reopen"
    done = {d["id"]: d for d in body["done"]}
    assert set(done) == {analyst, by_hunt}
    assert done[analyst]["previous_reason"] == "known_change"
    assert done[by_hunt]["previous_reason"] == "hunt_clean"
    assert _skip_reasons(body) == {
        promoted: "promoted",
        still_open: "not_closed",
        shadow: "shadow",
    }
    for lead_id in (analyst, by_hunt):
        lead = _lead(client, lead_id)
        assert lead["status"] == "open"
        assert lead["decisions"][-1]["action"] == "reopened"
    assert _lead(client, promoted)["status"] == "promoted"


def test_the_undo_of_a_bulk_dismiss_reopens_only_the_leads_that_did_not_change(
    client: TestClient,
) -> None:
    ids = [_seed(client) for _ in range(3)]
    first = _post(client, "bulk-dismiss", ids, reason="benign_repeat", seen=_seen(client, ids))
    assert first.status_code == 200, first.text
    tokens = {str(d["id"]): d["updated_at"] for d in first.json()["done"]}
    # Another hand moves one lead after the press.
    _touch(client, ids[2])
    undo = _post(client, "bulk-reopen", ids, seen=tokens)
    assert undo.status_code == 200, undo.text
    body = undo.json()
    assert sorted(d["id"] for d in body["done"]) == sorted(ids[:2])
    assert _skip_reasons(body) == {ids[2]: "changed"}
    assert _lead(client, ids[2])["status"] == "dismissed"
    for lead_id in ids[:2]:
        actions = [d["action"] for d in _lead(client, lead_id)["decisions"]]
        assert actions == ["dismissed", "reopened"]


# ── Dismiss again: the Undo of a reopen ──────────────────────────────────────


def test_the_undo_of_a_bulk_reopen_dismisses_each_lead_with_its_last_reason(
    client: TestClient,
) -> None:
    first = _seed(client)
    second = _seed(client)
    by_hunt = _seed(
        client, status="dismissed", dismissed_reason="hunt_clean", dismissed_by="auto-hunt"
    )
    client.post(
        f"/api/v1/hunts/leads/{first}/dismiss", json={"reason": "known_change", "note": "patch"}
    )
    client.post(f"/api/v1/hunts/leads/{second}/dismiss", json={"reason": "lab_host"})
    ids = [first, second, by_hunt]
    reopened = _post(client, "bulk-reopen", ids, seen=_seen(client, ids))
    assert reopened.status_code == 200, reopened.text
    tokens = {str(d["id"]): d["updated_at"] for d in reopened.json()["done"]}

    res = _post(client, "bulk-dismiss-again", ids, seen=tokens)
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["action"] == "dismiss_again"
    assert sorted(d["id"] for d in body["done"]) == sorted([first, second])
    # soc-ai closed this lead after a clean hunt. An analyst reason cannot
    # restore that close, so it stays open.
    assert _skip_reasons(body) == {by_hunt: "no_dismissal"}
    one = _lead(client, first)
    assert one["status"] == "dismissed"
    assert one["dismissed_reason"] == "known_change"
    assert [d["action"] for d in one["decisions"]] == ["dismissed", "reopened", "dismissed"]
    assert one["decisions"][-1]["note"] == "patch"
    assert _lead(client, second)["dismissed_reason"] == "lab_host"
    assert _lead(client, by_hunt)["status"] == "open"


# ── Hunt ─────────────────────────────────────────────────────────────────────


def test_a_bulk_hunt_starts_at_most_the_cap_and_skips_a_hunt_in_flight(
    client: TestClient,
) -> None:
    from soc_ai.api.webui import routes_lead_bulk
    from soc_ai.webui import hunt_console_manager as hcm

    cap = routes_lead_bulk.LEAD_BULK_HUNT_CAP
    fresh = [_seed(client) for _ in range(cap + 2)]
    in_flight = _seed(client, status="hunting", hunt_status="running")
    shadow = _seed(client, shadow=True)
    closed = _seed(client, status="dismissed", dismissed_reason="lab_host")
    ids = [in_flight, shadow, closed, *fresh]

    manager = hcm.get_manager(client.app.state)
    # No model runs: the console start is faked and answers a hunt id.
    started = [f"fake-hunt-{n}" for n in range(10)]
    start = AsyncMock(side_effect=started)
    with patch.object(manager, "start", start):
        res = _post(client, "bulk-hunt", ids, seen=_seen(client, ids))
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["action"] == "hunt"
    assert body["cap"] == cap
    assert start.await_count == cap
    done = body["done"]
    assert [d["id"] for d in done] == fresh[:cap]
    assert [d["hunt_id"] for d in done] == started[:cap]
    assert _skip_reasons(body) == {
        in_flight: "hunt_running",
        shadow: "shadow",
        closed: "already_closed",
        fresh[cap]: "over_cap",
        fresh[cap + 1]: "over_cap",
    }
    for lead_id, hunt_id in zip(fresh[:cap], started[:cap], strict=True):
        lead = _lead(client, lead_id)
        assert lead["status"] == "hunting" and lead["hunt_id"] == hunt_id
    assert _lead(client, fresh[cap])["status"] == "open"


def test_a_bulk_hunt_names_a_start_the_console_refused(client: TestClient) -> None:
    from soc_ai.webui import hunt_console_manager as hcm

    ids = [_seed(client), _seed(client)]
    manager = hcm.get_manager(client.app.state)
    with patch.object(manager, "start", AsyncMock(side_effect=[None, "fake-hunt-ok"])):
        res = _post(client, "bulk-hunt", ids)
    assert res.status_code == 200, res.text
    body = res.json()
    assert [(f["id"], f["reason"]) for f in body["failed"]] == [(ids[0], "could_not_start")]
    assert [d["id"] for d in body["done"]] == [ids[1]]


def test_the_hunt_plan_states_the_cap_and_the_measured_hunt_time(client: TestClient) -> None:
    from soc_ai.api.webui import routes_lead_bulk
    from soc_ai.store.models import Hunt

    empty = client.get("/api/v1/leads/bulk-hunt-plan")
    assert empty.status_code == 200, empty.text
    assert empty.json() == {"cap": routes_lead_bulk.LEAD_BULK_HUNT_CAP, "typical_run": None}

    async def go() -> None:
        end = datetime.now(UTC).replace(tzinfo=None) - timedelta(hours=2)
        async with client.app.state.db_sessionmaker() as db:
            for n, minutes in enumerate((4, 5, 6, 7, 8)):
                db.add(
                    Hunt(
                        id=f"plan-{n}",
                        objective="o",
                        objective_hash="x",
                        started_by="analyst",
                        kind="lead",
                        status="complete",
                        created_at=end - timedelta(minutes=minutes),
                        finished_at=end,
                    )
                )
            await db.commit()

    asyncio.run(go())
    plan = client.get("/api/v1/leads/bulk-hunt-plan").json()
    assert plan["typical_run"]["medianMin"] == 6
    assert plan["typical_run"]["samples"] == 5
    assert plan["typical_run"]["lowMin"] <= 6 <= plan["typical_run"]["highMin"]


def test_a_bulk_route_takes_at_most_the_list_limit(client: TestClient) -> None:
    from soc_ai.api.webui import routes_lead_bulk

    too_many = list(range(1, routes_lead_bulk.LEAD_BULK_MAX + 2))
    res = client.post(
        "/api/v1/hunts/leads/bulk-reopen", json={"ids": too_many, "expected": len(too_many)}
    )
    assert res.status_code == 422
    assert (
        client.post("/api/v1/hunts/leads/bulk-reopen", json={"ids": [], "expected": 0}).status_code
        == 422
    )
