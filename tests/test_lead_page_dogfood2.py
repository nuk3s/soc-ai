"""The lead page after the second hunting dogfood (2026-10-06).

The lead page labelled each hunt by its id and gave none of its answer. The
leads list read the newest hunt alone, so a lead whose earlier hunts found a
threat read "No threat observed". These tests pin what the API now sends for
both surfaces.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.api.webui.routes_hunts import _first_sentence
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.store import hunts as hunt_svc
from soc_ai.store.models import Hunt, Lead


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=AsyncMock()),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=settings_kratos),
    ):
        app = create_app()
        with TestClient(app) as test_client:
            yield test_client


def _seed_lead(client: TestClient, *, status: str = "hunting") -> int:
    async def go() -> int:
        async with client.app.state.db_sessionmaker() as db:
            lead = Lead(
                status=status,
                entities_json=[["host", "10.1.2.3"]],
                kinds_json=["catalog_match"],
                shadow=False,
            )
            db.add(lead)
            await db.commit()
            return int(lead.id)

    return asyncio.run(go())


_EVENTS: list[dict[str, Any]] = [
    {"sequence": 1, "kind": "hunt_started", "payload": {"objective": "x"}},
    {
        "sequence": 2,
        "kind": "tool_call",
        "payload": {"tool_name": "t_host_dossier", "args": {}, "tool_call_id": "c1"},
    },
    {"sequence": 3, "kind": "tool_result", "payload": {"tool_call_id": "c1", "result": {}}},
    {
        "sequence": 4,
        "kind": "tool_call",
        "payload": {"tool_name": "t_origin_chain", "args": {}, "tool_call_id": "c2"},
    },
    {"sequence": 5, "kind": "tool_result", "payload": {"tool_call_id": "c2", "result": {}}},
    {"sequence": 6, "kind": "hunt_report", "payload": {"findings": [], "narrative": "x"}},
    {"sequence": 7, "kind": "done", "payload": {}},
]


def _seed_hunt(
    client: TestClient,
    lead_id: int,
    *,
    findings: list[dict[str, Any]],
    narrative: str,
    started: datetime,
    status: str = "complete",
    attach: bool = True,
) -> str:
    """One lead hunt that started at ``started``. ``attach`` names it on the lead."""

    async def go() -> str:
        async with client.app.state.db_sessionmaker() as db:
            hunt = await hunt_svc.create(
                db,
                objective=f"[lead {lead_id}] look at this lead",
                started_by="admin",
                kind="lead",
                starter="lead",
                lead_id=lead_id,
            )
            await hunt_svc.append_events(db, hunt.id, [dict(e) for e in _EVENTS])
            if status != "running":
                await hunt_svc.finalize(
                    db,
                    hunt.id,
                    status=status,
                    narrative=narrative,
                    report={"findings": findings, "narrative": narrative},
                )
            row = await db.get(Hunt, hunt.id)
            assert row is not None
            row.created_at = started.replace(tzinfo=None)
            if row.finished_at is not None:
                row.finished_at = (started + timedelta(minutes=6)).replace(tzinfo=None)
            if attach:
                lead = await db.get(Lead, lead_id)
                assert lead is not None
                lead.hunt_id = hunt.id
            await db.commit()
            return hunt.id

    return asyncio.run(go())


_THREAT = {"title": "HTTP service runs id as root", "category": "threat", "detail": "x"}
_GAP = {
    "title": "DCE-RPC traffic",
    "category": "visibility_gap",
    "detail": "This grid has no zeek.dce_rpc data. The hunt read the 4662 events alone.",
}
_NOTE = {"title": "Attribute writes", "category": "observation", "detail": "Two 4662 writes."}


# ---------------------------------------------------------------------------
# W3 and K5: each hunt with its answer and a label
# ---------------------------------------------------------------------------


def test_the_lead_page_names_each_hunt_with_its_answer(client: TestClient) -> None:
    lead_id = _seed_lead(client)
    now = datetime.now(UTC)
    older = _seed_hunt(
        client,
        lead_id,
        findings=[_THREAT],
        narrative="## Summary\nThe HTTP service ran **id** as root. It did so twice.",
        started=now - timedelta(days=3),
        attach=False,
    )
    newer = _seed_hunt(
        client,
        lead_id,
        findings=[_NOTE, _GAP],
        narrative="The two events are attribute writes. No replication right appears.",
        started=now - timedelta(hours=2),
    )
    body = client.get(f"/api/v1/hunts/leads/{lead_id}").json()
    hunts = body["hunts"]
    assert [h["id"] for h in hunts] == [newer, older]
    first, second = hunts
    assert first["answer"] == "The two events are attribute writes."
    assert first["not_checked"] == ["DCE-RPC traffic. This grid has no zeek.dce_rpc data."]
    assert first["outcome"] == "clean" and first["threat_findings"] == 0
    # The steps the hunt page lists: the objective, two tool calls, the report.
    assert first["steps"] == 4
    assert first["elapsed_sec"] == 360
    assert second["answer"] == "The HTTP service ran id as root."
    assert second["threat_findings"] == 1 and second["not_checked"] == []
    assert body["hunt_count"] == 2 and body["hunt_threat_count"] == 1


def test_a_running_hunt_states_no_answer(client: TestClient) -> None:
    # Negative control: a hunt that has not finished has no answer to state.
    lead_id = _seed_lead(client)
    _seed_hunt(
        client,
        lead_id,
        findings=[],
        narrative="",
        started=datetime.now(UTC) - timedelta(minutes=2),
        status="running",
    )
    hunt = client.get(f"/api/v1/hunts/leads/{lead_id}").json()["hunts"][0]
    assert hunt["status"] == "running"
    assert hunt["answer"] == "" and hunt["not_checked"] == []


def test_a_lead_with_no_hunt_lists_none(client: TestClient) -> None:
    lead_id = _seed_lead(client, status="open")
    body = client.get(f"/api/v1/hunts/leads/{lead_id}").json()
    assert body["hunts"] == []
    assert body["hunt_count"] == 0 and body["hunt_threat_count"] == 0


# ---------------------------------------------------------------------------
# S3: the list counts every hunt on record
# ---------------------------------------------------------------------------


def test_the_lead_list_counts_the_hunts_that_found_a_threat(client: TestClient) -> None:
    lead_id = _seed_lead(client)
    now = datetime.now(UTC)
    for days in (5, 4, 3):
        _seed_hunt(
            client,
            lead_id,
            findings=[_THREAT],
            narrative="A threat.",
            started=now - timedelta(days=days),
            attach=False,
        )
    _seed_hunt(client, lead_id, findings=[], narrative="Clean.", started=now)
    other = _seed_lead(client)
    _seed_hunt(client, other, findings=[], narrative="Clean.", started=now)
    rows = {r["id"]: r for r in client.get("/api/v1/leads?status=all").json()}
    assert rows[lead_id]["hunt_count"] == 4
    assert rows[lead_id]["hunt_threat_count"] == 3
    # The newest hunt is the clean one, and the pill still names it, in the
    # words of soc_ai.hunting.outcome.OUTCOME_LABEL and lib/labels.ts.
    assert rows[lead_id]["hunt_outcome_label"] == "No threat found"
    assert rows[lead_id]["hunt_outcome"] == "clean"
    detail = client.get(f"/api/v1/hunts/leads/{lead_id}").json()
    assert detail["hunt_outcome"] == "clean" and detail["hunt_threat_count"] == 3
    # Negative control: another lead's hunts count on that lead only.
    assert rows[other]["hunt_count"] == 1 and rows[other]["hunt_threat_count"] == 0


# ---------------------------------------------------------------------------
# The first sentence of a narrative
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "first"),
    [
        ("The host 10.1.2.3 beacons. It does so hourly.", "The host 10.1.2.3 beacons."),
        ("Tools such as e.g. psexec ran. Then more.", "Tools such as e.g. psexec ran."),
        ("# Report\n\n- The hunt found nothing. Done.", "The hunt found nothing."),
        ("", ""),
    ],
)
def test_the_first_sentence_of_a_narrative(text: str, first: str) -> None:
    assert _first_sentence(text) == first


def test_a_long_first_sentence_is_whole() -> None:
    """No sentence is cut. The owner banned the ellipsis cut on 2026-10-07."""
    text = "word " * 100
    out = _first_sentence(text)
    assert out == text.strip()
    assert "…" not in out


# ---------------------------------------------------------------------------
# C8: an observation whose analytic was retired says so, with the date
# ---------------------------------------------------------------------------


def test_an_observation_names_the_day_its_analytic_was_retired(client: TestClient) -> None:
    from soc_ai.store.models import AnalyticState, AnalyticVersion, EntityObservation

    retired_id = "identity-4662-dcsync-nonmachine"
    live_id = "identity-4719-audit-policy-change"
    lead_id = _seed_lead(client, status="open")

    async def go() -> None:
        async with client.app.state.db_sessionmaker() as db:
            db.add(AnalyticState(analytic_id=retired_id, tier="shipped", status="retired"))
            for day, to in ((3, "live"), (1, "retired")):
                db.add(
                    AnalyticVersion(
                        analytic_id=retired_id,
                        from_status="shadow",
                        to_status=to,
                        who="alice",
                        at=datetime(2026, 10, 6 - day, 9, 0),
                        why="two attribute writes",
                    )
                )
            for spec in (retired_id, live_id):
                db.add(
                    EntityObservation(
                        entity_kind="host",
                        entity_key="10.1.2.3",
                        kind="catalog_match",
                        spec_id=spec,
                        fingerprint=spec,
                        lead_id=lead_id,
                        source="catalog",
                        shadow=True,
                    )
                )
            await db.commit()

    asyncio.run(go())
    rows = {
        o["spec_id"]: o for o in client.get(f"/api/v1/hunts/leads/{lead_id}").json()["observations"]
    }
    assert rows[retired_id]["analytic_retired_at"] == "2026-10-05T09:00:00Z"
    # Negative control: an analytic that is not retired carries no date.
    assert rows[live_id]["analytic_retired_at"] is None


# ---------------------------------------------------------------------------
# A lead that formed from backtest replays carries the mark on both surfaces
# ---------------------------------------------------------------------------


def test_a_lead_formed_from_backtest_replays_says_so(client: TestClient) -> None:
    from soc_ai.store.leads import BACKTEST_DECISION, BACKTEST_DECISION_NOTE, record_decision

    marked = _seed_lead(client, status="open")
    plain = _seed_lead(client, status="open")

    async def mark() -> None:
        async with client.app.state.db_sessionmaker() as db:
            lead = await db.get(Lead, marked)
            assert lead is not None
            record_decision(
                lead,
                BACKTEST_DECISION,
                datetime.now(UTC),
                by="soc-ai",
                reason="backtest_replay",
                note=BACKTEST_DECISION_NOTE,
            )
            await db.commit()

    asyncio.run(mark())
    rows = {r["id"]: r for r in client.get("/api/v1/leads?status=all").json()}
    assert rows[marked]["formed_from_backtest"] is True
    # Negative control: a lead with no mark carries none.
    assert rows[plain]["formed_from_backtest"] is False
    detail = client.get(f"/api/v1/hunts/leads/{marked}").json()
    assert detail["formed_from_backtest"] is True
    assert detail["decisions"][-1]["note"] == BACKTEST_DECISION_NOTE


# ---------------------------------------------------------------------------
# S2: a promoted finding's verdict comes back to its lead
# ---------------------------------------------------------------------------


def _seed_finding_investigation(
    client: TestClient,
    inv_id: str,
    hunt_id: str,
    *,
    ordinal: int | None = 0,
    verdict: str | None = "true_positive",
) -> None:
    from soc_ai.store.models import Investigation

    async def go() -> None:
        async with client.app.state.db_sessionmaker() as db:
            db.add(
                Investigation(
                    id=inv_id,
                    alert_es_id="es-1",
                    kind="hunt",
                    hunt_id=hunt_id,
                    finding_ordinal=ordinal,
                    status="complete" if verdict else "running",
                    verdict=verdict,
                    confidence=0.75 if verdict else None,
                    started_by="alice",
                )
            )
            await db.commit()

    asyncio.run(go())


def _hunted_lead_with_promoted_finding(client: TestClient) -> tuple[int, str]:
    lead_id = _seed_lead(client)
    hunt_id = _seed_hunt(
        client,
        lead_id,
        findings=[{"title": "x", "category": "observation"}, _THREAT],
        narrative="The HTTP service ran id as root.",
        started=datetime.now(UTC) - timedelta(hours=3),
    )
    _seed_finding_investigation(client, "01INVFINDING000000000000F2", hunt_id, ordinal=1)
    return lead_id, hunt_id


def test_the_lead_names_the_investigation_of_a_promoted_finding(client: TestClient) -> None:
    lead_id, hunt_id = _hunted_lead_with_promoted_finding(client)
    other = _seed_lead(client)
    other_hunt = _seed_hunt(
        client, other, findings=[_THREAT], narrative="x", started=datetime.now(UTC)
    )
    _seed_finding_investigation(client, "01INVOTHERLEAD00000000000X", other_hunt)
    # A promotion of the lead itself stores no ordinal. It is not a finding.
    _seed_finding_investigation(client, "01INVLEADITSELF0000000000Y", hunt_id, ordinal=None)
    body = client.get(f"/api/v1/hunts/leads/{lead_id}").json()
    assert body["promoted_findings"] == [
        {
            "investigation_id": "01INVFINDING000000000000F2",
            "hunt_id": hunt_id,
            "finding_ordinal": 1,
            "finding_title": "HTTP service runs id as root",
            "promoted_by": "alice",
            "promoted_at": body["promoted_findings"][0]["promoted_at"],
            "status": "complete",
            "verdict": "true_positive",
            "confidence": 0.75,
            "shared_with": [],
        }
    ]


def test_closing_a_lead_as_promoted_takes_it_out_of_needs_you(client: TestClient) -> None:
    lead_id, _hunt = _hunted_lead_with_promoted_finding(client)
    client.app.state.settings = client.app.state.settings.model_copy(
        update={"lead_auto_hunt": False}
    )
    waiting = {r["id"] for r in client.get("/api/v1/leads?status=needs_decision").json()}
    assert lead_id in waiting
    res = client.post(
        f"/api/v1/hunts/leads/{lead_id}/close-promoted",
        json={"investigation_id": "01INVFINDING000000000000F2"},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "promoted"
    assert body["investigation_id"] == "01INVFINDING000000000000F2"
    last = body["decisions"][-1]
    assert last["action"] == "promoted" and last["reason"] == "finding_verdict"
    waiting = {r["id"] for r in client.get("/api/v1/leads?status=needs_decision").json()}
    assert lead_id not in waiting
    # A second click answers with the lead as it stands.
    again = client.post(
        f"/api/v1/hunts/leads/{lead_id}/close-promoted",
        json={"investigation_id": "01INVFINDING000000000000F2"},
    )
    assert again.status_code == 200 and len(again.json()["decisions"]) == len(body["decisions"])


def test_a_lead_closes_only_on_an_investigation_of_its_own_evidence(client: TestClient) -> None:
    # Negative control: an investigation of another lead's finding is a wrong
    # link, and the lead stays open.
    lead_id, _hunt = _hunted_lead_with_promoted_finding(client)
    other = _seed_lead(client)
    other_hunt = _seed_hunt(
        client, other, findings=[_THREAT], narrative="x", started=datetime.now(UTC)
    )
    _seed_finding_investigation(client, "01INVOTHERLEAD00000000000X", other_hunt)
    for inv in ("01INVOTHERLEAD00000000000X", "01NOSUCHINVESTIGATION0000Z"):
        res = client.post(
            f"/api/v1/hunts/leads/{lead_id}/close-promoted", json={"investigation_id": inv}
        )
        assert res.status_code == 422
        assert res.json()["detail"]["reason"] == "not_this_lead"
    assert client.get(f"/api/v1/hunts/leads/{lead_id}").json()["status"] == "hunting"


def test_keep_open_records_the_answer_once_and_keeps_the_status(client: TestClient) -> None:
    lead_id, _hunt = _hunted_lead_with_promoted_finding(client)
    for _ in range(2):
        res = client.post(
            f"/api/v1/hunts/leads/{lead_id}/keep-open",
            json={"investigation_id": "01INVFINDING000000000000F2"},
        )
        assert res.status_code == 200
    body = res.json()
    assert body["status"] == "hunting"
    kept = [d for d in body["decisions"] if d["action"] == "kept_open"]
    assert len(kept) == 1
    assert kept[0]["investigation_id"] == "01INVFINDING000000000000F2"


async def _hold(client: TestClient, lead_id: int, hunt_id: str) -> None:
    from soc_ai.store.leads import record_decision

    async with client.app.state.db_sessionmaker() as db:
        lead = await db.get(Lead, lead_id)
        assert lead is not None
        record_decision(
            lead,
            "held",
            datetime.now(UTC),
            by="auto-hunt",
            reason="partial_read",
            hunt_id=hunt_id,
        )
        await db.commit()


def test_keep_open_leaves_the_hold_in_force(client: TestClient) -> None:
    # A kept-open answer is about the verdict. The hold is about the hunt,
    # and the page still states why the hunt did not close the lead.
    lead_id, hunt_id = _hunted_lead_with_promoted_finding(client)
    asyncio.run(_hold(client, lead_id, hunt_id))
    assert client.get(f"/api/v1/hunts/leads/{lead_id}").json()["hold_reason"] == "partial_read"
    client.post(
        f"/api/v1/hunts/leads/{lead_id}/keep-open",
        json={"investigation_id": "01INVFINDING000000000000F2"},
    )
    assert client.get(f"/api/v1/hunts/leads/{lead_id}").json()["hold_reason"] == "partial_read"


# ---------------------------------------------------------------------------
# W11: the New hunt dialog states the range cap, the run time and plain starters
# ---------------------------------------------------------------------------


def _finished_hunts(client: TestClient, minutes: list[int]) -> None:
    async def go() -> None:
        async with client.app.state.db_sessionmaker() as db:
            for i, m in enumerate(minutes):
                hunt = await hunt_svc.create(db, objective=f"hunt {i}", started_by="admin")
                await hunt_svc.finalize(db, hunt.id, status="complete", narrative="x", report={})
                row = await db.get(Hunt, hunt.id)
                assert row is not None
                start = datetime(2026, 10, 1, 9, 0) + timedelta(hours=i)
                row.created_at = start
                row.finished_at = start + timedelta(minutes=m)
            await db.commit()

    asyncio.run(go())


def test_the_composer_states_the_range_cap_and_the_run_time(client: TestClient) -> None:
    _finished_hunts(client, [4, 5, 5, 6, 7, 8, 9, 30])
    body = client.get("/api/v1/hunts/composer").json()
    # The cap of the event query tool: 43 200 minutes.
    assert body["max_range_days"] == 30
    assert body["run_sample"] == 8
    assert (body["run_minutes_low"], body["run_minutes_high"]) == (5, 8)


def test_the_composer_states_no_run_time_from_too_few_hunts(client: TestClient) -> None:
    # Negative control: four hunts are a guess, so no range is stated.
    _finished_hunts(client, [4, 5, 6, 7])
    body = client.get("/api/v1/hunts/composer").json()
    assert body["run_sample"] == 4
    assert body["run_minutes_low"] is None and body["run_minutes_high"] is None


def test_a_hunt_carries_the_range_the_analyst_chose(client: TestClient) -> None:
    with patch("soc_ai.webui.hunt_console_manager.get_manager") as gm:
        gm.return_value.start = AsyncMock(return_value="01HUNT")
        res = client.post(
            "/api/v1/hunts/chat", json={"objective": "Hunt for beacons.", "range_days": 7}
        )
        assert res.status_code == 200, res.text
        objective = gm.return_value.start.call_args.kwargs["objective"]
    assert objective == "Hunt for beacons.\n\nTime range: the last 7 days."
    # Negative control: a range past the cap is refused before any hunt starts.
    too_far = client.post(
        "/api/v1/hunts/chat", json={"objective": "Hunt for beacons.", "range_days": 31}
    )
    assert too_far.status_code == 422


def test_the_builtin_starters_name_no_tool_and_the_hunt_keeps_the_steer(
    client: TestClient,
) -> None:
    import re

    from soc_ai.so_client.inventory import GridInventory

    with patch(
        "soc_ai.api.webui.routes_hunts.discover_datasets",
        AsyncMock(return_value=GridInventory(datasets=(), window_minutes=1440, live_events=0)),
    ):
        templates = client.get("/api/v1/hunt-templates").json()
    builtins = [t for t in templates if t["builtin"]]
    assert len(builtins) == 7
    for t in builtins:
        assert not re.search(r"\bt_[a-z_]+", t["objectiveTemplate"]), t["name"]
    beacon = next(t for t in builtins if t["name"] == "Beaconing to rare IPs")
    with patch("soc_ai.webui.hunt_console_manager.get_manager") as gm:
        gm.return_value.start = AsyncMock(return_value="01HUNT")
        client.post(
            "/api/v1/hunts/chat",
            json={"objective": beacon["objectiveTemplate"], "template_id": beacon["id"]},
        )
        objective = gm.return_value.start.call_args.kwargs["objective"]
    assert objective.startswith(beacon["objectiveTemplate"])
    assert "t_beacon_profile" in objective and "t_first_seen" in objective
    # Negative control: a custom starter carries no hint.
    from soc_ai.store.hunt_templates import tool_hint_for

    assert tool_hint_for("Beaconing to rare IPs", builtin=False) == ""
