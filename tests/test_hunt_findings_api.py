"""The surfaces of a hunt that investigates its findings.

The hunt row and the hunt page carry the counts, each finding carries its
investigation, the outcome reads the verdicts, the bell titles the hunt by
them, and the recorded hunt runs the phase before it completes.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from pydantic_ai.models.test import TestModel
from soc_ai.agent.context import InvestigationContext
from soc_ai.agent.hunt import HuntFinding, HuntReport
from soc_ai.api.hunt_runner import hunt_recorded_run
from soc_ai.config import Settings
from soc_ai.hunting import outcome as hunt_outcome
from soc_ai.hunting.outcome import FindingVerdicts
from soc_ai.main import create_app
from soc_ai.notify import event_for_hunt
from soc_ai.so_client.elastic import EsSearchResult
from soc_ai.store import hunts as hunt_svc
from soc_ai.store import investigations as inv_svc
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import Hunt
from soc_ai.webui import hunt_findings

from tests.test_hunt_findings_investigated import FakeManager, _finding, _grid

_MGR = "soc_ai.webui.hunt_manager.get_manager"


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    fake_es = AsyncMock()
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=settings_kratos),
    ):
        app = create_app()
        with TestClient(app) as c:
            yield c


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


async def _seed(
    maker: Any,
    findings: list[dict[str, Any]],
    *,
    status: str,
    plan: dict[str, dict[str, Any]],
) -> str:
    async with maker() as db:
        hunt = await hunt_svc.create(db, objective="hunt for beacons", started_by="admin")
        await hunt_svc.finalize(
            db,
            hunt.id,
            status=status,
            narrative="The hunt found beacons.",
            report={"findings": findings, "narrative": "The hunt found beacons."},
            finding_plan=plan,
        )
        return hunt.id


async def _run_row(
    maker: Any,
    hunt_id: str,
    ordinal: int,
    *,
    status: str = "complete",
    verdict: str | None = None,
    report: dict[str, Any] | None = None,
) -> str:
    async with maker() as db:
        inv = await inv_svc.create(
            db,
            alert_es_id=f"tel-doc-{ordinal + 1:08d}",
            started_by="system:hunt",
            kind="hunt",
            hunt_id=hunt_id,
            finding_ordinal=ordinal,
        )
        if status != "running":
            await inv_svc.finalize(
                db, inv.id, status=status, verdict=verdict, confidence=0.83, report=report
            )
        return inv.id


def _entry(state: str, inv_id: str | None = None, origin: str = "opened") -> dict[str, Any]:
    return hunt_svc.plan_entry(state, investigation_id=inv_id, origin=origin if inv_id else None)


def test_an_investigating_hunt_states_its_progress(client: TestClient) -> None:
    maker = client.app.state.db_sessionmaker
    findings = [_finding(1), _finding(2), _finding(3)]

    async def seed() -> tuple[str, str, str]:
        hunt_id = await _seed(maker, findings, status="investigating", plan={})
        done = await _run_row(maker, hunt_id, 0, verdict="true_positive")
        running = await _run_row(maker, hunt_id, 1, status="running")
        async with maker() as db:
            row = await db.get(Hunt, hunt_id)
            assert row is not None
            row.finding_investigations = {
                "0": _entry("ended", done),
                "1": _entry("investigating", running),
                "2": _entry("queued"),
            }
            row.findings_total = 3
            row.findings_investigated = 1
            await db.commit()
        return hunt_id, done, running

    hunt_id, done, running = _run(seed())
    detail = client.get(f"/api/v1/hunts/{hunt_id}").json()
    assert detail["status"] == "investigating"
    assert detail["outcome"] == "investigating"
    assert detail["outcome_label"] == "Investigating 1 of 3 findings"
    assert (detail["findingsInvestigated"], detail["findingsTotal"]) == (1, 3)
    f0, f1, f2 = detail["findings"]
    assert (f0["investigationId"], f0["investigationStatus"], f0["verdict"]) == (
        done,
        "complete",
        "true_positive",
    )
    assert f0["confidence"] == pytest.approx(0.83)
    assert f0["investigation"]["id"] == done
    assert (f1["investigationId"], f1["investigationStatus"]) == (running, "running")
    assert (f2["investigationId"], f2["investigationStatus"]) == (None, "queued")

    row = next(h for h in client.get("/api/v1/hunts").json() if h["id"] == hunt_id)
    assert row["outcome_label"] == "Investigating 1 of 3 findings"
    assert (row["findingsInvestigated"], row["findingsTotal"]) == (1, 3)
    # The status filter knows the phase.
    listed = client.get("/api/v1/hunts", params={"status": "investigating"}).json()
    assert [h["id"] for h in listed] == [hunt_id]


def test_a_complete_hunt_reads_the_verdicts(client: TestClient) -> None:
    maker = client.app.state.db_sessionmaker
    findings = [_finding(1), _finding(2), _finding(3), _finding(4)]
    actions = {
        "recommended_actions": [
            {"kind": "isolate_host", "title": "Isolate 10.0.0.1", "rationale": "beacon"},
            {"kind": "block_ip", "title": "Block 203.0.113.9", "rationale": "c2"},
        ]
    }

    async def seed() -> tuple[str, list[str]]:
        hunt_id = await _seed(maker, findings, status="complete", plan={})
        tp1 = await _run_row(maker, hunt_id, 0, verdict="true_positive", report=actions)
        tp2 = await _run_row(maker, hunt_id, 1, verdict="true_positive")
        fp = await _run_row(maker, hunt_id, 2, verdict="false_positive")
        async with maker() as db:
            row = await db.get(Hunt, hunt_id)
            assert row is not None
            row.finding_investigations = {
                "0": _entry("ended", tp1),
                "1": _entry("ended", tp2),
                "2": _entry("ended", fp),
                "3": _entry("over_cap"),
            }
            row.findings_total = 4
            row.findings_investigated = 3
            await db.commit()
        return hunt_id, [tp1, tp2, fp]

    hunt_id, (tp1, _tp2, _fp) = _run(seed())
    detail = client.get(f"/api/v1/hunts/{hunt_id}").json()
    assert detail["outcome"] == "threats_confirmed"
    assert detail["outcome_label"] == "2 of 4 findings are threats"
    f0, _f1, f2, f3 = detail["findings"]
    # No person can execute an action of a promoted finding: the finding has
    # no Security Onion alert. The action waits for nobody, as on the
    # needs-you count (dogfood 2026-10-20).
    assert f0["pendingActions"] == 0
    # A false positive's actions are housekeeping, as on the needs-you count.
    assert f2["pendingActions"] == 0
    assert (f3["investigationId"], f3["investigationStatus"]) == (None, "over_cap")
    assert f0["investigationId"] == tp1

    # The bell titles the hunt by the verdicts.
    titles = [n["title"] for n in client.get("/api/v1/notifications").json()]
    assert any(t.startswith("Hunt finished: 2 of 4 findings are threats") for t in titles)


def _shared_hunt_findings() -> list[dict[str, Any]]:
    """The lead 5 hunt of 2026-10-19: two threats and an observation on one
    host pair, a gap and a second observation. No finding cites a document.
    An older rule linked the first three to one investigation."""
    pair = ["192.0.2.11", "192.0.2.5"]
    return [
        _finding(1, hosts=pair, citations=[], title="RC4 service ticket for svc_sql"),
        _finding(2, hosts=pair, citations=[], title="Password guessing then success"),
        _finding(
            3, hosts=pair, citations=[], category="observation", title="All abuse is historical"
        ),
        _finding(4, hosts=["192.0.2.5"], citations=[], category="visibility_gap"),
        _finding(5, hosts=["192.0.2.11"], citations=[], category="observation"),
    ]


def test_a_stored_observation_link_does_not_count_as_a_threat(client: TestClient) -> None:
    """A row the older rule wrote: the observation reused the investigation of
    the first threat. The label counts the threat findings over every finding,
    and the observation card borrows no verdict. No migration rewrites the row."""
    maker = client.app.state.db_sessionmaker

    async def seed() -> tuple[str, str]:
        hunt_id = await _seed(maker, _shared_hunt_findings(), status="complete", plan={})
        tp = await _run_row(maker, hunt_id, 0, verdict="true_positive")
        async with maker() as db:
            row = await db.get(Hunt, hunt_id)
            assert row is not None
            row.finding_investigations = {
                "0": _entry("ended", tp),
                "1": _entry("ended", tp, origin="reused"),
                "2": _entry("ended", tp, origin="reused"),
            }
            row.findings_total = 3
            row.findings_investigated = 3
            await db.commit()
        return hunt_id, tp

    hunt_id, tp = _run(seed())
    detail = client.get(f"/api/v1/hunts/{hunt_id}").json()
    assert detail["outcome"] == "threats_confirmed"
    assert detail["outcome_label"] == "2 of 5 findings are threats"
    assert (detail["findingsInvestigated"], detail["findingsTotal"]) == (2, 2)
    f0, f1, f2, f3, f4 = detail["findings"]
    assert (f0["investigationId"], f1["investigationId"]) == (tp, tp)
    # The observation borrows no verdict.
    assert (f2["investigationId"], f2["verdict"], f2["investigationStatus"]) == (None, None, None)
    # Each card names the other finding that shares its investigation.
    assert (f0["sharedWith"], f0["investigationSubject"]) == ([1], 0)
    assert (f1["sharedWith"], f1["investigationSubject"]) == ([0], 0)
    assert f1["investigationOrigin"] == "reused"
    assert (f3["sharedWith"], f4["sharedWith"]) == ([], [])

    row = next(h for h in client.get("/api/v1/hunts").json() if h["id"] == hunt_id)
    assert row["outcome_label"] == "2 of 5 findings are threats"
    assert (row["findingCount"], row["threatFindingCount"]) == (5, 2)


def test_two_threats_that_share_one_run_count_as_two_of_all(client: TestClient) -> None:
    """The lead 18 hunt: the run was opened for F2 and F1 reused it. A gap is
    the third finding. The label read "2 of 2" on a three-finding hunt."""
    maker = client.app.state.db_sessionmaker
    pair = ["192.0.2.40", "192.0.2.10"]
    findings = [
        _finding(1, hosts=pair, citations=[]),
        _finding(2, hosts=pair, citations=[]),
        _finding(3, hosts=["192.0.2.10"], category="visibility_gap"),
    ]

    async def seed() -> tuple[str, str]:
        hunt_id = await _seed(maker, findings, status="complete", plan={})
        tp = await _run_row(maker, hunt_id, 1, verdict="true_positive")
        async with maker() as db:
            row = await db.get(Hunt, hunt_id)
            assert row is not None
            row.finding_investigations = {
                "0": _entry("ended", tp, origin="reused"),
                "1": _entry("ended", tp),
            }
            row.findings_total = 2
            row.findings_investigated = 2
            await db.commit()
        return hunt_id, tp

    hunt_id, _tp = _run(seed())
    detail = client.get(f"/api/v1/hunts/{hunt_id}").json()
    assert detail["outcome_label"] == "2 of 3 findings are threats"
    f0, f1, _f2 = detail["findings"]
    assert (f0["sharedWith"], f0["investigationSubject"]) == ([1], 1)
    assert (f1["sharedWith"], f1["investigationSubject"]) == ([0], 1)


def test_a_lead_soc_ai_closed_on_verdicts_says_so(client: TestClient) -> None:
    """R3-D5: a lead the hunt closed on its finding verdicts read "Promoted",
    the word of an analyst's act. The list and the page send the close."""
    from soc_ai.store import leads as leads_store
    from soc_ai.store.models import Lead

    maker = client.app.state.db_sessionmaker

    async def seed() -> tuple[int, int]:
        ids: list[int] = []
        async with maker() as db:
            for by, reason in (
                (leads_store.SYSTEM_HUNT_ACTOR, leads_store.PROMOTED_FINDING_REASON),
                ("alice", None),
            ):
                lead = Lead(
                    status="open",
                    entities_json=[["host", "192.0.2.11"]],
                    kinds_json=["catalog_match"],
                    weight_at_formation=1.5,
                    shadow=False,
                )
                db.add(lead)
                await db.commit()
                await db.refresh(lead)
                await leads_store.mark_promoted(
                    db, lead.id, investigation_id="INV-1", by=by, reason=reason
                )
                ids.append(int(lead.id))
        return ids[0], ids[1]

    by_soc_ai, by_analyst = _run(seed())
    rows = {r["id"]: r for r in client.get("/api/v1/leads?status=promoted").json()}
    assert rows[by_soc_ai]["closed_by_hunt_verdicts"] is True
    assert rows[by_analyst]["closed_by_hunt_verdicts"] is False
    detail = client.get(f"/api/v1/hunts/leads/{by_soc_ai}").json()
    assert detail["closed_by_hunt_verdicts"] is True


def test_a_lead_held_on_a_finding_with_no_verdict_states_the_reason(client: TestClient) -> None:
    """Prod lead 47 (2026-10-24): the hunt investigated three subject
    findings, one run ended in error, and the lead waited in 'hunting' with
    no reason on its page. The page now names the hold."""
    from soc_ai.store import leads as leads_store
    from soc_ai.store.models import Lead

    maker = client.app.state.db_sessionmaker
    findings = [_finding(n, hosts=[f"192.0.2.{n}"], detail=f"Host 192.0.2.{n}.") for n in (1, 2, 3)]

    async def seed() -> int:
        async with maker() as db:
            lead = Lead(
                status="open",
                entities_json=[["host", "192.0.2.1"]],
                kinds_json=["alert"],
                weight_at_formation=1.5,
                shadow=False,
            )
            db.add(lead)
            await db.commit()
            await db.refresh(lead)
            hunt = await hunt_svc.create(
                db, objective="hunt", started_by="auto-hunt", kind="lead", lead_id=lead.id
            )
            hunt_id = hunt.id
            lead_id = int(lead.id)
        runs = [
            await _run_row(maker, hunt_id, 0, verdict="true_positive"),
            await _run_row(maker, hunt_id, 1, status="error"),
            await _run_row(maker, hunt_id, 2, verdict="true_positive"),
        ]
        async with maker() as db:
            await hunt_svc.finalize(
                db,
                hunt_id,
                status="complete",
                report={"findings": findings},
                finding_plan={str(i): _entry("ended", r) for i, r in enumerate(runs)},
            )
            await leads_store.mark_hunting(db, lead_id, hunt_id=hunt_id)
            row = await db.get(Hunt, hunt_id)
            assert row is not None
            assert await leads_store.settle_after_hunt(db, row) == "waits"
        return lead_id

    lead_id = _run(seed())
    detail = client.get(f"/api/v1/hunts/leads/{lead_id}").json()
    assert detail["status"] == "hunting"
    assert detail["hunt_status"] == "complete"
    assert detail["hold_reason"] == "no_verdict"
    assert detail["hold_sentence"] == "A threat finding of the hunt has no verdict."
    held = detail["decisions"][-1]
    assert (held["action"], held["reason"]) == ("held", "no_verdict")


def test_a_reused_run_of_another_hunt_answers_on_the_hunt_page_and_settles_the_lead(
    client: TestClient,
) -> None:
    """The held lead's remedy is "re-run the investigation of that finding".
    When a run of another hunt with the same subject answers (change E), the
    route returned it and left the finding's entry on the failed run. The
    lead stayed held on each press, and the hunt page still read failed. The
    route now names the reused run on the finding's entry, the same way the
    hunt phase records a reuse."""
    from soc_ai.hunting.findings import subject_fingerprint
    from soc_ai.store import leads as leads_store
    from soc_ai.store.models import Lead

    maker = client.app.state.db_sessionmaker
    findings = [
        _finding(n, hosts=[f"192.0.2.{n}"], citations=[f"tel-doc-{n:08d}"]) for n in (1, 2, 3)
    ]
    fingerprint = subject_fingerprint(findings[1])

    async def seed() -> tuple[int, str, str, str]:
        async with maker() as db:
            lead = Lead(
                status="open",
                entities_json=[["host", "192.0.2.1"]],
                kinds_json=["alert"],
                weight_at_formation=1.5,
                shadow=False,
            )
            db.add(lead)
            await db.commit()
            await db.refresh(lead)
            hunt = await hunt_svc.create(
                db, objective="hunt", started_by="auto-hunt", kind="lead", lead_id=lead.id
            )
            other = await hunt_svc.create(
                db, objective="other hunt", started_by="auto-hunt", kind="lead"
            )
            hunt_id, lead_id = hunt.id, int(lead.id)
            reused = await inv_svc.create(
                db,
                alert_es_id="tel-doc-00000002",
                started_by="system:hunt",
                kind="hunt",
                hunt_id=other.id,
                finding_ordinal=0,
                subject={
                    "type": "hunt",
                    "hunt_id": other.id,
                    "subject_fingerprint": fingerprint,
                    "judges": "finding",
                },
            )
            await inv_svc.finalize(
                db, reused.id, status="complete", verdict="true_positive", confidence=0.8
            )
        runs = [
            await _run_row(maker, hunt_id, 0, verdict="true_positive"),
            await _run_row(maker, hunt_id, 1, status="error"),
            await _run_row(maker, hunt_id, 2, verdict="true_positive"),
        ]
        async with maker() as db:
            await hunt_svc.finalize(
                db,
                hunt_id,
                status="complete",
                report={"findings": findings},
                finding_plan={str(i): _entry("ended", r) for i, r in enumerate(runs)},
            )
            await leads_store.mark_hunting(db, lead_id, hunt_id=hunt_id)
            row = await db.get(Hunt, hunt_id)
            assert row is not None
            assert await leads_store.settle_after_hunt(db, row) == "waits"
        return lead_id, hunt_id, reused.id, runs[1]

    lead_id, hunt_id, reused, failed = _run(seed())
    body = client.post(f"/api/v1/hunts/{hunt_id}/findings/1/investigate").json()
    assert body == {"investigation_id": reused, "existing": True}

    async def settle() -> tuple[str, str, Any]:
        async with maker() as db:
            row = await db.get(Hunt, hunt_id)
            assert row is not None
            link = hunt_svc.finding_links(row)[1]
            out = await leads_store.settle_after_hunt(db, row)
            lead = await db.get(Lead, lead_id)
            assert lead is not None
            return out, str(lead.status), link

    out, status, link = _run(settle())
    assert (link.investigation_id, link.state, link.origin) == (
        reused,
        hunt_svc.LINK_ENDED,
        hunt_svc.ORIGIN_REUSED,
    )
    assert link.investigation_id != failed
    assert (out, status) == ("closed", "promoted")
    f2 = client.get(f"/api/v1/hunts/{hunt_id}").json()["findings"][1]
    assert (f2["investigationId"], f2["investigationStatus"], f2["verdict"]) == (
        reused,
        "complete",
        "true_positive",
    )


def test_a_reused_running_run_reads_investigating_on_the_finding(client: TestClient) -> None:
    """The reused run still runs, so the finding's entry reads investigating."""
    from soc_ai.hunting.findings import subject_fingerprint

    maker = client.app.state.db_sessionmaker
    findings = [_finding(1, hosts=["192.0.2.1"], citations=["tel-doc-00000001"])]

    async def seed() -> tuple[str, str]:
        hunt_id = await _seed(maker, findings, status="complete", plan={})
        failed = await _run_row(maker, hunt_id, 0, status="error")
        async with maker() as db:
            other = await hunt_svc.create(db, objective="other hunt", started_by="admin")
            running = await inv_svc.create(
                db,
                alert_es_id="tel-doc-00000001",
                started_by="system:hunt",
                kind="hunt",
                hunt_id=other.id,
                finding_ordinal=0,
                subject={
                    "type": "hunt",
                    "hunt_id": other.id,
                    "subject_fingerprint": subject_fingerprint(findings[0]),
                },
            )
            await hunt_svc.set_finding_link(db, hunt_id, 0, "ended", investigation_id=failed)
        return hunt_id, running.id

    hunt_id, running = _run(seed())
    body = client.post(f"/api/v1/hunts/{hunt_id}/findings/0/investigate").json()
    assert body == {"investigation_id": running, "existing": True}

    async def link() -> Any:
        async with maker() as db:
            row = await db.get(Hunt, hunt_id)
            return hunt_svc.finding_links(row)[0]

    entry = _run(link())
    assert (entry.investigation_id, entry.state, entry.origin) == (
        running,
        hunt_svc.LINK_INVESTIGATING,
        hunt_svc.ORIGIN_REUSED,
    )


def test_a_failed_investigation_reads_failed_and_offers_the_manual_control(
    client: TestClient,
) -> None:
    maker = client.app.state.db_sessionmaker

    async def seed() -> str:
        hunt_id = await _seed(maker, [_finding(1), _finding(2)], status="complete", plan={})
        failed = await _run_row(maker, hunt_id, 0, status="error")
        async with maker() as db:
            row = await db.get(Hunt, hunt_id)
            assert row is not None
            row.finding_investigations = {
                "0": _entry("ended", failed),
                "1": hunt_svc.plan_entry("failed", reason="grid_unavailable"),
            }
            row.findings_total = 2
            row.findings_investigated = 2
            await db.commit()
        return hunt_id

    hunt_id = _run(seed())
    detail = client.get(f"/api/v1/hunts/{hunt_id}").json()
    f0, f1 = detail["findings"]
    assert f0["investigationStatus"] == "failed"
    assert f1["investigationStatus"] == "failed"
    assert f1["investigationId"] is None
    # No verdict landed, so the hunt keeps the outcome its report gives.
    assert detail["outcome"] == "threat_found"


def test_all_false_positives_read_no_threat_confirmed(client: TestClient) -> None:
    maker = client.app.state.db_sessionmaker

    async def seed() -> str:
        hunt_id = await _seed(maker, [_finding(1)], status="complete", plan={})
        fp = await _run_row(maker, hunt_id, 0, verdict="false_positive")
        async with maker() as db:
            await hunt_svc.set_finding_link(db, hunt_id, 0, "ended", investigation_id=fp)
            row = await db.get(Hunt, hunt_id)
            assert row is not None
            row.findings_total = 1
            await db.commit()
        return hunt_id

    hunt_id = _run(seed())
    detail = client.get(f"/api/v1/hunts/{hunt_id}").json()
    assert detail["outcome"] == "no_threat_confirmed"
    assert detail["outcome_label"] == "No threat confirmed"
    titles = [n["title"] for n in client.get("/api/v1/notifications").json()]
    assert any(t.startswith("Hunt finished: no threat confirmed.") for t in titles)


def test_a_legacy_hunt_keeps_its_outcome_and_zero_counts(client: TestClient) -> None:
    """Control: a hunt from before the phase has no plan and no counts."""
    maker = client.app.state.db_sessionmaker
    hunt_id = _run(_seed(maker, [_finding(1)], status="complete", plan={}))
    detail = client.get(f"/api/v1/hunts/{hunt_id}").json()
    assert detail["outcome"] == "threat_found"
    assert (detail["findingsInvestigated"], detail["findingsTotal"]) == (0, 0)
    assert detail["findings"][0]["investigationStatus"] is None
    assert detail["findings"][0]["pendingActions"] == 0


def test_the_manual_control_on_an_over_cap_finding_names_the_run(client: TestClient) -> None:
    maker = client.app.state.db_sessionmaker

    async def seed() -> str:
        return await _seed(
            maker, [_finding(1)], status="complete", plan={"0": hunt_svc.plan_entry("over_cap")}
        )

    hunt_id = _run(seed())
    mgr = FakeManager(maker)
    hits = [{"_id": "tel-doc-00000001", "_source": {"event": {"dataset": "zeek.conn"}}}]
    from soc_ai.so_client.elastic import ElasticClient

    with (
        patch(_MGR, return_value=mgr),
        patch.object(
            ElasticClient,
            "search",
            AsyncMock(return_value=EsSearchResult(total=1, took_ms=1, hits=hits)),
        ),
    ):
        resp = client.post(f"/api/v1/hunts/{hunt_id}/findings/0/investigate")
        assert resp.status_code == 200
        inv_id = resp.json()["investigation_id"]
        # A second press returns the same run.
        again = client.post(f"/api/v1/hunts/{hunt_id}/findings/0/investigate").json()
    assert again == {"investigation_id": inv_id, "existing": True}
    assert len(mgr.started) == 1
    assert mgr.started[0]["started_by"] != "system:hunt"
    assert mgr.started[0]["subject"].subject_fingerprint

    async def link() -> Any:
        async with maker() as db:
            row = await db.get(Hunt, hunt_id)
            return hunt_svc.finding_links(row)[0]

    entry = _run(link())
    assert (entry.investigation_id, entry.origin) == (inv_id, hunt_svc.ORIGIN_MANUAL)


def test_the_promote_route_never_returns_the_run_of_another_finding_of_the_hunt(
    client: TestClient,
) -> None:
    """Change E. F0 and F1 of one hunt name the same hosts and cite the same
    document, so they share a subject fingerprint. The run of F1 judged the
    claim of F1, and the button on F0 starts a run of its own."""
    from soc_ai.hunting.findings import subject_fingerprint
    from soc_ai.so_client.elastic import ElasticClient

    maker = client.app.state.db_sessionmaker
    pair = ["192.0.2.10", "192.0.2.20"]
    doc = ["tel-doc-00000050"]
    findings = [
        _finding(1, hosts=pair, citations=doc, title="Web shell upload to the web server"),
        _finding(2, hosts=pair, citations=doc, title="Repeated exploit variants"),
    ]
    assert subject_fingerprint(findings[0]) == subject_fingerprint(findings[1])

    async def seed() -> tuple[str, str]:
        hunt_id = await _seed(maker, findings, status="complete", plan={})
        async with maker() as db:
            inv = await inv_svc.create(
                db,
                alert_es_id=doc[0],
                started_by="system:hunt",
                kind="hunt",
                hunt_id=hunt_id,
                finding_ordinal=1,
                subject={
                    "type": "hunt",
                    "hunt_id": hunt_id,
                    "subject_fingerprint": subject_fingerprint(findings[1]),
                    "judges": "finding",
                },
            )
            await inv_svc.finalize(
                db, inv.id, status="complete", verdict="true_positive", confidence=0.8
            )
        return hunt_id, inv.id

    hunt_id, sibling = _run(seed())
    mgr = FakeManager(maker)
    hits = [{"_id": doc[0], "_source": {"event": {"dataset": "suricata.alert"}}}]
    with (
        patch(_MGR, return_value=mgr),
        patch.object(
            ElasticClient,
            "search",
            AsyncMock(return_value=EsSearchResult(total=1, took_ms=1, hits=hits)),
        ),
    ):
        resp = client.post(f"/api/v1/hunts/{hunt_id}/findings/0/investigate")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "existing" not in body
    assert body["investigation_id"] != sibling
    assert len(mgr.started) == 1


def test_delete_refuses_an_investigating_hunt(client: TestClient) -> None:
    maker = client.app.state.db_sessionmaker
    hunt_id = _run(_seed(maker, [_finding(1)], status="investigating", plan={}))
    resp = client.delete(f"/api/v1/hunts/{hunt_id}")
    assert resp.status_code == 409


# ── outcome words ────────────────────────────────────────────────────────────


def test_the_outcome_labels_count_the_findings() -> None:
    three = FindingVerdicts(total=3, investigated=2, decided=2, threats=2)
    assert hunt_outcome.outcome_label("investigating", three) == "Investigating 2 of 3 findings"
    assert hunt_outcome.outcome_label("threats_confirmed", three) == "2 of 3 findings are threats"
    one = FindingVerdicts(total=1, investigated=1, decided=1, threats=1)
    assert hunt_outcome.outcome_label("threats_confirmed", one) == "1 of 1 finding is a threat"
    assert hunt_outcome.outcome_label("no_threat_confirmed", one) == "No threat confirmed"
    assert hunt_outcome.outcome_label("threats_confirmed") == "Threats confirmed"
    assert hunt_outcome.outcome_label("no_answer") == "No answer"
    # The threats are counted over every finding of the report when the
    # summary knows that count.
    five = FindingVerdicts(total=2, investigated=2, decided=2, threats=2, findings=5)
    assert hunt_outcome.outcome_label("threats_confirmed", five) == "2 of 5 findings are threats"
    for key in hunt_outcome.OUTCOMES:
        assert hunt_outcome.OUTCOME_LABEL[key]


def test_public_outcome_reads_the_verdicts_only_when_one_landed() -> None:
    threat = [_finding(1)]
    decided = FindingVerdicts(total=2, investigated=2, decided=2, threats=0)
    assert hunt_outcome.public_outcome("investigating", threat) == "investigating"
    assert hunt_outcome.public_outcome("complete", threat, None, decided) == "no_threat_confirmed"
    tp = FindingVerdicts(total=2, investigated=2, decided=1, threats=1)
    assert hunt_outcome.public_outcome("complete", threat, None, tp) == "threats_confirmed"
    # Control: no verdict landed, the report decides.
    none = FindingVerdicts(total=2, investigated=2, decided=0, threats=0)
    assert hunt_outcome.public_outcome("complete", threat, None, none) == "threat_found"
    # A stopped hunt is a stopped hunt whatever its findings decided.
    assert hunt_outcome.public_outcome("error", threat, None, tp) == "could_not_run"


# ── the webhook ──────────────────────────────────────────────────────────────


def test_the_webhook_names_the_confirmed_threats(settings_kratos: Settings) -> None:
    settings = settings_kratos.model_copy(update={"notify_on_hunt_threat": True})
    report = {"findings": [_finding(1), _finding(2), _finding(3)]}
    tp = FindingVerdicts(total=3, investigated=3, decided=3, threats=2)
    event = event_for_hunt(hunt_id="H1", report=report, settings=settings, verdicts=tp)
    assert event is not None
    assert event.title == "Hunt finished: 2 of 3 findings are threats"
    clean = FindingVerdicts(total=3, investigated=3, decided=3, threats=0)
    assert event_for_hunt(hunt_id="H1", report=report, settings=settings, verdicts=clean) is None
    # Control: with no verdict the report's threat finding still pages.
    legacy = event_for_hunt(hunt_id="H1", report=report, settings=settings)
    assert legacy is not None
    assert legacy.title == "Hunt found a threat"


def test_the_bell_line_of_an_investigating_hunt() -> None:
    from soc_ai.api.webui.routes_meta import _hunt_in_flight

    row = hunt_svc.HuntNotifRow(
        id="H1",
        objective="hunt for beacons",
        status="investigating",
        created_at=datetime(2026, 10, 7, 9, 0),
        finished_at=None,
        findings_count=3,
        threat_findings_count=3,
        is_synth_eval=False,
        findings_total=3,
        findings_investigated=1,
    )
    notice = _hunt_in_flight(row)
    assert notice.title == "Hunt: hunt for beacons. Investigating 1 of 3 findings."
    assert notice.outcome == "investigating"
    # The chip says "Running", so the line names the hunt only.
    running = _hunt_in_flight(row._replace(status="running"))
    assert running.title == "Hunt: hunt for beacons"
    assert running.outcome == "running"


def test_the_bell_line_of_a_lead_hunt_names_the_hunt_once() -> None:
    """The bell read "Hunt running: Lead 19 hunt: 192.0.2.20" beside a Running chip.

    A lead hunt title already names the hunt (dogfood 2026-10-19, R1 STE 17).
    """
    from soc_ai.api.webui.routes_meta import _hunt_in_flight

    row = hunt_svc.HuntNotifRow(
        id="H2",
        objective="[lead 19] Investigate 192.0.2.20. The lead formed.\nObservations:\n- a",
        status="running",
        created_at=datetime(2026, 10, 7, 9, 0),
        finished_at=None,
        findings_count=0,
        threat_findings_count=0,
        is_synth_eval=False,
        findings_total=0,
        findings_investigated=0,
    )
    assert _hunt_in_flight(row).title == "Lead 19 hunt: 192.0.2.20"
    counted = row._replace(status="investigating", findings_total=2, findings_investigated=1)
    assert _hunt_in_flight(counted).title == (
        "Lead 19 hunt: 192.0.2.20. Investigating 1 of 2 findings."
    )


# ── the recorded hunt ────────────────────────────────────────────────────────


def _report(citation: str) -> HuntReport:
    return HuntReport(
        findings=[
            HuntFinding(
                title="Beaconing to a rare external address",
                detail="10.0.0.5 calls out every 60 s.",
                severity="high",
                hosts=["10.0.0.5"],
                citations=[citation],
            )
        ],
        narrative="One host beacons to a rare external address.",
        affected_hosts=["10.0.0.5"],
        confidence=0.7,
    )


async def _recorded(settings: Settings, citation: str) -> tuple[Any, str, FakeManager]:
    engine = make_engine(settings)
    await run_migrations(engine)
    maker = make_sessionmaker(engine)
    state = SimpleNamespace(db_sessionmaker=maker, settings=settings)
    ctx = InvestigationContext(
        settings=settings, auth=MagicMock(), elastic=_grid(), db_sessionmaker=maker
    )
    mgr = FakeManager(maker, verdicts={0: "true_positive"})
    read = EsSearchResult(
        total=1, took_ms=1, hits=[{"_id": citation, "_source": {"event": {"dataset": "zeek"}}}]
    )
    hunt_id = ""
    with (
        patch(
            "soc_ai.api.hunt_runner.build_investigator_model",
            return_value=TestModel(
                call_tools=["t_query_events_oql"], custom_output_args=_report(citation)
            ),
        ),
        patch("soc_ai.agent.toolset.query_events_oql", AsyncMock(return_value=read)),
        patch(_MGR, return_value=mgr),
    ):
        async for name, data in hunt_recorded_run(
            state, ctx=ctx, objective="beaconing", started_by="admin"
        ):
            if name == "hunt_created":
                hunt_id = data["hunt_id"]
    return engine, hunt_id, mgr


def test_the_recorded_hunt_investigates_its_finding_before_it_completes(
    settings_kratos: Settings,
) -> None:
    async def go() -> None:
        engine, hunt_id, mgr = await _recorded(settings_kratos, "tel-doc-00000005")
        maker = make_sessionmaker(engine)
        async with maker() as db:
            hunt = await db.get(Hunt, hunt_id)
            assert hunt is not None
            assert hunt.status == "complete"
            assert (hunt.findings_total, hunt.findings_investigated) == (1, 1)
        assert [s["started_by"] for s in mgr.started] == [hunt_findings.SYSTEM_HUNT_ACTOR]
        assert mgr.started[0]["hunt_id"] == hunt_id
        await engine.dispose()

    asyncio.run(go())


def test_a_recorded_hunt_whose_finding_cites_no_document_reports_the_failure(
    settings_kratos: Settings,
) -> None:
    """A finding that names a host and cites no document is a subject. The
    anchor rule refuses it, the finding reads failed with the reason, no run
    starts, and the hunt completes. The range re-hunt of 2026-10-07 reported
    such a finding, and a citation rule left it uninvestigated and uncounted."""

    async def go() -> None:
        engine, hunt_id, mgr = await _recorded(settings_kratos, "es-abc")
        maker = make_sessionmaker(engine)
        async with maker() as db:
            hunt = await db.get(Hunt, hunt_id)
            assert hunt is not None
            assert hunt.status == "complete"
            assert hunt.findings_total == 1
            entries = hunt.finding_investigations or {}
            assert entries["0"]["state"] == "failed"
            assert entries["0"].get("reason")
        assert mgr.started == []
        await engine.dispose()

    asyncio.run(go())


def test_the_system_path_records_no_observation(settings_kratos: Settings) -> None:
    """An observation per finding would form a lead on the host of every lead hunt."""
    from soc_ai.store.models import EntityObservation
    from sqlalchemy import func, select

    async def go() -> None:
        engine, _hunt_id, _mgr = await _recorded(settings_kratos, "tel-doc-00000005")
        maker = make_sessionmaker(engine)
        async with maker() as db:
            count = await db.scalar(select(func.count(EntityObservation.id)))
        assert count == 0
        await engine.dispose()

    asyncio.run(go())


def test_the_lead_pages_label_a_hunt_by_its_finding_verdicts() -> None:
    """The lead list and the lead page name the hunt by the server label with
    its counts, the words the hunt page prints. Without the verdict summary
    the label read "Threat found" beside a hunt page that read "2 of 2
    findings are threats"."""
    from soc_ai.api.webui.routes_hunts import _lead_hunt_out, _lead_hunt_state
    from soc_ai.hunting.outcome import FindingVerdicts

    hunt = Hunt(
        id="H-V",
        objective="o",
        kind="lead",
        status="complete",
        narrative="Two hosts scan each other.",
        report={
            "findings": [
                {"title": "Scan", "detail": "d", "severity": "high", "hosts": ["10.0.0.5"]},
                {"title": "Scan 2", "detail": "d", "severity": "high", "hosts": ["10.0.0.6"]},
            ]
        },
        findings_total=2,
        findings_investigated=2,
        created_at=datetime.now(UTC),
    )
    verdicts = FindingVerdicts(total=2, investigated=2, decided=2, threats=2)
    assert _lead_hunt_state(hunt, verdicts) == ("complete", "2 of 2 findings are threats")
    assert _lead_hunt_out(hunt, 3, verdicts).outcome_label == "2 of 2 findings are threats"
    # Control: with no summary the report's own outcome stands.
    assert _lead_hunt_state(hunt, None)[1] == "Threat found"
