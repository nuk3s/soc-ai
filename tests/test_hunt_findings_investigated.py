"""A hunt investigates its subject findings as part of the hunt.

The owner's decision of 2026-10-07: "A hunt's findings should ALWAYS be
investigated and that should be part of the hunt." These tests drive the
investigation phase (soc_ai.webui.hunt_findings) against a real store, a fake
grid that answers id lookups, and a fake investigation manager that records
each start and lands each run when the test opens its gate.
"""

from __future__ import annotations

import asyncio
from datetime import timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from soc_ai.agent.context import InvestigationContext
from soc_ai.config import Settings
from soc_ai.hunting.findings import subject_fingerprint
from soc_ai.so_client.elastic import EsSearchResult
from soc_ai.store import hunts as hunt_svc
from soc_ai.store import investigations as inv_svc
from soc_ai.store import leads as leads_store
from soc_ai.store.auth import utcnow
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import EntityObservation, Hunt, Investigation, Lead
from soc_ai.webui import hunt_findings
from sqlalchemy import select

_MGR = "soc_ai.webui.hunt_manager.get_manager"


# ── fakes ────────────────────────────────────────────────────────────────────


def _grid() -> Any:
    """An Elasticsearch client that resolves every id it is asked for."""

    async def _search(_index: str, query: dict[str, Any], **_kw: Any) -> EsSearchResult:
        ids = (query.get("ids") or {}).get("values") or []
        hits = [{"_id": i, "_source": {"event": {"dataset": "zeek.conn"}}} for i in ids]
        return EsSearchResult(total=len(hits), took_ms=1, hits=hits)

    return SimpleNamespace(search=AsyncMock(side_effect=_search))


class FakeManager:
    """Stands in for the investigation manager.

    ``start`` writes a real investigation row with the kwargs it was given and
    starts a task that lands the run when its gate opens. ``verdicts`` maps a
    finding ordinal to the verdict its run lands, or "error".
    """

    def __init__(self, maker: Any, *, verdicts: dict[int, str] | None = None, auto: bool = True):
        self.maker = maker
        self.verdicts = verdicts or {}
        self.auto = auto
        self.tasks: dict[str, asyncio.Task[None]] = {}
        self.gates: dict[str, asyncio.Event] = {}
        self.started: list[dict[str, Any]] = []
        self.cancelled: list[str] = []
        self.live = 0
        self.max_live = 0

    async def start(self, _state: Any, **kw: Any) -> str:
        subject = kw.get("subject")
        async with self.maker() as db:
            inv = await inv_svc.create(
                db,
                alert_es_id=kw["alert_id"],
                started_by=kw["started_by"],
                rule_name=kw.get("rule_name"),
                kind=kw.get("kind", "suricata"),
                hunt_id=kw.get("hunt_id"),
                finding_ordinal=kw.get("finding_ordinal"),
                is_synth_eval=kw.get("is_synth_eval", False),
                subject=subject.as_record() if subject is not None else None,
            )
        self.started.append({**kw, "inv_id": inv.id})
        gate = asyncio.Event()
        if self.auto:
            gate.set()
        self.gates[inv.id] = gate
        self.tasks[inv.id] = asyncio.create_task(self._run(inv.id, kw.get("finding_ordinal"), gate))
        return inv.id

    async def _run(self, inv_id: str, ordinal: int | None, gate: asyncio.Event) -> None:
        self.live += 1
        self.max_live = max(self.max_live, self.live)
        try:
            await gate.wait()
            verdict = self.verdicts.get(ordinal if ordinal is not None else -1, "false_positive")
            async with self.maker() as db:
                if verdict == "error":
                    await inv_svc.finalize(db, inv_id, status="error")
                else:
                    await inv_svc.finalize(
                        db, inv_id, status="complete", verdict=verdict, confidence=0.82
                    )
        except asyncio.CancelledError:
            async with self.maker() as db:
                await inv_svc.finalize(db, inv_id, status="cancelled")
            raise
        finally:
            self.live -= 1

    async def wait(self, inv_id: str) -> None:
        task = self.tasks.get(inv_id)
        if task is not None and not task.done():
            await asyncio.wait({task})

    def is_live(self, inv_id: str) -> bool:
        task = self.tasks.get(inv_id)
        return task is not None and not task.done()

    def cancel(self, inv_id: str) -> bool:
        task = self.tasks.get(inv_id)
        if task is None or task.done():
            return False
        self.cancelled.append(inv_id)
        task.cancel()
        return True


# ── helpers ──────────────────────────────────────────────────────────────────


def _finding(n: int, *, severity: str = "high", **over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "title": f"Beacon from host {n}",
        "detail": f"Host 10.0.0.{n} calls out on a fixed cadence.",
        "severity": severity,
        "category": "threat",
        "hosts": [f"10.0.0.{n}"],
        "citations": [f"tel-doc-{n:08d}"],
    }
    base.update(over)
    return base


async def _store(settings: Settings) -> tuple[Any, Any]:
    engine = make_engine(settings)
    await run_migrations(engine)
    return engine, make_sessionmaker(engine)


def _state(maker: Any, settings: Settings) -> Any:
    return SimpleNamespace(db_sessionmaker=maker, settings=settings)


def _ctx(settings: Settings, maker: Any) -> InvestigationContext:
    return InvestigationContext(
        settings=settings, auth=MagicMock(), elastic=_grid(), db_sessionmaker=maker
    )


async def _investigating_hunt(
    maker: Any,
    settings: Settings,
    findings: list[dict[str, Any]],
    *,
    lead_id: int | None = None,
) -> tuple[str, hunt_findings.FindingPlan]:
    """A hunt in the state the recorder leaves it: report landed, plan written."""
    report = {"findings": findings, "narrative": "The hunt found beacons."}
    plan = hunt_findings.plan_findings(report, settings)
    assert plan is not None
    async with maker() as db:
        hunt = await hunt_svc.create(
            db,
            objective="hunt for beacons",
            started_by="admin",
            kind="lead" if lead_id else "chat",
            lead_id=lead_id,
        )
        await hunt_svc.finalize(
            db,
            hunt.id,
            status=hunt_svc.STATUS_INVESTIGATING,
            narrative=report["narrative"],
            report=report,
            finding_plan=plan.as_column(),
        )
        return hunt.id, plan


async def _hunt(maker: Any, hunt_id: str) -> Hunt:
    async with maker() as db:
        hunt = await db.get(Hunt, hunt_id)
        assert hunt is not None
        return hunt


async def _runs(maker: Any) -> list[Investigation]:
    async with maker() as db:
        return list(
            (await db.scalars(select(Investigation).order_by(Investigation.created_at))).all()
        )


async def _run_phase(
    settings: Settings, maker: Any, mgr: FakeManager, hunt_id: str, plan: Any
) -> Any:
    with patch(_MGR, return_value=mgr):
        return await hunt_findings.investigate_findings(
            _state(maker, settings), hunt_id=hunt_id, ctx=_ctx(settings, maker), plan=plan
        )


# ── the plan ─────────────────────────────────────────────────────────────────


def test_the_plan_takes_subjects_in_priority_order_and_splits_at_the_cap(
    settings_kratos: Settings,
) -> None:
    settings = settings_kratos.model_copy(update={"hunt_findings_investigate_max": 2})
    findings = [
        _finding(1, severity="low"),
        _finding(2, category="visibility_gap"),
        _finding(3, severity="critical"),
        _finding(4, severity="high"),
    ]
    plan = hunt_findings.plan_findings({"findings": findings}, settings)
    assert plan is not None
    assert plan.queued == [2, 3]
    assert plan.over_cap == [0]
    assert plan.total == 3


def test_no_subject_and_the_switch_off_plan_nothing(settings_kratos: Settings) -> None:
    gaps = {"findings": [_finding(1, category="visibility_gap"), _finding(2, hosts=[])]}
    assert hunt_findings.plan_findings(gaps, settings_kratos) is None
    off = settings_kratos.model_copy(update={"hunt_findings_investigate": False})
    assert hunt_findings.plan_findings({"findings": [_finding(1)]}, off) is None
    # Control: the same report with the switch on plans one finding.
    assert hunt_findings.plan_findings({"findings": [_finding(1)]}, settings_kratos) is not None


def test_the_settings_default_on_with_a_cap_of_20() -> None:
    fields = Settings.model_fields
    assert fields["hunt_findings_investigate"].default is True
    assert fields["hunt_findings_investigate_max"].default == 20


# ── the phase ────────────────────────────────────────────────────────────────


async def test_three_findings_under_a_cap_of_two_open_two_and_queue_one(
    settings_kratos: Settings,
) -> None:
    settings = settings_kratos.model_copy(update={"hunt_findings_investigate_max": 2})
    engine, maker = await _store(settings)
    findings = [_finding(1, severity="low"), _finding(2), _finding(3, severity="critical")]
    hunt_id, plan = await _investigating_hunt(maker, settings, findings)
    mgr = FakeManager(maker, verdicts={2: "true_positive"})

    verdicts = await _run_phase(settings, maker, mgr, hunt_id, plan)

    # The two workers open the two highest findings at the same time.
    assert {s["finding_ordinal"] for s in mgr.started} == {1, 2}
    assert {s["started_by"] for s in mgr.started} == {"system:hunt"}
    assert {s["kind"] for s in mgr.started} == {"hunt"}
    assert all(s["hunt_id"] == hunt_id for s in mgr.started)
    assert all(s["allow_so_writes"] is False for s in mgr.started)
    hunt = await _hunt(maker, hunt_id)
    assert hunt.status == "complete"
    assert (hunt.findings_total, hunt.findings_investigated) == (3, 2)
    links = hunt_svc.finding_links(hunt)
    assert links[0].state == hunt_svc.LINK_OVER_CAP
    assert links[0].investigation_id is None
    assert {links[1].state, links[2].state} == {hunt_svc.LINK_ENDED}
    assert verdicts is not None
    assert (verdicts.total, verdicts.decided, verdicts.threats) == (3, 2, 1)
    # The subject record carries the fingerprint, so a later hunt can reuse it.
    runs = await _runs(maker)
    assert {r.subject_json["subject_fingerprint"] for r in runs} == {
        subject_fingerprint(findings[1]),
        subject_fingerprint(findings[2]),
    }
    await engine.dispose()


async def test_two_investigations_run_at_a_time_in_priority_order(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _store(settings_kratos)
    findings = [
        _finding(1, severity="low"),
        _finding(2, severity="medium"),
        _finding(3, severity="critical"),
        _finding(4, severity="high"),
    ]
    hunt_id, plan = await _investigating_hunt(maker, settings_kratos, findings)
    mgr = FakeManager(maker, auto=False)
    phase = asyncio.create_task(_run_phase(settings_kratos, maker, mgr, hunt_id, plan))

    async def started(n: int) -> None:
        for _ in range(400):
            if len(mgr.started) >= n:
                return
            await asyncio.sleep(0.005)
        raise AssertionError(f"{n} investigations did not start")

    await started(2)
    await asyncio.sleep(0.05)
    # Two run, and the other two wait for a slot.
    assert len(mgr.started) == 2
    assert {s["finding_ordinal"] for s in mgr.started} == {2, 3}
    hunt = await _hunt(maker, hunt_id)
    assert hunt.status == "investigating"
    assert (hunt.findings_total, hunt.findings_investigated) == (4, 0)

    mgr.gates[mgr.started[0]["inv_id"]].set()
    await started(3)
    await asyncio.sleep(0.05)
    assert len(mgr.started) == 3
    hunt = await _hunt(maker, hunt_id)
    assert hunt.status == "investigating"
    assert hunt.findings_investigated == 1

    for gate in mgr.gates.values():
        gate.set()
    await started(4)
    for gate in mgr.gates.values():
        gate.set()
    await phase
    assert mgr.max_live == 2
    # A freed slot takes the next finding in priority order.
    assert [s["finding_ordinal"] for s in mgr.started][2:] == [1, 0]
    hunt = await _hunt(maker, hunt_id)
    assert hunt.status == "complete"
    assert hunt.findings_investigated == 4
    await engine.dispose()


async def test_a_failed_investigation_counts_as_ended(settings_kratos: Settings) -> None:
    engine, maker = await _store(settings_kratos)
    hunt_id, plan = await _investigating_hunt(maker, settings_kratos, [_finding(1), _finding(2)])
    mgr = FakeManager(maker, verdicts={0: "error"})

    verdicts = await _run_phase(settings_kratos, maker, mgr, hunt_id, plan)

    hunt = await _hunt(maker, hunt_id)
    assert hunt.status == "complete"
    assert hunt.findings_investigated == 2
    assert verdicts is not None
    assert (verdicts.decided, verdicts.threats) == (1, 0)
    await engine.dispose()


async def test_a_finding_whose_evidence_is_gone_is_failed_and_the_hunt_completes(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _store(settings_kratos)
    hunt_id, plan = await _investigating_hunt(maker, settings_kratos, [_finding(1)])
    mgr = FakeManager(maker)
    empty = SimpleNamespace(
        search=AsyncMock(return_value=EsSearchResult(total=0, took_ms=1, hits=[]))
    )
    ctx = InvestigationContext(
        settings=settings_kratos, auth=MagicMock(), elastic=empty, db_sessionmaker=maker
    )
    with patch(_MGR, return_value=mgr):
        await hunt_findings.investigate_findings(
            _state(maker, settings_kratos), hunt_id=hunt_id, ctx=ctx, plan=plan
        )
    assert mgr.started == []
    hunt = await _hunt(maker, hunt_id)
    assert hunt.status == "complete"
    link = hunt_svc.finding_links(hunt)[0]
    assert (link.state, link.reason) == (hunt_svc.LINK_FAILED, "no_promotable_evidence")
    await engine.dispose()


async def test_cancel_of_the_hunt_cancels_its_queued_and_running_investigations(
    settings_kratos: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A run cancelled before its first step reads running. The phase polls it.
    monkeypatch.setattr(hunt_findings, "REUSED_POLL_S", 0.01)
    engine, maker = await _store(settings_kratos)
    findings = [_finding(1), _finding(2), _finding(3)]
    hunt_id, plan = await _investigating_hunt(maker, settings_kratos, findings)
    mgr = FakeManager(maker, auto=False)
    phase = asyncio.create_task(_run_phase(settings_kratos, maker, mgr, hunt_id, plan))
    for _ in range(400):
        if len(mgr.started) >= 2:
            break
        await asyncio.sleep(0.005)
    assert len(mgr.started) == 2

    phase.cancel()
    with pytest.raises(asyncio.CancelledError):
        await phase
    await asyncio.sleep(0.05)

    assert sorted(mgr.cancelled) == sorted(s["inv_id"] for s in mgr.started)
    hunt = await _hunt(maker, hunt_id)
    assert hunt.status == "complete"
    links = hunt_svc.finding_links(hunt)
    assert {link.state for link in links.values()} == {hunt_svc.LINK_CANCELLED}
    assert links[2].investigation_id is None
    # The queued finding never started.
    assert len(mgr.started) == 2
    await engine.dispose()


# ── one investigation per subject ────────────────────────────────────────────


async def test_a_rehunt_of_the_same_lead_reuses_the_investigation_of_the_same_subject(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _store(settings_kratos)
    first, plan = await _investigating_hunt(maker, settings_kratos, [_finding(1)])
    mgr = FakeManager(maker, verdicts={0: "true_positive"})
    await _run_phase(settings_kratos, maker, mgr, first, plan)
    assert len(mgr.started) == 1
    opened = mgr.started[0]["inv_id"]

    # The re-hunt words the finding another way. The subject is the same:
    # one host, one document.
    again = _finding(1, title="Fixed cadence callouts", detail="Another wording.")
    second, plan2 = await _investigating_hunt(maker, settings_kratos, [again, _finding(9)])
    await _run_phase(settings_kratos, maker, mgr, second, plan2)

    hunt = await _hunt(maker, second)
    links = hunt_svc.finding_links(hunt)
    assert links[0].investigation_id == opened
    assert links[0].origin == hunt_svc.ORIGIN_REUSED
    # Control: the new subject got its own investigation.
    assert len(mgr.started) == 2
    assert mgr.started[1]["finding_ordinal"] == 1
    assert links[1].investigation_id == mgr.started[1]["inv_id"]
    assert len(await _runs(maker)) == 2
    await engine.dispose()


async def test_an_alert_run_never_answers_for_a_finding(settings_kratos: Settings) -> None:
    """Change E. The alert run judges the alert. The finding makes its own claim,
    so it gets its own run even when it cites the alert of that run."""
    engine, maker = await _store(settings_kratos)
    finding = _finding(1)
    async with maker() as db:
        alert_run = await inv_svc.create(
            db, alert_es_id=finding["citations"][0], started_by="analyst", rule_name="ET beacon"
        )
        await inv_svc.finalize(db, alert_run.id, status="complete", verdict="true_positive")
    hunt_id, plan = await _investigating_hunt(maker, settings_kratos, [finding])
    mgr = FakeManager(maker)
    await _run_phase(settings_kratos, maker, mgr, hunt_id, plan)
    assert len(mgr.started) == 1
    link = hunt_svc.finding_links(await _hunt(maker, hunt_id))[0]
    assert link.investigation_id == mgr.started[0]["inv_id"]
    assert link.investigation_id != alert_run.id
    assert link.origin == hunt_svc.ORIGIN_OPENED
    await engine.dispose()


async def _lead_with_alert_observation(maker: Any, alert_id: str) -> int:
    """A lead formed from one alert observation, the lead 49 shape."""
    lead_id = await _lead(maker)
    async with maker() as db:
        db.add(
            EntityObservation(
                entity_kind="host",
                entity_key="192.0.2.10",
                kind="alert_burst",
                spec_id="alerts",
                fingerprint="fp-alert-000049",
                summary="exploit alerts on the web server",
                evidence_json={"alert_id": alert_id},
                lead_id=lead_id,
            )
        )
        await db.commit()
    return lead_id


async def test_findings_that_cite_no_document_never_reuse_the_alert_run_of_the_lead(
    settings_kratos: Settings,
) -> None:
    """Change E. Lead 49 (2026-10-24) mapped four different findings to one
    alert run. Its findings cited prose only, so each run anchored on the alert
    of the lead, and the alert run answered for all of them."""
    engine, maker = await _store(settings_kratos)
    lead_alert = "alert-doc-000049"
    lead_id = await _lead_with_alert_observation(maker, lead_alert)
    async with maker() as db:
        alert_run = await inv_svc.create(db, alert_es_id=lead_alert, started_by="analyst")
        await inv_svc.finalize(db, alert_run.id, status="complete", verdict="true_positive")
    pair = ["192.0.2.10", "192.0.2.20"]
    findings = [
        _finding(1, hosts=pair, citations=["the web log"], title="Exploit of the web server"),
        _finding(
            2, hosts=pair, citations=["t_origin_chain(192.0.2.10)"], title="Upload of a shell"
        ),
        _finding(3, hosts=["192.0.2.30"], citations=[], title="Probe of the web server"),
    ]
    hunt_id, plan = await _investigating_hunt(maker, settings_kratos, findings, lead_id=lead_id)
    mgr = FakeManager(maker)
    await _run_phase(settings_kratos, maker, mgr, hunt_id, plan)
    assert len(mgr.started) == 3
    links = hunt_svc.finding_links(await _hunt(maker, hunt_id))
    assert {links[o].investigation_id for o in (0, 1, 2)} == {s["inv_id"] for s in mgr.started}
    assert all(links[o].origin == hunt_svc.ORIGIN_OPENED for o in (0, 1, 2))
    assert alert_run.id not in {links[o].investigation_id for o in (0, 1, 2)}
    await engine.dispose()


async def test_two_findings_of_one_hunt_never_share_a_run(settings_kratos: Settings) -> None:
    """Change E. Lead 50 (2026-10-24): two findings of one hunt named the same
    hosts and cited the same document, and the first reused the run of the
    second. Each finding makes its own claim."""
    engine, maker = await _store(settings_kratos)
    pair = ["192.0.2.10", "192.0.2.20"]
    doc = ["tel-doc-00000050"]
    findings = [
        _finding(1, hosts=pair, citations=doc, title="Web shell upload to the web server"),
        _finding(2, hosts=pair, citations=doc, title="Repeated exploit variants"),
    ]
    hunt_id, plan = await _investigating_hunt(maker, settings_kratos, findings)
    mgr = FakeManager(maker)
    await _run_phase(settings_kratos, maker, mgr, hunt_id, plan)
    assert len(mgr.started) == 2
    links = hunt_svc.finding_links(await _hunt(maker, hunt_id))
    assert links[0].origin == links[1].origin == hunt_svc.ORIGIN_OPENED
    assert links[0].investigation_id != links[1].investigation_id
    await engine.dispose()


@pytest.mark.parametrize("shape", ["backtest", "failed", "fallback", "old", "synth"])
async def test_a_run_that_cannot_answer_is_not_reused(
    settings_kratos: Settings, shape: str
) -> None:
    """Negative controls. Each run is a finding run of another hunt with the
    same subject fingerprint, and each one fails one test. An alert run never
    answers for a finding, so the controls use the one path that can reuse."""
    engine, maker = await _store(settings_kratos)
    finding = _finding(1)
    async with maker() as db:
        run = await inv_svc.create(
            db,
            alert_es_id=finding["citations"][0],
            started_by=inv_svc.BACKTEST_ACTOR if shape == "backtest" else "system:hunt",
            kind="hunt",
            hunt_id="01OTHERHUNT000000000000000",
            finding_ordinal=0,
            is_synth_eval=shape == "synth",
            subject={
                "type": "hunt",
                "hunt_id": "01OTHERHUNT000000000000000",
                "subject_fingerprint": subject_fingerprint(finding),
                "judges": "finding",
            },
        )
        await inv_svc.finalize(
            db,
            run.id,
            status="error" if shape == "failed" else "complete",
            verdict="true_positive",
            report={"fallback": True} if shape == "fallback" else None,
        )
        row = await db.get(Investigation, run.id)
        assert row is not None
        if shape == "fallback":
            row.is_fallback = True
        if shape == "old":
            row.created_at = utcnow() - timedelta(days=inv_svc.SUBJECT_REUSE_DAYS + 1)
        await db.commit()
    hunt_id, plan = await _investigating_hunt(maker, settings_kratos, [finding])
    mgr = FakeManager(maker)
    await _run_phase(settings_kratos, maker, mgr, hunt_id, plan)
    assert len(mgr.started) == 1
    link = hunt_svc.finding_links(await _hunt(maker, hunt_id))[0]
    assert link.investigation_id == mgr.started[0]["inv_id"]
    await engine.dispose()


async def test_the_backtest_fence_is_unchanged() -> None:
    assert inv_svc.BACKTEST_ACTOR == "backtest"
    assert inv_svc.is_backtest(SimpleNamespace(started_by="backtest")) is True
    assert inv_svc.is_backtest(SimpleNamespace(started_by="system:hunt")) is False


# ── the lead closes itself ───────────────────────────────────────────────────


async def _lead(maker: Any) -> int:
    async with maker() as db:
        lead = Lead(
            status="open",
            entities_json=[["host", "10.0.0.1"]],
            kinds_json=["catalog_match"],
            weight_at_formation=1.5,
            shadow=False,
        )
        db.add(lead)
        await db.commit()
        await db.refresh(lead)
        return int(lead.id)


async def _hunting(maker: Any, lead_id: int, hunt_id: str) -> None:
    async with maker() as db:
        await leads_store.mark_hunting(db, lead_id, hunt_id=hunt_id)


async def test_the_lead_closes_as_promoted_when_every_finding_has_a_verdict(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _store(settings_kratos)
    lead_id = await _lead(maker)
    hunt_id, plan = await _investigating_hunt(
        maker, settings_kratos, [_finding(1), _finding(2, severity="critical")], lead_id=lead_id
    )
    await _hunting(maker, lead_id, hunt_id)
    mgr = FakeManager(maker, verdicts={0: "false_positive", 1: "true_positive"})
    await _run_phase(settings_kratos, maker, mgr, hunt_id, plan)

    async with maker() as db:
        lead = await db.get(Lead, lead_id)
        assert lead is not None
        assert lead.status == "promoted"
        decision = leads_store.decisions_of(lead)[-1]
    tp = next(s["inv_id"] for s in mgr.started if s["finding_ordinal"] == 1)
    assert lead.investigation_id == tp
    assert decision["action"] == "promoted"
    assert decision["by"] == "system:hunt"
    assert decision["reason"] == leads_store.PROMOTED_FINDING_REASON
    assert decision["hunt_id"] == hunt_id
    assert [(v["ordinal"], v["verdict"]) for v in decision["verdicts"]] == [
        (0, "false_positive"),
        (1, "true_positive"),
    ]
    # R3-D5: the strip names this close. It read "Promoted" alone.
    assert leads_store.closed_on_verdicts(lead) is True
    await engine.dispose()


async def test_the_lead_waits_when_a_finding_has_no_verdict(settings_kratos: Settings) -> None:
    """Control: a failed investigation leaves the lead to the analyst."""
    engine, maker = await _store(settings_kratos)
    lead_id = await _lead(maker)
    hunt_id, plan = await _investigating_hunt(
        maker, settings_kratos, [_finding(1), _finding(2)], lead_id=lead_id
    )
    await _hunting(maker, lead_id, hunt_id)
    mgr = FakeManager(maker, verdicts={0: "error", 1: "true_positive"})
    await _run_phase(settings_kratos, maker, mgr, hunt_id, plan)
    async with maker() as db:
        lead = await db.get(Lead, lead_id)
        assert lead is not None
        assert lead.status == "hunting"
    await engine.dispose()


def _net_finding(n: int, **over: Any) -> dict[str, Any]:
    """A subject finding on a TEST-NET host."""
    base: dict[str, Any] = {"hosts": [f"192.0.2.{n}"], "detail": f"Host 192.0.2.{n} sent it."}
    base.update(over)
    return _finding(n, **base)


async def _net_lead(maker: Any) -> int:
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
        return int(lead.id)


async def test_a_failed_finding_investigation_holds_the_lead_with_a_reason(
    settings_kratos: Settings,
) -> None:
    """Replay of prod lead 47 (2026-10-24): three subject findings, the middle
    investigation ended in error at its wall clock, the other two reached
    true positive. The documented rule leaves the lead to the analyst. The
    lead stayed 'hunting' with no reason on its page, while a sibling lead
    with every verdict closed. The hold now names the reason, once."""
    engine, maker = await _store(settings_kratos)
    lead_id = await _net_lead(maker)
    hunt_id, plan = await _investigating_hunt(
        maker,
        settings_kratos,
        [_net_finding(1), _net_finding(2), _net_finding(3, severity="medium")],
        lead_id=lead_id,
    )
    await _hunting(maker, lead_id, hunt_id)
    mgr = FakeManager(maker, verdicts={0: "true_positive", 1: "error", 2: "true_positive"})
    await _run_phase(settings_kratos, maker, mgr, hunt_id, plan)

    async with maker() as db:
        lead = await db.get(Lead, lead_id)
        assert lead is not None
        assert lead.status == "hunting"
        assert leads_store.hold_reason_of(lead) == leads_store.HOLD_NO_VERDICT
        held = leads_store.decisions_of(lead)[-1]
        assert (held["action"], held["hunt_id"]) == ("held", hunt_id)
        assert held["by"] == leads_store.SYSTEM_HUNT_ACTOR
        assert await leads_store.derived_hold_reason(db, lead) == leads_store.HOLD_NO_VERDICT
        assert leads_store.HOLD_SENTENCES[leads_store.HOLD_NO_VERDICT] == (
            "A threat finding of the hunt has no verdict."
        )
        # The reconciliation pass calls the rule on every wake. It records
        # the hold once per hunt.
        hunt = await db.get(Hunt, hunt_id)
        assert hunt is not None
        assert await leads_store.settle_after_hunt(db, hunt) == "waits"
        assert await leads_store.settle_finished_hunts(db) == 0
        lead = await db.get(Lead, lead_id)
        assert lead is not None
        assert [d["action"] for d in leads_store.decisions_of(lead)].count("held") == 1
    await engine.dispose()


async def test_a_re_run_of_the_failed_finding_settles_the_held_lead(
    settings_kratos: Settings,
) -> None:
    """Control: the hold does not strand the lead. The analyst re-runs the
    failed finding on the hunt page, and the next settle pass closes it."""
    engine, maker = await _store(settings_kratos)
    lead_id = await _net_lead(maker)
    hunt_id, plan = await _investigating_hunt(
        maker, settings_kratos, [_net_finding(1), _net_finding(2)], lead_id=lead_id
    )
    await _hunting(maker, lead_id, hunt_id)
    mgr = FakeManager(maker, verdicts={0: "true_positive", 1: "error"})
    await _run_phase(settings_kratos, maker, mgr, hunt_id, plan)
    async with maker() as db:
        rerun = await inv_svc.create(
            db,
            alert_es_id="tel-doc-00000002",
            started_by="alice",
            kind="hunt",
            hunt_id=hunt_id,
            finding_ordinal=1,
        )
        await inv_svc.finalize(
            db, rerun.id, status="complete", verdict="false_positive", confidence=0.7
        )
        await hunt_svc.set_finding_link(
            db,
            hunt_id,
            1,
            hunt_svc.LINK_INVESTIGATING,
            investigation_id=rerun.id,
            origin=hunt_svc.ORIGIN_MANUAL,
        )
        assert await leads_store.settle_finished_hunts(db) == 1
        lead = await db.get(Lead, lead_id)
        assert lead is not None
        assert lead.status == "promoted"
        assert leads_store.hold_reason_of(lead) is None
        decision = leads_store.decisions_of(lead)[-1]
        assert [(v["ordinal"], v["verdict"]) for v in decision["verdicts"]] == [
            (0, "true_positive"),
            (1, "false_positive"),
        ]
    await engine.dispose()


async def test_a_lead_held_before_the_rule_recorded_it_reads_the_reason(
    settings_kratos: Settings,
) -> None:
    """A lead that an older release left 'hunting' over a finding with no
    verdict has no 'held' entry. The page reads the reason on read."""
    engine, maker = await _store(settings_kratos)
    lead_id = await _net_lead(maker)
    async with maker() as db:
        hunt = await hunt_svc.create(
            db, objective="hunt", started_by="auto-hunt", kind="lead", lead_id=lead_id
        )
        tp = await inv_svc.create(
            db, alert_es_id="tel-doc-00000001", started_by="system:hunt", kind="hunt"
        )
        await inv_svc.finalize(db, tp.id, status="complete", verdict="true_positive")
        await hunt_svc.finalize(
            db,
            hunt.id,
            status="complete",
            report={"findings": [_net_finding(1), _net_finding(2)]},
            finding_plan={
                "0": hunt_svc.plan_entry(
                    hunt_svc.LINK_ENDED, investigation_id=tp.id, origin="opened"
                ),
                "1": hunt_svc.plan_entry(hunt_svc.LINK_FAILED, reason="restart"),
            },
        )
        hunt_id = hunt.id
    await _hunting(maker, lead_id, hunt_id)
    async with maker() as db:
        lead = await db.get(Lead, lead_id)
        assert lead is not None
        assert leads_store.hold_reason_of(lead) is None
        assert await leads_store.derived_hold_reason(db, lead) == leads_store.HOLD_NO_VERDICT
        # Control: a lead whose verdicts are all in reads no hold.
        row = await db.get(Hunt, hunt_id)
        assert row is not None
        row.finding_investigations = {
            "0": hunt_svc.plan_entry(hunt_svc.LINK_ENDED, investigation_id=tp.id, origin="opened")
        }
        await db.commit()
        assert await leads_store.derived_hold_reason(db, lead) is None
    await engine.dispose()


async def test_an_entry_on_a_finding_that_is_no_subject_does_not_hold_the_lead(
    settings_kratos: Settings,
) -> None:
    """An older row holds an entry on an observation, which is no subject by
    the current rule. The hunt page drops that entry, and the settle rule
    waited on it. The lead now settles on the verdicts of its subjects."""
    engine, maker = await _store(settings_kratos)
    lead_id = await _net_lead(maker)
    async with maker() as db:
        hunt = await hunt_svc.create(
            db, objective="hunt", started_by="auto-hunt", kind="lead", lead_id=lead_id
        )
        tp = await inv_svc.create(
            db, alert_es_id="tel-doc-00000001", started_by="system:hunt", kind="hunt"
        )
        await inv_svc.finalize(db, tp.id, status="complete", verdict="true_positive")
        failed = await inv_svc.create(
            db, alert_es_id="tel-doc-00000002", started_by="system:hunt", kind="hunt"
        )
        await inv_svc.finalize(db, failed.id, status="error")
        await hunt_svc.finalize(
            db,
            hunt.id,
            status="complete",
            report={"findings": [_net_finding(1), _net_finding(2, category="observation")]},
            finding_plan={
                "0": hunt_svc.plan_entry(
                    hunt_svc.LINK_ENDED, investigation_id=tp.id, origin="opened"
                ),
                "1": hunt_svc.plan_entry(
                    hunt_svc.LINK_ENDED, investigation_id=failed.id, origin="reused"
                ),
            },
        )
        hunt_id = hunt.id
    await _hunting(maker, lead_id, hunt_id)
    async with maker() as db:
        row = await db.get(Hunt, hunt_id)
        assert row is not None
        assert await leads_store.settle_after_hunt(db, row) == "closed"
        lead = await db.get(Lead, lead_id)
        assert lead is not None
        assert lead.status == "promoted"
        decision = leads_store.decisions_of(lead)[-1]
        assert [(v["ordinal"], v["verdict"]) for v in decision["verdicts"]] == [
            (0, "true_positive")
        ]
    await engine.dispose()


async def test_a_lead_hunt_with_no_subject_settles_as_before(settings_kratos: Settings) -> None:
    """Control: a threat finding that cites no document is no subject. The
    hunt completes at once and the lead waits for the analyst, as before."""
    engine, maker = await _store(settings_kratos)
    lead_id = await _lead(maker)
    async with maker() as db:
        hunt = await hunt_svc.create(
            db, objective="hunt", started_by="auto-hunt", kind="lead", lead_id=lead_id
        )
        await hunt_svc.finalize(
            db, hunt.id, status="complete", report={"findings": [_finding(1, citations=[])]}
        )
        hunt_id = hunt.id
    await _hunting(maker, lead_id, hunt_id)
    async with maker() as db:
        row = await db.get(Hunt, hunt_id)
        assert row is not None
        assert row.findings_total == 0
        assert await leads_store.settle_after_hunt(db, row) == "waits"
        lead = await db.get(Lead, lead_id)
        assert lead is not None
        assert lead.status == "hunting"
    await engine.dispose()


async def test_an_investigating_hunt_does_not_settle_its_lead(settings_kratos: Settings) -> None:
    engine, maker = await _store(settings_kratos)
    lead_id = await _lead(maker)
    hunt_id, _plan = await _investigating_hunt(
        maker, settings_kratos, [_finding(1)], lead_id=lead_id
    )
    await _hunting(maker, lead_id, hunt_id)
    async with maker() as db:
        row = await db.get(Hunt, hunt_id)
        assert row is not None
        assert await leads_store.settle_after_hunt(db, row) == "none"
    await engine.dispose()


# ── a restart ────────────────────────────────────────────────────────────────


async def test_a_restart_completes_an_investigating_hunt(settings_kratos: Settings) -> None:
    engine, maker = await _store(settings_kratos)
    hunt_id, _plan = await _investigating_hunt(maker, settings_kratos, [_finding(1), _finding(2)])
    async with maker() as db:
        await hunt_svc.set_finding_link(
            db, hunt_id, 0, hunt_svc.LINK_INVESTIGATING, investigation_id="INV-A"
        )
        assert await hunt_svc.reap_investigating(db) == 1
    hunt = await _hunt(maker, hunt_id)
    assert hunt.status == "complete"
    links = hunt_svc.finding_links(hunt)
    assert links[0].state == hunt_svc.LINK_ENDED
    assert (links[1].state, links[1].reason) == (hunt_svc.LINK_FAILED, "restart")
    assert hunt.findings_investigated == 2
    await engine.dispose()
