"""D2: an investigation of a hunt has the hunt as its subject.

Covers the subject builder (which documents it fetches, in which order, and
the cap), the prompt (the subject block replaces the alert block), and the
pipeline (the decision templates, the same-session prior, the round-1 synth
and the unattended acknowledge are all skipped, and the evidence gate resolves
a citation of a fetched document).
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic_ai.models.test import TestModel
from soc_ai.agent.context import (
    MAX_SUBJECT_DOCUMENTS,
    HuntSubject,
    InvestigationContext,
    SubjectFinding,
    build_hunt_subject,
)
from soc_ai.agent.orchestrator import investigate
from soc_ai.agent.prompts import _format_investigator_prompt
from soc_ai.agent.triage import InvestigationTranscript, TriageReport
from soc_ai.config import Settings
from soc_ai.so_client.elastic import ElasticClient, EsSearchResult
from soc_ai.so_client.models import SoAlert
from soc_ai.store import hunts as hunt_svc
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.tools.get_alert_context import EnrichedAlertContext

pytestmark = pytest.mark.asyncio

ANCHOR_ID = "tel-doc-000001"
# A cited document that is NOT the anchor. The anchor's own id resolves off
# the alert whatever the subject holds, so only this one proves the subject's
# documents reach the citation resolver.
CITED_ID = "tel-doc-000002"


# ── helpers ───────────────────────────────────────────────────────────────────


async def _db(settings: Settings):  # type: ignore[no-untyped-def]
    engine = make_engine(settings)
    await run_migrations(engine)
    return engine, make_sessionmaker(engine)


def _hit(doc_id: str, dataset: str = "zeek.conn") -> dict[str, Any]:
    return {"_id": doc_id, "_source": {"event": {"dataset": dataset}}}


def _fake_grid(hits: list[dict[str, Any]]) -> Any:
    """An Elasticsearch client that answers one ids query with *hits*."""
    return SimpleNamespace(
        search=AsyncMock(return_value=EsSearchResult(total=len(hits), took_ms=1, hits=hits))
    )


async def _seed_hunt(
    maker: Any,
    *,
    objective: str = "read the domain controllers for kerberoasting",
    narrative: str = "One host asked for an RC4 ticket and then read SYSVOL.",
    findings: list[dict[str, Any]] | None = None,
) -> str:
    async with maker() as db:
        hunt = await hunt_svc.create(db, objective=objective, started_by="admin")
        await hunt_svc.finalize(
            db,
            hunt.id,
            status="complete",
            narrative=narrative,
            report={"findings": list(findings or [])},
        )
        return hunt.id


def _make_ctx(settings: Settings, *, db_sessionmaker: Any = None) -> InvestigationContext:
    fake_es = AsyncMock()
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es):
        elastic = ElasticClient(settings)
    return InvestigationContext(
        settings=settings,
        auth=AsyncMock(),
        elastic=elastic,
        db_sessionmaker=db_sessionmaker,
    )


def _subject(**over: Any) -> HuntSubject:
    """A subject holding one fetched document, for the pipeline tests."""
    base: dict[str, Any] = {
        "hunt_id": "01HUNT0000000000000000000",
        "objective": "read the domain controllers for kerberoasting",
        "narrative": "One host asked for an RC4 ticket.",
        "findings": [
            SubjectFinding(
                ordinal=0,
                title="RC4 ticket for svc_sql",
                detail="One host requested an RC4 service ticket.",
                hosts=["10.1.2.3"],
                citations=[ANCHOR_ID],
                promoted=True,
            )
        ],
        "documents": [
            SoAlert(id=ANCHOR_ID, event_dataset="zeek.kerberos"),
            SoAlert(id=CITED_ID, event_dataset="zeek.files"),
        ],
    }
    base.update(over)
    return HuntSubject(**base)


def _enriched(alert_id: str = ANCHOR_ID) -> EnrichedAlertContext:
    """A prefetch whose anchor HAS a session, so the skipped same-session
    prior is a decision and not an absence."""
    return EnrichedAlertContext(
        alert=SoAlert(
            id=alert_id,
            severity_label="low",
            network_community_id="1:abcdefghijklmnop",
        ),
        pivot_summary={"community_id": 0, "host": 0, "user": 0, "process": 0, "file": 0},
    )


class _FakeIterNode:
    def __init__(self, message: Any) -> None:
        self.model_response = message


class _FakeAgentRun:
    def __init__(self, messages: list[Any], result: Any) -> None:
        self._nodes = [_FakeIterNode(m) for m in messages]
        self.result = result

    def __aiter__(self) -> Any:
        return self._agen()

    async def _agen(self) -> Any:
        for node in self._nodes:
            yield node


class _FakeIterCM:
    def __init__(self, run: _FakeAgentRun) -> None:
        self._run = run

    async def __aenter__(self) -> _FakeAgentRun:
        return self._run

    async def __aexit__(self, *exc: Any) -> bool:
        return False


def _fake_investigator() -> Any:
    """A loop investigator that makes one successful tool call and hands back
    a transcript."""
    call = SimpleNamespace(
        tool_name="t_query_zeek_logs", args={"community_id": "1:abc"}, tool_call_id="tc1"
    )
    ret = SimpleNamespace(
        tool_name="t_query_zeek_logs",
        content={"kerberos": [{"_id": ANCHOR_ID, "cipher": "rc4-hmac"}]},
        tool_call_id="tc1",
        part_kind="tool-return",
    )
    message = SimpleNamespace(parts=[call, ret])
    transcript = InvestigationTranscript(
        evidence=[f"t_query_zeek_logs -> rc4-hmac ticket (id={ANCHOR_ID})"],
        tentative_summary="An RC4 service ticket was requested.",
        open_questions=[],
    )
    result = MagicMock()
    result.output = transcript
    result.all_messages = MagicMock(return_value=[message])
    result.usage = MagicMock(
        return_value=SimpleNamespace(
            tool_calls=1, requests=2, input_tokens=10, output_tokens=5, total_tokens=15
        )
    )
    agent = MagicMock()
    agent.run = AsyncMock(return_value=result)
    agent.iter = MagicMock(return_value=_FakeIterCM(_FakeAgentRun([message], result)))
    return agent


def _fake_loop_synth(report: TriageReport) -> Any:
    result = MagicMock()
    result.output = report
    result.usage = MagicMock(side_effect=RuntimeError("no usage in stub"))
    agent = MagicMock()
    agent.run = AsyncMock(return_value=result)
    return agent


async def _run(
    settings: Settings,
    *,
    subject: HuntSubject | None,
    report: TriageReport,
    db_sessionmaker: Any = None,
    allow_so_writes: bool = True,
    template: Any = None,
) -> tuple[list[Any], dict[str, Any]]:
    """Drive investigate() with a stubbed prefetch, loop and synthesis.

    Returns the events and the spies the assertions read.
    """
    settings.investigate_when_unsure = True
    ctx = _make_ctx(settings, db_sessionmaker=db_sessionmaker)
    spies: dict[str, Any] = {
        "match_decision_template": MagicMock(return_value=template),
        "session_verdicts": AsyncMock(return_value=[]),
        "maybe_auto_ack_fp": AsyncMock(return_value=None),
        "investigator": _fake_investigator(),
    }

    async def _stub_enriched(alert_id: str, **_kw: Any) -> Any:
        return _enriched(alert_id)

    with (
        patch(
            "soc_ai.tools.get_alert_context.get_enriched_alert_context",
            side_effect=_stub_enriched,
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synthesizer_model",
            return_value=TestModel(call_tools=[]),
        ),
        patch(
            "soc_ai.agent.orchestrator.build_investigator",
            return_value=spies["investigator"],
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synthesizer",
            return_value=_fake_loop_synth(report),
        ),
        patch(
            "soc_ai.agent.decision_templates.match_decision_template",
            spies["match_decision_template"],
        ),
        patch("soc_ai.store.investigations.session_verdicts", spies["session_verdicts"]),
        patch("soc_ai.agent.orchestrator.maybe_auto_ack_fp", spies["maybe_auto_ack_fp"]),
    ):
        events = [
            ev
            async for ev in investigate(
                ANCHOR_ID,
                ctx=ctx,
                subject=subject,
                allow_so_writes=allow_so_writes,
            )
        ]
    return events, spies


def _payload(events: list[Any], kind: str) -> dict[str, Any]:
    return next(e.payload for e in events if e.kind == kind)


# ── the subject builder ───────────────────────────────────────────────────────


async def test_the_builder_reads_the_hunt_and_its_findings(settings_kratos: Settings) -> None:
    """The subject is the hunt: its objective, its narrative, every finding."""
    engine, maker = await _db(settings_kratos)
    hunt_id = await _seed_hunt(
        maker,
        findings=[
            {"title": "RC4 ticket", "hosts": ["10.1.2.3"], "citations": [ANCHOR_ID]},
            {"title": "SYSVOL read", "severity": "medium", "citations": ["tel-doc-000002"]},
        ],
    )
    grid = _fake_grid([_hit("tel-doc-000002"), _hit(ANCHOR_ID)])
    async with maker() as db:
        subject = await build_hunt_subject(
            db,
            elastic=grid,
            settings=settings_kratos,
            hunt_id=hunt_id,
            finding_ordinal=1,
        )
    assert subject.type == "hunt"
    assert subject.hunt_id == hunt_id
    assert subject.objective == "read the domain controllers for kerberoasting"
    assert subject.narrative is not None
    assert subject.finding_ordinals == [0, 1]
    assert [f.promoted for f in subject.findings] == [False, True]
    assert subject.findings[1].severity == "medium"
    record = subject.as_record()
    assert record["type"] == "hunt"
    assert record["finding_titles"] == ["RC4 ticket", "SYSVOL read"]
    assert record["lead_id"] is None
    await engine.dispose()


async def test_the_promoted_findings_documents_come_first(settings_kratos: Settings) -> None:
    """The analyst pressed the button on one finding. Its documents lead, and
    the rest follow in the order the grid returned them, newest first."""
    engine, maker = await _db(settings_kratos)
    hunt_id = await _seed_hunt(
        maker,
        findings=[
            {"title": "One", "citations": ["tel-doc-000010", "tel-doc-000011"]},
            {"title": "Two", "citations": ["tel-doc-000020"]},
        ],
    )
    # The grid answers newest first: 11, 20, 10.
    grid = _fake_grid([_hit("tel-doc-000011"), _hit("tel-doc-000020"), _hit("tel-doc-000010")])
    async with maker() as db:
        subject = await build_hunt_subject(
            db, elastic=grid, settings=settings_kratos, hunt_id=hunt_id, finding_ordinal=1
        )
    assert subject.document_ids == ["tel-doc-000020", "tel-doc-000011", "tel-doc-000010"]
    # One read of the grid, sorted by timestamp, with every id-shaped citation.
    args, kwargs = grid.search.await_args
    assert args[1] == {"ids": {"values": ["tel-doc-000020", "tel-doc-000010", "tel-doc-000011"]}}
    assert kwargs["sort"] == [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}]
    await engine.dispose()


async def test_the_document_set_is_capped(settings_kratos: Settings) -> None:
    """Past the cap the block stops being evidence and starts being a dump."""
    engine, maker = await _db(settings_kratos)
    ids = [f"tel-doc-{n:06d}" for n in range(MAX_SUBJECT_DOCUMENTS + 5)]
    hunt_id = await _seed_hunt(maker, findings=[{"title": "Many", "citations": ids}])
    grid = _fake_grid([_hit(i) for i in ids])
    async with maker() as db:
        subject = await build_hunt_subject(
            db, elastic=grid, settings=settings_kratos, hunt_id=hunt_id, finding_ordinal=0
        )
    assert len(subject.documents) == MAX_SUBJECT_DOCUMENTS
    assert subject.document_ids == ids[:MAX_SUBJECT_DOCUMENTS]
    await engine.dispose()


async def test_prose_citations_never_reach_the_grid(settings_kratos: Settings) -> None:
    """A finding also cites prose. Prose is not a document id."""
    engine, maker = await _db(settings_kratos)
    hunt_id = await _seed_hunt(
        maker,
        findings=[{"title": "One", "citations": ["the host has never done this", "short", None]}],
    )
    grid = _fake_grid([])
    async with maker() as db:
        subject = await build_hunt_subject(
            db, elastic=grid, settings=settings_kratos, hunt_id=hunt_id, finding_ordinal=0
        )
    assert subject.documents == []
    grid.search.assert_not_awaited()
    await engine.dispose()


async def test_the_builder_reads_the_lead_and_its_related_leads(
    settings_kratos: Settings,
) -> None:
    """A lead hunt is investigated with the observations that formed the lead
    and with the leads that relate to it."""
    from datetime import UTC, datetime

    from soc_ai.hunting.leads import content_fingerprint, form_leads, record_observation
    from soc_ai.hunting.weight import Kind

    engine, maker = await _db(settings_kratos)
    now = datetime(2026, 9, 18, 12, 0, tzinfo=UTC)
    async with maker() as db:
        await record_observation(
            db,
            entity_kind="host",
            entity_key="10.1.2.3",
            kind=Kind.NOVEL_DESTINATION,
            spec_id="s",
            fingerprint=content_fingerprint("peers_out", "203.0.113.9"),
            summary="new outbound peer 203.0.113.9",
            evidence={"sample_ids": ["tel-doc-000003"]},
            now=now,
        )
        await record_observation(
            db,
            entity_kind="host",
            entity_key="10.1.2.3",
            kind=Kind.OFF_HOURS,
            spec_id="p",
            fingerprint=content_fingerprint("active_hours", "3"),
            summary="active around 03:00 UTC",
            now=now,
        )
        outcome = await form_leads(db, entity_keys=[("host", "10.1.2.3")], now=now, threshold=0.7)
        lead_id = outcome.formed[0]

    hunt_id = await _seed_hunt(maker, findings=[{"title": "One", "citations": [ANCHOR_ID]}])
    grid = _fake_grid([_hit(ANCHOR_ID), _hit("tel-doc-000003")])
    async with maker() as db:
        subject = await build_hunt_subject(
            db,
            elastic=grid,
            settings=settings_kratos,
            hunt_id=hunt_id,
            lead_id=lead_id,
            related_leads=[{"lead_id": 99, "reason": "same analytic within 24 h"}],
        )
    assert subject.lead_id == lead_id
    assert {o.kind for o in subject.observations} == {"novel_destination", "off_hours"}
    assert subject.observation_ids and all(isinstance(i, int) for i in subject.observation_ids)
    # The lead's own cited document joins the hunt's.
    assert set(subject.document_ids) == {ANCHOR_ID, "tel-doc-000003"}
    assert [r.lead_id for r in subject.related_leads] == [99]
    block = subject.render_block()
    assert "Related leads" in block and "same analytic within 24 h" in block
    await engine.dispose()


async def test_a_missing_hunt_is_a_lookup_error(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        with pytest.raises(LookupError):
            await build_hunt_subject(
                db, elastic=_fake_grid([]), settings=settings_kratos, hunt_id="01NOSUCHHUNT"
            )
    await engine.dispose()


# ── the prompt ────────────────────────────────────────────────────────────────


async def test_the_prompt_carries_the_subject_block_and_not_the_alert_block() -> None:
    """The subject block REPLACES the alert block. A hunt has no rule, so the
    Suricata reading order has nothing to read."""
    subject = _subject()
    with_subject = _format_investigator_prompt(
        ANCHOR_ID,
        '{"alert": {"id": "tel-doc-000001"}}',
        subject_block=subject.render_block(),
    )
    assert "## Subject: the hunt below" in with_subject
    assert subject.objective in with_subject
    assert "RC4 ticket for svc_sql" in with_subject
    assert "Pre-fetched alert context" not in with_subject
    assert "Read these typed fields FIRST" not in with_subject
    assert '{"alert": {"id": "tel-doc-000001"}}' not in with_subject
    # The three verdicts are restated for a hunt, and the summary answers the
    # objective.
    assert "the hunt's hypothesis holds" in with_subject
    assert "one paragraph that answers the hunt's objective" in with_subject
    # No em-dash anywhere in the block the prompt adds.
    assert "—" not in subject.render_block()

    without = _format_investigator_prompt(ANCHOR_ID, '{"alert": {"id": "tel-doc-000001"}}')
    assert "Pre-fetched alert context" in without
    assert "## Subject: the hunt below" not in without


# ── the pipeline ──────────────────────────────────────────────────────────────


async def test_a_hunt_subject_skips_the_templates_the_prior_and_round_one(
    settings_kratos: Settings,
) -> None:
    """Three things do not run for a hunt subject, and each one says so."""
    from soc_ai.agent.decision_templates import CandidateVerdict

    template = CandidateVerdict(
        verdict="false_positive",
        confidence=0.85,
        cited_evidence=["alert.rule_name"],
        template_id="stun_quic_keepalive",
        rationale="STUN keepalive",
        authority="dispositive",
    )
    report = TriageReport(
        verdict="true_positive",
        confidence=0.85,
        summary="The hunt's hypothesis holds: an RC4 service ticket was requested.",
        citations=[ANCHOR_ID],
        recommended_actions=[],
        gap_for_investigator=None,
    )
    engine, maker = await _db(settings_kratos)
    events, spies = await _run(
        settings_kratos,
        subject=_subject(),
        report=report,
        db_sessionmaker=maker,
        template=template,
    )
    kinds = [e.kind for e in events]

    # The templates match alert rule classes. A hunt has none.
    spies["match_decision_template"].assert_not_called()
    assert _payload(events, "decision_template_match")["skipped"] == "hunt_subject"
    # The same-session prior is keyed on a community id the hunt does not have.
    spies["session_verdicts"].assert_not_awaited()
    assert "session_prior" not in kinds
    # Round 1 is a tool-less synthesis over one alert.
    assert _payload(events, "synth_round1_skipped")["reason"] == "hunt_subject"
    # And the loop runs, which is the point of skipping it.
    assert "investigation_loop_entered" in kinds
    assert "retask" not in kinds
    await engine.dispose()


async def test_the_prefetch_events_say_the_subject_is_the_hunt(
    settings_kratos: Settings,
) -> None:
    """Two events carry the word "alert" and were written on a hunt.

    ``session_start`` names the anchor document as the alert id, and
    ``enriched_alert_context`` is the alert prefetch. On a hunt subject both
    describe a run whose subject is the hunt, and the timeline read them as
    "Loaded alert context + enrichments". The events keep their names, which
    every reader and the audit schema know. They now say what they loaded.
    """
    report = TriageReport(
        verdict="true_positive",
        confidence=0.85,
        summary="The hunt's hypothesis holds.",
        citations=[ANCHOR_ID],
        recommended_actions=[],
        gap_for_investigator=None,
    )
    engine, maker = await _db(settings_kratos)
    events, _spies = await _run(
        settings_kratos, subject=_subject(), report=report, db_sessionmaker=maker
    )
    start = _payload(events, "session_start")
    assert start["subject"] == "hunt"
    # The anchor id stays. The pipeline anchors its time windows on it.
    assert start["alert_id"] == ANCHOR_ID

    context = _payload(events, "enriched_alert_context")
    assert context["subject"] == "hunt"
    assert context["subject_findings"] == 1
    assert len(context["subject_documents"]) == 2
    await engine.dispose()


async def test_a_hunt_subject_never_acknowledges_in_security_onion(
    settings_kratos: Settings,
) -> None:
    """Nothing in Security Onion holds a hunt. The caller asked for writes and
    still gets none."""
    settings_kratos.auto_ack_fp_enabled = True
    report = TriageReport(
        verdict="false_positive",
        confidence=0.95,
        summary="The findings have a benign explanation: a scheduled service check.",
        citations=[ANCHOR_ID],
        recommended_actions=[],
        gap_for_investigator=None,
    )
    events, spies = await _run(
        settings_kratos,
        subject=_subject(),
        report=report,
        allow_so_writes=True,
    )
    spies["maybe_auto_ack_fp"].assert_not_awaited()
    assert _payload(events, "auto_ack_skipped")["reason"] == "promoted_finding"
    assert "auto_ack" not in [e.kind for e in events]


async def test_the_evidence_gate_resolves_a_citation_of_a_fetched_document(
    settings_kratos: Settings,
) -> None:
    """The subject's documents ARE the prefetched evidence, so a verdict that
    cites one of them stands."""
    report = TriageReport(
        verdict="true_positive",
        confidence=0.85,
        summary="The hunt's hypothesis holds: an RC4 service ticket was requested.",
        citations=[CITED_ID],
        recommended_actions=[],
        gap_for_investigator=None,
    )
    events, _spies = await _run(settings_kratos, subject=_subject(), report=report)

    enriched_payload = _payload(events, "enriched_alert_context")
    assert [d["id"] for d in enriched_payload["subject_documents"]] == [ANCHOR_ID, CITED_ID]

    validation = _payload(events, "citation_validation")
    assert validation["coverage_ratio"] == 1.0
    assert validation["per_citation"][0]["resolution_kind"] == "strict_id"

    # The verdict lands as written, with the document it cites.
    final = _payload(events, "triage_report")
    assert final["verdict"] == "true_positive"
    assert final["citations"] == [CITED_ID]
    assert "evidence_gate_downgrade" not in [e.kind for e in events]


async def test_a_citation_of_a_document_the_run_never_held_does_not_resolve(
    settings_kratos: Settings,
) -> None:
    """The negative control. The same citation, the same pipeline, and the
    subject holding no documents: the id must NOT resolve, or the test above
    proves nothing about where the documents came from."""
    report = TriageReport(
        verdict="true_positive",
        confidence=0.85,
        summary="The hunt's hypothesis holds: an RC4 service ticket was requested.",
        citations=[CITED_ID],
        recommended_actions=[],
        gap_for_investigator=None,
    )
    events, _spies = await _run(settings_kratos, subject=_subject(documents=[]), report=report)
    assert _payload(events, "enriched_alert_context")["subject_documents"] == []
    validation = _payload(events, "citation_validation")
    assert validation["per_citation"][0]["resolved"] is False
    assert validation["coverage_ratio"] == 0.0


async def test_an_alert_run_is_unchanged(settings_kratos: Settings) -> None:
    """The same pipeline with no subject still matches a template, reads the
    prior and holds no subject documents."""
    report = TriageReport(
        verdict="true_positive",
        confidence=0.85,
        summary="Confirmed.",
        citations=[ANCHOR_ID],
        recommended_actions=[],
        gap_for_investigator=None,
    )
    engine, maker = await _db(settings_kratos)
    events, spies = await _run(settings_kratos, subject=None, report=report, db_sessionmaker=maker)
    spies["match_decision_template"].assert_called_once()
    spies["session_verdicts"].assert_awaited()
    assert _payload(events, "decision_template_match")["skipped"] is None
    assert _payload(events, "enriched_alert_context")["subject_documents"] == []
    # NEGATIVE CONTROL. An alert run claims no hunt subject on either event.
    assert "subject" not in _payload(events, "enriched_alert_context")
    assert "subject" not in _payload(events, "session_start")
    await engine.dispose()


# ── what the API serves ───────────────────────────────────────────────────────


async def test_the_api_reads_the_subject_off_the_row(settings_kratos: Settings) -> None:
    """The page reads "Subject: hunt <objective>" from the row, not from the
    hunt: the hunt carries no foreign key and may be deleted."""
    from soc_ai.api.webui.routes_investigations import _subject_out, _subject_type
    from soc_ai.store import investigations as inv_svc
    from soc_ai.store.models import Hunt

    engine, maker = await _db(settings_kratos)
    record = _subject().as_record()
    async with maker() as db:
        alert_run = await inv_svc.create(db, alert_es_id=ANCHOR_ID, started_by="admin")
        hunt_run = await inv_svc.create(
            db, alert_es_id=ANCHOR_ID, started_by="admin", kind="hunt", subject=record
        )
    assert _subject_type(alert_run) == "alert"
    assert _subject_out(alert_run, None) is None
    assert _subject_type(hunt_run) == "hunt"
    served = _subject_out(hunt_run, None)
    assert served is not None
    assert served["type"] == "hunt"
    assert served["objective"] == record["objective"]
    assert served["finding_titles"] == ["RC4 ticket for svc_sql"]
    assert served["document_ids"] == [ANCHOR_ID, CITED_ID]
    # A legacy row with no objective takes the hunt's, when the hunt is there.
    hunt_run.subject_json = {"type": "hunt", "hunt_id": "01H"}
    topped_up = _subject_out(hunt_run, Hunt(id="01H", objective="read the controllers"))
    assert topped_up is not None and topped_up["objective"] == "read the controllers"
    await engine.dispose()
