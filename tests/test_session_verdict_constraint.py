"""One session cannot be both a true positive and a false positive.

Range dogfood: two alerts from ONE TCP session, twenty-eight minutes apart,
reached opposite conclusions. Same source, same destination, same port, same
community id, same fifty-nine second window. The first was a true positive
recommending escalation. The second matched a benign template on its own
prefetch, settled false positive and recommended acknowledgement. An analyst
working the queue top down meets the false positive first, acknowledges on the
product's recommendation, and never reaches the row saying the same session was
lateral movement.

Nothing in the product could see the two were the same conversation. The finest
key an investigation row carried was (rule, src, dest): no ports, no protocol,
and only a match when the rule name matched too. The community id is the hashed
five-tuple, which is exactly the identity that was missing.

Store-level filter behaviour lives in ``tests/test_store_investigations.py``.
This file covers the pipeline: the constraint reaching the prompt, the loop
being forced, the gate refusing the close, the analyst being told, and the
control that matters most — two genuinely unrelated alerts are NOT made to
agree.

No real gateway or model is ever called; the synth agent is a stub whose
``run`` is an ``AsyncMock``, so ``fake_agent.run.call_args[0][0]`` is the
composed outbound round-1 prompt.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic_ai import Agent
from pydantic_ai.models.test import TestModel
from soc_ai.agent.orchestrator import InvestigationContext, investigate
from soc_ai.agent.triage import TriageReport
from soc_ai.config import Settings
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.so_client.models import SoAlert
from soc_ai.store import investigations as inv_svc
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.tools.get_alert_context import EnrichedAlertContext
from soc_ai.triage_models import RecommendedAction

# Deliberately NOT a malware/exploit-class name: those trip the
# definitely-investigate gate on their own, which would hide whether the session
# constraint is what forced the loop.
RULE = "ET INFO Observed SMB Session Setup"
SRC = "10.0.0.1"
DST = "10.0.0.2"

SESSION = "1:hV6oYm5cQ8mQPWNQdCJvL5cM7YM="
OTHER_SESSION = "1:0kZmS0V0mZLZoCk7hjfHVBjLmpQ="

BLOCK_HEADER = "## Same network session, already investigated"


def _enriched(alert_id: str = "alert-001", community_id: str | None = SESSION) -> Any:
    return EnrichedAlertContext(
        alert=SoAlert(
            id=alert_id,
            severity_label="low",
            rule_name=RULE,
            source_ip=SRC,
            destination_ip=DST,
            network_community_id=community_id,
        ),
        pivot_summary={"community_id": 0, "host": 0, "user": 0, "process": 0, "file": 0},
    )


async def _db(settings: Settings):  # type: ignore[no-untyped-def]
    engine = make_engine(settings)
    await run_migrations(engine)
    return engine, make_sessionmaker(engine)


async def _seed(
    maker: Any,
    *,
    verdict: str = "true_positive",
    community_id: str = SESSION,
    alert_es_id: str = "seed-1",
    rationale: str = "The session carried a remote service install.",
) -> str:
    """One completed investigation stamped with a session; returns its id."""
    async with maker() as db:
        inv = await inv_svc.create(
            db,
            alert_es_id=alert_es_id,
            started_by="t",
            rule_name="ET LATERAL Service Control Manager Remote Install",
            src_ip=SRC,
            dest_ip=DST,
        )
        await inv_svc.set_alert_fields(db, inv.id, community_id=community_id)
        await inv_svc.finalize(
            db,
            inv.id,
            status="complete",
            verdict=verdict,
            confidence=0.85,
            rationale=rationale,
        )
        return str(inv.id)


def _make_ctx(settings: Settings, maker: Any = None) -> InvestigationContext:
    fake_es = AsyncMock()
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es):
        elastic = ElasticClient(settings)
    return InvestigationContext(
        settings=settings,
        auth=AsyncMock(),
        elastic=elastic,
        db_sessionmaker=maker,
    )


def _report(verdict: str = "false_positive") -> TriageReport:
    """The second run's own conclusion: benign, close it, acknowledge it."""
    return TriageReport(
        verdict=verdict,
        confidence=0.85,
        summary="Routine internal SMB session between two domain members.",
        citations=["alert.severity_label"],
        recommended_actions=[
            RecommendedAction(
                tool_name="ack_alert",
                tool_args={"alert_id": "alert-001"},
                rationale="Routine east-west SMB.",
            )
        ],
        gap_for_investigator=None,
    )


def _benign_template() -> Any:
    """A DISPOSITIVE benign template: the fast path that closed the real one."""
    from soc_ai.agent.decision_templates import CandidateVerdict

    return CandidateVerdict(
        verdict="false_positive",
        confidence=0.85,
        cited_evidence=["alert.rule_name"],
        template_id="stun_quic_keepalive",
        rationale="Keepalive with a clean conn",
        authority="dispositive",
    )


class _Node:
    """A pydantic-ai-style node whose ``model_response`` the orchestrator reads."""

    def __init__(self, message: Any) -> None:
        self.model_response = message


class _Run:
    def __init__(self, messages: list[Any], result: Any) -> None:
        self._nodes = [_Node(m) for m in messages]
        self.result = result

    def __aiter__(self) -> Any:
        return self._agen()

    async def _agen(self) -> Any:
        for node in self._nodes:
            yield node


class _RunCM:
    def __init__(self, run: _Run) -> None:
        self._run = run

    async def __aenter__(self) -> _Run:
        return self._run

    async def __aexit__(self, *_exc: Any) -> bool:
        return False


def _fake_investigator() -> Any:
    """An investigator that makes one successful Zeek call and settles.

    The tool RETURN part is what earns the loop its evidence-gate exemption, so
    without it the forced loop lands on needs_more_info for a reason that has
    nothing to do with the session gate.
    """
    from types import SimpleNamespace

    from soc_ai.agent.triage import InvestigationTranscript

    call = SimpleNamespace(
        tool_name="t_query_zeek_logs", args={"community_id": SESSION}, tool_call_id="tc1"
    )
    ret = SimpleNamespace(
        tool_name="t_query_zeek_logs",
        content={"conn": {"service": "smb", "duration": 59}},
        tool_call_id="tc1",
        part_kind="tool-return",
    )
    msg = SimpleNamespace(parts=[call, ret])
    result = MagicMock()
    result.output = InvestigationTranscript(
        evidence=["t_query_zeek_logs(community_id) -> conn.service=smb (tool t_query_zeek_logs)"],
        tentative_summary="One SMB conn, 59 seconds.",
        open_questions=[],
    )
    result.all_messages = MagicMock(return_value=[msg])
    result.usage = MagicMock(
        return_value=SimpleNamespace(
            tool_calls=1, requests=2, input_tokens=10, output_tokens=5, total_tokens=15
        )
    )
    agent = MagicMock()
    agent.run = AsyncMock(return_value=result)
    agent.iter = MagicMock(return_value=_RunCM(_Run([msg], result)))
    return agent


async def _drive(
    ctx: InvestigationContext,
    report: TriageReport,
    *,
    community_id: str | None = SESSION,
) -> tuple[list[Any], Any]:
    """Run investigate() end to end with stubbed synth + investigator agents.

    The investigator and the loop synthesizer are stubbed too, because a session
    true positive FORCES the loop: without them the run this file is measuring
    dies in the investigator instead of reaching a verdict.
    """
    fake_agent = Agent(
        model=TestModel(call_tools=[], custom_output_args=report),
        system_prompt="stub",
        output_type=TriageReport,
    )
    fake_agent.run = AsyncMock(return_value=MagicMock(output=report))

    loop_synth_result = MagicMock()
    loop_synth_result.output = report
    loop_synth_result.usage = MagicMock(side_effect=RuntimeError("no usage in stub"))
    fake_loop_synth = MagicMock()
    fake_loop_synth.run = AsyncMock(return_value=loop_synth_result)

    async def _stub_enriched(aid: str, **_kw: Any) -> Any:
        return _enriched(aid, community_id)

    with (
        patch(
            "soc_ai.tools.get_alert_context.get_enriched_alert_context",
            side_effect=_stub_enriched,
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synthesizer_model",
            return_value=TestModel(call_tools=[], custom_output_args=report),
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synth_first_agent",
            return_value=fake_agent,
        ),
        patch("soc_ai.agent.orchestrator.build_investigator", return_value=_fake_investigator()),
        patch("soc_ai.agent.orchestrator.build_synthesizer", return_value=fake_loop_synth),
        patch(
            "soc_ai.agent.decision_templates.match_decision_template",
            return_value=_benign_template(),
        ),
    ):
        events = [ev async for ev in investigate("alert-001", ctx=ctx)]
    return events, fake_agent


def _kinds(events: list[Any]) -> list[str]:
    return [e.kind for e in events]


def _payload(events: list[Any], kind: str) -> dict[str, Any]:
    for e in events:
        if e.kind == kind:
            return dict(e.payload)
    raise AssertionError(f"no {kind!r} event in {_kinds(events)}")


# =====================================================================
# The constraint reaches the model
# =====================================================================


@pytest.mark.asyncio
async def test_the_same_session_verdict_reaches_the_round_one_prompt(
    settings_kratos: Settings,
) -> None:
    """The prompt has to carry it, and carry it as a constraint rather than as
    another resemblance the model may weigh away."""
    settings_kratos.investigate_when_unsure = False
    engine, maker = await _db(settings_kratos)
    prior_id = await _seed(maker)

    _events, agent = await _drive(_make_ctx(settings_kratos, maker), _report())
    prompt = agent.run.call_args[0][0]

    assert BLOCK_HEADER in prompt
    assert prior_id in prompt
    assert "true_positive" in prompt
    assert "You may not settle this alert `false_positive`" in prompt
    await engine.dispose()


@pytest.mark.asyncio
async def test_the_analyst_is_told_the_two_are_related(settings_kratos: Settings) -> None:
    """Told regardless of how the verdicts land. Driven with the two AGREEING,
    so nothing the gate does can account for the row: the timeline names the
    other investigation because they are the same session, full stop."""
    settings_kratos.investigate_when_unsure = False
    engine, maker = await _db(settings_kratos)
    prior_id = await _seed(maker, verdict="false_positive")

    events, _ = await _drive(_make_ctx(settings_kratos, maker), _report())

    payload = _payload(events, "session_prior")
    assert payload["count"] == 1
    assert payload["items"] == [{"id": prior_id, "verdict": "false_positive"}]
    assert payload["forces_investigation"] is False
    # Agreement needs no correction, so the gate stays quiet.
    assert "session_verdict_conflict" not in _kinds(events)
    assert _payload(events, "triage_report")["verdict"] == "false_positive"
    await engine.dispose()


# =====================================================================
# The constraint changes the outcome
# =====================================================================


@pytest.mark.asyncio
async def test_a_false_positive_does_not_stand_against_a_session_true_positive(
    settings_kratos: Settings,
) -> None:
    """The defect. The second alert settles false positive and recommends an
    acknowledgement while the same session is already a true positive. It is
    held at needs_more_info, the acknowledgement is dropped, and the note names
    the investigation the analyst has to read."""
    settings_kratos.investigate_when_unsure = False
    settings_kratos.fast_triage_enabled = True
    engine, maker = await _db(settings_kratos)
    prior_id = await _seed(maker)

    events, _ = await _drive(_make_ctx(settings_kratos, maker), _report())

    report = _payload(events, "triage_report")
    assert report["verdict"] == "needs_more_info"
    assert report["recommended_actions"] == [], "the acknowledgement is the whole harm"
    assert prior_id in (report["validator_note"] or "")

    conflict = _payload(events, "session_verdict_conflict")
    assert conflict["original_verdict"] == "false_positive"
    assert conflict["prior_investigation_id"] == prior_id
    assert conflict["dropped_actions"] == ["ack_alert"]
    await engine.dispose()


@pytest.mark.asyncio
async def test_a_session_true_positive_forces_the_investigation_loop(
    settings_kratos: Settings,
) -> None:
    """A dispositive benign template can close a case with no tools at all, and
    that is exactly how the range's false positive got made. A true positive on
    the session takes the fast path away, with ``investigate_when_unsure`` off,
    which is the flag the fast path is otherwise gated on."""
    settings_kratos.investigate_when_unsure = False
    settings_kratos.fast_triage_enabled = True
    engine, maker = await _db(settings_kratos)
    await _seed(maker)

    events, _ = await _drive(_make_ctx(settings_kratos, maker), _report())

    assert _payload(events, "investigation_loop_entered")["reason"] == (
        "session_true_positive_stands"
    )
    await engine.dispose()


# =====================================================================
# Negative controls
# =====================================================================


@pytest.mark.asyncio
async def test_two_unrelated_alerts_are_not_forced_to_agree(
    settings_kratos: Settings,
) -> None:
    """The control that matters. A true positive on a DIFFERENT session, between
    the same two hosts, must not touch this verdict: same pair is not same
    conversation, and a constraint that fired on it would turn every busy host
    pair into one verdict. The false positive stands, nothing is held, and the
    fast path is not taken away."""
    settings_kratos.investigate_when_unsure = False
    settings_kratos.fast_triage_enabled = True
    engine, maker = await _db(settings_kratos)
    await _seed(maker, community_id=OTHER_SESSION)

    events, agent = await _drive(_make_ctx(settings_kratos, maker), _report())
    prompt = agent.run.call_args[0][0]

    assert BLOCK_HEADER not in prompt
    assert "session_prior" not in _kinds(events)
    assert "session_verdict_conflict" not in _kinds(events)
    assert "investigation_loop_entered" not in _kinds(events)
    report = _payload(events, "triage_report")
    assert report["verdict"] == "false_positive"
    assert [a["tool_name"] for a in report["recommended_actions"]] == ["ack_alert"]
    await engine.dispose()


@pytest.mark.asyncio
async def test_an_alert_with_no_session_is_left_alone(settings_kratos: Settings) -> None:
    """An alert with no network session behind it (endpoint alerts, and anything
    the grid gave no community id) asks nothing and is constrained by nothing.
    A missing session is not a wildcard that matches every stamped row."""
    settings_kratos.investigate_when_unsure = False
    engine, maker = await _db(settings_kratos)
    await _seed(maker)

    events, agent = await _drive(_make_ctx(settings_kratos, maker), _report(), community_id=None)

    assert BLOCK_HEADER not in agent.run.call_args[0][0]
    assert "session_prior" not in _kinds(events)
    assert _payload(events, "triage_report")["verdict"] == "false_positive"
    await engine.dispose()


@pytest.mark.asyncio
async def test_a_false_positive_on_the_session_does_not_hold_a_true_positive(
    settings_kratos: Settings,
) -> None:
    """The gate runs one way only. It refuses a CLOSE that contradicts a true
    positive; it never talks a true positive down to match an earlier benign
    reading, because the newer run is the one that looked.

    Asserted on the gate rather than on the final verdict: an unevidenced true
    positive has its own downgrades to answer to, and this test is about which
    gate did not fire.
    """
    settings_kratos.investigate_when_unsure = False
    engine, maker = await _db(settings_kratos)
    await _seed(maker, verdict="false_positive")

    events, _ = await _drive(_make_ctx(settings_kratos, maker), _report("true_positive"))

    assert "session_verdict_conflict" not in _kinds(events)
    assert "same-session gate" not in (_payload(events, "triage_report")["validator_note"] or "")
    await engine.dispose()


@pytest.mark.asyncio
async def test_the_session_lookup_is_fail_soft(settings_kratos: Settings) -> None:
    """A store that will not answer must not kill the investigation. No block,
    no event, and a verdict all the same."""
    settings_kratos.investigate_when_unsure = False
    engine, maker = await _db(settings_kratos)
    await _seed(maker)

    async def boom(*_a: Any, **_kw: Any) -> list[dict[str, Any]]:
        raise RuntimeError("the store is not answering")

    with patch("soc_ai.store.investigations.session_verdicts", side_effect=boom):
        events, agent = await _drive(_make_ctx(settings_kratos, maker), _report())

    assert BLOCK_HEADER not in agent.run.call_args[0][0]
    assert "session_prior" not in _kinds(events)
    assert _payload(events, "triage_report")["verdict"] == "false_positive"
    await engine.dispose()


@pytest.mark.asyncio
async def test_the_recorder_stamps_the_session_on_the_row(settings_kratos: Settings) -> None:
    """None of the above happens unless the session gets WRITTEN. The recorder
    reads it off the enriched alert the same way it reads the endpoints, so a
    run that dies before the context event leaves it NULL rather than wrong."""
    from soc_ai.api.recorder import InvestigationRecorder
    from soc_ai.store.models import Investigation

    engine, maker = await _db(settings_kratos)
    rec = InvestigationRecorder(maker, alert_id="alert-001", started_by="t")
    inv_id = await rec.start()
    assert inv_id is not None

    await rec.record(
        "enriched_alert_context",
        1,
        _enriched().model_dump(mode="json"),
    )
    await rec.finish("error")  # flushes; the verdict is beside the point here

    async with maker() as db:
        row = await db.get(Investigation, inv_id)
        assert row is not None
        assert row.community_id == SESSION
        assert row.src_ip == SRC
    await engine.dispose()


@pytest.mark.asyncio
async def test_an_alert_with_no_session_leaves_the_column_null(
    settings_kratos: Settings,
) -> None:
    """Negative control for the stamp. NULL is the absence of a session, and the
    lookup treats it as such: a run with nothing to stamp must not acquire a
    session by inheriting somebody's empty string."""
    from soc_ai.api.recorder import InvestigationRecorder
    from soc_ai.store.models import Investigation

    engine, maker = await _db(settings_kratos)
    rec = InvestigationRecorder(maker, alert_id="alert-002", started_by="t")
    inv_id = await rec.start()
    assert inv_id is not None

    await rec.record(
        "enriched_alert_context",
        1,
        _enriched("alert-002", None).model_dump(mode="json"),
    )
    await rec.finish("error")

    async with maker() as db:
        row = await db.get(Investigation, inv_id)
        assert row is not None
        assert row.community_id is None
    await engine.dispose()


@pytest.mark.asyncio
async def test_no_database_means_no_lookup(settings_kratos: Settings) -> None:
    """CLI and eval runs have no store at all. They must still triage."""
    settings_kratos.investigate_when_unsure = False

    events, agent = await _drive(_make_ctx(settings_kratos, None), _report())

    assert BLOCK_HEADER not in agent.run.call_args[0][0]
    assert "session_prior" not in _kinds(events)
    assert _payload(events, "triage_report")["verdict"] == "false_positive"
