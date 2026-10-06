"""No override without evidence (2026-10-04).

On production ``oracle_tools_enabled`` is off, so every adjudication ran the
single-shot path. That path had no override gate: 6 of 23 answers changed the
class, needs_more_info to false_positive, with no tool call and no citation,
and 2 of them were then auto-acknowledged.

Now an Oracle verdict that changes the local class is accepted only when the
Oracle cites evidence that resolves: an id the local run retrieved beyond the
alert itself, or, on the tool path, its own tool results. Without that, the
answer is an opinion on the run, the local verdict stands, and the
auto-acknowledge never fires on it.

The negative controls sit on the paths a careless gate would miss: the
single-shot path, a citation of the alert's own id (every case holds it), and
a citation of a token planted in packet text.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
from pydantic_ai.models.test import TestModel
from soc_ai.agent.orchestrator import investigate, maybe_auto_ack_fp
from soc_ai.api.webui._timeline import _build_oracle
from soc_ai.config import Settings
from soc_ai.oracle.client import OracleResult
from soc_ai.so_client.models import SoAlert
from soc_ai.triage_models import TriageReport
from soc_ai.webui.timeline_labels import title_for

from tests.test_agent import _make_ctx, _malware_signal_enriched

PIVOT_ID = "evt-pivot-7f3a9c"
PLANTED = "plantedtoken-c2-0042"


def _enriched_with_pivot(alert_id: str) -> Any:
    """The malware-rule stub plus one prefetched event whose text carries a planted token."""
    base = _malware_signal_enriched(alert_id)
    pivot = SoAlert(
        id=PIVOT_ID,
        severity_label="low",
        message=f"beacon payload {PLANTED} observed",
    )
    return base.model_copy(update={"community_id_events": [pivot]})


def _oracle_answer(verdict: str, confidence: float, citations: list[str] | None) -> str:
    body: dict[str, Any] = {
        "verdict": verdict,
        "confidence": confidence,
        "summary": "Routine software update traffic.",
        "reasoning": "The destination is a vendor update service.",
    }
    if citations is not None:
        body["citations"] = citations
    return json.dumps(body)


def _gateway(answer: str) -> Any:
    real_client = httpx.AsyncClient

    def _handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/chat/completions"):
            return httpx.Response(200, json={"choices": [{"message": {"content": answer}}]})
        return httpx.Response(404, json={"error": {"message": "not here"}})

    def _client(**kw: Any) -> httpx.AsyncClient:
        return real_client(transport=httpx.MockTransport(_handler), **kw)

    return patch("httpx.AsyncClient", _client)


async def _run(settings: Settings, answer: str) -> tuple[list[Any], AsyncMock]:
    """A malware-rule alert whose zero-tool local FP the evidence gate turns into
    needs_more_info at 0.4. The real single-shot Oracle client answers ``answer``."""
    settings.investigate_when_unsure = False
    settings.oracle_enabled = True
    settings.auto_ack_fp_enabled = True
    settings.auto_ack_fp_threshold = 0.5
    ctx = _make_ctx(settings)
    local_fp = TriageReport(
        verdict="false_positive",
        confidence=0.75,
        summary="Local verdict: benign.",
        citations=["alert.severity_label"],
        recommended_actions=[],
    )

    async def _stub_enriched(alert_id: str, **_kw: Any) -> Any:
        return _enriched_with_pivot(alert_id)

    write = AsyncMock(return_value=({"ok": True}, None))
    with (
        patch(
            "soc_ai.tools.get_alert_context.get_enriched_alert_context",
            side_effect=_stub_enriched,
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synthesizer_model",
            return_value=TestModel(call_tools=[], custom_output_args=local_fp),
        ),
        patch("soc_ai.agent.orchestrator.execute_write_tool", write),
        patch("soc_ai.oracle.client.asyncio.sleep", AsyncMock()),
        _gateway(answer),
    ):
        events = [ev async for ev in investigate("beacon-001", ctx=ctx)]
    return events, write


def _final(events: list[Any]) -> dict[str, Any]:
    return dict(next(e for e in events if e.kind == "triage_report").payload)


def _adjudication(events: list[Any]) -> dict[str, Any]:
    return dict(next(e for e in events if e.kind == "oracle_adjudication").payload)


# ── The single-shot path ─────────────────────────────────────────────────────


async def test_an_uncited_flip_on_nmi_leaves_nmi_and_no_auto_ack(settings_kratos: Settings) -> None:
    """The owner's negative control: rows 47 and 59 of the 2026-10-04 review."""
    events, write = await _run(
        settings_kratos, _oracle_answer("false_positive", 0.93, citations=None)
    )
    final = _final(events)
    assert final["verdict"] == "needs_more_info"
    assert "[Oracle adjudicated]" not in (final["summary"] or "")
    adj = _adjudication(events)
    assert adj["override_withheld"] is True
    assert adj["withheld_reason"] == "no_resolving_evidence"
    assert adj["oracle_verdict"] == "false_positive"
    assert adj["oracle_confidence"] == 0.93
    assert adj["local_verdict"] == "needs_more_info"
    assert adj["oracle_citations"] == []
    assert adj["oracle_summary"].startswith("Routine software update traffic.")
    # Never acknowledged: no write to the grid, no ack event.
    write.assert_not_awaited()
    assert "auto_ack" not in [e.kind for e in events]


async def test_a_flip_that_cites_only_the_alert_is_an_opinion(settings_kratos: Settings) -> None:
    """Every case holds the alert's id. Citing it backs nothing."""
    events, write = await _run(
        settings_kratos, _oracle_answer("false_positive", 0.93, citations=["beacon-001"])
    )
    assert _final(events)["verdict"] == "needs_more_info"
    adj = _adjudication(events)
    assert adj["override_withheld"] is True
    assert adj["oracle_citations_cited"] == 1
    assert adj["oracle_citations"] == []
    write.assert_not_awaited()


async def test_a_flip_that_cites_a_planted_token_is_an_opinion(settings_kratos: Settings) -> None:
    """A token in packet text is no retrieved id. Membership, never substring."""
    events, _write = await _run(
        settings_kratos, _oracle_answer("false_positive", 0.93, citations=[PLANTED])
    )
    assert _final(events)["verdict"] == "needs_more_info"
    assert _adjudication(events)["override_withheld"] is True


async def test_a_flip_that_cites_a_retrieved_event_lands(settings_kratos: Settings) -> None:
    """The positive control: the same answer, citing the prefetched event."""
    events, _write = await _run(
        settings_kratos,
        _oracle_answer("false_positive", 0.93, citations=[f"community event {PIVOT_ID}"]),
    )
    final = _final(events)
    assert final["verdict"] == "false_positive"
    assert final["local_verdict"] == "needs_more_info"
    adj = _adjudication(events)
    assert "override_withheld" not in adj
    assert adj["oracle_citations"] == [PIVOT_ID]


# ── The orchestrator holds the rule for every client path ───────────────────


async def test_a_stub_client_flip_with_no_evidence_is_withheld(settings_kratos: Settings) -> None:
    """A client path that forgets the gate still cannot land an unbacked flip."""
    settings_kratos.investigate_when_unsure = False
    settings_kratos.oracle_enabled = True
    ctx = _make_ctx(settings_kratos)
    local_fp = TriageReport(
        verdict="false_positive",
        confidence=0.75,
        summary="Local verdict: benign.",
        citations=["alert.severity_label"],
        recommended_actions=[],
    )
    flip = OracleResult(
        report=TriageReport(
            verdict="true_positive",
            confidence=0.91,
            summary="C2.",
            citations=[],
            recommended_actions=[],
        ),
        redaction_summary={},
        oracle_model="test-oracle",
    )

    async def _stub_enriched(alert_id: str, **_kw: Any) -> Any:
        return _malware_signal_enriched(alert_id)

    with (
        patch(
            "soc_ai.tools.get_alert_context.get_enriched_alert_context",
            side_effect=_stub_enriched,
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synthesizer_model",
            return_value=TestModel(call_tools=[], custom_output_args=local_fp),
        ),
        patch("soc_ai.oracle.client.adjudicate", new=AsyncMock(return_value=flip)),
    ):
        events = [ev async for ev in investigate("beacon-001", ctx=ctx)]
    assert _final(events)["verdict"] == "needs_more_info"
    adj = _adjudication(events)
    assert (adj["override_withheld"], adj["oracle_verdict"], adj["oracle_confidence"]) == (
        True,
        "true_positive",
        0.91,
    )


# ── The auto-acknowledge ─────────────────────────────────────────────────────


async def test_a_withheld_dissent_on_a_local_false_positive_blocks_the_auto_ack(
    settings_kratos: Settings,
) -> None:
    """A confident local FP that the Oracle disputes is never written back unattended."""
    settings_kratos.auto_ack_fp_enabled = True
    settings_kratos.auto_ack_fp_threshold = 0.5
    ctx = MagicMock()
    ctx.settings = settings_kratos
    report = TriageReport(
        verdict="false_positive",
        confidence=0.95,
        summary="Benign.",
        citations=[PIVOT_ID],
        recommended_actions=[],
    )
    emitted: list[tuple[str, dict[str, Any]]] = []

    def _emit(kind: str, payload: dict[str, Any]) -> Any:
        emitted.append((kind, payload))
        return MagicMock(kind=kind, payload=payload)

    write = AsyncMock(return_value=({"ok": True}, None))
    with patch("soc_ai.agent.orchestrator.execute_write_tool", write):
        ev = await maybe_auto_ack_fp(
            report,
            "beacon-001",
            alert=SoAlert(id="beacon-001", severity_label="low"),
            ctx=ctx,
            emit_ev=_emit,
            audit_ev=AsyncMock(),
            investigated=True,
            citation_coverage=1.0,
            oracle_dissent=True,
        )
    write.assert_not_awaited()
    assert ev is not None
    assert emitted == [
        (
            "auto_ack_skipped",
            {
                "es_id": "beacon-001",
                "reason": "oracle_dissent",
                "confidence": 0.95,
                "threshold": 0.5,
            },
        )
    ]


# ── The console ──────────────────────────────────────────────────────────────


def test_the_card_and_the_timeline_call_it_an_opinion() -> None:
    events = [
        MagicMock(
            kind="oracle_escalation",
            payload={"reason": "needs_more_info", "local_verdict": "needs_more_info"},
        ),
        MagicMock(
            kind="oracle_adjudication",
            payload={
                "oracle_verdict": "false_positive",
                "oracle_confidence": 0.93,
                "override_withheld": True,
                "local_verdict": "needs_more_info",
            },
        ),
    ]
    out = _build_oracle(events)
    assert out is not None
    assert out.withheld is True
    assert title_for("oracle_adjudication", events[1].payload) == (
        "Oracle opinion: false positive (0.93). No evidence resolved. The local verdict stands"
    )
