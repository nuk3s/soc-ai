"""An unattended write never acts against an analyst verdict (dogfood 2026-10-19, R2-D1).

The analyst overrode a false positive to true positive and pressed Re-run. The
new run reached false positive at 0.80, and the auto-acknowledge closed the
alert in Security Onion. Nothing on that path read the analyst verdict: the new
run has no resolution of its own, and the override sits on an EARLIER run of
the alert.

The plants sit on the paths a careless guard would miss:

- the re-run path, where the analyst verdict is on an earlier run and the
  newest complete run of the alert is a model false positive;
- the inheritance fan-out, where the cluster's representative event is clean
  and a SIBLING event carries the analyst verdict.

Each guard has a negative control: an analyst false positive, or an analyst
verdict on another alert, still lets the acknowledgement through.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic_ai.models.test import TestModel
from soc_ai.agent.orchestrator import InvestigationContext, investigate
from soc_ai.config import Settings
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.store import investigations as inv_svc
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.triage_models import TriageReport

from tests.test_agent import (
    _fake_loop_investigator_with_zeek_call,
    _non_malware_benign_enriched,
)

ALERT = "benign-001"
ANALYST_HEADER = "## Analyst verdict on this alert"


async def _maker(settings: Settings) -> Any:
    engine = make_engine(settings)
    await run_migrations(engine)
    return make_sessionmaker(engine)


async def _complete_run(maker: Any, alert_es_id: str, verdict: str) -> str:
    """One COMPLETE model run on the alert. Returns its id."""
    async with maker() as db:
        inv = await inv_svc.create(
            db, alert_es_id=alert_es_id, started_by="t", rule_name="ET INFO Observed DNS Query"
        )
        await inv_svc.finalize(
            db,
            inv.id,
            status="complete",
            verdict=verdict,
            confidence=0.8,
            rationale="The model read the flow.",
        )
        return str(inv.id)


async def _override(maker: Any, inv_id: str, verdict: str) -> None:
    """The analyst's manual override, through the same store call the route uses."""
    async with maker() as db:
        await inv_svc.resolve(
            db,
            inv_id,
            verdict=verdict,
            confidence=1.0,
            rationale="Verdict set by analyst1: the DNS name is a known C2 domain.",
            recommended_actions=[],
            resolved_by="analyst1",
            resolved_via="manual",
        )


def _ctx(settings: Settings, maker: Any) -> InvestigationContext:
    fake_es = AsyncMock()
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es):
        elastic = ElasticClient(settings)
    return InvestigationContext(
        settings=settings, auth=AsyncMock(), elastic=elastic, db_sessionmaker=maker
    )


async def _rerun(settings: Settings, maker: Any) -> tuple[list[Any], AsyncMock, Any, Any]:
    """A run that investigates, settles false positive at 0.9 and would auto-ack.

    The same shape as ``test_auto_ack_still_fires_when_the_run_did_investigate``
    in tests/test_agent.py, with a store on the context.
    """
    settings.investigate_when_unsure = True
    settings.auto_ack_fp_enabled = True
    settings.auto_ack_fp_threshold = 0.7
    ctx = _ctx(settings, maker)
    fake_investigator = _fake_loop_investigator_with_zeek_call()
    settled = TriageReport(
        verdict="false_positive",
        confidence=0.9,
        summary="Zeek shows the SNI belongs to the vendor's update service.",
        citations=["(tool t_query_zeek_logs)"],
    )
    loop_synth_result = MagicMock()
    loop_synth_result.output = settled
    loop_synth_result.usage = MagicMock(side_effect=RuntimeError("no usage in stub"))
    fake_loop_synth = MagicMock()
    fake_loop_synth.run = AsyncMock(return_value=loop_synth_result)

    async def _stub_enriched(alert_id: str, **_kw: Any) -> Any:
        return _non_malware_benign_enriched(alert_id)

    write = AsyncMock(return_value=({"ok": True}, None))
    with (
        patch(
            "soc_ai.tools.get_alert_context.get_enriched_alert_context",
            side_effect=_stub_enriched,
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synthesizer_model",
            return_value=TestModel(call_tools=[]),
        ),
        patch("soc_ai.agent.orchestrator.build_investigator", return_value=fake_investigator),
        patch("soc_ai.agent.orchestrator.build_synthesizer", return_value=fake_loop_synth),
        patch("soc_ai.agent.orchestrator.execute_write_tool", write),
        patch("soc_ai.agent.decision_templates.match_decision_template", return_value=None),
    ):
        events = [ev async for ev in investigate(ALERT, ctx=ctx)]
    return events, write, fake_investigator, fake_loop_synth


def _payload(events: list[Any], kind: str) -> dict[str, Any]:
    for e in events:
        if e.kind == kind:
            return dict(e.payload)
    raise AssertionError(f"no {kind!r} event in {[e.kind for e in events]}")


# ── The direct auto-acknowledge ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_rerun_never_acks_an_alert_the_analyst_called_a_true_positive(
    settings_kratos: Settings,
) -> None:
    """The defect, on the path the guard would miss. The analyst verdict is on
    the FIRST run. A second model run already landed false positive after it,
    so the alert's newest complete run says false positive. The third run is
    the re-run under test."""
    maker = await _maker(settings_kratos)
    first = await _complete_run(maker, ALERT, "false_positive")
    await _override(maker, first, "true_positive")
    await _complete_run(maker, ALERT, "false_positive")

    events, write, _inv, _synth = await _rerun(settings_kratos, maker)

    write.assert_not_awaited()
    assert not any(e.kind == "auto_ack" for e in events)
    skipped = _payload(events, "auto_ack_skipped")
    assert skipped["reason"] == "analyst_verdict"
    assert skipped["analyst_verdict"] == "true_positive"
    assert skipped["analyst_investigation_id"] == first


@pytest.mark.asyncio
async def test_an_analyst_needs_more_info_also_holds_the_ack(settings_kratos: Settings) -> None:
    """An analyst who asked for more information did not close the alert."""
    maker = await _maker(settings_kratos)
    first = await _complete_run(maker, ALERT, "false_positive")
    await _override(maker, first, "needs_more_info")

    events, write, _inv, _synth = await _rerun(settings_kratos, maker)

    write.assert_not_awaited()
    assert _payload(events, "auto_ack_skipped")["reason"] == "analyst_verdict"


@pytest.mark.asyncio
async def test_an_analyst_false_positive_still_lets_the_ack_through(
    settings_kratos: Settings,
) -> None:
    """NEGATIVE CONTROL. The analyst agrees with the ack, and an analyst true
    positive on ANOTHER alert says nothing about this one. Without this the
    guard could pass by refusing every ack."""
    maker = await _maker(settings_kratos)
    first = await _complete_run(maker, ALERT, "true_positive")
    await _override(maker, first, "false_positive")
    other = await _complete_run(maker, "another-alert", "false_positive")
    await _override(maker, other, "true_positive")

    events, write, _inv, _synth = await _rerun(settings_kratos, maker)

    write.assert_awaited_once()
    assert _payload(events, "auto_ack")["success"] is True


@pytest.mark.asyncio
async def test_a_store_that_cannot_answer_holds_the_ack(settings_kratos: Settings) -> None:
    """Fail closed. A store that did not answer is not permission to write."""
    maker = await _maker(settings_kratos)
    boom = AsyncMock(side_effect=RuntimeError("db down"))
    with patch.object(inv_svc, "analyst_verdicts_for_alerts", boom):
        events, write, _inv, _synth = await _rerun(settings_kratos, maker)

    write.assert_not_awaited()
    assert _payload(events, "auto_ack_skipped")["reason"] == "analyst_verdict_unknown"


# ── The re-run reads the analyst verdict ────────────────────────────────────


@pytest.mark.asyncio
async def test_the_rerun_is_told_the_analyst_verdict(settings_kratos: Settings) -> None:
    """R2-D1 (b). The investigator and the verdict writer both read the fact,
    and the timeline records that the run read it."""
    maker = await _maker(settings_kratos)
    first = await _complete_run(maker, ALERT, "false_positive")
    await _override(maker, first, "true_positive")

    events, _write, fake_investigator, fake_loop_synth = await _rerun(settings_kratos, maker)

    seen = _payload(events, "analyst_verdict")
    assert seen["id"] == first
    assert seen["verdict"] == "true_positive"
    inv_prompt = str(fake_investigator.iter.call_args.args[0])
    synth_prompt = str(fake_loop_synth.run.call_args.args[0])
    for prompt in (inv_prompt, synth_prompt):
        assert ANALYST_HEADER in prompt
        assert f"on investigation {first}, an analyst set the verdict to true_positive" in prompt
        # The analyst's words reach the run. The analyst's name does not.
        assert "known C2 domain" in prompt
        assert "analyst1" not in prompt


@pytest.mark.asyncio
async def test_a_run_with_no_analyst_verdict_reads_no_block(settings_kratos: Settings) -> None:
    """NEGATIVE CONTROL. A model verdict on the alert is not an analyst verdict."""
    maker = await _maker(settings_kratos)
    await _complete_run(maker, ALERT, "true_positive")

    events, _write, fake_investigator, _synth = await _rerun(settings_kratos, maker)

    assert "analyst_verdict" not in [e.kind for e in events]
    assert ANALYST_HEADER not in str(fake_investigator.iter.call_args.args[0])


# ── The store ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_the_newest_analyst_resolution_stands(settings_kratos: Settings) -> None:
    """Over every run of the alert, the newest resolution wins. A model run
    and a pipeline fallback are never an analyst verdict."""
    maker = await _maker(settings_kratos)
    first = await _complete_run(maker, ALERT, "false_positive")
    await _override(maker, first, "true_positive")
    second = await _complete_run(maker, ALERT, "true_positive")
    await _override(maker, second, "false_positive")
    await _complete_run(maker, ALERT, "true_positive")
    model_only = await _complete_run(maker, "model-only", "true_positive")

    async with maker() as db:
        got = await inv_svc.analyst_verdicts_for_alerts(db, [ALERT, "model-only", ""])

    assert set(got) == {ALERT}
    assert got[ALERT].investigation_id == second
    assert got[ALERT].verdict == "false_positive"
    assert got[ALERT].resolved_by == "analyst1"
    assert model_only not in {v.investigation_id for v in got.values()}


# ── The inheritance fan-out ─────────────────────────────────────────────────


def _hit(es_id: str) -> dict[str, Any]:
    return {
        "_id": es_id,
        "_source": {
            "@timestamp": "2026-06-12T06:41:00.000Z",
            "source": {"ip": "192.0.2.41"},
            "destination": {"ip": "192.0.2.1"},
            "rule": {"name": "ET SCAN thing"},
            "event": {"severity_label": "low"},
        },
    }


def _grounded(maker: Any, inv_id: str) -> None:
    """Give the inheritance source a successful retrieval, the bar it must pass."""

    async def _go() -> None:
        async with maker() as db:
            await inv_svc.append_events(
                db,
                inv_id,
                [
                    {
                        "sequence": 1,
                        "kind": "tool_result",
                        "payload": {
                            "tool_name": "t_query_events",
                            "result": {"total": 1, "hits": [{"_id": "a"}]},
                        },
                    }
                ],
            )

    asyncio.run(_go())


class _State:
    def __init__(self, settings: Settings, maker: Any, es: Any) -> None:
        self.settings = settings
        self.db_sessionmaker = maker
        with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=es):
            self.elastic = ElasticClient(settings)


def _fan_out(settings: Settings, maker: Any, source: str, ids: list[str]) -> tuple[Any, Any]:
    from types import SimpleNamespace

    from soc_ai.webui import autotriage as at

    settings.auto_ack_fp_enabled = True
    es = AsyncMock()
    es.search.return_value = {
        "took": 1,
        "hits": {
            "total": {"value": len(ids), "relation": "eq"},
            "hits": [_hit(i) for i in ids],
        },
    }
    state = _State(settings, maker, es)
    status = at.AutoTriageStatus()
    acks = [
        at.InheritedAck(
            alert_es_id=i, rule_name="ET SCAN thing", inherited_from=source, confidence=0.9
        )
        for i in ids
    ]
    ctx = SimpleNamespace(auth=AsyncMock(), settings=settings, audit=None)
    write = AsyncMock(return_value=({"ok": True}, None))
    with patch("soc_ai.tools.write_exec.execute_write_tool", write):
        asyncio.run(at._ack_inherited_fps(state, ctx, acks, status))
    return write, status


def test_an_inherited_false_positive_never_acks_a_sibling_the_analyst_held(
    settings_kratos: Settings,
) -> None:
    """The fan-out path. The source run is a grounded false positive, the
    planner checked only the cluster's representative, and one sibling event
    carries its own analyst true positive. The sibling is not acked. The
    clean sibling is, so the guard is no off switch."""
    maker = asyncio.run(_maker(settings_kratos))
    source = asyncio.run(_complete_run(maker, "src-ev", "false_positive"))
    _grounded(maker, source)
    held = asyncio.run(_complete_run(maker, "ev-held", "false_positive"))
    asyncio.run(_override(maker, held, "true_positive"))

    write, status = _fan_out(settings_kratos, maker, source, ["ev-held", "ev-clean"])

    write.assert_awaited_once()
    assert write.await_args.args[1] == {"alert_id": "ev-clean"}
    assert status.inherited_acked == 1
    assert status.inherited_refused == {"analyst_verdict": 1}


def test_the_fan_out_fails_closed_on_a_store_error(settings_kratos: Settings) -> None:
    maker = asyncio.run(_maker(settings_kratos))
    source = asyncio.run(_complete_run(maker, "src-ev", "false_positive"))
    _grounded(maker, source)
    boom = AsyncMock(side_effect=RuntimeError("db down"))
    with patch.object(inv_svc, "analyst_verdicts_for_alerts", boom):
        write, status = _fan_out(settings_kratos, maker, source, ["ev-clean"])
    write.assert_not_awaited()
    assert status.inherited_refused == {"analyst_verdict": 1}
