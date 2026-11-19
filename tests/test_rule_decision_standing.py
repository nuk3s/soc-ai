"""The standing rule decision lifts the hold high_stakes and no other guard (round 3, RS5).

With a standing decision in force for a rule, the hold ``high_stakes`` does
not apply in ``maybe_auto_ack_fp`` and in the inherited fan-out. Every other
guard stays: the threshold, no investigation, uncited, the Oracle dissent,
an analyst verdict, an earlier true positive and ``auto_ack_fp_enabled``.
The decision ends after its term, when the analyst ends it, and at once when
an investigation of the rule gets a true positive verdict.

Each negative control plants the case on the path that the lifted hold would
reach. The Security Onion write is a fake, and the data is synthetic.
"""

from __future__ import annotations

import asyncio
from datetime import timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.agent.orchestrator import InvestigationContext, maybe_auto_ack_fp
from soc_ai.config import Settings
from soc_ai.so_client.models import SoAlert
from soc_ai.store import investigations as inv_svc
from soc_ai.store import rule_decisions as rd_store
from soc_ai.store.auth import utcnow
from soc_ai.store.models import RuleDecision
from soc_ai.triage_models import TriageReport
from soc_ai.webui import rule_decisions as rd

from tests import test_autotriage as autotriage_tests
from tests.test_autotriage import (
    _FakeState,
    _seed_investigation,
    at_settings,  # noqa: F401 - the shared fixture
)
from tests.test_rule_decision_api import Audit, client  # noqa: F401 - the shared fixture
from tests.test_rule_decision_selection import OTHER_RULE, RULE, maker_for, seed_fp

WRITE = "soc_ai.agent.orchestrator.execute_write_tool"


def exploit_alert(alert_id: str = "ev-new", rule: str = RULE) -> SoAlert:
    """A high stakes alert: an exploit classification."""
    return SoAlert(
        id=alert_id,
        rule_name=rule,
        classtype="Web Application Attack",
        severity_label="high",
        severity_score=3,
        event_module="suricata",
        event_dataset="suricata.alert",
    )


async def standing(maker: Any, *, rule: str = RULE, ends_in: timedelta = timedelta(days=30)) -> int:
    now = utcnow()
    async with maker() as db:
        row = rd_store.new_decision(
            rule_name=rule,
            decision="standing",
            include_weak=False,
            note="",
            by="analyst1",
            at=now - timedelta(minutes=5),
            ends_at=now + ends_in,
        )
        row.state = "done"
        db.add(row)
        await db.commit()
        return int(row.id)


def ctx_for(settings: Settings, maker: Any, **over: Any) -> InvestigationContext:
    values = {"auto_ack_fp_enabled": True, "auto_ack_fp_threshold": 0.7, **over}
    return InvestigationContext(
        settings=settings.model_copy(update=values),
        auth=AsyncMock(),
        elastic=AsyncMock(),
        db_sessionmaker=maker,
    )


async def auto_ack(
    ctx: InvestigationContext,
    *,
    alert: SoAlert | None = None,
    confidence: float = 0.9,
    citations: list[str] | None = None,
    investigated: bool = True,
    oracle_dissent: bool = False,
) -> tuple[Any, AsyncMock]:
    target = alert or exploit_alert()
    report = TriageReport(
        verdict="false_positive",
        confidence=confidence,
        summary="test",
        citations=["ev1"] if citations is None else citations,
        recommended_actions=[],
    )
    emit, audit, _captured = autotriage_tests.TestMaybeAutoAckFp._make_emit_audit()
    write = AsyncMock(return_value=({"ok": True}, None))
    with patch(WRITE, write):
        result = await maybe_auto_ack_fp(
            report,
            target.id,
            alert=target,
            ctx=ctx,
            emit_ev=emit,
            audit_ev=audit,
            investigated=investigated,
            oracle_dissent=oracle_dissent,
        )
    return result, write


async def decision(maker: Any, decision_id: int) -> RuleDecision:
    async with maker() as db:
        row = await db.get(RuleDecision, decision_id)
        assert row is not None
        return row


# ── The direct path ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_standing_decision_lifts_the_hold_high_stakes(settings_kratos: Settings) -> None:
    maker = await maker_for(settings_kratos)
    held, write = await auto_ack(ctx_for(settings_kratos, maker))
    # Control: with no decision the hold stands.
    write.assert_not_awaited()
    assert held.payload["reason"] == "high_stakes"

    decision_id = await standing(maker)
    result, write = await auto_ack(ctx_for(settings_kratos, maker))

    write.assert_awaited_once()
    assert result.kind == "auto_ack"
    assert result.payload["rule_decision"] == decision_id
    assert result.payload["rule_key"] == rd.rule_key(RULE)
    assert (await decision(maker, decision_id)).acknowledged == 1


@pytest.mark.asyncio
async def test_the_decision_of_another_rule_lifts_nothing(settings_kratos: Settings) -> None:
    """NEGATIVE CONTROL: the decision names one rule."""
    maker = await maker_for(settings_kratos)
    await standing(maker, rule="ET POLICY ws-1 other rule")

    result, write = await auto_ack(ctx_for(settings_kratos, maker))

    write.assert_not_awaited()
    assert result.payload["reason"] == "high_stakes"


@pytest.mark.parametrize(
    ("over", "reason"),
    [
        ({"confidence": 0.5}, "below_threshold"),
        ({"investigated": False}, "no_investigation"),
        ({"citations": []}, "uncited"),
        ({"oracle_dissent": True}, "oracle_dissent"),
    ],
)
@pytest.mark.asyncio
async def test_every_other_guard_still_holds_under_a_standing_decision(
    settings_kratos: Settings, over: dict[str, Any], reason: str
) -> None:
    """NEGATIVE CONTROL: a confidence under the limit, and each evidence guard, still hold."""
    maker = await maker_for(settings_kratos)
    await standing(maker)

    result, write = await auto_ack(ctx_for(settings_kratos, maker), **over)

    write.assert_not_awaited()
    assert result.kind == "auto_ack_skipped"
    assert result.payload["reason"] == reason


@pytest.mark.asyncio
async def test_an_analyst_verdict_and_an_earlier_true_positive_still_hold(
    settings_kratos: Settings,
) -> None:
    """NEGATIVE CONTROL: the two store guards read the alert while the decision is in force."""
    maker = await maker_for(settings_kratos)
    await standing(maker)
    first = await seed_fp(maker, "ev-analyst", reason=None)
    async with maker() as db:
        await inv_svc.resolve(
            db,
            first,
            verdict="needs_more_info",
            confidence=1.0,
            rationale="Verdict set by analyst1.",
            recommended_actions=[],
            resolved_by="analyst1",
            resolved_via="manual",
        )
    # An earlier run of the alert under another rule name leaned true positive.
    await seed_fp(maker, "ev-earlier", rule=OTHER_RULE, verdict="true_positive")
    ctx = ctx_for(settings_kratos, maker)

    analyst, write = await auto_ack(ctx, alert=exploit_alert("ev-analyst"))
    write.assert_not_awaited()
    assert analyst.payload["reason"] == "analyst_verdict"

    earlier, write = await auto_ack(ctx, alert=exploit_alert("ev-earlier"))
    write.assert_not_awaited()
    assert earlier.payload["reason"] == "earlier_true_positive"

    # The decision was in force the whole time: the guards held, not its end.
    async with maker() as db:
        assert await rd_store.in_force(db, RULE, now=utcnow()) is not None


@pytest.mark.asyncio
async def test_with_auto_ack_off_a_standing_decision_acknowledges_nothing(
    settings_kratos: Settings,
) -> None:
    """NEGATIVE CONTROL: the decision acts through the automatic acknowledge only."""
    maker = await maker_for(settings_kratos)
    await standing(maker)

    result, write = await auto_ack(ctx_for(settings_kratos, maker, auto_ack_fp_enabled=False))

    write.assert_not_awaited()
    assert result is None


@pytest.mark.asyncio
async def test_a_true_positive_ends_the_decision_and_the_next_false_positive_is_held(
    settings_kratos: Settings,
) -> None:
    """NEGATIVE CONTROL: a true positive verdict on the rule ends the decision at once."""
    maker = await maker_for(settings_kratos)
    decision_id = await standing(maker)
    _ok, write = await auto_ack(ctx_for(settings_kratos, maker), alert=exploit_alert("ev-1"))
    write.assert_awaited_once()

    await seed_fp(maker, "ev-tp", verdict="true_positive")
    held, write = await auto_ack(ctx_for(settings_kratos, maker), alert=exploit_alert("ev-2"))

    write.assert_not_awaited()
    assert held.payload["reason"] == "high_stakes"
    audit = Audit()
    state = SimpleNamespace(db_sessionmaker=maker, audit=audit)
    (ended,) = await rd.settle_decisions(state)
    assert ended.id == decision_id and ended.end_cause == "true_positive"
    assert audit.kinds() == ["rule_decision_ended"]
    assert audit.records[0][1]["cause"] == "true_positive"


@pytest.mark.asyncio
async def test_a_decision_ends_after_its_term(settings_kratos: Settings) -> None:
    maker = await maker_for(settings_kratos)
    decision_id = await standing(maker, ends_in=timedelta(seconds=-1))

    held, write = await auto_ack(ctx_for(settings_kratos, maker))

    write.assert_not_awaited()
    assert held.payload["reason"] == "high_stakes"
    (ended,) = await rd.settle_decisions(SimpleNamespace(db_sessionmaker=maker, audit=None))
    assert ended.id == decision_id and ended.end_cause == "expired"
    assert ended.ended_at == ended.ends_at


@pytest.mark.asyncio
async def test_a_store_that_does_not_answer_keeps_the_hold(settings_kratos: Settings) -> None:
    """NEGATIVE CONTROL: no answer is no permission to write."""
    maker = await maker_for(settings_kratos)
    await standing(maker)
    calls = {"n": 0}

    def flaky() -> Any:
        calls["n"] += 1
        # The analyst and earlier-run guards read first, then the decision.
        if calls["n"] == 2:
            raise ConnectionError("the store did not answer")
        return maker()

    result, write = await auto_ack(ctx_for(settings_kratos, flaky))

    write.assert_not_awaited()
    assert result.payload["reason"] == "high_stakes"


# ── The analyst ends it ─────────────────────────────────────────────────────


def test_the_analyst_ends_the_standing_decision(client: TestClient) -> None:  # noqa: F811
    key = rd.rule_key(RULE)
    maker = client.app.state.db_sessionmaker  # type: ignore[attr-defined]
    assert client.post(f"/api/v1/rule-decisions/{key}/end", json={}).status_code == 409
    created = client.post(f"/api/v1/rule-decisions/{key}", json={"decision": "standing"})
    assert created.status_code == 202
    assert created.json()["endsAt"] is not None
    listing = client.get("/api/v1/rule-decisions").json()
    assert [r["id"] for r in listing["standing"]] == [created.json()["id"]]
    page = client.get(f"/api/v1/rule-decisions/{key}").json()
    assert page["standing"]["id"] == created.json()["id"]
    assert page["canStanding"] is False

    ended = client.post(f"/api/v1/rule-decisions/{key}/end", json={})

    assert ended.status_code == 200
    body = ended.json()
    assert body["endCause"] == "analyst" and body["endedAt"] is not None
    listing = client.get("/api/v1/rule-decisions").json()
    assert listing["standing"] == [] and [r["id"] for r in listing["ended"]] == [body["id"]]
    audit: Audit = client.app.state.audit  # type: ignore[attr-defined]
    assert "rule_decision_ended" in audit.kinds()

    async def in_force() -> Any:
        async with maker() as db:
            return await rd_store.in_force(db, RULE, now=utcnow())

    assert asyncio.run(in_force()) is None


# ── The inherited fan-out ───────────────────────────────────────────────────


def _hit(es_id: str) -> dict[str, Any]:
    return {
        "_id": es_id,
        "_source": {
            "@timestamp": "2026-11-10T06:41:00.000Z",
            "source": {"ip": "192.0.2.10"},
            "destination": {"ip": "203.0.113.5"},
            "rule": {"name": RULE},
            "event": {"severity_label": "high", "module": "suricata", "dataset": "suricata.alert"},
            "message": '{"alert": {"category": "Web Application Attack"}}',
        },
    }


def _fan_out(settings: Settings, *, with_decision: str | None) -> tuple[Any, Any, list[Any]]:
    from soc_ai.webui import autotriage as at

    es = AsyncMock()
    es.search.return_value = {
        "took": 1,
        "hits": {"total": {"value": 1, "relation": "eq"}, "hits": [_hit("ev-sib")]},
    }
    state = _FakeState(settings, es)
    source = _seed_investigation(settings, rule_name=RULE, alert_es_id="src-ev")
    autotriage_tests.TestInheritedFpAutoAck._grounded_source(settings, source)
    decision_id = (
        asyncio.run(standing(state.db_sessionmaker, rule=with_decision)) if with_decision else None
    )
    status = at.AutoTriageStatus()
    acks = [
        at.InheritedAck(alert_es_id="ev-sib", rule_name=RULE, inherited_from=source, confidence=0.9)
    ]
    audit = Audit()
    ctx = SimpleNamespace(auth=AsyncMock(), settings=settings, audit=audit)
    write = AsyncMock(return_value=({"ok": True}, None))
    with patch("soc_ai.tools.write_exec.execute_write_tool", write):
        asyncio.run(at._ack_inherited_fps(state, ctx, acks, status))
    return (status, write, [decision_id, state, audit])


def test_the_fan_out_acknowledges_a_high_stakes_sibling_under_a_standing_decision(
    at_settings: Settings,  # noqa: F811
) -> None:
    status, write, (decision_id, state, audit) = _fan_out(at_settings, with_decision=RULE)

    write.assert_awaited_once()
    assert status.inherited_acked == 1
    (record,) = [p for kind, p, _m in audit.records if kind == "auto_ack_inherited"]
    assert record["rule_decision"] == decision_id
    assert asyncio.run(decision(state.db_sessionmaker, decision_id)).acknowledged == 1


def test_the_fan_out_keeps_the_hold_with_no_decision_for_the_rule(
    at_settings: Settings,  # noqa: F811
) -> None:
    """NEGATIVE CONTROL: a decision of another rule lifts nothing in the fan-out."""
    status, write, _rest = _fan_out(at_settings, with_decision="ET POLICY ws-1 other rule")

    write.assert_not_awaited()
    assert status.inherited_refused == {"high_stakes": 1}
