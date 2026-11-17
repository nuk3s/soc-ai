"""No unattended acknowledge of an alert that an earlier run called a true positive.

Production, 2026-11-13. An earlier run of an alert reached true positive, and
an evidence gate lowered it to needs more info. Hours later a new run of the
same alert reached false positive at 0.82, and the auto-acknowledge wrote the
acknowledge to Security Onion with no person. Nothing on that path read the
earlier runs of the alert.

The plants sit on the paths a careless guard would miss: a final verdict that
is not true positive over a stored model verdict that was, an Oracle answer
that lives in an event and not on the row, and a gate step that is not the
first step. The negative controls show that the guard is no off switch: an
earlier false positive, an earlier failed run, a backtest replay and a
synthetic run do not hold the acknowledge.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from soc_ai.api.webui._timeline import _build_actions
from soc_ai.api.webui.routes_meta import waiting_actions_by_run
from soc_ai.config import Settings
from soc_ai.store import investigations as inv_svc
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import Investigation
from soc_ai.triage_models import RecommendedAction
from sqlalchemy import event

from tests.test_analyst_verdict_guard import (
    ALERT,
    _complete_run,
    _fan_out,
    _grounded,
    _maker,
    _payload,
    _rerun,
)

HELD_NOTE = (
    "An earlier investigation of this alert gave a true positive. "
    "soc-ai does not acknowledge it without you."
)


async def _run(
    maker: Any,
    alert_es_id: str,
    *,
    status: str = "complete",
    verdict: str | None,
    report: dict[str, Any] | None = None,
    started_by: str = "t",
    is_synth_eval: bool = False,
    events: list[dict[str, Any]] | None = None,
) -> str:
    """One earlier run of the alert, in the shape the recorder stores. Returns its id."""
    async with maker() as db:
        inv = await inv_svc.create(
            db,
            alert_es_id=alert_es_id,
            started_by=started_by,
            rule_name="ET INFO Observed DNS Query",
            is_synth_eval=is_synth_eval,
        )
        if events:
            await inv_svc.append_events(db, inv.id, events)
        await inv_svc.finalize(
            db,
            inv.id,
            status=status,
            verdict=verdict,
            confidence=0.8 if verdict else None,
            rationale="The model read the flow." if verdict else None,
            report=report,
        )
        return str(inv.id)


def _oracle(verdict: str) -> list[dict[str, Any]]:
    return [
        {
            "sequence": 1,
            "kind": "oracle_adjudication",
            "payload": {"oracle_verdict": verdict, "oracle_confidence": 0.8},
        }
    ]


def _assert_held(events: list[Any], write: AsyncMock, earlier: str) -> None:
    write.assert_not_awaited()
    assert not any(e.kind == "auto_ack" for e in events)
    skipped = _payload(events, "auto_ack_skipped")
    assert skipped["reason"] == "earlier_true_positive"
    assert skipped["earlier_investigation_id"] == earlier


def _assert_acked(events: list[Any], write: AsyncMock) -> None:
    write.assert_awaited_once()
    assert _payload(events, "auto_ack")["success"] is True
    assert "auto_ack_skipped" not in [e.kind for e in events]


# ── The direct auto-acknowledge ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_the_production_shape_holds_the_ack_and_the_action_waits(
    settings_kratos: Settings,
) -> None:
    """The defect. The earlier run reads needs more info on the row, and its
    stored report keeps the model verdict true positive. The new run reaches
    false positive and would acknowledge. The write waits for the analyst."""
    maker = await _maker(settings_kratos)
    earlier = await _run(
        maker,
        ALERT,
        verdict="needs_more_info",
        report={"verdict": "needs_more_info", "local_verdict": "true_positive"},
    )

    ack_action = RecommendedAction(
        tool_name="ack_alert", tool_args={"alert_id": ALERT}, rationale="Benign update traffic."
    )
    events, write, _inv, _synth = await _rerun(settings_kratos, maker, [ack_action])

    _assert_held(events, write, earlier)
    report = _payload(events, "triage_report")
    assert report["verdict"] == "false_positive"
    ack = [a for a in _build_actions(events, report) if a.tag == "ack"]
    assert ack, "the false positive run keeps its Acknowledge action"
    assert ack[0].applied is False
    assert ack[0].pendingNote == HELD_NOTE

    # The run as the recorder stores it: the Acknowledge action counts as a
    # waiting action of the run, the same as after a high-stakes hold.
    async with maker() as db:
        inv = await inv_svc.create(db, alert_es_id=ALERT, started_by="t")
        await inv_svc.append_events(
            db,
            inv.id,
            [
                {"sequence": i, "kind": e.kind, "payload": dict(e.payload)}
                for i, e in enumerate(events)
                if e.kind in ("auto_ack_skipped", "auto_ack")
            ],
        )
        await inv_svc.finalize(
            db, inv.id, status="complete", verdict="false_positive", report=report
        )
        run = await db.get(Investigation, inv.id)
        waiting = await waiting_actions_by_run(db, [run])
    assert [(w.type, w.executable) for w in waiting.get(inv.id, [])] == [("ack", True)]


@pytest.mark.asyncio
async def test_an_earlier_final_true_positive_holds_the_ack(settings_kratos: Settings) -> None:
    maker = await _maker(settings_kratos)
    earlier = await _complete_run(maker, ALERT, "true_positive")

    events, write, _inv, _synth = await _rerun(settings_kratos, maker)

    _assert_held(events, write, earlier)


@pytest.mark.asyncio
async def test_an_earlier_oracle_true_positive_holds_the_ack(settings_kratos: Settings) -> None:
    """The Oracle answer is an event of the run. The row reads false positive."""
    maker = await _maker(settings_kratos)
    earlier = await _run(
        maker,
        ALERT,
        verdict="false_positive",
        report={"verdict": "false_positive"},
        events=_oracle("true_positive"),
    )

    events, write, _inv, _synth = await _rerun(settings_kratos, maker)

    _assert_held(events, write, earlier)


@pytest.mark.asyncio
async def test_an_earlier_gate_step_from_true_positive_holds_the_ack(
    settings_kratos: Settings,
) -> None:
    """The second step of the change starts at true positive. The origin of
    the whole change does not, so a reader of the top level alone misses it."""
    maker = await _maker(settings_kratos)
    earlier = await _run(
        maker,
        ALERT,
        verdict="needs_more_info",
        report={
            "verdict": "needs_more_info",
            "verdict_change": {
                "from_verdict": "needs_more_info",
                "to_verdict": "needs_more_info",
                "steps": [
                    {"from_verdict": "needs_more_info", "to_verdict": "true_positive"},
                    {"fromVerdict": "true_positive", "toVerdict": "needs_more_info"},
                ],
            },
        },
    )

    events, write, _inv, _synth = await _rerun(settings_kratos, maker)

    _assert_held(events, write, earlier)


@pytest.mark.asyncio
async def test_a_store_that_cannot_read_the_earlier_runs_holds_the_ack(
    settings_kratos: Settings,
) -> None:
    """Fail closed. A store that did not answer is not permission to write."""
    maker = await _maker(settings_kratos)
    boom = AsyncMock(side_effect=RuntimeError("db down"))
    with patch.object(inv_svc, "earlier_true_positive_runs", boom):
        events, write, _inv, _synth = await _rerun(settings_kratos, maker)

    write.assert_not_awaited()
    assert _payload(events, "auto_ack_skipped")["reason"] == "earlier_runs_unread"


# ── Negative controls ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_an_earlier_false_positive_lets_the_ack_through(settings_kratos: Settings) -> None:
    """NEGATIVE CONTROL. An earlier false positive, with an Oracle false
    positive, and a true positive on ANOTHER alert do not hold this ack."""
    maker = await _maker(settings_kratos)
    await _run(
        maker,
        ALERT,
        verdict="false_positive",
        report={"verdict": "false_positive", "local_verdict": "needs_more_info"},
        events=_oracle("false_positive"),
    )
    await _complete_run(maker, "another-alert", "true_positive")

    events, write, _inv, _synth = await _rerun(settings_kratos, maker)

    _assert_acked(events, write)


@pytest.mark.asyncio
async def test_an_earlier_failed_run_lets_the_ack_through(settings_kratos: Settings) -> None:
    """NEGATIVE CONTROL. A run that failed with no verdict leans neither way."""
    maker = await _maker(settings_kratos)
    await _run(maker, ALERT, status="error", verdict=None)

    events, write, _inv, _synth = await _rerun(settings_kratos, maker)

    _assert_acked(events, write)


@pytest.mark.asyncio
async def test_an_earlier_replay_or_synthetic_true_positive_lets_the_ack_through(
    settings_kratos: Settings,
) -> None:
    """NEGATIVE CONTROL. A backtest replay and a synthetic-evaluation run are
    measurements. Neither is a verdict about the live alert."""
    maker = await _maker(settings_kratos)
    await _run(
        maker,
        ALERT,
        verdict="true_positive",
        report={"verdict": "true_positive"},
        started_by=inv_svc.BACKTEST_ACTOR,
    )
    await _run(
        maker,
        ALERT,
        verdict="true_positive",
        report={"verdict": "true_positive"},
        is_synth_eval=True,
    )

    events, write, _inv, _synth = await _rerun(settings_kratos, maker)

    _assert_acked(events, write)


@pytest.mark.asyncio
async def test_no_earlier_run_lets_the_ack_through(settings_kratos: Settings) -> None:
    """NEGATIVE CONTROL. The first run of an alert acknowledges as before."""
    maker = await _maker(settings_kratos)

    events, write, _inv, _synth = await _rerun(settings_kratos, maker)

    _assert_acked(events, write)


# ── The store ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_the_store_answers_a_batch_in_one_query(settings_kratos: Settings) -> None:
    """One statement for every alert of the batch. A run with no verdict, as
    the current run is until its recorder finalizes it, is left out, and so
    is a run the caller excludes."""
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    maker = make_sessionmaker(engine)
    leaned = await _run(
        maker,
        "ev-a",
        verdict="needs_more_info",
        report={"verdict": "needs_more_info", "local_verdict": "true_positive"},
    )
    await _complete_run(maker, "ev-b", "false_positive")
    async with maker() as db:
        running = await inv_svc.create(db, alert_es_id="ev-c", started_by="t")
        await inv_svc.append_events(db, running.id, _oracle("true_positive"))
    excluded = await _complete_run(maker, "ev-d", "true_positive")

    statements: list[str] = []

    def _count(_conn: Any, _cursor: Any, sql: str, *_args: Any) -> None:
        statements.append(sql)

    event.listen(engine.sync_engine, "before_cursor_execute", _count)
    try:
        async with maker() as db:
            got = await inv_svc.earlier_true_positive_runs(
                db, ["ev-a", "ev-b", "ev-c", "ev-d", ""], exclude_ids=[excluded]
            )
    finally:
        event.remove(engine.sync_engine, "before_cursor_execute", _count)

    assert got == {"ev-a": leaned}
    assert len(statements) == 1


# ── The inheritance fan-out ─────────────────────────────────────────────────


def test_an_inherited_false_positive_never_acks_a_sibling_an_earlier_run_called_true(
    settings_kratos: Settings,
) -> None:
    """Three alerts of the cluster. One has an earlier run that leaned true
    positive and is left. The other two are acknowledged. One store read
    covers the batch."""
    maker = asyncio.run(_maker(settings_kratos))
    source = asyncio.run(_complete_run(maker, "src-ev", "false_positive"))
    _grounded(maker, source)
    asyncio.run(
        _run(
            maker,
            "ev-held",
            verdict="needs_more_info",
            report={"verdict": "needs_more_info", "local_verdict": "true_positive"},
        )
    )
    asyncio.run(_complete_run(maker, "ev-two", "false_positive"))

    real = inv_svc.earlier_true_positive_runs
    calls: list[list[str]] = []

    async def _spy(db: Any, alert_ids: Any, **kw: Any) -> Any:
        calls.append(list(alert_ids))
        return await real(db, alert_ids, **kw)

    with patch.object(inv_svc, "earlier_true_positive_runs", _spy):
        write, status = _fan_out(settings_kratos, maker, source, ["ev-held", "ev-one", "ev-two"])

    assert [c.args[1] for c in write.await_args_list] == [
        {"alert_id": "ev-one"},
        {"alert_id": "ev-two"},
    ]
    assert status.inherited_acked == 2
    assert status.inherited_refused == {"earlier_true_positive": 1}
    assert len(calls) == 1
    assert sorted(calls[0]) == ["ev-held", "ev-one", "ev-two"]


def test_the_fan_out_holds_every_ack_when_the_earlier_runs_are_unread(
    settings_kratos: Settings,
) -> None:
    maker = asyncio.run(_maker(settings_kratos))
    source = asyncio.run(_complete_run(maker, "src-ev", "false_positive"))
    _grounded(maker, source)
    boom = AsyncMock(side_effect=RuntimeError("db down"))
    with patch.object(inv_svc, "earlier_true_positive_runs", boom):
        write, status = _fan_out(settings_kratos, maker, source, ["ev-one", "ev-two"])
    write.assert_not_awaited()
    assert status.inherited_refused == {"earlier_runs_unread": 2}
