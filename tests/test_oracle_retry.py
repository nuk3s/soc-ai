"""A run whose Oracle call failed is sent again after the pause ends (B3).

Three production runs stayed needs more info because the Oracle call failed:
two on the usage limit of the route and one on a residue refusal (review
2026-11-12, triage finding 2). Two of them were correct true positives that a
gate had lowered. Nothing tried the adjudication again.

The queue is the store (:mod:`soc_ai.oracle.retry`). The auto-triage sweep
reads it and starts a new run of the same alert or finding.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from soc_ai.config import Settings
from soc_ai.oracle import breaker, failures
from soc_ai.oracle import retry as oracle_retry
from soc_ai.oracle.breaker import BREAKER, route_key
from soc_ai.store import investigations as inv_svc
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import Hunt, Investigation
from soc_ai.webui import autotriage as at
from sqlalchemy import update

NOW = datetime.now(UTC)


@pytest.fixture
def settings(settings_kratos: Settings) -> Settings:
    return settings_kratos.model_copy(update={"oracle_enabled": True})


@pytest.fixture
async def maker(settings: Settings) -> AsyncIterator[Any]:
    BREAKER.reset()
    engine = make_engine(settings)
    await run_migrations(engine)
    yield make_sessionmaker(engine)
    await engine.dispose()
    BREAKER.reset()


def _failed(
    error_class: str = failures.QUOTA, paused_until: datetime | None = None
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "reason": "http_error",
        "error_class": error_class,
        "local_verdict": "needs_more_info",
        "local_confidence": 0.5,
    }
    if paused_until is not None:
        payload["paused_until"] = breaker.iso(paused_until)
    return {"sequence": 5, "kind": "oracle_adjudication_failed", "payload": payload}


def _skipped(paused_until: datetime) -> dict[str, Any]:
    return {
        "sequence": 5,
        "kind": "oracle_skipped",
        "payload": {"reason": "oracle_paused", "paused_until": breaker.iso(paused_until)},
    }


async def _run(
    maker: Any,
    *,
    alert_es_id: str = "alert-0001",
    events: list[dict[str, Any]] | None = None,
    age: timedelta = timedelta(hours=2),
    status: str = "complete",
    report: dict[str, Any] | None = None,
    kind: str = "suricata",
    hunt_id: str | None = None,
    finding_ordinal: int | None = None,
    is_synth_eval: bool = False,
    subject: dict[str, Any] | None = None,
) -> str:
    """One stored run, created ``age`` ago. Seeded relative to now."""
    async with maker() as db:
        inv = await inv_svc.create(
            db,
            alert_es_id=alert_es_id,
            started_by="auto-triage:scheduler",
            rule_name="ET INFO Example Rule",
            kind=kind,
            hunt_id=hunt_id,
            finding_ordinal=finding_ordinal,
            is_synth_eval=is_synth_eval,
            subject=subject,
        )
        if events:
            await inv_svc.append_events(db, inv.id, events)
        if status == "complete":
            await inv_svc.finalize(
                db,
                inv.id,
                status="complete",
                verdict="needs_more_info",
                confidence=0.5,
                rationale="The host contacted the domain.",
                report=report or {"verdict": "needs_more_info", "confidence": 0.5},
            )
        await db.execute(
            update(Investigation)
            .where(Investigation.id == inv.id)
            .values(created_at=(NOW - age).replace(tzinfo=None))
        )
        await db.commit()
        return str(inv.id)


async def _pending(
    maker: Any, settings: Settings, **kw: Any
) -> list[oracle_retry.PendingEscalation]:
    return await oracle_retry.pending_escalations(maker, settings, now=NOW, **kw)


# ── the queue ─────────────────────────────────────────────────────────────────


async def test_a_failed_escalation_is_due_after_its_pause(maker: Any, settings: Settings) -> None:
    inv_id = await _run(maker, events=[_failed(paused_until=NOW - timedelta(minutes=5))])
    due = await _pending(maker, settings)
    assert [p.investigation_id for p in due] == [inv_id]
    assert due[0].error_class == failures.QUOTA
    assert due[0].alert_es_id == "alert-0001"
    assert due[0].failed_runs == 1
    assert not due[0].is_finding


async def test_no_run_is_due_before_the_recorded_pause_end(maker: Any, settings: Settings) -> None:
    """The provider named a wait of 10 hours. The queue waits that long."""
    await _run(maker, events=[_failed(paused_until=NOW + timedelta(hours=8))])
    assert await _pending(maker, settings) == []


async def test_no_run_is_due_while_the_route_pause_is_open(maker: Any, settings: Settings) -> None:
    """The pause of the process is the gate, also after a restart cleared the
    recorded time of an older run."""
    await _run(maker, events=[_failed(paused_until=NOW - timedelta(minutes=5))])
    with patch("soc_ai.oracle.breaker._now", lambda: NOW):
        BREAKER.record_failure(route_key(settings), error_class="quota", message="rate limit")
        assert await _pending(maker, settings) == []
    BREAKER.reset()
    assert len(await _pending(maker, settings)) == 1


async def test_a_skipped_escalation_is_in_the_queue(maker: Any, settings: Settings) -> None:
    inv_id = await _run(maker, events=[_skipped(NOW - timedelta(minutes=1))])
    due = await _pending(maker, settings)
    assert [(p.investigation_id, p.error_class) for p in due] == [(inv_id, failures.PAUSED)]


async def test_a_refusal_is_due_at_once(maker: Any, settings: Settings) -> None:
    """A residue refusal opens no pause. A new run writes a new payload."""
    inv_id = await _run(maker, events=[_failed(failures.REFUSED)])
    assert [p.investigation_id for p in await _pending(maker, settings)] == [inv_id]


@pytest.mark.parametrize(
    "error_class", [failures.CLIENT, failures.SERIALIZATION, failures.BLOCKED, "", "tool_loop"]
)
async def test_a_failure_that_needs_the_operator_is_not_in_the_queue(
    maker: Any, settings: Settings, error_class: str
) -> None:
    """Negative control: a new run cannot repair a wrong key or the demo block."""
    await _run(maker, events=[_failed(error_class)])
    assert await _pending(maker, settings) == []


async def test_a_later_run_of_the_alert_takes_the_place_of_the_failed_run(
    maker: Any, settings: Settings
) -> None:
    await _run(maker, events=[_failed()], age=timedelta(hours=3))
    await _run(maker, events=[], age=timedelta(hours=1))
    assert await _pending(maker, settings) == []


async def test_a_running_later_run_also_takes_the_place(maker: Any, settings: Settings) -> None:
    """Negative control: the queue starts no second run beside one in flight."""
    await _run(maker, events=[_failed()], age=timedelta(hours=3))
    await _run(maker, events=[], age=timedelta(minutes=1), status="running")
    assert await _pending(maker, settings) == []


async def test_a_subject_gets_two_new_runs_and_no_more(maker: Any, settings: Settings) -> None:
    """The bound for a quota or transport failure. Each new run fails again.
    The third failed run stays."""
    first = await _run(maker, events=[_failed()], age=timedelta(hours=5))
    assert [p.failed_runs for p in await _pending(maker, settings)] == [1]
    second = await _run(maker, events=[_failed(failures.TRANSPORT)], age=timedelta(hours=4))
    due = await _pending(maker, settings)
    assert [(p.investigation_id, p.failed_runs) for p in due] == [(second, 2)]
    await _run(maker, events=[_failed()], age=timedelta(hours=3))
    assert await _pending(maker, settings) == []
    assert first != second
    assert oracle_retry.RETRY_LIMIT == 2


async def test_a_refusal_gets_one_new_run_and_no_more(maker: Any, settings: Settings) -> None:
    """A residue refusal repeats when the evidence of the alert holds the
    residue. One new run can write another payload. A second refusal stops."""
    first = await _run(maker, events=[_failed(failures.REFUSED)], age=timedelta(hours=5))
    assert [p.investigation_id for p in await _pending(maker, settings)] == [first]
    await _run(maker, events=[_failed(failures.REFUSED)], age=timedelta(hours=4))
    assert await _pending(maker, settings) == []
    assert oracle_retry.REFUSAL_RETRY_LIMIT == 1


async def test_the_cap_is_a_count_for_all_time(maker: Any, settings: Settings) -> None:
    """Review defect 3. The count read the failed runs inside the window of 9
    days. When the first failed run left the window the count fell, and the
    subject got a new run again: about three new runs each 9 days, with no
    end. The count now reads every stored run of the subject."""
    window = oracle_retry.RETRY_WINDOW
    quota = [_failed()]
    await _run(maker, alert_es_id="a-out", events=quota, age=window + timedelta(minutes=5))
    await _run(maker, alert_es_id="a-out", events=quota, age=window - timedelta(minutes=1))
    await _run(maker, alert_es_id="a-out", events=quota, age=window - timedelta(minutes=6))
    assert await _pending(maker, settings) == []


async def test_a_skipped_run_does_not_use_the_cap(maker: Any, settings: Settings) -> None:
    """Review defect 8. The pause skipped the escalation, so no Oracle call
    failed. A subject used both of its new runs with no Oracle call."""
    past = NOW - timedelta(minutes=1)
    await _run(maker, events=[_skipped(past)], age=timedelta(hours=6))
    await _run(maker, events=[_skipped(past)], age=timedelta(hours=5))
    third = await _run(maker, events=[_skipped(past)], age=timedelta(hours=4))
    due = await _pending(maker, settings)
    assert [(p.investigation_id, p.failed_runs) for p in due] == [(third, 0)]
    # Negative control: the failed calls of the same subject still count.
    await _run(maker, events=[_failed()], age=timedelta(hours=3))
    await _run(maker, events=[_failed()], age=timedelta(hours=2))
    await _run(maker, events=[_failed()], age=timedelta(hours=1))
    assert await _pending(maker, settings) == []


async def test_an_analyst_action_takes_the_subject_out_of_the_queue(
    maker: Any, settings: Settings
) -> None:
    """Review defect 6. The analyst escalated the alert from the console. The
    queue read the report only and started a new run."""
    await _run(
        maker,
        events=[
            _failed(failures.SERVER),
            {"sequence": 9, "kind": "action_executed", "payload": {"tool": "escalate_case"}},
        ],
    )
    assert await _pending(maker, settings) == []


async def test_an_action_on_an_earlier_run_of_the_subject_also_counts(
    maker: Any, settings: Settings
) -> None:
    await _run(
        maker,
        events=[{"sequence": 9, "kind": "action_executed", "payload": {"tool": "ack_alert"}}],
        age=timedelta(hours=5),
    )
    await _run(maker, events=[_failed()], age=timedelta(hours=1))
    assert await _pending(maker, settings) == []


async def test_a_dropped_subject_stays_out_of_the_queue(maker: Any, settings: Settings) -> None:
    inv_id = await _run(maker, events=[_failed()])
    assert len(await _pending(maker, settings)) == 1
    await oracle_retry.drop_from_queue(maker, inv_id, "hunt_not_found")
    assert await _pending(maker, settings) == []
    async with maker() as db:
        found = await inv_svc.get_with_events(db, inv_id)
    assert found is not None
    dropped = [e for e in found[1] if e.kind == oracle_retry.DROPPED_KIND]
    assert [e.payload["reason"] for e in dropped] == ["hunt_not_found"]
    # A new run of the subject does not bring it back.
    await _run(maker, events=[_failed()], age=timedelta(minutes=5))
    assert await _pending(maker, settings) == []


async def test_an_analyst_verdict_is_not_in_the_queue(maker: Any, settings: Settings) -> None:
    await _run(
        maker,
        events=[_failed()],
        report={"verdict": "false_positive", "resolution": {"resolved_via": "manual"}},
    )
    assert await _pending(maker, settings) == []


async def test_an_evaluation_run_and_a_lead_run_are_not_in_the_queue(
    maker: Any, settings: Settings
) -> None:
    await _run(maker, alert_es_id="synth-0001", events=[_failed()], is_synth_eval=True)
    await _run(maker, alert_es_id="lead-doc-0001", events=[_failed()], kind="lead")
    assert await _pending(maker, settings) == []


async def test_an_old_failed_run_is_out_of_the_queue(maker: Any, settings: Settings) -> None:
    await _run(maker, events=[_failed()], age=oracle_retry.RETRY_WINDOW + timedelta(hours=1))
    assert await _pending(maker, settings) == []


async def test_the_queue_is_empty_while_the_oracle_is_off(maker: Any, settings: Settings) -> None:
    await _run(maker, events=[_failed()])
    off = settings.model_copy(update={"oracle_enabled": False})
    assert await _pending(maker, off) == []


async def test_a_finding_is_one_subject_for_each_hunt_and_ordinal(
    maker: Any, settings: Settings
) -> None:
    """The shape of run 01M6Y7MDY1GQ7RC00ANYEYESRJ. A later run of another
    finding of the same hunt does not take its place."""
    failed = await _run(
        maker,
        alert_es_id="anchor-doc-0001",
        events=[_failed()],
        kind="hunt",
        hunt_id="01HUNT0000000000000000000",
        finding_ordinal=0,
        age=timedelta(hours=3),
        subject={"type": "hunt", "hunt_id": "01HUNT0000000000000000000", "lead_id": 7},
    )
    await _run(
        maker,
        alert_es_id="anchor-doc-0002",
        kind="hunt",
        hunt_id="01HUNT0000000000000000000",
        finding_ordinal=1,
        age=timedelta(hours=1),
    )
    due = await _pending(maker, settings)
    assert [p.investigation_id for p in due] == [failed]
    assert due[0].is_finding
    assert (due[0].hunt_id, due[0].finding_ordinal, due[0].lead_id) == (
        "01HUNT0000000000000000000",
        0,
        7,
    )


async def test_one_sweep_starts_three_runs_from_the_queue(maker: Any, settings: Settings) -> None:
    for n in range(5):
        await _run(maker, alert_es_id=f"alert-{n:04d}", events=[_failed()])
    assert len(await _pending(maker, settings)) == 5
    targets = await at.plan_oracle_retries(_State(settings, maker), planned=set())
    assert len(targets) == oracle_retry.RETRY_PER_SWEEP == 3


# ── the sweep ─────────────────────────────────────────────────────────────────


def _grid(
    sources: dict[str, dict[str, Any]] | None = None, *, missing: tuple[str, ...] = ()
) -> Any:
    """A grid that holds each alert it is asked for. ``sources`` sets the
    document of one alert, and ``missing`` names alerts that the grid lost."""
    from types import SimpleNamespace

    async def _search(_index: str, query: dict[str, Any], **_kw: Any) -> Any:
        ids = query["ids"]["values"]
        return SimpleNamespace(
            hits=[
                {"_id": i, "_source": (sources or {}).get(i, {"event": {}})}
                for i in ids
                if i not in missing
            ]
        )

    elastic = AsyncMock()
    elastic.search = _search
    return elastic


class _State:
    def __init__(self, settings: Settings, maker: Any, elastic: Any = None) -> None:
        self.settings = settings
        self.db_sessionmaker = maker
        self.elastic = elastic if elastic is not None else _grid()


async def test_the_sweep_plans_an_alert_of_the_queue(
    maker: Any, settings: Settings, caplog: pytest.LogCaptureFixture
) -> None:
    inv_id = await _run(maker, events=[_failed(paused_until=NOW - timedelta(minutes=5))])
    state = _State(settings, maker)
    with caplog.at_level(logging.INFO, logger="soc_ai.webui.autotriage"):
        targets = await at.plan_oracle_retries(state, planned=set())
    assert [(t.alert_es_id, t.oracle_retry_of) for t in targets] == [("alert-0001", inv_id)]
    assert targets[0].rule_name == "ET INFO Example Rule"
    line = next(r.getMessage() for r in caplog.records if "Oracle did not answer" in r.getMessage())
    assert inv_id in line and "quota" in line


async def test_the_scheduled_sweep_runs_a_queue_alert_when_the_backlog_is_empty(
    maker: Any, settings: Settings
) -> None:
    """The backlog holds no new alert. The sweep still starts, for the queue."""
    inv_id = await _run(maker, events=[_failed(paused_until=NOW - timedelta(minutes=5))])
    state = _State(settings, maker)
    ran: list[Any] = []

    async def _empty(_s: Any, **_kw: Any) -> Any:
        return [], 0, []

    async def _worker(_s: Any, *, targets: list[Any], **_kw: Any) -> None:
        ran.extend(targets)
        at.get_status(state).active = False

    with (
        patch.object(at, "plan_targets", _empty),
        patch.object(at, "run_auto_triage", _worker),
    ):
        launched = await at.start_config_sweep(state, started_by="auto-triage:scheduler")
        task = at.get_status(state)._task
        assert task is not None
        await task
    assert launched == 1
    assert [(t.alert_es_id, t.oracle_retry_of) for t in ran] == [("alert-0001", inv_id)]


async def test_the_sweep_does_not_plan_an_alert_two_times(maker: Any, settings: Settings) -> None:
    """Negative control: the planner of the sweep chose the alert already."""
    await _run(maker, events=[_failed()])
    assert await at.plan_oracle_retries(_State(settings, maker), planned={"alert-0001"}) == []


async def test_a_queue_read_error_plans_nothing(settings: Settings) -> None:
    """The sweep must not stop when the queue cannot be read."""

    def _broken() -> Any:
        raise RuntimeError("the store is closed")

    state = _State(settings, _broken)
    assert await at.plan_oracle_retries(state, planned=set()) == []


async def test_the_worker_runs_a_queue_target_with_the_model_and_names_the_queue(
    maker: Any, settings: Settings
) -> None:
    """The rule prior covers a target with no model call. A target of the
    queue runs the model, because only a model run can reach the Oracle."""
    seen: list[dict[str, Any]] = []

    async def _fake_run(state: Any, **kw: Any) -> AsyncIterator[tuple[str, dict[str, Any]]]:
        seen.append(kw)
        yield "investigation_created", {"investigation_id": "01NEW000000000000000000000"}
        yield "triage_report", {"payload": {"verdict": "true_positive", "confidence": 0.8}}

    state = _State(settings, maker)
    prior = AsyncMock()
    prior.gate = AsyncMock(return_value=(True, 1))
    targets = [
        at.Target(
            alert_es_id="alert-0001", rule_name="r", src_ip="", dst_ip="", oracle_retry_of="01OLD"
        ),
        at.Target(alert_es_id="alert-0002", rule_name="r", src_ip="", dst_ip=""),
    ]
    with (
        patch.object(at, "run_recorded", _fake_run),
        patch.object(at, "ctx_from_state", lambda _s: AsyncMock()),
        patch.object(at, "_RulePriorSweep", lambda *_a, **_k: prior),
        patch.object(at.rule_prior, "mode_of", lambda _s: "live"),
    ):
        await at.run_auto_triage(
            state, targets=targets, started_by="auto-triage:scheduler", apply_rule_prior=True
        )
    # The queue target ran the model under the actor of the queue. The prior
    # covered the other target, so that one made no model run.
    assert [(k["alert_id"], k["started_by"]) for k in seen] == [
        ("alert-0001", oracle_retry.STARTED_BY)
    ]
    assert [c.args[0].alert_es_id for c in prior.gate.await_args_list] == ["alert-0002"]


async def test_a_finding_of_the_queue_starts_its_own_run(maker: Any, settings: Settings) -> None:
    hunt_id = "01HUNT0000000000000000000"
    async with maker() as db:
        db.add(
            Hunt(
                id=hunt_id,
                objective="find web attacks",
                status="complete",
                started_by="scheduler",
                report={
                    "findings": [
                        {
                            "title": "Internal host exploits the web application",
                            "detail": "The host sends exploit requests.",
                            "hosts": ["10.0.0.5"],
                            "citations": ["anchor-doc-0001"],
                        }
                    ]
                },
                # The hunt planned a run for this finding, and that run ended.
                finding_investigations={
                    "0": {"state": "ended", "investigation_id": "01OLDRUN000000000000000000"}
                },
            )
        )
        await db.commit()
    await _run(
        maker,
        alert_es_id="anchor-doc-0001",
        events=[_failed(failures.REFUSED)],
        kind="hunt",
        hunt_id=hunt_id,
        finding_ordinal=0,
    )
    state = _State(settings, maker)
    subject = AsyncMock()
    subject.model_copy = lambda update: subject
    start = AsyncMock(return_value="01NEW000000000000000000000")
    with (
        patch("soc_ai.agent.context.build_hunt_subject", AsyncMock(return_value=subject)),
        patch(
            "soc_ai.webui.finding_promotion.promotion_anchor",
            AsyncMock(return_value="anchor-doc-0001"),
        ),
        patch("soc_ai.webui.finding_promotion.start_promotion", start),
    ):
        targets = await at.plan_oracle_retries(state, planned=set())
    # A finding is no target of the sweep worker. It starts through the manager.
    assert targets == []
    start.assert_awaited_once()
    kwargs = start.await_args.kwargs
    assert kwargs["started_by"] == oracle_retry.STARTED_BY
    assert (kwargs["kind"], kwargs["hunt_id"], kwargs["finding_ordinal"]) == ("hunt", hunt_id, 0)
    assert kwargs["title"] == "Internal host exploits the web application"
    assert kwargs["focus_origin"] == "hunt_finding"
    # Review defect 8. The hunt row points at the new run. It kept the link to
    # the run that the new one replaces.
    async with maker() as db:
        hunt = await db.get(Hunt, hunt_id)
    assert hunt is not None
    link = hunt.finding_investigations["0"]
    assert link["investigation_id"] == "01NEW000000000000000000000"
    assert link["state"] == "investigating"


async def test_a_finding_whose_hunt_is_gone_leaves_the_queue_with_a_reason(
    maker: Any, settings: Settings
) -> None:
    inv_id = await _run(
        maker,
        alert_es_id="anchor-doc-0001",
        events=[_failed()],
        kind="hunt",
        hunt_id="01GONE0000000000000000000",
        finding_ordinal=0,
    )
    start = AsyncMock()
    with patch("soc_ai.webui.finding_promotion.start_promotion", start):
        assert await at.plan_oracle_retries(_State(settings, maker), planned=set()) == []
    start.assert_not_awaited()
    assert await _pending(maker, settings) == []
    async with maker() as db:
        found = await inv_svc.get_with_events(db, inv_id)
    assert found is not None
    reasons = [e.payload["reason"] for e in found[1] if e.kind == oracle_retry.DROPPED_KIND]
    assert reasons == ["hunt_not_found"]


async def test_subjects_that_cannot_run_do_not_block_the_queue(
    maker: Any, settings: Settings
) -> None:
    """Review defect 4. Three failed finding runs whose hunt row is gone were
    the three oldest subjects. Each sweep read them, started nothing and never
    reached the alert behind them."""
    for n in range(3):
        await _run(
            maker,
            alert_es_id=f"anchor-{n}",
            events=[_failed(failures.SERVER)],
            kind="hunt",
            hunt_id=f"hunt-gone-{n}",
            finding_ordinal=0,
            age=timedelta(hours=5 - n),
        )
    waiting = await _run(maker, alert_es_id="alert-waits", events=[_failed(failures.SERVER)])
    targets = await at.plan_oracle_retries(_State(settings, maker), planned=set())
    assert [(t.alert_es_id, t.oracle_retry_of) for t in targets] == [("alert-waits", waiting)]


async def test_an_alert_that_the_grid_shows_closed_leaves_the_queue(
    maker: Any, settings: Settings
) -> None:
    """Review defect 6. The analyst acknowledged or escalated the alert in
    Security Onion. The grid holds that state, and the sweep reads it."""
    acked = await _run(maker, alert_es_id="alert-acked", events=[_failed()])
    escalated = await _run(maker, alert_es_id="alert-escalated", events=[_failed()])
    lost = await _run(maker, alert_es_id="alert-lost", events=[_failed()])
    open_run = await _run(maker, alert_es_id="alert-open", events=[_failed()])
    grid = _grid(
        {
            "alert-acked": {"event": {"acknowledged": True}},
            "alert-escalated": {"event": {"escalated": True}},
        },
        missing=("alert-lost",),
    )
    state = _State(settings, maker, grid)
    targets = await at.plan_oracle_retries(state, planned=set())
    assert [(t.alert_es_id, t.oracle_retry_of) for t in targets] == [("alert-open", open_run)]
    reasons: dict[str, list[str]] = {}
    async with maker() as db:
        for inv_id in (acked, escalated, lost, open_run):
            found = await inv_svc.get_with_events(db, inv_id)
            assert found is not None
            reasons[inv_id] = [
                e.payload["reason"] for e in found[1] if e.kind == oracle_retry.DROPPED_KIND
            ]
    assert reasons == {
        acked: ["alert_closed"],
        escalated: ["alert_closed"],
        lost: ["alert_not_found"],
        open_run: [],
    }


async def test_a_grid_that_does_not_answer_starts_no_alert_run_and_drops_nothing(
    maker: Any, settings: Settings
) -> None:
    """Negative control: an unknown alert state is no reason to drop. The
    subject waits for the next sweep."""
    await _run(maker, events=[_failed()])
    elastic = AsyncMock()
    elastic.search = AsyncMock(side_effect=RuntimeError("the grid is down"))
    assert await at.plan_oracle_retries(_State(settings, maker, elastic), planned=set()) == []
    assert len(await _pending(maker, settings)) == 1


def test_the_drop_event_has_a_title_in_words() -> None:
    from soc_ai.webui.timeline_labels import label_event

    title = label_event(oracle_retry.DROPPED_KIND, {"reason": "hunt_not_found"})["title"]
    assert title == (
        "No new run for the Oracle: the hunt of the finding is gone. The local verdict stands"
    )
    closed = label_event(oracle_retry.DROPPED_KIND, {"reason": "alert_closed"})["title"]
    assert "acknowledged or escalated" in closed
