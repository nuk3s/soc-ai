"""The rule prior rung and its six safeguards (stage 1, item 3).

docs/dev/specs/2026-10-04-four-tier-detection-methodology.md, "Rule prior
safeguards". The prior is the one rung that can hide a new case, so most of
these tests are negative controls, planted on the path a careless guard would
miss: an override older than any window, a rule with more recent runs than
the tuning tally reads, a sample that disagrees.
"""

from __future__ import annotations

import ipaddress
import random
from collections.abc import AsyncIterator
from datetime import timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest
from soc_ai.agent import rule_prior
from soc_ai.agent.context import StepEvent
from soc_ai.agent.rule_prior import PriorTarget, evaluate
from soc_ai.config import Settings
from soc_ai.store import investigations as inv_svc
from soc_ai.store import rule_prior as prior_store
from soc_ai.store.auth import utcnow
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import EntityObservation, Investigation, Lead, RulePriorDecision
from soc_ai.webui import autotriage as at
from sqlalchemy import select

RULE = "ET INFO Internal STUN Binding"
INSIDE = [ipaddress.ip_network("192.0.2.0/24"), ipaddress.ip_network("198.51.100.0/24")]
SRC, DST = "192.0.2.10", "198.51.100.20"
OUTSIDE = "203.0.113.50"


class _Fixed(random.Random):
    """A sampling draw that always returns one value."""

    def __init__(self, value: float) -> None:
        super().__init__(0)
        self._value = value

    def random(self) -> float:
        return self._value


def _settings(base: Settings, **kw: Any) -> Settings:
    update: dict[str, Any] = {"internal_cidrs": INSIDE, "rule_prior_mode": "shadow"}
    update.update(kw)
    return base.model_copy(update=update)


async def _store(settings: Settings) -> Any:
    engine = make_engine(settings)
    await run_migrations(engine)
    return engine, make_sessionmaker(engine)


def _run(n: int, *, hours_ago: float, verdict: str = "false_positive", **kw: Any) -> Investigation:
    created = utcnow() - timedelta(hours=hours_ago)
    base: dict[str, Any] = {
        "id": f"run{n:022d}",
        "alert_es_id": f"ev-{n}",
        "rule_name": RULE,
        "status": "complete",
        "verdict": verdict,
        "confidence": 0.88,
        "summary": f"Run {n}: a keepalive.",
        "rationale": "Keepalive.",
        "report": {"verdict": verdict, "summary": f"Run {n}.", "citations": [f"doc-{n}"]},
        "started_by": "auto-triage:scheduler",
        "src_ip": SRC,
        "dest_ip": DST,
        "created_at": created,
        "finished_at": created,
        "is_fallback": False,
        "run_class": "standard",
    }
    base.update(kw)
    return Investigation(**base)


async def _seed_history(maker: Any, *, count: int = 5, newest_hours: float = 2.0) -> None:
    async with maker() as db:
        for i in range(count):
            db.add(_run(i, hours_ago=newest_hours + i * 12))
        await db.commit()


def _target(**kw: Any) -> PriorTarget:
    base: dict[str, Any] = {
        "rule_name": RULE,
        "alert_es_id": "ev-new",
        "src_ip": SRC,
        "dst_ip": DST,
        "severity": "medium",
        "host_name": "",
    }
    base.update(kw)
    return PriorTarget(**base)


async def _decide(
    maker: Any,
    settings: Settings,
    target: PriorTarget | None = None,
    *,
    nominated: frozenset[str] | None = frozenset({RULE}),
    draw: float = 0.5,
) -> rule_prior.PriorDecision:
    async with maker() as db:
        return await evaluate(
            db,
            target or _target(),
            settings=settings,
            cidrs=INSIDE,
            nominated=nominated,
            now=utcnow(),
            rng=_Fixed(draw),
        )


# ── The rung ─────────────────────────────────────────────────────────────────


async def test_a_rule_with_five_fresh_false_positives_is_covered(settings_kratos: Settings) -> None:
    settings = _settings(settings_kratos)
    engine, maker = await _store(settings)
    await _seed_history(maker)
    decision = await _decide(maker, settings)
    await engine.dispose()
    assert decision.applies is True
    assert decision.reason == "covered"
    assert decision.would_verdict == "false_positive"
    assert decision.source_id == f"run{0:022d}"
    assert decision.runs_in_window == 5
    assert decision.sampled is False


async def test_a_new_pair_on_an_external_endpoint_runs(settings_kratos: Settings) -> None:
    """Negative control: the history covers the rule, but this pair leaves the estate."""
    settings = _settings(settings_kratos)
    engine, maker = await _store(settings)
    await _seed_history(maker)
    out = await _decide(maker, settings, _target(dst_ip=OUTSIDE, alert_es_id="ev-out"))
    back = await _decide(maker, settings, _target(src_ip=OUTSIDE, alert_es_id="ev-in"))
    no_flow = await _decide(maker, settings, _target(dst_ip="", alert_es_id="ev-host"))
    await engine.dispose()
    assert (out.applies, out.reason) == (False, "external_endpoint")
    assert (back.applies, back.reason) == (False, "external_endpoint")
    assert (no_flow.applies, no_flow.reason) == (False, "no_flow_endpoints")


async def test_a_rule_with_one_old_override_never_qualifies(settings_kratos: Settings) -> None:
    """Negative control on the path the tuning tally misses.

    The override is 60 days old, outside the 7-day window, and behind 30
    newer runs, more than the 25 rows the detection tuning tally reads.
    """
    settings = _settings(settings_kratos)
    engine, maker = await _store(settings)
    async with maker() as db:
        for i in range(30):
            db.add(_run(i, hours_ago=1 + i * 4))
        db.add(
            _run(
                99,
                hours_ago=24 * 60,
                report={
                    "verdict": "false_positive",
                    "resolution": {
                        "original_verdict": "true_positive",
                        "resolved_via": "manual",
                        "resolved_by": "analyst",
                    },
                },
            )
        )
        await db.commit()
        assert RULE not in await inv_svc.override_counts_by_rule(db, [RULE])
    decision = await _decide(maker, settings)
    await engine.dispose()
    assert (decision.applies, decision.reason) == (False, "analyst_override")


async def test_a_critical_alert_runs(settings_kratos: Settings) -> None:
    settings = _settings(settings_kratos)
    engine, maker = await _store(settings)
    await _seed_history(maker)
    critical = await _decide(maker, settings, _target(severity="critical"))
    unlabelled = await _decide(maker, settings, _target(severity="unknown"))
    await engine.dispose()
    assert (critical.applies, critical.reason) == (False, "critical_severity")
    # An alert with no label could be critical. It runs too.
    assert (unlabelled.applies, unlabelled.reason) == (False, "severity_unknown")


async def test_the_prior_lapses_after_a_day_without_a_model_run(settings_kratos: Settings) -> None:
    settings = _settings(settings_kratos)
    engine, maker = await _store(settings)
    await _seed_history(maker, newest_hours=25)
    decision = await _decide(maker, settings)
    await engine.dispose()
    assert (decision.applies, decision.reason) == (False, "lapsed")


async def test_four_runs_are_too_few(settings_kratos: Settings) -> None:
    settings = _settings(settings_kratos)
    engine, maker = await _store(settings)
    await _seed_history(maker, count=4)
    decision = await _decide(maker, settings)
    await engine.dispose()
    assert (decision.applies, decision.reason) == (False, "too_few_runs")


async def test_one_true_positive_this_week_holds_the_prior(settings_kratos: Settings) -> None:
    settings = _settings(settings_kratos)
    engine, maker = await _store(settings)
    await _seed_history(maker, count=6)
    async with maker() as db:
        db.add(_run(50, hours_ago=100, verdict="true_positive"))
        await db.commit()
    decision = await _decide(maker, settings)
    await engine.dispose()
    assert (decision.applies, decision.reason) == (False, "non_false_positive_in_window")


async def test_rule_prior_runs_and_fallbacks_never_count_as_model_runs(
    settings_kratos: Settings,
) -> None:
    """Five rule-prior runs and fallbacks cannot feed the prior that made them."""
    settings = _settings(settings_kratos)
    engine, maker = await _store(settings)
    async with maker() as db:
        for i in range(3):
            db.add(_run(i, hours_ago=1 + i))
        for i in range(3, 8):
            db.add(_run(i, hours_ago=1 + i, run_class="rule_prior"))
        db.add(_run(9, hours_ago=2, is_fallback=True, verdict="needs_more_info"))
        await db.commit()
    decision = await _decide(maker, settings)
    await engine.dispose()
    assert (decision.applies, decision.reason) == (False, "too_few_runs")
    assert decision.runs_in_window == 3


async def test_the_prior_yields_to_an_open_lead_or_a_fresh_observation(
    settings_kratos: Settings,
) -> None:
    settings = _settings(settings_kratos)
    engine, maker = await _store(settings)
    await _seed_history(maker)
    async with maker() as db:
        db.add(Lead(status="open", entities_json=[["host", DST]], kinds_json=["alert"]))
        await db.commit()
    with_lead = await _decide(maker, settings)
    async with maker() as db:
        lead = (await db.scalars(select(Lead))).one()
        lead.status = "dismissed"
        db.add(
            EntityObservation(
                entity_kind="host",
                entity_key=SRC,
                kind="alert",
                spec_id="alert",
                fingerprint="fp-1",
                observed_at=utcnow() - timedelta(hours=3),
            )
        )
        await db.commit()
    with_observation = await _decide(maker, settings)
    await engine.dispose()
    assert (with_lead.applies, with_lead.reason) == (False, "open_lead_or_fresh_observation")
    assert (with_observation.applies, with_observation.reason) == (
        False,
        "open_lead_or_fresh_observation",
    )


async def test_a_rule_the_panel_does_not_nominate_runs(settings_kratos: Settings) -> None:
    settings = _settings(settings_kratos)
    engine, maker = await _store(settings)
    await _seed_history(maker)
    other = await _decide(maker, settings, nominated=frozenset({"ET OTHER"}))
    blind = await _decide(maker, settings, nominated=None)
    await engine.dispose()
    assert (other.applies, other.reason) == (False, "not_nominated")
    # The grid could not list the nominations: the prior holds, it never guesses.
    assert (blind.applies, blind.reason) == (False, "nomination_unavailable")


def test_the_minimum_run_count_is_never_below_five(settings_kratos: Settings) -> None:
    with pytest.raises(ValueError, match="greater than or equal to 5"):
        Settings(**{**settings_kratos.model_dump(), "rule_prior_min_runs": 3})


# ── The scheduler ────────────────────────────────────────────────────────────


def _scripted(verdict: str, calls: list[str]) -> Any:
    async def investigate(alert_id: str, **_kw: Any) -> AsyncIterator[StepEvent]:
        calls.append(alert_id)
        report = {
            "verdict": verdict,
            "confidence": 0.9,
            "summary": "Real run.",
            "citations": ["doc-x"],
            "recommended_actions": [],
        }
        yield StepEvent(kind="session_start", session_id="s", sequence=1, payload={})
        yield StepEvent(kind="triage_report", session_id="s", sequence=2, payload=report)
        yield StepEvent(kind="done", session_id="s", sequence=3, payload={})

    return investigate


async def _sweep(
    settings: Settings,
    maker: Any,
    *,
    verdict: str,
    draw: float,
    alert_id: str = "ev-new",
) -> list[str]:
    state = SimpleNamespace(settings=settings, db_sessionmaker=maker)
    calls: list[str] = []
    target = at.Target(
        alert_es_id=alert_id, rule_name=RULE, src_ip=SRC, dst_ip=DST, severity="medium"
    )

    async def nominate(_state: Any) -> list[dict[str, Any]]:
        return [{"rule_name": RULE}]

    with (
        patch("soc_ai.api.runner.investigate", _scripted(verdict, calls)),
        patch("soc_ai.webui.autotriage.ctx_from_state", lambda _s: SimpleNamespace()),
        patch("soc_ai.webui.detection_tuning.nominate", nominate),
        patch("soc_ai.webui.autotriage._prior_rng", lambda: _Fixed(draw)),
    ):
        await at.run_auto_triage(
            state, targets=[target], started_by="auto-triage:scheduler", apply_rule_prior=True
        )
    return calls


async def _decisions(maker: Any) -> list[RulePriorDecision]:
    async with maker() as db:
        rows = await db.scalars(select(RulePriorDecision).order_by(RulePriorDecision.id))
        return list(rows.all())


async def test_shadow_runs_the_model_and_records_the_agreement(settings_kratos: Settings) -> None:
    settings = _settings(settings_kratos)
    engine, maker = await _store(settings)
    await _seed_history(maker)
    calls = await _sweep(settings, maker, verdict="false_positive", draw=0.5)
    rows = await _decisions(maker)
    await engine.dispose()
    assert calls == ["ev-new"]
    assert len(rows) == 1
    row = rows[0]
    assert (row.mode, row.applies, row.reason, row.sampled) == ("shadow", True, "covered", False)
    assert (row.would_verdict, row.real_verdict, row.agree) == (
        "false_positive",
        "false_positive",
        True,
    )
    assert row.investigation_id is not None


async def test_shadow_records_why_the_prior_did_not_apply(settings_kratos: Settings) -> None:
    settings = _settings(settings_kratos)
    engine, maker = await _store(settings)
    await _seed_history(maker, count=2)
    calls = await _sweep(settings, maker, verdict="false_positive", draw=0.5)
    rows = await _decisions(maker)
    await engine.dispose()
    assert calls == ["ev-new"]
    assert (rows[0].applies, rows[0].reason, rows[0].agree) == (False, "too_few_runs", None)
    assert rows[0].real_verdict == "false_positive"


async def test_live_covers_an_unsampled_alert_with_no_model_call(settings_kratos: Settings) -> None:
    settings = _settings(settings_kratos, rule_prior_mode="live")
    engine, maker = await _store(settings)
    await _seed_history(maker)
    calls = await _sweep(settings, maker, verdict="true_positive", draw=0.99)
    rows = await _decisions(maker)
    async with maker() as db:
        covered = await db.get(Investigation, rows[0].investigation_id)
    await engine.dispose()
    assert calls == []
    assert (rows[0].mode, rows[0].applies, rows[0].sampled, rows[0].agree) == (
        "live",
        True,
        False,
        None,
    )
    assert covered is not None
    assert covered.run_class == "rule_prior"
    assert covered.verdict == "false_positive"
    assert covered.model_requests == 0
    assert covered.alert_es_id == "ev-new"
    report = covered.report or {}
    # The rationale and the citations come from the source run.
    assert report["citations"] == ["doc-0"]
    assert covered.rationale == "Keepalive."
    assert "rule prior covered this alert" in report["summary"]
    # It never acknowledges: no recommended action, no acknowledgement event.
    assert report["recommended_actions"] == []
    async with maker() as db:
        got = await inv_svc.get_with_events(db, covered.id)
    assert got is not None
    assert "auto_ack" not in [e.kind for e in got[1]]


async def test_a_sampled_disagreement_suspends_the_rule(settings_kratos: Settings) -> None:
    settings = _settings(settings_kratos, rule_prior_mode="live")
    engine, maker = await _store(settings)
    await _seed_history(maker)
    # The draw picks this alert for a real run, and the model disagrees.
    calls = await _sweep(settings, maker, verdict="true_positive", draw=0.0)
    rows = await _decisions(maker)
    assert calls == ["ev-new"]
    assert (rows[0].sampled, rows[0].agree, rows[0].real_verdict) == (True, False, "true_positive")
    # The next alert of the rule runs, with the suspension as the reason. The
    # true positive in the window would hold it too; drop it to prove the
    # suspension alone holds.
    async with maker() as db:
        real = await db.get(Investigation, rows[0].investigation_id)
        assert real is not None
        real.verdict = "false_positive"
        await db.commit()
    later = await _decide(maker, settings)
    assert (later.applies, later.reason) == (False, "suspended")
    async with maker() as db:
        assert await prior_store.clear_suspension(db, RULE, by="analyst") == 1
    cleared = await _decide(maker, settings)
    await engine.dispose()
    assert cleared.applies is True


async def test_a_rule_prior_run_never_lends_its_verdict_along_a_pair(
    settings_kratos: Settings,
) -> None:
    """Safeguard 5: the pair inheritance rung never acks off a rule-prior run."""
    settings = _settings(settings_kratos)
    engine, maker = await _store(settings)
    async with maker() as db:
        db.add(_run(1, hours_ago=1, run_class="rule_prior"))
        await db.commit()
        key = inv_svc.pair_key(RULE, SRC, DST, None)
        hits = await inv_svc.latest_for_pairs(db, [key], window_days=7)
    await engine.dispose()
    assert hits == {}


def test_the_panel_route_shows_the_record_and_clears_a_suspension(
    settings_kratos: Settings,
) -> None:
    """GET /detection-tuning carries the Rule prior column; Clear lifts a suspension."""
    import asyncio

    from tests.test_investigations_query import _client

    async def nominate(_state: Any) -> list[dict[str, Any]]:
        return [
            {
                "rule_name": RULE,
                "alert_count": 400,
                "investigations": 40,
                "fp": 40,
                "tp": 0,
                "nmi": 0,
                "recommendation": "mute",
                "reason": "all false positive",
                "already_muted": False,
                "override_fp": 0,
                "chat_resolved": 0,
                "manual_resolved": 0,
            }
        ]

    gen = _client(_settings(settings_kratos))
    client = next(gen)
    try:

        async def seed() -> None:
            async with client.app.state.db_sessionmaker() as db:
                row = await prior_store.record_decision(
                    db,
                    rule_name=RULE,
                    alert_es_id="a",
                    mode="live",
                    applies=True,
                    reason="covered",
                    sampled=True,
                    would_verdict="false_positive",
                )
                await prior_store.settle_decision(
                    db, row.id, investigation_id="x", real_verdict="true_positive"
                )

        asyncio.run(seed())
        with patch("soc_ai.webui.detection_tuning.nominate", nominate):
            body = client.get("/api/v1/detection-tuning").json()
            row = body["nominations"][0]
            assert (row["prior_covered"], row["prior_disagreements"]) == (1, 1)
            assert row["prior_suspended"] is True
            cleared = client.post(
                "/api/v1/detection-tuning/rule-prior/clear", json={"rule_name": RULE}
            )
            assert cleared.status_code == 200
            assert cleared.json() == {"rule_name": RULE, "cleared": 1}
            after = client.get("/api/v1/detection-tuning").json()["nominations"][0]
            assert after["prior_suspended"] is False
            # The record stays: clearing is a decision on top of it, not an erase.
            assert after["prior_disagreements"] == 1
    finally:
        gen.close()


async def test_the_detection_tuning_stats_count_the_record(settings_kratos: Settings) -> None:
    settings = _settings(settings_kratos)
    engine, maker = await _store(settings)
    async with maker() as db:
        common = {"rule_name": RULE, "mode": "shadow", "would_verdict": "false_positive"}
        await prior_store.record_decision(
            db, alert_es_id="a", applies=True, reason="covered", sampled=False, **common
        )
        row = await prior_store.record_decision(
            db, alert_es_id="b", applies=True, reason="covered", sampled=False, **common
        )
        await prior_store.settle_decision(
            db, row.id, investigation_id="x", real_verdict="false_positive"
        )
        bad = await prior_store.record_decision(
            db, alert_es_id="c", applies=True, reason="covered", sampled=True, **common
        )
        await prior_store.settle_decision(
            db, bad.id, investigation_id="y", real_verdict="needs_more_info"
        )
        await prior_store.record_decision(
            db, alert_es_id="d", applies=False, reason="lapsed", sampled=False, **common
        )
        stats = (await prior_store.stats_by_rule(db, [RULE]))[RULE]
    await engine.dispose()
    assert (stats.covered, stats.agreements, stats.disagreements, stats.unchecked) == (3, 1, 1, 1)
    assert stats.suspended is True
    assert stats.last_reason == "lapsed"
