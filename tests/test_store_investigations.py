"""Tests for the investigations store service."""

from __future__ import annotations

from datetime import timedelta

import pytest
from soc_ai.config import Settings
from soc_ai.store import investigations as inv_svc
from soc_ai.store.auth import utcnow
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import Investigation


async def _db(settings: Settings):  # type: ignore[no-untyped-def]
    engine = make_engine(settings)
    await run_migrations(engine)
    return engine, make_sessionmaker(engine)


REPORT = {
    "verdict": "false_positive",
    "confidence": 0.85,
    "summary": "Benign ICMP echo between gateway and Mac. Nothing else.",
    "citations": ["x7KpQ2"],
    "recommended_actions": [
        {
            "tool_name": "ack_alert",
            "tool_args": {"alert_id": "x7KpQ2"},
            "rationale": "Routine gateway monitoring traffic.",
        }
    ],
}


async def test_create_seeds_rule_name_at_birth(settings_kratos: Settings) -> None:
    """create(rule_name=...) names the row immediately so it is never anonymous,
    even if the run dies before the first alert_context event. Empty/None seeds
    leave it NULL for the recorder's stream-backfill."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        named = await inv_svc.create(
            db, alert_es_id="a1", started_by="admin", rule_name="ET SCAN seeded"
        )
        assert named.rule_name == "ET SCAN seeded"

        # Empty string must NOT persist as "" — it stays NULL so backfill can fire.
        blank = await inv_svc.create(db, alert_es_id="a2", started_by="admin", rule_name="")
        assert blank.rule_name is None

        none = await inv_svc.create(db, alert_es_id="a3", started_by="admin")
        assert none.rule_name is None

        # Over-long names are truncated to the column bound (512).
        long = await inv_svc.create(db, alert_es_id="a4", started_by="admin", rule_name="x" * 600)
        assert long.rule_name is not None and len(long.rule_name) == 512
    await engine.dispose()


async def test_lifecycle_create_append_finalize(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        inv = await inv_svc.create(db, alert_es_id="x7KpQ2", started_by="admin")
        assert len(inv.id) == 26  # ULID
        assert inv.status == "running"

        await inv_svc.append_events(
            db,
            inv.id,
            [
                {"kind": "session_start", "sequence": 1, "payload": {"alert_id": "x7KpQ2"}},
                {"kind": "alert_context", "sequence": 2, "payload": {"rule": {"name": "ET TEST"}}},
            ],
        )
        await inv_svc.set_rule_name(db, inv.id, "ET TEST Rule")
        await inv_svc.finalize(
            db,
            inv.id,
            status="complete",
            verdict="false_positive",
            confidence=0.85,
            rationale="Routine gateway monitoring traffic.",
            summary=REPORT["summary"],
            report=REPORT,
        )
        got = await inv_svc.get_with_events(db, inv.id)
        assert got is not None
        stored, events = got
        assert stored.status == "complete"
        assert stored.verdict == "false_positive"
        assert stored.rule_name == "ET TEST Rule"
        assert stored.finished_at is not None
        assert [e.kind for e in events] == ["session_start", "alert_context"]
        assert events[1].payload["rule"]["name"] == "ET TEST"
    await engine.dispose()


async def test_get_with_events_unknown_id(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        assert await inv_svc.get_with_events(db, "0" * 26) is None
    await engine.dispose()


async def test_latest_for_rules_and_alerts(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        a = await inv_svc.create(db, alert_es_id="ev-old", started_by="admin")
        await inv_svc.set_rule_name(db, a.id, "ET RULE A")
        await inv_svc.finalize(db, a.id, status="complete", verdict="true_positive")

        b = await inv_svc.create(db, alert_es_id="ev-new", started_by="admin")
        await inv_svc.set_rule_name(db, b.id, "ET RULE A")
        # b stays running — still the most recent for the rule

        c = await inv_svc.create(db, alert_es_id="ev-c", started_by="admin")
        await inv_svc.set_rule_name(db, c.id, "ET RULE C")
        await inv_svc.finalize(db, c.id, status="error")

        by_rule = await inv_svc.latest_for_rules(db, ["ET RULE A", "ET RULE C", "NOPE"])
        assert by_rule["ET RULE A"].id == b.id  # most recent wins, running included
        assert by_rule["ET RULE C"].status == "error"
        assert "NOPE" not in by_rule

        by_alert = await inv_svc.latest_for_alerts(db, ["ev-old", "ev-new", "missing"])
        assert by_alert["ev-old"].id == a.id
        assert by_alert["ev-new"].id == b.id
        assert "missing" not in by_alert
    await engine.dispose()


async def test_latest_for_rules_empty_input(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        assert await inv_svc.latest_for_rules(db, []) == {}
        assert await inv_svc.latest_for_alerts(db, []) == {}
    await engine.dispose()


async def test_latest_for_pairs(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        a = await inv_svc.create(
            db, alert_es_id="e1", started_by="x", src_ip="10.0.0.1", dest_ip="10.0.0.2"
        )
        await inv_svc.set_rule_name(db, a.id, "RULE A")
        await inv_svc.finalize(db, a.id, status="complete", verdict="false_positive")

        hits = await inv_svc.latest_for_pairs(
            db,
            [("RULE A", "10.0.0.1", "10.0.0.2"), ("RULE A", "10.0.0.1", "10.0.0.9")],
            window_days=7,
        )
        assert hits[("RULE A", "10.0.0.1", "10.0.0.2")].id == a.id
        assert ("RULE A", "10.0.0.1", "10.0.0.9") not in hits
        # outside the window → not inherited
        assert (
            await inv_svc.latest_for_pairs(db, [("RULE A", "10.0.0.1", "10.0.0.2")], window_days=0)
            == {}
        )
        # running/error rows do not propagate
        b = await inv_svc.create(
            db, alert_es_id="e2", started_by="x", src_ip="10.0.0.3", dest_ip="10.0.0.4"
        )
        await inv_svc.set_rule_name(db, b.id, "RULE B")
        assert (
            await inv_svc.latest_for_pairs(db, [("RULE B", "10.0.0.3", "10.0.0.4")], window_days=7)
            == {}
        )
    await engine.dispose()


async def _age(db, inv_id: str, minutes: int) -> None:  # type: ignore[no-untyped-def]
    """Backdate a row's created_at so the periodic reaper sees it as stale."""
    row = await db.get(Investigation, inv_id)
    row.created_at = utcnow() - timedelta(minutes=minutes)
    await db.commit()


async def test_reap_all_running_when_age_none(settings_kratos: Settings) -> None:
    """older_than_minutes=None reaps EVERY running row (startup case)."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        r1 = await inv_svc.create(db, alert_es_id="r1", started_by="x")
        r2 = await inv_svc.create(db, alert_es_id="r2", started_by="x")
        done = await inv_svc.create(db, alert_es_id="ok", started_by="x")
        await inv_svc.finalize(db, done.id, status="complete", verdict="false_positive")

        n = await inv_svc.reap_stale_running(db, older_than_minutes=None)
        assert n == 2

        for rid in (r1.id, r2.id):
            row = await db.get(Investigation, rid)
            assert row.status == "error"
            assert row.finished_at is not None
            assert row.rationale  # a note was set
        # the completed one is untouched
        assert (await db.get(Investigation, done.id)).status == "complete"
    await engine.dispose()


async def test_reap_only_stale_when_age_set(settings_kratos: Settings) -> None:
    """A positive age reaps only rows older than it; a fresh hunt is spared."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        fresh = await inv_svc.create(db, alert_es_id="fresh", started_by="x")
        stale = await inv_svc.create(db, alert_es_id="stale", started_by="x")
        await _age(db, stale.id, minutes=60)

        n = await inv_svc.reap_stale_running(db, older_than_minutes=30)
        assert n == 1
        assert (await db.get(Investigation, stale.id)).status == "error"
        assert (await db.get(Investigation, fresh.id)).status == "running"
    await engine.dispose()


async def test_reap_preserves_existing_rationale(settings_kratos: Settings) -> None:
    """The reaper only fills a rationale when one is absent."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        inv = await inv_svc.create(db, alert_es_id="r", started_by="x")
        row = await db.get(Investigation, inv.id)
        row.rationale = "partial progress note"
        await db.commit()

        await inv_svc.reap_stale_running(db, older_than_minutes=None)
        row = await db.get(Investigation, inv.id)
        assert row.status == "error"
        assert row.rationale == "partial progress note"
    await engine.dispose()


async def test_reap_returns_zero_when_nothing_running(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        done = await inv_svc.create(db, alert_es_id="ok", started_by="x")
        await inv_svc.finalize(db, done.id, status="complete", verdict="true_positive")
        assert await inv_svc.reap_stale_running(db, older_than_minutes=None) == 0
        assert await inv_svc.reap_stale_running(db, older_than_minutes=30) == 0
    await engine.dispose()


async def test_reap_interrupted_status_marks_benign_state(settings_kratos: Settings) -> None:
    """The startup reap writes 'interrupted' (not 'error') so a clean restart never
    surfaces a scary failure in a healthy env — and the row stays re-huntable."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        inv = await inv_svc.create(db, alert_es_id="cut-off", started_by="x")

        n = await inv_svc.reap_stale_running(db, older_than_minutes=None, status="interrupted")
        assert n == 1
        row = await db.get(Investigation, inv.id)
        assert row.status == "interrupted"
        assert row.finished_at is not None
        # interrupted-specific note (distinct from the 'error' timeout note)
        assert "interrupted by a service restart" in row.rationale
        # re-huntable: continuous auto-triage / manual re-hunt must pick it back up
        assert inv_svc.blocks_rehunt(row) is False
    await engine.dispose()


async def test_reap_default_status_is_error(settings_kratos: Settings) -> None:
    """The periodic over-age sweep keeps the 'error' status — a hunt that ran too
    long is a genuine failure, not a benign restart."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        stale = await inv_svc.create(db, alert_es_id="ran-too-long", started_by="x")
        await _age(db, stale.id, minutes=60)

        n = await inv_svc.reap_stale_running(db, older_than_minutes=30)
        assert n == 1
        row = await db.get(Investigation, stale.id)
        assert row.status == "error"
        assert "interrupted by a service restart" not in (row.rationale or "")
    await engine.dispose()


async def test_resolve_changes_verdict_and_records_provenance(settings_kratos: Settings) -> None:
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    maker = make_sessionmaker(engine)
    async with maker() as db:
        inv = await inv_svc.create(db, alert_es_id="ev-r1", started_by="tester")
        await inv_svc.finalize(
            db,
            inv.id,
            status="complete",
            verdict="needs_more_info",
            confidence=0.4,
            rationale="Need PCAP.",
            report={"open_questions": ["q1"]},
        )
    async with maker() as db:
        updated = await inv_svc.resolve(
            db,
            inv.id,
            verdict="true_positive",
            confidence=0.82,
            rationale="PCAP confirmed C2 beacon.",
            recommended_actions=[
                {"tool_name": "escalate_to_case", "tool_args": {}, "rationale": "Active C2."}
            ],
            resolved_by="analyst",
            source_message_id=7,
        )
    assert updated is not None
    assert updated.verdict == "true_positive"
    assert updated.confidence == pytest.approx(0.82)
    res = updated.report["resolution"]
    assert res["original_verdict"] == "needs_more_info"
    assert res["resolved_via"] == "chat"
    assert res["resolved_by"] == "analyst"
    assert res["source_message_id"] == 7
    assert updated.report["open_questions"] == ["q1"]
    assert updated.report["recommended_actions"][0]["tool_name"] == "escalate_to_case"
    await engine.dispose()


@pytest.mark.asyncio
async def test_resolve_manual_sets_resolved_via_and_no_source_message(
    settings_kratos: Settings,
) -> None:
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    maker = make_sessionmaker(engine)
    async with maker() as db:
        inv = await inv_svc.create(db, alert_es_id="ev-manual1", started_by="tester")
        await inv_svc.finalize(
            db,
            inv.id,
            status="complete",
            verdict="needs_more_info",
            confidence=0.5,
            rationale="Unclear.",
        )
    async with maker() as db:
        updated = await inv_svc.resolve(
            db,
            inv.id,
            verdict="false_positive",
            confidence=1.0,
            rationale="Analyst confirmed benign.",
            recommended_actions=None,
            resolved_by="alice",
            resolved_via="manual",
            source_message_id=None,
        )
    assert updated is not None
    assert updated.verdict == "false_positive"
    res = updated.report["resolution"]
    assert res["resolved_via"] == "manual"
    assert res["resolved_by"] == "alice"
    assert res["original_verdict"] == "needs_more_info"
    assert "source_message_id" not in res
    await engine.dispose()


# ---------------------------------------------------------------------------
# override_counts_by_rule — the analyst-feedback signal (E4.3)
# ---------------------------------------------------------------------------


async def _complete_inv(
    db,  # type: ignore[no-untyped-def]
    *,
    rule_name: str,
    verdict: str,
    alert_es_id: str,
    report: dict | None = None,
) -> Investigation:
    inv = await inv_svc.create(db, alert_es_id=alert_es_id, started_by="t", rule_name=rule_name)
    await inv_svc.finalize(
        db, inv.id, status="complete", verdict=verdict, confidence=0.9, report=report
    )
    return inv


async def test_override_counts_by_rule_counts_analyst_overrides(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        # A manual override out of NMI to false_positive → overridden_to_fp + manual.
        m = await _complete_inv(
            db, rule_name="ET NOISE", verdict="needs_more_info", alert_es_id="o1"
        )
        await inv_svc.resolve(
            db,
            m.id,
            verdict="false_positive",
            confidence=1.0,
            rationale="Analyst confirmed benign.",
            recommended_actions=None,
            resolved_by="alice",
            resolved_via="manual",
        )
        # A chat resolution out of NMI to false_positive → overridden_to_fp + chat.
        c = await _complete_inv(
            db, rule_name="ET NOISE", verdict="needs_more_info", alert_es_id="o2"
        )
        await inv_svc.resolve(
            db,
            c.id,
            verdict="false_positive",
            confidence=0.95,
            rationale="Chat proposal applied.",
            recommended_actions=None,
            resolved_by="bob",
            resolved_via="chat",
            source_message_id=3,
        )
        # An override the OTHER direction (to true_positive) → overridden_to_tp.
        t = await _complete_inv(
            db, rule_name="ET NOISE", verdict="needs_more_info", alert_es_id="o3"
        )
        await inv_svc.resolve(
            db,
            t.id,
            verdict="true_positive",
            confidence=1.0,
            rationale="Analyst escalated.",
            recommended_actions=None,
            resolved_by="carol",
            resolved_via="manual",
        )

        counts = await inv_svc.override_counts_by_rule(db, ["ET NOISE"])
    assert counts["ET NOISE"] == {
        "overridden_to_fp": 2,
        "overridden_to_tp": 1,
        "chat_resolved": 1,
        "manual_resolved": 2,
    }
    await engine.dispose()


async def test_override_counts_by_rule_ignores_pipeline_fallback_and_plain(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        # A pipeline_fallback stamps report.resolution with `provenance` and NO
        # `resolved_via` — it is NOT an analyst override and must not be counted.
        await _complete_inv(
            db,
            rule_name="ET FB",
            verdict="needs_more_info",
            alert_es_id="f1",
            report={
                "resolution": {
                    "provenance": "pipeline_fallback",
                    "phase": "synth_first",
                    "error_type": "TimeoutError",
                }
            },
        )
        # A plain completed investigation (no resolution at all) is not counted.
        await _complete_inv(db, rule_name="ET FB", verdict="false_positive", alert_es_id="f2")

        counts = await inv_svc.override_counts_by_rule(db, ["ET FB"])
    # ET FB has no analyst overrides → absent from the result entirely.
    assert "ET FB" not in counts
    await engine.dispose()


async def test_override_counts_by_rule_empty(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        assert await inv_svc.override_counts_by_rule(db, []) == {}
    await engine.dispose()
