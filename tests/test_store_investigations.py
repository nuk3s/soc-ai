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


async def test_list_recent_notifications_is_column_scoped_and_bounds_finished_since(
    settings_kratos: Settings,
) -> None:
    """The bell's investigation query selects scalar columns only (never the
    report blob) and bounds the completed half in SQL by ``finished_since`` —
    where the endpoint used to take the newest-N page and drop out-of-window
    rows in Python."""
    engine, maker = await _db(settings_kratos)
    now = utcnow()
    async with maker() as db:
        fresh = await inv_svc.create(db, alert_es_id="ev-a", started_by="t", rule_name="ET Fresh")
        await inv_svc.finalize(
            db, fresh.id, status="complete", verdict="false_positive", report=REPORT
        )
        stale = await inv_svc.create(db, alert_es_id="ev-b", started_by="t", rule_name="ET Stale")
        await inv_svc.finalize(db, stale.id, status="complete", verdict="false_positive")
        stale_row = await db.get(Investigation, stale.id)
        assert stale_row is not None
        stale_row.finished_at = now - timedelta(hours=30)
        await db.commit()

        rows = await inv_svc.list_recent_notifications(
            db, status="complete", limit=20, finished_since=now - timedelta(hours=24)
        )
        ids = {r.id for r in rows}
        assert fresh.id in ids
        assert stale.id not in ids  # finished 30h ago → excluded IN SQL

        # The returned rows are the scalar NotifRow — no report attribute exists,
        # so the report column is provably never on this query's select list.
        assert all(isinstance(r, inv_svc.NotifRow) for r in rows)
        assert not hasattr(rows[0], "report")
        assert rows[0].rule_name == "ET Fresh"
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


async def test_latest_for_pairs_finds_no_ip_investigations(settings_kratos: Settings) -> None:
    """A NULL-endpoint investigation must be reachable under the ('rule','','') key.

    Endpoint/process-shaped detections (Sigma host rules, Zeek notices) carry no
    ``source.ip``/``destination.ip``, so the recorder leaves BOTH columns NULL.
    The sweep planner clusters them under ``(rule, "", "")`` and asks this
    function about that key. While the query filtered ``src_ip IS NOT NULL AND
    dest_ip IS NOT NULL`` those rows were dropped BEFORE the ``or ""`` coalescing
    below it ran, so a no-IP cluster could never inherit its own prior verdict —
    it was re-investigated on every sweep that saw a newer event id.
    """
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        # Exactly what the recorder writes for an alert with no endpoints: a rule
        # name and NULL for both IPs.
        a = await inv_svc.create(db, alert_es_id="ev-host", started_by="x", rule_name="SIGMA HOST")
        assert a.src_ip is None and a.dest_ip is None
        await inv_svc.finalize(db, a.id, status="complete", verdict="false_positive")

        hits = await inv_svc.latest_for_pairs(db, [("SIGMA HOST", "", "")], window_days=7)
        assert hits[("SIGMA HOST", "", "")].id == a.id

        # A half-endpoint row is keyed on the endpoint it DOES have, so it can
        # only be inherited by a cluster of the same shape.
        b = await inv_svc.create(
            db, alert_es_id="ev-half", started_by="x", rule_name="HALF RULE", dest_ip="1.2.3.4"
        )
        await inv_svc.finalize(db, b.id, status="complete", verdict="true_positive")
        half = await inv_svc.latest_for_pairs(
            db, [("HALF RULE", "", "1.2.3.4"), ("HALF RULE", "", "")], window_days=7
        )
        assert half[("HALF RULE", "", "1.2.3.4")].id == b.id
        assert ("HALF RULE", "", "") not in half
    await engine.dispose()


async def test_latest_for_pairs_ip_keyed_rows_unchanged(settings_kratos: Settings) -> None:
    """Regression guard for the ~99.99% path.

    Admitting NULL-endpoint rows must not disturb a both-endpoints lookup: a
    NULL row's coalesced key always carries an empty component, so it can never
    equal — nor outrank, since the map keeps the newest row per key — the key of
    a flow the caller asked about.
    """
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        flow = await inv_svc.create(
            db,
            alert_es_id="ev-flow",
            started_by="x",
            rule_name="ET FLOW",
            src_ip="10.0.0.1",
            dest_ip="1.2.3.4",
        )
        await inv_svc.finalize(db, flow.id, status="complete", verdict="true_positive")
        # Same rule, no endpoints, NEWER — the row that would hijack the flow's
        # key if coalescing collapsed the two shapes together.
        noip = await inv_svc.create(db, alert_es_id="ev-noip", started_by="x", rule_name="ET FLOW")
        await inv_svc.finalize(db, noip.id, status="complete", verdict="false_positive")

        hits = await inv_svc.latest_for_pairs(
            db, [("ET FLOW", "10.0.0.1", "1.2.3.4"), ("ET FLOW", "", "")], window_days=7
        )
        assert hits[("ET FLOW", "10.0.0.1", "1.2.3.4")].id == flow.id
        assert hits[("ET FLOW", "", "")].id == noip.id
    await engine.dispose()


async def test_running_for_pairs_blocks_a_no_ip_duplicate(settings_kratos: Settings) -> None:
    """The in-flight guard has to cover no-IP clusters too.

    Without it a manual (or previous sweep's) investigation of a host-shaped rule
    is invisible to the planner: a newer event id defeats the direct id check and
    the pair check sees nothing, so the same rule is investigated concurrently —
    duplicate work and duplicate model spend at every 5-minute sweep.
    """
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        running = await inv_svc.create(
            db, alert_es_id="ev-host", started_by="x", rule_name="SIGMA HOST"
        )
        assert running.status == "running"
        # A completed run of the same shape must NOT be reported as in-flight.
        done = await inv_svc.create(
            db, alert_es_id="ev-host-old", started_by="x", rule_name="SIGMA DONE"
        )
        await inv_svc.finalize(db, done.id, status="complete", verdict="false_positive")
        # IP-bearing rows keep their own key, unaffected by the no-IP admission.
        flow = await inv_svc.create(
            db,
            alert_es_id="ev-flow",
            started_by="x",
            rule_name="ET FLOW",
            src_ip="10.0.0.1",
            dest_ip="1.2.3.4",
        )
        assert flow.status == "running"

        assert await inv_svc.running_for_pairs(
            db,
            [
                ("SIGMA HOST", "", ""),
                ("SIGMA DONE", "", ""),
                ("ET FLOW", "10.0.0.1", "1.2.3.4"),
                ("ET FLOW", "", ""),
            ],
        ) == {("SIGMA HOST", "", ""), ("ET FLOW", "10.0.0.1", "1.2.3.4")}
    await engine.dispose()


async def test_verdict_counts_since_tallies_the_window_in_sql(
    settings_kratos: Settings,
) -> None:
    """Verdicts landed since a cutoff, counted in SQL over the WHOLE table.

    Aggregated rather than tallied from :func:`list_recent`: a capped scan
    reports a floor as a total the moment a backlog drain completes more
    investigations than the cap, and the dashboard chat states this number to the
    model as fact. Only settled, verdict-bearing rows count — a running or
    errored run has decided nothing.
    """
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        assert await inv_svc.verdict_counts_since(db, utcnow() - timedelta(hours=24)) == {}

        for n in range(2):
            fp = await inv_svc.create(db, alert_es_id=f"ev-fp{n}", started_by="t")
            await inv_svc.finalize(db, fp.id, status="complete", verdict="false_positive")
        tp = await inv_svc.create(db, alert_es_id="ev-tp", started_by="t")
        await inv_svc.finalize(db, tp.id, status="complete", verdict="true_positive")

        # Settled but verdictless, still running, and errored: none is a decision.
        no_verdict = await inv_svc.create(db, alert_es_id="ev-none", started_by="t")
        await inv_svc.finalize(db, no_verdict.id, status="complete")
        await inv_svc.create(db, alert_es_id="ev-running", started_by="t")
        errored = await inv_svc.create(db, alert_es_id="ev-err", started_by="t")
        await inv_svc.finalize(db, errored.id, status="error", verdict="true_positive")

        # Older than the cutoff — last quarter's story is not last night's.
        stale = await inv_svc.create(db, alert_es_id="ev-stale", started_by="t")
        await inv_svc.finalize(db, stale.id, status="complete", verdict="needs_more_info")
        stale_row = await db.get(Investigation, stale.id)
        assert stale_row is not None
        stale_row.created_at = utcnow() - timedelta(days=9)
        await db.commit()

        assert await inv_svc.verdict_counts_since(db, utcnow() - timedelta(hours=24)) == {
            "false_positive": 2,
            "true_positive": 1,
        }
        # Widening the cutoff picks the old row back up.
        assert (await inv_svc.verdict_counts_since(db, utcnow() - timedelta(days=30))).get(
            "needs_more_info"
        ) == 1
    await engine.dispose()


async def test_latest_complete_for_rules_window_bounds_inheritance(
    settings_kratos: Settings,
) -> None:
    """The rule-level fallback honours ``window_days`` for PER-ALERT inheritance:
    a standing verdict older than the window is not inherited (so the alert is
    re-triaged, not stuck on a stale verdict), while the unbounded call (the
    rule-group badge) still returns it. Regression for "inherited a verdict from
    18d ago, past the configured window"."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        a = await inv_svc.create(db, alert_es_id="e1", started_by="t", rule_name="RULE A")
        await inv_svc.finalize(
            db, a.id, status="complete", verdict="false_positive", confidence=0.9
        )
        row = await db.get(Investigation, a.id)
        assert row is not None
        row.created_at = utcnow() - timedelta(days=18)
        await db.commit()

        # Unbounded (group-badge use): the 18d-old standing verdict is returned.
        unbounded = await inv_svc.latest_complete_for_rules(db, ["RULE A"])
        assert unbounded["RULE A"].id == a.id
        # Bounded to a 7-day inherit window (per-alert use): the 18d verdict is excluded.
        assert await inv_svc.latest_complete_for_rules(db, ["RULE A"], window_days=7) == {}

        # A fresh verdict for the same rule IS inherited within the window.
        b = await inv_svc.create(db, alert_es_id="e2", started_by="t", rule_name="RULE A")
        await inv_svc.finalize(db, b.id, status="complete", verdict="true_positive", confidence=0.9)
        bounded = await inv_svc.latest_complete_for_rules(db, ["RULE A"], window_days=7)
        assert bounded["RULE A"].id == b.id
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


# ---------------------------------------------------------------------------
# prior_outcomes — deterministic investigation memory (E4.2)
# ---------------------------------------------------------------------------

_MEM_RULE = "ET MALWARE Memory Beacon"
_MEM_SRC = "10.0.0.1"
_MEM_DST = "10.0.0.2"


async def _seed_prior(
    db,  # type: ignore[no-untyped-def]
    *,
    alert_es_id: str,
    rule_name: str = _MEM_RULE,
    verdict: str | None = "false_positive",
    src_ip: str | None = _MEM_SRC,
    dest_ip: str | None = _MEM_DST,
    rationale: str | None = "benign gateway heartbeat",
    report: dict | None = None,
    age_days: int = 0,
) -> Investigation:
    """Seed one COMPLETE candidate row (optionally backdated) for memory tests."""
    inv = await inv_svc.create(
        db,
        alert_es_id=alert_es_id,
        started_by="t",
        rule_name=rule_name,
        src_ip=src_ip,
        dest_ip=dest_ip,
    )
    await inv_svc.finalize(
        db,
        inv.id,
        status="complete",
        verdict=verdict,
        confidence=0.9,
        rationale=rationale,
        report=report,
    )
    if age_days:
        row = await db.get(Investigation, inv.id)
        row.created_at = utcnow() - timedelta(days=age_days)
        await db.commit()
    return inv


async def _lookup(
    db,  # type: ignore[no-untyped-def]
    *,
    src_ip: str | None = _MEM_SRC,
    dest_ip: str | None = _MEM_DST,
    exclude_id: str | None = None,
    window_days: int = 30,
    limit: int = 5,
) -> list[dict]:
    return await inv_svc.prior_outcomes(
        db,
        rule_name=_MEM_RULE,
        src_ip=src_ip,
        dest_ip=dest_ip,
        exclude_id=exclude_id,
        window_days=window_days,
        limit=limit,
    )


async def test_prior_outcomes_tier_ordering_beats_recency(settings_kratos: Settings) -> None:
    """Exact triple outranks endpoint-share outranks rule-only, whatever the age;
    WITHIN a tier the newest row wins."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        # Oldest row is the exact triple; the freshest is rule-only — tier must win.
        exact = await _seed_prior(db, alert_es_id="m1", age_days=5)
        ep_src = await _seed_prior(db, alert_es_id="m2", dest_ip="10.9.9.9", age_days=2)
        ep_dst = await _seed_prior(db, alert_es_id="m3", src_ip="10.5.5.5", age_days=3)
        rule_only = await _seed_prior(
            db, alert_es_id="m4", src_ip="10.7.7.7", dest_ip="10.9.9.9", age_days=0
        )

        got = await _lookup(db)
        # Tier first; within the endpoint tier, m2 (2d) is newer than m3 (3d).
        assert [d["id"] for d in got] == [exact.id, ep_src.id, ep_dst.id, rule_only.id]
        assert [d["matched_on"] for d in got] == [
            "rule+src+dest",
            "rule+endpoint",
            "rule+endpoint",
            "rule",
        ]
        # Digest shape: light fields only, rationale collapsed into the digest.
        assert got[0]["verdict"] == "false_positive"
        assert got[0]["confidence"] == pytest.approx(0.9)
        assert got[0]["rationale_digest"] == "benign gateway heartbeat"
    await engine.dispose()


async def test_prior_outcomes_filters_window_status_verdict_exclude(
    settings_kratos: Settings,
) -> None:
    """Only complete, verdict-bearing rows inside the window count; exclude_id
    drops the caller's own row."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        keeper = await _seed_prior(db, alert_es_id="k1", age_days=1)
        # Outside the window.
        await _seed_prior(db, alert_es_id="k2", age_days=40)
        # Still running (never finalized) — must never hand out a verdict.
        await inv_svc.create(
            db,
            alert_es_id="k3",
            started_by="t",
            rule_name=_MEM_RULE,
            src_ip=_MEM_SRC,
            dest_ip=_MEM_DST,
        )
        # Complete but verdictless (e.g. an interrupted finalize) — no verdict, no memory.
        await _seed_prior(db, alert_es_id="k4", verdict=None)

        got = await _lookup(db, window_days=30)
        assert [d["id"] for d in got] == [keeper.id]

        # exclude_id drops the caller's own (completed) row.
        assert await _lookup(db, exclude_id=keeper.id) == []
    await engine.dispose()


async def test_prior_outcomes_drops_pipeline_fallback_keeps_analyst_override(
    settings_kratos: Settings,
) -> None:
    """A pipeline-fallback verdict is failure noise, not memory; an analyst
    override (resolution with resolved_via, no provenance) is the OPPOSITE —
    the strongest conclusion we have — and must be kept."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _seed_prior(
            db,
            alert_es_id="f1",
            age_days=0,
            report={
                "resolution": {
                    "provenance": "pipeline_fallback",
                    "phase": "synth_first_round1",
                    "error_type": "TimeoutError",
                }
            },
        )
        overridden = await _seed_prior(
            db,
            alert_es_id="f2",
            age_days=1,
            report={"resolution": {"resolved_via": "manual", "resolved_by": "alice"}},
        )
        got = await _lookup(db)
        assert [d["id"] for d in got] == [overridden.id]
    await engine.dispose()


async def test_prior_outcomes_limit_applies_after_fallback_filter(
    settings_kratos: Settings,
) -> None:
    """``limit`` bounds the RETURNED digests (newest first within the tier), and
    a fallback row between real ones doesn't eat a slot (bounded overscan)."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        rows = [
            await _seed_prior(db, alert_es_id=f"l{i}", age_days=i) for i in range(1, 5)
        ]  # ages 1..4 — newest first is l1, l2, l3, l4
        await _seed_prior(
            db,
            alert_es_id="l0",
            age_days=0,  # newest of all, but a fallback → filtered out
            report={"resolution": {"provenance": "pipeline_fallback"}},
        )
        got = await _lookup(db, limit=3)
        assert [d["id"] for d in got] == [rows[0].id, rows[1].id, rows[2].id]
    await engine.dispose()


async def test_prior_outcomes_unknown_endpoints_rank_rule_only(
    settings_kratos: Settings,
) -> None:
    """With no known endpoint on the CURRENT alert, NULL never 'matches' NULL —
    every candidate is a rule-only match (shared absence isn't a shared endpoint)."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await _seed_prior(db, alert_es_id="n1")
        got = await _lookup(db, src_ip=None, dest_ip=None)
        assert [d["matched_on"] for d in got] == ["rule"]
    await engine.dispose()


async def test_prior_outcomes_rationale_digest_truncates_on_word_boundary(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        long_rationale = "Solicited echo replies from the gateway monitor. " * 12  # ~588 chars
        await _seed_prior(db, alert_es_id="d1", rationale=long_rationale, age_days=1)
        await _seed_prior(db, alert_es_id="d2", rationale="short\n note", age_days=2)
        await _seed_prior(db, alert_es_id="d3", rationale=None, age_days=3)

        got = await _lookup(db)
        digest = got[0]["rationale_digest"]
        assert digest is not None and digest.endswith("…")
        assert len(digest) <= 281  # 280 + the ellipsis
        # Word boundary: the last token before the ellipsis is a whole word.
        assert digest[:-1].rstrip().split()[-1] in long_rationale.split()
        # Short rationales pass through with whitespace collapsed; None stays None.
        assert got[1]["rationale_digest"] == "short note"
        assert got[2]["rationale_digest"] is None
    await engine.dispose()
